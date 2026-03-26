"""Process wrapper that sits between MCP client and server on stdio.

This is the core of mcpfw. It:
1. Spawns the real MCP server as a subprocess
2. Reads JSON-RPC messages from stdin (from the MCP client)
3. Evaluates each message against the policy
4. Forwards allowed messages to the subprocess stdin
5. Reads responses from subprocess stdout
6. Scans responses for sensitive data
7. Forwards to stdout (back to the MCP client)
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from pathlib import Path

from .logger import AuditLogger
from .parser import (
    MCPMessage,
    MessageDirection,
    make_block_response,
    parse_message,
)
from .policy import Action, Policy, Verdict


class MCPFirewall:
    """The mcpfw process wrapper."""

    def __init__(
        self,
        server_command: list[str],
        policy: Policy,
        server_name: str = "unknown",
        audit_logger: AuditLogger | None = None,
    ):
        self.server_command = server_command
        self.policy = policy
        self.server_name = server_name
        self.logger = audit_logger or AuditLogger()
        self._process: asyncio.subprocess.Process | None = None
        self._pending_requests: dict[int | str, MCPMessage] = {}

    async def run(self) -> int:
        """Start the MCP server subprocess and proxy all traffic."""
        self.logger.log_event(
            "start",
            message=f"mcpfw wrapping: {' '.join(self.server_command)}",
            server=self.server_name,
            policy_version=self.policy.version,
        )

        try:
            self._process = await asyncio.create_subprocess_exec(
                *self.server_command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ},
            )
        except FileNotFoundError:
            print(
                f"[mcpfw] Error: command not found: {self.server_command[0]}",
                file=sys.stderr,
            )
            return 1
        except PermissionError:
            print(
                f"[mcpfw] Error: permission denied: {self.server_command[0]}",
                file=sys.stderr,
            )
            return 1

        # Set up tasks for bidirectional proxying
        try:
            tasks = [
                asyncio.create_task(self._proxy_client_to_server(), name="client→server"),
                asyncio.create_task(self._proxy_server_to_client(), name="server→client"),
                asyncio.create_task(self._forward_stderr(), name="stderr"),
            ]

            # Wait for any task to complete (usually means the process exited)
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            # Cancel remaining tasks
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        except Exception as e:
            self.logger.log_event("error", message=str(e))
        finally:
            await self._cleanup()

        self.logger.print_stats()
        self.logger.log_event("stop", message="mcpfw session ended")

        return self._process.returncode if self._process.returncode is not None else 0

    async def _proxy_client_to_server(self) -> None:
        """Read from stdin (client), evaluate policy, forward to subprocess."""
        assert self._process and self._process.stdin

        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        while True:
            line = await reader.readline()
            if not line:
                # Client closed stdin — signal the server
                self._process.stdin.close()
                break

            line_str = line.decode("utf-8", errors="replace")
            msg = parse_message(line_str, MessageDirection.CLIENT_TO_SERVER)

            if msg is None:
                # Not a valid JSON-RPC message, forward as-is
                self._process.stdin.write(line)
                await self._process.stdin.drain()
                continue

            if msg.is_tool_call:
                verdict = self.policy.evaluate_tool_call(self.server_name, msg)
                self.logger.log_tool_call(self.server_name, msg, verdict)

                if verdict.is_blocked:
                    # Don't forward to server — send block response directly to client
                    block_resp = make_block_response(
                        msg.msg_id,
                        verdict.reason or "Blocked by mcpfw policy",
                    )
                    sys.stdout.buffer.write((block_resp + "\n").encode("utf-8"))
                    sys.stdout.buffer.flush()
                    continue

                # Track the request so we can match the response for scanning
                if msg.msg_id is not None:
                    self._pending_requests[msg.msg_id] = msg

            # Forward to server
            self._process.stdin.write(line)
            await self._process.stdin.drain()

    async def _proxy_server_to_client(self) -> None:
        """Read from subprocess stdout (server), scan responses, forward to stdout."""
        assert self._process and self._process.stdout

        while True:
            line = await self._process.stdout.readline()
            if not line:
                break

            line_str = line.decode("utf-8", errors="replace")
            msg = parse_message(line_str, MessageDirection.SERVER_TO_CLIENT)

            if msg is not None and msg.tool_result_text is not None:
                # This is a tool result — scan for sensitive data
                verdict = self.policy.evaluate_response(self.server_name, msg)

                if verdict.action != Action.ALLOW or verdict.rule_name:
                    self.logger.log_response_scan(self.server_name, msg, verdict)

                if verdict.is_blocked:
                    # Replace the response with a block message
                    block_resp = make_block_response(
                        msg.msg_id,
                        verdict.reason or "Response blocked by mcpfw policy",
                    )
                    sys.stdout.buffer.write((block_resp + "\n").encode("utf-8"))
                    sys.stdout.buffer.flush()
                    continue

                # Clean up tracked request
                if msg.msg_id is not None:
                    self._pending_requests.pop(msg.msg_id, None)

            # Forward to client
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

    async def _forward_stderr(self) -> None:
        """Forward subprocess stderr to our stderr."""
        assert self._process and self._process.stderr

        while True:
            line = await self._process.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    async def _cleanup(self) -> None:
        """Clean up the subprocess."""
        if self._process is None:
            return

        if self._process.returncode is None:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()

        self.logger.close()

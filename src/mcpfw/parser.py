"""Parse MCP JSON-RPC messages and extract security-relevant fields."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MessageDirection(Enum):
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"


class MessageType(Enum):
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"


@dataclass
class MCPMessage:
    """A parsed MCP JSON-RPC message with security-relevant fields extracted."""

    raw: str
    direction: MessageDirection
    message_type: MessageType
    method: str | None = None
    msg_id: int | str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None

    # Extracted from tools/call messages
    tool_name: str | None = None
    tool_arguments: dict[str, Any] = field(default_factory=dict)

    # Extracted from tool results (server responses)
    tool_result_text: str | None = None

    @property
    def is_tool_call(self) -> bool:
        return self.method == "tools/call" and self.tool_name is not None

    @property
    def is_tool_result(self) -> bool:
        return (
            self.message_type == MessageType.RESPONSE
            and self.direction == MessageDirection.SERVER_TO_CLIENT
            and self.tool_result_text is not None
        )


def parse_message(raw_line: str, direction: MessageDirection) -> MCPMessage | None:
    """Parse a raw JSON-RPC line into an MCPMessage.

    Returns None if the line is not valid JSON-RPC.
    """
    raw_line = raw_line.strip()
    if not raw_line:
        return None

    try:
        data = json.loads(raw_line)
    except json.JSONDecodeError:
        return None

    if not isinstance(data, dict):
        return None

    # Determine message type
    msg_id = data.get("id")
    method = data.get("method")
    result = data.get("result")
    error = data.get("error")

    if method is not None and msg_id is not None:
        message_type = MessageType.REQUEST
    elif method is not None and msg_id is None:
        message_type = MessageType.NOTIFICATION
    elif error is not None:
        message_type = MessageType.ERROR
    elif result is not None:
        message_type = MessageType.RESPONSE
    else:
        message_type = MessageType.RESPONSE

    msg = MCPMessage(
        raw=raw_line,
        direction=direction,
        message_type=message_type,
        method=method,
        msg_id=msg_id,
        params=data.get("params", {}),
        result=result,
        error=error,
    )

    # Extract tool call details
    if method == "tools/call" and isinstance(msg.params, dict):
        msg.tool_name = msg.params.get("name")
        msg.tool_arguments = msg.params.get("arguments", {})

    # Extract tool result text for DLP scanning
    if message_type == MessageType.RESPONSE and result and isinstance(result, dict):
        content = result.get("content", [])
        if isinstance(content, list):
            texts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    texts.append(item.get("text", ""))
            if texts:
                msg.tool_result_text = "\n".join(texts)

    return msg


def make_error_response(request_id: int | str, code: int, message: str) -> str:
    """Create a JSON-RPC error response string."""
    response = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }
    return json.dumps(response)


def make_block_response(request_id: int | str, reason: str) -> str:
    """Create a JSON-RPC response that indicates a blocked tool call.

    Uses the standard MCP result format so the client handles it gracefully.
    """
    response = {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": f"[mcpfw] Blocked: {reason}",
                }
            ],
            "isError": True,
        },
    }
    return json.dumps(response)

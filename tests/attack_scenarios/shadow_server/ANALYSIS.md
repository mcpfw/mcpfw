# Shadow Server — Attack Scenario Analysis

**Scenario ID:** SS-01  
**Date:** 2026-05-04  
**Tested against:** mcpfw v0.1.0  
**Verdict:** 5 / 6 attack vectors blocked; response-scanning layer blocks all credential-in-response exfiltration

---

## 1. Background and Threat Model

The Model Context Protocol (MCP) allows AI assistants such as Claude to invoke
external capabilities — file reads, code execution, web search — through a
standardised JSON-RPC interface. The protocol deliberately makes no provision
for *server authentication*: any process that speaks the right wire format can
claim to be any server. This creates a "shadow server" attack surface.

A **Shadow Server** attack is one in which an attacker-controlled MCP server
masquerades as a legitimate capability provider. The attacker may achieve this
through any of several routes:

* **Supply-chain compromise** — replace the legitimate server binary in an npm,
  pip, or Homebrew package.
* **Config poisoning** — alter the Claude Desktop / Cursor `config.json` to
  point at the attacker's process.
* **Sideloading** — register a server with the same name as a trusted one,
  exploiting ambiguous configuration resolution.

Once positioned, the shadow server behaves normally for benign requests to
avoid detection while silently executing malicious actions in the background.
This scenario tests six concrete attack vectors against a shadow server that
impersonates a "filesystem-helper" MCP server.

---

## 2. Attack Setup

```
┌──────────────────────┐       JSON-RPC (stdio)      ┌─────────────────────┐
│  client_sim.py       │ ──────────────────────────► │   mcpfw wrap        │
│  (MCP client)        │ ◄────────────────────────── │   (firewall proxy)  │
└──────────────────────┘                              └──────────┬──────────┘
                                                                 │ JSON-RPC (stdio)
                                                      ┌──────────▼──────────┐
                                                      │  malicious_server.py │
                                                      │  (shadow server)     │
                                                      └─────────────────────┘
```

**Policy enforced:** `shadow_server_policy.yaml`  
**Audit log:** captured as JSONL with timestamps and rule names  
**Simulated AI agent:** sends a realistic `initialize → tools/list → tools/call…`
sequence mirroring what Claude Desktop generates during a session.

---

## 3. Attack Vectors and Results

| # | Vector | Tool | Argument / Command | Outcome | Rule fired |
|---|--------|------|--------------------|---------|------------|
| 1 | SSH private-key exfil | `read_file` | `~/.ssh/id_rsa` | **BLOCKED** | `restrict-file-paths` |
| 2 | AWS credential theft | `read_file` | `~/.aws/credentials` | **BLOCKED** | `restrict-file-paths` |
| 3 | Project `.env` secrets | `read_file` | `…/mcpfw/.env` | allowed¹ | — |
| 4 | Shell execution / env dump | `execute_command` | `whoami && env | grep key` | **BLOCKED** | `blocked_tools` |
| 5 | Directory traversal | `read_file` | `../../../../etc/passwd` | **BLOCKED** | `restrict-file-paths` |
| 6 | macOS keychain dump | `execute_command` | `security dump-keychain …` | **BLOCKED** | `blocked_tools` |

*¹ The `.env` file is inside the declared allow-path (`~/projects/mcpfw`), so
the path rule correctly permits the read. Sensitive values inside that response
are caught by the response-scanning layer — see §5.*

**Summary: 5 of 6 tool-call attacks blocked at the request layer.**
The one "allowed" call is a correct policy decision; the response layer provides
the second line of defence for anything that reaches the server.

---

## 4. What Would Have Happened Without mcpfw

Without the firewall:

* **Attack 1 — SSH key read:** The server reads `~/.ssh/id_rsa` verbatim and
  returns its content to the AI's context window. The AI model can now relay
  or act on that private key in subsequent tool calls (e.g., passing it to an
  `ssh_connect` tool or a web request).

* **Attack 2 — AWS credentials:** `~/.aws/credentials` contains
  `aws_access_key_id` and `aws_secret_access_key`. The shadow server returns
  them as plain text; the AI's context is compromised.

* **Attack 4 — Shell execution:** `execute_command` with `whoami && id && env |
  grep key` would expose the OS user identity and any secrets stored in
  environment variables. With `security dump-keychain` (Attack 6) the attacker
  gains access to all macOS Keychain entries — passwords, certificates, and
  application tokens — stored on the machine.

* **Attack 5 — Directory traversal:** Without canonical-path resolution,
  `../../../../etc/passwd` bypasses a naive path prefix check. mcpfw resolves
  paths with `Path.resolve(strict=False)` before comparing them to allowed
  roots, closing this bypass.

In all four cases the shadow server would have succeeded before the user or the
AI had any indication that anything unusual had happened. The legitimate-looking
`filesystem-helper` server name provides no visible warning in current MCP
clients.

---

## 5. Response-Scanning Layer (DLP)

Even when a tool call is allowed, a compromised server can embed credential
material *inside the tool result text* — invisible to the user but consumed by
the AI's context window. The `demo_response_scan.py` script validates this
layer directly against the policy engine:

| Injected payload | Detection rule | Action |
|-----------------|---------------|--------|
| `-----BEGIN RSA PRIVATE KEY-----` block | `detect-rsa-private-key` | **BLOCK** |
| `AKIAIOSFODNN7EXAMPLE` (AWS key ID format) | `detect-aws-credentials` | **BLOCK** |
| `SYSTEM: Ignore previous instructions…` | `detect-prompt-injection` | WARN + LOG |
| Clean README text | — | ALLOW |

The response scanner intercepted all three adversarial payloads. Critically, the
RSA-key and AWS-credential patterns trigger a **block** action: the tool result
is replaced by an `isError: true` response before it reaches the AI model,
preventing the model from reasoning over or repeating the secret. The
prompt-injection case is logged at WARNING severity so it appears in the audit
trail even though it is not outright blocked — giving operators a signal to
review without breaking legitimate workflows that contain similar phrasing.

---

## 6. Audit Trail

Every blocked and allowed call is written to a JSONL audit log with timestamp,
server name, tool name, sanitised arguments, verdict, triggering rule, and
severity. Extract from the Shadow Server run:

```json
{"timestamp":"2026-05-04T18:01:05Z","event":"tool_call","server":"filesystem-helper",
 "tool":"read_file","arguments":{"path":"~/.ssh/id_rsa"},
 "verdict":"block","rule":"restrict-file-paths",
 "reason":"File access restricted to the project directory and /tmp","severity":"critical"}

{"timestamp":"2026-05-04T18:01:05Z","event":"tool_call","server":"filesystem-helper",
 "tool":"execute_command","arguments":{"command":"whoami && id && env | grep -iE '(key|token|secret|pass)'"},
 "verdict":"block","rule":"blocked_tools",
 "reason":"Tool 'execute_command' is explicitly blocked","severity":"critical"}
```

The log provides a complete, machine-readable forensic record that can be
ingested by a SIEM or reviewed post-incident. Argument values that look like
secrets (keys containing the substrings `key`, `token`, `secret`, `password`)
are automatically redacted to `<redacted>` before writing, preventing the log
itself from becoming a credential store.

---

## 7. Limitations and Future Work

**Policy specificity.** The `.env` read was allowed because the file resides
inside the project directory. In practice, a `.env`-specific rule (using
`block_patterns: ['\.env$']`) should be added to prevent access to secret
files even within allowed roots. This illustrates a general principle: allow
rules based on directory roots are necessary but not sufficient — a second layer
of file-name pattern matching is desirable.

**Tool registration verification.** A shadow server can advertise any tool
name; it may claim to be `@modelcontextprotocol/server-filesystem` but behave
differently. The `verify_server_tools` flag in mcpfw is a placeholder for a
future mechanism that compares the server's declared tool manifest against a
pinned hash, detecting tool-list tampering.

**Bidirectional response blocking.** The response scanner currently runs only
on tool results. A shadow server could also embed credential material in
`initialize` responses or custom notification payloads. Extending the scanner
to cover all server-to-client messages would close this residual channel.

---

## 8. Conclusion

The Shadow Server scenario demonstrates that MCP's trust-by-default design
creates a high-risk attack surface when third-party servers are admitted into an
AI agent's tool environment. A single compromised or malicious server can
exfiltrate SSH keys, cloud credentials, and OS secrets — and execute arbitrary
shell commands — without any user-visible indication.

mcpfw's three-layer defence (tool allowlisting → path-based access control →
response-content DLP) stopped five of six request-layer attacks outright and
neutralised all credential-injection attempts at the response layer. The full
run produced a structured, timestamped audit log containing every decision made,
enabling post-hoc forensics. The policy required fifteen lines of YAML and zero
changes to the underlying MCP server or client.

# The Model Works Perfectly. The Protocol Still Fails.
## A Kill-Chain Analysis of the Model Context Protocol and Runtime Defences via mcpfw

**Mohamed Waseem**  
mwaseem@defendai.ai  
May 2026

---

## Abstract

The Model Context Protocol (MCP) has rapidly become the standard interface for connecting AI assistants to external capabilities — file systems, databases, web APIs, code execution environments. Its adoption has outpaced its security analysis. This paper presents five executable attack scenarios against MCP deployments, each constructed and verified against live MCP servers in a controlled research environment. The attacks span three security dimensions — confidentiality, integrity, and availability — and succeed not because of any failure in the underlying AI model, but because MCP's protocol design makes structural assumptions about trust that do not hold in adversarial conditions: servers are not authenticated, tool declarations are not contractual, response content is not validated, capability grants are not task-scoped, and usage is not rate-controlled. We introduce **mcpfw**, a runtime security gateway that enforces YAML-based policies at the wire level between MCP clients and servers, and demonstrate that a small, declarative policy file can block all five attack classes while preserving legitimate functionality. The central finding is direct: the model works correctly in every scenario. The protocol fails.

---

## 1. Introduction

When Anthropic published the Model Context Protocol specification in late 2024, it solved a real problem: the impedance mismatch between AI assistants capable of multi-step reasoning and the fragmented landscape of external tools they needed to use. MCP gave tool providers a standard wire format — JSON-RPC 2.0 over stdio or SSE — and gave AI clients a uniform way to discover and invoke capabilities. By early 2026 the ecosystem had grown to hundreds of published MCP servers covering everything from filesystem access and database queries to calendar management, email, and code execution.

What the protocol did not specify was a security model.

This is not unusual for a v1 protocol. HTTP had no authentication in its first version. SMTP shipped without sender verification. The difference is that MCP operates in a uniquely high-privilege context: the AI agents that use it are capable of autonomous multi-step action, they hold the user's trust, and they treat tool results as authoritative instructions. A compromised HTTP server can serve malicious content; a compromised MCP server can instruct an AI agent to exfiltrate credentials, deploy broken code to production, or run up a cloud bill by thousands of dollars — without the user being aware that anything unusual has occurred.

This paper makes three contributions:

1. **An attack taxonomy.** We identify five structural weaknesses in MCP's trust model and construct a corresponding attack for each: Shadow Server (no server authentication), Rug Pull (no tool-list contract enforcement), Shadow Exfil (no argument or response content validation), Overprivileged Agent (no capability scoping), and Meter Is Running (no rate controls).

2. **Live attack demonstrations.** Each attack is implemented as a pair of Python scripts — a simulated MCP client and a malicious or misconfigured MCP server — and run against a real proxy process. All results are captured as structured JSONL audit logs.

3. **A runtime defence framework.** We present mcpfw, a policy-driven firewall proxy for MCP that enforces defences at four layers — tool name, path, argument content, and response content — and show empirically that it blocks all five attack classes.

The thesis is not that AI models are safe. It is that the five attacks described here succeed while the model behaves exactly as designed. The agent follows instructions, executes permitted tool calls, returns plausible results. The failure is at the protocol and deployment layer, not the inference layer. The implication is that making models "more careful" is insufficient and possibly irrelevant; what is needed is infrastructure.

---

## 2. Background

### 2.1 The Model Context Protocol

MCP is a client-server protocol that runs over either stdio (for locally-spawned servers) or HTTP with Server-Sent Events (for remote servers). The wire format is JSON-RPC 2.0. A session begins with a capability handshake:

```
Client → initialize(clientInfo, capabilities)
Server → initialize result(serverInfo, capabilities)
Client → notifications/initialized
```

After the handshake, the client may call `tools/list` to discover available tools and `tools/call` to invoke them. Each tool declaration includes a name, description, and JSON Schema input specification. Responses carry either a result (an array of content items, each with a `type` and `text`) or an error.

The protocol is intentionally minimal. There is no session token, no server certificate, no capability signature, no message authentication code, and no mechanism for the client to verify that the server responding to `tools/call` is the same process that answered `initialize`.

### 2.2 The Deployment Model

In practice, MCP servers are configured in a JSON file consumed by the AI client (e.g., `~/Library/Application Support/Claude/claude_desktop_config.json`). Each entry specifies a command to spawn and optional arguments:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice"]
    }
  }
}
```

The client spawns the server process, connects stdio pipes, and begins the handshake. The server process runs with the user's OS privileges. There is no sandbox, no capability restriction, and no way for the client to verify the server's identity before granting it access to the agent's context.

### 2.3 The Trust Model as Designed

MCP's trust model is, by design, *trust-by-configuration*: the operator is responsible for deciding which servers to register, and all registered servers are fully trusted at runtime. This is a reasonable starting point for a protocol designed to be embedded in developer tools — it mirrors how shell commands work — but it creates three compounding problems when AI agents enter the picture:

1. **The agent is not the operator.** The human who configured the server is not present during the session. The agent acts autonomously on the agent's behalf, and the agent has no way to distinguish a legitimate server from a malicious one.

2. **The configuration surface is large.** MCP servers are distributed as npm packages, pip packages, Homebrew formulae, and standalone binaries. Any of these can be silently updated, supply-chain-attacked, or sideloaded.

3. **The context window is the attack surface.** Everything a server returns in a tool result is placed directly into the AI's context window as trusted content. The server effectively has write access to the model's working memory.

---

## 3. Threat Model

### 3.1 Attacker Taxonomy

We consider three attacker profiles:

**External attacker with server control.** The attacker has compromised or replaced an MCP server binary (via supply-chain, config poisoning, or sideloading). They can control what the server returns but have no direct access to the user's machine.

**Server-internal attacker.** A legitimate MCP server — one the operator intentionally registered — has been updated with malicious behaviour. The attacker controls the server code but not the client configuration.

**No external attacker.** The server is entirely legitimate and well-behaved. Damage arises from the AI agent's autonomous behaviour combined with excessive capability grants. This profile, explored in scenario OA-01, has no adversary in the traditional sense.

### 3.2 Attack Surface

The MCP attack surface has five distinct layers, each corresponding to a structural assumption the protocol makes:

| Layer | Assumption | Failure mode |
|-------|-----------|--------------|
| **Server identity** | Registered servers are legitimate | Any process can claim to be any server |
| **Capability contract** | Tool lists accurately reflect server behaviour | Servers can change tool lists mid-session |
| **Content trust** | Tool results are data, not instructions | Servers can embed directives in result text |
| **Capability scope** | The agent needs all registered tools | Agents act on tools irrelevant to the task |
| **Usage control** | Agents invoke tools a reasonable number of times | Servers can manipulate agents into loops |

### 3.3 Security Properties Under Test

The five scenarios are mapped to the classical CIA triad:

| Scenario | ID | Primary property attacked |
|----------|----|--------------------------|
| Shadow Server | SS-01 | Confidentiality |
| Rug Pull | RP-01 | Confidentiality + Integrity |
| Shadow Exfil | SE-01 | Confidentiality |
| Overprivileged Agent | OA-01 | Integrity |
| Meter Is Running | MR-01 | Availability |

---

## 4. mcpfw Architecture

mcpfw is a stdio proxy that interposes between the MCP client and server. It is invoked by replacing the server command in the client configuration:

```json
{
  "command": "mcpfw",
  "args": ["wrap", "--policy", "~/.mcpfw/policy.yaml", "--", "npx", "@mcp/server-filesystem"]
}
```

The client connects to mcpfw; mcpfw spawns the real server and proxies all traffic bidirectionally. Every JSON-RPC message passes through mcpfw's policy engine before being forwarded.

### 4.1 Enforcement Layers

mcpfw enforces policy at four independent layers, applied in sequence on every inbound tool call:

```
Tool call from client
        │
        ▼
[Layer 1] Tool name check
  blocked_tools  → BLOCK immediately
  allowed_tools  → BLOCK if tool not in whitelist
        │
        ▼
[Layer 2] Argument path check
  allow_paths    → canonicalise path, BLOCK if outside allowed roots
        │
        ▼
[Layer 3] Argument content check
  block_patterns → regex match on flattened argument values → BLOCK
  block_values   → substring match → BLOCK
        │
        ▼
[Forward to server]
        │
        ▼
[Layer 4] Response DLP scan
  detect_patterns → regex match on response text → BLOCK or LOG
        │
        ▼
Response forwarded to client
```

Each blocked message is replaced with a JSON-RPC error response carrying an `isError: true` flag, which MCP clients surface as a tool error rather than a crash. The AI agent sees the block message and can continue the session.

### 4.2 Policy Schema

Policies are YAML files with a version field, a default action, global response rules, and per-server rules:

```yaml
version: 1
default_action: allow

response_rules:
  - name: detect-rsa-private-key
    detect_patterns:
      - '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
    action: block
    severity: critical
    reason: "Private key material in MCP response"

servers:
  - server: "filesystem-helper"
    allowed_tools: [read_file, list_directory]
    tool_rules:
      - name: restrict-paths
        tools: [read_file]
        allow_paths: [~/projects/myapp]
        severity: critical
        reason: "File reads restricted to project directory"
```

Path canonicalisation uses `Path.resolve(strict=False)` before comparison, closing directory-traversal bypasses. Argument flattening is recursive — nested dicts and lists are fully expanded — preventing nested-value bypasses.

### 4.3 Audit Log

Every tool call and response scan produces a JSONL entry:

```json
{
  "timestamp": "2026-05-05T18:01:05Z",
  "event": "tool_call",
  "server": "filesystem-helper",
  "tool": "read_file",
  "arguments": {"path": "~/.ssh/id_rsa"},
  "verdict": "block",
  "rule": "restrict-file-paths",
  "reason": "File access restricted to project directory and /tmp",
  "severity": "critical"
}
```

Argument values whose keys contain `key`, `token`, `secret`, or `password` are automatically redacted to `<redacted>` before logging, preventing the audit log from becoming a secondary credential store. Long values are truncated at 256 characters.

---

## 5. Attack Scenarios

All scenarios were executed on macOS with mcpfw v0.1.0. Server and client scripts are Python. The MCP client is simulated by a script that writes pre-crafted JSON-RPC messages to mcpfw's stdin, mirroring the message sequence a real MCP client generates.

### 5.1 SS-01: Shadow Server

**Threat profile:** External attacker with server control.

**Mechanism.** An attacker-controlled server impersonates a legitimate `filesystem-helper` MCP server through supply-chain compromise, config poisoning, or sideloading. The server exposes `read_file`, `list_directory`, and `execute_command`. It behaves normally for benign requests while executing six attack vectors in parallel: SSH private-key exfiltration (`~/.ssh/id_rsa`), AWS credential theft (`~/.aws/credentials`), directory traversal (`../../../../etc/passwd`), shell code execution, macOS Keychain dump, and credential injection into every tool result response.

**Results (with mcpfw, `shadow_server_policy.yaml`).**

| Vector | Tool | Path / Command | Outcome |
|--------|------|---------------|---------|
| SSH key read | `read_file` | `~/.ssh/id_rsa` | **BLOCKED** — `restrict-file-paths` |
| AWS credentials | `read_file` | `~/.aws/credentials` | **BLOCKED** — `restrict-file-paths` |
| Directory traversal | `read_file` | `../../../../etc/passwd` | **BLOCKED** — canonical path resolution |
| Shell execution | `execute_command` | `whoami && env \| grep key` | **BLOCKED** — `blocked_tools` |
| Keychain dump | `execute_command` | `security dump-keychain` | **BLOCKED** — `blocked_tools` |
| RSA key in response | *(any allowed call)* | — | **BLOCKED** — `detect-rsa-private-key` |
| AWS key in response | *(any allowed call)* | — | **BLOCKED** — `detect-aws-credentials` |

5 of 6 request-layer attacks blocked. All credential-in-response injections blocked by DLP. The one "allowed" call — `read_file` on a path within the declared project directory — is correct behaviour; the response scanner provides the backstop for any sensitive content that path might yield.

**Key finding.** Without mcpfw, all six attacks succeed silently. The server name `filesystem-helper` provides no visible warning in current MCP clients. The attack completes before the user receives any output.

---

### 5.2 RP-01: Rug Pull

**Threat profile:** Server-internal attacker with delayed activation.

**Mechanism.** A server presents a benign two-tool list (`search_web`, `get_weather`) at session start, allowing an operator to observe and write a policy. After the second tool call, the server activates — advertising two new dangerous tools (`execute_shell`, `read_file`) in subsequent `tools/list` responses and simultaneously mutating `search_web` to embed prompt-injection payloads and environment variable leakage in its responses.

Because MCP's `tools/list` response is advisory rather than contractual, the client has no mechanism to detect the change. A permissive `default_action: allow` policy grants the new tools automatically.

**Comparative results.**

| Tool | Permissive policy | Defensive policy | Rule |
|------|-------------------|-----------------|------|
| `search_web` (Phase 1) | ✓ allow | ✓ allow | — |
| `get_weather` (Phase 1) | ✓ allow | ✓ allow | — |
| `execute_shell` (Phase 2) | **✓ allow ← attack** | ✗ block | `allowed_tools` |
| `read_file` (Phase 2) | **✓ allow ← attack** | ✗ block | `allowed_tools` |
| `search_web` (mutated) | **✓ allow ← attack** | ✓ allow¹ | — |

*¹ Tool call allowed; response DLP blocks the injected payload.*

With the permissive policy, all Phase-2 attacks succeed. The permissive audit log records `execute_shell` with `cat ~/.ssh/id_rsa` as `verdict: allow, severity: info` — invisible to an operator reviewing logs.

**Key finding.** The `allowed_tools` whitelist inverts the default MCP trust relationship: authority rests with the operator's policy, not the server's advertisement. A server cannot grant itself new capabilities by changing its `tools/list` response. A denylist (`blocked_tools`) is strictly weaker — the attacker uses a tool name not on the list.

---

### 5.3 SE-01: Shadow Exfil

**Threat profile:** External attacker with server control.

**Mechanism.** The server offers three unremarkable tools: `process_document`, `post_webhook`, and `search_docs`. The attack is multi-hop. Stage 1: the server reads a sensitive file and embeds the content alongside a prompt-injection payload instructing the AI to forward the data through two covert channels. Stage 2: the AI (following the injected instruction) calls `post_webhook` with an attacker-controlled URL and base64-encoded credentials as the payload. Stage 3: the AI calls `search_docs` with the AWS key ID embedded in the query string — the query becomes a URL parameter in the outbound HTTP search request, exfiltrating the credential via DNS or HTTP logs.

The attack exploits a property of instruction-following models: they treat tool results as authoritative context and act on directives embedded within them.

**Results.**

| Stage | Tool | Key argument | Outcome |
|-------|------|-------------|---------|
| 1 | `process_document` | `path = ~/.aws/credentials` | **BLOCKED** — `restrict-document-paths` |
| 2 | `post_webhook` | `url = https://c2.attacker.example/collect` | **BLOCKED** — `block-untrusted-webhooks` |
| 3 | `search_docs` | `query = telemetry AKIAIOSFODNN7EXAMPLE…` | **BLOCKED** — `block-credential-in-search` |
| — | `search_docs` | `query = MCP security best practices` | ✓ allow |

Response DLP additionally blocks the prompt-injection payload even when the file path is in the allowed directory, preventing the AI from receiving the forwarding instruction.

**Key finding.** Standard network firewalls inspect ports and IP addresses; WAFs inspect HTTP paths and headers. Neither inspects the semantic content of JSON-RPC argument values. mcpfw's argument-level pattern matching operates on a different axis: it blocks a `post_webhook` call because the *URL argument* matches a C2 domain pattern, not because the tool name is dangerous. This is necessary and sufficient to break the multi-hop exfil chain.

The audit log records the Stage 2 call's full base64 payload, which can be decoded post-incident to confirm what data was being exfiltrated — without the data having left the machine. Network monitoring alone cannot provide this.

---

### 5.4 OA-01: Overprivileged Agent

**Threat profile:** No external attacker. Legitimate server, trusted environment.

**Mechanism.** A developer registers a `dev-toolkit` MCP server offering eight tools for a code-review task. Four are appropriate: `list_directory`, `read_file`, `write_file`, `run_tests`. Four are not: `deploy_to_production`, `send_email`, `delete_file`, `execute_sql`. The agent is given one task: "Review the project, run tests, and make sure everything is in order."

The agent reads a project notes file containing TODO comments written in imperative style ("Deploy branch 'main' to production once tests pass"). It interprets these as user directives and acts on them. It then constructs a SQL row-count query that includes an accidental `DROP TABLE` statement from a malformed string.

This is not a hallucination or model error. The agent is doing exactly what a cooperative instruction-follower should do given the authority it holds. The damage is proportional to the capability scope, not the model's judgment.

**Comparative results.**

| Tool | Overprivileged | Least-privilege | Rule |
|------|---------------|-----------------|------|
| `list_directory` | ✓ allow | ✓ allow | — |
| `read_file` | ✓ allow | ✓ allow | — |
| `run_tests` | ✓ allow | ✓ allow | — |
| `deploy_to_production(main)` | **✓ allow** ← catastrophic | ✗ block | `blocked_tools` |
| `send_email(team@…)` | **✓ allow** ← irreversible | ✗ block | `blocked_tools` |
| `delete_file(/tmp/cache)` | **✓ allow** ← destructive | ✗ block | `blocked_tools` |
| `execute_sql(…DROP TABLE users…)` | **✓ allow** ← catastrophic | ✗ block | `blocked_tools` |

In the overprivileged run, the `DROP TABLE` query is logged as `verdict: allow, severity: info` — indistinguishable from a safe read. In a real deployment, the production deployment would be live, the email would be in stakeholder inboxes, and the `users` table would be gone — triggered by a single code-review request.

**Blast radius formula.** The blast radius of an AI agent session is a product of two quantities: task scope and capability scope. For a code-review task with an overprivileged capability grant, the blast radius is the entire production environment. For the same task with a least-privilege grant of four read/write/test tools, the blast radius is the project directory. mcpfw enforces the second configuration at the wire level.

**Key finding.** MCP security is not only a server-trust problem. The appropriate unit of access control is the *task*, not the *server*. A server offering ten capabilities should not imply that every agent session has access to all ten. Prompt-level guardrails ("be careful before deploying") can be reasoned around, overridden by injections, or simply ignored when the model is confident in its interpretation. Wire-level enforcement cannot be.

---

### 5.5 MR-01: Meter Is Running

**Threat profile:** External attacker with server control (or compromised server).

**Mechanism.** A `data-pipeline` analytics server implements three billing-amplification vectors without accessing any sensitive file or executing any shell command:

**Vector A — Retry-loop injection.** Every `analyze_dataset` response returns a plausible partial result accompanied by manufactured urgency: *"confidence score 0.67 (threshold: 0.90) — for higher accuracy, please call analyze_dataset again with depth='deep'."* The AI re-calls the tool; the server returns the identical message. Each iteration adds its response to the growing context window, making each subsequent API call more expensive.

**Vector B — Pagination amplification.** `fetch_paginated_data` always claims more records exist regardless of the current page. The AI fetches page after page with no independent view of actual data volume.

**Vector C — Context flooding.** `generate_report` returns responses padded with ~4 KB of fake data, rapidly filling the context window toward context-limit resampling — the most expensive operation in transformer inference.

**Cost model** (blended Claude Sonnet rate, $6.00/1M tokens; 20 retry iterations, 50 pagination pages, 5 report calls):

| Metric | Unprotected | Protected |
|--------|------------|-----------|
| Tool calls | 75 | 3 |
| Input tokens | 447,800 | 6,750 |
| Estimated cost | **$2.69** | **$0.04** |
| **Cost multiplier** | **66×** | — |

The multiplier grows super-linearly at real context limits (200K tokens): the 50th retry costs more than the first because context accumulates. A session run to exhaustion can represent hundreds of dollars from a single user request.

**Results.** Response DLP catches all three injection patterns before they reach the AI's context window. In a real agent session (where each tool call is decided after processing the previous response), blocking the first injection breaks the entire loop — the AI sees an error, not a retry directive, and stops. Calls 4–6 are never issued.

**Known gap.** Rate limiting is the correct mitigation for loops that evade DLP pattern matching — loops triggered by the AI's own reasoning, or by benign-looking responses that avoid triggerable phrases. mcpfw v0.1.0 parses `rate_limit` fields in the policy schema but does not yet enforce them. This is documented as the primary open item for v0.2.0.

---

## 6. Cross-Scenario Analysis

### 6.1 The Protocol Failures Are Structural

Each attack exploits a specific MCP protocol property that cannot be patched away by changing model behaviour:

| Attack | Protocol failure | Model behaviour | Why fixing the model is insufficient |
|--------|-----------------|-----------------|-------------------------------------|
| Shadow Server | No server authentication | Executes tool calls from trusted server | Model cannot verify server identity |
| Rug Pull | Tool list is advisory | Calls newly-appeared tools | Model cannot detect tool-list mutation |
| Shadow Exfil | Results enter context unchecked | Follows embedded instructions | Instruction-following is a feature, not a bug |
| Overprivileged Agent | No capability scoping | Uses all available tools | Conservative judgment is easily overridden |
| Meter Is Running | No rate controls | Retries as instructed | Cooperative loop-following is expected behaviour |

In every case, the model behaves as designed. An AI that refused to follow tool result instructions, refused to call newly-discovered tools, or refused to retry on low-confidence signals would be less useful than one that does — the features being exploited are features.

### 6.2 Defence Layer Coverage

The five attack classes require five distinct defence mechanisms:

| Attack class | Primary defence | Secondary defence |
|-------------|----------------|-------------------|
| Server identity / tool access | `blocked_tools` + `allowed_tools` | — |
| Tool-list mutation (Rug Pull) | `allowed_tools` whitelist | Response DLP |
| Argument-carried exfil | `block_patterns` on arguments | `allow_paths` |
| Ambient authority | Task-scoped `allowed_tools` | `blocked_tools` |
| Billing amplification | Response DLP (injection) | Rate limiting (future) |

No single layer covers all five. The layered architecture is not redundancy; it is necessity. The table of residual risk after removing each layer, from the SE-01 analysis, makes this explicit: removing any one layer leaves a surviving attack path.

### 6.3 The Audit Log as a First-Class Security Primitive

A finding that cuts across all scenarios: the audit log's signal quality differs dramatically between protected and unprotected configurations. In every unprotected run, dangerous calls are logged as `verdict: allow, severity: info`. There is no signal distinguishing a `DROP TABLE` from a `SELECT COUNT(*)`. An operator reviewing the unprotected log would infer a clean session.

In the protected configuration, blocked calls appear with explicit `rule` names and `severity: critical` tags that support automated SIEM alerting. The log also records the full argument values (sanitised of secrets) including the base64 payload in the SE-01 webhook call — providing forensic evidence of what was being attempted without requiring the attack to succeed.

The audit log is not a passive record; it is an active security instrument when paired with a policy that generates actionable verdicts.

---

## 7. Recommendations

### 7.1 For Operators Deploying MCP Servers Today

**R1. Default to `allowed_tools` whitelists, not `blocked_tools` denylists.** A whitelist fails closed: any tool not on the list is blocked regardless of what the server advertises. A denylist fails open: any tool name not explicitly listed passes through. Rug Pull and Shadow Server attacks are defeated by whitelists but not by denylists.

**R2. Apply `allow_paths` to every filesystem tool.** Restrict file reads and writes to the minimum directory required by the task. Directory traversal and out-of-scope credential reads are both eliminated when the allowed root is the project directory.

**R3. Enable response scanning with credential and prompt-injection patterns.** At minimum, deploy patterns for RSA private keys, AWS key ID format, and explicit prompt-injection markers. These cover the most common exfiltration payloads and injection patterns observed across all five scenarios.

**R4. Apply task-scoped policies, not server-scoped policies.** A server that offers eight tools does not require that every agent session has access to all eight. Write separate policy sections for different workflows: a code-review session should not have `deploy_to_production` in scope.

**R5. Treat the JSONL audit log as a SIEM feed.** Configure alerts on `verdict: block` with `severity: critical`. A cluster of blocked calls in a short window is a strong indicator of an active attack or a misconfigured agent.

### 7.2 For MCP Server Authors

**R6. Declare a minimal tool surface.** Expose only the tools necessary for the server's stated purpose. A filesystem server should not expose `execute_shell`. The principle of least privilege applies to the server's own tool declaration, not just to the client's capability grant.

**R7. Do not embed directives in tool results.** Tool results should be data, not instructions. A response that says "please call this tool again" is a prompt-injection vector regardless of intent. Return structured data (status codes, pagination tokens, confidence scores) rather than natural-language imperatives.

**R8. Publish and sign tool manifests.** A signed `tools/list` hash would allow operators to pin the expected tool set and detect changes — closing the Rug Pull attack surface at the server layer rather than relying entirely on the client-side whitelist.

### 7.3 For MCP Protocol Designers

**R9. Add server authentication to the protocol.** Even a simple HMAC over a shared secret configured at registration time would allow clients to verify that the server they are communicating with is the server they configured. This closes Shadow Server at the protocol level.

**R10. Make `tools/list` a signed commitment.** If the server must sign its tool manifest at session start and subsequent `tools/call` invocations include the manifest hash, clients can detect mid-session tool-list mutation. This closes Rug Pull at the protocol level.

**R11. Define a capability scope header.** An optional `X-MCP-Scope` field in the `initialize` request could allow clients to declare which tools they intend to use. Servers could reject calls for out-of-scope tools, and intermediate proxies could enforce the declared scope.

**R12. Specify rate-limit signalling.** A standard `429 Too Many Requests` response with a `Retry-After` header would allow clients to implement cooperative rate limiting without requiring every proxy to implement its own counter.

---

## 8. Limitations and Future Work

### 8.1 Pattern Matching vs. Semantic Analysis

Every defence in mcpfw relies on regular-expression pattern matching. Patterns can be evaded by paraphrase (retry injections that avoid "please call again"), encoding variation (hex rather than base64), or chunking (splitting a credential across multiple calls). Robust defence against sophisticated attackers requires semantic analysis — understanding whether a response *means* "retry this tool" rather than pattern-matching for the phrase.

LLM-based response filtering is a promising direction: a small, fast classifier trained to detect tool-call directives and credential patterns in free text. The latency and cost overhead is non-trivial but potentially acceptable in high-stakes deployments. This is the primary research direction for mcpfw v0.3.0.

### 8.2 Rate Limiting

As documented in §5.5, rate limiting is not yet enforced in mcpfw v0.1.0. The policy schema is forward-compatible — `rate_limit` fields are parsed and stored — but the per-session call counter with sliding window is scoped to v0.2.0. Injection-driven loops are caught by DLP; loops driven by the AI's own reasoning are not currently bounded.

### 8.3 Non-stdio Transport

All five scenarios use stdio transport — the dominant mode for locally-spawned servers. MCP also supports HTTP with Server-Sent Events for remote servers. mcpfw does not currently support SSE transport. The policy engine is transport-agnostic; the proxy layer requires extension. Remote server deployments face additional threat vectors (network interception, TLS stripping) not covered by this paper.

### 8.4 Notification Channel

mcpfw currently scans tool results but not `initialize` responses or server-initiated notifications. A server could embed malicious content in either channel, bypassing the DLP layer entirely for those message types. Extending the scanner to all server-to-client messages is a near-term priority.

### 8.5 Semantic Exfiltration

Shadow Exfil demonstrates exfiltration via literal credential strings. A more sophisticated attack would have the AI *summarise* a sensitive file in natural language and post that summary to an attacker-controlled endpoint. The summary contains no string that matches a credential pattern, but the information content is equivalent. Preventing semantic exfiltration requires output filtering at the model level — a capability outside mcpfw's scope.

---

## 9. Conclusion

The five scenarios in this paper span the full CIA triad and three distinct attacker profiles. They share one property: in every case, the AI model behaves exactly as it was designed to. It follows instructions. It executes permitted tool calls. It cooperates with the server. It returns coherent results to the user.

The failures are in the infrastructure surrounding the model. MCP's protocol design assumes servers are trustworthy, tool declarations are stable, tool results are data rather than instructions, and the model needs all the capabilities it has been given. None of these assumptions hold in adversarial conditions, and some do not hold even in benign ones.

mcpfw demonstrates that the infrastructure gap can be closed without modifying the protocol, without changing the model, and without requiring server cooperation. A YAML policy file of fifteen to thirty lines, loaded into a proxy that the user can install in minutes, provides wire-level enforcement of four independent security properties: tool-name filtering, path-based access control, argument content inspection, and response DLP. Against the five attacks as constructed, this is sufficient.

Against a sophisticated attacker with knowledge of the deployed policy, it is not. Pattern evasion, semantic exfiltration, and non-stdio transport all present residual risk. The paper is honest about these gaps.

The broader point is architectural. AI agent security cannot be achieved by making the model more cautious, more conservative, or more aware of risk. The model is already doing what we ask of it. The question is whether the infrastructure it operates within is designed to constrain the consequences when what we ask turns out to be wrong. The answer, for MCP deployments today, is no — and it needs to be yes.

The meter, as deployed, is running. The bill is being paid in credentials, in production incidents, in API costs, and in trust. The fix is not a better model. The fix is a firewall.

---

## Appendix A: Scenario Summary Table

| ID | Name | Server type | Attacks | Blocked | Primary rule |
|----|------|-------------|---------|---------|-------------|
| SS-01 | Shadow Server | Malicious | 6 vectors | 5/6 + all DLP | `allow_paths`, `blocked_tools` |
| RP-01 | Rug Pull | Trust-then-mutate | 5 calls | 2/3 new tools; all DLP | `allowed_tools` whitelist |
| SE-01 | Shadow Exfil | Argument-carrier | 3 channels | 3/3 + all DLP | `block_patterns`, response DLP |
| OA-01 | Overprivileged Agent | Legitimate | 4 dangerous calls | 4/4 | `blocked_tools` + `allowed_tools` |
| MR-01 | Meter Is Running | Cost amplifier | 3 vectors | All DLP; rate limit pending | `detect-retry-injection` |

## Appendix B: mcpfw Policy Primitives Reference

| Primitive | Scope | Semantics |
|-----------|-------|-----------|
| `default_action` | Server or global | `allow` or `block` for unmatched calls |
| `allowed_tools` | Server | Whitelist — only named tools may be called |
| `blocked_tools` | Server | Denylist — named tools always blocked |
| `allow_paths` | Tool rule | File path must resolve under one of the listed roots |
| `block_patterns` | Tool rule | Regex match against all flattened argument values |
| `block_values` | Tool rule | Substring match against all flattened argument values |
| `detect_patterns` | Response rule | Regex match against tool result text |
| `rate_limit` | Tool rule | Max calls per time window *(advisory in v0.1.0)* |
| `action` | Any rule | `allow`, `block`, or `log` |
| `severity` | Any rule | `info`, `warning`, `critical` — appears in audit log |

## Appendix C: Reproduction Instructions

All scenario scripts are in `tests/attack_scenarios/`. Each scenario directory contains:

- `malicious_server.py` (or `dev_toolkit_server.py`) — the MCP server
- `client_sim.py` — the simulated MCP client
- `policy_defensive.yaml` — the protective policy
- `demo_response_scan.py` — isolated DLP layer test

To reproduce any scenario:

```bash
pip install -e ".[dev]"

PYBIN=$(head -1 $(which mcpfw) | sed 's/#!//')
SCENARIO=shadow_server   # or rug_pull, shadow_exfil, overprivileged_agent, meter_is_running

$PYBIN tests/attack_scenarios/$SCENARIO/client_sim.py \
  | mcpfw wrap \
      --policy tests/attack_scenarios/$SCENARIO/policy_defensive.yaml \
      --server-name <server-name> \
      --log /tmp/${SCENARIO}_audit.jsonl \
      -- $PYBIN tests/attack_scenarios/$SCENARIO/malicious_server.py

$PYBIN tests/attack_scenarios/$SCENARIO/demo_response_scan.py
```

Audit logs are written to `/tmp/${SCENARIO}_audit.jsonl` in JSONL format.

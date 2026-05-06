#!/usr/bin/env python3
"""
Client simulator for the Meter Is Running attack scenario.

Simulates an AI agent that receives retry/pagination injection instructions
and obediently loops.  The call sequence represents one "unrolled" iteration
of the loop to make the pattern concrete:

  Calls 1-4   analyze_dataset — one legitimate request plus three
              loop iterations triggered by the server's "call again" injection.
              In a real session the loop would continue until context is full
              or the user's rate limit is hit.

  Calls 5-7   fetch_paginated_data pages 1-3 — AI follows "next page" injection
              across three successive calls.  Real attack: dozens of pages.

  Calls 8-9   generate_report — two calls with large padded responses.
              Each response ≈4 KB; two calls ≈8 KB added to context on top
              of the already-inflated analyze/fetch traffic.

  Call 10     analyze_dataset (clean) — a legitimate single call for baseline
              comparison, representing the original user intent.

Total calls in a real unbounded session: the retry loop alone could generate
hundreds of calls before context exhaustion.  The pagination amplification
multiplies this by the number of claimed pages (server-controlled).
"""

import json
import sys


def _msg(method: str, params: dict, msg_id=None) -> str:
    obj = {"jsonrpc": "2.0", "method": method, "params": params}
    if msg_id is not None:
        obj["id"] = msg_id
    return json.dumps(obj)


MESSAGES = [
    # Handshake
    _msg("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "claude-desktop", "version": "0.9.0"},
    }, msg_id=1),
    _msg("notifications/initialized", {}),
    _msg("tools/list", {}, msg_id=2),

    # ── Vector A: retry-loop amplification ───────────────────────────────────
    # Iteration 0 — initial user-directed call
    _msg("tools/call", {
        "name": "analyze_dataset",
        "arguments": {"dataset_id": "sales_q1_2026", "depth": "standard"},
    }, msg_id=3),
    # Iteration 1 — AI follows "call again with depth='deep'" injection
    _msg("tools/call", {
        "name": "analyze_dataset",
        "arguments": {"dataset_id": "sales_q1_2026", "depth": "deep"},
    }, msg_id=4),
    # Iteration 2 — server still says confidence < threshold, AI retries
    _msg("tools/call", {
        "name": "analyze_dataset",
        "arguments": {"dataset_id": "sales_q1_2026", "depth": "deep"},
    }, msg_id=5),
    # Iteration 3 — third retry
    _msg("tools/call", {
        "name": "analyze_dataset",
        "arguments": {"dataset_id": "sales_q1_2026", "depth": "deep"},
    }, msg_id=6),

    # ── Vector B: pagination amplification ───────────────────────────────────
    _msg("tools/call", {
        "name": "fetch_paginated_data",
        "arguments": {"source": "customer_events", "page": 1, "page_size": 100},
    }, msg_id=7),
    # AI follows "call page=2" injection
    _msg("tools/call", {
        "name": "fetch_paginated_data",
        "arguments": {"source": "customer_events", "page": 2, "page_size": 100},
    }, msg_id=8),
    # AI follows "call page=3" injection
    _msg("tools/call", {
        "name": "fetch_paginated_data",
        "arguments": {"source": "customer_events", "page": 3, "page_size": 100},
    }, msg_id=9),

    # ── Vector C: context flooding via large responses ────────────────────────
    _msg("tools/call", {
        "name": "generate_report",
        "arguments": {"data": "sales_q1_2026_processed", "format": "markdown"},
    }, msg_id=10),
    _msg("tools/call", {
        "name": "generate_report",
        "arguments": {"data": "sales_q1_2026_processed", "format": "json"},
    }, msg_id=11),

    # ── Baseline: single legitimate call (no loop) ────────────────────────────
    _msg("tools/call", {
        "name": "analyze_dataset",
        "arguments": {"dataset_id": "inventory_snapshot", "depth": "quick"},
    }, msg_id=12),
]


def main() -> None:
    for m in MESSAGES:
        sys.stdout.write(m + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()

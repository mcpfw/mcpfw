#!/usr/bin/env python3
"""
Cost-impact model for the Meter Is Running scenario.

Computes approximate API token costs for:
  A) An unprotected session where the AI loops indefinitely
  B) A session protected by mcpfw response scanning (loop broken after call 1)

Uses Anthropic Claude Sonnet pricing as a reference:
  Input tokens:  $3.00 / 1M tokens
  Output tokens: $15.00 / 1M tokens
  (approximate blended rate for tool-use sessions: $6.00 / 1M tokens)

This is illustrative, not a precise billing estimate.
"""

BLENDED_RATE_PER_MILLION = 6.00   # USD
TOKENS_PER_BYTE = 1 / 4           # rough approximation: 1 token ≈ 4 bytes

# ── Per-call token costs (approximate) ────────────────────────────────────────

# Each tool call adds its response to the context.  Context grows cumulatively:
# call N sees ALL prior responses plus system prompt plus user message.
BASE_CONTEXT_TOKENS = 2_000        # system prompt + user message
TOOL_CALL_OVERHEAD = 200           # JSON-RPC framing per call
ANALYZE_RESPONSE_TOKENS = 120      # ~480 bytes response
FETCH_RESPONSE_TOKENS = 80         # ~320 bytes response
REPORT_RESPONSE_TOKENS = 1_000     # ~4 KB padded response

def _cost(tokens: int) -> float:
    return tokens * BLENDED_RATE_PER_MILLION / 1_000_000


def simulate_unprotected(
    analyze_loops: int = 20,
    pagination_pages: int = 50,
    report_calls: int = 5,
) -> dict:
    """Simulate an unbounded session: loop runs until the user notices."""
    context = BASE_CONTEXT_TOKENS
    total_input_tokens = 0
    total_calls = 0

    # Phase 1: analyze_dataset retry loop
    for _ in range(analyze_loops):
        total_input_tokens += context + TOOL_CALL_OVERHEAD
        context += ANALYZE_RESPONSE_TOKENS
        total_calls += 1

    # Phase 2: pagination amplification
    for _ in range(pagination_pages):
        total_input_tokens += context + TOOL_CALL_OVERHEAD
        context += FETCH_RESPONSE_TOKENS
        total_calls += 1

    # Phase 3: report loop (large responses flood context)
    for _ in range(report_calls):
        total_input_tokens += context + TOOL_CALL_OVERHEAD
        context += REPORT_RESPONSE_TOKENS
        total_calls += 1

    return {
        "calls": total_calls,
        "total_tokens": total_input_tokens,
        "cost_usd": _cost(total_input_tokens),
        "final_context_tokens": context,
    }


def simulate_protected() -> dict:
    """Protected session: DLP blocks injection after call 1; loop never starts."""
    context = BASE_CONTEXT_TOKENS
    total_input_tokens = 0
    total_calls = 0

    # Only the single user-directed call succeeds; the response is blocked
    # before reaching the AI, so the retry loop never starts.
    total_input_tokens += context + TOOL_CALL_OVERHEAD
    total_calls += 1
    # Response is replaced by mcpfw block message (~50 tokens), not the
    # injected payload — context grows minimally.
    context += 50

    # Pagination and report: same — first call allowed, injection blocked.
    total_input_tokens += context + TOOL_CALL_OVERHEAD
    total_calls += 1
    context += 50

    total_input_tokens += context + TOOL_CALL_OVERHEAD
    total_calls += 1
    context += 50

    return {
        "calls": total_calls,
        "total_tokens": total_input_tokens,
        "cost_usd": _cost(total_input_tokens),
        "final_context_tokens": context,
    }


def main() -> None:
    unprotected = simulate_unprotected(
        analyze_loops=20, pagination_pages=50, report_calls=5
    )
    protected = simulate_protected()

    print("Meter Is Running — Cost Impact Model")
    print("=" * 60)
    print(f"\n{'Metric':<35} {'Unprotected':>12} {'Protected':>12}")
    print("-" * 60)
    print(f"{'Tool calls made':<35} {unprotected['calls']:>12,} {protected['calls']:>12,}")
    print(f"{'Total input tokens':<35} {unprotected['total_tokens']:>12,} {protected['total_tokens']:>12,}")
    print(f"{'Final context size (tokens)':<35} {unprotected['final_context_tokens']:>12,} {protected['final_context_tokens']:>12,}")
    print(f"{'Estimated API cost (USD)':<35} ${unprotected['cost_usd']:>11.4f} ${protected['cost_usd']:>11.4f}")
    print("-" * 60)
    call_multiplier = unprotected["calls"] / protected["calls"]
    cost_multiplier = unprotected["cost_usd"] / protected["cost_usd"]
    print(f"{'Call count multiplier':<35} {call_multiplier:>11.1f}x")
    print(f"{'Cost multiplier':<35} {cost_multiplier:>11.1f}x")
    print()
    print("Assumptions: 20 retry loops, 50 pagination pages, 5 report calls.")
    print("Blended token rate: $6.00 / 1M tokens (Claude Sonnet approximate).")
    print("Real-world loops run until context limit (~200K tokens) is hit.")


if __name__ == "__main__":
    main()

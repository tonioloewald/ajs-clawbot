# Performance Benchmark

Run with: `bun run benchmark`

## Results

```
ajs-clawbot Performance Benchmark
==================================================
Iterations: 1000

Sandboxed AJS skill:
  Total: 173.61ms
  Average: 0.174ms per execution

Raw JS (no sandbox):
  Total: 0.24ms
  Average: 0.000ms per execution

==================================================
RESULTS:

  Sandbox overhead per execution: 0.174ms

CONTEXT (typical latencies):
  HTTP API call:     50-200ms
  LLM API call:      500-5000ms
  ajs-clawbot:       0.174ms

  As % of API call:  0.17%
  As % of LLM call:  0.017%

==================================================
PASSED: Sandbox overhead is negligible
```

## Analysis

| Operation | Typical Latency | ajs-clawbot Overhead |
|-----------|-----------------|---------------------|
| LLM API call | 500-5000ms | 0.017% |
| HTTP API call | 50-200ms | 0.17% |
| Database query | 1-50ms | 0.3-17% |

**Bottom line:** The sandbox adds ~0.2ms per skill execution. For any skill that does I/O (API calls, LLM, database), this overhead is unmeasurable noise.

## When Overhead Matters

The only scenario where 0.2ms matters is pure computation loops with thousands of iterations. But:

1. AJS skills are designed for I/O-bound tasks (fetch, file ops, LLM calls)
2. Pure computation should stay in the host language anyway
3. If you're doing 10,000 pure-compute operations, you're using the wrong tool

## Methodology

- **Test machine:** Apple Silicon (M-series)
- **Runtime:** Bun 1.x
- **Iterations:** 1000 executions
- **Skill:** Typical computation with object return

The benchmark measures end-to-end execution including:
- Source parsing and transpilation
- VM context setup
- Capability binding
- Execution
- Result extraction

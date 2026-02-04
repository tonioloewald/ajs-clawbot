/**
 * Performance Benchmark for ajs-clawbot
 *
 * Measures overhead of capability-based execution vs raw JS
 *
 * Run with: bun run src/benchmark.ts
 */

import { SafeExecutor } from "./executor/safe-executor.js";

async function benchmark() {
  const executor = new SafeExecutor({ selfIds: ["benchmark"] });

  // Typical skill - computation with object return
  const skill = `
    function compute({ a, b }) {
      let sum = a + b;
      let product = a * b;
      let diff = a - b;
      return { sum: sum, product: product, diff: diff, original: { a: a, b: b } };
    }
  `;

  const iterations = 1000;
  const context = { source: "main" as const, workdir: "/tmp" };

  console.log("ajs-clawbot Performance Benchmark");
  console.log("=".repeat(50));
  console.log(`Iterations: ${iterations}\n`);

  // Benchmark sandboxed skill
  const sandboxStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    await executor.executeSource(skill, "compute", { a: i, b: i + 1 }, context);
  }
  const sandboxTime = performance.now() - sandboxStart;
  const sandboxAvg = sandboxTime / iterations;

  console.log("Sandboxed AJS skill:");
  console.log(`  Total: ${sandboxTime.toFixed(2)}ms`);
  console.log(`  Average: ${sandboxAvg.toFixed(3)}ms per execution\n`);

  // Raw JS comparison
  const rawFn = (a: number, b: number) => {
    const sum = a + b;
    const product = a * b;
    const diff = a - b;
    return { sum, product, diff, original: { a, b } };
  };
  const rawStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    rawFn(i, i + 1);
  }
  const rawTime = performance.now() - rawStart;
  const rawAvg = rawTime / iterations;

  console.log("Raw JS (no sandbox):");
  console.log(`  Total: ${rawTime.toFixed(2)}ms`);
  console.log(`  Average: ${rawAvg.toFixed(3)}ms per execution\n`);

  console.log("=".repeat(50));
  console.log("RESULTS:\n");
  console.log(`  Sandbox overhead per execution: ${sandboxAvg.toFixed(3)}ms\n`);
  console.log("CONTEXT (typical latencies):");
  console.log("  HTTP API call:     50-200ms");
  console.log("  LLM API call:      500-5000ms");
  console.log(`  ajs-clawbot:       ${sandboxAvg.toFixed(3)}ms\n`);

  const pctOfAPI = ((sandboxAvg / 100) * 100).toFixed(2);
  const pctOfLLM = ((sandboxAvg / 1000) * 100).toFixed(3);
  console.log(`  As % of API call:  ${pctOfAPI}%`);
  console.log(`  As % of LLM call:  ${pctOfLLM}%\n`);

  return { sandboxAvgMs: sandboxAvg, rawAvgMs: rawAvg };
}

benchmark().then((results) => {
  if (results.sandboxAvgMs > 5) {
    console.error("FAIL: Execution exceeds 5ms threshold");
    process.exit(1);
  }
  console.log("=".repeat(50));
  console.log("PASSED: Sandbox overhead is negligible");
});

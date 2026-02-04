/**
 * Basic Usage Example
 *
 * Demonstrates how to use ajs-clawbot for safe skill execution.
 * Run with: bun examples/basic-usage.ts
 */

import {
  SafeExecutor,
  createCapabilitySet,
  createMockLLM,
  type ExecutionContext
} from '../src'

async function main() {
  console.log('=== ajs-clawbot Basic Usage Example ===\n')

  // Create executor with tracing enabled
  const executor = new SafeExecutor({
    trace: true,
    onBeforeExecute: (skill, context) => {
      console.log(`Executing skill: ${skill.manifest.name}`)
      console.log(`  Trust level: ${skill.trustLevel}`)
      console.log(`  Source: ${context.source}`)
    },
    onAfterExecute: (skill, context, result) => {
      console.log(`  Success: ${result.success}`)
      console.log(`  Fuel used: ${result.fuelUsed}`)
      console.log(`  Duration: ${result.durationMs}ms`)
      if (result.warnings?.length) {
        console.log(`  Warnings: ${result.warnings.join(', ')}`)
      }
    },
    onTrustDenied: (skill, context, reason) => {
      console.log(`  BLOCKED: ${reason}`)
    }
  })

  // Example 1: Pure computation skill (no capabilities needed)
  console.log('\n--- Example 1: Calculator (trust: none) ---')
  const calcResult = await executor.executeSource(
    `function calculate({ operation, a, b }) {
      if (operation === 'add') return { result: a + b }
      if (operation === 'multiply') return { result: a * b }
      return { error: 'Unknown operation' }
    }`,
    'calculator',
    { operation: 'multiply', a: 7, b: 6 },
    { source: 'public', workdir: '/tmp' }
  )
  console.log('Result:', calcResult.result)

  // Example 2: Same skill from public source (should work - it's compute only)
  console.log('\n--- Example 2: Calculator from public source ---')
  const publicCalc = await executor.executeSource(
    `function add({ a, b }) { return { sum: a + b } }`,
    'public-calc',
    { a: 100, b: 200 },
    { source: 'public', workdir: '/tmp' },
    'none' // Explicit trust level
  )
  console.log('Result:', publicCalc.result)

  // Example 3: Skill that needs LLM but called from public source (should be blocked)
  console.log('\n--- Example 3: LLM skill from public source (should be blocked) ---')
  const blockedResult = await executor.executeSource(
    `function summarize({ text }) {
      let summary = llmPredict({ prompt: 'Summarize: ' + text })
      return { summary }
    }`,
    'summarizer',
    { text: 'Hello world' },
    { source: 'public', workdir: '/tmp' },
    'llm' // Requires LLM trust
  )
  console.log('Blocked:', !blockedResult.success)
  console.log('Error:', blockedResult.error?.message)

  // Example 4: Same LLM skill from main session (should work)
  console.log('\n--- Example 4: LLM skill from main session ---')
  const mockLLM = createMockLLM((prompt) => {
    if (prompt.includes('Summarize')) {
      return 'This is a mock summary of the provided text.'
    }
    return 'Mock response'
  })

  const llmResult = await executor.executeSource(
    `function summarize({ text }) {
      let summary = llmPredict({ prompt: 'Summarize: ' + text })
      return { summary: summary }
    }`,
    'summarizer',
    { text: 'This is a long document about the history of computing...' },
    {
      source: 'main',
      workdir: '/tmp',
      llmPredict: mockLLM.predict,
    },
    'llm'
  )
  console.log('Result:', llmResult.result)

  // Example 5: Demonstrate fuel exhaustion
  console.log('\n--- Example 5: Fuel exhaustion ---')
  const exhaustedResult = await executor.executeSource(
    `function infiniteLoop({ n }) {
      let i = 0
      while (i < 1000000) {
        i = i + 1
      }
      return { iterations: i }
    }`,
    'infinite',
    { n: 1 },
    { source: 'main', workdir: '/tmp' },
    'none'
  )
  console.log('Completed:', exhaustedResult.success)
  console.log('Fuel used:', exhaustedResult.fuelUsed)
  if (exhaustedResult.error) {
    console.log('Error:', exhaustedResult.error.message?.slice(0, 80) + '...')
  }

  console.log('\n=== Examples complete ===')
}

main().catch(console.error)

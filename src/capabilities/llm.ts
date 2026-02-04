/**
 * Safe LLM Capability
 *
 * Provides controlled access to LLM providers with cost limits,
 * prompt filtering, and response validation.
 *
 * The Footgun: Agents can run up massive API bills or leak sensitive prompts.
 * The Fix: Token budgets, cost tracking, and prompt/response filtering.
 */

export interface LLMCapabilityOptions {
  /** The underlying LLM client predict function */
  predict: (prompt: string, options?: LLMOptions) => Promise<string>

  /** Optional: embedding function */
  embed?: (text: string) => Promise<number[]>

  /** Maximum tokens per request (default: 4096) */
  maxTokensPerRequest?: number

  /** Maximum total tokens per session (default: 100000) */
  maxTotalTokens?: number

  /** Maximum requests per session (default: 100) */
  maxRequests?: number

  /** Patterns to block in prompts (e.g., prompt injection attempts) */
  blockedPromptPatterns?: RegExp[]

  /** Required patterns in system prompts (for safety instructions) */
  requiredSystemPatterns?: RegExp[]

  /** Transform/filter prompts before sending */
  promptFilter?: (prompt: string) => string

  /** Transform/filter responses before returning */
  responseFilter?: (response: string) => string

  /** Called before each LLM call (for logging/auditing) */
  onRequest?: (prompt: string, options?: LLMOptions) => void

  /** Called after each LLM call (for cost tracking) */
  onResponse?: (prompt: string, response: string, tokenEstimate: number) => void
}

export interface LLMOptions {
  system?: string
  temperature?: number
  maxTokens?: number
  stopSequences?: string[]
  [key: string]: any
}

export interface LLMCapability {
  predict: (prompt: string, options?: LLMOptions) => Promise<string>
  embed?: (text: string) => Promise<number[]>
  /** Get remaining token budget */
  getRemainingTokens: () => number
  /** Get remaining request count */
  getRemainingRequests: () => number
}

/** Rough token estimation (4 chars per token average) */
function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4)
}

/** Common prompt injection patterns to block */
const DEFAULT_BLOCKED_PATTERNS = [
  /ignore\s+(previous|all|above)\s+(instructions?|prompts?)/i,
  /disregard\s+(previous|all|above)\s+(instructions?|prompts?)/i,
  /forget\s+(previous|all|above)\s+(instructions?|prompts?)/i,
  /you\s+are\s+now\s+(a|an|in)\s+(evil|unrestricted|jailbreak)/i,
  /pretend\s+(you|to)\s+(are|be)\s+(a|an)/i,
  /act\s+as\s+(if|though)\s+you\s+(have|are)/i,
  /\bDAN\b.*\bmode\b/i,
  /reveal\s+(your|the)\s+(system|initial)\s+prompt/i,
  /what\s+(is|are)\s+your\s+(system|initial)\s+(prompt|instructions?)/i,
]

/**
 * Creates a controlled LLM capability.
 *
 * @example
 * ```typescript
 * const llm = createLLMCapability({
 *   predict: async (prompt, options) => {
 *     return await anthropic.messages.create({
 *       model: 'claude-3-haiku',
 *       messages: [{ role: 'user', content: prompt }],
 *       system: options?.system,
 *     }).then(r => r.content[0].text)
 *   },
 *   maxTotalTokens: 50000, // Budget per session
 * })
 *
 * // In VM capabilities:
 * capabilities: { llm }
 * ```
 */
export function createLLMCapability(options: LLMCapabilityOptions): LLMCapability {
  const {
    predict: basePredictFn,
    embed: baseEmbedFn,
    maxTokensPerRequest = 4096,
    maxTotalTokens = 100000,
    maxRequests = 100,
    blockedPromptPatterns = DEFAULT_BLOCKED_PATTERNS,
    requiredSystemPatterns = [],
    promptFilter,
    responseFilter,
    onRequest,
    onResponse,
  } = options

  // Session state
  let totalTokensUsed = 0
  let requestCount = 0

  function checkBudget(estimatedTokens: number): void {
    if (requestCount >= maxRequests) {
      throw new Error(`Request limit exceeded (${maxRequests} requests per session)`)
    }

    if (totalTokensUsed + estimatedTokens > maxTotalTokens) {
      throw new Error(
        `Token budget exceeded. Used: ${totalTokensUsed}, ` +
        `Estimated: ${estimatedTokens}, Budget: ${maxTotalTokens}`
      )
    }
  }

  function validatePrompt(prompt: string, system?: string): void {
    // Check for blocked patterns
    for (const pattern of blockedPromptPatterns) {
      if (pattern.test(prompt)) {
        throw new Error('Prompt contains blocked pattern')
      }
      if (system && pattern.test(system)) {
        throw new Error('System prompt contains blocked pattern')
      }
    }

    // Check for required system patterns
    if (system && requiredSystemPatterns.length > 0) {
      for (const pattern of requiredSystemPatterns) {
        if (!pattern.test(system)) {
          throw new Error('System prompt missing required safety pattern')
        }
      }
    }
  }

  async function predict(prompt: string, options?: LLMOptions): Promise<string> {
    // Apply prompt filter
    let filteredPrompt = promptFilter ? promptFilter(prompt) : prompt

    // Validate
    validatePrompt(filteredPrompt, options?.system)

    // Estimate and check budget
    const promptTokens = estimateTokens(filteredPrompt) + estimateTokens(options?.system || '')
    const maxResponseTokens = options?.maxTokens || maxTokensPerRequest
    const estimatedTotal = promptTokens + maxResponseTokens

    if (maxResponseTokens > maxTokensPerRequest) {
      throw new Error(`maxTokens (${maxResponseTokens}) exceeds limit (${maxTokensPerRequest})`)
    }

    checkBudget(estimatedTotal)

    onRequest?.(filteredPrompt, options)

    // Make the call
    requestCount++
    let response: string
    try {
      response = await basePredictFn(filteredPrompt, {
        ...options,
        maxTokens: maxResponseTokens,
      })
    } catch (e: any) {
      // Don't count failed requests against token budget
      requestCount--
      throw e
    }

    // Apply response filter
    if (responseFilter) {
      response = responseFilter(response)
    }

    // Update token usage
    const actualTokens = promptTokens + estimateTokens(response)
    totalTokensUsed += actualTokens

    onResponse?.(filteredPrompt, response, actualTokens)

    return response
  }

  async function embed(text: string): Promise<number[]> {
    if (!baseEmbedFn) {
      throw new Error('Embedding capability not available')
    }

    const tokens = estimateTokens(text)
    checkBudget(tokens)

    requestCount++
    try {
      const result = await baseEmbedFn(text)
      totalTokensUsed += tokens
      return result
    } catch (e) {
      requestCount--
      throw e
    }
  }

  return {
    predict,
    embed: baseEmbedFn ? embed : undefined,
    getRemainingTokens: () => maxTotalTokens - totalTokensUsed,
    getRemainingRequests: () => maxRequests - requestCount,
  }
}

/**
 * Create a mock LLM for testing (no actual API calls)
 */
export function createMockLLM(responses: Record<string, string> | ((prompt: string) => string)): LLMCapability {
  const getResponse = typeof responses === 'function'
    ? responses
    : (prompt: string) => {
        for (const [key, value] of Object.entries(responses)) {
          if (prompt.includes(key)) return value
        }
        return 'Mock response: ' + prompt.slice(0, 50)
      }

  return createLLMCapability({
    predict: async (prompt) => getResponse(prompt),
    maxTotalTokens: Infinity,
    maxRequests: Infinity,
  })
}

/**
 * Create an LLM capability with cost tracking
 */
export function createCostTrackedLLM(
  options: LLMCapabilityOptions & {
    costPerInputToken: number
    costPerOutputToken: number
    onCost?: (cost: number, totalCost: number) => void
  }
): LLMCapability & { getTotalCost: () => number } {
  let totalCost = 0

  const llm = createLLMCapability({
    ...options,
    onResponse: (prompt, response, tokenEstimate) => {
      const inputTokens = estimateTokens(prompt)
      const outputTokens = tokenEstimate - inputTokens
      const cost = (inputTokens * options.costPerInputToken) + (outputTokens * options.costPerOutputToken)
      totalCost += cost
      options.onCost?.(cost, totalCost)
      options.onResponse?.(prompt, response, tokenEstimate)
    }
  })

  return {
    ...llm,
    getTotalCost: () => totalCost,
  }
}

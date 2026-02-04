/**
 * Safe Fetch Capability
 *
 * Instead of giving agents unrestricted network access, this provides
 * a fetch capability with domain allowlisting, rate limiting, and SSRF protection.
 *
 * The Footgun: Agents can SSRF internal services, exfiltrate data, or DDoS.
 * The Fix: Agents can only fetch from domains you've explicitly allowed,
 * with rate limits and size restrictions.
 */

export interface FetchCapabilityOptions {
  /** Allowed domains/hosts. Supports wildcards like '*.example.com' */
  allowedHosts: string[]

  /** Blocked hosts (take precedence). Defaults include private IP ranges. */
  blockedHosts?: string[]

  /** Allowed URL schemes (default: ['https']). Set to ['https', 'http'] to allow HTTP. */
  allowedSchemes?: string[]

  /** Maximum response size in bytes (default: 10MB) */
  maxResponseSize?: number

  /** Request timeout in ms (default: 30000) */
  timeout?: number

  /** Rate limit: max requests per minute (default: 60) */
  rateLimit?: number

  /** Headers to add to all requests (e.g., User-Agent) */
  defaultHeaders?: Record<string, string>

  /** Headers to block from being set by agents */
  blockedHeaders?: string[]

  /** Called before each fetch (for logging/auditing) */
  onRequest?: (url: string, init?: RequestInit) => void

  /** Called after each fetch */
  onResponse?: (url: string, status: number, size: number) => void
}

export type FetchCapability = (url: string, init?: RequestInit) => Promise<Response>

/** Default blocked hosts - private IP ranges and localhost */
const DEFAULT_BLOCKED_HOSTS = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '169.254.*', // Link-local
  '10.*',      // Private Class A
  '172.16.*', '172.17.*', '172.18.*', '172.19.*',
  '172.20.*', '172.21.*', '172.22.*', '172.23.*',
  '172.24.*', '172.25.*', '172.26.*', '172.27.*',
  '172.28.*', '172.29.*', '172.30.*', '172.31.*', // Private Class B
  '192.168.*', // Private Class C
  'metadata.google.internal',
  '169.254.169.254', // Cloud metadata endpoints
]

/** Headers that agents shouldn't be able to set */
const DEFAULT_BLOCKED_HEADERS = [
  'host',
  'authorization', // Let the capability add this, not the agent
  'cookie',
  'x-forwarded-for',
  'x-real-ip',
]

/**
 * Creates a restricted fetch capability.
 *
 * @example
 * ```typescript
 * const fetch = createFetchCapability({
 *   allowedHosts: ['api.example.com', '*.cdn.example.com'],
 *   rateLimit: 30, // 30 requests per minute
 * })
 *
 * // In VM capabilities:
 * capabilities: { fetch }
 * ```
 */
export function createFetchCapability(options: FetchCapabilityOptions): FetchCapability {
  const {
    allowedHosts,
    blockedHosts = DEFAULT_BLOCKED_HOSTS,
    allowedSchemes = ['https'],
    maxResponseSize = 10 * 1024 * 1024,
    timeout = 30000,
    rateLimit = 60,
    defaultHeaders = {},
    blockedHeaders = DEFAULT_BLOCKED_HEADERS,
    onRequest,
    onResponse,
  } = options

  // Rate limiting state
  const requestTimes: number[] = []

  function checkRateLimit(): void {
    const now = Date.now()
    const windowStart = now - 60000 // 1 minute window

    // Remove old entries
    while (requestTimes.length > 0 && requestTimes[0] < windowStart) {
      requestTimes.shift()
    }

    if (requestTimes.length >= rateLimit) {
      const oldestRequest = requestTimes[0]
      const waitTime = Math.ceil((oldestRequest + 60000 - now) / 1000)
      throw new Error(`Rate limit exceeded. Try again in ${waitTime} seconds.`)
    }

    requestTimes.push(now)
  }

  function matchesPattern(host: string, pattern: string): boolean {
    if (pattern.startsWith('*.')) {
      // Wildcard: *.example.com matches foo.example.com, bar.example.com
      const suffix = pattern.slice(1) // .example.com
      return host.endsWith(suffix) || host === pattern.slice(2)
    }
    if (pattern.endsWith('.*')) {
      // IP wildcard: 10.* matches 10.0.0.1
      const prefix = pattern.slice(0, -1)
      return host.startsWith(prefix)
    }
    return host === pattern
  }

  function isHostAllowed(host: string): boolean {
    // Check blocked first
    for (const pattern of blockedHosts) {
      if (matchesPattern(host, pattern)) {
        return false
      }
    }

    // Then check allowed
    for (const pattern of allowedHosts) {
      if (matchesPattern(host, pattern)) {
        return true
      }
    }

    return false
  }

  function validateUrl(urlString: string): URL {
    let url: URL
    try {
      url = new URL(urlString)
    } catch {
      throw new Error(`Invalid URL: ${urlString}`)
    }

    // Check scheme
    const scheme = url.protocol.replace(':', '')
    if (!allowedSchemes.includes(scheme)) {
      throw new Error(`URL scheme not allowed: ${scheme}. Allowed: ${allowedSchemes.join(', ')}`)
    }

    // Check host
    const host = url.hostname
    if (!isHostAllowed(host)) {
      throw new Error(`Host not allowed: ${host}`)
    }

    return url
  }

  function sanitizeHeaders(init?: RequestInit): Headers {
    const headers = new Headers(defaultHeaders)

    if (init?.headers) {
      const inputHeaders = new Headers(init.headers)
      for (const [key, value] of inputHeaders.entries()) {
        if (!blockedHeaders.includes(key.toLowerCase())) {
          headers.set(key, value)
        }
      }
    }

    return headers
  }

  return async function safeFetch(url: string, init?: RequestInit): Promise<Response> {
    // Validate URL
    const validatedUrl = validateUrl(url)

    // Check rate limit
    checkRateLimit()

    // Sanitize headers
    const headers = sanitizeHeaders(init)

    // Build fetch options
    const fetchInit: RequestInit = {
      ...init,
      headers,
      signal: AbortSignal.timeout(timeout),
    }

    // Don't allow redirect to blocked hosts
    fetchInit.redirect = 'manual'

    onRequest?.(url, fetchInit)

    // Make the request
    const response = await fetch(validatedUrl.toString(), fetchInit)

    // Handle redirects manually to validate target
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location')
      if (location) {
        // Validate redirect target
        try {
          const redirectUrl = new URL(location, validatedUrl)
          validateUrl(redirectUrl.toString())
          // Recursively follow (will decrement from rate limit)
          return safeFetch(redirectUrl.toString(), init)
        } catch (e: any) {
          throw new Error(`Redirect to blocked URL: ${location}`)
        }
      }
    }

    // Check response size via Content-Length header
    const contentLength = response.headers.get('content-length')
    if (contentLength && parseInt(contentLength, 10) > maxResponseSize) {
      throw new Error(`Response too large: ${contentLength} bytes (max: ${maxResponseSize})`)
    }

    onResponse?.(url, response.status, parseInt(contentLength || '0', 10))

    // Wrap response to enforce size limit during streaming
    return new Response(
      new ReadableStream({
        start: async (controller) => {
          const reader = response.body?.getReader()
          if (!reader) {
            controller.close()
            return
          }

          let totalSize = 0
          try {
            while (true) {
              const { done, value } = await reader.read()
              if (done) break

              totalSize += value.length
              if (totalSize > maxResponseSize) {
                controller.error(new Error(`Response exceeded maximum size (${maxResponseSize} bytes)`))
                reader.cancel()
                return
              }

              controller.enqueue(value)
            }
            controller.close()
          } catch (e) {
            controller.error(e)
          }
        }
      }),
      {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      }
    )
  }
}

/**
 * Preset: Public API access (common API hosts)
 */
export function createPublicApiCapability(additionalHosts: string[] = []): FetchCapability {
  return createFetchCapability({
    allowedHosts: [
      'api.github.com',
      'api.openai.com',
      'api.anthropic.com',
      'api.weather.gov',
      '*.wikipedia.org',
      'api.dictionaryapi.dev',
      ...additionalHosts,
    ],
  })
}

/**
 * Create a fetch capability that requires request signing/authentication
 */
export function createAuthenticatedFetch(
  baseFetch: FetchCapability,
  getAuth: () => Promise<{ header: string; value: string }>
): FetchCapability {
  return async (url: string, init?: RequestInit) => {
    const auth = await getAuth()
    const headers = new Headers(init?.headers)
    headers.set(auth.header, auth.value)
    return baseFetch(url, { ...init, headers })
  }
}

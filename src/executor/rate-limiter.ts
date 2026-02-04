/**
 * Rate Limiter and Flood Protection
 *
 * Protects against:
 * 1. Self-triggered recursion (bot messaging itself causing infinite loops)
 * 2. Per-requester flooding (single user spamming requests)
 * 3. Global flooding (DDoS-style attacks from multiple sources)
 *
 * All protections use sliding window rate limiting with configurable thresholds.
 */

export interface RateLimiterOptions {
  /**
   * Bot's own user IDs - messages from these are ALWAYS rejected.
   * This prevents recursion attacks where the bot triggers itself.
   */
  selfIds: string[];

  /**
   * Per-requester limits
   */
  perRequester: {
    /** Max requests per window (default: 10) */
    maxRequests: number;
    /** Window size in ms (default: 60000 = 1 minute) */
    windowMs: number;
    /** Max concurrent requests per requester (default: 2) */
    maxConcurrent: number;
  };

  /**
   * Global limits (across all requesters)
   */
  global: {
    /** Max requests per window (default: 100) */
    maxRequests: number;
    /** Window size in ms (default: 60000 = 1 minute) */
    windowMs: number;
    /** Max concurrent requests globally (default: 10) */
    maxConcurrent: number;
  };

  /**
   * Cooldown after hitting rate limit (default: 30000ms = 30 seconds)
   * During cooldown, ALL requests from the offending requester are rejected.
   */
  cooldownMs?: number;

  /**
   * Called when a request is rejected (for logging)
   */
  onRejected?: (
    reason: RejectionReason,
    requesterId: string,
    details: string
  ) => void;
}

export type RejectionReason =
  | "self_message" // Bot's own message (recursion prevention)
  | "requester_rate_limit" // Single requester exceeded rate limit
  | "requester_concurrent" // Single requester has too many concurrent requests
  | "requester_cooldown" // Requester is in cooldown after hitting limit
  | "global_rate_limit" // Global rate limit exceeded
  | "global_concurrent"; // Too many concurrent requests globally

export interface RateLimitResult {
  allowed: boolean;
  reason?: RejectionReason;
  retryAfterMs?: number;
}

interface RequesterState {
  /** Timestamps of requests in the current window */
  requests: number[];
  /** Currently running requests */
  concurrent: number;
  /** Cooldown end time (if in cooldown) */
  cooldownUntil?: number;
}

/**
 * Sliding window rate limiter with self-message rejection
 */
export class RateLimiter {
  private selfIds: Set<string>;
  private perRequester: RateLimiterOptions["perRequester"];
  private global: RateLimiterOptions["global"];
  private cooldownMs: number;
  private onRejected?: RateLimiterOptions["onRejected"];

  /** Per-requester state */
  private requesterState: Map<string, RequesterState> = new Map();

  /** Global request timestamps */
  private globalRequests: number[] = [];

  /** Global concurrent count */
  private globalConcurrent: number = 0;

  constructor(options: RateLimiterOptions) {
    this.selfIds = new Set(options.selfIds.map((id) => id.toLowerCase()));
    this.perRequester = options.perRequester;
    this.global = options.global;
    this.cooldownMs = options.cooldownMs ?? 30000;
    this.onRejected = options.onRejected;
  }

  /**
   * Check if a request should be allowed
   *
   * @param requesterId - Unique identifier for the requester
   * @returns Whether the request is allowed and reason if not
   */
  check(requesterId: string): RateLimitResult {
    const now = Date.now();
    const normalizedId = requesterId.toLowerCase();

    // 1. ALWAYS reject self-messages (recursion prevention)
    if (this.selfIds.has(normalizedId)) {
      this.onRejected?.("self_message", requesterId, "Bot's own message");
      return { allowed: false, reason: "self_message" };
    }

    // 2. Check requester cooldown
    const state = this.getRequesterState(normalizedId);
    if (state.cooldownUntil && now < state.cooldownUntil) {
      const retryAfterMs = state.cooldownUntil - now;
      this.onRejected?.(
        "requester_cooldown",
        requesterId,
        `Cooldown for ${retryAfterMs}ms`
      );
      return { allowed: false, reason: "requester_cooldown", retryAfterMs };
    }

    // 3. Check requester concurrent limit
    if (state.concurrent >= this.perRequester.maxConcurrent) {
      this.onRejected?.(
        "requester_concurrent",
        requesterId,
        `${state.concurrent} concurrent requests`
      );
      return { allowed: false, reason: "requester_concurrent" };
    }

    // 4. Check requester rate limit (sliding window)
    this.pruneOldRequests(state.requests, this.perRequester.windowMs, now);
    if (state.requests.length >= this.perRequester.maxRequests) {
      // Put requester in cooldown
      state.cooldownUntil = now + this.cooldownMs;
      const oldestInWindow = state.requests[0];
      const retryAfterMs = oldestInWindow + this.perRequester.windowMs - now;
      this.onRejected?.(
        "requester_rate_limit",
        requesterId,
        `${state.requests.length} requests in window, cooldown activated`
      );
      return { allowed: false, reason: "requester_rate_limit", retryAfterMs };
    }

    // 5. Check global concurrent limit
    if (this.globalConcurrent >= this.global.maxConcurrent) {
      this.onRejected?.(
        "global_concurrent",
        requesterId,
        `${this.globalConcurrent} global concurrent requests`
      );
      return { allowed: false, reason: "global_concurrent" };
    }

    // 6. Check global rate limit (sliding window)
    this.pruneOldRequests(this.globalRequests, this.global.windowMs, now);
    if (this.globalRequests.length >= this.global.maxRequests) {
      const oldestInWindow = this.globalRequests[0];
      const retryAfterMs = oldestInWindow + this.global.windowMs - now;
      this.onRejected?.(
        "global_rate_limit",
        requesterId,
        `${this.globalRequests.length} global requests in window`
      );
      return { allowed: false, reason: "global_rate_limit", retryAfterMs };
    }

    return { allowed: true };
  }

  /**
   * Record the start of a request (call after check() returns allowed: true)
   */
  recordStart(requesterId: string): void {
    const now = Date.now();
    const normalizedId = requesterId.toLowerCase();
    const state = this.getRequesterState(normalizedId);

    state.requests.push(now);
    state.concurrent++;

    this.globalRequests.push(now);
    this.globalConcurrent++;
  }

  /**
   * Record the end of a request (call when request completes or fails)
   */
  recordEnd(requesterId: string): void {
    const normalizedId = requesterId.toLowerCase();
    const state = this.requesterState.get(normalizedId);

    if (state && state.concurrent > 0) {
      state.concurrent--;
    }

    if (this.globalConcurrent > 0) {
      this.globalConcurrent--;
    }
  }

  /**
   * Add a self ID (e.g., when bot creates a new identity)
   */
  addSelfId(id: string): void {
    this.selfIds.add(id.toLowerCase());
  }

  /**
   * Remove a self ID
   */
  removeSelfId(id: string): void {
    this.selfIds.delete(id.toLowerCase());
  }

  /**
   * Check if an ID is registered as a self ID
   */
  isSelfId(id: string): boolean {
    return this.selfIds.has(id.toLowerCase());
  }

  /**
   * Get current stats for monitoring
   */
  getStats(): {
    globalConcurrent: number;
    globalRequestsInWindow: number;
    requesterCount: number;
    requestersInCooldown: number;
  } {
    const now = Date.now();
    this.pruneOldRequests(this.globalRequests, this.global.windowMs, now);

    let requestersInCooldown = 0;
    for (const state of this.requesterState.values()) {
      if (state.cooldownUntil && now < state.cooldownUntil) {
        requestersInCooldown++;
      }
    }

    return {
      globalConcurrent: this.globalConcurrent,
      globalRequestsInWindow: this.globalRequests.length,
      requesterCount: this.requesterState.size,
      requestersInCooldown,
    };
  }

  /**
   * Clear all state (for testing or reset)
   */
  reset(): void {
    this.requesterState.clear();
    this.globalRequests = [];
    this.globalConcurrent = 0;
  }

  /**
   * Clear cooldown for a specific requester
   */
  clearCooldown(requesterId: string): void {
    const state = this.requesterState.get(requesterId.toLowerCase());
    if (state) {
      state.cooldownUntil = undefined;
    }
  }

  private getRequesterState(normalizedId: string): RequesterState {
    let state = this.requesterState.get(normalizedId);
    if (!state) {
      state = { requests: [], concurrent: 0 };
      this.requesterState.set(normalizedId, state);
    }
    return state;
  }

  private pruneOldRequests(
    requests: number[],
    windowMs: number,
    now: number
  ): void {
    const cutoff = now - windowMs;
    while (requests.length > 0 && requests[0] < cutoff) {
      requests.shift();
    }
  }
}

/**
 * Create a rate limiter with sensible defaults for a public-facing bot
 */
export function createDefaultRateLimiter(
  selfIds: string[],
  options?: Partial<RateLimiterOptions>
): RateLimiter {
  return new RateLimiter({
    selfIds,
    perRequester: {
      maxRequests: 10,
      windowMs: 60000, // 1 minute
      maxConcurrent: 2,
      ...options?.perRequester,
    },
    global: {
      maxRequests: 100,
      windowMs: 60000, // 1 minute
      maxConcurrent: 10,
      ...options?.global,
    },
    cooldownMs: options?.cooldownMs ?? 30000,
    onRejected: options?.onRejected,
  });
}

/**
 * Create a strict rate limiter for high-security environments
 */
export function createStrictRateLimiter(
  selfIds: string[],
  onRejected?: RateLimiterOptions["onRejected"]
): RateLimiter {
  return new RateLimiter({
    selfIds,
    perRequester: {
      maxRequests: 5,
      windowMs: 60000,
      maxConcurrent: 1,
    },
    global: {
      maxRequests: 30,
      windowMs: 60000,
      maxConcurrent: 5,
    },
    cooldownMs: 60000, // 1 minute cooldown
    onRejected,
  });
}

/**
 * Token bucket rate limiter for more bursty workloads
 * Allows short bursts while maintaining average rate
 */
export class TokenBucketLimiter {
  private selfIds: Set<string>;
  private buckets: Map<string, { tokens: number; lastRefill: number }> =
    new Map();
  private globalBucket: { tokens: number; lastRefill: number };

  constructor(
    private options: {
      selfIds: string[];
      /** Max tokens per requester (burst capacity) */
      maxTokens: number;
      /** Tokens added per second */
      refillRate: number;
      /** Global max tokens */
      globalMaxTokens: number;
      /** Global refill rate */
      globalRefillRate: number;
      onRejected?: RateLimiterOptions["onRejected"];
    }
  ) {
    this.selfIds = new Set(options.selfIds.map((id) => id.toLowerCase()));
    this.globalBucket = {
      tokens: options.globalMaxTokens,
      lastRefill: Date.now(),
    };
  }

  check(requesterId: string): RateLimitResult {
    const normalizedId = requesterId.toLowerCase();

    // Always reject self-messages
    if (this.selfIds.has(normalizedId)) {
      this.options.onRejected?.(
        "self_message",
        requesterId,
        "Bot's own message"
      );
      return { allowed: false, reason: "self_message" };
    }

    // Check and refill global bucket
    this.refillBucket(this.globalBucket, this.options.globalRefillRate, this.options.globalMaxTokens);
    if (this.globalBucket.tokens < 1) {
      this.options.onRejected?.(
        "global_rate_limit",
        requesterId,
        "Global token bucket empty"
      );
      return { allowed: false, reason: "global_rate_limit" };
    }

    // Check and refill requester bucket
    let bucket = this.buckets.get(normalizedId);
    if (!bucket) {
      bucket = { tokens: this.options.maxTokens, lastRefill: Date.now() };
      this.buckets.set(normalizedId, bucket);
    }
    this.refillBucket(bucket, this.options.refillRate, this.options.maxTokens);

    if (bucket.tokens < 1) {
      this.options.onRejected?.(
        "requester_rate_limit",
        requesterId,
        "Requester token bucket empty"
      );
      return { allowed: false, reason: "requester_rate_limit" };
    }

    return { allowed: true };
  }

  consume(requesterId: string): void {
    const normalizedId = requesterId.toLowerCase();
    const bucket = this.buckets.get(normalizedId);
    if (bucket) {
      bucket.tokens = Math.max(0, bucket.tokens - 1);
    }
    this.globalBucket.tokens = Math.max(0, this.globalBucket.tokens - 1);
  }

  private refillBucket(
    bucket: { tokens: number; lastRefill: number },
    refillRate: number,
    maxTokens: number
  ): void {
    const now = Date.now();
    const elapsed = (now - bucket.lastRefill) / 1000;
    const tokensToAdd = elapsed * refillRate;
    bucket.tokens = Math.min(maxTokens, bucket.tokens + tokensToAdd);
    bucket.lastRefill = now;
  }

  addSelfId(id: string): void {
    this.selfIds.add(id.toLowerCase());
  }

  reset(): void {
    this.buckets.clear();
    this.globalBucket = {
      tokens: this.options.globalMaxTokens,
      lastRefill: Date.now(),
    };
  }
}

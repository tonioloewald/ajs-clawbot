/**
 * Tests for Rate Limiter and Flood Protection
 */

import { describe, it, expect, beforeEach } from "bun:test";
import {
  RateLimiter,
  TokenBucketLimiter,
  createDefaultRateLimiter,
  createStrictRateLimiter,
} from "./rate-limiter";

describe("RateLimiter", () => {
  describe("self-message rejection", () => {
    it("should always reject messages from self IDs", () => {
      const limiter = new RateLimiter({
        selfIds: ["bot-id-123", "Bot-ID-456"],
        perRequester: { maxRequests: 100, windowMs: 60000, maxConcurrent: 10 },
        global: { maxRequests: 1000, windowMs: 60000, maxConcurrent: 100 },
      });

      // Exact match
      const result1 = limiter.check("bot-id-123");
      expect(result1.allowed).toBe(false);
      expect(result1.reason).toBe("self_message");

      // Case-insensitive
      const result2 = limiter.check("BOT-ID-123");
      expect(result2.allowed).toBe(false);
      expect(result2.reason).toBe("self_message");

      // Second ID
      const result3 = limiter.check("bot-id-456");
      expect(result3.allowed).toBe(false);
      expect(result3.reason).toBe("self_message");
    });

    it("should allow adding new self IDs at runtime", () => {
      const limiter = new RateLimiter({
        selfIds: ["bot-1"],
        perRequester: { maxRequests: 100, windowMs: 60000, maxConcurrent: 10 },
        global: { maxRequests: 1000, windowMs: 60000, maxConcurrent: 100 },
      });

      // Initially allowed
      expect(limiter.check("bot-2").allowed).toBe(true);

      // Add new self ID
      limiter.addSelfId("bot-2");

      // Now rejected
      expect(limiter.check("bot-2").allowed).toBe(false);
      expect(limiter.check("bot-2").reason).toBe("self_message");
    });

    it("should check if ID is a self ID", () => {
      const limiter = new RateLimiter({
        selfIds: ["bot-1"],
        perRequester: { maxRequests: 100, windowMs: 60000, maxConcurrent: 10 },
        global: { maxRequests: 1000, windowMs: 60000, maxConcurrent: 100 },
      });

      expect(limiter.isSelfId("bot-1")).toBe(true);
      expect(limiter.isSelfId("BOT-1")).toBe(true);
      expect(limiter.isSelfId("user-1")).toBe(false);
    });
  });

  describe("per-requester rate limiting", () => {
    it("should allow requests within the limit", () => {
      const limiter = new RateLimiter({
        selfIds: [],
        perRequester: { maxRequests: 5, windowMs: 60000, maxConcurrent: 10 },
        global: { maxRequests: 1000, windowMs: 60000, maxConcurrent: 100 },
      });

      for (let i = 0; i < 5; i++) {
        const result = limiter.check("user-1");
        expect(result.allowed).toBe(true);
        limiter.recordStart("user-1");
        limiter.recordEnd("user-1");
      }
    });

    it("should reject requests exceeding the limit", () => {
      const limiter = new RateLimiter({
        selfIds: [],
        perRequester: { maxRequests: 3, windowMs: 60000, maxConcurrent: 10 },
        global: { maxRequests: 1000, windowMs: 60000, maxConcurrent: 100 },
      });

      // First 3 should be allowed
      for (let i = 0; i < 3; i++) {
        expect(limiter.check("user-1").allowed).toBe(true);
        limiter.recordStart("user-1");
        limiter.recordEnd("user-1");
      }

      // 4th should be rejected
      const result = limiter.check("user-1");
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("requester_rate_limit");
    });

    it("should track different users separately", () => {
      const limiter = new RateLimiter({
        selfIds: [],
        perRequester: { maxRequests: 2, windowMs: 60000, maxConcurrent: 10 },
        global: { maxRequests: 1000, windowMs: 60000, maxConcurrent: 100 },
      });

      // User 1 hits limit
      for (let i = 0; i < 2; i++) {
        limiter.check("user-1");
        limiter.recordStart("user-1");
        limiter.recordEnd("user-1");
      }
      expect(limiter.check("user-1").allowed).toBe(false);

      // User 2 should still be allowed
      expect(limiter.check("user-2").allowed).toBe(true);
    });

    it("should enforce concurrent limit", () => {
      const limiter = new RateLimiter({
        selfIds: [],
        perRequester: { maxRequests: 100, windowMs: 60000, maxConcurrent: 2 },
        global: { maxRequests: 1000, windowMs: 60000, maxConcurrent: 100 },
      });

      // Start 2 concurrent requests
      limiter.check("user-1");
      limiter.recordStart("user-1");
      limiter.check("user-1");
      limiter.recordStart("user-1");

      // 3rd concurrent should be rejected
      const result = limiter.check("user-1");
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("requester_concurrent");

      // End one request
      limiter.recordEnd("user-1");

      // Now should be allowed
      expect(limiter.check("user-1").allowed).toBe(true);
    });
  });

  describe("global rate limiting", () => {
    it("should reject when global limit is exceeded", () => {
      const limiter = new RateLimiter({
        selfIds: [],
        perRequester: { maxRequests: 100, windowMs: 60000, maxConcurrent: 10 },
        global: { maxRequests: 5, windowMs: 60000, maxConcurrent: 100 },
      });

      // Exhaust global limit with different users
      for (let i = 0; i < 5; i++) {
        expect(limiter.check(`user-${i}`).allowed).toBe(true);
        limiter.recordStart(`user-${i}`);
        limiter.recordEnd(`user-${i}`);
      }

      // 6th request from new user should be rejected
      const result = limiter.check("user-new");
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("global_rate_limit");
    });

    it("should enforce global concurrent limit", () => {
      const limiter = new RateLimiter({
        selfIds: [],
        perRequester: { maxRequests: 100, windowMs: 60000, maxConcurrent: 10 },
        global: { maxRequests: 1000, windowMs: 60000, maxConcurrent: 3 },
      });

      // Start 3 concurrent requests from different users
      for (let i = 0; i < 3; i++) {
        limiter.check(`user-${i}`);
        limiter.recordStart(`user-${i}`);
      }

      // 4th concurrent should be rejected
      const result = limiter.check("user-new");
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("global_concurrent");
    });
  });

  describe("cooldown", () => {
    it("should put requester in cooldown after hitting rate limit", () => {
      const limiter = new RateLimiter({
        selfIds: [],
        perRequester: { maxRequests: 2, windowMs: 60000, maxConcurrent: 10 },
        global: { maxRequests: 1000, windowMs: 60000, maxConcurrent: 100 },
        cooldownMs: 1000,
      });

      // Hit rate limit
      for (let i = 0; i < 2; i++) {
        limiter.check("user-1");
        limiter.recordStart("user-1");
        limiter.recordEnd("user-1");
      }

      // Trigger cooldown
      const limitResult = limiter.check("user-1");
      expect(limitResult.allowed).toBe(false);
      expect(limitResult.reason).toBe("requester_rate_limit");

      // Subsequent request should be in cooldown
      const cooldownResult = limiter.check("user-1");
      expect(cooldownResult.allowed).toBe(false);
      expect(cooldownResult.reason).toBe("requester_cooldown");
      expect(cooldownResult.retryAfterMs).toBeGreaterThan(0);
    });

    it("should allow clearing cooldown manually", () => {
      const limiter = new RateLimiter({
        selfIds: [],
        perRequester: { maxRequests: 1, windowMs: 60000, maxConcurrent: 10 },
        global: { maxRequests: 1000, windowMs: 60000, maxConcurrent: 100 },
        cooldownMs: 60000,
      });

      // Hit rate limit and trigger cooldown
      limiter.check("user-1");
      limiter.recordStart("user-1");
      limiter.recordEnd("user-1");
      limiter.check("user-1"); // This triggers cooldown

      // Verify in cooldown
      expect(limiter.check("user-1").reason).toBe("requester_cooldown");

      // Clear cooldown
      limiter.clearCooldown("user-1");

      // Should now get rate_limit instead of cooldown (still rate limited, but not in cooldown)
      const result = limiter.check("user-1");
      expect(result.reason).toBe("requester_rate_limit");
    });
  });

  describe("stats and monitoring", () => {
    it("should provide accurate stats", () => {
      const limiter = new RateLimiter({
        selfIds: [],
        perRequester: { maxRequests: 10, windowMs: 60000, maxConcurrent: 5 },
        global: { maxRequests: 100, windowMs: 60000, maxConcurrent: 20 },
      });

      // Start some requests
      limiter.check("user-1");
      limiter.recordStart("user-1");
      limiter.check("user-2");
      limiter.recordStart("user-2");
      limiter.check("user-3");
      limiter.recordStart("user-3");

      const stats = limiter.getStats();
      expect(stats.globalConcurrent).toBe(3);
      expect(stats.globalRequestsInWindow).toBe(3);
      expect(stats.requesterCount).toBe(3);
      expect(stats.requestersInCooldown).toBe(0);
    });

    it("should reset all state", () => {
      const limiter = new RateLimiter({
        selfIds: ["bot-1"],
        perRequester: { maxRequests: 1, windowMs: 60000, maxConcurrent: 1 },
        global: { maxRequests: 100, windowMs: 60000, maxConcurrent: 100 },
      });

      // Use up limit
      limiter.check("user-1");
      limiter.recordStart("user-1");

      // Reset
      limiter.reset();

      // Stats should be zero
      const stats = limiter.getStats();
      expect(stats.globalConcurrent).toBe(0);
      expect(stats.globalRequestsInWindow).toBe(0);
      expect(stats.requesterCount).toBe(0);

      // But self IDs should still work
      expect(limiter.check("bot-1").allowed).toBe(false);
    });
  });

  describe("callback notifications", () => {
    it("should call onRejected for blocked requests", () => {
      const rejections: { reason: string; requesterId: string }[] = [];

      const limiter = new RateLimiter({
        selfIds: ["bot-1"],
        perRequester: { maxRequests: 1, windowMs: 60000, maxConcurrent: 10 },
        global: { maxRequests: 100, windowMs: 60000, maxConcurrent: 100 },
        onRejected: (reason, requesterId) => {
          rejections.push({ reason, requesterId });
        },
      });

      // Self-message rejection
      limiter.check("bot-1");
      expect(rejections).toContainEqual({
        reason: "self_message",
        requesterId: "bot-1",
      });

      // Rate limit rejection
      limiter.check("user-1");
      limiter.recordStart("user-1");
      limiter.recordEnd("user-1");
      limiter.check("user-1");

      expect(rejections).toContainEqual({
        reason: "requester_rate_limit",
        requesterId: "user-1",
      });
    });
  });
});

describe("TokenBucketLimiter", () => {
  it("should reject self-messages", () => {
    const limiter = new TokenBucketLimiter({
      selfIds: ["bot-1"],
      maxTokens: 10,
      refillRate: 1,
      globalMaxTokens: 100,
      globalRefillRate: 10,
    });

    const result = limiter.check("bot-1");
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("self_message");
  });

  it("should allow bursts up to maxTokens", () => {
    const limiter = new TokenBucketLimiter({
      selfIds: [],
      maxTokens: 5,
      refillRate: 1,
      globalMaxTokens: 100,
      globalRefillRate: 10,
    });

    // Should allow 5 rapid requests
    for (let i = 0; i < 5; i++) {
      expect(limiter.check("user-1").allowed).toBe(true);
      limiter.consume("user-1");
    }

    // 6th should fail
    expect(limiter.check("user-1").allowed).toBe(false);
    expect(limiter.check("user-1").reason).toBe("requester_rate_limit");
  });

  it("should respect global token bucket", () => {
    const limiter = new TokenBucketLimiter({
      selfIds: [],
      maxTokens: 100,
      refillRate: 10,
      globalMaxTokens: 3,
      globalRefillRate: 1,
    });

    // Exhaust global bucket with different users
    for (let i = 0; i < 3; i++) {
      expect(limiter.check(`user-${i}`).allowed).toBe(true);
      limiter.consume(`user-${i}`);
    }

    // 4th should fail due to global limit
    expect(limiter.check("user-new").allowed).toBe(false);
    expect(limiter.check("user-new").reason).toBe("global_rate_limit");
  });
});

describe("factory functions", () => {
  it("createDefaultRateLimiter should create limiter with sensible defaults", () => {
    const limiter = createDefaultRateLimiter(["bot-1", "bot-2"]);

    // Self messages blocked
    expect(limiter.check("bot-1").allowed).toBe(false);
    expect(limiter.check("bot-2").allowed).toBe(false);

    // Regular users allowed
    expect(limiter.check("user-1").allowed).toBe(true);
  });

  it("createStrictRateLimiter should create limiter with strict limits", () => {
    const limiter = createStrictRateLimiter(["bot-1"]);

    // Only 1 concurrent request allowed per user in strict mode
    limiter.check("user-1");
    limiter.recordStart("user-1");

    const result = limiter.check("user-1");
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("requester_concurrent");
  });
});

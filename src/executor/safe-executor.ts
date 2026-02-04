/**
 * Safe Skill Executor
 *
 * The main entry point for executing OpenClaw skills safely.
 * This replaces OpenClaw's default execution with tjs-lang's AgentVM.
 *
 * Includes protection against:
 * - Self-triggered recursion (bot messaging itself)
 * - Per-requester flooding
 * - Global flooding (DDoS)
 */

import { AgentVM, type Capabilities, type RunResult } from "tjs-lang";
import {
  type TrustLevel,
  type TrustLevelConfig,
  type TrustContext,
  getCapabilitiesForTrustLevel,
  validateTrustForSource,
} from "./trust-levels";
import {
  type LoadedSkill,
  loadSkill,
  loadSkillFromSource,
  validateSkill,
} from "./skill-loader";
import {
  RateLimiter,
  createDefaultRateLimiter,
  type RateLimiterOptions,
  type RejectionReason,
} from "./rate-limiter";

export interface ExecutionContext {
  /** Source of the request: main session, DM, group, or public */
  source: "main" | "dm" | "group" | "public";

  /** User ID or identifier for the requester */
  userId?: string;

  /** Channel/conversation ID */
  channelId?: string;

  /** Working directory for this execution */
  workdir: string;

  /** Allowed network hosts */
  allowedHosts?: string[];

  /** LLM predict function */
  llmPredict?: (prompt: string, options?: any) => Promise<string>;

  /** LLM embed function */
  llmEmbed?: (text: string) => Promise<number[]>;

  /** Writable directories (relative to workdir) */
  writableDirs?: string[];

  /** Additional shell commands to allow */
  additionalCommands?: any[];

  /** Request metadata (passed to agent as context) */
  metadata?: Record<string, any>;
}

export interface ExecutionResult {
  /** The result returned by the skill */
  result: any;

  /** Error if execution failed */
  error?: Error;

  /** Fuel consumed by execution */
  fuelUsed: number;

  /** Execution trace (if enabled) */
  trace?: any[];

  /** Warnings generated during execution */
  warnings?: string[];

  /** Whether execution was successful */
  success: boolean;

  /** Execution duration in ms */
  durationMs: number;

  /** Rate limit rejection reason (if rejected before execution) */
  rateLimitReason?: RejectionReason;

  /** Retry after (ms) if rate limited */
  retryAfterMs?: number;
}

export interface SafeExecutorOptions {
  /** Default fuel budget */
  defaultFuel?: number;

  /** Default timeout in ms */
  defaultTimeoutMs?: number;

  /** Enable execution tracing */
  trace?: boolean;

  /**
   * Bot's own user IDs - requests from these are ALWAYS rejected.
   * This prevents recursion attacks where the bot triggers itself.
   * REQUIRED for public-facing bots.
   */
  selfIds?: string[];

  /**
   * Rate limiter configuration. If selfIds is provided but rateLimiter is not,
   * a default rate limiter will be created.
   */
  rateLimiter?: RateLimiterOptions;

  /** Called before each execution */
  onBeforeExecute?: (
    skill: LoadedSkill,
    context: ExecutionContext,
    args: any
  ) => void;

  /** Called after each execution */
  onAfterExecute?: (
    skill: LoadedSkill,
    context: ExecutionContext,
    result: ExecutionResult
  ) => void;

  /** Called when a skill is blocked due to trust level */
  onTrustDenied?: (
    skill: LoadedSkill,
    context: ExecutionContext,
    reason: string
  ) => void;

  /** Called when a request is rate limited */
  onRateLimited?: (
    context: ExecutionContext,
    reason: RejectionReason,
    retryAfterMs?: number
  ) => void;

  /** Custom capability overrides by skill name */
  skillCapabilityOverrides?: Record<string, Partial<Capabilities>>;

  /** Custom trust level overrides by skill name */
  skillTrustOverrides?: Record<string, TrustLevel>;
}

/**
 * SafeExecutor - Drop-in replacement for OpenClaw's skill execution
 *
 * @example
 * ```typescript
 * const executor = new SafeExecutor({
 *   defaultFuel: 1000,
 *   trace: true,
 * })
 *
 * // Load and execute a skill
 * const result = await executor.execute(
 *   '/path/to/skill',
 *   { query: 'hello world' },
 *   {
 *     source: 'dm',
 *     workdir: '/app/workspace',
 *     llmPredict: myLLMClient.predict,
 *   }
 * )
 * ```
 */
export class SafeExecutor {
  private vm: AgentVM<{}>;
  private options: SafeExecutorOptions;
  private skillCache: Map<string, LoadedSkill> = new Map();
  private rateLimiter: RateLimiter | null = null;

  constructor(options: SafeExecutorOptions = {}) {
    this.vm = new AgentVM();
    this.options = {
      defaultFuel: 1000,
      defaultTimeoutMs: 30000,
      trace: false,
      ...options,
    };

    // Initialize rate limiter if selfIds provided
    if (options.selfIds && options.selfIds.length > 0) {
      if (options.rateLimiter) {
        this.rateLimiter = new RateLimiter({
          ...options.rateLimiter,
          selfIds: options.selfIds,
        });
      } else {
        this.rateLimiter = createDefaultRateLimiter(options.selfIds, {
          onRejected: (reason, requesterId, details) => {
            console.warn(
              `[SafeExecutor] Rate limited: ${reason} - ${requesterId} - ${details}`
            );
          },
        });
      }
    }
  }

  /**
   * Execute a skill by path
   */
  async execute(
    skillPath: string,
    args: Record<string, any>,
    context: ExecutionContext
  ): Promise<ExecutionResult> {
    const startTime = Date.now();

    // Load skill (with caching)
    let skill: LoadedSkill;
    if (this.skillCache.has(skillPath)) {
      skill = this.skillCache.get(skillPath)!;
    } else {
      skill = loadSkill(skillPath);
      this.skillCache.set(skillPath, skill);
    }

    return this.executeSkill(skill, args, context, startTime);
  }

  /**
   * Execute a skill from source code
   */
  async executeSource(
    source: string,
    name: string,
    args: Record<string, any>,
    context: ExecutionContext,
    trustLevel?: TrustLevel
  ): Promise<ExecutionResult> {
    const startTime = Date.now();
    const skill = loadSkillFromSource(source, name, { trustLevel });
    return this.executeSkill(skill, args, context, startTime);
  }

  /**
   * Execute a pre-loaded skill
   */
  async executeSkill(
    skill: LoadedSkill,
    args: Record<string, any>,
    context: ExecutionContext,
    startTime: number = Date.now()
  ): Promise<ExecutionResult> {
    // Check rate limits FIRST (before any other processing)
    if (this.rateLimiter && context.userId) {
      const rateLimitCheck = this.rateLimiter.check(context.userId);
      if (!rateLimitCheck.allowed) {
        this.options.onRateLimited?.(
          context,
          rateLimitCheck.reason!,
          rateLimitCheck.retryAfterMs
        );
        return {
          result: undefined,
          error: new Error("Request rejected"),
          fuelUsed: 0,
          success: false,
          durationMs: Date.now() - startTime,
          rateLimitReason: rateLimitCheck.reason,
          retryAfterMs: rateLimitCheck.retryAfterMs,
        };
      }
      // Record the start of this request
      this.rateLimiter.recordStart(context.userId);
    }

    // Track whether we need to record end (for finally block)
    const shouldRecordEnd = this.rateLimiter && context.userId;

    try {
      return await this._executeSkillInternal(skill, args, context, startTime);
    } finally {
      if (shouldRecordEnd) {
        this.rateLimiter!.recordEnd(context.userId!);
      }
    }
  }

  /**
   * Internal skill execution (after rate limit check)
   */
  private async _executeSkillInternal(
    skill: LoadedSkill,
    args: Record<string, any>,
    context: ExecutionContext,
    startTime: number
  ): Promise<ExecutionResult> {
    // Validate skill
    const validation = validateSkill(skill);
    if (!validation.valid) {
      return {
        result: undefined,
        error: new Error(
          `Skill validation failed: ${validation.errors.join(", ")}`
        ),
        fuelUsed: 0,
        success: false,
        durationMs: Date.now() - startTime,
      };
    }

    // Check trust level override
    const effectiveTrustLevel =
      this.options.skillTrustOverrides?.[skill.manifest.name] ||
      skill.trustLevel;

    // Validate trust level for source
    const trustValidation = validateTrustForSource(
      effectiveTrustLevel,
      context.source
    );
    if (!trustValidation.allowed) {
      this.options.onTrustDenied?.(skill, context, trustValidation.reason!);
      return {
        result: undefined,
        error: new Error(trustValidation.reason),
        fuelUsed: 0,
        success: false,
        durationMs: Date.now() - startTime,
      };
    }

    // Build capabilities
    const trustContext: TrustContext = {
      workdir: context.workdir,
      allowedHosts: context.allowedHosts,
      llmPredict: context.llmPredict,
      llmEmbed: context.llmEmbed,
      writableDirs: context.writableDirs,
      additionalCommands: context.additionalCommands,
    };

    const { capabilities, fuel, timeoutMs } = getCapabilitiesForTrustLevel(
      { level: effectiveTrustLevel },
      trustContext
    );

    // Apply skill-specific capability overrides
    const overrides =
      this.options.skillCapabilityOverrides?.[skill.manifest.name];
    const finalCapabilities = overrides
      ? { ...capabilities, ...overrides }
      : capabilities;

    // Notify before execution
    this.options.onBeforeExecute?.(skill, context, args);

    // Execute in VM
    let vmResult: RunResult;
    try {
      vmResult = await this.vm.run(skill.ast, args, {
        fuel: this.options.defaultFuel ?? fuel,
        timeoutMs: this.options.defaultTimeoutMs ?? timeoutMs,
        capabilities: finalCapabilities,
        trace: this.options.trace,
        context: {
          source: context.source,
          userId: context.userId,
          channelId: context.channelId,
          ...context.metadata,
        },
      });
    } catch (e: any) {
      const result: ExecutionResult = {
        result: undefined,
        error: e,
        fuelUsed: 0,
        success: false,
        durationMs: Date.now() - startTime,
      };
      this.options.onAfterExecute?.(skill, context, result);
      return result;
    }

    const result: ExecutionResult = {
      result: vmResult.result,
      error: vmResult.error,
      fuelUsed: vmResult.fuelUsed,
      trace: vmResult.trace,
      warnings: vmResult.warnings,
      success: !vmResult.error,
      durationMs: Date.now() - startTime,
    };

    this.options.onAfterExecute?.(skill, context, result);
    return result;
  }

  /**
   * Clear the skill cache (useful when skills are updated)
   */
  clearCache(): void {
    this.skillCache.clear();
  }

  /**
   * Remove a specific skill from cache
   */
  invalidateSkill(skillPath: string): void {
    this.skillCache.delete(skillPath);
  }

  /**
   * Get the underlying VM instance (for advanced usage)
   */
  getVM(): AgentVM<{}> {
    return this.vm;
  }

  /**
   * Get the rate limiter instance (for monitoring/management)
   */
  getRateLimiter(): RateLimiter | null {
    return this.rateLimiter;
  }

  /**
   * Add a self ID to the rate limiter (e.g., when bot gets a new identity)
   */
  addSelfId(id: string): void {
    this.rateLimiter?.addSelfId(id);
  }

  /**
   * Check if an ID is registered as a self ID
   */
  isSelfId(id: string): boolean {
    return this.rateLimiter?.isSelfId(id) ?? false;
  }

  /**
   * Get rate limiter stats for monitoring
   */
  getRateLimitStats(): {
    globalConcurrent: number;
    globalRequestsInWindow: number;
    requesterCount: number;
    requestersInCooldown: number;
  } | null {
    return this.rateLimiter?.getStats() ?? null;
  }

  /**
   * Clear rate limiter cooldown for a specific user (admin action)
   */
  clearUserCooldown(userId: string): void {
    this.rateLimiter?.clearCooldown(userId);
  }
}

/**
 * Create a pre-configured executor for OpenClaw integration
 */
export function createOpenClawExecutor(options: {
  workspaceRoot: string;
  /** Bot's own user IDs - REQUIRED for public-facing bots */
  selfIds?: string[];
  llmPredict?: (prompt: string, options?: any) => Promise<string>;
  allowedHosts?: string[];
  defaultTrustLevel?: TrustLevel;
  onExecute?: (skill: string, result: ExecutionResult) => void;
  onRateLimited?: (userId: string, reason: RejectionReason) => void;
}): SafeExecutor {
  return new SafeExecutor({
    defaultFuel: 1000,
    defaultTimeoutMs: 30000,
    trace: true,
    selfIds: options.selfIds,
    onAfterExecute: (skill, context, result) => {
      options.onExecute?.(skill.manifest.name, result);

      // Log execution for auditing
      console.log(`[SafeExecutor] ${skill.manifest.name}:`, {
        success: result.success,
        fuelUsed: result.fuelUsed,
        durationMs: result.durationMs,
        source: context.source,
        warnings: result.warnings,
      });
    },
    onTrustDenied: (skill, context, reason) => {
      console.warn(
        `[SafeExecutor] Trust denied for ${skill.manifest.name}:`,
        reason
      );
    },
    onRateLimited: (context, reason, retryAfterMs) => {
      console.warn(
        `[SafeExecutor] Rate limited ${context.userId}:`,
        reason,
        retryAfterMs ? `retry after ${retryAfterMs}ms` : ""
      );
      if (context.userId) {
        options.onRateLimited?.(context.userId, reason);
      }
    },
  });
}

/**
 * Middleware-style wrapper for existing OpenClaw skill execution
 *
 * This can wrap the existing execution to add safety checks even if
 * the skill isn't converted to AJS yet.
 */
export function createSafetyMiddleware(executor: SafeExecutor) {
  return async function safeExecute(
    skillFn: () => Promise<any>,
    skillName: string,
    context: ExecutionContext
  ): Promise<any> {
    // For non-AJS skills, we can at least enforce trust levels
    // and provide audit logging
    const validation = validateTrustForSource("shell", context.source);
    if (!validation.allowed) {
      throw new Error(`Skill ${skillName} blocked: ${validation.reason}`);
    }

    console.warn(
      `[SafetyMiddleware] Executing non-AJS skill ${skillName}. ` +
        `Consider converting to AJS for full sandboxing.`
    );

    const startTime = Date.now();
    try {
      const result = await skillFn();
      console.log(
        `[SafetyMiddleware] ${skillName} completed in ${
          Date.now() - startTime
        }ms`
      );
      return result;
    } catch (e) {
      console.error(`[SafetyMiddleware] ${skillName} failed:`, e);
      throw e;
    }
  };
}

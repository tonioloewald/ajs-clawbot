/**
 * ajs-clawbot: Safe Execution Layer for OpenClaw/Clawbot
 *
 * This package provides capability-based security for AI agent execution,
 * designed as a drop-in safety layer for OpenClaw and similar agent frameworks.
 *
 * Key Features:
 * - Zero capabilities by default (agents can't do anything unless you allow it)
 * - Capability injection (you control what each agent can access)
 * - Fuel metering (bounded compute prevents infinite loops)
 * - Trust levels (automatic capability matching based on skill requirements)
 * - Audit trails (full execution tracing for accountability)
 *
 * @example
 * ```typescript
 * import { SafeExecutor, createCapabilitySet } from 'ajs-clawbot'
 *
 * const executor = new SafeExecutor()
 *
 * const result = await executor.execute(
 *   './skills/weather',
 *   { city: 'Seattle' },
 *   {
 *     source: 'dm',
 *     workdir: '/app/workspace',
 *     allowedHosts: ['api.weather.gov'],
 *   }
 * )
 * ```
 */

// Re-export from tjs-lang for convenience
export {
  AgentVM,
  ajs,
  transpile,
  type Capabilities,
  type RunResult,
} from "tjs-lang";

// Capabilities
export {
  // Shell
  createShellCapability,
  type ShellCapability,
  type ShellCapabilityOptions,
  type ShellCommand,
  READ_ONLY_SHELL,
  GIT_READ_ONLY,
  NPM_READ_ONLY,

  // Filesystem
  createFilesystemCapability,
  type FilesystemCapability,
  type FilesystemCapabilityOptions,
  createSourceReadOnly,
  createWorkspaceCapability,

  // Fetch
  createFetchCapability,
  type FetchCapability,
  type FetchCapabilityOptions,
  createPublicApiCapability,
  createAuthenticatedFetch,

  // LLM
  createLLMCapability,
  type LLMCapability,
  type LLMCapabilityOptions,
  type LLMOptions,
  createMockLLM,
  createCostTrackedLLM,

  // Unified
  createCapabilitySet,
  type CapabilitySetOptions,
  createReadOnlyCapabilities,
  createComputeOnlyCapabilities,
  createChatCapabilities,
  type SecurityLevel,
  getSecurityDefaults,

  // Security utilities (for integration)
  BLOCKED_FILE_PATTERNS,
  DANGEROUS_PATH_PATTERNS,
  DANGEROUS_ENV_VARS,
  DANGEROUS_ENV_PREFIXES,
  BLOCKED_HOSTNAMES,
  BLOCKED_HOSTNAME_SUFFIXES,
  CLOUD_METADATA_IPS,
  isBlocked as isBlockedPath,
  isDangerousEnvVar,
  sanitizeEnv,
  isBlockedHostname,
  isPrivateIP,
  isCloudMetadataIP,
  type BlockedPattern,
  type DangerousPattern,

  // Process utilities
  killProcessTree,
  terminateProcessTree,
  safeSpawn,
  isProcessRunning,
  type SafeSpawnOptions,
  type SafeSpawnResult,
} from "./capabilities/index.js";

// Executor
export {
  SafeExecutor,
  type SafeExecutorOptions,
  type ExecutionContext,
  type ExecutionResult,
  createOpenClawExecutor,
  createSafetyMiddleware,
} from "./executor/safe-executor.js";

// Trust Levels
export {
  type TrustLevel,
  type TrustLevelConfig,
  type TrustContext,
  getCapabilitiesForTrustLevel,
  inferTrustLevel,
  validateTrustForSource,
} from "./executor/trust-levels.js";

// Skill Loading
export {
  loadSkill,
  loadSkillFromSource,
  validateSkill,
  type LoadedSkill,
  type SkillManifest,
} from "./executor/skill-loader.js";

// Rate Limiting & Flood Protection
export {
  RateLimiter,
  TokenBucketLimiter,
  createDefaultRateLimiter,
  createStrictRateLimiter,
  type RateLimiterOptions,
  type RateLimitResult,
  type RejectionReason,
} from "./executor/rate-limiter.js";

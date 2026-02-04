/**
 * Trust Levels for Skills
 *
 * Different skills need different levels of access. A weather lookup skill
 * needs fetch but not shell. A code formatter needs filesystem but not network.
 *
 * Trust levels provide preset capability configurations that match common
 * use cases, making it easy to grant appropriate access without thinking
 * through every capability individually.
 */

import type { Capabilities } from "tjs-lang";
import {
  createCapabilitySet,
  createShellCapability,
  createFilesystemCapability,
  createFetchCapability,
  createLLMCapability,
  READ_ONLY_SHELL,
  GIT_READ_ONLY,
  type ShellCapabilityOptions,
  type FilesystemCapabilityOptions,
  type FetchCapabilityOptions,
  type LLMCapabilityOptions,
} from "../capabilities/index.js";

/**
 * Trust level definitions
 *
 * Each level builds on the previous, granting more access.
 * Choose the MINIMUM level required for the skill to function.
 */
export type TrustLevel =
  | "none" // Pure computation only
  | "network" // Can fetch from allowed hosts
  | "read" // Can read allowed files
  | "llm" // Can call LLM APIs
  | "write" // Can write to allowed locations
  | "shell" // Can run allowed shell commands
  | "full"; // Full access (use sparingly, for trusted skills only)

export interface TrustLevelConfig {
  /** Base trust level */
  level: TrustLevel;

  /** Override/extend shell config */
  shell?: Partial<ShellCapabilityOptions> | false;

  /** Override/extend filesystem config */
  filesystem?: Partial<FilesystemCapabilityOptions> | false;

  /** Override/extend fetch config */
  fetch?: Partial<FetchCapabilityOptions> | false;

  /** Override/extend LLM config */
  llm?: Partial<LLMCapabilityOptions> | false;

  /** Fuel budget for this skill */
  fuel?: number;

  /** Timeout in ms */
  timeoutMs?: number;
}

export interface TrustContext {
  /** Working directory / project root */
  workdir: string;

  /** Allowed network hosts */
  allowedHosts?: string[];

  /** LLM predict function (if LLM access is needed) */
  llmPredict?: (prompt: string, options?: any) => Promise<string>;

  /** LLM embed function (optional) */
  llmEmbed?: (text: string) => Promise<number[]>;

  /** Directories that are writable (relative to workdir) */
  writableDirs?: string[];

  /** Additional shell commands to allow */
  additionalCommands?: ShellCapabilityOptions["allowlist"];
}

/**
 * Get capabilities for a trust level
 */
export function getCapabilitiesForTrustLevel(
  config: TrustLevelConfig,
  context: TrustContext
): { capabilities: Capabilities; fuel: number; timeoutMs: number } {
  const {
    level,
    fuel = getDefaultFuel(level),
    timeoutMs = getDefaultTimeout(level),
  } = config;

  let capabilities: Capabilities = {};

  switch (level) {
    case "none":
      // No capabilities - pure computation
      break;

    case "network":
      // Fetch only
      if (config.fetch !== false) {
        capabilities.fetch = createFetchCapability({
          allowedHosts: context.allowedHosts || [],
          ...config.fetch,
        });
      }
      break;

    case "read":
      // Fetch + read-only filesystem
      if (config.fetch !== false && context.allowedHosts?.length) {
        capabilities.fetch = createFetchCapability({
          allowedHosts: context.allowedHosts,
          ...config.fetch,
        });
      }
      if (config.filesystem !== false) {
        const fs = createFilesystemCapability({
          root: context.workdir,
          allowWrite: false,
          ...config.filesystem,
        });
        capabilities.files = fs;
      }
      break;

    case "llm":
      // Fetch + read + LLM
      if (config.fetch !== false && context.allowedHosts?.length) {
        capabilities.fetch = createFetchCapability({
          allowedHosts: context.allowedHosts,
          ...config.fetch,
        });
      }
      if (config.filesystem !== false) {
        capabilities.files = createFilesystemCapability({
          root: context.workdir,
          allowWrite: false,
          ...config.filesystem,
        });
      }
      if (config.llm !== false && context.llmPredict) {
        const llm = createLLMCapability({
          predict: context.llmPredict,
          embed: context.llmEmbed,
          ...config.llm,
        });
        capabilities.llm = {
          predict: llm.predict,
          embed: llm.embed,
        };
      }
      break;

    case "write":
      // Fetch + read/write + LLM
      if (config.fetch !== false && context.allowedHosts?.length) {
        capabilities.fetch = createFetchCapability({
          allowedHosts: context.allowedHosts,
          ...config.fetch,
        });
      }
      if (config.filesystem !== false) {
        capabilities.files = createFilesystemCapability({
          root: context.workdir,
          allowWrite: true,
          allowCreate: true,
          ...config.filesystem,
        });
      }
      if (config.llm !== false && context.llmPredict) {
        const llm = createLLMCapability({
          predict: context.llmPredict,
          embed: context.llmEmbed,
          ...config.llm,
        });
        capabilities.llm = {
          predict: llm.predict,
          embed: llm.embed,
        };
      }
      break;

    case "shell":
      // Everything above + limited shell
      if (config.fetch !== false && context.allowedHosts?.length) {
        capabilities.fetch = createFetchCapability({
          allowedHosts: context.allowedHosts,
          ...config.fetch,
        });
      }
      if (config.filesystem !== false) {
        capabilities.files = createFilesystemCapability({
          root: context.workdir,
          allowWrite: true,
          allowCreate: true,
          ...config.filesystem,
        });
      }
      if (config.llm !== false && context.llmPredict) {
        const llm = createLLMCapability({
          predict: context.llmPredict,
          embed: context.llmEmbed,
          ...config.llm,
        });
        capabilities.llm = {
          predict: llm.predict,
          embed: llm.embed,
        };
      }
      if (config.shell !== false) {
        capabilities.shell = createShellCapability({
          workdir: context.workdir,
          allowlist: [
            ...READ_ONLY_SHELL,
            ...GIT_READ_ONLY,
            ...(context.additionalCommands || []),
          ],
          ...config.shell,
        });
      }
      break;

    case "full":
      // Full access - use with caution
      console.warn(
        'Warning: Using "full" trust level grants extensive system access'
      );
      if (config.fetch !== false) {
        capabilities.fetch = createFetchCapability({
          allowedHosts: context.allowedHosts || ["*"],
          ...config.fetch,
        });
      }
      if (config.filesystem !== false) {
        capabilities.files = createFilesystemCapability({
          root: context.workdir,
          allowWrite: true,
          allowCreate: true,
          allowDelete: true,
          ...config.filesystem,
        });
      }
      if (config.llm !== false && context.llmPredict) {
        const llm = createLLMCapability({
          predict: context.llmPredict,
          embed: context.llmEmbed,
          maxTotalTokens: 1000000, // Higher limit for full trust
          ...config.llm,
        });
        capabilities.llm = {
          predict: llm.predict,
          embed: llm.embed,
        };
      }
      if (config.shell !== false) {
        // Even "full" doesn't mean unrestricted shell - still uses allowlist
        capabilities.shell = createShellCapability({
          workdir: context.workdir,
          allowlist: [
            ...READ_ONLY_SHELL,
            ...GIT_READ_ONLY,
            // Add more commands for full trust
            { binary: "npm", argPatterns: [/^[a-z\-]+$/] },
            { binary: "bun", argPatterns: [/^[a-z\-]+$/] },
            { binary: "node", argPatterns: [/^[a-zA-Z0-9_\-\.\/]+\.js$/] },
            ...(context.additionalCommands || []),
          ],
          ...config.shell,
        });
      }
      break;
  }

  return { capabilities, fuel, timeoutMs };
}

function getDefaultFuel(level: TrustLevel): number {
  switch (level) {
    case "none":
      return 100;
    case "network":
      return 500;
    case "read":
      return 500;
    case "llm":
      return 2000;
    case "write":
      return 1000;
    case "shell":
      return 2000;
    case "full":
      return 5000;
  }
}

function getDefaultTimeout(level: TrustLevel): number {
  switch (level) {
    case "none":
      return 5000;
    case "network":
      return 30000;
    case "read":
      return 15000;
    case "llm":
      return 120000;
    case "write":
      return 30000;
    case "shell":
      return 60000;
    case "full":
      return 300000;
  }
}

/**
 * Infer minimum required trust level from skill capabilities used
 */
export function inferTrustLevel(usedCapabilities: string[]): TrustLevel {
  const caps = new Set(usedCapabilities.map((c) => c.toLowerCase()));

  if (caps.has("shell") || caps.has("exec") || caps.has("spawn")) {
    return "shell";
  }
  if (
    caps.has("write") ||
    caps.has("writefile") ||
    caps.has("mkdir") ||
    caps.has("delete")
  ) {
    return "write";
  }
  if (
    caps.has("llm") ||
    caps.has("predict") ||
    caps.has("embed") ||
    caps.has("ai")
  ) {
    return "llm";
  }
  if (
    caps.has("read") ||
    caps.has("readfile") ||
    caps.has("files") ||
    caps.has("fs")
  ) {
    return "read";
  }
  if (
    caps.has("fetch") ||
    caps.has("http") ||
    caps.has("network") ||
    caps.has("request")
  ) {
    return "network";
  }

  return "none";
}

/**
 * Validate that a trust level is appropriate for the message source
 */
export function validateTrustForSource(
  level: TrustLevel,
  source: "main" | "dm" | "group" | "public"
): { allowed: boolean; reason?: string } {
  // Main session (local user) can use any trust level
  if (source === "main") {
    return { allowed: true };
  }

  // DMs from approved users - restricted trust
  if (source === "dm") {
    if (level === "full" || level === "shell") {
      return {
        allowed: false,
        reason: `Trust level "${level}" not allowed for DM sources. Max: "write"`,
      };
    }
    return { allowed: true };
  }

  // Group chats - limited trust
  if (source === "group") {
    if (level === "full" || level === "shell" || level === "write") {
      return {
        allowed: false,
        reason: `Trust level "${level}" not allowed for group sources. Max: "llm"`,
      };
    }
    return { allowed: true };
  }

  // Public/unknown sources - minimal trust
  if (source === "public") {
    if (level !== "none" && level !== "network") {
      return {
        allowed: false,
        reason: `Trust level "${level}" not allowed for public sources. Max: "network"`,
      };
    }
    return { allowed: true };
  }

  return { allowed: false, reason: "Unknown source type" };
}

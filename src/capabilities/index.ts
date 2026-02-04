/**
 * Capability Factories for Safe Agent Execution
 *
 * These factories create capability objects that can be injected into
 * the tjs-lang AgentVM. Each capability provides controlled, auditable
 * access to system resources.
 *
 * Key principle: Agents have ZERO capabilities by default.
 * You must explicitly grant each capability, and each capability
 * enforces its own security constraints.
 */

export * from "./shell";
export * from "./filesystem";
export * from "./fetch";
export * from "./llm";
export * from "./security.secrets";

import type { Capabilities } from "tjs-lang";
import {
  createShellCapability,
  type ShellCapabilityOptions,
  READ_ONLY_SHELL,
} from "./shell";
import {
  createFilesystemCapability,
  type FilesystemCapabilityOptions,
  createSourceReadOnly,
} from "./filesystem";
import { createFetchCapability, type FetchCapabilityOptions } from "./fetch";
import { createLLMCapability, type LLMCapabilityOptions } from "./llm";

/**
 * Options for creating a complete capability set
 */
export interface CapabilitySetOptions {
  /** Shell capability options, or false to disable */
  shell?: ShellCapabilityOptions | false;

  /** Filesystem capability options, or false to disable */
  filesystem?: FilesystemCapabilityOptions | false;

  /** Fetch capability options, or false to disable */
  fetch?: FetchCapabilityOptions | false;

  /** LLM capability options, or false to disable */
  llm?: LLMCapabilityOptions | false;

  /** Additional custom capabilities */
  custom?: Record<string, any>;
}

/**
 * Create a complete capability set from options.
 *
 * @example
 * ```typescript
 * const capabilities = createCapabilitySet({
 *   filesystem: { root: '/app/workspace', allowWrite: false },
 *   fetch: { allowedHosts: ['api.example.com'] },
 *   shell: false, // Explicitly disable
 *   llm: false,   // Explicitly disable
 * })
 *
 * await vm.run(agent, args, { capabilities })
 * ```
 */
export function createCapabilitySet(
  options: CapabilitySetOptions
): Capabilities {
  const capabilities: Capabilities = {};

  if (options.shell !== false && options.shell) {
    capabilities.shell = createShellCapability(options.shell);
  }

  if (options.filesystem !== false && options.filesystem) {
    const fsCapability = createFilesystemCapability(options.filesystem);
    capabilities.files = fsCapability;
    // Also expose as 'store' interface for compatibility with tjs-lang atoms
    capabilities.store = {
      get: async (key: string) => {
        try {
          return JSON.parse(await fsCapability.read(key));
        } catch {
          return undefined;
        }
      },
      set: async (key: string, value: any) => {
        await fsCapability.write(key, JSON.stringify(value, null, 2));
      },
    };
  }

  if (options.fetch !== false && options.fetch) {
    capabilities.fetch = createFetchCapability(options.fetch);
  }

  if (options.llm !== false && options.llm) {
    const llmCapability = createLLMCapability(options.llm);
    capabilities.llm = {
      predict: llmCapability.predict,
      embed: llmCapability.embed,
    };
  }

  // Merge custom capabilities
  if (options.custom) {
    Object.assign(capabilities, options.custom);
  }

  return capabilities;
}

/**
 * Preset: Minimal read-only capabilities for inspection/analysis agents
 */
export function createReadOnlyCapabilities(options: {
  projectRoot: string;
  allowedHosts?: string[];
}): Capabilities {
  return createCapabilitySet({
    shell: {
      workdir: options.projectRoot,
      allowlist: READ_ONLY_SHELL,
    },
    filesystem: {
      root: options.projectRoot,
      allowWrite: false,
    },
    fetch: options.allowedHosts
      ? {
          allowedHosts: options.allowedHosts,
        }
      : false,
    llm: false,
  });
}

/**
 * Preset: Zero capabilities (compute only)
 *
 * Agent can only perform pure computation - no I/O of any kind.
 * Useful for rule engines, data transformation, validation logic.
 */
export function createComputeOnlyCapabilities(): Capabilities {
  return {};
}

/**
 * Preset: Chat agent capabilities (LLM + limited fetch)
 */
export function createChatCapabilities(options: {
  llmPredict: (prompt: string, options?: any) => Promise<string>;
  llmEmbed?: (text: string) => Promise<number[]>;
  allowedHosts?: string[];
  maxTokens?: number;
}): Capabilities {
  return createCapabilitySet({
    shell: false,
    filesystem: false,
    fetch: options.allowedHosts
      ? {
          allowedHosts: options.allowedHosts,
        }
      : false,
    llm: {
      predict: options.llmPredict,
      embed: options.llmEmbed,
      maxTotalTokens: options.maxTokens ?? 100000,
    },
  });
}

/**
 * Security levels for quick configuration
 */
export type SecurityLevel =
  | "paranoid"
  | "restricted"
  | "standard"
  | "permissive";

/**
 * Get recommended capability constraints for a security level
 */
export function getSecurityDefaults(level: SecurityLevel): {
  maxFuel: number;
  timeoutMs: number;
  maxResponseSize: number;
  rateLimit: number;
} {
  switch (level) {
    case "paranoid":
      return {
        maxFuel: 100,
        timeoutMs: 5000,
        maxResponseSize: 100 * 1024, // 100KB
        rateLimit: 10,
      };
    case "restricted":
      return {
        maxFuel: 500,
        timeoutMs: 15000,
        maxResponseSize: 1024 * 1024, // 1MB
        rateLimit: 30,
      };
    case "standard":
      return {
        maxFuel: 1000,
        timeoutMs: 30000,
        maxResponseSize: 10 * 1024 * 1024, // 10MB
        rateLimit: 60,
      };
    case "permissive":
      return {
        maxFuel: 5000,
        timeoutMs: 120000,
        maxResponseSize: 50 * 1024 * 1024, // 50MB
        rateLimit: 120,
      };
  }
}

/**
 * Safe Shell Capability
 *
 * Defense-in-depth shell execution with:
 * 1. Command allowlists (only permitted binaries)
 * 2. Path sanitization (block sensitive directories)
 * 3. Argument validation (reject dangerous patterns)
 * 4. Opaque failures (don't leak information about why something failed)
 *
 * The Footgun: Even with command allowlists, `cat ~/.ssh/id_rsa` works.
 * The Fix: All path arguments are validated against a jail + blocklist.
 */

import { spawn, type SpawnOptions } from "child_process";
import { resolve, relative, normalize, isAbsolute } from "path";
import { homedir } from "os";
import { killProcessTree } from "./process-utils.js";

export interface ShellCommand {
  /** The command binary (e.g., 'ls', 'git', 'npm') */
  binary: string;
  /** Optional: allowed argument patterns (regex). If omitted, no args allowed. */
  argPatterns?: RegExp[];
  /** Optional: require all args match at least one pattern */
  strictArgs?: boolean;
  /** Optional: working directory jail */
  cwd?: string;
  /** Optional: environment variables to pass */
  env?: Record<string, string>;
  /** Optional: timeout in ms (default: 30000) */
  timeout?: number;
  /** Optional: max output size in bytes (default: 1MB) */
  maxOutput?: number;
}

export interface ShellCapabilityOptions {
  /** Allowed commands with their configurations */
  allowlist: ShellCommand[];

  /**
   * Working directory - ALL paths are relative to this and cannot escape.
   * REQUIRED for security. Commands cannot access anything outside this directory.
   */
  workdir: string;

  /**
   * Additional blocked path patterns (beyond defaults).
   * Paths matching these are always rejected, even within workdir.
   */
  blockedPaths?: string[];

  /** Global timeout in ms (default: 30000) */
  timeout?: number;

  /** Global max output size in bytes (default: 1MB) */
  maxOutput?: number;

  /** Called before each command executes (for logging/auditing) */
  onBeforeExec?: (binary: string, args: string[]) => void;

  /** Called after each command completes */
  onAfterExec?: (
    binary: string,
    args: string[],
    exitCode: number,
    output: string
  ) => void;

  /**
   * Called when a command is blocked (for security logging).
   * NOTE: The error message to the agent is always opaque - this is for YOUR logs.
   */
  onBlocked?: (binary: string, args: string[], reason: string) => void;
}

export interface ShellCapability {
  run: (
    command: string
  ) => Promise<{ stdout: string; stderr: string; exitCode: number }>;
  exec: (
    binary: string,
    args?: string[]
  ) => Promise<{ stdout: string; stderr: string; exitCode: number }>;
}

/**
 * Paths that are ALWAYS blocked, regardless of workdir.
 * These represent sensitive system and user data that agents should never access.
 */
const ALWAYS_BLOCKED_PATHS = [
  // Home directory hidden files (credentials, configs, keys)
  /^~\/\./,
  /^\/home\/[^/]+\/\./,
  /^\/Users\/[^/]+\/\./,

  // SSH keys and config - block anywhere they appear
  /\.ssh/,
  /(^|\/)id_rsa/,
  /(^|\/)id_ed25519/,
  /(^|\/)id_ecdsa/,
  /(^|\/)authorized_keys$/,
  /(^|\/)known_hosts$/,

  // Git credentials
  /\.git\/config$/,
  /(^|\/)\.gitconfig/,
  /(^|\/)\.git-credentials/,

  // Environment and secrets - block anywhere
  /(^|\/)\.env($|\.)/,
  /(^|\/)secrets\b/i,
  /(^|\/)credentials\b/i,
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /private.*key/i,
  /secret.*key/i,

  // Package manager credentials
  /(^|\/)\.npmrc/,
  /(^|\/)\.yarnrc/,

  // Cloud credentials
  /\.aws\//,
  /\.azure\//,
  /\.gcloud\//,
  /\.config\/gcloud/,
  /\.kube\//,

  // Browser data
  /Cookies/i,
  /Login\s*Data/i,
  /Web\s*Data/i,
  /\.mozilla\//,
  /\.chrome\//,
  /Google\/Chrome/,

  // System directories
  /^\/etc\//,
  /^\/var\//,
  /^\/root\//,
  /^\/private\/etc/,
  /^\/private\/var/,

  // Password and shadow files
  /\/passwd$/,
  /\/shadow$/,
  /\/sudoers/,

  // Process and system info that could leak data
  /^\/proc\//,
  /^\/sys\//,
  /^\/dev\//,
];

/** Patterns in arguments that suggest path traversal or escape attempts */
const DANGEROUS_ARG_PATTERNS = [
  // Path traversal
  /\.\.\//,
  /\.\.\\/,

  // Absolute paths to sensitive locations
  /^\/etc\//,
  /^\/var\//,
  /^\/root/,
  /^\/home\/[^/]+\/\./,
  /^\/Users\/[^/]+\/\./,
  /^~\/\./,
  /^~\//, // Any home directory reference

  // Shell metacharacters (command injection)
  /[;&|`$(){}[\]<>\\]/,

  // Null bytes (path truncation attacks)
  /\x00/,

  // Encoded traversal attempts
  /%2e%2e/i,
  /%252e/i,
  /\.%00/,
];

/** The generic error message returned to agents - never leak why something failed */
const OPAQUE_ERROR = "Command failed";

/**
 * Creates a secure shell capability with path-based restrictions.
 *
 * @example
 * ```typescript
 * const shell = createShellCapability({
 *   workdir: '/app/workspace',  // REQUIRED - all paths jailed here
 *   allowlist: [
 *     { binary: 'ls' },
 *     { binary: 'cat' },
 *     { binary: 'grep' },
 *   ]
 * })
 * ```
 */
export function createShellCapability(
  options: ShellCapabilityOptions
): ShellCapability {
  const {
    allowlist,
    workdir,
    blockedPaths = [],
    timeout: globalTimeout = 30000,
    maxOutput: globalMaxOutput = 1024 * 1024,
    onBeforeExec,
    onAfterExec,
    onBlocked,
  } = options;

  // Resolve workdir to absolute path
  const resolvedWorkdir = resolve(workdir);
  const home = homedir();

  // Build lookup map for O(1) command validation
  const allowedCommands = new Map<string, ShellCommand>();
  for (const cmd of allowlist) {
    allowedCommands.set(cmd.binary, cmd);
  }

  // Compile additional blocked patterns
  const additionalBlocked = blockedPaths.map((p) => new RegExp(p));

  /**
   * Check if a path is blocked (sensitive location)
   */
  function isPathBlocked(pathArg: string): {
    blocked: boolean;
    reason: string;
  } {
    // Expand ~ to home directory for checking
    const expanded = pathArg.startsWith("~")
      ? pathArg.replace(/^~/, home)
      : pathArg;

    // Check against always-blocked patterns
    for (const pattern of ALWAYS_BLOCKED_PATHS) {
      if (pattern.test(pathArg) || pattern.test(expanded)) {
        return {
          blocked: true,
          reason: `Path matches blocked pattern: ${pattern}`,
        };
      }
    }

    // Check against additional blocked patterns
    for (const pattern of additionalBlocked) {
      if (pattern.test(pathArg) || pattern.test(expanded)) {
        return { blocked: true, reason: `Path matches custom blocked pattern` };
      }
    }

    return { blocked: false, reason: "" };
  }

  /**
   * Validate that a path is within the workdir jail
   */
  function isPathInJail(pathArg: string): {
    inJail: boolean;
    resolved: string;
    reason: string;
  } {
    try {
      // Handle relative vs absolute paths
      let targetPath: string;
      if (isAbsolute(pathArg)) {
        targetPath = normalize(pathArg);
      } else if (pathArg.startsWith("~")) {
        // Block home directory references entirely
        return {
          inJail: false,
          resolved: "",
          reason: "Home directory references not allowed",
        };
      } else {
        targetPath = resolve(resolvedWorkdir, pathArg);
      }

      // Check if resolved path is within workdir
      const rel = relative(resolvedWorkdir, targetPath);
      if (rel.startsWith("..") || isAbsolute(rel)) {
        return {
          inJail: false,
          resolved: targetPath,
          reason: "Path escapes workdir",
        };
      }

      return { inJail: true, resolved: targetPath, reason: "" };
    } catch {
      return { inJail: false, resolved: "", reason: "Invalid path" };
    }
  }

  /**
   * Check if an argument is safe to use
   */
  function validateArgument(
    arg: string,
    binary: string
  ): { valid: boolean; reason: string } {
    // Check for dangerous patterns first (injection, traversal, etc.)
    for (const pattern of DANGEROUS_ARG_PATTERNS) {
      if (pattern.test(arg)) {
        return { valid: false, reason: `Argument contains dangerous pattern` };
      }
    }

    // Skip validation for flags (but still caught dangerous patterns above)
    if (arg.startsWith("-")) {
      return { valid: true, reason: "" };
    }

    // ALWAYS check against blocked path patterns
    // This catches credentials.json, secrets.yaml, *.pem, etc.
    // even when they don't "look like paths"
    const blockCheck = isPathBlocked(arg);
    if (blockCheck.blocked) {
      return { valid: false, reason: blockCheck.reason };
    }

    // If it looks like a path, also validate it's in the jail
    const looksLikePath =
      arg.includes("/") || arg.startsWith(".") || arg.startsWith("~");

    if (looksLikePath) {
      const jailCheck = isPathInJail(arg);
      if (!jailCheck.inJail) {
        return { valid: false, reason: jailCheck.reason };
      }
    }

    return { valid: true, reason: "" };
  }

  /**
   * Validate command and all arguments
   */
  function validateCommand(
    binary: string,
    args: string[]
  ): { valid: boolean; config?: ShellCommand; reason: string } {
    // Check if command is allowed
    const config = allowedCommands.get(binary);
    if (!config) {
      return { valid: false, reason: `Command not in allowlist: ${binary}` };
    }

    // Validate each argument
    for (const arg of args) {
      const argCheck = validateArgument(arg, binary);
      if (!argCheck.valid) {
        return { valid: false, reason: argCheck.reason };
      }

      // Also check against command-specific patterns if defined
      if (config.argPatterns && config.argPatterns.length > 0) {
        const matchesPattern = config.argPatterns.some((pattern) =>
          pattern.test(arg)
        );
        if (!matchesPattern && config.strictArgs !== false) {
          return {
            valid: false,
            reason: `Argument doesn't match allowed patterns for ${binary}`,
          };
        }
      }
    }

    // If no patterns defined and args provided, check strictArgs setting
    if (
      (!config.argPatterns || config.argPatterns.length === 0) &&
      args.length > 0
    ) {
      if (config.strictArgs !== false) {
        return {
          valid: false,
          reason: `${binary} doesn't accept arguments in this configuration`,
        };
      }
    }

    return { valid: true, config, reason: "" };
  }

  /**
   * Execute a validated command
   */
  async function execCommand(
    binary: string,
    args: string[]
  ): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    // Validate everything
    const validation = validateCommand(binary, args);
    if (!validation.valid || !validation.config) {
      onBlocked?.(binary, args, validation.reason);
      throw new Error(OPAQUE_ERROR);
    }

    const config = validation.config;
    const cwd = config.cwd || resolvedWorkdir;
    const timeout = config.timeout || globalTimeout;
    const maxOutput = config.maxOutput || globalMaxOutput;

    onBeforeExec?.(binary, args);

    return new Promise((resolve, reject) => {
      const spawnOpts: SpawnOptions = {
        cwd,
        env: {
          // Minimal environment - don't leak host env vars
          PATH: "/usr/local/bin:/usr/bin:/bin",
          HOME: resolvedWorkdir, // Fake home to break ~ expansion
          ...config.env,
        },
        // CRITICAL: detached: true on Unix creates a process group
        // This allows us to kill ALL spawned children, not just the parent
        detached: process.platform !== "win32",
        shell: false, // CRITICAL: never use shell=true
      };

      const proc = spawn(binary, args, spawnOpts);

      let stdout = "";
      let stderr = "";
      let outputSize = 0;
      let killed = false;

      // Helper to kill the entire process tree, not just the parent
      const killTree = () => {
        if (proc.pid) {
          killProcessTree(proc.pid);
        }
      };

      proc.stdout?.on("data", (data: Buffer) => {
        outputSize += data.length;
        if (outputSize > maxOutput && !killed) {
          killed = true;
          killTree();
          onBlocked?.(binary, args, "Output exceeded maximum size");
          reject(new Error(OPAQUE_ERROR));
          return;
        }
        stdout += data.toString();
      });

      proc.stderr?.on("data", (data: Buffer) => {
        outputSize += data.length;
        if (outputSize > maxOutput && !killed) {
          killed = true;
          killTree();
          onBlocked?.(binary, args, "Output exceeded maximum size");
          reject(new Error(OPAQUE_ERROR));
          return;
        }
        stderr += data.toString();
      });

      proc.on("close", (code) => {
        if (killed) return;
        const exitCode = code ?? 0;
        onAfterExec?.(binary, args, exitCode, stdout + stderr);
        resolve({ stdout, stderr, exitCode });
      });

      proc.on("error", (err) => {
        if (killed) return;
        onBlocked?.(binary, args, `Spawn error: ${err.message}`);
        reject(new Error(OPAQUE_ERROR));
      });

      // Timeout safety net - kills entire process tree
      setTimeout(() => {
        if (!killed) {
          killed = true;
          killTree();
          onBlocked?.(binary, args, "Timeout");
          reject(new Error(OPAQUE_ERROR));
        }
      }, timeout + 1000);
    });
  }

  return {
    /**
     * Run a command string (parsed into binary + args)
     * @example shell.run('ls -la')
     */
    async run(command: string) {
      const parts = parseCommand(command);
      if (parts.length === 0) {
        throw new Error(OPAQUE_ERROR);
      }
      const [binary, ...args] = parts;
      return execCommand(binary, args);
    },

    /**
     * Execute a command with explicit binary and args
     * @example shell.exec('git', ['status'])
     */
    async exec(binary: string, args: string[] = []) {
      return execCommand(binary, args);
    },
  };
}

/**
 * Parse a command string into binary and arguments.
 * Rejects commands with shell metacharacters.
 */
function parseCommand(command: string): string[] {
  const parts: string[] = [];
  let current = "";
  let inQuote: '"' | "'" | null = null;

  for (let i = 0; i < command.length; i++) {
    const char = command[i];

    if (inQuote) {
      if (char === inQuote) {
        inQuote = null;
      } else {
        current += char;
      }
    } else if (char === '"' || char === "'") {
      inQuote = char;
    } else if (char === " " || char === "\t") {
      if (current) {
        parts.push(current);
        current = "";
      }
    } else {
      current += char;
    }
  }

  if (current) {
    parts.push(current);
  }

  // Security: reject shell metacharacters in the raw command
  const dangerous = /[;&|`$(){}[\]<>\\]/;
  for (const part of parts) {
    if (dangerous.test(part)) {
      // Don't say what was wrong - opaque failure
      return [];
    }
  }

  return parts;
}

/**
 * Preset: Safe read-only commands with path restrictions built-in
 *
 * These commands can only operate within the workdir and cannot
 * access hidden files, home directories, or system paths.
 */
export const SAFE_READ_COMMANDS: ShellCommand[] = [
  { binary: "ls", strictArgs: false },
  { binary: "cat", strictArgs: false },
  { binary: "head", strictArgs: false },
  { binary: "tail", strictArgs: false },
  { binary: "wc", strictArgs: false },
  { binary: "file", strictArgs: false },
  { binary: "stat", strictArgs: false },
];

/**
 * Preset: Safe git commands (read-only operations)
 */
export const SAFE_GIT_COMMANDS: ShellCommand[] = [
  {
    binary: "git",
    argPatterns: [
      /^(status|log|diff|branch|show|blame|ls-files|rev-parse)$/,
      /^--[a-z\-]+(=.*)?$/, // Flags like --oneline, --format=...
      /^-\d+$/, // Like -10 for log
      /^[a-zA-Z0-9_\-\.\/\:\^~]+$/, // Refs, paths (validated separately)
    ],
    strictArgs: false,
  },
];

/**
 * Preset: Safe search commands
 */
export const SAFE_SEARCH_COMMANDS: ShellCommand[] = [
  { binary: "grep", strictArgs: false },
  { binary: "find", strictArgs: false },
  { binary: "which", strictArgs: false },
];

// Legacy exports for backwards compatibility
export const READ_ONLY_SHELL = SAFE_READ_COMMANDS;
export const GIT_READ_ONLY = SAFE_GIT_COMMANDS;
export const NPM_READ_ONLY: ShellCommand[] = [
  {
    binary: "npm",
    argPatterns: [/^(list|ls|outdated|audit|view)$/, /^--[a-z\-]+$/],
  },
  { binary: "bun", argPatterns: [/^(pm|x)$/, /^(ls|list)$/, /^--[a-z\-]+$/] },
];

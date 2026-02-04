/**
 * Safe Filesystem Capability
 *
 * Defense-in-depth filesystem access with:
 * 1. Root directory jail (cannot escape)
 * 2. Always-blocked sensitive file patterns
 * 3. Path traversal protection
 * 4. Opaque error messages (no information leakage)
 *
 * The Footgun: Agents can read .env, SSH keys, credentials, etc.
 * The Fix: Sensitive files are blocked by pattern matching on the filename,
 * not just the path. `credentials.json` is blocked anywhere it appears.
 */

import {
  readFileSync,
  writeFileSync,
  existsSync,
  readdirSync,
  statSync,
  mkdirSync,
} from "fs";
import { readFile, writeFile, mkdir, unlink } from "fs/promises";
import { join, resolve, relative, dirname, normalize, isAbsolute } from "path";
import { homedir } from "os";

export interface FilesystemCapabilityOptions {
  /** Root directory - all paths are relative to this and cannot escape it */
  root: string;

  /** Allowed file patterns (glob-like). If empty, nothing is accessible. */
  allowPatterns?: string[];

  /** Additional blocked patterns (beyond the default sensitive file list) */
  blockPatterns?: string[];

  /** Allow write operations (default: false - read-only) */
  allowWrite?: boolean;

  /** Allow delete operations (default: false) */
  allowDelete?: boolean;

  /** Allow creating new files (default: false, requires allowWrite) */
  allowCreate?: boolean;

  /** Maximum file size to read in bytes (default: 10MB) */
  maxReadSize?: number;

  /** Maximum file size to write in bytes (default: 1MB) */
  maxWriteSize?: number;

  /** Called before each file operation (for logging/auditing) */
  onAccess?: (operation: string, path: string) => void;

  /**
   * Called when access is blocked (for security logging).
   * NOTE: The error message to the agent is always opaque.
   */
  onBlocked?: (operation: string, path: string, reason: string) => void;
}

export interface FilesystemCapability {
  read: (path: string) => Promise<string>;
  write: (path: string, content: string) => Promise<void>;
  exists: (path: string) => Promise<boolean>;
  list: (path: string) => Promise<string[]>;
  stat: (path: string) => Promise<{
    size: number;
    isDirectory: boolean;
    isFile: boolean;
    mtime: number;
  }>;
  delete: (path: string) => Promise<void>;
  mkdir: (path: string) => Promise<void>;
}

/**
 * Patterns that are ALWAYS blocked, regardless of allowPatterns.
 * These match against the full path AND individual path components.
 */
const ALWAYS_BLOCKED_PATTERNS = [
  // Environment and secrets - block anywhere in path
  /(^|\/|\\)\.env($|\.|\/|\\)/i,
  /(^|\/|\\)secrets\./i,
  /(^|\/|\\)credentials\./i,
  /\.env\.[a-z]+$/i,

  // SSH keys and config
  /(^|\/|\\)\.ssh(\/|\\|$)/,
  /(^|\/|\\)id_rsa/,
  /(^|\/|\\)id_ed25519/,
  /(^|\/|\\)id_ecdsa/,
  /(^|\/|\\)id_dsa/,
  /(^|\/|\\)authorized_keys$/,
  /(^|\/|\\)known_hosts$/,

  // Private keys and certificates
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /\.crt$/i,
  /private.*key/i,
  /secret.*key/i,

  // Git credentials
  /(^|\/|\\)\.git\/config$/,
  /(^|\/|\\)\.gitconfig$/,
  /(^|\/|\\)\.git-credentials$/,

  // Package manager tokens
  /(^|\/|\\)\.npmrc$/,
  /(^|\/|\\)\.yarnrc/,
  /(^|\/|\\)\.pip(\/|\\|$)/,

  // Cloud credentials
  /(^|\/|\\)\.aws(\/|\\|$)/,
  /(^|\/|\\)\.azure(\/|\\|$)/,
  /(^|\/|\\)\.gcloud(\/|\\|$)/,
  /(^|\/|\\)\.kube(\/|\\|$)/,
  /(^|\/|\\)\.config\/gcloud/,

  // Browser data
  /(^|\/|\\)Cookies$/i,
  /(^|\/|\\)cookies\.sqlite$/i,
  /(^|\/|\\)Login Data$/i,
  /(^|\/|\\)Web Data$/i,
  /(^|\/|\\)History$/i,
  /(^|\/|\\)\.mozilla(\/|\\|$)/,
  /(^|\/|\\)\.chrome(\/|\\|$)/,

  // System files
  /(^|\/|\\)shadow$/,
  /(^|\/|\\)passwd$/,
  /(^|\/|\\)sudoers/,

  // Database files (might contain credentials)
  /\.sqlite$/i,
  /\.sqlite3$/i,
  /\.db$/i,

  // Backup files that might contain secrets
  /\.bak$/i,
  /~$/,

  // Hidden directories in home (catch-all for dotfiles we might have missed)
  /^\.(?!gitignore$|prettierrc|eslint|editorconfig|vscode)/,
];

/**
 * Patterns that indicate path traversal or escape attempts
 */
const DANGEROUS_PATH_PATTERNS = [
  // Path traversal
  /\.\.\//,
  /\.\.\\/,
  /\.\.$/,

  // Null bytes
  /\x00/,

  // Encoded traversal
  /%2e%2e/i,
  /%252e/i,

  // Absolute paths to sensitive locations
  /^\/etc(\/|$)/,
  /^\/var(\/|$)/,
  /^\/root(\/|$)/,
  /^\/home\/[^/]+\/\./,
  /^\/Users\/[^/]+\/\./,
  /^\/proc(\/|$)/,
  /^\/sys(\/|$)/,
  /^\/dev(\/|$)/,
  /^\/private\/etc/,
  /^\/private\/var/,

  // Home directory references
  /^~(\/|$)/,
];

/** Opaque error message - never leak why access was denied */
const ACCESS_DENIED = "Access denied";

/**
 * Creates a jailed filesystem capability with defense-in-depth security.
 *
 * @example
 * ```typescript
 * const fs = createFilesystemCapability({
 *   root: '/app/workspace',
 *   allowPatterns: ['**\/*.ts', '**\/*.js', '**\/*.json'],
 *   allowWrite: false,
 *   onBlocked: (op, path, reason) => console.log(`BLOCKED: ${op} ${path} - ${reason}`)
 * })
 * ```
 */
export function createFilesystemCapability(
  options: FilesystemCapabilityOptions
): FilesystemCapability {
  const {
    root,
    allowPatterns = ["**/*"],
    blockPatterns = [],
    allowWrite = false,
    allowDelete = false,
    allowCreate = false,
    maxReadSize = 10 * 1024 * 1024,
    maxWriteSize = 1 * 1024 * 1024,
    onAccess,
    onBlocked,
  } = options;

  const resolvedRoot = resolve(root);
  const home = homedir();

  // Compile additional block patterns
  const additionalBlocked = blockPatterns.map((p) => {
    // If it's already a regex-like string, convert it
    if (p.startsWith("**/")) {
      // Convert glob to regex: **/ means "anywhere in path"
      const pattern = p.slice(3).replace(/\./g, "\\.").replace(/\*/g, "[^/]*");
      return new RegExp(`(^|/|\\\\)${pattern}`, "i");
    }
    return new RegExp(p, "i");
  });

  /**
   * Check if a path contains dangerous patterns (traversal, etc.)
   */
  function isDangerousPath(inputPath: string): {
    dangerous: boolean;
    reason: string;
  } {
    for (const pattern of DANGEROUS_PATH_PATTERNS) {
      if (pattern.test(inputPath)) {
        return {
          dangerous: true,
          reason: `Dangerous path pattern: ${pattern}`,
        };
      }
    }
    return { dangerous: false, reason: "" };
  }

  /**
   * Check if a path matches always-blocked patterns
   */
  function isBlockedPath(inputPath: string): {
    blocked: boolean;
    reason: string;
  } {
    // Check against always-blocked patterns
    for (const pattern of ALWAYS_BLOCKED_PATTERNS) {
      if (pattern.test(inputPath)) {
        return { blocked: true, reason: `Matches blocked pattern: ${pattern}` };
      }
    }

    // Check against additional blocked patterns
    for (const pattern of additionalBlocked) {
      if (pattern.test(inputPath)) {
        return { blocked: true, reason: "Matches custom blocked pattern" };
      }
    }

    // Also check individual path components
    const parts = inputPath.split(/[/\\]/);
    for (const part of parts) {
      for (const pattern of ALWAYS_BLOCKED_PATTERNS) {
        if (pattern.test(part)) {
          return {
            blocked: true,
            reason: `Path component matches blocked pattern: ${pattern}`,
          };
        }
      }
    }

    return { blocked: false, reason: "" };
  }

  /**
   * Resolve and validate a path is within the jail
   */
  function resolveAndValidate(inputPath: string): {
    valid: boolean;
    resolved: string;
    reason: string;
  } {
    // Check for dangerous patterns first
    const dangerCheck = isDangerousPath(inputPath);
    if (dangerCheck.dangerous) {
      return { valid: false, resolved: "", reason: dangerCheck.reason };
    }

    // Expand ~ to check (but we'll reject it)
    if (inputPath.startsWith("~")) {
      return {
        valid: false,
        resolved: "",
        reason: "Home directory references not allowed",
      };
    }

    // Handle absolute vs relative paths
    let targetPath: string;
    if (isAbsolute(inputPath)) {
      // Absolute paths must be within root
      targetPath = normalize(inputPath);
    } else {
      targetPath = resolve(resolvedRoot, inputPath);
    }

    // Normalize to handle any remaining .. that resolve() might leave
    targetPath = normalize(targetPath);

    // Check if resolved path is within root
    const rel = relative(resolvedRoot, targetPath);
    if (rel.startsWith("..") || isAbsolute(rel)) {
      return {
        valid: false,
        resolved: targetPath,
        reason: "Path escapes root",
      };
    }

    // Check against blocked patterns (use relative path for pattern matching)
    const blockCheck = isBlockedPath(rel);
    if (blockCheck.blocked) {
      return { valid: false, resolved: targetPath, reason: blockCheck.reason };
    }

    // Also check the absolute path
    const absBlockCheck = isBlockedPath(targetPath);
    if (absBlockCheck.blocked) {
      return {
        valid: false,
        resolved: targetPath,
        reason: absBlockCheck.reason,
      };
    }

    return { valid: true, resolved: targetPath, reason: "" };
  }

  /**
   * Check if a path matches allow patterns (glob-like)
   */
  function matchesAllowPatterns(relativePath: string): boolean {
    for (const pattern of allowPatterns) {
      if (matchesGlob(relativePath, pattern)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Simple glob matching
   */
  function matchesGlob(path: string, pattern: string): boolean {
    // Handle special case: **/* should match everything including root files
    if (pattern === "**/*") {
      return true;
    }

    // Handle **/*.ext pattern (any file with extension anywhere)
    if (pattern.startsWith("**/")) {
      const suffix = pattern.slice(3); // Remove **/
      if (suffix.startsWith("*")) {
        // **/*.ext - match any file ending with .ext
        const ext = suffix.slice(1); // Remove *
        return (
          path.endsWith(ext) || path.includes("/" + suffix.replace("*", ""))
        );
      } else {
        // **/filename - match filename anywhere in path
        return path === suffix || path.endsWith("/" + suffix);
      }
    }

    // Convert glob to regex for other patterns
    const regexPattern = pattern
      .replace(/\./g, "\\.")
      .replace(/\*\*/g, "<<<GLOBSTAR>>>")
      .replace(/\*/g, "[^/]*")
      .replace(/<<<GLOBSTAR>>>/g, ".*")
      .replace(/\?/g, ".");

    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(path);
  }

  /**
   * Full access check: jail + blocked + allowed
   */
  function checkAccess(
    operation: string,
    inputPath: string
  ): { allowed: boolean; resolved: string } {
    const validation = resolveAndValidate(inputPath);

    if (!validation.valid) {
      onBlocked?.(operation, inputPath, validation.reason);
      return { allowed: false, resolved: "" };
    }

    // Check allow patterns
    const relativePath = relative(resolvedRoot, validation.resolved);
    if (!matchesAllowPatterns(relativePath)) {
      onBlocked?.(operation, inputPath, "Path not in allow patterns");
      return { allowed: false, resolved: "" };
    }

    return { allowed: true, resolved: validation.resolved };
  }

  return {
    async read(path: string): Promise<string> {
      const { allowed, resolved } = checkAccess("read", path);
      if (!allowed) {
        throw new Error(ACCESS_DENIED);
      }

      // Check file exists
      if (!existsSync(resolved)) {
        throw new Error(ACCESS_DENIED); // Don't reveal if file exists or not
      }

      // Check file size
      const stats = statSync(resolved);
      if (stats.isDirectory()) {
        throw new Error(ACCESS_DENIED);
      }
      if (stats.size > maxReadSize) {
        onBlocked?.("read", path, `File too large: ${stats.size}`);
        throw new Error(ACCESS_DENIED);
      }

      onAccess?.("read", resolved);
      return readFile(resolved, "utf-8");
    },

    async write(path: string, content: string): Promise<void> {
      if (!allowWrite) {
        onBlocked?.("write", path, "Write not allowed");
        throw new Error(ACCESS_DENIED);
      }

      const { allowed, resolved } = checkAccess("write", path);
      if (!allowed) {
        throw new Error(ACCESS_DENIED);
      }

      // Check if file exists
      const fileExists = existsSync(resolved);
      if (!fileExists && !allowCreate) {
        onBlocked?.("write", path, "Creating new files not allowed");
        throw new Error(ACCESS_DENIED);
      }

      // Check content size
      const size = Buffer.byteLength(content, "utf-8");
      if (size > maxWriteSize) {
        onBlocked?.("write", path, `Content too large: ${size}`);
        throw new Error(ACCESS_DENIED);
      }

      onAccess?.("write", resolved);

      // Ensure parent directory exists
      const dir = dirname(resolved);
      if (!existsSync(dir)) {
        if (!allowCreate) {
          onBlocked?.("write", path, "Creating directories not allowed");
          throw new Error(ACCESS_DENIED);
        }
        mkdirSync(dir, { recursive: true });
      }

      await writeFile(resolved, content, "utf-8");
    },

    async exists(path: string): Promise<boolean> {
      const { allowed, resolved } = checkAccess("exists", path);
      if (!allowed) {
        return false; // Don't reveal blocked paths exist
      }
      return existsSync(resolved);
    },

    async list(path: string): Promise<string[]> {
      const { allowed, resolved } = checkAccess("list", path);
      if (!allowed) {
        throw new Error(ACCESS_DENIED);
      }

      if (!existsSync(resolved)) {
        throw new Error(ACCESS_DENIED);
      }

      const stats = statSync(resolved);
      if (!stats.isDirectory()) {
        throw new Error(ACCESS_DENIED);
      }

      onAccess?.("list", resolved);
      const entries = readdirSync(resolved);

      // Filter out entries that would be blocked
      return entries.filter((entry) => {
        const entryPath = join(resolved, entry);
        const relPath = relative(resolvedRoot, entryPath);
        const blockCheck = isBlockedPath(relPath);
        return !blockCheck.blocked;
      });
    },

    async stat(path: string): Promise<{
      size: number;
      isDirectory: boolean;
      isFile: boolean;
      mtime: number;
    }> {
      const { allowed, resolved } = checkAccess("stat", path);
      if (!allowed) {
        throw new Error(ACCESS_DENIED);
      }

      if (!existsSync(resolved)) {
        throw new Error(ACCESS_DENIED);
      }

      onAccess?.("stat", resolved);
      const stats = statSync(resolved);
      return {
        size: stats.size,
        isDirectory: stats.isDirectory(),
        isFile: stats.isFile(),
        mtime: stats.mtimeMs,
      };
    },

    async delete(path: string): Promise<void> {
      if (!allowDelete) {
        onBlocked?.("delete", path, "Delete not allowed");
        throw new Error(ACCESS_DENIED);
      }

      const { allowed, resolved } = checkAccess("delete", path);
      if (!allowed) {
        throw new Error(ACCESS_DENIED);
      }

      if (!existsSync(resolved)) {
        throw new Error(ACCESS_DENIED);
      }

      const stats = statSync(resolved);
      if (stats.isDirectory()) {
        onBlocked?.("delete", path, "Cannot delete directories");
        throw new Error(ACCESS_DENIED);
      }

      onAccess?.("delete", resolved);
      await unlink(resolved);
    },

    async mkdir(path: string): Promise<void> {
      if (!allowWrite || !allowCreate) {
        onBlocked?.("mkdir", path, "Creating directories not allowed");
        throw new Error(ACCESS_DENIED);
      }

      const { allowed, resolved } = checkAccess("mkdir", path);
      if (!allowed) {
        throw new Error(ACCESS_DENIED);
      }

      onAccess?.("mkdir", resolved);
      await mkdir(resolved, { recursive: true });
    },
  };
}

/**
 * Preset: Source code read-only access
 */
export function createSourceReadOnly(root: string): FilesystemCapability {
  return createFilesystemCapability({
    root,
    allowPatterns: [
      "**/*.ts",
      "**/*.tsx",
      "**/*.js",
      "**/*.jsx",
      "**/*.mjs",
      "**/*.cjs",
      "**/*.json",
      "**/*.md",
      "**/*.txt",
      "**/*.yaml",
      "**/*.yml",
      "**/*.toml",
      "**/*.css",
      "**/*.scss",
      "**/*.html",
      "**/*.vue",
      "**/*.svelte",
      "**/package.json",
      "**/tsconfig.json",
      "**/README*",
    ],
    allowWrite: false,
  });
}

/**
 * Preset: Workspace with write access to specific directories
 */
export function createWorkspaceCapability(
  root: string,
  writableDirs: string[] = ["output", "tmp", "workspace"]
): FilesystemCapability {
  return createFilesystemCapability({
    root,
    allowPatterns: ["**/*"],
    allowWrite: true,
    allowCreate: true,
  });
}

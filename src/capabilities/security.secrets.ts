/**
 * Security Patterns - Single Source of Truth
 *
 * NOTE: This file is named *.secrets.ts deliberately so that it matches
 * our own blocked patterns. This ensures agents cannot read our security
 * configuration - we eat our own dogfood.
 *
 * This module defines all the blocked file/path patterns used across
 * shell and filesystem capabilities. Edit this file to customize
 * what's blocked in your deployment.
 *
 * NAMING CONVENTION FOR SENSITIVE CONFIG:
 * Name your sensitive configuration files to match blocked patterns:
 * - *.secrets.ts / *.secrets.json - matches /secrets\./
 * - *.credentials.* - matches /credentials\./
 * - .env.* - matches /\.env/
 *
 * This way they're automatically protected without extra configuration.
 *
 * EXTENDING THESE PATTERNS:
 * If you have custom sensitive files in your environment, add them here
 * or pass them via the `additionalBlockedPatterns` option.
 *
 * Examples of things you might want to add:
 * - Custom credential files: /myapp\.credentials/i
 * - Internal config: /internal-config\.json/i
 * - Proprietary data: /\.proprietary/
 */

export interface BlockedPattern {
  pattern: RegExp;
  description: string;
  category: string;
}

export interface DangerousPattern {
  pattern: RegExp;
  description: string;
}

/**
 * Files that are ALWAYS blocked, regardless of configuration.
 * These patterns match against filenames and paths.
 *
 * Each pattern includes a comment explaining what it protects against.
 */
export const BLOCKED_FILE_PATTERNS: BlockedPattern[] = [
  // ============================================
  // ENVIRONMENT & SECRETS
  // ============================================
  {
    pattern: /(^|\/|\\)\.env($|\.|\/|\\)/i,
    description: "Environment files often contain API keys, database passwords",
    category: "secrets",
  },
  {
    pattern: /\.env\.[a-z]+$/i,
    description: "Environment variants (.env.local, .env.production)",
    category: "secrets",
  },
  {
    pattern: /(^|\/|\\)secrets\./i,
    description: "Files named secrets.* likely contain sensitive data",
    category: "secrets",
  },
  {
    pattern: /(^|\/|\\)credentials\./i,
    description: "Files named credentials.* likely contain auth data",
    category: "secrets",
  },
  {
    pattern: /secret/i,
    description: 'Any file with "secret" in the name',
    category: "secrets",
  },

  // ============================================
  // SSH & AUTHENTICATION KEYS
  // ============================================
  {
    pattern: /(^|\/|\\)\.ssh(\/|\\|$)/,
    description: "SSH directory contains private keys",
    category: "ssh",
  },
  {
    pattern: /(^|\/|\\)id_rsa/,
    description: "RSA private key",
    category: "ssh",
  },
  {
    pattern: /(^|\/|\\)id_ed25519/,
    description: "Ed25519 private key",
    category: "ssh",
  },
  {
    pattern: /(^|\/|\\)id_ecdsa/,
    description: "ECDSA private key",
    category: "ssh",
  },
  {
    pattern: /(^|\/|\\)id_dsa/,
    description: "DSA private key (legacy)",
    category: "ssh",
  },
  {
    pattern: /(^|\/|\\)authorized_keys$/,
    description: "SSH authorized keys file",
    category: "ssh",
  },
  {
    pattern: /(^|\/|\\)known_hosts$/,
    description: "SSH known hosts (reveals infrastructure)",
    category: "ssh",
  },

  // ============================================
  // CERTIFICATES & PRIVATE KEYS
  // ============================================
  {
    pattern: /\.pem$/i,
    description: "PEM certificate/key file",
    category: "certificates",
  },
  {
    pattern: /\.key$/i,
    description: "Private key file",
    category: "certificates",
  },
  {
    pattern: /\.p12$/i,
    description: "PKCS#12 certificate bundle",
    category: "certificates",
  },
  {
    pattern: /\.pfx$/i,
    description: "PFX certificate bundle",
    category: "certificates",
  },
  {
    pattern: /\.crt$/i,
    description: "Certificate file",
    category: "certificates",
  },
  {
    pattern: /private.*key/i,
    description: 'Any file with "private" and "key" in name',
    category: "certificates",
  },

  // ============================================
  // GIT CREDENTIALS
  // ============================================
  {
    pattern: /(^|\/|\\)\.git\/config$/,
    description: "Git config may contain credentials",
    category: "git",
  },
  {
    pattern: /(^|\/|\\)\.gitconfig$/,
    description: "Global git config",
    category: "git",
  },
  {
    pattern: /(^|\/|\\)\.git-credentials$/,
    description: "Git credential storage",
    category: "git",
  },

  // ============================================
  // PACKAGE MANAGER CREDENTIALS
  // ============================================
  {
    pattern: /(^|\/|\\)\.npmrc$/,
    description: "NPM config often contains auth tokens",
    category: "package-managers",
  },
  {
    pattern: /(^|\/|\\)\.yarnrc/,
    description: "Yarn config may contain auth tokens",
    category: "package-managers",
  },
  {
    pattern: /(^|\/|\\)\.pip(\/|\\|$)/,
    description: "Python pip config",
    category: "package-managers",
  },
  {
    pattern: /(^|\/|\\)\.pypirc$/,
    description: "PyPI credentials",
    category: "package-managers",
  },
  {
    pattern: /(^|\/|\\)\.gem\/credentials$/,
    description: "RubyGems credentials",
    category: "package-managers",
  },
  {
    pattern: /(^|\/|\\)\.cargo\/credentials$/,
    description: "Cargo (Rust) credentials",
    category: "package-managers",
  },

  // ============================================
  // CLOUD PROVIDER CREDENTIALS
  // ============================================
  {
    pattern: /(^|\/|\\)\.aws(\/|\\|$)/,
    description: "AWS credentials and config",
    category: "cloud",
  },
  {
    pattern: /(^|\/|\\)\.azure(\/|\\|$)/,
    description: "Azure credentials",
    category: "cloud",
  },
  {
    pattern: /(^|\/|\\)\.gcloud(\/|\\|$)/,
    description: "Google Cloud credentials",
    category: "cloud",
  },
  {
    pattern: /(^|\/|\\)\.config\/gcloud/,
    description: "Google Cloud config directory",
    category: "cloud",
  },
  {
    pattern: /(^|\/|\\)\.kube(\/|\\|$)/,
    description: "Kubernetes config and credentials",
    category: "cloud",
  },
  {
    pattern: /(^|\/|\\)\.docker\/config\.json$/,
    description: "Docker registry credentials",
    category: "cloud",
  },
  {
    pattern: /service.?account.*\.json$/i,
    description: "GCP service account key files",
    category: "cloud",
  },

  // ============================================
  // BROWSER DATA
  // ============================================
  {
    pattern: /(^|\/|\\)Cookies$/i,
    description: "Browser cookies",
    category: "browser",
  },
  {
    pattern: /(^|\/|\\)cookies\.sqlite$/i,
    description: "Firefox cookies database",
    category: "browser",
  },
  {
    pattern: /(^|\/|\\)Login Data$/i,
    description: "Chrome saved passwords",
    category: "browser",
  },
  {
    pattern: /(^|\/|\\)Web Data$/i,
    description: "Chrome autofill data",
    category: "browser",
  },
  {
    pattern: /(^|\/|\\)History$/i,
    description: "Browser history",
    category: "browser",
  },
  {
    pattern: /(^|\/|\\)\.mozilla(\/|\\|$)/,
    description: "Firefox profile directory",
    category: "browser",
  },
  {
    pattern: /(^|\/|\\)\.chrome(\/|\\|$)/,
    description: "Chrome profile directory",
    category: "browser",
  },

  // ============================================
  // SYSTEM FILES
  // ============================================
  {
    pattern: /(^|\/|\\)shadow$/,
    description: "Unix password shadow file",
    category: "system",
  },
  {
    pattern: /(^|\/|\\)passwd$/,
    description: "Unix passwd file",
    category: "system",
  },
  {
    pattern: /(^|\/|\\)sudoers/,
    description: "Sudo configuration",
    category: "system",
  },

  // ============================================
  // DATABASES (may contain credentials/sensitive data)
  // ============================================
  {
    pattern: /\.sqlite$/i,
    description: "SQLite database",
    category: "database",
  },
  {
    pattern: /\.sqlite3$/i,
    description: "SQLite3 database",
    category: "database",
  },
  {
    pattern: /\.db$/i,
    description: "Database file",
    category: "database",
  },

  // ============================================
  // BACKUP FILES (may contain secrets from backups)
  // ============================================
  {
    pattern: /\.bak$/i,
    description: "Backup file",
    category: "backup",
  },
  {
    pattern: /~$/,
    description: "Editor backup file",
    category: "backup",
  },

  // ============================================
  // SHELL HISTORY (contains command history)
  // ============================================
  {
    pattern: /(^|\/|\\)\.bash_history$/,
    description: "Bash command history",
    category: "history",
  },
  {
    pattern: /(^|\/|\\)\.zsh_history$/,
    description: "Zsh command history",
    category: "history",
  },
  {
    pattern: /(^|\/|\\)\.node_repl_history$/,
    description: "Node.js REPL history",
    category: "history",
  },
  {
    pattern: /(^|\/|\\)\.python_history$/,
    description: "Python REPL history",
    category: "history",
  },

  // ============================================
  // APPLICATION-SPECIFIC CONFIGS
  // ============================================
  {
    pattern: /(^|\/|\\)\.netrc$/,
    description: "FTP/HTTP credentials",
    category: "application",
  },
  {
    pattern: /(^|\/|\\)\.pgpass$/,
    description: "PostgreSQL password file",
    category: "application",
  },
  {
    pattern: /(^|\/|\\)\.my\.cnf$/,
    description: "MySQL config with credentials",
    category: "application",
  },
  {
    pattern: /(^|\/|\\)\.mongocli\.toml$/,
    description: "MongoDB CLI credentials",
    category: "application",
  },

  // ============================================
  // NODE/JS INTERNALS (may expose security config)
  // ============================================
  {
    pattern: /(^|\/|\\)node_modules(\/|\\|$)/,
    description: "Node modules directory (may contain security code)",
    category: "internals",
  },
  {
    pattern: /(^|\/|\\)\.pnpm(\/|\\|$)/,
    description: "pnpm store",
    category: "internals",
  },
  {
    pattern: /(^|\/|\\)\.yarn(\/|\\|$)/,
    description: "Yarn cache/config",
    category: "internals",
  },
  {
    pattern: /(^|\/|\\)\.bun(\/|\\|$)/,
    description: "Bun cache",
    category: "internals",
  },

  // ============================================
  // INFRASTRUCTURE & DEPLOYMENT
  // ============================================
  {
    pattern: /\.tfstate$/i,
    description: "Terraform state (contains infrastructure secrets)",
    category: "infrastructure",
  },
  {
    pattern: /\.tfvars$/i,
    description: "Terraform variables (may contain secrets)",
    category: "infrastructure",
  },
  {
    pattern: /(^|\/|\\)\.terraform(\/|\\|$)/,
    description: "Terraform working directory",
    category: "infrastructure",
  },
  {
    pattern: /(^|\/|\\)ansible\.cfg$/,
    description: "Ansible config",
    category: "infrastructure",
  },
  {
    pattern: /vault.*\.ya?ml$/i,
    description: "Ansible vault files",
    category: "infrastructure",
  },
];

/**
 * Path patterns that indicate traversal or escape attempts.
 * These are checked before file patterns.
 */
export const DANGEROUS_PATH_PATTERNS: DangerousPattern[] = [
  // Path traversal
  { pattern: /\.\.\//, description: "Path traversal with ../" },
  { pattern: /\.\.\\/, description: "Path traversal with ..\\ (Windows)" },
  { pattern: /\.\.$/, description: "Path ending with .." },

  // Null bytes (path truncation attacks)
  { pattern: /\x00/, description: "Null byte injection" },

  // Encoded traversal
  { pattern: /%2e%2e/i, description: "URL-encoded traversal" },
  { pattern: /%252e/i, description: "Double-encoded traversal" },

  // Absolute paths to sensitive system locations
  { pattern: /^\/etc(\/|$)/, description: "System /etc directory" },
  { pattern: /^\/var(\/|$)/, description: "System /var directory" },
  { pattern: /^\/root(\/|$)/, description: "Root home directory" },
  {
    pattern: /^\/home\/[^/]+\/\./,
    description: "Hidden files in user home (Linux)",
  },
  {
    pattern: /^\/Users\/[^/]+\/\./,
    description: "Hidden files in user home (macOS)",
  },
  { pattern: /^\/proc(\/|$)/, description: "Linux proc filesystem" },
  { pattern: /^\/sys(\/|$)/, description: "Linux sys filesystem" },
  { pattern: /^\/dev(\/|$)/, description: "Device files" },
  { pattern: /^\/private\/etc/, description: "macOS /private/etc" },
  { pattern: /^\/private\/var/, description: "macOS /private/var" },

  // Home directory references
  { pattern: /^~(\/|$)/, description: "Home directory reference" },
];

/**
 * Get all blocked patterns as simple RegExp array (for backwards compatibility)
 */
export function getBlockedPatterns(): RegExp[] {
  return BLOCKED_FILE_PATTERNS.map((p) => p.pattern);
}

/**
 * Get blocked patterns by category
 */
export function getBlockedPatternsByCategory(category: string): RegExp[] {
  return BLOCKED_FILE_PATTERNS.filter((p) => p.category === category).map(
    (p) => p.pattern
  );
}

/**
 * Get all categories
 */
export function getCategories(): string[] {
  return [...new Set(BLOCKED_FILE_PATTERNS.map((p) => p.category))];
}

/**
 * Check if a path matches any blocked pattern
 */
export function isBlocked(path: string): {
  blocked: boolean;
  pattern?: RegExp;
  description?: string;
  category?: string;
} {
  // Check dangerous patterns first
  for (const { pattern, description } of DANGEROUS_PATH_PATTERNS) {
    if (pattern.test(path)) {
      return { blocked: true, pattern, description, category: "dangerous" };
    }
  }

  // Check file patterns
  for (const { pattern, description, category } of BLOCKED_FILE_PATTERNS) {
    if (pattern.test(path)) {
      return { blocked: true, pattern, description, category };
    }
  }

  return { blocked: false };
}

/**
 * Print a human-readable summary of all blocked patterns
 */
export function printSecuritySummary(): void {
  console.log("\n=== ajs-clawbot Security Patterns ===\n");

  const categories = getCategories();
  for (const category of categories) {
    console.log(`\n## ${category.toUpperCase()}\n`);
    const patterns = BLOCKED_FILE_PATTERNS.filter(
      (p) => p.category === category
    );
    for (const { pattern, description } of patterns) {
      console.log(`  ${pattern.toString().padEnd(50)} - ${description}`);
    }
  }

  console.log("\n## DANGEROUS PATH PATTERNS\n");
  for (const { pattern, description } of DANGEROUS_PATH_PATTERNS) {
    console.log(`  ${pattern.toString().padEnd(50)} - ${description}`);
  }
}

/**
 * Suggestions for users to review based on their environment
 */
export const SECURITY_REVIEW_CHECKLIST = `
## Security Review Checklist

Before deploying ajs-clawbot, review these items for your environment:

### Recommended: Use Self-Protecting File Names

Name your sensitive config files to match our blocked patterns:

  ✓ myapp.secrets.json     - blocked by /secrets\\./
  ✓ api.credentials.yaml   - blocked by /credentials\\./
  ✓ .env.production        - blocked by /\\.env/
  ✓ config.secret.ts       - blocked by /secret/

This way they're automatically protected without extra configuration.
(This file itself is named security.secrets.ts for this reason!)

### Credentials you might have that we don't block by default:

□ Custom application config files (e.g., myapp.config.json with API keys)
  → Rename to myapp.secrets.json to auto-protect
□ Internal tooling credentials (e.g., .internal-tool-rc)
  → Rename to .internal-tool.credentials to auto-protect
□ CI/CD tokens (e.g., .circleci/config.yml with embedded secrets)
□ Hashicorp Vault tokens
□ Custom cloud provider configs (e.g., .digitalocean, .linode)
□ API key files with custom naming conventions
□ License files that might reveal organization info
□ Internal documentation with sensitive URLs/IPs

### Already blocked by default:

✓ Terraform state (*.tfstate, *.tfvars, .terraform/)
✓ Ansible vault files (vault*.yml)
✓ node_modules/ (prevents reading security code)
✓ .pnpm/, .yarn/, .bun/ (package manager internals)

### Directories you might want to add to blockPatterns:

□ /path/to/production/configs
□ /path/to/internal/tools
□ Any directory containing customer data
□ Backup directories
□ Log directories (might contain sensitive data in logs)

### To add custom patterns:

\`\`\`typescript
import { createFilesystemCapability } from 'ajs-clawbot'

const fs = createFilesystemCapability({
  root: '/app/workspace',
  blockPatterns: [
    // Add your custom patterns here
    'myapp.config.json',  // Or better: rename to myapp.secrets.json
    '**/internal-*',
  ],
})
\`\`\`

### Environment variables to check:

These env vars might be inherited by agents:
□ AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
□ GITHUB_TOKEN
□ ANTHROPIC_API_KEY / OPENAI_API_KEY
□ DATABASE_URL
□ Any *_TOKEN, *_KEY, *_SECRET variables

Consider running agents with a minimal environment.
`;

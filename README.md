# ajs-clawbot

**Safe execution layer for OpenClaw/Clawbot using capability-based security.**

Running an AI agent without proper sandboxing is like running a web server as root—possible, but irresponsible. This package provides the missing safety layer.

## The Problem

OpenClaw/Clawbot is powerful: it can execute shell commands, write files, control browsers, and talk to external services. When you're the only user, that's fine. But when you expose your bot to a Discord server, Telegram group, or public channel, anyone can potentially:

1. **Execute arbitrary commands** via prompt injection
2. **Read sensitive files** (.env, SSH keys, browser cookies)
3. **Exfiltrate data** to attacker-controlled servers
4. **Run up massive API bills** with infinite loops
5. **Use your bot as an attack platform** for SSRF

Current "fixes" (regex filters, prompt engineering, "please don't do bad things") are trivially bypassed.

## The Solution

**ajs-clawbot** wraps skill execution in [tjs-lang](https://github.com/tonioloewald/tjs-lang)'s capability-based VM:

| Danger | Current "Fix" | ajs-clawbot Fix |
|--------|---------------|-----------------|
| Malicious shell commands | Regex / "please don't" | **Allowlist bindings** - command must be explicitly permitted |
| Secret theft (.env) | "Don't look there" | **Filesystem jails** - hard logic barriers, not prompts |
| SSRF / data exfiltration | Auth tokens / hope | **Domain allowlists** - can't fetch from unapproved hosts |
| Infinite loops | Manual Ctrl+C | **Fuel metering** - execution halts when budget exhausted |
| Jailbroken prompts | Better prompts | **Immutable host logic** - security is code, not text |

## Quick Start

```bash
npm install ajs-clawbot
# or
bun add ajs-clawbot
```

```typescript
import { SafeExecutor } from 'ajs-clawbot'

const executor = new SafeExecutor()

// Execute a skill safely
const result = await executor.execute(
  './skills/weather',
  { city: 'Seattle' },
  {
    source: 'dm',  // DM from approved user
    workdir: '/app/workspace',
    allowedHosts: ['api.weather.gov'],
  }
)

if (result.success) {
  console.log(result.result)
} else {
  console.error(result.error)
}
```

## Core Concepts

### Zero Capabilities by Default

Agents start with **nothing**. They can't read files, fetch URLs, or execute commands unless you explicitly grant each capability:

```typescript
// This agent can ONLY compute - no I/O whatsoever
await executor.executeSource(
  `function calculate({ a, b }) { return { sum: a + b } }`,
  'calculator',
  { a: 5, b: 3 },
  { source: 'public', workdir: '/tmp' }
)
```

### Trust Levels

Instead of configuring every capability, use trust levels that match common patterns:

| Level | Capabilities | Use Case |
|-------|-------------|----------|
| `none` | Pure computation | Math, validation, data transformation |
| `network` | Fetch from allowed hosts | API lookups, webhooks |
| `read` | + Read allowed files | Code analysis, documentation |
| `llm` | + LLM API calls | AI-powered skills |
| `write` | + Write to allowed dirs | Code generation, file creation |
| `shell` | + Run allowed commands | Build tools, git operations |
| `full` | Extended access | Trusted skills only |

Trust levels are automatically restricted based on message source:

```typescript
// Public sources can only use 'none' or 'network'
// Group chats max out at 'llm'
// DMs from approved users max out at 'write'
// Only main session (local user) can use 'shell' or 'full'
```

### Capability Factories

For fine-grained control, create capabilities directly:

```typescript
import { 
  createShellCapability, 
  createFilesystemCapability,
  createFetchCapability,
  createLLMCapability 
} from 'ajs-clawbot'

// Shell: only these commands, only in this directory
const shell = createShellCapability({
  workdir: '/app/workspace',
  allowlist: [
    { binary: 'ls', argPatterns: [/^-[la]+$/] },
    { binary: 'cat', argPatterns: [/^[a-zA-Z0-9_\-\.\/]+$/] },
    { binary: 'git', argPatterns: [/^(status|log|diff)$/] },
  ]
})

// Filesystem: read source files, never secrets
const files = createFilesystemCapability({
  root: '/app/workspace',
  allowPatterns: ['**/*.ts', '**/*.js', '**/*.json'],
  // .env, SSH keys, etc. are blocked by default
  allowWrite: false,
})

// Fetch: only these domains
const fetch = createFetchCapability({
  allowedHosts: ['api.github.com', 'api.weather.gov'],
  rateLimit: 30, // requests per minute
})

// LLM: with budget limits
const llm = createLLMCapability({
  predict: myLLMClient.predict,
  maxTotalTokens: 50000, // per session
  maxRequests: 100,
})
```

## Writing Safe Skills

Skills are written in AJS (AsyncJS), a JavaScript subset that compiles to safe JSON:

```javascript
// skills/weather/skill.ajs
function getWeather({ city }) {
  let response = httpFetch({ 
    url: `https://api.weather.gov/gridpoints/SEW/124,67/forecast` 
  })
  return {
    city: city,
    forecast: response.properties.periods[0].detailedForecast
  }
}
```

```json
// skills/weather/manifest.json
{
  "name": "weather",
  "description": "Get weather forecast for a city",
  "trustLevel": "network",
  "capabilities": ["fetch"]
}
```

### What AJS Allows

- Functions, variables, conditionals, loops
- Object/array literals, destructuring, spread
- Template literals, ternary operators
- Math, JSON, Array, Object, String built-ins

### What AJS Forbids (and Why)

| Forbidden | Why |
|-----------|-----|
| `class` | Enables prototype pollution |
| `new` | Arbitrary object construction |
| `this` | Implicit context escapes sandbox |
| `eval`, `Function` | Code injection |
| `__proto__`, `.constructor` | Prototype pollution |
| `import`/`export` | Module system bypasses sandbox |
| `async`/`await` | VM handles async internally |

## Migration Guide

### Converting Existing Skills

**Before (unsafe JavaScript):**
```javascript
// This skill has unrestricted access to everything
async function searchAndSummarize(query) {
  const results = await fetch(`https://api.search.com?q=${query}`)
  const data = await results.json()
  
  // Could read any file
  const context = fs.readFileSync('.env', 'utf-8')
  
  // Could execute any command
  const { stdout } = await exec('whoami')
  
  return { results: data, user: stdout }
}
```

**After (safe AJS):**
```javascript
// This skill can only do what its capabilities allow
function searchAndSummarize({ query }) {
  // httpFetch only works if fetch capability is granted
  // and only to allowed hosts
  let response = httpFetch({ url: `https://api.search.com?q=${query}` })
  
  // Files can only be read if filesystem capability is granted
  // and only from allowed paths
  // (We removed the .env read - it wasn't needed)
  
  // Shell access requires shell capability
  // (We removed whoami - it wasn't needed)
  
  return { results: response }
}
```

### Gradual Migration

You don't have to convert everything at once. Use the safety middleware to add logging and trust checks to existing skills:

```typescript
import { createSafetyMiddleware, SafeExecutor } from 'ajs-clawbot'

const executor = new SafeExecutor()
const safeExecute = createSafetyMiddleware(executor)

// Wrap existing skill execution
const result = await safeExecute(
  () => existingSkillFunction(args),
  'skill-name',
  { source: 'dm', workdir: '/app' }
)
```

This provides:
- Trust level validation (blocks shell-level skills from public sources)
- Audit logging
- Execution timing
- Warnings about unconverted skills

## OpenClaw Integration

### Drop-in Executor

Replace OpenClaw's skill execution with the safe executor:

```typescript
// openclaw-config.js
import { createOpenClawExecutor } from 'ajs-clawbot'

export const safeExecutor = createOpenClawExecutor({
  workspaceRoot: process.env.OPENCLAW_WORKSPACE,
  llmPredict: anthropicClient.predict,
  allowedHosts: ['api.github.com', 'api.weather.gov'],
  onExecute: (skill, result) => {
    // Log to your audit system
    auditLog.record({
      skill,
      success: result.success,
      fuelUsed: result.fuelUsed,
      timestamp: Date.now(),
    })
  }
})
```

### Per-Channel Configuration

Different channels can have different trust levels:

```typescript
const channelConfig = {
  'main': { maxTrust: 'full' },
  'dm-approved': { maxTrust: 'write' },
  'dm-unknown': { maxTrust: 'network' },
  'group-private': { maxTrust: 'llm' },
  'group-public': { maxTrust: 'network' },
}
```

## API Reference

### SafeExecutor

```typescript
class SafeExecutor {
  constructor(options?: SafeExecutorOptions)
  
  // Execute skill by path
  execute(
    skillPath: string,
    args: Record<string, any>,
    context: ExecutionContext
  ): Promise<ExecutionResult>
  
  // Execute skill from source
  executeSource(
    source: string,
    name: string,
    args: Record<string, any>,
    context: ExecutionContext,
    trustLevel?: TrustLevel
  ): Promise<ExecutionResult>
  
  // Cache management
  clearCache(): void
  invalidateSkill(skillPath: string): void
}
```

### ExecutionContext

```typescript
interface ExecutionContext {
  source: 'main' | 'dm' | 'group' | 'public'
  userId?: string
  channelId?: string
  workdir: string
  allowedHosts?: string[]
  llmPredict?: (prompt: string, options?: any) => Promise<string>
  writableDirs?: string[]
  additionalCommands?: ShellCommand[]
  metadata?: Record<string, any>
}
```

### ExecutionResult

```typescript
interface ExecutionResult {
  result: any
  error?: Error
  fuelUsed: number
  trace?: any[]
  warnings?: string[]
  success: boolean
  durationMs: number
}
```

## Security Model

### Defense in Depth

1. **Syntax restrictions** - AJS forbids dangerous constructs at parse time
2. **Capability isolation** - No capability = no access, enforced by VM
3. **Resource limits** - Fuel metering prevents runaway execution
4. **Trust validation** - Source-based limits on what skills can run
5. **Path-based blocking** - Sensitive files blocked by pattern, not just path
6. **Opaque errors** - Blocked operations don't reveal why they failed
7. **Audit trails** - Every operation is traceable via `onBlocked` callbacks

### Always-Blocked Patterns

These files are blocked regardless of configuration:

| Category | Patterns |
|----------|----------|
| **Secrets** | `.env`, `.env.*`, `credentials.*`, `secrets.*` |
| **SSH** | `id_rsa`, `id_ed25519`, `.ssh/*`, `authorized_keys` |
| **Certificates** | `*.pem`, `*.key`, `*.p12`, `*.pfx` |
| **Git** | `.git/config`, `.gitconfig`, `.git-credentials` |
| **Package managers** | `.npmrc`, `.yarnrc` |
| **Cloud** | `.aws/*`, `.azure/*`, `.gcloud/*`, `.kube/*` |
| **Databases** | `*.sqlite`, `*.db` |

### Path Traversal Protection

All of these attacks are blocked:
- `../../../etc/passwd` - traversal
- `~/.ssh/id_rsa` - home directory
- `/etc/passwd` - absolute system paths
- `%2e%2e/etc/passwd` - encoded traversal

### Opaque Errors

Blocked operations return generic "Access denied" or "Command failed" messages.
Detailed reasons go to the `onBlocked` callback for your server logs only.

```typescript
const fs = createFilesystemCapability({
  root: '/app/workspace',
  onBlocked: (op, path, reason) => {
    // This goes to YOUR logs, not the agent
    securityLog.warn(`Blocked ${op} on ${path}: ${reason}`)
  }
})

// Agent sees: "Access denied"
// Your logs see: "Blocked read on credentials.json: Matches blocked pattern"
```

### What This Doesn't Protect Against

- Bugs in your capability implementations
- Side channels (timing attacks, etc.)
- Social engineering of the bot operator
- Vulnerabilities in the underlying runtime (Node.js, Bun)

This is a **sandbox**, not a security boundary for hostile code. It's designed to protect against accidents and casual attacks, not nation-state adversaries.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup and guidelines.

## License

Apache-2.0

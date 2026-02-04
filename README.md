# ajs-clawbot

**Architectural Human-in-the-Loop: Sudo for AI Agents**

Running an AI agent without proper sandboxing is like running a web server as root—possible, but irresponsible. This package provides the missing safety layer through **capability-based security** that makes dangerous operations impossible rather than merely discouraged.

## Runtime-Layer vs Application-Layer Permission

```
  APPLICATION-LAYER                      RUNTIME-LAYER (ajs-clawbot)
  ==================                     ===========================
                                        
  +------------------+                   +------------------+
  |   Agent Code     |                   |   Agent Code     |
  +--------+---------+                   +--------+---------+
           |                                      |
           v                                      v
  +------------------+                   +------------------+
  | if (allowed) {   |  <-- bypass!      |   fs.read()?     |
  |   fs.read()      |                   +--------+---------+
  | }                |                            |
  +--------+---------+                            v
           |                             +------------------+
           v                             | CAPABILITY NOT   |
  +------------------+                   | BOUND TO VM      |
  |  fs.read() runs  |                   |                  |
  |  (always exists) |                   | Function doesn't |
  +------------------+                   | exist to call!   |
                                         +------------------+
```

Most AI safety approaches use **Application-Layer Permission**: the capability exists, and a boolean check decides whether to use it. This is fundamentally flawed because:

- The check can be bypassed via prompt injection
- The capability is always *available*, just gated
- Security depends on the AI "following rules"

**ajs-clawbot** uses **Runtime-Layer Permission**: the capability literally doesn't exist until explicitly granted. There's nothing to bypass—the code physically cannot access what it hasn't been given.

| Approach | How It Works | Failure Mode |
|----------|-------------|--------------|
| **Application-Layer** | `if (allowed) { fs.read() }` | Prompt injection bypasses the `if` |
| **Runtime-Layer** | Capability not bound to VM | No `fs.read` function exists to call |

This is the same model used by browser sandboxes, WebAssembly, and operating system capabilities. It's not novel—it's proven.

## The Problem

OpenClaw/Clawbot is powerful: it can execute shell commands, write files, control browsers, and talk to external services. When you're the only user, that's fine. But when you expose your bot to a Discord server, Telegram group, or public channel, anyone can potentially:

1. **Execute arbitrary commands** via prompt injection
2. **Read sensitive files** (.env, SSH keys, browser cookies)
3. **Exfiltrate data** to attacker-controlled servers
4. **Run up massive API bills** with infinite loops
5. **Use your bot as an attack platform** for SSRF

Current "fixes" (regex filters, prompt engineering, "please don't do bad things") are Application-Layer Permission—trivially bypassed.

## The Solution

**ajs-clawbot** wraps skill execution in [tjs-lang](https://github.com/tonioloewald/tjs-lang)'s capability-based VM:

| Danger | Application-Layer "Fix" | ajs-clawbot (Runtime-Layer) |
|--------|------------------------|----------------------------|
| Malicious shell commands | Regex / "please don't" | **Capability not granted** - no shell function exists |
| Secret theft (.env) | "Don't look there" | **Filesystem capability** - can't read what you can't access |
| SSRF / data exfiltration | Auth tokens / hope | **Fetch capability** - domains must be explicitly allowed |
| Infinite loops | Manual Ctrl+C | **Fuel metering** - execution halts when budget exhausted |
| Jailbroken prompts | Better prompts | **Immutable host logic** - security is code, not text |

## JIT Capabilities: The Killer Feature

```
  HUMAN-IN-THE-LOOP FLOW
  ======================
                                        
  +----------+     +-----------+     +------------------+
  |  Agent   |---->|  Request  |---->|  Human/Policy    |
  |  Code    |     | Capability|     |  Decision Point  |
  +----------+     +-----------+     +--------+---------+
                                              |
                        +---------------------+---------------------+
                        |                                           |
                        v                                           v
               +----------------+                          +----------------+
               |    GRANTED     |                          |     DENIED     |
               | Capability now |                          | Still no access|
               | exists in VM   |                          | (safe default) |
               +----------------+                          +----------------+
```

Traditional permission systems are static: decide upfront what's allowed. This forces you to either:
- Over-provision (security risk)
- Under-provision (functionality loss)

**ajs-clawbot supports Just-In-Time (JIT) Capabilities**: grant permissions dynamically based on runtime context, user approval, or policy evaluation.

```typescript
const executor = new SafeExecutor({
  onCapabilityRequest: async (skill, capability, context) => {
    // Ask user for approval in real-time
    if (context.source === 'dm') {
      const approved = await askUser(
        `Skill "${skill}" wants ${capability} access. Allow?`
      )
      return approved ? 'grant' : 'deny'
    }
    // Auto-deny for public sources
    return 'deny'
  }
})
```

This enables **true human-in-the-loop security**: the agent can request elevated access, but a human (or policy engine) decides whether to grant it—at runtime, with full context.

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

## Performance

The sandbox overhead is negligible:

| Metric | Value |
|--------|-------|
| **Sandbox overhead per execution** | 0.174ms |
| As % of typical API call (100ms) | 0.17% |
| As % of typical LLM call (1000ms) | 0.017% |

Security doesn't have to mean slow. See [BENCHMARK.md](./BENCHMARK.md) for methodology and full results.

## Comparison: Standard OpenClaw vs ajs-clawbot

| Feature | Standard OpenClaw | With ajs-clawbot |
|---------|------------------|------------------|
| Shell access | Always available | Granted per-skill, per-context |
| File reading | Always available | Capability-gated, path-restricted |
| Network requests | Always available | Domain allowlist enforced |
| Infinite loops | Hope for the best | Fuel metering halts execution |
| Prompt injection | Vulnerable | Capabilities don't exist to exploit |
| Secret files | Rely on prompts | Blocked at runtime layer |
| Public channel safety | Risky | Safe by default (zero capabilities) |
| Audit trail | Manual logging | Built-in operation tracing |

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

## Rate Limiting & Flood Protection

Beyond capability isolation, ajs-clawbot includes protection against abuse patterns:

```typescript
import { createDefaultRateLimiter } from 'ajs-clawbot'

const executor = new SafeExecutor({
  selfIds: ['bot-user-id'],  // Reject messages from ourselves (recursion attack)
  rateLimiter: createDefaultRateLimiter(),
  onRateLimited: (reason, requesterId) => {
    console.log(`Rate limited ${requesterId}: ${reason}`)
  }
})
```

**Protections include:**
- **Self-message rejection** - Prevents recursion/reflection attacks
- **Per-requester limits** - Sliding window rate limiting
- **Global limits** - Protects against distributed flooding
- **Cooldown periods** - Automatic backoff for abusers

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
  
  // Rate limiter access
  getRateLimiter(): RateLimiter | undefined
  addSelfId(id: string): void
  isSelfId(id: string): boolean
  getRateLimitStats(): RateLimitStats
  clearUserCooldown(userId: string): void
  
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
6. **SSRF protection** - Private IPs, cloud metadata services, localhost all blocked
7. **Opaque errors** - Blocked operations don't reveal why they failed
8. **Audit trails** - Every operation is traceable via `onBlocked` callbacks
9. **Rate limiting** - Flood and recursion attack protection

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

### SSRF Protection

Network requests are validated against:
- **Private IP ranges** - 10.x, 172.16-31.x, 192.168.x, localhost
- **IPv6 private ranges** - fc00::/7, fe80::/10, ::1
- **IPv4-mapped IPv6** - ::ffff:192.168.x.x bypass attempts detected
- **Cloud metadata services** - 169.254.169.254, fd00:ec2::254
- **Blocked hostnames** - localhost, metadata.google.internal, etc.

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

## Why Not Just Use Docker?

```
  DOCKER CONTAINER                       AJS-CLAWBOT
  ================                       ===========
                                        
  +------------------------+             +------------------------+
  |     Container          |             |      AJS VM            |
  |  +------------------+  |             |  +------------------+  |
  |  |    AI Agent      |  |             |  |    AI Agent      |  |
  |  +------------------+  |             |  +------------------+  |
  |          |             |             |          |             |
  |          v             |             |          v             |
  |  +------------------+  |             |  +------------------+  |
  |  | FULL ACCESS to:  |  |             |  | ONLY what you    |  |
  |  | - all files      |  |             |  | granted:         |  |
  |  | - all network    |  |             |  | - specific files |  |
  |  | - all commands   |  |             |  | - specific hosts |  |
  |  +------------------+  |             |  | - specific cmds  |  |
  +------------------------+             |  +------------------+  |
           |                             +------------------------+
           v                                        |
    Heavy, slow startup                      Lightweight, instant
    Escape vulnerabilities                   No escalation possible
```

Containers provide process isolation but don't solve the core problem:

1. **The AI still has full access inside the container** - it can read all files, make all network calls, run all commands within its sandbox
2. **You still need capability restrictions** - Docker doesn't know which files are secrets or which URLs are safe
3. **Containers are heavy** - spinning up a container per request adds latency and resource overhead
4. **Escape vulnerabilities exist** - container breakouts happen; defense in depth means not relying solely on one boundary

ajs-clawbot works *inside* any deployment model (container, bare metal, serverless) and provides the fine-grained capability control that containers can't.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup and guidelines.

## License

Apache-2.0

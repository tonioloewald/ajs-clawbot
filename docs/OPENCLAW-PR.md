# RFC: Safe Skill Execution via Capability-Based Sandboxing

**Status:** Proposal  
**Author:** ajs-clawbot contributors  
**Target:** OpenClaw/openclaw  

## Summary

This PR introduces an optional safe execution layer for OpenClaw skills, using capability-based security to prevent privilege escalation from untrusted message sources.

## Motivation

OpenClaw's power comes from its ability to execute code, access files, and interact with external services. This is safe when you're the only user. But when you expose your bot to:

- Public Discord servers
- Telegram groups
- Open DM policies
- Shared workspaces

...anyone can potentially leverage prompt injection to:

1. Execute arbitrary shell commands
2. Read sensitive files (.env, SSH keys, credentials)
3. Exfiltrate data to attacker-controlled servers
4. Run up API bills with infinite loops
5. Use your infrastructure for attacks (SSRF)

Current mitigations (sandbox mode, pairing, allowlists) help but don't address the fundamental issue: **skills have more capabilities than they need**.

## Proposed Solution

Integrate `ajs-clawbot`, a capability-based execution layer built on [tjs-lang](https://github.com/tonioloewald/tjs-lang), which provides:

### 1. Zero Capabilities by Default

Skills start with no I/O access. Each capability (shell, filesystem, fetch, LLM) must be explicitly granted:

```typescript
// Skill can ONLY fetch from weather.gov - nothing else
await executor.execute(skill, args, {
  capabilities: {
    fetch: createFetchCapability({
      allowedHosts: ['api.weather.gov']
    })
  }
})
```

### 2. Trust Levels Based on Message Source

```
Source        Max Trust    Can Use
────────────────────────────────────
main          full         Everything
dm-approved   write        Files, LLM, fetch
dm-unknown    network      Fetch only
group         llm          LLM + fetch
public        network      Fetch only (limited)
```

Skills requesting higher trust than their source allows are automatically blocked.

### 3. Fuel Metering

Every operation costs fuel. Execution halts when the budget is exhausted:

```typescript
// This infinite loop will be stopped, not your server
await executor.execute(skill, args, { fuel: 1000 })
```

### 4. Audit Trails

Full execution tracing for accountability:

```typescript
const { trace } = await executor.execute(skill, args, { trace: true })
// trace: [{ op: 'httpFetch', url: '...', fuel: 990 }, ...]
```

## Integration Points

### Option A: Replace Skill Executor (Recommended)

```typescript
// config/executor.ts
import { createOpenClawExecutor } from 'ajs-clawbot'

export const skillExecutor = createOpenClawExecutor({
  workspaceRoot: process.env.OPENCLAW_WORKSPACE,
  llmPredict: anthropicClient.predict,
  allowedHosts: JSON.parse(process.env.ALLOWED_HOSTS || '[]'),
})
```

### Option B: Middleware Wrapper

For gradual migration, wrap existing execution:

```typescript
import { createSafetyMiddleware } from 'ajs-clawbot'

const safeExecute = createSafetyMiddleware(executor)

// Existing skills get trust validation + logging
await safeExecute(
  () => existingSkill(args),
  'skill-name',
  { source: messageSource }
)
```

### Option C: Per-Skill Opt-In

Add `safe: true` to skill manifests to enable sandboxed execution:

```yaml
# SKILL.md frontmatter
---
name: weather
trust: network
safe: true  # Execute in AJS sandbox
---
```

## Configuration

New config options in `openclaw.json`:

```json
{
  "safeExecution": {
    "enabled": true,
    "defaultTrust": {
      "main": "full",
      "dm": "write", 
      "group": "llm",
      "public": "network"
    },
    "allowedHosts": ["api.github.com", "api.weather.gov"],
    "fuelBudget": {
      "default": 1000,
      "llm": 2000,
      "shell": 2000
    },
    "auditLog": true
  }
}
```

## Migration Path

1. **Phase 1:** Add `ajs-clawbot` as optional dependency
2. **Phase 2:** Enable middleware wrapper for all skills (logging only)
3. **Phase 3:** Convert high-risk skills to AJS format
4. **Phase 4:** Enable trust enforcement for non-main sources
5. **Phase 5:** Default to safe execution for new skills

### Converting Skills to AJS

**Before:**
```javascript
async function searchGitHub(query) {
  const response = await fetch(`https://api.github.com/search?q=${query}`)
  return response.json()
}
```

**After:**
```javascript
function searchGitHub({ query }) {
  let response = httpFetch({ url: 'https://api.github.com/search?q=' + query })
  return response
}
```

Key differences:
- No `async/await` (VM handles async)
- No `fetch()` global (use `httpFetch` atom)
- Destructured input parameters
- Returns value directly (no explicit Promise)

## Backwards Compatibility

- Existing skills continue to work unchanged
- Safe execution is opt-in initially
- No breaking changes to config format
- Skills can be migrated incrementally

## Security Considerations

### What This Protects Against

- Prompt injection leading to shell execution
- Accidental credential exposure via file reads
- SSRF attacks through unrestricted fetch
- Resource exhaustion from infinite loops
- Privilege escalation from untrusted sources

### What This Doesn't Protect Against

- Bugs in capability implementations
- Social engineering of the operator
- Vulnerabilities in Node.js/Bun runtime
- Side-channel attacks

This is defense-in-depth, not a security boundary for hostile code.

## Performance Impact

- **Overhead:** ~0.5ms per skill execution (JSON AST interpretation)
- **Memory:** ~50KB per VM instance
- **Startup:** One-time 2ms for VM initialization

For I/O-bound skills (most of them), overhead is negligible.

## Testing

```bash
# Run ajs-clawbot tests
cd packages/ajs-clawbot
bun test

# Integration tests with OpenClaw
bun test:integration
```

## Open Questions

1. Should safe execution be opt-in or opt-out for new installs?
2. How should we handle skills that legitimately need shell access?
3. Should trust levels be configurable per-skill or per-source?
4. Do we need a skill certification/signing system?

## References

- [ajs-clawbot repository](https://github.com/tonioloewald/ajs-clawbot)
- [tjs-lang documentation](https://github.com/tonioloewald/tjs-lang)
- [Capability-based security (Wikipedia)](https://en.wikipedia.org/wiki/Capability-based_security)
- [OWASP Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

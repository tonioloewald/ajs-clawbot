# Migration Guide: Converting OpenClaw Skills to Safe AJS

This guide walks through converting existing OpenClaw skills to AJS format for safe sandboxed execution.

## Why Migrate?

| Unsafe Skill | Safe AJS Skill |
|--------------|----------------|
| Can access any file | Can only access files you allow |
| Can execute any command | Can only run commands you allow |
| Can fetch any URL | Can only fetch from allowed hosts |
| Can run forever | Stops when fuel budget exhausted |
| Trust based on prompts | Trust enforced by code |

## Quick Reference

### Syntax Changes

| JavaScript | AJS |
|------------|-----|
| `async function name()` | `function name()` |
| `await fetch(url)` | `httpFetch({ url: url })` |
| `await fs.readFile(path)` | `files.read(path)` |
| `await fs.writeFile(path, data)` | `files.write(path, data)` |
| `await exec(cmd)` | `shell.run(cmd)` |
| `import x from 'y'` | *(not supported - use capabilities)* |
| `class Foo {}` | *(not supported - use functions)* |
| `this.something` | *(not supported - pass as parameter)* |

### Capability Mapping

| OpenClaw Feature | AJS Capability | Trust Level |
|------------------|----------------|-------------|
| `fetch()` | `httpFetch()` | `network` |
| `fs.readFile()` | `files.read()` | `read` |
| `fs.writeFile()` | `files.write()` | `write` |
| `child_process.exec()` | `shell.run()` | `shell` |
| LLM calls | `llmPredict()` | `llm` |

## Step-by-Step Migration

### Step 1: Identify Capabilities Used

Look at your existing skill and list what it accesses:

```javascript
// Original skill
async function mySkill(input) {
  // Uses: fetch (network)
  const data = await fetch('https://api.example.com/data')
  
  // Uses: fs (read)
  const config = await fs.readFile('./config.json')
  
  // Uses: LLM
  const summary = await llm.predict('Summarize: ' + data)
  
  return { data, summary }
}
```

Capabilities needed: `fetch`, `files`, `llm`  
Trust level: `llm` (highest of the three)

### Step 2: Convert Syntax

```javascript
// Converted AJS skill
function mySkill({ input }) {
  // Network access via httpFetch atom
  let data = httpFetch({ url: 'https://api.example.com/data' })
  
  // File access via files capability
  let config = files.read('./config.json')
  
  // LLM access via llmPredict atom
  let summary = llmPredict({ prompt: 'Summarize: ' + JSON.stringify(data) })
  
  return { data: data, summary: summary }
}
```

### Step 3: Create Manifest

```json
{
  "name": "my-skill",
  "description": "Fetches data and summarizes it",
  "version": "1.0.0",
  "trustLevel": "llm",
  "capabilities": ["fetch", "files", "llm"],
  "inputSchema": {
    "type": "object",
    "properties": {
      "input": { "type": "string" }
    },
    "required": ["input"]
  }
}
```

### Step 4: Test

```typescript
import { SafeExecutor } from 'ajs-clawbot'

const executor = new SafeExecutor({ trace: true })

const result = await executor.execute(
  './skills/my-skill',
  { input: 'test' },
  {
    source: 'main',
    workdir: '/app/workspace',
    allowedHosts: ['api.example.com'],
    llmPredict: myLLMClient.predict,
  }
)

console.log(result)
```

## Common Patterns

### Pattern: API Lookup

**Before:**
```javascript
async function lookupWeather(city) {
  const response = await fetch(`https://api.weather.gov/...`)
  const data = await response.json()
  return data.forecast
}
```

**After:**
```javascript
function lookupWeather({ city }) {
  let response = httpFetch({ url: 'https://api.weather.gov/...' })
  return { forecast: response.properties.periods[0] }
}
```

### Pattern: File Processing

**Before:**
```javascript
async function processFile(path) {
  const content = await fs.readFile(path, 'utf-8')
  const processed = content.toUpperCase()
  await fs.writeFile(path + '.processed', processed)
  return { success: true }
}
```

**After:**
```javascript
function processFile({ path }) {
  let content = files.read(path)
  let processed = content.toUpperCase()
  files.write(path + '.processed', processed)
  return { success: true }
}
```

### Pattern: LLM Chat

**Before:**
```javascript
async function chat(message, history) {
  const response = await anthropic.messages.create({
    messages: [...history, { role: 'user', content: message }]
  })
  return response.content[0].text
}
```

**After:**
```javascript
function chat({ message, history }) {
  let prompt = ''
  for (let msg of history) {
    prompt = prompt + msg.role + ': ' + msg.content + '\n'
  }
  prompt = prompt + 'user: ' + message
  
  let response = llmPredict({ prompt: prompt })
  return { response: response }
}
```

### Pattern: Conditional Logic

**Before:**
```javascript
async function route(request) {
  if (request.type === 'search') {
    return await searchHandler(request)
  } else if (request.type === 'create') {
    return await createHandler(request)
  }
  throw new Error('Unknown type')
}
```

**After:**
```javascript
function route({ request }) {
  if (request.type === 'search') {
    // Inline the handler or call another skill via agentRun
    let results = httpFetch({ url: '/search?q=' + request.query })
    return { type: 'search', results: results }
  }
  
  if (request.type === 'create') {
    files.write('/data/' + request.id + '.json', JSON.stringify(request.data))
    return { type: 'create', id: request.id }
  }
  
  return { error: 'Unknown type: ' + request.type }
}
```

## Things That Won't Convert

### Classes

AJS doesn't support classes. Refactor to functions:

```javascript
// Won't work
class DataProcessor {
  constructor(config) { this.config = config }
  process(data) { return transform(data, this.config) }
}

// Instead, pass config as a parameter
function processData({ data, config }) {
  return transform(data, config)
}
```

### Closures

AJS doesn't support closures that capture outer scope:

```javascript
// Won't work
function createCounter() {
  let count = 0
  return () => ++count
}

// Instead, manage state through the store capability
function incrementCounter({ key }) {
  let current = storeGet({ key: key }) ?? 0
  let next = current + 1
  storeSet({ key: key, value: next })
  return { count: next }
}
```

### Dynamic Imports

```javascript
// Won't work
const module = await import(dynamicPath)

// Instead, use capabilities or agentRun for sub-agents
```

### eval / Function Constructor

```javascript
// Won't work (and shouldn't!)
eval(userInput)
new Function(code)()

// These are security holes - there's no safe equivalent
```

## Handling Errors

AJS uses monadic error handling - errors are values, not exceptions:

```javascript
function riskyOperation({ input }) {
  let result = httpFetch({ url: 'https://api.example.com/' + input })
  
  // Check for error
  if (result.$error) {
    return { success: false, error: result.$error }
  }
  
  return { success: true, data: result }
}
```

For explicit error handling, use try/catch:

```javascript
function safeOperation({ input }) {
  try {
    let result = riskyThing(input)
    return { success: true, result: result }
  } catch (e) {
    return { success: false, error: e.message }
  }
}
```

## Testing Your Converted Skill

### Unit Test

```typescript
import { loadSkillFromSource, validateSkill } from 'ajs-clawbot'

const skill = loadSkillFromSource(source, 'my-skill')

// Validate structure
const validation = validateSkill(skill)
expect(validation.valid).toBe(true)

// Check inferred trust level
expect(skill.trustLevel).toBe('llm')
```

### Integration Test

```typescript
import { SafeExecutor, createMockLLM } from 'ajs-clawbot'

const executor = new SafeExecutor()

const result = await executor.execute(
  './skills/my-skill',
  { input: 'test' },
  {
    source: 'main',
    workdir: '/tmp/test',
    llmPredict: createMockLLM({ 'Summarize': 'Mock summary' }).predict,
  }
)

expect(result.success).toBe(true)
expect(result.result.summary).toBe('Mock summary')
```

## Gradual Migration Strategy

You don't have to convert everything at once:

1. **Identify high-risk skills** - Those exposed to public sources
2. **Start with simple skills** - Pure computation, single capability
3. **Use middleware** - Add logging/trust checks to unconverted skills
4. **Convert incrementally** - One skill at a time
5. **Test thoroughly** - Each converted skill needs integration tests

## Getting Help

- [AJS Language Reference](../../tosijs-agent/DOCS-AJS.md)
- [Capability API Reference](../README.md#api-reference)
- [Example Skills](../examples/skills/)

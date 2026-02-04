/**
 * Skill Loader
 *
 * Loads OpenClaw-style skills and converts them to AJS agents that can
 * run in the safe VM. Supports both AJS-native skills and legacy skill
 * formats with automatic conversion.
 */

import { ajs, transpile, type AgentAST } from 'tjs-lang'
import { readFileSync, existsSync } from 'fs'
import { join, dirname, basename, extname } from 'path'
import { type TrustLevel, inferTrustLevel } from './trust-levels'

export interface SkillManifest {
  /** Skill name */
  name: string

  /** Human-readable description */
  description?: string

  /** Version string */
  version?: string

  /** Required trust level (if not specified, will be inferred) */
  trustLevel?: TrustLevel

  /** Capabilities this skill uses (for trust inference) */
  capabilities?: string[]

  /** Input schema (JSON Schema) */
  inputSchema?: Record<string, any>

  /** Output schema (JSON Schema) */
  outputSchema?: Record<string, any>

  /** Tags for categorization */
  tags?: string[]

  /** Author */
  author?: string

  /** Source file (relative to manifest) */
  source?: string
}

export interface LoadedSkill {
  /** The skill manifest */
  manifest: SkillManifest

  /** Compiled AJS agent AST */
  ast: AgentAST

  /** Inferred or declared trust level */
  trustLevel: TrustLevel

  /** Path to the skill directory */
  path: string

  /** Original source code */
  source: string
}

/**
 * Load a skill from an OpenClaw-style skill directory.
 *
 * Expects either:
 * - skill.ajs (AJS source)
 * - skill.js (JavaScript that will be analyzed)
 * - SKILL.md (OpenClaw manifest with embedded code)
 *
 * Plus optional:
 * - manifest.json (skill metadata)
 */
export function loadSkill(skillPath: string): LoadedSkill {
  // Check what files exist
  const ajsPath = join(skillPath, 'skill.ajs')
  const jsPath = join(skillPath, 'skill.js')
  const mdPath = join(skillPath, 'SKILL.md')
  const manifestPath = join(skillPath, 'manifest.json')

  // Load manifest if exists
  let manifest: SkillManifest = {
    name: basename(skillPath),
  }

  if (existsSync(manifestPath)) {
    try {
      const manifestContent = readFileSync(manifestPath, 'utf-8')
      manifest = { ...manifest, ...JSON.parse(manifestContent) }
    } catch (e) {
      console.warn(`Failed to parse manifest.json for skill ${skillPath}`)
    }
  }

  // Load source code
  let source: string
  let sourceType: 'ajs' | 'js' | 'md'

  if (existsSync(ajsPath)) {
    source = readFileSync(ajsPath, 'utf-8')
    sourceType = 'ajs'
  } else if (existsSync(jsPath)) {
    source = readFileSync(jsPath, 'utf-8')
    sourceType = 'js'
  } else if (existsSync(mdPath)) {
    source = extractCodeFromMarkdown(readFileSync(mdPath, 'utf-8'))
    sourceType = 'md'
    // Also extract manifest from markdown frontmatter
    const mdManifest = extractManifestFromMarkdown(readFileSync(mdPath, 'utf-8'))
    manifest = { ...manifest, ...mdManifest }
  } else {
    throw new Error(`No skill source found in ${skillPath}. Expected skill.ajs, skill.js, or SKILL.md`)
  }

  // Transpile to AST
  let ast: AgentAST
  try {
    if (sourceType === 'ajs' || sourceType === 'md') {
      ast = transpile(source).ast as AgentAST
    } else {
      // JavaScript needs conversion
      ast = convertJsToAjs(source)
    }
  } catch (e: any) {
    throw new Error(`Failed to compile skill ${manifest.name}: ${e.message}`)
  }

  // Determine trust level
  const trustLevel = manifest.trustLevel || inferTrustLevel(manifest.capabilities || detectCapabilities(source))

  return {
    manifest,
    ast,
    trustLevel,
    path: skillPath,
    source,
  }
}

/**
 * Load a skill directly from AJS source code
 */
export function loadSkillFromSource(source: string, name: string, options?: Partial<SkillManifest>): LoadedSkill {
  const ast = transpile(source).ast as AgentAST
  const capabilities = detectCapabilities(source)
  const trustLevel = options?.trustLevel || inferTrustLevel(capabilities)

  return {
    manifest: {
      name,
      capabilities,
      ...options,
    },
    ast,
    trustLevel,
    path: '',
    source,
  }
}

/**
 * Extract code blocks from OpenClaw-style SKILL.md
 */
function extractCodeFromMarkdown(markdown: string): string {
  // Look for ```javascript or ```js code blocks
  const codeBlockRegex = /```(?:javascript|js|ajs)\n([\s\S]*?)```/g
  const blocks: string[] = []

  let match
  while ((match = codeBlockRegex.exec(markdown)) !== null) {
    blocks.push(match[1])
  }

  if (blocks.length === 0) {
    throw new Error('No code blocks found in SKILL.md')
  }

  // Return the first block that looks like a function
  for (const block of blocks) {
    if (block.includes('function') || block.includes('=>')) {
      return block
    }
  }

  return blocks[0]
}

/**
 * Extract manifest-like properties from SKILL.md frontmatter
 */
function extractManifestFromMarkdown(markdown: string): Partial<SkillManifest> {
  const manifest: Partial<SkillManifest> = {}

  // Check for YAML frontmatter
  const frontmatterMatch = markdown.match(/^---\n([\s\S]*?)\n---/)
  if (frontmatterMatch) {
    const frontmatter = frontmatterMatch[1]
    // Simple YAML parsing for common fields
    const nameMatch = frontmatter.match(/name:\s*(.+)/)
    if (nameMatch) manifest.name = nameMatch[1].trim()

    const descMatch = frontmatter.match(/description:\s*(.+)/)
    if (descMatch) manifest.description = descMatch[1].trim()

    const trustMatch = frontmatter.match(/trust(?:Level)?:\s*(.+)/)
    if (trustMatch) manifest.trustLevel = trustMatch[1].trim() as TrustLevel
  }

  // Also check for # Title as name
  const titleMatch = markdown.match(/^#\s+(.+)/m)
  if (titleMatch && !manifest.name) {
    manifest.name = titleMatch[1].trim()
  }

  // Check for description in first paragraph
  const descMatch = markdown.match(/^#.+\n\n(.+?)(?:\n\n|```)/s)
  if (descMatch && !manifest.description) {
    manifest.description = descMatch[1].trim()
  }

  return manifest
}

/**
 * Detect capabilities used in source code
 */
function detectCapabilities(source: string): string[] {
  const capabilities: string[] = []

  // Shell/exec detection
  if (/\b(exec|spawn|shell|subprocess|child_process)\b/i.test(source)) {
    capabilities.push('shell')
  }

  // File system detection
  if (/\b(readFile|writeFile|fs\.|readdir|mkdir|unlink|existsSync)\b/i.test(source)) {
    if (/\b(writeFile|mkdir|unlink)\b/i.test(source)) {
      capabilities.push('write')
    } else {
      capabilities.push('read')
    }
  }

  // Network detection
  if (/\b(fetch|http|request|axios|got)\b/i.test(source)) {
    capabilities.push('fetch')
  }

  // LLM detection
  if (/\b(llm|predict|openai|anthropic|claude|gpt|embed)\b/i.test(source)) {
    capabilities.push('llm')
  }

  return capabilities
}

/**
 * Convert JavaScript to AJS (best-effort)
 *
 * This handles simple cases but complex JS may need manual conversion.
 */
function convertJsToAjs(jsSource: string): AgentAST {
  // Remove async/await (AJS handles this internally)
  let converted = jsSource
    .replace(/\basync\s+/g, '')
    .replace(/\bawait\s+/g, '')

  // Remove module imports/exports (AJS doesn't support them)
  converted = converted
    .replace(/^import\s+.*$/gm, '// import removed')
    .replace(/^export\s+(default\s+)?/gm, '')

  // Remove class definitions (not supported)
  if (/\bclass\s+/.test(converted)) {
    throw new Error('AJS does not support class definitions. Please refactor to functions.')
  }

  // Remove this references
  if (/\bthis\./g.test(converted)) {
    throw new Error('AJS does not support "this". Please refactor to avoid implicit context.')
  }

  // Try to transpile
  return transpile(converted).ast as AgentAST
}

/**
 * Validate that a loaded skill is safe to run
 */
export function validateSkill(skill: LoadedSkill): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  // Check for dangerous patterns in source
  const dangerousPatterns = [
    { pattern: /eval\s*\(/, message: 'eval() is not allowed' },
    { pattern: /Function\s*\(/, message: 'Function constructor is not allowed' },
    { pattern: /require\s*\(/, message: 'require() is not allowed in AJS' },
    { pattern: /__proto__/, message: '__proto__ access is forbidden' },
    { pattern: /\.constructor/, message: '.constructor access is forbidden' },
    { pattern: /\.prototype/, message: '.prototype access is forbidden' },
  ]

  for (const { pattern, message } of dangerousPatterns) {
    if (pattern.test(skill.source)) {
      errors.push(message)
    }
  }

  // Validate AST structure
  if (!skill.ast || skill.ast.op !== 'seq') {
    errors.push('Invalid AST structure: root must be a sequence')
  }

  return {
    valid: errors.length === 0,
    errors,
  }
}

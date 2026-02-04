/**
 * Safe Skill Executor for OpenClaw
 *
 * This module provides a drop-in replacement for OpenClaw's skill execution
 * that routes all skill execution through tjs-lang's AgentVM with capability
 * constraints.
 *
 * Instead of skills having unrestricted access to the host machine,
 * they run in a sandboxed VM with only the capabilities you've granted.
 */

export * from './safe-executor'
export * from './skill-loader'
export * from './trust-levels'

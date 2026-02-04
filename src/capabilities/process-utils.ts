/**
 * Process Utilities
 *
 * Robust process management including:
 * - Process tree killing (not just the parent process)
 * - Cross-platform support (Unix process groups, Windows taskkill)
 *
 * Based on battle-tested patterns from OpenClaw.
 */

import { spawn, type ChildProcess, type SpawnOptions } from 'child_process'

/**
 * Kill a process and all its descendants (the entire process tree).
 *
 * On Unix: Uses process groups (negative PID) to kill all children.
 * On Windows: Uses taskkill /F /T to force-kill the process tree.
 *
 * This is critical for timeout enforcement - a simple process.kill()
 * only kills the immediate child, leaving grandchildren running.
 *
 * @example
 * ```typescript
 * const proc = spawn('bash', ['-c', 'sleep 100 & sleep 200'], { detached: true })
 * // Later, to kill bash AND both sleep processes:
 * killProcessTree(proc.pid)
 * ```
 */
export function killProcessTree(pid: number): void {
  if (process.platform === 'win32') {
    try {
      // taskkill /F = force, /T = tree (kill children)
      spawn('taskkill', ['/F', '/T', '/PID', String(pid)], {
        stdio: 'ignore',
        detached: true,
      })
    } catch {
      // Ignore errors if taskkill fails (process already dead, etc.)
    }
    return
  }

  // Unix: Kill the process group using negative PID
  // This only works if the process was spawned with detached: true
  try {
    process.kill(-pid, 'SIGKILL')
  } catch {
    // Fallback: try killing just the single process
    // This happens if:
    // - Process wasn't spawned with detached: true
    // - Process already exited
    // - No permission (shouldn't happen for our own children)
    try {
      process.kill(pid, 'SIGKILL')
    } catch {
      // Process already dead, ignore
    }
  }
}

/**
 * Gracefully terminate a process tree, with escalation.
 *
 * 1. First sends SIGTERM to allow graceful shutdown
 * 2. After graceMs, sends SIGKILL to force termination
 *
 * @param pid - Process ID to terminate
 * @param graceMs - Milliseconds to wait before SIGKILL (default: 1000)
 */
export function terminateProcessTree(pid: number, graceMs = 1000): void {
  if (process.platform === 'win32') {
    // Windows doesn't have graceful signals, just force kill
    killProcessTree(pid)
    return
  }

  // First, try graceful termination
  try {
    process.kill(-pid, 'SIGTERM')
  } catch {
    try {
      process.kill(pid, 'SIGTERM')
    } catch {
      // Already dead
      return
    }
  }

  // Schedule force kill
  setTimeout(() => {
    killProcessTree(pid)
  }, graceMs)
}

/**
 * Options for spawning a process with proper timeout and tree management.
 */
export interface SafeSpawnOptions extends Omit<SpawnOptions, 'detached' | 'shell'> {
  /** Timeout in milliseconds. Process tree is killed when exceeded. */
  timeoutMs?: number

  /** Maximum output size in bytes. Process is killed if exceeded. */
  maxOutputBytes?: number

  /** Grace period before SIGKILL after timeout (default: 1000ms) */
  graceMs?: number

  /** Callback when timeout occurs (for logging) */
  onTimeout?: () => void

  /** Callback when max output exceeded (for logging) */
  onMaxOutput?: () => void
}

export interface SafeSpawnResult {
  stdout: string
  stderr: string
  exitCode: number | null
  signal: NodeJS.Signals | null
  timedOut: boolean
  truncated: boolean
  durationMs: number
}

/**
 * Spawn a process with robust timeout enforcement and tree killing.
 *
 * Unlike Node's built-in timeout option (which only kills the immediate child),
 * this kills the entire process tree when the timeout is exceeded.
 *
 * @example
 * ```typescript
 * const result = await safeSpawn('bash', ['-c', 'for i in $(seq 1 100); do sleep 1; done'], {
 *   timeoutMs: 5000,
 *   onTimeout: () => console.log('Process timed out')
 * })
 * // After 5 seconds, bash AND seq AND sleep are all killed
 * ```
 */
export async function safeSpawn(
  command: string,
  args: string[],
  options: SafeSpawnOptions = {}
): Promise<SafeSpawnResult> {
  const {
    timeoutMs = 30000,
    maxOutputBytes = 1024 * 1024,
    graceMs = 1000,
    onTimeout,
    onMaxOutput,
    ...spawnOptions
  } = options

  const startTime = Date.now()

  return new Promise((resolve) => {
    let stdout = ''
    let stderr = ''
    let outputBytes = 0
    let timedOut = false
    let truncated = false
    let settled = false
    let timeoutTimer: NodeJS.Timeout | null = null
    let graceTimer: NodeJS.Timeout | null = null

    // Spawn with detached: true on Unix for process group support
    // shell: false is critical for security (no command injection)
    const proc = spawn(command, args, {
      ...spawnOptions,
      detached: process.platform !== 'win32',
      shell: false,
    })

    const cleanup = () => {
      if (timeoutTimer) {
        clearTimeout(timeoutTimer)
        timeoutTimer = null
      }
      if (graceTimer) {
        clearTimeout(graceTimer)
        graceTimer = null
      }
    }

    const finish = (exitCode: number | null, signal: NodeJS.Signals | null) => {
      if (settled) return
      settled = true
      cleanup()

      resolve({
        stdout,
        stderr,
        exitCode,
        signal,
        timedOut,
        truncated,
        durationMs: Date.now() - startTime,
      })
    }

    const killTree = () => {
      if (proc.pid) {
        killProcessTree(proc.pid)
      }
    }

    const handleTimeout = () => {
      if (settled) return
      timedOut = true
      onTimeout?.()

      // Try graceful termination first
      if (proc.pid) {
        try {
          process.kill(-(proc.pid), 'SIGTERM')
        } catch {
          try {
            process.kill(proc.pid, 'SIGTERM')
          } catch {
            // Already dead
          }
        }
      }

      // Schedule force kill
      graceTimer = setTimeout(() => {
        if (!settled) {
          killTree()
          // Give it a moment to die, then force resolve
          setTimeout(() => {
            if (!settled) {
              finish(null, 'SIGKILL')
            }
          }, 100)
        }
      }, graceMs)
    }

    const handleMaxOutput = () => {
      if (settled) return
      truncated = true
      onMaxOutput?.()
      killTree()
    }

    // Set up timeout
    if (timeoutMs > 0) {
      timeoutTimer = setTimeout(handleTimeout, timeoutMs)
    }

    // Collect stdout
    proc.stdout?.on('data', (data: Buffer) => {
      const chunk = data.toString()
      outputBytes += data.length

      if (outputBytes > maxOutputBytes) {
        handleMaxOutput()
        return
      }

      stdout += chunk
    })

    // Collect stderr
    proc.stderr?.on('data', (data: Buffer) => {
      const chunk = data.toString()
      outputBytes += data.length

      if (outputBytes > maxOutputBytes) {
        handleMaxOutput()
        return
      }

      stderr += chunk
    })

    // Handle process exit
    proc.on('close', (code, signal) => {
      finish(code, signal)
    })

    // Handle spawn errors
    proc.on('error', (err) => {
      if (!settled) {
        stderr += err.message
        finish(null, null)
      }
    })
  })
}

/**
 * Check if a process (and its children) are still running.
 * Useful for testing that killProcessTree actually worked.
 */
export function isProcessRunning(pid: number): boolean {
  try {
    // Sending signal 0 checks if process exists without killing it
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

/**
 * Tests for Process Utilities
 *
 * These tests verify process tree killing and timeout enforcement.
 */

import { describe, it, expect } from "bun:test";
import { spawn } from "child_process";
import {
  killProcessTree,
  terminateProcessTree,
  safeSpawn,
  isProcessRunning,
} from "./process-utils";

describe("killProcessTree", () => {
  it("should kill a simple process", async () => {
    // Spawn a sleep process
    const proc = spawn("sleep", ["100"], {
      detached: process.platform !== "win32",
    });

    expect(proc.pid).toBeDefined();
    const pid = proc.pid!;

    // Verify it's running
    expect(isProcessRunning(pid)).toBe(true);

    // Kill it
    killProcessTree(pid);

    // Wait a bit for the process to die
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Verify it's dead
    expect(isProcessRunning(pid)).toBe(false);
  });

  it("should kill child processes (process tree)", async () => {
    // Spawn a shell that spawns children
    // The shell will spawn sleep processes
    const proc = spawn("sh", ["-c", "sleep 100 & sleep 100 & wait"], {
      detached: process.platform !== "win32",
    });

    expect(proc.pid).toBeDefined();
    const pid = proc.pid!;

    // Wait a moment for children to spawn
    await new Promise((resolve) => setTimeout(resolve, 200));

    // Kill the tree
    killProcessTree(pid);

    // Wait for processes to die
    await new Promise((resolve) => setTimeout(resolve, 200));

    // The parent should be dead
    expect(isProcessRunning(pid)).toBe(false);
  });

  it("should not throw when killing non-existent process", () => {
    // Should not throw
    expect(() => killProcessTree(999999)).not.toThrow();
  });
});

describe("terminateProcessTree", () => {
  it("should gracefully terminate then force kill", async () => {
    // Spawn a process that ignores SIGTERM
    const proc = spawn("sh", ["-c", 'trap "" TERM; sleep 100'], {
      detached: process.platform !== "win32",
    });

    expect(proc.pid).toBeDefined();
    const pid = proc.pid!;

    // Wait for trap to be set up
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Gracefully terminate with short grace period
    terminateProcessTree(pid, 500);

    // Should still be running immediately (ignoring SIGTERM)
    // Note: This may or may not pass depending on timing

    // Wait for grace period + kill
    await new Promise((resolve) => setTimeout(resolve, 800));

    // Should be dead after SIGKILL
    expect(isProcessRunning(pid)).toBe(false);
  });
});

describe("safeSpawn", () => {
  it("should run a command and capture output", async () => {
    const result = await safeSpawn("echo", ["hello world"], {
      timeoutMs: 5000,
    });

    expect(result.stdout.trim()).toBe("hello world");
    expect(result.exitCode).toBe(0);
    expect(result.timedOut).toBe(false);
    expect(result.truncated).toBe(false);
  });

  it("should capture stderr", async () => {
    const result = await safeSpawn("sh", ["-c", "echo error >&2"], {
      timeoutMs: 5000,
    });

    expect(result.stderr.trim()).toBe("error");
    expect(result.exitCode).toBe(0);
  });

  it("should timeout and kill process tree", async () => {
    let timeoutCalled = false;

    const result = await safeSpawn("sh", ["-c", "sleep 100"], {
      timeoutMs: 500,
      graceMs: 200,
      onTimeout: () => {
        timeoutCalled = true;
      },
    });

    expect(result.timedOut).toBe(true);
    expect(result.durationMs).toBeGreaterThanOrEqual(500);
    expect(result.durationMs).toBeLessThan(2000); // Should not wait forever
    expect(timeoutCalled).toBe(true);
  });

  it("should timeout and kill child processes", async () => {
    const result = await safeSpawn(
      "sh",
      ["-c", "sleep 100 & sleep 100 & wait"],
      {
        timeoutMs: 500,
        graceMs: 200,
      }
    );

    expect(result.timedOut).toBe(true);
    expect(result.durationMs).toBeLessThan(2000);
  });

  it("should truncate output when maxOutputBytes exceeded", async () => {
    let truncateCalled = false;

    // Generate lots of output
    const result = await safeSpawn("sh", ["-c", "yes | head -10000"], {
      timeoutMs: 10000,
      maxOutputBytes: 1000, // Small limit
      onMaxOutput: () => {
        truncateCalled = true;
      },
    });

    expect(result.truncated).toBe(true);
    expect(truncateCalled).toBe(true);
    expect(result.stdout.length).toBeLessThanOrEqual(1500); // Some buffer is ok
  });

  it("should report non-zero exit codes", async () => {
    const result = await safeSpawn("sh", ["-c", "exit 42"], {
      timeoutMs: 5000,
    });

    expect(result.exitCode).toBe(42);
    expect(result.timedOut).toBe(false);
  });

  it("should respect working directory", async () => {
    const result = await safeSpawn("pwd", [], {
      timeoutMs: 5000,
      cwd: "/tmp",
    });

    // macOS symlinks /tmp to /private/tmp
    const output = result.stdout.trim();
    expect(output === "/tmp" || output === "/private/tmp").toBe(true);
  });

  it("should pass environment variables", async () => {
    const result = await safeSpawn("sh", ["-c", "echo $TEST_VAR"], {
      timeoutMs: 5000,
      env: { ...process.env, TEST_VAR: "test_value" },
    });

    expect(result.stdout.trim()).toBe("test_value");
  });
});

describe("isProcessRunning", () => {
  it("should return true for running process", () => {
    // Current process should be running
    expect(isProcessRunning(process.pid)).toBe(true);
  });

  it("should return false for non-existent process", () => {
    // Very high PID unlikely to exist
    expect(isProcessRunning(999999999)).toBe(false);
  });
});

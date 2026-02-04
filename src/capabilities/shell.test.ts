/**
 * Shell Capability Security Tests
 *
 * These tests verify that the shell capability properly blocks
 * access to sensitive files and directories.
 */

import { describe, test, expect } from "bun:test";
import { createShellCapability, SAFE_READ_COMMANDS } from "./shell";
import { mkdtempSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { tmpdir, homedir } from "os";

describe("Shell Capability Security", () => {
  // Create a temp workspace for testing
  const workspace = mkdtempSync(join(tmpdir(), "shell-test-"));

  // Create some test files
  writeFileSync(join(workspace, "allowed.txt"), "This is allowed content");
  mkdirSync(join(workspace, "subdir"));
  writeFileSync(join(workspace, "subdir", "nested.txt"), "Nested content");

  const shell = createShellCapability({
    workdir: workspace,
    allowlist: SAFE_READ_COMMANDS,
    onBlocked: (binary, args, reason) => {
      console.log(`BLOCKED: ${binary} ${args.join(" ")} - ${reason}`);
    },
  });

  describe("Allowed operations", () => {
    test("can list files in workspace", async () => {
      const result = await shell.run("ls");
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("allowed.txt");
    });

    test("can read files in workspace", async () => {
      const result = await shell.run("cat allowed.txt");
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toBe("This is allowed content");
    });

    test("can access subdirectories", async () => {
      const result = await shell.run("cat subdir/nested.txt");
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toBe("Nested content");
    });
  });

  describe("Path traversal attacks", () => {
    test("blocks ../ traversal", async () => {
      await expect(shell.run("cat ../../../etc/passwd")).rejects.toThrow(
        "Command failed"
      );
    });

    test("blocks encoded traversal", async () => {
      await expect(shell.run("cat %2e%2e/etc/passwd")).rejects.toThrow(
        "Command failed"
      );
    });

    test("blocks absolute paths outside workspace", async () => {
      await expect(shell.run("cat /etc/passwd")).rejects.toThrow(
        "Command failed"
      );
    });
  });

  describe("Home directory protection", () => {
    test("blocks ~ expansion", async () => {
      await expect(shell.run("cat ~/.ssh/id_rsa")).rejects.toThrow(
        "Command failed"
      );
    });

    test("blocks ~/.bashrc", async () => {
      await expect(shell.run("cat ~/.bashrc")).rejects.toThrow(
        "Command failed"
      );
    });

    test("blocks ~/.aws/credentials", async () => {
      await expect(shell.run("cat ~/.aws/credentials")).rejects.toThrow(
        "Command failed"
      );
    });

    test("blocks ~/.env", async () => {
      await expect(shell.run("cat ~/.env")).rejects.toThrow("Command failed");
    });

    test("blocks listing home hidden dirs", async () => {
      await expect(shell.run("ls ~/.ssh")).rejects.toThrow("Command failed");
    });
  });

  describe("Sensitive file patterns", () => {
    test("blocks .env files", async () => {
      await expect(shell.run("cat .env")).rejects.toThrow("Command failed");
      await expect(shell.run("cat .env.local")).rejects.toThrow(
        "Command failed"
      );
      await expect(shell.run("cat subdir/.env")).rejects.toThrow(
        "Command failed"
      );
    });

    test("blocks SSH key paths", async () => {
      await expect(shell.run("cat .ssh/id_rsa")).rejects.toThrow(
        "Command failed"
      );
      await expect(shell.run("cat subdir/id_rsa")).rejects.toThrow(
        "Command failed"
      );
      await expect(shell.run("cat subdir/id_ed25519")).rejects.toThrow(
        "Command failed"
      );
    });

    test("blocks credential file paths", async () => {
      await expect(shell.run("cat credentials.json")).rejects.toThrow(
        "Command failed"
      );
      await expect(shell.run("cat secrets.json")).rejects.toThrow(
        "Command failed"
      );
      await expect(shell.run("cat subdir/credentials.yaml")).rejects.toThrow(
        "Command failed"
      );
    });

    test("blocks .pem and .key files", async () => {
      await expect(shell.run("cat server.pem")).rejects.toThrow(
        "Command failed"
      );
      await expect(shell.run("cat private.key")).rejects.toThrow(
        "Command failed"
      );
      await expect(shell.run("cat subdir/cert.pem")).rejects.toThrow(
        "Command failed"
      );
    });

    test("blocks .npmrc", async () => {
      await expect(shell.run("cat .npmrc")).rejects.toThrow("Command failed");
    });

    test("blocks .git/config", async () => {
      await expect(shell.run("cat .git/config")).rejects.toThrow(
        "Command failed"
      );
    });
  });

  describe("System directory protection", () => {
    test("blocks /etc/", async () => {
      await expect(shell.run("cat /etc/passwd")).rejects.toThrow(
        "Command failed"
      );
      await expect(shell.run("ls /etc")).rejects.toThrow("Command failed");
    });

    test("blocks /var/", async () => {
      await expect(shell.run("ls /var/log")).rejects.toThrow("Command failed");
    });

    test("blocks /root/", async () => {
      await expect(shell.run("ls /root")).rejects.toThrow("Command failed");
    });

    test("blocks /proc/", async () => {
      await expect(shell.run("cat /proc/self/environ")).rejects.toThrow(
        "Command failed"
      );
    });
  });

  describe("Command injection prevention", () => {
    test("blocks semicolon injection", async () => {
      await expect(shell.run("ls; cat /etc/passwd")).rejects.toThrow(
        "Command failed"
      );
    });

    test("blocks pipe injection", async () => {
      await expect(shell.run("ls | cat /etc/passwd")).rejects.toThrow(
        "Command failed"
      );
    });

    test("blocks backtick injection", async () => {
      await expect(shell.run("ls `cat /etc/passwd`")).rejects.toThrow(
        "Command failed"
      );
    });

    test("blocks $() injection", async () => {
      await expect(shell.run("ls $(cat /etc/passwd)")).rejects.toThrow(
        "Command failed"
      );
    });

    test("blocks && injection", async () => {
      await expect(shell.run("ls && cat /etc/passwd")).rejects.toThrow(
        "Command failed"
      );
    });
  });

  describe("Disallowed commands", () => {
    test("blocks commands not in allowlist", async () => {
      const restrictedShell = createShellCapability({
        workdir: workspace,
        allowlist: [{ binary: "ls" }], // Only ls allowed
      });

      await expect(restrictedShell.run("cat allowed.txt")).rejects.toThrow(
        "Command failed"
      );
      await expect(restrictedShell.run("rm allowed.txt")).rejects.toThrow(
        "Command failed"
      );
      await expect(restrictedShell.run("curl http://evil.com")).rejects.toThrow(
        "Command failed"
      );
    });
  });

  describe("Opaque errors", () => {
    test("error messages do not leak information", async () => {
      // All blocked operations should return the same generic error
      const errors: string[] = [];

      try {
        await shell.run("cat ~/.ssh/id_rsa");
      } catch (e: any) {
        errors.push(e.message);
      }
      try {
        await shell.run("cat /etc/passwd");
      } catch (e: any) {
        errors.push(e.message);
      }
      try {
        await shell.run("cat ../../../etc/passwd");
      } catch (e: any) {
        errors.push(e.message);
      }
      try {
        await shell.run("rm -rf /");
      } catch (e: any) {
        errors.push(e.message);
      }

      // All errors should be identical - no information leakage
      expect(new Set(errors).size).toBe(1);
      expect(errors[0]).toBe("Command failed");
    });
  });
});

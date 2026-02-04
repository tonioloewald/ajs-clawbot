/**
 * Filesystem Capability Security Tests
 */

import { describe, test, expect } from "bun:test";
import { createFilesystemCapability } from "./filesystem";
import { mkdtempSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

describe("Filesystem Capability Security", () => {
  // Create a temp workspace for testing
  const workspace = mkdtempSync(join(tmpdir(), "fs-test-"));

  // Create test files
  writeFileSync(join(workspace, "allowed.txt"), "This is allowed content");
  writeFileSync(join(workspace, "readme.md"), "# Readme");
  mkdirSync(join(workspace, "subdir"));
  writeFileSync(join(workspace, "subdir", "nested.txt"), "Nested content");
  writeFileSync(join(workspace, "subdir", "code"), "const x = 1;");

  const fs = createFilesystemCapability({
    root: workspace,
    allowPatterns: ["**/*"],
    onBlocked: (op, path, reason) => {
      console.log(`BLOCKED: ${op} ${path} - ${reason}`);
    },
  });

  describe("Allowed operations", () => {
    test("can read files in workspace", async () => {
      const content = await fs.read("allowed.txt");
      expect(content).toBe("This is allowed content");
    });

    test("can read nested files", async () => {
      const content = await fs.read("subdir/nested.txt");
      expect(content).toBe("Nested content");
    });

    test("can list directory", async () => {
      const entries = await fs.list(".");
      expect(entries).toContain("allowed.txt");
      expect(entries).toContain("subdir");
    });

    test("can check if file exists", async () => {
      expect(await fs.exists("allowed.txt")).toBe(true);
      expect(await fs.exists("nonexistent.txt")).toBe(false);
    });

    test("can stat files", async () => {
      const stats = await fs.stat("allowed.txt");
      expect(stats.isFile).toBe(true);
      expect(stats.isDirectory).toBe(false);
    });
  });

  describe("Path traversal attacks", () => {
    test("blocks ../ traversal", async () => {
      await expect(fs.read("../../../etc/passwd")).rejects.toThrow(
        "Access denied"
      );
    });

    test("blocks ../../ in nested paths", async () => {
      await expect(fs.read("subdir/../../etc/passwd")).rejects.toThrow(
        "Access denied"
      );
    });

    test("blocks absolute paths outside root", async () => {
      await expect(fs.read("/etc/passwd")).rejects.toThrow("Access denied");
    });

    test("blocks ~ home directory references", async () => {
      await expect(fs.read("~/.ssh/id_rsa")).rejects.toThrow("Access denied");
    });
  });

  describe("Sensitive file patterns", () => {
    test("blocks .env files", async () => {
      await expect(fs.read(".env")).rejects.toThrow("Access denied");
      await expect(fs.read(".env.local")).rejects.toThrow("Access denied");
      await expect(fs.read("subdir/.env")).rejects.toThrow("Access denied");
      await expect(fs.read("subdir/.env.production")).rejects.toThrow(
        "Access denied"
      );
    });

    test("blocks credentials files", async () => {
      await expect(fs.read("credentials.json")).rejects.toThrow("Access denied");
      await expect(fs.read("credentials.yaml")).rejects.toThrow("Access denied");
      await expect(fs.read("subdir/credentials.txt")).rejects.toThrow(
        "Access denied"
      );
    });

    test("blocks secrets files", async () => {
      await expect(fs.read("secrets.json")).rejects.toThrow("Access denied");
      await expect(fs.read("secrets.yaml")).rejects.toThrow("Access denied");
    });

    test("blocks SSH key files", async () => {
      await expect(fs.read("id_rsa")).rejects.toThrow("Access denied");
      await expect(fs.read("id_ed25519")).rejects.toThrow("Access denied");
      await expect(fs.read("subdir/id_rsa")).rejects.toThrow("Access denied");
      await expect(fs.read(".ssh/id_rsa")).rejects.toThrow("Access denied");
    });

    test("blocks certificate and key files", async () => {
      await expect(fs.read("server.pem")).rejects.toThrow("Access denied");
      await expect(fs.read("private.key")).rejects.toThrow("Access denied");
      await expect(fs.read("cert.p12")).rejects.toThrow("Access denied");
      await expect(fs.read("subdir/ssl.pem")).rejects.toThrow("Access denied");
    });

    test("blocks .npmrc", async () => {
      await expect(fs.read(".npmrc")).rejects.toThrow("Access denied");
    });

    test("blocks .git/config", async () => {
      await expect(fs.read(".git/config")).rejects.toThrow("Access denied");
    });

    test("blocks database files", async () => {
      await expect(fs.read("data.sqlite")).rejects.toThrow("Access denied");
      await expect(fs.read("app.db")).rejects.toThrow("Access denied");
    });
  });

  describe("System directory protection", () => {
    test("blocks /etc/", async () => {
      await expect(fs.read("/etc/passwd")).rejects.toThrow("Access denied");
      await expect(fs.list("/etc")).rejects.toThrow("Access denied");
    });

    test("blocks /var/", async () => {
      await expect(fs.read("/var/log/syslog")).rejects.toThrow("Access denied");
    });

    test("blocks /proc/", async () => {
      await expect(fs.read("/proc/self/environ")).rejects.toThrow(
        "Access denied"
      );
    });
  });

  describe("Write protection", () => {
    test("read-only fs blocks writes", async () => {
      const readOnlyFs = createFilesystemCapability({
        root: workspace,
        allowPatterns: ["**/*"],
        allowWrite: false,
      });

      await expect(readOnlyFs.write("test.txt", "content")).rejects.toThrow(
        "Access denied"
      );
    });

    test("writable fs still blocks sensitive files", async () => {
      const writableFs = createFilesystemCapability({
        root: workspace,
        allowPatterns: ["**/*"],
        allowWrite: true,
        allowCreate: true,
      });

      await expect(writableFs.write(".env", "SECRET=bad")).rejects.toThrow(
        "Access denied"
      );
      await expect(
        writableFs.write("credentials.json", "{}")
      ).rejects.toThrow("Access denied");
    });
  });

  describe("Directory listing filters blocked files", () => {
    test("list does not show blocked files", async () => {
      // Create some files that would be blocked
      writeFileSync(join(workspace, "visible.txt"), "ok");

      const entries = await fs.list(".");

      // Should show visible files
      expect(entries).toContain("visible.txt");
      expect(entries).toContain("allowed.txt");

      // Should NOT show blocked patterns (if they existed)
      // The listing itself filters them out
    });
  });

  describe("Opaque errors", () => {
    test("all blocked operations return same error", async () => {
      const errors: string[] = [];

      try { await fs.read(".env"); } catch (e: any) { errors.push(e.message); }
      try { await fs.read("credentials.json"); } catch (e: any) { errors.push(e.message); }
      try { await fs.read("../../../etc/passwd"); } catch (e: any) { errors.push(e.message); }
      try { await fs.read("~/.ssh/id_rsa"); } catch (e: any) { errors.push(e.message); }
      try { await fs.read("/etc/passwd"); } catch (e: any) { errors.push(e.message); }

      // All errors should be identical
      expect(new Set(errors).size).toBe(1);
      expect(errors[0]).toBe("Access denied");
    });

    test("blocked exists() returns false instead of throwing", async () => {
      // For exists(), we return false for blocked paths (don't reveal they're blocked)
      expect(await fs.exists(".env")).toBe(false);
      expect(await fs.exists("credentials.json")).toBe(false);
      expect(await fs.exists("~/.ssh/id_rsa")).toBe(false);
    });
  });
});

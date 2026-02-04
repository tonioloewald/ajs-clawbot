#!/usr/bin/env bun
/**
 * Security Check Tool
 *
 * Run this to:
 * 1. See all security patterns that are blocked
 * 2. Test specific paths against the security rules
 * 3. Get suggestions for what to review in your environment
 *
 * Usage:
 *   bun bin/security-check.ts                    # Show all patterns
 *   bun bin/security-check.ts --test <path>      # Test if a path is blocked
 *   bun bin/security-check.ts --checklist        # Show security review checklist
 */

import {
  BLOCKED_FILE_PATTERNS,
  DANGEROUS_PATH_PATTERNS,
  isBlocked,
  getCategories,
  SECURITY_REVIEW_CHECKLIST,
} from "../src/capabilities/security.secrets";

const args = process.argv.slice(2);

function printPatternsByCategory() {
  console.log(
    "\n╔══════════════════════════════════════════════════════════════╗"
  );
  console.log(
    "║           ajs-clawbot Security Patterns                      ║"
  );
  console.log(
    "╚══════════════════════════════════════════════════════════════╝\n"
  );

  const categories = getCategories();

  for (const category of categories) {
    console.log(
      `\n┌─ ${category.toUpperCase()} ${"─".repeat(55 - category.length)}┐`
    );
    const patterns = BLOCKED_FILE_PATTERNS.filter(
      (p) => p.category === category
    );
    for (const { pattern, description } of patterns) {
      const patternStr = pattern.toString();
      console.log(
        `│  ${patternStr.slice(0, 40).padEnd(40)} │ ${description.slice(0, 30)}`
      );
    }
    console.log(`└${"─".repeat(62)}┘`);
  }

  console.log(`\n┌─ DANGEROUS PATH PATTERNS ${"─".repeat(36)}┐`);
  for (const { pattern, description } of DANGEROUS_PATH_PATTERNS) {
    const patternStr = pattern.toString();
    console.log(
      `│  ${patternStr.slice(0, 40).padEnd(40)} │ ${description.slice(0, 30)}`
    );
  }
  console.log(`└${"─".repeat(62)}┘`);

  console.log(`\nTotal blocked patterns: ${BLOCKED_FILE_PATTERNS.length}`);
  console.log(
    `Total dangerous path patterns: ${DANGEROUS_PATH_PATTERNS.length}`
  );
}

function testPath(path: string) {
  console.log(`\nTesting path: "${path}"\n`);

  const result = isBlocked(path);

  if (result.blocked) {
    console.log("❌ BLOCKED");
    console.log(`   Pattern:     ${result.pattern}`);
    console.log(`   Category:    ${result.category}`);
    console.log(`   Description: ${result.description}`);
  } else {
    console.log("✅ ALLOWED (not matched by any blocked pattern)");
    console.log("   Note: This only checks security patterns.");
    console.log("   The path must still be within the workdir jail");
    console.log("   and match allow patterns to be accessible.");
  }
}

function testCommonAttacks() {
  console.log(
    "\n╔══════════════════════════════════════════════════════════════╗"
  );
  console.log(
    "║           Security Test Suite                                ║"
  );
  console.log(
    "╚══════════════════════════════════════════════════════════════╝\n"
  );

  const testCases = [
    // Path traversal
    { path: "../../../etc/passwd", expected: true, category: "Path traversal" },
    {
      path: "subdir/../../etc/passwd",
      expected: true,
      category: "Path traversal",
    },
    {
      path: "%2e%2e/etc/passwd",
      expected: true,
      category: "Encoded traversal",
    },

    // Home directory
    { path: "~/.ssh/id_rsa", expected: true, category: "Home directory" },
    { path: "~/.bashrc", expected: true, category: "Home directory" },

    // Environment files
    { path: ".env", expected: true, category: "Secrets" },
    { path: ".env.local", expected: true, category: "Secrets" },
    { path: "config/.env.production", expected: true, category: "Secrets" },

    // Credentials
    { path: "credentials.json", expected: true, category: "Secrets" },
    { path: "secrets.yaml", expected: true, category: "Secrets" },

    // SSH keys
    { path: "id_rsa", expected: true, category: "SSH" },
    { path: ".ssh/id_ed25519", expected: true, category: "SSH" },
    { path: "keys/id_rsa.pub", expected: true, category: "SSH" },

    // Certificates
    { path: "server.pem", expected: true, category: "Certificates" },
    { path: "private.key", expected: true, category: "Certificates" },
    { path: "ssl/cert.p12", expected: true, category: "Certificates" },

    // Cloud credentials
    { path: ".aws/credentials", expected: true, category: "Cloud" },
    { path: ".kube/config", expected: true, category: "Cloud" },

    // System paths
    { path: "/etc/passwd", expected: true, category: "System" },
    { path: "/proc/self/environ", expected: true, category: "System" },

    // Package managers
    { path: ".npmrc", expected: true, category: "Package managers" },

    // Databases
    { path: "data.sqlite", expected: true, category: "Database" },
    { path: "app.db", expected: true, category: "Database" },

    // Allowed paths (should NOT be blocked)
    { path: "src/index.ts", expected: false, category: "Source code" },
    { path: "package.json", expected: false, category: "Config" },
    { path: "README.md", expected: false, category: "Documentation" },
    { path: "data/users.json", expected: false, category: "Data" },
  ];

  let passed = 0;
  let failed = 0;

  for (const { path, expected, category } of testCases) {
    const result = isBlocked(path);
    const ok = result.blocked === expected;

    if (ok) {
      passed++;
      console.log(
        `✅ ${category.padEnd(20)} │ ${path.padEnd(30)} │ ${
          expected ? "BLOCKED" : "ALLOWED"
        }`
      );
    } else {
      failed++;
      console.log(
        `❌ ${category.padEnd(20)} │ ${path.padEnd(30)} │ Expected ${
          expected ? "BLOCKED" : "ALLOWED"
        }, got ${result.blocked ? "BLOCKED" : "ALLOWED"}`
      );
    }
  }

  console.log(`\n${"─".repeat(70)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);

  if (failed > 0) {
    process.exit(1);
  }
}

// Main
if (args.includes("--test")) {
  const pathIndex = args.indexOf("--test") + 1;
  if (pathIndex < args.length) {
    testPath(args[pathIndex]);
  } else {
    console.error("Usage: bun bin/security-check.ts --test <path>");
    process.exit(1);
  }
} else if (args.includes("--checklist")) {
  console.log(SECURITY_REVIEW_CHECKLIST);
} else if (args.includes("--run-tests")) {
  testCommonAttacks();
} else if (args.includes("--help") || args.includes("-h")) {
  console.log(`
ajs-clawbot Security Check Tool

Usage:
  bun bin/security-check.ts                    Show all blocked patterns
  bun bin/security-check.ts --test <path>      Test if a specific path is blocked
  bun bin/security-check.ts --checklist        Show security review checklist
  bun bin/security-check.ts --run-tests        Run security test suite

Examples:
  bun bin/security-check.ts --test ~/.ssh/id_rsa
  bun bin/security-check.ts --test credentials.json
  bun bin/security-check.ts --test src/index.ts
`);
} else {
  printPatternsByCategory();
  console.log(
    "\nRun with --checklist to see what you should review for your environment."
  );
  console.log(
    "Run with --run-tests to verify all security patterns work correctly."
  );
}

/**
 * Tests for Security Patterns
 *
 * Tests the security functions learned from OpenClaw's production hardening.
 */

import { describe, it, expect } from "bun:test";
import {
  isDangerousEnvVar,
  sanitizeEnv,
  isBlockedHostname,
  isPrivateIP,
  isCloudMetadataIP,
  isBlocked,
  DANGEROUS_ENV_VARS,
  CLOUD_METADATA_IPS,
} from "./security.secrets";

describe("Dangerous Environment Variables", () => {
  describe("isDangerousEnvVar", () => {
    it("should block LD_PRELOAD (linker injection)", () => {
      expect(isDangerousEnvVar("LD_PRELOAD")).toBe(true);
      expect(isDangerousEnvVar("ld_preload")).toBe(true);
    });

    it("should block DYLD_* prefixes (macOS linker)", () => {
      expect(isDangerousEnvVar("DYLD_INSERT_LIBRARIES")).toBe(true);
      expect(isDangerousEnvVar("DYLD_LIBRARY_PATH")).toBe(true);
      expect(isDangerousEnvVar("DYLD_ANYTHING")).toBe(true);
    });

    it("should block LD_* prefixes (Linux linker)", () => {
      expect(isDangerousEnvVar("LD_LIBRARY_PATH")).toBe(true);
      expect(isDangerousEnvVar("LD_AUDIT")).toBe(true);
      expect(isDangerousEnvVar("LD_ANYTHING")).toBe(true);
    });

    it("should block Node.js injection vars", () => {
      expect(isDangerousEnvVar("NODE_OPTIONS")).toBe(true);
      expect(isDangerousEnvVar("NODE_PATH")).toBe(true);
    });

    it("should block Python injection vars", () => {
      expect(isDangerousEnvVar("PYTHONPATH")).toBe(true);
      expect(isDangerousEnvVar("PYTHONHOME")).toBe(true);
    });

    it("should block shell injection vars", () => {
      expect(isDangerousEnvVar("BASH_ENV")).toBe(true);
      expect(isDangerousEnvVar("ENV")).toBe(true);
      expect(isDangerousEnvVar("IFS")).toBe(true);
    });

    it("should block PATH modification (binary hijacking)", () => {
      expect(isDangerousEnvVar("PATH")).toBe(true);
      expect(isDangerousEnvVar("path")).toBe(true);
    });

    it("should allow safe env vars", () => {
      expect(isDangerousEnvVar("HOME")).toBe(false);
      expect(isDangerousEnvVar("USER")).toBe(false);
      expect(isDangerousEnvVar("TERM")).toBe(false);
      expect(isDangerousEnvVar("MY_APP_CONFIG")).toBe(false);
    });
  });

  describe("sanitizeEnv", () => {
    it("should remove dangerous env vars", () => {
      const env = {
        HOME: "/home/user",
        LD_PRELOAD: "/evil.so",
        PATH: "/usr/bin",
        NODE_OPTIONS: "--inspect",
        MY_CONFIG: "value",
      };

      const sanitized = sanitizeEnv(env);

      expect(sanitized.HOME).toBe("/home/user");
      expect(sanitized.MY_CONFIG).toBe("value");
      expect(sanitized.LD_PRELOAD).toBeUndefined();
      expect(sanitized.PATH).toBeUndefined();
      expect(sanitized.NODE_OPTIONS).toBeUndefined();
    });

    it("should handle undefined values", () => {
      const env = {
        DEFINED: "value",
        UNDEFINED: undefined,
      };

      const sanitized = sanitizeEnv(env);

      expect(sanitized.DEFINED).toBe("value");
      expect("UNDEFINED" in sanitized).toBe(false);
    });
  });
});

describe("SSRF Protection", () => {
  describe("isBlockedHostname", () => {
    it("should block localhost", () => {
      expect(isBlockedHostname("localhost")).toBe(true);
      expect(isBlockedHostname("LOCALHOST")).toBe(true);
      expect(isBlockedHostname("localhost.")).toBe(true);
    });

    it("should block .localhost suffix", () => {
      expect(isBlockedHostname("evil.localhost")).toBe(true);
      expect(isBlockedHostname("foo.bar.localhost")).toBe(true);
    });

    it("should block .local suffix", () => {
      expect(isBlockedHostname("myserver.local")).toBe(true);
      expect(isBlockedHostname("printer.local")).toBe(true);
    });

    it("should block .internal suffix", () => {
      expect(isBlockedHostname("metadata.google.internal")).toBe(true);
      expect(isBlockedHostname("api.internal")).toBe(true);
    });

    it("should block GCP metadata service", () => {
      expect(isBlockedHostname("metadata.google.internal")).toBe(true);
    });

    it("should allow normal public hostnames", () => {
      expect(isBlockedHostname("google.com")).toBe(false);
      expect(isBlockedHostname("api.example.com")).toBe(false);
      expect(isBlockedHostname("github.com")).toBe(false);
    });
  });

  describe("isPrivateIP - IPv4", () => {
    it("should detect 10.x.x.x as private", () => {
      expect(isPrivateIP("10.0.0.1")).toBe(true);
      expect(isPrivateIP("10.255.255.255")).toBe(true);
    });

    it("should detect 127.x.x.x (loopback) as private", () => {
      expect(isPrivateIP("127.0.0.1")).toBe(true);
      expect(isPrivateIP("127.255.255.255")).toBe(true);
    });

    it("should detect 169.254.x.x (link-local) as private", () => {
      expect(isPrivateIP("169.254.0.1")).toBe(true);
      expect(isPrivateIP("169.254.169.254")).toBe(true); // Cloud metadata!
    });

    it("should detect 172.16-31.x.x as private", () => {
      expect(isPrivateIP("172.16.0.1")).toBe(true);
      expect(isPrivateIP("172.31.255.255")).toBe(true);
      expect(isPrivateIP("172.15.0.1")).toBe(false); // Not in range
      expect(isPrivateIP("172.32.0.1")).toBe(false); // Not in range
    });

    it("should detect 192.168.x.x as private", () => {
      expect(isPrivateIP("192.168.0.1")).toBe(true);
      expect(isPrivateIP("192.168.255.255")).toBe(true);
    });

    it("should detect 100.64-127.x.x (CGNAT) as private", () => {
      expect(isPrivateIP("100.64.0.1")).toBe(true);
      expect(isPrivateIP("100.127.255.255")).toBe(true);
      expect(isPrivateIP("100.63.0.1")).toBe(false);
      expect(isPrivateIP("100.128.0.1")).toBe(false);
    });

    it("should allow public IPv4 addresses", () => {
      expect(isPrivateIP("8.8.8.8")).toBe(false);
      expect(isPrivateIP("1.1.1.1")).toBe(false);
      expect(isPrivateIP("142.250.80.46")).toBe(false); // google.com
    });
  });

  describe("isPrivateIP - IPv6", () => {
    it("should detect :: and ::1 (loopback) as private", () => {
      expect(isPrivateIP("::")).toBe(true);
      expect(isPrivateIP("::1")).toBe(true);
    });

    it("should detect fe80: (link-local) as private", () => {
      expect(isPrivateIP("fe80::1")).toBe(true);
      expect(isPrivateIP("fe80:0:0:0:0:0:0:1")).toBe(true);
    });

    it("should detect fc/fd (unique local) as private", () => {
      expect(isPrivateIP("fc00::1")).toBe(true);
      expect(isPrivateIP("fd00::1")).toBe(true);
    });

    it("should allow public IPv6 addresses", () => {
      expect(isPrivateIP("2001:4860:4860::8888")).toBe(false); // Google DNS
      expect(isPrivateIP("2606:4700:4700::1111")).toBe(false); // Cloudflare
    });
  });

  describe("isPrivateIP - IPv4-mapped IPv6 bypass", () => {
    it("should detect ::ffff:127.0.0.1 as private (bypass attempt)", () => {
      expect(isPrivateIP("::ffff:127.0.0.1")).toBe(true);
    });

    it("should detect ::ffff:192.168.1.1 as private (bypass attempt)", () => {
      expect(isPrivateIP("::ffff:192.168.1.1")).toBe(true);
    });

    it("should detect ::ffff:10.0.0.1 as private (bypass attempt)", () => {
      expect(isPrivateIP("::ffff:10.0.0.1")).toBe(true);
    });

    it("should detect ::ffff:169.254.169.254 as private (metadata bypass!)", () => {
      expect(isPrivateIP("::ffff:169.254.169.254")).toBe(true);
    });

    it("should allow ::ffff with public IPs", () => {
      expect(isPrivateIP("::ffff:8.8.8.8")).toBe(false);
    });
  });

  describe("isCloudMetadataIP", () => {
    it("should detect AWS/GCP/Azure metadata IP", () => {
      expect(isCloudMetadataIP("169.254.169.254")).toBe(true);
    });

    it("should detect AWS IPv6 metadata", () => {
      expect(isCloudMetadataIP("fd00:ec2::254")).toBe(true);
    });

    it("should not flag normal IPs", () => {
      expect(isCloudMetadataIP("8.8.8.8")).toBe(false);
      expect(isCloudMetadataIP("169.254.1.1")).toBe(false);
    });
  });
});

describe("File Pattern Blocking", () => {
  describe("isBlocked", () => {
    it("should block .env files", () => {
      expect(isBlocked(".env").blocked).toBe(true);
      expect(isBlocked(".env.local").blocked).toBe(true);
      expect(isBlocked("config/.env").blocked).toBe(true);
    });

    it("should block credentials files", () => {
      expect(isBlocked("credentials.json").blocked).toBe(true);
      expect(isBlocked("app/credentials.yaml").blocked).toBe(true);
    });

    it("should block secrets files", () => {
      expect(isBlocked("secrets.json").blocked).toBe(true);
      expect(isBlocked("my.secrets.ts").blocked).toBe(true);
      expect(isBlocked("security.secrets.ts").blocked).toBe(true); // This file!
    });

    it("should block SSH keys", () => {
      expect(isBlocked("id_rsa").blocked).toBe(true);
      expect(isBlocked("id_ed25519").blocked).toBe(true);
      expect(isBlocked(".ssh/id_rsa").blocked).toBe(true);
    });

    it("should block path traversal", () => {
      expect(isBlocked("../etc/passwd").blocked).toBe(true);
      expect(isBlocked("..\\etc\\passwd").blocked).toBe(true);
    });

    it("should allow normal files", () => {
      expect(isBlocked("index.ts").blocked).toBe(false);
      expect(isBlocked("package.json").blocked).toBe(false);
      expect(isBlocked("README.md").blocked).toBe(false);
    });
  });
});

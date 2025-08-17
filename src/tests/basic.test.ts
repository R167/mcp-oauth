import { describe, it, expect } from "vitest";
import { ScopeValidator } from "../validators/ScopeValidator.js";
import { EncryptionManager } from "../managers/EncryptionManager.js";
import type { GitHubUser } from "../types.js";

describe("ScopeValidator", () => {
  const validator = new ScopeValidator();

  it("should validate correct MCP scope format", () => {
    const result = validator.validateScopeFormat("mcp:example.com:github-tools");
    expect(result.isValid).toBe(true);
    expect(result.mcpScope).toBe("mcp:example.com:github-tools");
    expect(result.emailRequested).toBe(false);
  });

  it("should validate MCP scope with email", () => {
    const result = validator.validateScopeFormat("mcp:example.com:github-tools email");
    expect(result.isValid).toBe(true);
    expect(result.mcpScope).toBe("mcp:example.com:github-tools");
    expect(result.emailRequested).toBe(true);
  });

  it("should reject invalid scope format", () => {
    const result = validator.validateScopeFormat("invalid-scope");
    expect(result.isValid).toBe(false);
  });

  it("should reject multiple MCP scopes", () => {
    const result = validator.validateScopeFormat("mcp:example.com:server1 mcp:example.com:server2");
    expect(result.isValid).toBe(false);
  });

  it("should validate domain match", () => {
    const isValid = validator.validateDomainMatch("mcp:example.com:github-tools", "https://example.com/callback");
    expect(isValid).toBe(true);
  });

  it("should reject domain mismatch", () => {
    const isValid = validator.validateDomainMatch("mcp:example.com:github-tools", "https://different.com/callback");
    expect(isValid).toBe(false);
  });

  it("should validate user access", () => {
    const user: GitHubUser = { login: "example-user", name: "Test User", email: null };
    const hasAccess = validator.validateUserAccess("mcp:example.com:github-tools", user);
    expect(hasAccess).toBe(true);
  });

  it("should reject unauthorized user", () => {
    const user: GitHubUser = { login: "unauthorized-user", name: "Test User", email: null };
    const hasAccess = validator.validateUserAccess("mcp:example.com:github-tools", user);
    expect(hasAccess).toBe(false);
  });
});

describe("EncryptionManager", () => {
  const encryption = new EncryptionManager("test-key-123");

  it("should encrypt and decrypt data", async () => {
    const originalData = "sensitive-data-to-encrypt";

    const encrypted = await encryption.encrypt(originalData);
    expect(encrypted).not.toBe(originalData);
    expect(encrypted).toContain("v1:");

    const decrypted = await encryption.decrypt(encrypted);
    expect(decrypted).toBe(originalData);
  });

  it("should support key rotation", async () => {
    const originalData = "data-to-rotate";

    const encryptedV1 = await encryption.encrypt(originalData, "v1");
    const rotatedV2 = await encryption.rotateKey("v1", "v2", encryptedV1);

    expect(rotatedV2).toContain("v2:");

    const decrypted = await encryption.decrypt(rotatedV2);
    expect(decrypted).toBe(originalData);
  });

  it("should throw error for invalid encrypted data", async () => {
    await expect(encryption.decrypt("invalid-data")).rejects.toThrow();
  });
});

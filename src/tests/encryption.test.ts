import { describe, it, expect, beforeEach } from "vitest";
import { EncryptionManager } from "../utils/encryption";
import { Environment } from "../types";

describe("EncryptionManager", () => {
	let mockEnv: Environment;
	let encryption: EncryptionManager;

	beforeEach(() => {
		mockEnv = {
			REFRESH_ENCRYPTION_KEY: "test_encryption_key_32_characters_",
			AUTH_KV: {
				get: vi.fn(),
				put: vi.fn(),
				delete: vi.fn(),
				list: vi.fn(),
			} as any,
		} as Environment;

		encryption = new EncryptionManager(mockEnv);
	});

	describe("encrypt and decrypt", () => {
		it("should encrypt and decrypt data successfully", async () => {
			const originalData = "test data to encrypt";

			const encrypted = await encryption.encrypt(originalData);
			expect(encrypted).toHaveProperty("data");
			expect(encrypted).toHaveProperty("iv");
			expect(encrypted).toHaveProperty("keyVersion");
			expect(encrypted.keyVersion).toBe("current");

			const decrypted = await encryption.decrypt(encrypted);
			expect(decrypted).toBe(originalData);
		});

		it("should produce different encrypted outputs for same input", async () => {
			const data = "test data";

			const encrypted1 = await encryption.encrypt(data);
			const encrypted2 = await encryption.encrypt(data);

			expect(encrypted1.data).not.toBe(encrypted2.data);
			expect(encrypted1.iv).not.toBe(encrypted2.iv);

			expect(await encryption.decrypt(encrypted1)).toBe(data);
			expect(await encryption.decrypt(encrypted2)).toBe(data);
		});

		it("should handle key versioning", async () => {
			const data = "test data";
			const version = "v123";

			mockEnv.AUTH_KV.get = vi.fn().mockResolvedValue("versioned_key_32_characters____");

			const encrypted = await encryption.encrypt(data, version);
			expect(encrypted.keyVersion).toBe(version);

			const decrypted = await encryption.decrypt(encrypted);
			expect(decrypted).toBe(data);
		});
	});

	describe("key rotation", () => {
		it("should store new key version", async () => {
			const newKey = "new_encryption_key_32_characters__";

			const version = await encryption.rotateKey(newKey);
			expect(version).toMatch(/^v\d+$/);
			expect(mockEnv.AUTH_KV.put).toHaveBeenCalledWith(`encryption_key:${version}`, newKey, { expirationTtl: 365 * 24 * 3600 });
		});
	});
});

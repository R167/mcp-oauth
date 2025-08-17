export class EncryptionManager {
  private readonly keyVersions = new Map<string, CryptoKey>();

  constructor(private readonly baseKey: string) {}

  private async deriveKey(version: string = "v1"): Promise<CryptoKey> {
    const cached = this.keyVersions.get(version);
    if (cached) return cached;

    const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(this.baseKey + version), "PBKDF2", false, [
      "deriveKey",
    ]);

    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: new TextEncoder().encode("mcp-oauth-salt-" + version),
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );

    this.keyVersions.set(version, key);
    return key;
  }

  async encrypt(data: string, version: string = "v1"): Promise<string> {
    const key = await this.deriveKey(version);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedData = new TextEncoder().encode(data);

    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encodedData);

    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    return version + ":" + btoa(String.fromCharCode(...combined));
  }

  async decrypt(encryptedData: string): Promise<string> {
    const [version, data] = encryptedData.split(":", 2);
    if (!version || !data) {
      throw new Error("Invalid encrypted data format");
    }

    const key = await this.deriveKey(version);
    const combined = new Uint8Array(
      atob(data)
        .split("")
        .map((c) => c.charCodeAt(0)),
    );

    const iv = combined.slice(0, 12);
    const encrypted = combined.slice(12);

    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);

    return new TextDecoder().decode(decrypted);
  }

  async rotateKey(oldVersion: string, newVersion: string, encryptedData: string): Promise<string> {
    const decrypted = await this.decrypt(encryptedData);
    return this.encrypt(decrypted, newVersion);
  }
}

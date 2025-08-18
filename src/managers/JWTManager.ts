import { SignJWT, jwtVerify, importPKCS8, importSPKI } from "jose";
import type { AccessToken, RefreshToken } from "../types.js";
import type { StorageManager } from "./StorageManager.js";

export class JWTManager {
  private privateKey: Promise<CryptoKey>;
  private publicKey: Promise<CryptoKey>;

  constructor(
    private readonly privateKeyPem: string,
    private readonly publicKeyPem: string,
    private readonly issuer: string,
  ) {
    this.privateKey = this.importPrivateKey();
    this.publicKey = this.importPublicKey();
  }

  private async importPrivateKey(): Promise<CryptoKey> {
    return importPKCS8(this.privateKeyPem, "RS256");
  }

  private async importPublicKey(): Promise<CryptoKey> {
    // Import as extractable for JWKS export
    const keyData = this.publicKeyPem
      .replace(/-----BEGIN PUBLIC KEY-----/g, "")
      .replace(/-----END PUBLIC KEY-----/g, "")
      .replace(/\s/g, "");

    const binaryKey = Uint8Array.from(atob(keyData), (c) => c.charCodeAt(0));

    return crypto.subtle.importKey(
      "spki",
      binaryKey,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
      },
      true, // extractable = true for JWKS export
      ["verify"],
    );
  }

  async createAccessToken(payload: Omit<AccessToken, "token_type" | "iss" | "exp">): Promise<string> {
    const privateKey = await this.privateKey;
    const now = Math.floor(Date.now() / 1000);

    return new SignJWT({
      ...payload,
      token_type: "access",
    })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(this.issuer)
      .setExpirationTime(now + 3600) // 1 hour
      .setIssuedAt(now)
      .setNotBefore(now)
      .sign(privateKey);
  }

  async createRefreshToken(payload: Omit<RefreshToken, "token_type" | "iss" | "exp">): Promise<string> {
    const privateKey = await this.privateKey;
    const now = Math.floor(Date.now() / 1000);

    return new SignJWT({
      ...payload,
      token_type: "refresh",
    })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(this.issuer)
      .setExpirationTime(now + 30 * 24 * 3600) // 30 days
      .setIssuedAt(now)
      .setNotBefore(now)
      .sign(privateKey);
  }

  async verifyToken(token: string, storageManager?: StorageManager): Promise<AccessToken | RefreshToken> {
    const publicKey = await this.publicKey;

    const { payload } = await jwtVerify(token, publicKey, {
      issuer: this.issuer,
    });

    // Check if token is revoked (if storage manager provided)
    if (storageManager) {
      // For access tokens, check revocation by token hash
      if ((payload as any).token_type === "access") {
        const tokenHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
        const tokenId = Array.from(new Uint8Array(tokenHash))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");

        if (await storageManager.isTokenRevoked(tokenId)) {
          throw new Error("Token has been revoked");
        }
      }
      // For refresh tokens, check revocation by jti
      else if ((payload as any).token_type === "refresh" && (payload as any).jti) {
        if (await storageManager.isTokenRevoked((payload as any).jti)) {
          throw new Error("Token has been revoked");
        }
      }
    }

    return payload as AccessToken | RefreshToken;
  }

  async getPublicKey(): Promise<CryptoKey> {
    return this.publicKey;
  }

  async getJWKS(): Promise<{ keys: any[] }> {
    const publicKey = await this.publicKey;
    const exported = await crypto.subtle.exportKey("jwk", publicKey);

    return {
      keys: [
        {
          ...exported,
          use: "sig",
          alg: "RS256",
          kid: "auth-server-key-1",
        },
      ],
    };
  }
}

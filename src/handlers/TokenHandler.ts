import { Hono } from "hono";
import type { Env, TokenRequest } from "../types.js";
import { TokenRequestSchema } from "../types.js";
import { StorageManager } from "../managers/StorageManager.js";
import { JWTManager } from "../managers/JWTManager.js";
import { EncryptionManager } from "../managers/EncryptionManager.js";

const app = new Hono<{ Bindings: Env }>();

app.post("/token", async (c) => {
  try {
    const formData = await c.req.formData();
    const params = Object.fromEntries(formData.entries()) as Record<string, string>;

    const parseResult = TokenRequestSchema.safeParse(params);
    if (!parseResult.success) {
      return c.json(
        {
          error: "invalid_request",
          error_description: "Invalid token request parameters",
        },
        400,
      );
    }

    const request = parseResult.data;
    const storage = new StorageManager(c.env.AUTH_DB);
    await storage.initialize();

    const jwtManager = new JWTManager(c.env.JWT_PRIVATE_KEY, c.env.JWT_PUBLIC_KEY, c.env.WORKER_BASE_URL);

    if (request.grant_type === "authorization_code") {
      return handleAuthorizationCodeGrant(request, storage, jwtManager, c.env);
    } else if (request.grant_type === "refresh_token") {
      return handleRefreshTokenGrant(request, storage, jwtManager, c.env);
    }

    return c.json(
      {
        error: "unsupported_grant_type",
        error_description: "Unsupported grant type",
      },
      400,
    );
  } catch (error) {
    console.error("Token error:", error);
    return c.json(
      {
        error: "server_error",
        error_description: "Internal server error",
      },
      500,
    );
  }
});

async function handleAuthorizationCodeGrant(request: TokenRequest, storage: StorageManager, jwtManager: JWTManager, env: Env) {
  if (!request.code || !request.redirect_uri || !request.code_verifier) {
    return Response.json(
      {
        error: "invalid_request",
        error_description: "Missing required parameters for authorization code grant",
      },
      { status: 400 },
    );
  }

  // Get authorization code
  const authCode = await storage.getAuthorizationCode(request.code);
  if (!authCode) {
    return Response.json(
      {
        error: "invalid_grant",
        error_description: "Invalid or expired authorization code",
      },
      { status: 400 },
    );
  }

  // Verify client and redirect URI
  if (authCode.client_id !== request.client_id || authCode.redirect_uri !== request.redirect_uri) {
    return Response.json(
      {
        error: "invalid_grant",
        error_description: "Authorization code was not issued to this client",
      },
      { status: 400 },
    );
  }

  // Verify PKCE challenge
  const encoder = new TextEncoder();
  const challengeBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(request.code_verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(challengeBuffer)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  if (challenge !== authCode.code_challenge) {
    return Response.json(
      {
        error: "invalid_grant",
        error_description: "PKCE verification failed",
      },
      { status: 400 },
    );
  }

  // Delete the used authorization code
  await storage.deleteAuthorizationCode(request.code);

  // Create tokens
  const accessToken = await jwtManager.createAccessToken({
    sub: authCode.user_id,
    aud: authCode.scope,
    email: authCode.email,
  });

  const refreshTokenId = crypto.randomUUID();
  const refreshTokenJwt = await jwtManager.createRefreshToken({
    sub: authCode.user_id,
    aud: authCode.scope,
    email: authCode.email,
  });

  // Encrypt refresh token
  const encryption = new EncryptionManager(env.REFRESH_ENCRYPTION_KEY);
  const encryptedRefreshToken = await encryption.encrypt(refreshTokenJwt);
  const refreshToken = `mcp_refresh__${encryptedRefreshToken}`;

  // Store refresh token metadata
  await storage.storeRefreshTokenMetadata(refreshTokenId, {
    user_id: authCode.user_id,
    client_id: authCode.client_id,
    scope: authCode.scope,
    expires_at: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60, // 30 days
    email: authCode.email,
  });

  return Response.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: authCode.scope,
  });
}

async function handleRefreshTokenGrant(request: TokenRequest, storage: StorageManager, jwtManager: JWTManager, env: Env) {
  if (!request.refresh_token) {
    return Response.json(
      {
        error: "invalid_request",
        error_description: "Missing refresh token",
      },
      { status: 400 },
    );
  }

  // Validate refresh token format
  if (!request.refresh_token.startsWith("mcp_refresh__")) {
    return Response.json(
      {
        error: "invalid_grant",
        error_description: "Invalid refresh token format",
      },
      { status: 400 },
    );
  }

  const encryptedToken = request.refresh_token.replace("mcp_refresh__", "");

  try {
    // Decrypt refresh token
    const encryption = new EncryptionManager(env.REFRESH_ENCRYPTION_KEY);
    const refreshTokenJwt = await encryption.decrypt(encryptedToken);

    // Verify refresh token
    const payload = await jwtManager.verifyToken(refreshTokenJwt);
    if (payload.token_type !== "refresh") {
      throw new Error("Invalid token type");
    }

    // Check if token is revoked
    const tokenId = `${payload.sub}:${payload.aud}:${payload.exp}`;
    if (await storage.isTokenRevoked(tokenId)) {
      return Response.json(
        {
          error: "invalid_grant",
          error_description: "Refresh token has been revoked",
        },
        { status: 400 },
      );
    }

    // Create new access token
    const accessToken = await jwtManager.createAccessToken({
      sub: payload.sub,
      aud: payload.aud,
      email: payload.email,
    });

    // Create new refresh token
    const newRefreshTokenJwt = await jwtManager.createRefreshToken({
      sub: payload.sub,
      aud: payload.aud,
      email: payload.email,
    });

    const newEncryptedRefreshToken = await encryption.encrypt(newRefreshTokenJwt);
    const newRefreshToken = `mcp_refresh__${newEncryptedRefreshToken}`;

    // Revoke old refresh token
    await storage.revokeRefreshToken(tokenId, payload.exp);

    return Response.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: newRefreshToken,
      scope: payload.aud,
    });
  } catch (error) {
    return Response.json(
      {
        error: "invalid_grant",
        error_description: "Invalid refresh token",
      },
      { status: 400 },
    );
  }
}

export { app as TokenHandler };

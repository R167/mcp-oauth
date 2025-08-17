import { Hono } from "hono";
import type { Env } from "../types.js";
import { JWTManager } from "../managers/JWTManager.js";

const app = new Hono<{ Bindings: Env }>();

// OAuth 2.0 Authorization Server Metadata (RFC 8414)
app.get("/.well-known/oauth-authorization-server", (c) => {
  const baseUrl = c.env.WORKER_BASE_URL || "";

  return c.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`,
    scopes_supported: ["mcp:*", "email"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint: `${baseUrl}/admin/revoke`,
    introspection_endpoint: null,
    service_documentation: "https://github.com/your-org/mcp-oauth-server",
  });
});

// OpenID Connect Discovery (optional, for compatibility)
app.get("/.well-known/openid_configuration", (c) => {
  const baseUrl = c.env.WORKER_BASE_URL || "";

  return c.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`,
    scopes_supported: ["mcp:*", "email"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    claims_supported: ["sub", "aud", "email", "iss", "exp", "iat"],
    id_token_signing_alg_values_supported: ["RS256"],
  });
});

// JSON Web Key Set (JWKS)
app.get("/.well-known/jwks.json", async (c) => {
  try {
    const jwtManager = new JWTManager(c.env.JWT_PRIVATE_KEY, c.env.JWT_PUBLIC_KEY, c.env.WORKER_BASE_URL || "");

    const jwks = await jwtManager.getJWKS();
    return c.json(jwks);
  } catch (error) {
    console.error("JWKS error:", error);
    return c.json({ error: "Failed to get JWKS" }, 500);
  }
});

export { app as MetadataHandler };

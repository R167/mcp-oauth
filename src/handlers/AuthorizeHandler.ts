import { Hono } from "hono";
import { z } from "zod";
import type { Env, AuthorizeRequest } from "../types.js";
import { AuthorizeRequestSchema } from "../types.js";
import { StorageManager } from "../managers/StorageManager.js";
import { ScopeValidator } from "../validators/ScopeValidator.js";
import { GitHubClient } from "../clients/GitHubClient.js";

const app = new Hono<{ Bindings: Env }>();

app.get("/authorize", async (c) => {
  try {
    // Parse and validate request parameters
    const params = Object.fromEntries(new URL(c.req.url).searchParams);
    const parseResult = AuthorizeRequestSchema.safeParse(params);

    if (!parseResult.success) {
      return c.json(
        {
          error: "invalid_request",
          error_description: "Invalid authorization request parameters",
        },
        400,
      );
    }

    const request = parseResult.data;
    const storage = new StorageManager(c.env.AUTH_DB);
    await storage.initialize();

    // Validate scope format and get MCP scope
    const scopeValidator = new ScopeValidator();
    const scopeFormat = scopeValidator.validateScopeFormat(request.scope);

    if (!scopeFormat.isValid || !scopeFormat.mcpScope) {
      return c.json(
        {
          error: "invalid_scope",
          error_description: "Invalid scope format. Must include exactly one mcp:<domain>:<server> scope.",
        },
        400,
      );
    }

    // Validate domain matches redirect URI
    if (!scopeValidator.validateDomainMatch(scopeFormat.mcpScope, request.redirect_uri)) {
      return c.json(
        {
          error: "invalid_scope",
          error_description: "MCP scope domain must match redirect URI domain.",
        },
        400,
      );
    }

    // Validate server exists
    if (!scopeValidator.validateServerExists(scopeFormat.mcpScope)) {
      return c.json(
        {
          error: "invalid_scope",
          error_description: "MCP server not found in configuration.",
        },
        400,
      );
    }

    // Create session for authorization flow
    const sessionId = crypto.randomUUID();
    const sessionData = {
      client_id: request.client_id,
      redirect_uri: request.redirect_uri,
      scope: request.scope,
      state: request.state,
      code_challenge: request.code_challenge,
      code_challenge_method: request.code_challenge_method,
    };

    await storage.storeUserSession(sessionId, {
      user_id: sessionId, // Temporary - will be updated after GitHub auth
      expires_at: Math.floor(Date.now() / 1000) + 1800, // 30 minutes
    });

    // Redirect to GitHub OAuth
    const githubClient = new GitHubClient(c.env.GITHUB_CLIENT_ID, c.env.GITHUB_CLIENT_SECRET);
    const githubAuthUrl = githubClient.getAuthorizeUrl(new URL("/auth/github/callback", c.env.WORKER_BASE_URL).href, sessionId);

    return c.redirect(githubAuthUrl);
  } catch (error) {
    console.error("Authorization error:", error);
    return c.json(
      {
        error: "server_error",
        error_description: "Internal server error",
      },
      500,
    );
  }
});

app.post("/authorize", async (c) => {
  try {
    const formData = await c.req.formData();
    const sessionId = formData.get("session_id") as string;
    const consent = formData.get("consent") as string;

    if (!sessionId) {
      return c.json(
        {
          error: "invalid_request",
          error_description: "Missing session ID",
        },
        400,
      );
    }

    const storage = new StorageManager(c.env.AUTH_DB);
    await storage.initialize();

    const session = await storage.getUserSession(sessionId);
    if (!session) {
      return c.json(
        {
          error: "invalid_request",
          error_description: "Invalid or expired session",
        },
        400,
      );
    }

    if (consent !== "approve") {
      // User denied consent - redirect back with error
      const errorParams = new URLSearchParams({
        error: "access_denied",
        error_description: "User denied access",
      });

      const state = formData.get("state") as string;
      if (state) {
        errorParams.set("state", state);
      }

      const redirectUrl = new URL(formData.get("redirect_uri") as string);
      redirectUrl.search = errorParams.toString();

      return c.redirect(redirectUrl.href);
    }

    // User approved - generate authorization code
    const authCode = crypto.randomUUID();
    const expiresAt = Math.floor(Date.now() / 1000) + 600; // 10 minutes

    await storage.storeAuthorizationCode(authCode, {
      client_id: formData.get("client_id") as string,
      redirect_uri: formData.get("redirect_uri") as string,
      scope: formData.get("scope") as string,
      user_id: session.user_id,
      code_challenge: formData.get("code_challenge") as string,
      expires_at: expiresAt,
      email: session.email,
    });

    // Store client approval for future requests
    await storage.storeClientApproval(session.user_id, formData.get("client_id") as string);

    // Clean up session
    await storage.deleteUserSession(sessionId);

    // Redirect back to client with authorization code
    const successParams = new URLSearchParams({
      code: authCode,
    });

    const state = formData.get("state") as string;
    if (state) {
      successParams.set("state", state);
    }

    const redirectUrl = new URL(formData.get("redirect_uri") as string);
    redirectUrl.search = successParams.toString();

    return c.redirect(redirectUrl.href);
  } catch (error) {
    console.error("Authorization consent error:", error);
    return c.json(
      {
        error: "server_error",
        error_description: "Internal server error",
      },
      500,
    );
  }
});

export { app as AuthorizeHandler };

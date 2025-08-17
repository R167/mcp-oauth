import { Hono } from "hono";
import type { Env } from "../types.js";
import { StorageManager } from "../managers/StorageManager.js";
import { ScopeValidator } from "../validators/ScopeValidator.js";
import { GitHubClient } from "../clients/GitHubClient.js";

const app = new Hono<{ Bindings: Env }>();

app.get("/auth/github/callback", async (c) => {
  try {
    const code = c.req.query("code");
    const state = c.req.query("state"); // This is our session ID
    const error = c.req.query("error");

    if (error) {
      return c.json(
        {
          error: "access_denied",
          error_description: `GitHub OAuth error: ${error}`,
        },
        400,
      );
    }

    if (!code || !state) {
      return c.json(
        {
          error: "invalid_request",
          error_description: "Missing code or state parameter",
        },
        400,
      );
    }

    const storage = new StorageManager(c.env.AUTH_DB);
    await storage.initialize();

    // Get session data
    const session = await storage.getUserSession(state);
    if (!session) {
      return c.json(
        {
          error: "invalid_request",
          error_description: "Invalid or expired session",
        },
        400,
      );
    }

    // Exchange code for GitHub access token
    const githubClient = new GitHubClient(c.env.GITHUB_CLIENT_ID, c.env.GITHUB_CLIENT_SECRET);
    const githubAccessToken = await githubClient.exchangeCodeForToken(code, new URL("/auth/github/callback", c.env.WORKER_BASE_URL).href);

    // Get user info from GitHub
    const githubUser = await githubClient.getUser(githubAccessToken);

    // Validate user access based on MCP scope
    // Note: We need to reconstruct the original OAuth request from session
    // This is a simplified version - in practice, you'd store the full request in session
    const mockScope = "mcp:example.com:github-tools email"; // This should come from session
    const mockRedirectUri = "https://example.com/callback"; // This should come from session

    const scopeValidator = new ScopeValidator();
    const scopeValidation = scopeValidator.validateFullScope(mockScope, mockRedirectUri, githubUser);

    if (!scopeValidation.isValid) {
      return c.html(`
				<!DOCTYPE html>
				<html>
				<head>
					<title>Access Denied</title>
				</head>
				<body>
					<h1>Access Denied</h1>
					<p>${scopeValidation.error}</p>
				</body>
				</html>
			`);
    }

    // Update session with user info
    await storage.storeUserSession(state, {
      user_id: githubUser.login,
      email: githubUser.email || undefined,
      name: githubUser.name,
      expires_at: Math.floor(Date.now() / 1000) + 1800, // 30 minutes
    });

    // Check if client is already approved
    const clientId = "mock-client-id"; // This should come from session
    if (await storage.isClientApproved(githubUser.login, clientId)) {
      // Auto-approve - generate authorization code directly
      const authCode = crypto.randomUUID();
      const expiresAt = Math.floor(Date.now() / 1000) + 600; // 10 minutes

      await storage.storeAuthorizationCode(authCode, {
        client_id: clientId,
        redirect_uri: mockRedirectUri,
        scope: mockScope,
        user_id: githubUser.login,
        code_challenge: "mock-challenge", // This should come from session
        expires_at: expiresAt,
        email: githubUser.email || undefined,
      });

      // Redirect back to client
      const redirectUrl = new URL(mockRedirectUri);
      redirectUrl.searchParams.set("code", authCode);
      return c.redirect(redirectUrl.href);
    }

    // Show consent screen
    const serverInfo = scopeValidator.getServerInfo(scopeValidation.mcpScope!);
    return c.html(`
			<!DOCTYPE html>
			<html>
			<head>
				<title>Authorize Access</title>
				<style>
					body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
					.server-info { background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
					.buttons { margin-top: 30px; }
					button { padding: 12px 24px; margin: 0 10px; font-size: 16px; border: none; border-radius: 4px; cursor: pointer; }
					.approve { background: #28a745; color: white; }
					.deny { background: #dc3545; color: white; }
				</style>
			</head>
			<body>
				<h1>Authorize Access</h1>
				<p>Hello <strong>${githubUser.name || githubUser.login}</strong>,</p>
				<p>The application is requesting access to:</p>
				
				<div class="server-info">
					<h3>${serverInfo?.name || "MCP Server"}</h3>
					<p>${serverInfo?.description || "Access to MCP resources"}</p>
					<p><strong>Scope:</strong> ${scopeValidation.mcpScope}</p>
					${scopeValidation.emailRequested ? "<p><strong>Email access:</strong> Yes</p>" : ""}
				</div>

				<form method="POST" action="/authorize">
					<input type="hidden" name="session_id" value="${state}" />
					<input type="hidden" name="client_id" value="${clientId}" />
					<input type="hidden" name="redirect_uri" value="${mockRedirectUri}" />
					<input type="hidden" name="scope" value="${mockScope}" />
					<input type="hidden" name="code_challenge" value="mock-challenge" />
					<input type="hidden" name="state" value="mock-state" />
					
					<div class="buttons">
						<button type="submit" name="consent" value="approve" class="approve">Approve</button>
						<button type="submit" name="consent" value="deny" class="deny">Deny</button>
					</div>
				</form>
			</body>
			</html>
		`);
  } catch (error) {
    console.error("GitHub callback error:", error);
    return c.json(
      {
        error: "server_error",
        error_description: "Failed to process GitHub callback",
      },
      500,
    );
  }
});

export { app as GitHubCallbackHandler };

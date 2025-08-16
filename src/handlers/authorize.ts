import { Environment, OAuthRequest, OAuthError } from "../types";
import { ScopeValidator } from "../utils/scopes";
import { GitHubClient } from "../utils/github";
import { StorageManager } from "../utils/storage";

export class AuthorizeHandler {
	private scopeValidator: ScopeValidator;
	private githubClient: GitHubClient;
	private storage: StorageManager;

	constructor(private env: Environment) {
		this.scopeValidator = new ScopeValidator();
		this.githubClient = new GitHubClient(env);
		this.storage = new StorageManager(env);
	}

	async handle(request: Request): Promise<Response> {
		try {
			const url = new URL(request.url);
			const params = url.searchParams;

			if (request.method === "GET") {
				return await this.handleAuthorizationRequest(params);
			} else if (request.method === "POST") {
				return await this.handleConsentSubmission(request);
			}

			return this.createErrorResponse(
				{
					error: "invalid_request",
					error_description: "Method not allowed",
				},
				405,
			);
		} catch (error) {
			console.error("Authorization error:", error);
			return this.createErrorResponse(
				{
					error: "server_error",
					error_description: "Internal server error",
				},
				500,
			);
		}
	}

	private async handleAuthorizationRequest(params: URLSearchParams): Promise<Response> {
		const oauthRequest = this.parseAuthorizationRequest(params);
		const validation = this.validateAuthorizationRequest(oauthRequest);

		if (!validation.valid) {
			return this.createErrorResponse(
				{
					error: validation.error!,
					error_description: validation.error_description,
					state: oauthRequest.state,
				},
				400,
			);
		}

		const sessionId = this.storage.generateSessionId();
		await this.storage.storeUserSession(sessionId, {
			oauth_request: oauthRequest,
			step: "github_auth",
		});

		const githubScopes = ["user:email"];
		const githubAuthUrl = this.githubClient.getAuthorizationUrl(
			`${this.env.WORKER_BASE_URL}/auth/github/callback?session=${sessionId}`,
			sessionId,
			githubScopes,
		);

		return Response.redirect(githubAuthUrl, 302);
	}

	private async handleConsentSubmission(request: Request): Promise<Response> {
		const formData = await request.formData();
		const sessionId = formData.get("session_id") as string;
		const consent = formData.get("consent") as string;

		if (!sessionId) {
			return this.createErrorResponse(
				{
					error: "invalid_request",
					error_description: "Session ID is required",
				},
				400,
			);
		}

		const session = await this.storage.getUserSession(sessionId);
		if (!session || session.step !== "consent") {
			return this.createErrorResponse(
				{
					error: "invalid_request",
					error_description: "Invalid or expired session",
				},
				400,
			);
		}

		if (consent !== "approved") {
			await this.storage.deleteUserSession(sessionId);

			const errorUrl = new URL(session.oauth_request.redirect_uri);
			errorUrl.searchParams.set("error", "access_denied");
			errorUrl.searchParams.set("error_description", "User denied authorization");
			if (session.oauth_request.state) {
				errorUrl.searchParams.set("state", session.oauth_request.state);
			}

			return Response.redirect(errorUrl.toString(), 302);
		}

		const authCode = this.storage.generateAuthorizationCode();
		const expiresAt = Date.now() + 10 * 60 * 1000;

		await this.storage.storeAuthorizationCode({
			code: authCode,
			client_id: session.oauth_request.client_id,
			redirect_uri: session.oauth_request.redirect_uri,
			scope: session.oauth_request.scope,
			user_id: session.github_user.id.toString(),
			code_challenge: session.oauth_request.code_challenge,
			code_challenge_method: session.oauth_request.code_challenge_method,
			expires_at: expiresAt,
			email: session.github_user.email,
		});

		await this.storage.deleteUserSession(sessionId);

		const redirectUrl = new URL(session.oauth_request.redirect_uri);
		redirectUrl.searchParams.set("code", authCode);
		if (session.oauth_request.state) {
			redirectUrl.searchParams.set("state", session.oauth_request.state);
		}

		return Response.redirect(redirectUrl.toString(), 302);
	}

	private parseAuthorizationRequest(params: URLSearchParams): OAuthRequest {
		return {
			response_type: params.get("response_type") || "",
			client_id: params.get("client_id") || "",
			redirect_uri: params.get("redirect_uri") || "",
			scope: params.get("scope") || "",
			state: params.get("state") || undefined,
			code_challenge: params.get("code_challenge") || "",
			code_challenge_method: params.get("code_challenge_method") || "",
		};
	}

	private validateAuthorizationRequest(request: OAuthRequest): {
		valid: boolean;
		error?: string;
		error_description?: string;
	} {
		if (request.response_type !== "code") {
			return {
				valid: false,
				error: "unsupported_response_type",
				error_description: "Only authorization code flow is supported",
			};
		}

		if (!request.client_id) {
			return {
				valid: false,
				error: "invalid_request",
				error_description: "client_id is required",
			};
		}

		if (!request.redirect_uri) {
			return {
				valid: false,
				error: "invalid_request",
				error_description: "redirect_uri is required",
			};
		}

		try {
			new URL(request.redirect_uri);
		} catch {
			return {
				valid: false,
				error: "invalid_request",
				error_description: "Invalid redirect_uri format",
			};
		}

		if (!request.scope) {
			return {
				valid: false,
				error: "invalid_scope",
				error_description: "scope is required",
			};
		}

		const scopes = request.scope.split(" ");
		const scopeValidation = this.scopeValidator.validateScopesComprehensive(scopes, request.redirect_uri);

		if (!scopeValidation.valid) {
			return {
				valid: false,
				error: "invalid_scope",
				error_description: scopeValidation.error,
			};
		}

		if (!request.code_challenge) {
			return {
				valid: false,
				error: "invalid_request",
				error_description: "code_challenge is required (PKCE)",
			};
		}

		if (request.code_challenge_method !== "S256") {
			return {
				valid: false,
				error: "invalid_request",
				error_description: "code_challenge_method must be S256",
			};
		}

		return { valid: true };
	}

	private createErrorResponse(error: OAuthError, status: number = 400): Response {
		if (error.state) {
			const errorUrl = new URL("about:blank");
			errorUrl.searchParams.set("error", error.error);
			if (error.error_description) {
				errorUrl.searchParams.set("error_description", error.error_description);
			}
			if (error.error_uri) {
				errorUrl.searchParams.set("error_uri", error.error_uri);
			}
			errorUrl.searchParams.set("state", error.state);

			return Response.redirect(errorUrl.toString(), 302);
		}

		return new Response(JSON.stringify(error), {
			status,
			headers: {
				"Content-Type": "application/json",
				"Cache-Control": "no-store",
			},
		});
	}

	async handleGitHubCallback(request: Request): Promise<Response> {
		try {
			const url = new URL(request.url);
			const code = url.searchParams.get("code");
			const sessionId = url.searchParams.get("session");
			const error = url.searchParams.get("error");

			if (error) {
				return this.createErrorResponse(
					{
						error: "access_denied",
						error_description: `GitHub OAuth error: ${error}`,
					},
					400,
				);
			}

			if (!code || !sessionId) {
				return this.createErrorResponse(
					{
						error: "invalid_request",
						error_description: "Missing code or session parameter",
					},
					400,
				);
			}

			const session = await this.storage.getUserSession(sessionId);
			if (!session || session.step !== "github_auth") {
				return this.createErrorResponse(
					{
						error: "invalid_request",
						error_description: "Invalid or expired session",
					},
					400,
				);
			}

			const redirectUri = `${this.env.WORKER_BASE_URL}/auth/github/callback?session=${sessionId}`;
			const githubToken = await this.githubClient.exchangeCodeForToken(code, redirectUri);
			const githubUser = await this.githubClient.getUserWithEmail(githubToken);

			const scopes = session.oauth_request.scope.split(" ");
			const scopeValidation = this.scopeValidator.validateScopesComprehensive(scopes, session.oauth_request.redirect_uri, githubUser.login);

			if (!scopeValidation.valid) {
				await this.storage.deleteUserSession(sessionId);
				return this.createErrorResponse(
					{
						error: "access_denied",
						error_description: scopeValidation.error!,
					},
					403,
				);
			}

			await this.storage.storeUserSession(sessionId, {
				...session,
				step: "consent",
				github_user: githubUser,
				github_token: githubToken,
			});

			return this.renderConsentPage(session.oauth_request, githubUser, sessionId);
		} catch (error) {
			console.error("GitHub callback error:", error);
			return this.createErrorResponse(
				{
					error: "server_error",
					error_description: "Failed to process GitHub authentication",
				},
				500,
			);
		}
	}

	private renderConsentPage(oauthRequest: OAuthRequest, githubUser: any, sessionId: string): Response {
		const scopes = oauthRequest.scope.split(" ");
		const formattedScopes = this.scopeValidator.formatScopesForDisplay(scopes);

		const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Authorize Application</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .user-info { background: #f5f5f5; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .scopes { margin: 20px 0; }
        .scope { margin: 10px 0; padding: 10px; background: #e3f2fd; border-radius: 4px; }
        .buttons { text-align: center; margin-top: 30px; }
        .btn { padding: 12px 24px; margin: 0 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .btn-approve { background: #4CAF50; color: white; }
        .btn-deny { background: #f44336; color: white; }
        .btn:hover { opacity: 0.8; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Authorize Application</h1>
        <p>An application is requesting access to your MCP resources</p>
    </div>

    <div class="user-info">
        <h3>Logged in as: ${githubUser.login}</h3>
        ${githubUser.email ? `<p>Email: ${githubUser.email}</p>` : ""}
    </div>

    <div class="scopes">
        <h3>Requested Permissions:</h3>
        ${formattedScopes.map((scope) => `<div class="scope">${scope}</div>`).join("")}
    </div>

    <form method="POST" action="/authorize">
        <input type="hidden" name="session_id" value="${sessionId}">
        <div class="buttons">
            <button type="submit" name="consent" value="approved" class="btn btn-approve">
                Authorize
            </button>
            <button type="submit" name="consent" value="denied" class="btn btn-deny">
                Deny
            </button>
        </div>
    </form>
</body>
</html>`;

		return new Response(html, {
			headers: {
				"Content-Type": "text/html",
				"Cache-Control": "no-store",
			},
		});
	}
}

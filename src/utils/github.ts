import { Environment, GitHubUser, GitHubEmail } from "../types";

export class GitHubError extends Error {
	constructor(
		message: string,
		public statusCode?: number,
	) {
		super(message);
		this.name = "GitHubError";
	}
}

export class GitHubClient {
	private readonly GITHUB_API_BASE = "https://api.github.com";
	private readonly GITHUB_AUTH_BASE = "https://github.com";

	constructor(private env: Environment) {}

	getAuthorizationUrl(redirectUri: string, state: string, scope: string[] = ["user:email"]): string {
		const params = new URLSearchParams({
			client_id: this.env.GITHUB_CLIENT_ID,
			redirect_uri: redirectUri,
			scope: scope.join(" "),
			state,
			response_type: "code",
		});

		return `${this.GITHUB_AUTH_BASE}/login/oauth/authorize?${params.toString()}`;
	}

	async exchangeCodeForToken(code: string, redirectUri: string): Promise<string> {
		try {
			const response = await fetch(`${this.GITHUB_AUTH_BASE}/login/oauth/access_token`, {
				method: "POST",
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					client_id: this.env.GITHUB_CLIENT_ID,
					client_secret: this.env.GITHUB_CLIENT_SECRET,
					code,
					redirect_uri: redirectUri,
				}),
			});

			if (!response.ok) {
				throw new GitHubError(`GitHub token exchange failed: ${response.statusText}`, response.status);
			}

			const data = await response.json();

			if (data.error) {
				throw new GitHubError(`GitHub OAuth error: ${data.error_description || data.error}`);
			}

			if (!data.access_token) {
				throw new GitHubError("No access token received from GitHub");
			}

			return data.access_token;
		} catch (error) {
			if (error instanceof GitHubError) {
				throw error;
			}
			throw new GitHubError(`Failed to exchange code for token: ${error}`);
		}
	}

	async getUser(accessToken: string): Promise<GitHubUser> {
		try {
			const response = await fetch(`${this.GITHUB_API_BASE}/user`, {
				headers: {
					Authorization: `token ${accessToken}`,
					Accept: "application/vnd.github.v3+json",
					"User-Agent": "MCP-OAuth-Server",
				},
			});

			if (!response.ok) {
				throw new GitHubError(`GitHub API error: ${response.statusText}`, response.status);
			}

			const user = (await response.json()) as GitHubUser;

			if (!user.id || !user.login) {
				throw new GitHubError("Invalid user data received from GitHub");
			}

			return user;
		} catch (error) {
			if (error instanceof GitHubError) {
				throw error;
			}
			throw new GitHubError(`Failed to get user: ${error}`);
		}
	}

	async getUserEmails(accessToken: string): Promise<GitHubEmail[]> {
		try {
			const response = await fetch(`${this.GITHUB_API_BASE}/user/emails`, {
				headers: {
					Authorization: `token ${accessToken}`,
					Accept: "application/vnd.github.v3+json",
					"User-Agent": "MCP-OAuth-Server",
				},
			});

			if (!response.ok) {
				if (response.status === 404) {
					return [];
				}
				throw new GitHubError(`GitHub emails API error: ${response.statusText}`, response.status);
			}

			const emails = (await response.json()) as GitHubEmail[];
			return emails || [];
		} catch (error) {
			if (error instanceof GitHubError) {
				throw error;
			}
			throw new GitHubError(`Failed to get user emails: ${error}`);
		}
	}

	async getPrimaryEmail(accessToken: string): Promise<string | undefined> {
		try {
			const user = await this.getUser(accessToken);

			if (user.email) {
				return user.email;
			}

			const emails = await this.getUserEmails(accessToken);
			const primaryEmail = emails.find((email) => email.primary && email.verified);

			return primaryEmail?.email;
		} catch (error) {
			if (error instanceof GitHubError) {
				throw error;
			}
			throw new GitHubError(`Failed to get primary email: ${error}`);
		}
	}

	async getUserWithEmail(accessToken: string): Promise<GitHubUser & { email?: string }> {
		try {
			const user = await this.getUser(accessToken);

			if (user.email) {
				return user;
			}

			const primaryEmail = await this.getPrimaryEmail(accessToken);

			return {
				...user,
				email: primaryEmail,
			};
		} catch (error) {
			if (error instanceof GitHubError) {
				throw error;
			}
			throw new GitHubError(`Failed to get user with email: ${error}`);
		}
	}

	validateScopes(requestedScopes: string[]): { valid: boolean; error?: string } {
		const validScopes = ["user", "user:email", "read:user"];
		const invalidScopes = requestedScopes.filter((scope) => !validScopes.includes(scope));

		if (invalidScopes.length > 0) {
			return {
				valid: false,
				error: `Invalid GitHub scopes: ${invalidScopes.join(", ")}`,
			};
		}

		return { valid: true };
	}
}

import { Octokit } from "octokit";
import type { GitHubUser } from "../types.js";

export class GitHubClient {
  constructor(
    private readonly clientId: string,
    private readonly clientSecret: string,
  ) {}

  getAuthorizeUrl(redirectUri: string, state: string): string {
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: redirectUri,
      scope: "read:user user:email",
      state,
    });

    return `https://github.com/login/oauth/authorize?${params}`;
  }

  async exchangeCodeForToken(code: string, redirectUri: string): Promise<string> {
    const response = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: this.clientId,
        client_secret: this.clientSecret,
        code,
        redirect_uri: redirectUri,
      }),
    });

    if (!response.ok) {
      throw new Error(`GitHub token exchange failed: ${response.status}`);
    }

    const data = (await response.json()) as { access_token?: string; error?: string; error_description?: string };

    if (data.error) {
      throw new Error(`GitHub OAuth error: ${data.error_description || data.error}`);
    }

    if (!data.access_token) {
      throw new Error("No access token received from GitHub");
    }

    return data.access_token;
  }

  async getUser(accessToken: string): Promise<GitHubUser> {
    const octokit = new Octokit({ auth: accessToken });

    try {
      const { data: user } = await octokit.rest.users.getAuthenticated();

      // Try to get primary email if not public
      let email = user.email;
      if (!email) {
        try {
          const { data: emails } = await octokit.rest.users.listEmailsForAuthenticatedUser();
          const primaryEmail = emails.find((e) => e.primary);
          email = primaryEmail?.email || null;
        } catch {
          // Email scope might not be granted or user has no emails
        }
      }

      return {
        login: user.login,
        name: user.name || undefined,
        email: email || null,
      };
    } catch (error) {
      throw new Error(`Failed to fetch user from GitHub: ${error}`);
    }
  }
}

import { MCPScope, ACLConfig } from "../types";
import config from "../config.json";

export class ScopeError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ScopeError";
	}
}

export class ScopeValidator {
	private config: ACLConfig;

	constructor() {
		this.config = config;
	}

	parseMCPScope(scope: string): MCPScope | null {
		const mcpScopeRegex = /^mcp:([^:]+):([^:]+)$/;
		const match = scope.match(mcpScopeRegex);

		if (!match) {
			return null;
		}

		return {
			type: "mcp",
			domain: match[1],
			server: match[2],
			raw: scope,
		};
	}

	validateScopeFormat(scopes: string[]): { valid: boolean; error?: string } {
		if (scopes.length === 0) {
			return { valid: false, error: "At least one scope is required" };
		}

		const mcpScopes = scopes.filter((scope) => scope.startsWith("mcp:"));
		const otherScopes = scopes.filter((scope) => !scope.startsWith("mcp:"));

		if (mcpScopes.length === 0) {
			return { valid: false, error: "At least one MCP scope is required" };
		}

		if (mcpScopes.length > 1) {
			return { valid: false, error: "Only one MCP scope is allowed per request" };
		}

		const validOtherScopes = ["user:email"];
		for (const scope of otherScopes) {
			if (!validOtherScopes.includes(scope)) {
				return { valid: false, error: `Invalid scope: ${scope}` };
			}
		}

		const mcpScope = this.parseMCPScope(mcpScopes[0]);
		if (!mcpScope) {
			return { valid: false, error: `Invalid MCP scope format: ${mcpScopes[0]}` };
		}

		return { valid: true };
	}

	validateDomainMatchesRedirect(scope: string, redirectUri: string): { valid: boolean; error?: string } {
		const mcpScope = this.parseMCPScope(scope);
		if (!mcpScope) {
			return { valid: false, error: "Invalid MCP scope format" };
		}

		let redirectDomain: string;
		try {
			const url = new URL(redirectUri);
			redirectDomain = url.hostname;
		} catch (error) {
			return { valid: false, error: "Invalid redirect URI format" };
		}

		if (mcpScope.domain !== redirectDomain) {
			return {
				valid: false,
				error: `MCP scope domain (${mcpScope.domain}) must match redirect URI domain (${redirectDomain})`,
			};
		}

		return { valid: true };
	}

	validateServerExists(scope: string): { valid: boolean; error?: string } {
		const mcpScope = this.parseMCPScope(scope);
		if (!mcpScope) {
			return { valid: false, error: "Invalid MCP scope format" };
		}

		const server = this.config.servers.find((s) => s.domain === mcpScope.domain && s.server === mcpScope.server);

		if (!server) {
			return {
				valid: false,
				error: `MCP server ${mcpScope.domain}:${mcpScope.server} is not configured`,
			};
		}

		return { valid: true };
	}

	validateUserAccess(scope: string, userLogin: string): { valid: boolean; error?: string } {
		const mcpScope = this.parseMCPScope(scope);
		if (!mcpScope) {
			return { valid: false, error: "Invalid MCP scope format" };
		}

		const server = this.config.servers.find((s) => s.domain === mcpScope.domain && s.server === mcpScope.server);

		if (!server) {
			return {
				valid: false,
				error: `MCP server ${mcpScope.domain}:${mcpScope.server} is not configured`,
			};
		}

		if (!server.allowed_users.includes(userLogin)) {
			return {
				valid: false,
				error: `User ${userLogin} is not authorized for MCP server ${mcpScope.domain}:${mcpScope.server}`,
			};
		}

		return { valid: true };
	}

	validateScopesComprehensive(
		scopes: string[],
		redirectUri: string,
		userLogin?: string,
	): { valid: boolean; error?: string; mcpScope?: MCPScope } {
		const formatValidation = this.validateScopeFormat(scopes);
		if (!formatValidation.valid) {
			return formatValidation;
		}

		const mcpScopeString = scopes.find((scope) => scope.startsWith("mcp:"))!;
		const mcpScope = this.parseMCPScope(mcpScopeString)!;

		const domainValidation = this.validateDomainMatchesRedirect(mcpScopeString, redirectUri);
		if (!domainValidation.valid) {
			return domainValidation;
		}

		const serverValidation = this.validateServerExists(mcpScopeString);
		if (!serverValidation.valid) {
			return serverValidation;
		}

		if (userLogin) {
			const userValidation = this.validateUserAccess(mcpScopeString, userLogin);
			if (!userValidation.valid) {
				return userValidation;
			}
		}

		return { valid: true, mcpScope };
	}

	getRequestedEmailScope(scopes: string[]): boolean {
		return scopes.includes("user:email");
	}

	getServerConfig(domain: string, server: string) {
		return this.config.servers.find((s) => s.domain === domain && s.server === server);
	}

	getAllServers() {
		return this.config.servers;
	}

	formatScopesForDisplay(scopes: string[]): string[] {
		return scopes.map((scope) => {
			if (scope.startsWith("mcp:")) {
				const mcpScope = this.parseMCPScope(scope);
				if (mcpScope) {
					const serverConfig = this.getServerConfig(mcpScope.domain, mcpScope.server);
					const description = serverConfig?.description || `Access to ${mcpScope.server}`;
					return `${scope} - ${description}`;
				}
			} else if (scope === "user:email") {
				return `${scope} - Access to your email address`;
			}
			return scope;
		});
	}
}

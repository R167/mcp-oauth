import type { Config, GitHubUser } from "../types.js";
import configData from "../config.json";

export class ScopeValidator {
  private readonly config: Config = configData;

  validateScopeFormat(scope: string): { isValid: boolean; mcpScope?: string; emailRequested?: boolean } {
    const scopes = scope.split(" ").filter((s) => s.length > 0);

    // Find MCP scope and email scope
    const mcpScopes = scopes.filter((s) => s.startsWith("mcp:"));
    const emailScope = scopes.includes("email");

    // Must have exactly one MCP scope
    if (mcpScopes.length !== 1) {
      return { isValid: false };
    }

    const mcpScope = mcpScopes[0];

    // Validate MCP scope format: mcp:<domain>:<server>
    const mcpPattern = /^mcp:([^:]+):([^:]+)$/;
    const match = mcpScope.match(mcpPattern);

    if (!match) {
      return { isValid: false };
    }

    return {
      isValid: true,
      mcpScope,
      emailRequested: emailScope,
    };
  }

  validateDomainMatch(mcpScope: string, redirectUri: string): boolean {
    const mcpPattern = /^mcp:([^:]+):([^:]+)$/;
    const mcpMatch = mcpScope.match(mcpPattern);

    if (!mcpMatch) return false;

    const mcpDomain = mcpMatch[1];

    try {
      const url = new URL(redirectUri);
      return url.hostname === mcpDomain;
    } catch {
      return false;
    }
  }

  validateServerExists(mcpScope: string): boolean {
    const mcpPattern = /^mcp:([^:]+):([^:]+)$/;
    const match = mcpScope.match(mcpPattern);

    if (!match) return false;

    const [, domain, server] = match;

    return !!this.config.servers[domain]?.[server];
  }

  validateUserAccess(mcpScope: string, user: GitHubUser): boolean {
    const mcpPattern = /^mcp:([^:]+):([^:]+)$/;
    const match = mcpScope.match(mcpPattern);

    if (!match) return false;

    const [, domain, server] = match;
    const serverConfig = this.config.servers[domain]?.[server];

    if (!serverConfig) return false;

    return serverConfig.allowed_users.includes(user.login);
  }

  getServerInfo(mcpScope: string): { name: string; description: string } | null {
    const mcpPattern = /^mcp:([^:]+):([^:]+)$/;
    const match = mcpScope.match(mcpPattern);

    if (!match) return null;

    const [, domain, server] = match;
    const serverConfig = this.config.servers[domain]?.[server];

    if (!serverConfig) return null;

    return {
      name: serverConfig.name,
      description: serverConfig.description,
    };
  }

  validateFullScope(
    scope: string,
    redirectUri: string,
    user: GitHubUser,
  ): {
    isValid: boolean;
    mcpScope?: string;
    emailRequested?: boolean;
    error?: string;
  } {
    // 1. Validate scope format
    const formatResult = this.validateScopeFormat(scope);
    if (!formatResult.isValid || !formatResult.mcpScope) {
      return { isValid: false, error: "Invalid scope format. Must include exactly one mcp:<domain>:<server> scope." };
    }

    // 2. Validate domain matches redirect URI
    if (!this.validateDomainMatch(formatResult.mcpScope, redirectUri)) {
      return { isValid: false, error: "MCP scope domain must match redirect URI domain." };
    }

    // 3. Validate server exists in configuration
    if (!this.validateServerExists(formatResult.mcpScope)) {
      return { isValid: false, error: "MCP server not found in configuration." };
    }

    // 4. Validate user has access to server
    if (!this.validateUserAccess(formatResult.mcpScope, user)) {
      return { isValid: false, error: "User does not have access to the requested MCP server." };
    }

    return {
      isValid: true,
      mcpScope: formatResult.mcpScope,
      emailRequested: formatResult.emailRequested,
    };
  }
}

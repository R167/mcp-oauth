export interface Environment {
	AUTH_KV: KVNamespace;
	GITHUB_CLIENT_ID: string;
	GITHUB_CLIENT_SECRET: string;
	JWT_PRIVATE_KEY: string;
	JWT_PUBLIC_KEY: string;
	REFRESH_ENCRYPTION_KEY: string;
	ACCESS_TOKEN_ENCRYPTION_KEY: string;
	WORKER_BASE_URL: string;
}

export interface MCPScope {
	type: "mcp";
	domain: string;
	server: string;
	raw: string;
}

export interface OAuthRequest {
	response_type: string;
	client_id: string;
	redirect_uri: string;
	scope: string;
	state?: string;
	code_challenge: string;
	code_challenge_method: string;
}

export interface AuthorizationCode {
	code: string;
	client_id: string;
	redirect_uri: string;
	scope: string;
	user_id: string;
	code_challenge: string;
	code_challenge_method: string;
	expires_at: number;
	email?: string;
}

export interface TokenRequest {
	grant_type: string;
	code?: string;
	redirect_uri?: string;
	client_id: string;
	code_verifier?: string;
	refresh_token?: string;
}

export interface AccessToken {
	token_type: "access";
	iss: string;
	exp: number;
	sub: string;
	aud: string;
	email?: string;
	extra?: Record<string, any>;
}

export interface RefreshToken {
	token_type: "refresh";
	iss: string;
	exp: number;
	sub: string;
	aud: string;
	email?: string;
}

export interface TokenResponse {
	access_token: string;
	token_type: "Bearer";
	expires_in: number;
	refresh_token: string;
	scope: string;
}

export interface GitHubUser {
	id: number;
	login: string;
	email?: string;
}

export interface GitHubEmail {
	email: string;
	primary: boolean;
	verified: boolean;
	visibility?: string;
}

export interface MCPServerConfig {
	domain: string;
	server: string;
	allowed_users: string[];
	description?: string;
}

export interface ACLConfig {
	servers: MCPServerConfig[];
}

export interface OAuthError {
	error: string;
	error_description?: string;
	error_uri?: string;
	state?: string;
}

export interface AuthServerMetadata {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	response_types_supported: string[];
	grant_types_supported: string[];
	subject_types_supported: string[];
	id_token_signing_alg_values_supported: string[];
	scopes_supported: string[];
	token_endpoint_auth_methods_supported: string[];
	code_challenge_methods_supported: string[];
}

export const TOKEN_CONSTANTS = {
	ACCESS_TOKEN_LIFETIME: 3600,
	REFRESH_TOKEN_LIFETIME: 30 * 24 * 3600,
	AUTHORIZATION_CODE_LIFETIME: 600,
	ACCESS_TOKEN_PREFIX: "mcp_token__",
	REFRESH_TOKEN_PREFIX: "mcp_refresh__",
} as const;

export const KV_KEYS = {
	AUTH_CODE: (code: string) => `auth_code:${code}`,
	REFRESH_TOKEN: (token_id: string) => `refresh_token:${token_id}`,
	USER_SESSION: (session_id: string) => `session:${session_id}`,
	ENCRYPTION_KEY: (version: string) => `encryption_key:${version}`,
} as const;

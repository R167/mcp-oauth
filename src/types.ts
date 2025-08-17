import { z } from 'zod';

export interface Env {
	AUTH_DB: D1Database;
	GITHUB_CLIENT_ID: string;
	GITHUB_CLIENT_SECRET: string;
	JWT_PRIVATE_KEY: string;
	JWT_PUBLIC_KEY: string;
	REFRESH_ENCRYPTION_KEY: string;
	WORKER_BASE_URL?: string;
}

export const OAuthErrorSchema = z.object({
	error: z.enum(['invalid_request', 'invalid_client', 'invalid_grant', 'unauthorized_client', 'unsupported_grant_type', 'invalid_scope']),
	error_description: z.string().optional(),
	error_uri: z.string().optional(),
});

export const AuthorizeRequestSchema = z.object({
	response_type: z.literal('code'),
	client_id: z.string(),
	redirect_uri: z.string().url(),
	scope: z.string(),
	state: z.string().optional(),
	code_challenge: z.string(),
	code_challenge_method: z.literal('S256'),
});

export const TokenRequestSchema = z.object({
	grant_type: z.enum(['authorization_code', 'refresh_token']),
	code: z.string().optional(),
	redirect_uri: z.string().url().optional(),
	client_id: z.string(),
	code_verifier: z.string().optional(),
	refresh_token: z.string().optional(),
});

export const AccessTokenSchema = z.object({
	token_type: z.literal('access'),
	iss: z.string(),
	exp: z.number(),
	iat: z.number().optional(),
	sub: z.string(),
	aud: z.string(),
	email: z.string().optional(),
});

export const RefreshTokenSchema = z.object({
	token_type: z.literal('refresh'),
	iss: z.string(),
	exp: z.number(),
	iat: z.number().optional(),
	sub: z.string(),
	aud: z.string(),
	email: z.string().optional(),
});

export type OAuthError = z.infer<typeof OAuthErrorSchema>;
export type AuthorizeRequest = z.infer<typeof AuthorizeRequestSchema>;
export type TokenRequest = z.infer<typeof TokenRequestSchema>;
export type AccessToken = z.infer<typeof AccessTokenSchema>;
export type RefreshToken = z.infer<typeof RefreshTokenSchema>;

export interface AuthorizationCode {
	client_id: string;
	redirect_uri: string;
	scope: string;
	user_id: string;
	code_challenge: string;
	expires_at: number;
	email?: string;
}

export interface RefreshTokenMetadata {
	user_id: string;
	client_id: string;
	scope: string;
	expires_at: number;
	email?: string;
}

export interface UserSession {
	user_id: string;
	email?: string;
	name?: string;
	expires_at: number;
}

export interface GitHubUser {
	login: string;
	name?: string;
	email?: string | null;
}

export interface ServerConfig {
	name: string;
	description: string;
	allowed_users: string[];
}

export interface Config {
	servers: Record<string, Record<string, ServerConfig>>;
}

export interface ClientRegistration {
	client_id: string;
	client_name: string;
	redirect_uris: string[];
	scope: string;
	created_at: number;
	last_used: number;
	expires_at: number;
}

export const ClientRegistrationRequestSchema = z.object({
	client_name: z.string().min(1).max(100),
	redirect_uris: z.array(z.string().url()).min(1).max(10),
	scope: z.string(),
});

export type ClientRegistrationRequest = z.infer<typeof ClientRegistrationRequestSchema>;
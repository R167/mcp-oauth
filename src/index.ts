import { Hono } from 'hono';
import type { Env } from './types.js';
import { AuthorizeHandler } from './handlers/AuthorizeHandler.js';
import { TokenHandler } from './handlers/TokenHandler.js';
import { MetadataHandler } from './handlers/MetadataHandler.js';
import { GitHubCallbackHandler } from './handlers/GitHubCallbackHandler.js';
import { ClientRegistrationHandler } from './handlers/ClientRegistrationHandler.js';
import { StorageManager } from './managers/StorageManager.js';
import { JWTManager } from './managers/JWTManager.js';

const app = new Hono<{ Bindings: Env }>();

// Database migrations are handled by D1's built-in migration system

// Mount OAuth handlers
app.route('/', AuthorizeHandler);
app.route('/', TokenHandler);
app.route('/', MetadataHandler);
app.route('/', GitHubCallbackHandler);
app.route('/', ClientRegistrationHandler);

// Health check
app.get('/health', (c) => {
	return c.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Root endpoint with server info
app.get('/', (c) => {
	return c.json({
		name: 'MCP OAuth Authorization Server',
		version: '1.0.0',
		endpoints: {
			authorize: '/authorize',
			token: '/token',
			github_callback: '/auth/github/callback',
			jwks: '/.well-known/jwks.json',
			metadata: '/.well-known/oauth-authorization-server',
			openid_config: '/.well-known/openid_configuration',
			validate: '/validate',
			revoke: '/admin/revoke',
			register: '/register',
			client_info: '/client/{client_id}',
		},
	});
});

// Token validation endpoint
app.post('/validate', async (c) => {
	try {
		// Extract token from request body or Authorization header
		let token: string | undefined;
		
		const authHeader = c.req.header('Authorization');
		if (authHeader?.startsWith('Bearer ')) {
			token = authHeader.substring(7);
		} else {
			// Try to get token from request body
			const body = await c.req.json().catch(() => ({}));
			token = body.token || body.access_token;
		}

		if (!token) {
			return c.json({
				valid: false,
				error: 'No token provided. Include token in Authorization header or request body.',
			}, 400);
		}

		// Initialize JWT manager and storage
		const jwtManager = new JWTManager(
			c.env.JWT_PRIVATE_KEY,
			c.env.JWT_PUBLIC_KEY,
			c.env.WORKER_BASE_URL || ''
		);
		const storage = new StorageManager(c.env.AUTH_DB);

		// Verify token (includes revocation check)
		const payload = await jwtManager.verifyToken(token, storage);

		// Return validation result
		return c.json({
			valid: true,
			payload: {
				token_type: payload.token_type,
				sub: payload.sub,
				aud: payload.aud,
				iss: payload.iss,
				exp: payload.exp,
				iat: payload.iat,
				email: payload.email,
			},
		});
	} catch (error) {
		// Return validation failure
		return c.json({
			valid: false,
			error: error instanceof Error ? error.message : 'Token validation failed',
		}, 400);
	}
});

// Token revocation endpoint
app.post('/admin/revoke', async (c) => {
	try {
		const body = await c.req.json().catch(() => ({}));
		const token = body.token || body.refresh_token;

		if (!token) {
			return c.json({
				error: 'invalid_request',
				error_description: 'Missing token parameter',
			}, 400);
		}

		const storage = new StorageManager(c.env.AUTH_DB);

		// Check if it's a refresh token (starts with mcp_refresh__)
		if (token.startsWith('mcp_refresh__')) {
			// Decrypt refresh token to get token ID
			const encryptionManager = new (await import('./managers/EncryptionManager.js')).EncryptionManager(
				c.env.REFRESH_ENCRYPTION_KEY
			);
			
			try {
				const decryptedToken = await encryptionManager.decrypt(token.substring(13)); // Remove prefix
				const refreshTokenData = JSON.parse(decryptedToken);
				
				// Add to revoked tokens list with expiration from token
				await storage.revokeRefreshToken(refreshTokenData.jti, refreshTokenData.exp);
				
				return c.json({ message: 'Token revoked successfully' });
			} catch (error) {
				return c.json({
					error: 'invalid_token',
					error_description: 'Invalid refresh token',
				}, 400);
			}
		} else {
			// It's an access token - verify it first to get its claims
			const jwtManager = new JWTManager(
				c.env.JWT_PRIVATE_KEY,
				c.env.JWT_PUBLIC_KEY,
				c.env.WORKER_BASE_URL || ''
			);

			try {
				const payload = await jwtManager.verifyToken(token, storage);
				
				// Hash the token for revocation tracking (since access tokens don't have jti)
				const tokenHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
				const tokenId = Array.from(new Uint8Array(tokenHash))
					.map(b => b.toString(16).padStart(2, '0'))
					.join('');
				
				// Store hash with token expiration
				await storage.revokeRefreshToken(tokenId, payload.exp);
				
				return c.json({ message: 'Token revoked successfully' });
			} catch (error) {
				return c.json({
					error: 'invalid_token',
					error_description: 'Invalid access token',
				}, 400);
			}
		}
	} catch (error) {
		console.error('Token revocation error:', error);
		return c.json({
			error: 'server_error',
			error_description: 'Internal server error',
		}, 500);
	}
});

// Scheduled event handler for daily cleanup
async function scheduled(event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
	console.log('Running scheduled cleanup task...');
	
	try {
		const storage = new StorageManager(env.AUTH_DB);
		await storage.cleanupExpired();
		
		console.log('Scheduled cleanup completed successfully');
	} catch (error) {
		console.error('Scheduled cleanup failed:', error);
	}
}

export default {
	fetch: app.fetch,
	scheduled,
};
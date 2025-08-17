import { Hono } from 'hono';
import type { Env } from './types.js';
import { AuthorizeHandler } from './handlers/AuthorizeHandler.js';
import { TokenHandler } from './handlers/TokenHandler.js';
import { MetadataHandler } from './handlers/MetadataHandler.js';
import { GitHubCallbackHandler } from './handlers/GitHubCallbackHandler.js';
import { StorageManager } from './managers/StorageManager.js';

const app = new Hono<{ Bindings: Env }>();

// Initialize database on first request
app.use('*', async (c, next) => {
	const storage = new StorageManager(c.env.AUTH_DB);
	await storage.initialize();
	await next();
});

// Mount OAuth handlers
app.route('/', AuthorizeHandler);
app.route('/', TokenHandler);
app.route('/', MetadataHandler);
app.route('/', GitHubCallbackHandler);

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
		},
	});
});

// Admin endpoints
app.post('/admin/revoke', async (c) => {
	// TODO: Implement token revocation
	return c.json({ message: 'Token revocation not implemented yet' }, 501);
});

export default app;
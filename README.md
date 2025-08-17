# MCP OAuth Authorization Server

A production-ready OAuth 2.1/OIDC authorization server built on Cloudflare Workers for securing Model Context Protocol (MCP) resources. The server implements 2-hop authentication via GitHub with comprehensive security features.

## Features

- **OAuth 2.1 Compliant**: Authorization Code flow with PKCE
- **GitHub Integration**: 2-hop authentication via GitHub OAuth
- **MCP Scope Validation**: Fine-grained access control for MCP servers
- **Security**: JWT tokens, encrypted refresh tokens, PKCE enforcement
- **Cloudflare Workers**: Serverless deployment with D1 database storage
- **Standards Compliance**: OAuth 2.1, OIDC Discovery, JWKS

## Architecture

See [Architecture.md](./Architecture.md) for detailed architecture documentation.

## Quick Start

### 1. Setup

```bash
# Install dependencies
pnpm install

# Create D1 database
wrangler d1 create mcp-oauth-db

# Update wrangler.jsonc with your database ID
```

### 2. Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Set the following secrets:

```bash
# GitHub OAuth App credentials
wrangler secret put GITHUB_CLIENT_ID
wrangler secret put GITHUB_CLIENT_SECRET

# Generate RSA key pair for JWT signing
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Set JWT keys (copy the full PEM content including headers)
wrangler secret put JWT_PRIVATE_KEY
wrangler secret put JWT_PUBLIC_KEY

# Generate encryption key for refresh tokens
openssl rand -base64 32 | wrangler secret put REFRESH_ENCRYPTION_KEY

# Set your worker base URL
wrangler secret put WORKER_BASE_URL
```

### 3. Configure MCP Servers

Edit `src/config.json` to define your MCP servers and authorized users:

```json
{
  "servers": {
    "your-domain.com": {
      "your-server": {
        "name": "Your MCP Server",
        "description": "Description of your server",
        "allowed_users": ["github-username1", "github-username2"]
      }
    }
  }
}
```

### 4. Deploy

```bash
# Deploy to Cloudflare Workers
pnpm run deploy
```

### 5. GitHub OAuth App Setup

1. Create a GitHub OAuth App at https://github.com/settings/applications/new
2. Set Authorization callback URL to: `https://your-worker.workers.dev/auth/github/callback`
3. Copy Client ID and Secret to your environment variables

## Development

```bash
# Start development server
pnpm run dev

# Run tests
pnpm test

# Type checking
pnpm run type-check

# Format code
pnpm run format
```

## Usage

### OAuth Flow

1. **Authorization Request**: Client redirects user to `/authorize` with PKCE parameters
2. **GitHub Authentication**: User authenticates with GitHub
3. **Scope Validation**: Server validates MCP scope and user permissions
4. **Consent Screen**: User approves access (skipped if previously approved)
5. **Authorization Code**: Server returns authorization code to client
6. **Token Exchange**: Client exchanges code for access/refresh tokens using PKCE verifier

### MCP Scope Format

Scopes must follow the pattern: `mcp:<domain>:<server>` where:
- `domain`: Must match the redirect URI domain
- `server`: Must exist in `src/config.json` configuration
- User must be in the server's `allowed_users` list

Example: `mcp:example.com:github-tools email`

### API Endpoints

- `GET /authorize` - OAuth authorization endpoint
- `POST /token` - Token exchange endpoint
- `GET /.well-known/jwks.json` - Public keys for token validation
- `GET /.well-known/oauth-authorization-server` - OAuth metadata
- `GET /auth/github/callback` - GitHub OAuth callback
- `GET /health` - Health check

### Token Validation

Resource servers can validate access tokens by:

1. Fetching public keys from `/.well-known/jwks.json`
2. Verifying JWT signature with RS256
3. Validating claims (issuer, audience, expiration)
4. Checking audience matches expected MCP scope

Example validation (pseudo-code):
```javascript
const token = request.headers.authorization.replace('Bearer ', '');
const publicKey = await fetchPublicKey();
const payload = await verifyJWT(token, publicKey);

if (payload.aud === 'mcp:example.com:github-tools') {
  // Grant access to user payload.sub
}
```

## Security Features

- **PKCE**: All authorization flows require PKCE for security
- **Encrypted Refresh Tokens**: AES-GCM encryption with key rotation
- **Scope Binding**: Tokens bound to specific MCP scopes
- **Domain Validation**: MCP scope domain must match redirect URI
- **User Authorization**: ACL-based access control per MCP server
- **Token Rotation**: Refresh tokens are rotated on use
- **Secure Headers**: Proper CORS and security headers

## Configuration

### D1 Database

The server automatically creates required tables on first startup:
- `authorization_codes` - Temporary authorization codes
- `refresh_tokens` - Refresh token metadata
- `user_sessions` - User authentication sessions
- `client_approvals` - Stored consent decisions
- `revoked_tokens` - Revoked refresh tokens

### Key Rotation

Refresh token encryption supports key rotation:

```bash
# Generate new encryption key
NEW_KEY=$(openssl rand -base64 32)
wrangler secret put REFRESH_ENCRYPTION_KEY --text "$NEW_KEY"
```

Old tokens remain valid during transition period.

## Monitoring

- Health check endpoint: `GET /health`
- Cloudflare Workers analytics and logs
- Error logging for debugging

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `pnpm test`
4. Submit a pull request

## License

MIT License - see LICENSE file for details.
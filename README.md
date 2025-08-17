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

### Development

```bash
# Install dependencies
pnpm install

# Start development server
pnpm run dev
```

Server runs on `http://localhost:8787` with auto-generated test keys.

### Staging Deployment (Ready to Use!)

The project includes a pre-configured staging environment:

```bash
# 1. Set up secrets (interactive script)
./scripts/setup-secrets.sh staging

# 2. Deploy to staging
pnpm run deploy:staging

# 3. Test deployment
curl https://mcp-oauth-authorization-server-staging.wmdurand.workers.dev/health
```

**Staging URL**: `https://mcp-oauth-authorization-server-staging.wmdurand.workers.dev`

**Note**: You must configure secrets before the server will work properly.

### Production Deployment

```bash
# 1. Set up production secrets
./scripts/setup-secrets.sh prod

# 2. Deploy to production
pnpm run deploy:prod
```

**Production URL**: `https://auth.mcp.r167.dev`

## Configuration

### GitHub OAuth App Setup

Create a GitHub OAuth App with these settings:
- **Staging callback**: `https://mcp-oauth-authorization-server-staging.wmdurand.workers.dev/auth/github/callback`
- **Production callback**: `https://auth.mcp.r167.dev/auth/github/callback`

### MCP Servers

Configure your MCP servers in `src/config.json` (production) or `src/config.staging.json` (staging):

```json
{
  "servers": {
    "your-domain.com": {
      "your-server": {
        "name": "Your MCP Server",
        "description": "Description of what this server provides",
        "allowed_users": ["github-username1", "github-username2"]
      }
    }
  }
}
```

### Required Configuration

#### Cloudflare Secrets
| Variable | Description |
|----------|-------------|
| `GITHUB_CLIENT_ID` | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth app client secret |
| `JWT_PRIVATE_KEY` | RS256 private key for JWT signing |
| `JWT_PUBLIC_KEY` | RS256 public key for JWT verification |
| `REFRESH_ENCRYPTION_KEY` | AES-256 key for refresh token encryption |

#### Environment Variables
| Variable | Description | Set in |
|----------|-------------|--------|
| `WORKER_BASE_URL` | Full URL of the deployed worker | `wrangler.jsonc` |

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

## Automated Secret Setup

Use the provided script to easily configure all required secrets:

```bash
# For staging environment
./scripts/setup-secrets.sh staging

# For production environment  
./scripts/setup-secrets.sh prod
```

The script will prompt you for all required values and set them automatically.

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

Resource servers validate access tokens by:

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
  // Grant access to user payload.sub (GitHub user ID)
}
```

**Note**: The system uses D1 database for state storage, not KV storage.

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

## Advanced Deployment

For detailed deployment procedures, advanced configuration, and troubleshooting, see [DEPLOYMENT.md](./DEPLOYMENT.md).

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `pnpm test`
4. Submit a pull request

## License

MIT License - see LICENSE file for details.
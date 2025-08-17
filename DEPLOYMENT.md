# MCP OAuth Authorization Server - Deployment Guide

## Overview

This guide covers deploying the MCP OAuth Authorization Server to Cloudflare Workers with staging and production environments.

## Prerequisites

- [Cloudflare account](https://dash.cloudflare.com/) with Workers access
- [Wrangler CLI](https://developers.cloudflare.com/workers/cli-wrangler/) installed and authenticated
- GitHub OAuth app created
- OpenSSL for generating JWT keys

## Environment Setup

### 1. Generate JWT Signing Keys

```bash
# Generate RSA private key (2048-bit for JWT RS256)
openssl genrsa -out jwt-private.pem 2048

# Extract public key
openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem

# Generate refresh token encryption key (AES-256)
openssl rand -base64 32
```

### 2. Create GitHub OAuth App

1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Click "New OAuth App"
3. Fill in details:
   - **Application name**: `MCP OAuth Server (Staging)` / `MCP OAuth Server (Production)`
   - **Homepage URL**: Your organization's URL
   - **Authorization callback URL**: 
     - Staging: `https://mcp-oauth-authorization-server-staging.wmdurand.workers.dev/auth/github/callback`
     - Production: `https://auth.mcp.r167.dev/auth/github/callback`
4. Save Client ID and Client Secret

## Deployment Environments

### Staging Deployment

#### 1. Set Staging Secrets

Use the automated script:
```bash
./scripts/setup-secrets.sh staging
```

Or set manually:
```bash
# GitHub OAuth credentials
wrangler secret put GITHUB_CLIENT_ID --env staging
wrangler secret put GITHUB_CLIENT_SECRET --env staging

# JWT signing keys (paste the full PEM content including headers)
wrangler secret put JWT_PRIVATE_KEY --env staging
wrangler secret put JWT_PUBLIC_KEY --env staging

# Refresh token encryption key
wrangler secret put REFRESH_ENCRYPTION_KEY --env staging

# Note: WORKER_BASE_URL is now set as environment variable in wrangler.jsonc
```

#### 2. Deploy to Staging

```bash
pnpm run deploy:staging
```

#### 3. Configure MCP Servers

Update `src/config.staging.json` with your staging MCP servers:

```json
{
  "servers": {
    "your-staging-domain.com": {
      "your-mcp-server": {
        "name": "Your MCP Server (Staging)",
        "description": "Description of your MCP server",
        "allowed_users": ["your-github-username"]
      }
    }
  }
}
```

### Production Deployment

#### 1. Set Production Secrets

Use the automated script:
```bash
./scripts/setup-secrets.sh prod
```

Or set manually:
```bash
# Use different GitHub OAuth app for production
wrangler secret put GITHUB_CLIENT_ID
wrangler secret put GITHUB_CLIENT_SECRET

# Use same or different JWT keys (recommended: different for security)
wrangler secret put JWT_PRIVATE_KEY
wrangler secret put JWT_PUBLIC_KEY

# Use different encryption key for production
wrangler secret put REFRESH_ENCRYPTION_KEY

# Note: WORKER_BASE_URL is now set as environment variable in wrangler.jsonc
```

#### 2. Deploy to Production

```bash
pnpm run deploy:prod
```

## Database Setup

### Automatic Table Creation

The server automatically creates all required D1 tables on first startup:

- `authorization_codes` - OAuth authorization codes (10 min expiration)
- `refresh_tokens` - Refresh token metadata (30 day expiration)
- `user_sessions` - User authentication sessions (30 min expiration)
- `client_approvals` - Stored user consent decisions (30 day expiration)
- `revoked_tokens` - Revoked refresh tokens (tracked until expiration)

### Manual Database Initialization (Optional)

If you need to manually create tables or run migrations:

```bash
# For staging
wrangler d1 execute mcp-oauth-db-staging --env staging --file schema.sql

# For production
wrangler d1 execute mcp-oauth-db-prod --file schema.sql
```

## Configuration

### MCP Server Configuration

Update `src/config.json` (production) and `src/config.staging.json` (staging) with your MCP servers:

```json
{
  "servers": {
    "your-domain.com": {
      "server-name": {
        "name": "Human-readable server name",
        "description": "Description of what this server provides",
        "allowed_users": ["github-username1", "github-username2"]
      }
    }
  }
}
```

### Configuration

#### Cloudflare Secrets

All environments require these secrets:

| Variable | Description | Example |
|----------|-------------|---------|
| `GITHUB_CLIENT_ID` | GitHub OAuth app client ID | `Iv1.a1b2c3d4e5f6g7h8` |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth app client secret | `1234567890abcdef...` |
| `JWT_PRIVATE_KEY` | RS256 private key for JWT signing | `-----BEGIN PRIVATE KEY-----\n...` |
| `JWT_PUBLIC_KEY` | RS256 public key for JWT verification | `-----BEGIN PUBLIC KEY-----\n...` |
| `REFRESH_ENCRYPTION_KEY` | AES-256 key for refresh token encryption | `base64-encoded-key` |

#### Environment Variables

| Variable | Description | Set in | Example |
|----------|-------------|--------|--------|
| `WORKER_BASE_URL` | Full URL of the deployed worker | `wrangler.jsonc` (`vars`) + `.dev.vars` (dev) | `https://auth.mcp.r167.dev` |

## Verification

### 1. Health Check

```bash
curl https://auth.mcp.r167.dev/health
```

Expected response:
```json
{
  "status": "ok",
  "timestamp": "2025-08-17T..."
}
```

### 2. OAuth Discovery

```bash
curl https://auth.mcp.r167.dev/.well-known/oauth-authorization-server
```

Should return OAuth server metadata with correct URLs.

### 3. JWKS Endpoint

```bash
curl https://auth.mcp.r167.dev/.well-known/jwks.json
```

Should return the public key in JWK format.

## Monitoring & Maintenance

### Logs

View deployment logs:
```bash
wrangler tail --env staging  # for staging
wrangler tail               # for production
```

### Database Queries

Query the database directly:
```bash
wrangler d1 execute mcp-oauth-db-staging --env staging --command "SELECT COUNT(*) FROM authorization_codes"
```

### Secret Rotation

Rotate secrets periodically:
```bash
# Generate new encryption key
NEW_KEY=$(openssl rand -base64 32)
echo $NEW_KEY | wrangler secret put REFRESH_ENCRYPTION_KEY --env staging

# Update JWT keys (requires coordination with resource servers)
wrangler secret put JWT_PRIVATE_KEY --env staging
wrangler secret put JWT_PUBLIC_KEY --env staging
```

## Security Considerations

1. **Separate Environments**: Use different GitHub OAuth apps for staging and production
2. **Key Rotation**: Rotate encryption keys and JWT keys periodically
3. **Access Control**: Limit GitHub usernames in MCP server configurations
4. **Monitoring**: Set up alerts for failed authentications and errors
5. **HTTPS Only**: Ensure all redirect URIs use HTTPS in production

## Troubleshooting

### Common Issues

1. **Invalid redirect_uri**: Ensure GitHub OAuth app callback URL exactly matches deployed URL
2. **JWT verification fails**: Check that JWT_PUBLIC_KEY is correctly formatted with line breaks
3. **Database errors**: Verify D1 database IDs in wrangler.jsonc match created databases
4. **CORS errors**: Ensure WORKER_BASE_URL matches the actual deployed URL

### Debug Commands

```bash
# Check deployment status
wrangler deployments list --env staging

# View environment variables (secrets are hidden)
wrangler secret list --env staging

# Test database connection
wrangler d1 execute mcp-oauth-db-staging --env staging --command "SELECT 1"
```

## Rollback

To rollback a deployment:

```bash
# List previous deployments
wrangler deployments list --env staging

# Rollback to previous version
wrangler rollback --env staging
```
# Quick Staging Setup Guide

## 🚀 Ready to Deploy Staging

Your staging environment is configured and ready! Here's what's been set up:

### ✅ Already Configured
- **Staging D1 Database**: `mcp-oauth-db-staging` (ID: `471fa3ec-770b-4bbf-87fb-4f565e3f3c1b`)
- **Worker Name**: `mcp-oauth-authorization-server-staging`
- **Staging URL**: `https://mcp-oauth-authorization-server-staging.wmdurand.workers.dev`
- **Deployment Commands**: `pnpm run deploy:staging`

### 🔑 Next Steps: Set Your Secrets

You need to provide your own GitHub OAuth app credentials and JWT keys for security.

#### Option 1: Use Setup Script (Recommended)
```bash
./scripts/setup-secrets.sh staging
```

#### Option 2: Manual Setup
```bash
# 1. Generate JWT keys
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
openssl rand -base64 32  # for refresh token encryption

# 2. Set secrets (will prompt for values)
wrangler secret put GITHUB_CLIENT_ID --env staging
wrangler secret put GITHUB_CLIENT_SECRET --env staging
wrangler secret put JWT_PRIVATE_KEY --env staging
wrangler secret put JWT_PUBLIC_KEY --env staging
wrangler secret put REFRESH_ENCRYPTION_KEY --env staging
wrangler secret put WORKER_BASE_URL --env staging
```

### 📱 GitHub OAuth App Setup

Create a GitHub OAuth app with:
- **Callback URL**: `https://mcp-oauth-authorization-server-staging.wmdurand.workers.dev/auth/github/callback`
- **Homepage URL**: Your choice
- **Application name**: `MCP OAuth Server (Staging)`

### 🔧 Configure MCP Servers

Edit `src/config.staging.json` to add your MCP servers and authorized GitHub usernames.

### 🚀 Deploy

```bash
pnpm run deploy:staging
```

### ✅ Test

```bash
curl https://mcp-oauth-authorization-server-staging.wmdurand.workers.dev/health
curl https://mcp-oauth-authorization-server-staging.wmdurand.workers.dev/.well-known/oauth-authorization-server
```

---

**Current Status**: Staging infrastructure is ready, waiting for your secrets and configuration.
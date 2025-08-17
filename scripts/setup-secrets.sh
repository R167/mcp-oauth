#!/bin/bash

# MCP OAuth Authorization Server - Secret Setup Script
# Usage: ./scripts/setup-secrets.sh [staging|prod]

set -e

ENVIRONMENT=${1:-staging}

if [ "$ENVIRONMENT" != "staging" ] && [ "$ENVIRONMENT" != "prod" ]; then
    echo "Usage: $0 [staging|prod]"
    exit 1
fi

echo "Setting up secrets for $ENVIRONMENT environment..."

# Check if environment flag should be used
if [ "$ENVIRONMENT" = "staging" ]; then
    ENV_FLAG="--env staging"
else
    ENV_FLAG=""
fi

echo "📝 Setting GitHub OAuth credentials..."
echo "Enter your GitHub OAuth Client ID:"
read -r GITHUB_CLIENT_ID
echo "$GITHUB_CLIENT_ID" | wrangler secret put GITHUB_CLIENT_ID $ENV_FLAG

echo "Enter your GitHub OAuth Client Secret:"
read -rs GITHUB_CLIENT_SECRET
echo "$GITHUB_CLIENT_SECRET" | wrangler secret put GITHUB_CLIENT_SECRET $ENV_FLAG

echo "🔑 Setting JWT keys..."
echo "Enter the JWT Private Key (including -----BEGIN/END PRIVATE KEY----- lines):"
echo "Paste the key, then press Ctrl+D when done:"
JWT_PRIVATE_KEY=$(cat)
echo "$JWT_PRIVATE_KEY" | wrangler secret put JWT_PRIVATE_KEY $ENV_FLAG

echo "Enter the JWT Public Key (including -----BEGIN/END PUBLIC KEY----- lines):"
echo "Paste the key, then press Ctrl+D when done:"
JWT_PUBLIC_KEY=$(cat)
echo "$JWT_PUBLIC_KEY" | wrangler secret put JWT_PUBLIC_KEY $ENV_FLAG

echo "🔐 Setting refresh token encryption key..."
echo "Enter the base64-encoded refresh token encryption key:"
read -r REFRESH_ENCRYPTION_KEY
echo "$REFRESH_ENCRYPTION_KEY" | wrangler secret put REFRESH_ENCRYPTION_KEY $ENV_FLAG

echo "🌐 Setting worker base URL..."
if [ "$ENVIRONMENT" = "staging" ]; then
    DEFAULT_URL="https://mcp-oauth-authorization-server-staging.your-subdomain.workers.dev"
else
    DEFAULT_URL="https://mcp-oauth-authorization-server.your-subdomain.workers.dev"
fi

echo "Enter the worker base URL [$DEFAULT_URL]:"
read -r WORKER_BASE_URL
WORKER_BASE_URL=${WORKER_BASE_URL:-$DEFAULT_URL}
echo "$WORKER_BASE_URL" | wrangler secret put WORKER_BASE_URL $ENV_FLAG

echo "✅ All secrets have been set for $ENVIRONMENT environment!"
echo ""
echo "Next steps:"
echo "1. Update src/config.json (or src/config.staging.json) with your MCP servers"
echo "2. Set up your GitHub OAuth app with callback URL: $WORKER_BASE_URL/auth/github/callback"
echo "3. Deploy: pnpm run deploy:$ENVIRONMENT"
echo "4. Test: curl $WORKER_BASE_URL/health"
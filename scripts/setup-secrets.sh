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
echo "Would you like to generate new JWT keys automatically? (y/n) [y]:"
read -r GENERATE_KEYS
GENERATE_KEYS=${GENERATE_KEYS:-y}

if [ "$GENERATE_KEYS" = "y" ] || [ "$GENERATE_KEYS" = "Y" ]; then
    echo "Generating RSA key pair..."
    
    # Create temporary files
    TEMP_PRIVATE=$(mktemp)
    TEMP_PUBLIC=$(mktemp)
    
    # Generate RSA private key
    openssl genrsa -out "$TEMP_PRIVATE" 2048
    
    # Extract public key
    openssl rsa -in "$TEMP_PRIVATE" -pubout -out "$TEMP_PUBLIC"
    
    # Read the keys
    JWT_PRIVATE_KEY=$(cat "$TEMP_PRIVATE")
    JWT_PUBLIC_KEY=$(cat "$TEMP_PUBLIC")
    
    # Clean up temp files
    rm "$TEMP_PRIVATE" "$TEMP_PUBLIC"
    
    echo "✅ Generated new RSA key pair"
else
    echo "Enter the JWT Private Key (including -----BEGIN/END PRIVATE KEY----- lines):"
    echo "Paste the key, then press Ctrl+D when done:"
    JWT_PRIVATE_KEY=$(cat)
    
    echo "Enter the JWT Public Key (including -----BEGIN/END PUBLIC KEY----- lines):"
    echo "Paste the key, then press Ctrl+D when done:"
    JWT_PUBLIC_KEY=$(cat)
fi

echo "$JWT_PRIVATE_KEY" | wrangler secret put JWT_PRIVATE_KEY $ENV_FLAG
echo "$JWT_PUBLIC_KEY" | wrangler secret put JWT_PUBLIC_KEY $ENV_FLAG

echo "🔐 Setting refresh token encryption key..."
echo "Would you like to generate a new encryption key automatically? (y/n) [y]:"
read -r GENERATE_ENCRYPTION_KEY
GENERATE_ENCRYPTION_KEY=${GENERATE_ENCRYPTION_KEY:-y}

if [ "$GENERATE_ENCRYPTION_KEY" = "y" ] || [ "$GENERATE_ENCRYPTION_KEY" = "Y" ]; then
    REFRESH_ENCRYPTION_KEY=$(openssl rand -base64 32)
    echo "✅ Generated new encryption key: $REFRESH_ENCRYPTION_KEY"
else
    echo "Enter the base64-encoded refresh token encryption key:"
    read -r REFRESH_ENCRYPTION_KEY
fi

echo "$REFRESH_ENCRYPTION_KEY" | wrangler secret put REFRESH_ENCRYPTION_KEY $ENV_FLAG

echo "ℹ️  WORKER_BASE_URL is configured as environment variable:"
echo "   Development: http://localhost:8787 (in .dev.vars)"
echo "   Staging: https://mcp-oauth-authorization-server-staging.wmdurand.workers.dev (in wrangler.jsonc)"
echo "   Production: https://auth.mcp.r167.dev (in wrangler.jsonc)"

if [ "$ENVIRONMENT" = "staging" ]; then
    WORKER_BASE_URL="https://mcp-oauth-authorization-server-staging.wmdurand.workers.dev"
else
    WORKER_BASE_URL="https://auth.mcp.r167.dev"
fi

echo "✅ All secrets have been set for $ENVIRONMENT environment!"
echo ""
echo "Next steps:"
echo "1. Update src/config.json (or src/config.staging.json) with your MCP servers"
echo "2. Set up your GitHub OAuth app with callback URL: $WORKER_BASE_URL/auth/github/callback"
echo "3. Deploy: pnpm run deploy:$ENVIRONMENT"
echo "4. Test: curl $WORKER_BASE_URL/health"
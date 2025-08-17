# MCP OAuth Client Examples

This directory contains complete OAuth client implementations for integrating with the MCP OAuth Authorization Server in different programming languages.

## Available Examples

### [Go](./go/)
- **File**: `client.go`
- **Dependencies**: `golang-jwt/jwt`, `lestrrat-go/jwx`
- **Features**: Complete OAuth client, PKCE generation, JWT validation, token management
- **Usage**: Drop into any Go MCP project

### [Ruby](./ruby/)
- **File**: `client.rb`
- **Dependencies**: `jwt` gem
- **Features**: OAuth client, token manager, resource server validation, HTTP client wrapper
- **Usage**: Can be used as a gem or standalone script

### [TypeScript/Node.js](./typescript/)
- **File**: `client.ts`
- **Dependencies**: `jose` library
- **Features**: Modern async/await API, Express.js middleware, file/memory storage, complete type definitions
- **Usage**: Import as ES modules or CommonJS

## Quick Start

Each example includes:

1. **OAuth Client**: Handle authorization flow with PKCE
2. **Token Management**: Automatic refresh and storage
3. **Resource Server**: JWT validation for protecting APIs
4. **HTTP Client**: Ready-to-use authenticated API clients

## Integration Steps

1. **Choose your language** and copy the appropriate example
2. **Install dependencies** using the provided package files
3. **Configure your client** with:
   - Client ID (from auth server configuration)
   - Base URL (`https://auth.mcp.r167.dev` for production)
   - Redirect URI (must match your domain)
   - MCP scope (`mcp:<your-domain>:<your-server>`)
4. **Implement OAuth flow** using the provided examples
5. **Protect your APIs** using the token validation examples

## Common Configuration

All examples use these OAuth server endpoints:

- **Production**: `https://auth.mcp.r167.dev`
- **Staging**: `https://mcp-oauth-authorization-server-staging.wmdurand.workers.dev`

### Required Environment Setup

1. **Register your MCP server** in the auth server configuration
2. **Create GitHub OAuth app** with callback URL matching your domain
3. **Configure MCP scope** following pattern: `mcp:<domain>:<server>`
4. **Ensure user permissions** - users must be in the `allowed_users` list

## Security Notes

- Always use HTTPS in production
- Implement proper CSRF protection with `state` parameter
- Store tokens securely (not in localStorage for web apps)
- Validate JWT audience matches your expected MCP scope
- Handle token expiration with automatic refresh

## Support

For detailed integration guide, see [CLIENTS.md](./CLIENTS.md).

For auth server issues, check the main repository documentation.
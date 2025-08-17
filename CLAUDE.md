# Claude Code Instructions for MCP OAuth Worker

This document provides specific guidance for Claude Code when working on this MCP OAuth Authorization Server project.

## Project Overview

This is a production-ready OAuth 2.1/OIDC authorization server built on Cloudflare Workers for securing Model Context Protocol (MCP) resources. The server implements 2-hop authentication via GitHub with comprehensive security features. It could be extended to support other Identity providers in the future.

## Architecture

@./Architecture.md

For understanding MCP flow, download https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization.md

## Architecture Understanding

### Core Components

- **AuthorizeHandler**: OAuth authorization flow, GitHub integration, consent screen
- **TokenHandler**: Token exchange, PKCE verification, refresh token grants
- **MetadataHandler**: OAuth/OIDC discovery endpoints, JWKS
- **ScopeValidator**: MCP scope validation and ACL enforcement
- **JWTManager**: JWT creation/validation with encryption integration
- **EncryptionManager**: AES-GCM encryption with key rotation
- **StorageManager**: Cloudflare KV storage with TTL management
- **GitHubClient**: GitHub OAuth API integration

### Key Design Patterns

- **Stateless validation**: Resource servers validate tokens without calling auth server
- **Encrypted refresh tokens**: AES-GCM encryption with versioned keys
- **Scope binding**: Tokens bound to specific `mcp:<domain>:<server>` scopes
- **PKCE enforcement**: All authorization flows require PKCE for security

## Testing Guidelines

### Running Tests

Always run tests before making changes:

```bash
npm test
```

### Test Structure

- Unit tests for all utility classes
- Integration tests for OAuth flows
- Security-focused test scenarios
- Mock utilities in `src/tests/test-utils.ts`

### Writing New Tests

When adding features:

1. Create unit tests for new utility functions
2. Add integration tests for new endpoints
3. Include security/error scenarios
4. Use existing mock patterns from `test-utils.ts`

## Code Style & Standards

### TypeScript

- Strict mode enabled
- Interfaces for all data structures
- Proper error handling with custom error classes
- Use `async/await` for asynchronous operations

### Security Requirements

- Never log sensitive data (tokens, keys, user info)
- Validate all inputs before processing
- Use constant-time comparisons for secrets
- Implement proper error handling without information leakage

### Environment Variables

All configuration via environment variables:

- `GITHUB_CLIENT_ID/SECRET` - GitHub OAuth app
- `JWT_PRIVATE_KEY/PUBLIC_KEY` - RS256 key pair
- `REFRESH_ENCRYPTION_KEY` - AES encryption key
- `WORKER_BASE_URL` - Authorization server base URL

## Common Tasks

### Adding New MCP Servers

1. Update `src/config.json` with new server configuration
2. Add allowed users list
3. Test scope validation with new domain/server combination

### Implementing New Endpoints

1. Create handler in `src/handlers/`
2. Add route in `src/index.ts`
3. Write comprehensive tests
4. Update architecture documentation

### Key Rotation

1. Generate new encryption key
2. Update environment variable
3. Use `EncryptionManager.rotateKey()` for gradual transition
4. Clean up old keys after transition period

### Debugging OAuth Flows

1. Check browser network tab for redirect chains
2. Verify PKCE challenge/verifier pair generation
3. Validate JWT token structure and signatures
4. Review KV storage for session data

## Security Best Practices

### Token Handling

- Access tokens: 1-hour expiration, stateless validation
- Refresh tokens: 30-day expiration, encrypted, rotated on use
  - Note: to ease race conditions, allow a short grace period for additional token renewal
  - Make sure to track old refresh tokens for revocation
- Authorization codes: 10-minute expiration, single-use

### Scope Validation

- Enforce single MCP scope per request
- Validate domain matches redirect URI
- Check user authorization in ACL

### Error Handling

- Return standard OAuth error formats
- Don't leak sensitive information in error messages
- Log security-relevant events for monitoring

## Integration Patterns

### For MCP Clients

Clients should:

1. Generate PKCE challenge/verifier pair
2. Redirect to `/authorize` with proper parameters
3. Handle authorization code callback
4. Exchange code for tokens with PKCE verifier
5. Use access tokens in Authorization header
6. Refresh tokens before expiration

### For MCP Resource Servers

Resource servers should:

1. Fetch public keys from JWKS endpoint
2. Validate JWT signature and claims
3. Verify audience matches expected MCP scope
4. Extract user identity from token claims
5. Implement local authorization if needed

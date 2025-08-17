# MCP OAuth Authorization Server - Testing Documentation

## Development Testing Procedures

This document details how to test the MCP OAuth Authorization Server in development mode.

### Prerequisites

1. **Node.js & pnpm**: Ensure you have Node.js and pnpm installed
2. **Wrangler CLI**: Cloudflare Workers CLI for local development
3. **OpenSSL**: For generating JWT signing keys

### Setup for Testing

1. **Generate JWT Keys** (done once):
   ```bash
   # Generate RSA private key for JWT signing
   openssl genrsa -out private.pem 2048
   
   # Extract public key from private key
   openssl rsa -in private.pem -pubout -out public.pem
   
   # Generate encryption key for refresh tokens
   openssl rand -base64 32
   ```

2. **Configure Environment Variables**:
   The `.dev.vars` file contains all necessary environment variables for local testing:
   - `WORKER_BASE_URL`: Set to `http://localhost:8787`
   - `JWT_PRIVATE_KEY` & `JWT_PUBLIC_KEY`: Generated RSA key pair
   - `REFRESH_ENCRYPTION_KEY`: Base64 encoded AES key

3. **Start Development Server**:
   ```bash
   pnpm run dev
   ```
   Server runs on `http://localhost:8787`

### Test Scenarios Performed

#### 1. Core Server Functionality
- ✅ **Root Endpoint**: `GET /` returns server information
- ✅ **Health Check**: `GET /health` returns server status
- ✅ **Database Initialization**: D1 tables created automatically

#### 2. OAuth Discovery & Metadata
- ✅ **OAuth Metadata**: `GET /.well-known/oauth-authorization-server`
- ✅ **OIDC Discovery**: `GET /.well-known/openid_configuration`  
- ✅ **JWKS Endpoint**: `GET /.well-known/jwks.json`

#### 3. Authorization Flow
- ✅ **Valid Authorization Request**: Redirects to GitHub OAuth (302)
- ✅ **Invalid Authorization Request**: Returns proper OAuth error

#### 4. Token Endpoint
- ✅ **Invalid Grant Type**: Returns standard OAuth error
- ✅ **Missing Parameters**: Validates required fields

#### 5. Error Handling
- ✅ **Invalid Endpoints**: Return appropriate HTTP status codes
- ✅ **Malformed Requests**: Return standard OAuth error responses
- ✅ **Database Errors**: Graceful error handling

### Specific Test Commands

```bash
# Test root endpoint
curl -s http://localhost:8787/ | jq

# Test health check
curl -s http://localhost:8787/health | jq

# Test OAuth metadata (should show proper URLs)
curl -s "http://localhost:8787/.well-known/oauth-authorization-server" | jq '.authorization_endpoint, .token_endpoint'

# Test JWKS endpoint (should return RSA public key)
curl -s "http://localhost:8787/.well-known/jwks.json" | jq '.keys[0].kty'

# Test authorization endpoint with valid params (should redirect to GitHub)
curl -I "http://localhost:8787/authorize?response_type=code&client_id=test&redirect_uri=https://example.com/callback&scope=mcp:example.com:github-tools&code_challenge=test&code_challenge_method=S256"

# Test authorization endpoint with invalid params (should return error)
curl -s "http://localhost:8787/authorize?invalid=params" | jq

# Test token endpoint with invalid grant type
curl -s -X POST "http://localhost:8787/token" -d "grant_type=invalid" | jq
```

### Expected Results

#### Successful Responses
- **Root**: Server info with all endpoint URLs
- **Health**: `{"status": "ok", "timestamp": "..."}`
- **OAuth Metadata**: All URLs show `http://localhost:8787` prefix
- **JWKS**: RSA public key in JWK format with proper algorithms
- **Authorization**: 302 redirect to GitHub OAuth

#### Error Responses
- **Invalid Requests**: Standard OAuth error format:
  ```json
  {
    "error": "invalid_request",
    "error_description": "Description of the error"
  }
  ```

### Database Testing

The server automatically creates the following D1 tables on startup:
- `authorization_codes` - Temporary auth codes (10 min TTL)
- `refresh_tokens` - Refresh token metadata (30 day TTL)
- `user_sessions` - User authentication sessions (30 min TTL)
- `client_approvals` - Stored consent decisions (30 day TTL)
- `revoked_tokens` - Revoked refresh tokens

### Limitations in Development Mode

1. **GitHub OAuth Integration**: Requires GitHub app setup and secrets
2. **Full OAuth Flow**: Cannot complete without GitHub client credentials
3. **Token Generation**: JWT creation works but tokens can't be used without GitHub auth
4. **MCP Scope Validation**: Server validation works but user lookup requires GitHub

### Next Steps for Production Testing

1. **Set GitHub OAuth Credentials**:
   ```bash
   wrangler secret put GITHUB_CLIENT_ID
   wrangler secret put GITHUB_CLIENT_SECRET
   ```

2. **Configure MCP Servers**: Update `src/config.json` with real server configurations

3. **Deploy to Cloudflare Workers**: `pnpm run deploy`

4. **Test Complete OAuth Flow**: With real GitHub app and MCP client

### Testing Results Summary

✅ **All core functionality works in development mode**
✅ **Database operations execute successfully**
✅ **OAuth endpoints respond with correct formats**
✅ **JWT key management functions properly**
✅ **Error handling follows OAuth 2.1 standards**
✅ **Server runs without errors or warnings**

The implementation is ready for production deployment with proper environment configuration.
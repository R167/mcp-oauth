# MCP OAuth Authorization Server - Architecture Documentation

## Overview

The MCP OAuth Authorization Server is a comprehensive **OAuth 2.1/OIDC-compliant authorization server** built on Cloudflare Workers, specifically designed for securing Model Context Protocol (MCP) resources. It implements a 2-hop authentication architecture using GitHub as the identity provider while enforcing fine-grained access controls for MCP servers.

## High-Level Architecture

```mermaid
sequenceDiagram
    participant Client as MCP Client
    participant AuthServer as OAuth Server
    participant GitHub as GitHub OAuth
    participant ResourceServer as MCP Resource Server
    participant User as End User

    Client->>AuthServer: 1. Authorization Request (PKCE)
    AuthServer->>AuthServer: 2. Validate scopes & domain
    AuthServer->>GitHub: 3. Redirect to GitHub OAuth
    GitHub->>User: 4. GitHub authentication
    User->>GitHub: 5. User credentials
    GitHub->>AuthServer: 6. Authorization code
    AuthServer->>GitHub: 7. Exchange code for GitHub token
    GitHub->>AuthServer: 8. GitHub access token
    AuthServer->>AuthServer: 9. Fetch user profile & validate ACL
    AuthServer->>User: 10. Show consent screen
    User->>AuthServer: 11. Grant/deny consent
    AuthServer->>Client: 12. Authorization code (if approved)
    Client->>AuthServer: 13. Token request (PKCE verification)
    AuthServer->>Client: 14. Access & refresh tokens
    Client->>ResourceServer: 15. API request with access token
    ResourceServer->>AuthServer: 16. Validate token (JWKS)
    ResourceServer->>Client: 17. API response
```

## Core Components

### 1. Authentication & Authorization Flow

```mermaid
flowchart TD
    A[Client Request] --> B{Valid Scope Format?}
    B -->|No| C[Error Response]
    B -->|Yes| D{Domain Matches Redirect?}
    D -->|No| C
    D -->|Yes| E[GitHub OAuth Redirect]
    E --> F[GitHub Authentication]
    F --> G[Fetch User Profile]
    G --> H{User in ACL?}
    H -->|No| I[Access Denied]
    H -->|Yes| J[Show Consent Screen]
    J --> K{User Consent?}
    K -->|No| I
    K -->|Yes| L[Generate Authorization Code]
    L --> M[Token Exchange]
    M --> N[Issue JWT Tokens]
```

### 2. Token Architecture

```mermaid
graph TB
    subgraph "Access Token (JWT)"
        AT[Header: RS256<br/>Payload: iss, sub, aud, exp, email<br/>Signature: Private Key]
    end

    subgraph "Refresh Token (Encrypted)"
        RT[JWT Token] --> ENC[AES-GCM Encryption]
        ENC --> B64[Base64 Encoding]
        B64 --> PREFIX[mcp_refresh__ prefix]
    end

    subgraph "Storage Layer"
        D1[Cloudflare D1 Database]
        D1 --> AUTH_CODE[authorization_codes table<br/>expires_at: SQL expiration]
        D1 --> REFRESH_META[refresh_tokens table<br/>expires_at: SQL expiration]
        D1 --> SESSIONS[user_sessions table<br/>expires_at: SQL expiration]
        D1 --> APPROVALS[client_approvals table<br/>expires_at: SQL expiration]
        D1 --> REVOKED[revoked_tokens table<br/>expires_at: SQL expiration]
    end
```

### 3. Security Architecture

```mermaid
graph LR
    subgraph "Encryption Layers"
        A[Refresh Tokens] --> B[AES-GCM Encryption]
        B --> C[Key Versioning]
        C --> D[Key Rotation Support]
    end

    subgraph "JWT Security"
        E[Access Tokens] --> F[RS256 Signing]
        F --> G[Public Key Validation]
        G --> H[Audience Binding]
    end

    subgraph "PKCE Security"
        I[Code Challenge] --> J[SHA256 Hash]
        J --> K[Code Verifier]
        K --> L[Secure Exchange]
    end
```

### API Endpoints

#### OAuth 2.1 Endpoints

- `GET /authorize` - Authorization endpoint with PKCE
- `POST /authorize` - Consent form submission
- `POST /token` - Token endpoint (authorization_code, refresh_token grants)

#### Discovery & Metadata

- `GET /.well-known/oauth-authorization-server` - OAuth server metadata (RFC 8414)
- `GET /.well-known/openid_configuration` - OIDC discovery
- `GET /.well-known/jwks.json` - JSON Web Key Set

#### GitHub Integration

- `GET /auth/github/callback` - GitHub OAuth callback handler

#### Administration

- `GET /health` - Health check endpoint
- `POST /admin/revoke` - Token revocation endpoint
- `GET /` - Server information endpoint

### Token Specifications

NOTE: these are ideas on implementation and the ideal solution may differ

#### Access Token Structure

```typescript
interface AccessToken {
	token_type: "access";
	iss: string; // Issuer (authorization server URL)
	exp: number; // Expiration (1 hour from issuance)
	sub: string; // Subject (GitHub user ID)
	aud: string; // Audience (MCP scope)
	email?: string; // User email (if user:email scope requested)
}
```

#### Refresh Token Structure

```typescript
interface RefreshToken {
	token_type: "refresh";
	iss: string; // Issuer (authorization server URL)
	exp: number; // Expiration (30 days from issuance)
	sub: string; // Subject (GitHub user ID)
	aud: string; // Audience (MCP scope)
	email?: string; // User email (if user:email scope requested)
}
```

### Scope Validation Rules

1. **Format Validation**: `mcp:<domain>:<server>` pattern
2. **Single Scope**: Only one MCP scope allowed per request
3. **Domain Matching**: MCP scope domain must match redirect URI domain
4. **Server Configuration**: MCP server must exist in ACL config
5. **User Authorization**: User must be in server's allowed_users list
6. **Additional Scopes**: Optional `email` scope supported

### Security Features

#### Encryption

- **Refresh Tokens**: AES-GCM encrypted with dedicated key
- **Key Rotation**: Versioned keys with graceful rotation
- **Key Derivation**: SHA-256 hash of environment key material

#### Token Security

- **JWT Signing**: RS256 algorithm with configurable key pairs
- **Token Prefixes**: Clear identification of token types
- **Audience Binding**: Tokens bound to specific MCP scopes
- **Short Expiration**: 1-hour access tokens, 30-day refresh tokens

#### PKCE Implementation

- **S256 Method**: SHA-256 code challenge method
- **Secure Verification**: Code verifier validation on token exchange
- **Replay Protection**: Authorization codes single-use with TTL

## Deployment Architecture

### Cloudflare Workers Environment

```mermaid
graph TB
    subgraph "Cloudflare Edge"
        Worker[OAuth Worker]
        D1[D1 Database]
    end

    subgraph "External Services"
        GitHub[GitHub OAuth]
        Client[MCP Client App]
        Resource[MCP Resource Server]
    end

    Worker <--> D1
    Worker <--> GitHub
    Client <--> Worker
    Resource --> Worker
```

## Standards Compliance

### OAuth 2.1 (RFC 6749bis)

- Authorization Code flow with PKCE (RFC 7636)
- Refresh token rotation
- Token endpoint authentication methods
- Error response formats

### OpenID Connect

- Discovery endpoint (RFC 8414)
- JWKS endpoint for public keys
- Standardized claim names

### Security Standards

- RFC 7636: PKCE for OAuth Public Clients
- RFC 8414: OAuth 2.0 Authorization Server Metadata
- RFC 9728: OAuth 2.0 Protected Resource Metadata

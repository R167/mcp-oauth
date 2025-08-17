import crypto from 'crypto';
import { createRemoteJWKSet, jwtVerify, JWTPayload } from 'jose';

/**
 * MCP OAuth Client for TypeScript/Node.js
 * Handles OAuth 2.1 flow with PKCE for MCP resources
 */

export interface PKCEChallenge {
  codeVerifier: string;
  codeChallenge: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface MCPClaims extends JWTPayload {
  token_type: 'access';
  sub: string; // GitHub user ID
  aud: string; // MCP scope
  email?: string; // User email (optional)
}

export interface ValidatedToken {
  userId: string;
  scope: string;
  email?: string;
  expiresAt: Date;
}

export interface ClientRegistrationRequest {
  client_name: string;
  redirect_uris: string[];
  scope: string;
}

export interface ClientRegistrationResponse {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  scope: string;
  expires_at: number;
  registration_client_uri: string;
}

export class MCPOAuthClient {
  constructor(
    private readonly clientId: string,
    private readonly baseUrl: string,
    private readonly redirectUri: string,
    private readonly scope: string,
    private readonly httpTimeout: number = 30000
  ) {}

  /**
   * Register client with OAuth server (dynamic client registration)
   */
  static async registerClient(
    baseUrl: string,
    clientName: string,
    redirectUris: string[],
    scope: string
  ): Promise<ClientRegistrationResponse> {
    const registrationData: ClientRegistrationRequest = {
      client_name: clientName,
      redirect_uris: redirectUris,
      scope: scope,
    };

    const response = await fetch(`${baseUrl}/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(registrationData),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Client registration failed: ${errorText}`);
    }

    return response.json() as Promise<ClientRegistrationResponse>;
  }

  /**
   * Generate PKCE challenge and verifier pair
   */
  generatePKCE(): PKCEChallenge {
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');

    return { codeVerifier, codeChallenge };
  }

  /**
   * Build OAuth authorization URL
   */
  getAuthorizationUrl(state: string, pkce: PKCEChallenge): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: this.scope,
      state,
      code_challenge: pkce.codeChallenge,
      code_challenge_method: 'S256',
    });

    return `${this.baseUrl}/authorize?${params.toString()}`;
  }

  /**
   * Exchange authorization code for tokens
   */
  async exchangeCodeForTokens(
    code: string,
    pkce: PKCEChallenge
  ): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.redirectUri,
      client_id: this.clientId,
      code_verifier: pkce.codeVerifier,
    });

    return this.makeTokenRequest(body);
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshTokens(refreshToken: string): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this.clientId,
    });

    return this.makeTokenRequest(body);
  }

  private async makeTokenRequest(body: URLSearchParams): Promise<TokenResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.httpTimeout);

    try {
      const response = await fetch(`${this.baseUrl}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Token request failed: ${response.status} ${errorText}`);
      }

      const data = await response.json();
      return data as TokenResponse;
    } finally {
      clearTimeout(timeout);
    }
  }
}

/**
 * JWT Token Validator for MCP Resource Servers
 */
export class MCPTokenValidator {
  private jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(
    private readonly jwksUrl: string,
    private readonly issuer: string,
    private readonly audience: string
  ) {
    this.jwks = createRemoteJWKSet(new URL(jwksUrl));
  }

  /**
   * Validate JWT access token
   */
  async validateToken(tokenString: string): Promise<ValidatedToken> {
    try {
      const { payload } = await jwtVerify<MCPClaims>(
        tokenString,
        this.jwks,
        {
          issuer: this.issuer,
          audience: this.audience,
        }
      );

      // Validate token type
      if (payload.token_type !== 'access') {
        throw new Error(
          `Invalid token type: expected 'access', got '${payload.token_type}'`
        );
      }

      return {
        userId: payload.sub,
        scope: payload.aud as string,
        email: payload.email,
        expiresAt: new Date((payload.exp as number) * 1000),
      };
    } catch (error) {
      throw new Error(`Token validation failed: ${error}`);
    }
  }
}

/**
 * Token storage interface
 */
export interface TokenStorage {
  saveTokens(tokens: StoredTokens): Promise<void>;
  loadTokens(): Promise<StoredTokens | null>;
  clearTokens(): Promise<void>;
}

export interface StoredTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
}

/**
 * Simple in-memory token storage (replace with persistent storage in production)
 */
export class MemoryTokenStorage implements TokenStorage {
  private tokens: StoredTokens | null = null;

  async saveTokens(tokens: StoredTokens): Promise<void> {
    this.tokens = tokens;
  }

  async loadTokens(): Promise<StoredTokens | null> {
    return this.tokens;
  }

  async clearTokens(): Promise<void> {
    this.tokens = null;
  }
}

/**
 * File-based token storage
 */
export class FileTokenStorage implements TokenStorage {
  constructor(private readonly filePath: string) {}

  async saveTokens(tokens: StoredTokens): Promise<void> {
    const { writeFile } = await import('fs/promises');
    const data = {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresAt: tokens.expiresAt.toISOString(),
    };
    await writeFile(this.filePath, JSON.stringify(data), 'utf8');
  }

  async loadTokens(): Promise<StoredTokens | null> {
    try {
      const { readFile } = await import('fs/promises');
      const data = JSON.parse(await readFile(this.filePath, 'utf8'));
      return {
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
        expiresAt: new Date(data.expiresAt),
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return null; // File doesn't exist
      }
      throw error;
    }
  }

  async clearTokens(): Promise<void> {
    try {
      const { unlink } = await import('fs/promises');
      await unlink(this.filePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw error;
      }
    }
  }
}

/**
 * Token Manager - handles token storage and automatic refresh
 */
export class MCPTokenManager {
  private readonly refreshThreshold = 5 * 60 * 1000; // 5 minutes in milliseconds

  constructor(
    private readonly oauthClient: MCPOAuthClient,
    private readonly storage: TokenStorage = new MemoryTokenStorage()
  ) {}

  /**
   * Get valid access token, refreshing if necessary
   */
  async getAccessToken(): Promise<string | null> {
    const tokens = await this.storage.loadTokens();
    if (!tokens) {
      return null;
    }

    // Check if token needs refresh
    if (this.tokenNeedsRefresh(tokens)) {
      try {
        await this.refreshAndStoreTokens(tokens.refreshToken);
        const newTokens = await this.storage.loadTokens();
        return newTokens?.accessToken || null;
      } catch (error) {
        // If refresh fails, clear tokens and return null
        await this.storage.clearTokens();
        throw error;
      }
    }

    return tokens.accessToken;
  }

  /**
   * Store initial tokens after OAuth flow
   */
  async storeTokens(tokens: TokenResponse): Promise<void> {
    const storedTokens: StoredTokens = {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: new Date(Date.now() + tokens.expires_in * 1000),
    };

    await this.storage.saveTokens(storedTokens);
  }

  /**
   * Clear stored tokens
   */
  async clearTokens(): Promise<void> {
    await this.storage.clearTokens();
  }

  private tokenNeedsRefresh(tokens: StoredTokens): boolean {
    const now = new Date();
    const refreshTime = new Date(tokens.expiresAt.getTime() - this.refreshThreshold);
    return now >= refreshTime;
  }

  private async refreshAndStoreTokens(refreshToken: string): Promise<void> {
    const newTokens = await this.oauthClient.refreshTokens(refreshToken);
    await this.storeTokens(newTokens);
  }
}

/**
 * HTTP client wrapper with automatic token management
 */
export class MCPAPIClient {
  private tokenManager: MCPTokenManager;

  constructor(
    oauthClient: MCPOAuthClient,
    private readonly apiBaseUrl: string,
    storage?: TokenStorage
  ) {
    this.tokenManager = new MCPTokenManager(oauthClient, storage);
  }

  /**
   * Store tokens after OAuth flow
   */
  async authenticateWithTokens(tokens: TokenResponse): Promise<void> {
    await this.tokenManager.storeTokens(tokens);
  }

  /**
   * Make authenticated GET request
   */
  async get<T = any>(path: string, headers: Record<string, string> = {}): Promise<T> {
    return this.makeRequest<T>('GET', path, undefined, headers);
  }

  /**
   * Make authenticated POST request
   */
  async post<T = any>(
    path: string,
    body?: any,
    headers: Record<string, string> = {}
  ): Promise<T> {
    return this.makeRequest<T>('POST', path, body, headers);
  }

  /**
   * Make authenticated PUT request
   */
  async put<T = any>(
    path: string,
    body?: any,
    headers: Record<string, string> = {}
  ): Promise<T> {
    return this.makeRequest<T>('PUT', path, body, headers);
  }

  /**
   * Make authenticated DELETE request
   */
  async delete<T = any>(path: string, headers: Record<string, string> = {}): Promise<T> {
    return this.makeRequest<T>('DELETE', path, undefined, headers);
  }

  private async makeRequest<T>(
    method: string,
    path: string,
    body?: any,
    headers: Record<string, string> = {}
  ): Promise<T> {
    const accessToken = await this.tokenManager.getAccessToken();
    if (!accessToken) {
      throw new Error('No valid access token available');
    }

    const url = `${this.apiBaseUrl}${path}`;
    const requestHeaders: Record<string, string> = {
      Authorization: `Bearer ${accessToken}`,
      ...headers,
    };

    if (body && !headers['Content-Type']) {
      requestHeaders['Content-Type'] = 'application/json';
    }

    const response = await fetch(url, {
      method,
      headers: requestHeaders,
      body: body ? JSON.stringify(body) : undefined,
    });

    if (response.status === 401) {
      // Clear tokens and re-throw
      await this.tokenManager.clearTokens();
      throw new Error(`Authentication failed: ${await response.text()}`);
    }

    if (!response.ok) {
      throw new Error(`API request failed: ${response.status} ${await response.text()}`);
    }

    return response.json() as Promise<T>;
  }
}

/**
 * Express.js middleware for token validation
 */
export function createMCPAuthMiddleware(validator: MCPTokenValidator) {
  return async (req: any, res: any, next: any) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or invalid Authorization header' });
      }

      const token = authHeader.substring(7);
      const claims = await validator.validateToken(token);

      // Add claims to request object
      req.mcpAuth = claims;
      next();
    } catch (error) {
      res.status(401).json({ error: `Invalid token: ${error}` });
    }
  };
}

// Example usage functions

/**
 * Example OAuth client usage
 */
export async function exampleOAuthClient(): Promise<void> {
  console.log('=== MCP OAuth Client Example ===');

  console.log('Step 1: Register OAuth Client');

  try {
    // Register client with the OAuth server
    const registration = await MCPOAuthClient.registerClient(
      'https://auth.mcp.r167.dev',
      'My TypeScript MCP Application',
      ['https://your-app.com/callback'],
      'mcp:your-app.com:github-tools email'
    );

    console.log('Client registered successfully!');
    console.log(`Client ID: ${registration.client_id}`);
    console.log(`Expires at: ${new Date(registration.expires_at * 1000)}`);
    console.log();

    console.log('Step 2: Initialize OAuth Flow');

    // Initialize OAuth client with the registered client ID
    const client = new MCPOAuthClient(
      registration.client_id,
      'https://auth.mcp.r167.dev',
      'https://your-app.com/callback',
      'mcp:your-app.com:github-tools email'
    );

    // Generate PKCE challenge
    const pkce = client.generatePKCE();
    console.log(`Generated PKCE challenge: ${pkce.codeChallenge}`);

    // Generate random state for CSRF protection
    const state = crypto.randomBytes(16).toString('base64url');

    // Get authorization URL
    const authUrl = client.getAuthorizationUrl(state, pkce);
    console.log('Visit this URL to authorize:');
    console.log(authUrl);
    console.log();

    // After user authorizes and returns with code...
    console.log('After authorization, exchange code for tokens:');
    console.log('const tokens = await client.exchangeCodeForTokens(authorizationCode, pkce);');
    console.log();

  } catch (error) {
    console.error('Client registration failed:', error.message);
    return;
  }

  // Example token refresh
  console.log('To refresh tokens:');
  console.log('const newTokens = await client.refreshTokens(refreshToken);');
  console.log();
}

/**
 * Example resource server usage
 */
export async function exampleResourceServer(): Promise<void> {
  console.log('=== MCP Resource Server Example ===');

  // Initialize token validator
  const validator = new MCPTokenValidator(
    'https://auth.mcp.r167.dev/.well-known/jwks.json',
    'https://auth.mcp.r167.dev',
    'mcp:your-app.com:github-tools'
  );

  console.log('Token validator initialized');
  console.log('Example Express.js route with authentication:');
  console.log();
  console.log(`
import express from 'express';

const app = express();

// Use MCP auth middleware
app.use('/api', createMCPAuthMiddleware(validator));

app.get('/api/resource', (req, res) => {
  const { userId, scope, email } = req.mcpAuth;
  console.log(\`Authenticated user: \${userId} (\${email}) with scope: \${scope}\`);
  
  res.json({
    message: 'Access granted',
    user_id: userId,
    email: email,
    scope: scope,
  });
});
  `);
}

/**
 * Example API client usage
 */
export async function exampleAPIClient(): Promise<void> {
  console.log('=== API Client Example ===');

  const oauthClient = new MCPOAuthClient(
    'your-client-id',
    'https://auth.mcp.r167.dev',
    'https://your-app.com/callback',
    'mcp:your-app.com:github-tools email'
  );

  // Use file-based token storage
  const storage = new FileTokenStorage('./tokens.json');
  const apiClient = new MCPAPIClient(oauthClient, 'https://api.your-app.com', storage);

  console.log('API client with automatic token management:');
  console.log();
  console.log(`
// After OAuth flow, store tokens
await apiClient.authenticateWithTokens(tokens);

// Make authenticated requests (tokens are managed automatically)
const data = await apiClient.get('/api/data');
const result = await apiClient.post('/api/action', { param: 'value' });
  `);
}

// Run examples if this file is executed directly
if (require.main === module) {
  console.log('MCP OAuth Client Examples for TypeScript');
  console.log('=========================================');
  console.log();

  Promise.all([
    exampleOAuthClient(),
    exampleResourceServer(),
    exampleAPIClient(),
  ]).catch(console.error);
}
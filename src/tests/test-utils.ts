import { Environment } from '../types';
import { vi } from 'vitest';

export function createMockEnvironment(overrides: Partial<Environment> = {}): Environment {
  return {
    GITHUB_CLIENT_ID: 'test_client_id',
    GITHUB_CLIENT_SECRET: 'test_client_secret',
    JWT_PRIVATE_KEY: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+1234567890ABCD
EFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH
IJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKL
MNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP
QRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRST
UVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWX
YZabcdefghijklmnopqrstuvwxyz
-----END PRIVATE KEY-----`,
    JWT_PUBLIC_KEY: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvtdU1234567890ABCDEFG
HIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJK
LMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNO
PQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRS
TUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVW
XYZabcdefghijklmnopqrstuvwxyz
-----END PUBLIC KEY-----`,
    REFRESH_ENCRYPTION_KEY: 'test_encryption_key_32_characters_',
    ACCESS_TOKEN_ENCRYPTION_KEY: 'test_access_key_32_characters___',
    WORKER_BASE_URL: 'https://test.example.com',
    AUTH_KV: createMockKV(),
    ...overrides
  };
}

export function createMockKV(): KVNamespace {
  const store = new Map<string, { value: string; expiration?: number }>();
  
  return {
    get: vi.fn(async (key: string) => {
      const item = store.get(key);
      if (!item) return null;
      if (item.expiration && Date.now() > item.expiration) {
        store.delete(key);
        return null;
      }
      return item.value;
    }),
    put: vi.fn(async (key: string, value: string, options?: { expirationTtl?: number }) => {
      const expiration = options?.expirationTtl ? Date.now() + (options.expirationTtl * 1000) : undefined;
      store.set(key, { value, expiration });
    }),
    delete: vi.fn(async (key: string) => {
      store.delete(key);
    }),
    list: vi.fn(async (options?: { prefix?: string }) => {
      const keys = Array.from(store.keys())
        .filter(key => !options?.prefix || key.startsWith(options.prefix))
        .map(name => ({ name }));
      return { keys };
    })
  } as any;
}

export function createMockRequest(options: {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  body?: string | FormData;
} = {}): Request {
  const {
    method = 'GET',
    url = 'https://test.example.com',
    headers = {},
    body
  } = options;

  const requestInit: RequestInit = {
    method,
    headers: new Headers(headers)
  };

  if (body) {
    if (typeof body === 'string') {
      requestInit.body = body;
    } else {
      requestInit.body = body;
    }
  }

  return new Request(url, requestInit);
}

export function createMockResponse(options: {
  status?: number;
  statusText?: string;
  headers?: Record<string, string>;
  body?: string;
} = {}): Response {
  const {
    status = 200,
    statusText = 'OK',
    headers = {},
    body = ''
  } = options;

  return new Response(body, {
    status,
    statusText,
    headers: new Headers(headers)
  });
}

export const MockFetch = {
  success: (data: any) => vi.fn().mockResolvedValue(
    createMockResponse({
      body: JSON.stringify(data),
      headers: { 'Content-Type': 'application/json' }
    })
  ),
  
  error: (status = 400, message = 'Bad Request') => vi.fn().mockResolvedValue(
    createMockResponse({ status, statusText: message })
  ),
  
  reject: (error: Error) => vi.fn().mockRejectedValue(error)
};

export function generateCodeChallenge(codeVerifier: string): string {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  
  // Note: In real tests, you'd use crypto.subtle.digest, but for mocking we'll simulate
  return btoa('mock-challenge-' + codeVerifier)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

export function generateCodeVerifier(length = 128): string {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return result;
}

export const TestFixtures = {
  validOAuthRequest: {
    response_type: 'code',
    client_id: 'test-client',
    redirect_uri: 'https://example.com/callback',
    scope: 'mcp:example.com:filesystem user:email',
    state: 'test-state',
    code_challenge: generateCodeChallenge('test-verifier'),
    code_challenge_method: 'S256'
  },
  
  validTokenRequest: {
    grant_type: 'authorization_code',
    code: 'test-auth-code',
    redirect_uri: 'https://example.com/callback',
    client_id: 'test-client',
    code_verifier: 'test-verifier'
  },
  
  githubUser: {
    id: 12345,
    login: 'alice',
    email: 'alice@example.com'
  },
  
  authorizationCode: {
    code: 'test-auth-code',
    client_id: 'test-client',
    redirect_uri: 'https://example.com/callback',
    scope: 'mcp:example.com:filesystem user:email',
    user_id: '12345',
    code_challenge: generateCodeChallenge('test-verifier'),
    code_challenge_method: 'S256',
    expires_at: Date.now() + 600000,
    email: 'alice@example.com'
  }
};
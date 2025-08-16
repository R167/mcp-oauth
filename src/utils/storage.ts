import { Environment, AuthorizationCode, KV_KEYS, TOKEN_CONSTANTS } from '../types';

export class StorageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StorageError';
  }
}

export class StorageManager {
  constructor(private env: Environment) {}

  async storeAuthorizationCode(code: AuthorizationCode): Promise<void> {
    try {
      const key = KV_KEYS.AUTH_CODE(code.code);
      const value = JSON.stringify(code);
      
      await this.env.AUTH_KV.put(key, value, {
        expirationTtl: TOKEN_CONSTANTS.AUTHORIZATION_CODE_LIFETIME
      });
    } catch (error) {
      throw new StorageError(`Failed to store authorization code: ${error}`);
    }
  }

  async getAuthorizationCode(code: string): Promise<AuthorizationCode | null> {
    try {
      const key = KV_KEYS.AUTH_CODE(code);
      const value = await this.env.AUTH_KV.get(key);
      
      if (!value) {
        return null;
      }

      const authCode = JSON.parse(value) as AuthorizationCode;
      
      if (authCode.expires_at < Date.now()) {
        await this.deleteAuthorizationCode(code);
        return null;
      }

      return authCode;
    } catch (error) {
      throw new StorageError(`Failed to get authorization code: ${error}`);
    }
  }

  async deleteAuthorizationCode(code: string): Promise<void> {
    try {
      const key = KV_KEYS.AUTH_CODE(code);
      await this.env.AUTH_KV.delete(key);
    } catch (error) {
      throw new StorageError(`Failed to delete authorization code: ${error}`);
    }
  }

  async storeRefreshToken(tokenId: string, userId: string, scope: string, email?: string): Promise<void> {
    try {
      const key = KV_KEYS.REFRESH_TOKEN(tokenId);
      const value = JSON.stringify({
        user_id: userId,
        scope,
        email,
        created_at: Date.now()
      });
      
      await this.env.AUTH_KV.put(key, value, {
        expirationTtl: TOKEN_CONSTANTS.REFRESH_TOKEN_LIFETIME
      });
    } catch (error) {
      throw new StorageError(`Failed to store refresh token: ${error}`);
    }
  }

  async getRefreshTokenData(tokenId: string): Promise<{
    user_id: string;
    scope: string;
    email?: string;
    created_at: number;
  } | null> {
    try {
      const key = KV_KEYS.REFRESH_TOKEN(tokenId);
      const value = await this.env.AUTH_KV.get(key);
      
      if (!value) {
        return null;
      }

      return JSON.parse(value);
    } catch (error) {
      throw new StorageError(`Failed to get refresh token data: ${error}`);
    }
  }

  async deleteRefreshToken(tokenId: string): Promise<void> {
    try {
      const key = KV_KEYS.REFRESH_TOKEN(tokenId);
      await this.env.AUTH_KV.delete(key);
    } catch (error) {
      throw new StorageError(`Failed to delete refresh token: ${error}`);
    }
  }

  async storeUserSession(sessionId: string, data: any): Promise<void> {
    try {
      const key = KV_KEYS.USER_SESSION(sessionId);
      const value = JSON.stringify({
        ...data,
        created_at: Date.now()
      });
      
      await this.env.AUTH_KV.put(key, value, {
        expirationTtl: 1800
      });
    } catch (error) {
      throw new StorageError(`Failed to store user session: ${error}`);
    }
  }

  async getUserSession(sessionId: string): Promise<any | null> {
    try {
      const key = KV_KEYS.USER_SESSION(sessionId);
      const value = await this.env.AUTH_KV.get(key);
      
      if (!value) {
        return null;
      }

      return JSON.parse(value);
    } catch (error) {
      throw new StorageError(`Failed to get user session: ${error}`);
    }
  }

  async deleteUserSession(sessionId: string): Promise<void> {
    try {
      const key = KV_KEYS.USER_SESSION(sessionId);
      await this.env.AUTH_KV.delete(key);
    } catch (error) {
      throw new StorageError(`Failed to delete user session: ${error}`);
    }
  }

  async listRefreshTokensForUser(userId: string): Promise<string[]> {
    try {
      const list = await this.env.AUTH_KV.list({ prefix: 'refresh_token:' });
      const userTokens: string[] = [];

      for (const key of list.keys) {
        const value = await this.env.AUTH_KV.get(key.name);
        if (value) {
          const data = JSON.parse(value);
          if (data.user_id === userId) {
            userTokens.push(key.name.replace('refresh_token:', ''));
          }
        }
      }

      return userTokens;
    } catch (error) {
      throw new StorageError(`Failed to list refresh tokens for user: ${error}`);
    }
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    try {
      const tokenIds = await this.listRefreshTokensForUser(userId);
      
      for (const tokenId of tokenIds) {
        await this.deleteRefreshToken(tokenId);
      }
    } catch (error) {
      throw new StorageError(`Failed to revoke all user tokens: ${error}`);
    }
  }

  generateSessionId(): string {
    return crypto.randomUUID();
  }

  generateAuthorizationCode(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}
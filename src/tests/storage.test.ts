import { describe, it, expect, beforeEach, vi } from 'vitest';
import { StorageManager, StorageError } from '../utils/storage';
import { createMockEnvironment, createMockKV, TestFixtures } from './test-utils';
import { Environment, AuthorizationCode, KV_KEYS, TOKEN_CONSTANTS } from '../types';

describe('StorageManager', () => {
  let mockEnv: Environment;
  let storage: StorageManager;
  let mockKV: any;

  beforeEach(() => {
    mockKV = createMockKV();
    mockEnv = createMockEnvironment({ AUTH_KV: mockKV });
    storage = new StorageManager(mockEnv);
    vi.clearAllMocks();
  });

  describe('storeAuthorizationCode', () => {
    it('should store authorization code with correct TTL', async () => {
      const authCode = TestFixtures.authorizationCode;
      
      await storage.storeAuthorizationCode(authCode);

      expect(mockKV.put).toHaveBeenCalledWith(
        KV_KEYS.AUTH_CODE(authCode.code),
        JSON.stringify(authCode),
        { expirationTtl: TOKEN_CONSTANTS.AUTHORIZATION_CODE_LIFETIME }
      );
    });

    it('should throw StorageError when KV operation fails', async () => {
      const authCode = TestFixtures.authorizationCode;
      mockKV.put.mockRejectedValue(new Error('KV put failed'));

      await expect(
        storage.storeAuthorizationCode(authCode)
      ).rejects.toThrow(StorageError);
    });
  });

  describe('getAuthorizationCode', () => {
    it('should retrieve valid authorization code', async () => {
      const authCode = TestFixtures.authorizationCode;
      mockKV.get.mockResolvedValue(JSON.stringify(authCode));

      const result = await storage.getAuthorizationCode(authCode.code);

      expect(mockKV.get).toHaveBeenCalledWith(KV_KEYS.AUTH_CODE(authCode.code));
      expect(result).toEqual(authCode);
    });

    it('should return null for non-existent code', async () => {
      mockKV.get.mockResolvedValue(null);

      const result = await storage.getAuthorizationCode('non-existent');

      expect(result).toBeNull();
    });

    it('should delete and return null for expired code', async () => {
      const expiredAuthCode = {
        ...TestFixtures.authorizationCode,
        expires_at: Date.now() - 60000 // Expired 1 minute ago
      };
      mockKV.get.mockResolvedValue(JSON.stringify(expiredAuthCode));

      const result = await storage.getAuthorizationCode(expiredAuthCode.code);

      expect(mockKV.delete).toHaveBeenCalledWith(KV_KEYS.AUTH_CODE(expiredAuthCode.code));
      expect(result).toBeNull();
    });

    it('should throw StorageError when KV get fails', async () => {
      mockKV.get.mockRejectedValue(new Error('KV get failed'));

      await expect(
        storage.getAuthorizationCode('test-code')
      ).rejects.toThrow(StorageError);
    });

    it('should throw StorageError when JSON parsing fails', async () => {
      mockKV.get.mockResolvedValue('invalid-json');

      await expect(
        storage.getAuthorizationCode('test-code')
      ).rejects.toThrow(StorageError);
    });
  });

  describe('deleteAuthorizationCode', () => {
    it('should delete authorization code', async () => {
      await storage.deleteAuthorizationCode('test-code');

      expect(mockKV.delete).toHaveBeenCalledWith(KV_KEYS.AUTH_CODE('test-code'));
    });

    it('should throw StorageError when delete fails', async () => {
      mockKV.delete.mockRejectedValue(new Error('Delete failed'));

      await expect(
        storage.deleteAuthorizationCode('test-code')
      ).rejects.toThrow(StorageError);
    });
  });

  describe('storeRefreshToken', () => {
    it('should store refresh token with correct data and TTL', async () => {
      const tokenId = 'token-123';
      const userId = 'user-456';
      const scope = 'mcp:example.com:filesystem user:email';
      const email = 'test@example.com';

      await storage.storeRefreshToken(tokenId, userId, scope, email);

      expect(mockKV.put).toHaveBeenCalledWith(
        KV_KEYS.REFRESH_TOKEN(tokenId),
        JSON.stringify({
          user_id: userId,
          scope,
          email,
          created_at: expect.any(Number)
        }),
        { expirationTtl: TOKEN_CONSTANTS.REFRESH_TOKEN_LIFETIME }
      );
    });

    it('should store refresh token without email', async () => {
      const tokenId = 'token-123';
      const userId = 'user-456';
      const scope = 'mcp:example.com:filesystem';

      await storage.storeRefreshToken(tokenId, userId, scope);

      expect(mockKV.put).toHaveBeenCalledWith(
        KV_KEYS.REFRESH_TOKEN(tokenId),
        JSON.stringify({
          user_id: userId,
          scope,
          email: undefined,
          created_at: expect.any(Number)
        }),
        { expirationTtl: TOKEN_CONSTANTS.REFRESH_TOKEN_LIFETIME }
      );
    });

    it('should throw StorageError when store fails', async () => {
      mockKV.put.mockRejectedValue(new Error('Store failed'));

      await expect(
        storage.storeRefreshToken('token-123', 'user-456', 'scope')
      ).rejects.toThrow(StorageError);
    });
  });

  describe('getRefreshTokenData', () => {
    it('should retrieve refresh token data', async () => {
      const tokenData = {
        user_id: 'user-456',
        scope: 'mcp:example.com:filesystem',
        email: 'test@example.com',
        created_at: Date.now()
      };
      mockKV.get.mockResolvedValue(JSON.stringify(tokenData));

      const result = await storage.getRefreshTokenData('token-123');

      expect(mockKV.get).toHaveBeenCalledWith(KV_KEYS.REFRESH_TOKEN('token-123'));
      expect(result).toEqual(tokenData);
    });

    it('should return null for non-existent token', async () => {
      mockKV.get.mockResolvedValue(null);

      const result = await storage.getRefreshTokenData('non-existent');

      expect(result).toBeNull();
    });

    it('should throw StorageError when get fails', async () => {
      mockKV.get.mockRejectedValue(new Error('Get failed'));

      await expect(
        storage.getRefreshTokenData('token-123')
      ).rejects.toThrow(StorageError);
    });
  });

  describe('deleteRefreshToken', () => {
    it('should delete refresh token', async () => {
      await storage.deleteRefreshToken('token-123');

      expect(mockKV.delete).toHaveBeenCalledWith(KV_KEYS.REFRESH_TOKEN('token-123'));
    });

    it('should throw StorageError when delete fails', async () => {
      mockKV.delete.mockRejectedValue(new Error('Delete failed'));

      await expect(
        storage.deleteRefreshToken('token-123')
      ).rejects.toThrow(StorageError);
    });
  });

  describe('storeUserSession', () => {
    it('should store user session with default TTL', async () => {
      const sessionId = 'session-123';
      const sessionData = { user: 'test', step: 'oauth' };

      await storage.storeUserSession(sessionId, sessionData);

      expect(mockKV.put).toHaveBeenCalledWith(
        KV_KEYS.USER_SESSION(sessionId),
        JSON.stringify({
          ...sessionData,
          created_at: expect.any(Number)
        }),
        { expirationTtl: 1800 } // 30 minutes
      );
    });

    it('should throw StorageError when store fails', async () => {
      mockKV.put.mockRejectedValue(new Error('Store failed'));

      await expect(
        storage.storeUserSession('session-123', {})
      ).rejects.toThrow(StorageError);
    });
  });

  describe('getUserSession', () => {
    it('should retrieve user session', async () => {
      const sessionData = { user: 'test', step: 'oauth', created_at: Date.now() };
      mockKV.get.mockResolvedValue(JSON.stringify(sessionData));

      const result = await storage.getUserSession('session-123');

      expect(mockKV.get).toHaveBeenCalledWith(KV_KEYS.USER_SESSION('session-123'));
      expect(result).toEqual(sessionData);
    });

    it('should return null for non-existent session', async () => {
      mockKV.get.mockResolvedValue(null);

      const result = await storage.getUserSession('non-existent');

      expect(result).toBeNull();
    });

    it('should throw StorageError when get fails', async () => {
      mockKV.get.mockRejectedValue(new Error('Get failed'));

      await expect(
        storage.getUserSession('session-123')
      ).rejects.toThrow(StorageError);
    });
  });

  describe('deleteUserSession', () => {
    it('should delete user session', async () => {
      await storage.deleteUserSession('session-123');

      expect(mockKV.delete).toHaveBeenCalledWith(KV_KEYS.USER_SESSION('session-123'));
    });

    it('should throw StorageError when delete fails', async () => {
      mockKV.delete.mockRejectedValue(new Error('Delete failed'));

      await expect(
        storage.deleteUserSession('session-123')
      ).rejects.toThrow(StorageError);
    });
  });

  describe('listRefreshTokensForUser', () => {
    it('should list refresh tokens for a specific user', async () => {
      const tokens = [
        { name: 'refresh_token:token1' },
        { name: 'refresh_token:token2' },
        { name: 'refresh_token:token3' }
      ];
      mockKV.list.mockResolvedValue({ keys: tokens });
      
      // Mock get calls for each token
      mockKV.get
        .mockResolvedValueOnce(JSON.stringify({ user_id: 'user123' }))
        .mockResolvedValueOnce(JSON.stringify({ user_id: 'other-user' }))
        .mockResolvedValueOnce(JSON.stringify({ user_id: 'user123' }));

      const result = await storage.listRefreshTokensForUser('user123');

      expect(mockKV.list).toHaveBeenCalledWith({ prefix: 'refresh_token:' });
      expect(result).toEqual(['token1', 'token3']);
    });

    it('should return empty array when no tokens found', async () => {
      mockKV.list.mockResolvedValue({ keys: [] });

      const result = await storage.listRefreshTokensForUser('user123');

      expect(result).toEqual([]);
    });

    it('should handle tokens with null values', async () => {
      const tokens = [
        { name: 'refresh_token:token1' },
        { name: 'refresh_token:token2' }
      ];
      mockKV.list.mockResolvedValue({ keys: tokens });
      mockKV.get
        .mockResolvedValueOnce(JSON.stringify({ user_id: 'user123' }))
        .mockResolvedValueOnce(null);

      const result = await storage.listRefreshTokensForUser('user123');

      expect(result).toEqual(['token1']);
    });

    it('should throw StorageError when list fails', async () => {
      mockKV.list.mockRejectedValue(new Error('List failed'));

      await expect(
        storage.listRefreshTokensForUser('user123')
      ).rejects.toThrow(StorageError);
    });
  });

  describe('revokeAllUserTokens', () => {
    it('should revoke all tokens for a user', async () => {
      const userTokens = ['token1', 'token2', 'token3'];
      
      // Mock listRefreshTokensForUser
      vi.spyOn(storage, 'listRefreshTokensForUser').mockResolvedValue(userTokens);
      vi.spyOn(storage, 'deleteRefreshToken').mockResolvedValue();

      await storage.revokeAllUserTokens('user123');

      expect(storage.listRefreshTokensForUser).toHaveBeenCalledWith('user123');
      expect(storage.deleteRefreshToken).toHaveBeenCalledTimes(3);
      expect(storage.deleteRefreshToken).toHaveBeenCalledWith('token1');
      expect(storage.deleteRefreshToken).toHaveBeenCalledWith('token2');
      expect(storage.deleteRefreshToken).toHaveBeenCalledWith('token3');
    });

    it('should handle empty token list', async () => {
      vi.spyOn(storage, 'listRefreshTokensForUser').mockResolvedValue([]);
      vi.spyOn(storage, 'deleteRefreshToken').mockResolvedValue();

      await storage.revokeAllUserTokens('user123');

      expect(storage.deleteRefreshToken).not.toHaveBeenCalled();
    });

    it('should throw StorageError when revocation fails', async () => {
      vi.spyOn(storage, 'listRefreshTokensForUser').mockRejectedValue(new Error('List failed'));

      await expect(
        storage.revokeAllUserTokens('user123')
      ).rejects.toThrow(StorageError);
    });
  });

  describe('generateSessionId', () => {
    it('should generate a UUID for session ID', () => {
      const mockUUID = 'session-uuid-123';
      global.crypto = {
        randomUUID: vi.fn().mockReturnValue(mockUUID)
      } as any;

      const result = storage.generateSessionId();

      expect(result).toBe(mockUUID);
      expect(crypto.randomUUID).toHaveBeenCalled();
    });
  });

  describe('generateAuthorizationCode', () => {
    it('should generate URL-safe base64 authorization code', () => {
      const mockArray = new Uint8Array(32);
      mockArray.fill(65); // Fill with 'A' character

      global.crypto = {
        getRandomValues: vi.fn().mockImplementation((array) => {
          array.set(mockArray);
          return array;
        })
      } as any;

      const result = storage.generateAuthorizationCode();

      expect(crypto.getRandomValues).toHaveBeenCalled();
      expect(result).toBeTruthy();
      expect(result).not.toContain('+');
      expect(result).not.toContain('/');
      expect(result).not.toContain('=');
    });
  });

  describe('edge cases and error conditions', () => {
    it('should handle malformed JSON in getAuthorizationCode', async () => {
      mockKV.get.mockResolvedValue('malformed json {');

      await expect(
        storage.getAuthorizationCode('test-code')
      ).rejects.toThrow(StorageError);
    });

    it('should handle malformed JSON in getRefreshTokenData', async () => {
      mockKV.get.mockResolvedValue('malformed json {');

      await expect(
        storage.getRefreshTokenData('token-123')
      ).rejects.toThrow(StorageError);
    });

    it('should handle malformed JSON in getUserSession', async () => {
      mockKV.get.mockResolvedValue('malformed json {');

      await expect(
        storage.getUserSession('session-123')
      ).rejects.toThrow(StorageError);
    });

    it('should handle KV exceptions in listRefreshTokensForUser when getting token data', async () => {
      const tokens = [{ name: 'refresh_token:token1' }];
      mockKV.list.mockResolvedValue({ keys: tokens });
      mockKV.get.mockRejectedValue(new Error('Get failed'));

      await expect(
        storage.listRefreshTokensForUser('user123')
      ).rejects.toThrow(StorageError);
    });
  });
});
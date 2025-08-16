import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JWTManager, JWTError } from '../utils/jwt';
import { createMockEnvironment } from './test-utils';
import { Environment, TOKEN_CONSTANTS } from '../types';

// Mock the jwt library
vi.mock('@tsndr/cloudflare-worker-jwt', () => ({
  default: {
    sign: vi.fn(),
    verify: vi.fn(),
    decode: vi.fn()
  }
}));

// Mock the encryption module
vi.mock('../utils/encryption', () => ({
  EncryptionManager: vi.fn().mockImplementation(() => ({
    encrypt: vi.fn().mockResolvedValue({
      data: 'encrypted-data',
      iv: 'test-iv',
      keyVersion: 'current'
    }),
    decrypt: vi.fn().mockResolvedValue('decrypted-jwt-token')
  })),
  encodeEncryptedData: vi.fn().mockReturnValue('encoded-encrypted-data'),
  decodeEncryptedData: vi.fn().mockReturnValue({
    data: 'encrypted-data',
    iv: 'test-iv',
    keyVersion: 'current'
  })
}));

import jwt from '@tsndr/cloudflare-worker-jwt';
import { EncryptionManager } from '../utils/encryption';

describe('JWTManager', () => {
  let mockEnv: Environment;
  let jwtManager: JWTManager;
  let mockEncryption: any;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEnv = createMockEnvironment();
    jwtManager = new JWTManager(mockEnv);
    
    // Get the mock instance
    mockEncryption = (EncryptionManager as any).mock.instances[0];
  });

  describe('createAccessToken', () => {
    it('should create a valid access token with correct payload', async () => {
      const mockJwtToken = 'mock.jwt.token';
      vi.mocked(jwt.sign).mockResolvedValue(mockJwtToken);
      
      const payload = {
        sub: 'user123',
        aud: 'mcp:example.com:filesystem',
        email: 'test@example.com'
      };

      const result = await jwtManager.createAccessToken(payload);

      expect(jwt.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          sub: 'user123',
          aud: 'mcp:example.com:filesystem',
          email: 'test@example.com',
          token_type: 'access',
          iss: mockEnv.WORKER_BASE_URL,
          exp: expect.any(Number)
        }),
        mockEnv.JWT_PRIVATE_KEY,
        { algorithm: 'RS256' }
      );

      expect(result).toBe(`${TOKEN_CONSTANTS.ACCESS_TOKEN_PREFIX}${mockJwtToken}`);
    });

    it('should create access token without email when not provided', async () => {
      const mockJwtToken = 'mock.jwt.token';
      vi.mocked(jwt.sign).mockResolvedValue(mockJwtToken);
      
      const payload = {
        sub: 'user123',
        aud: 'mcp:example.com:filesystem'
      };

      await jwtManager.createAccessToken(payload);

      expect(jwt.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          sub: 'user123',
          aud: 'mcp:example.com:filesystem',
          token_type: 'access',
          iss: mockEnv.WORKER_BASE_URL,
          exp: expect.any(Number)
        }),
        mockEnv.JWT_PRIVATE_KEY,
        { algorithm: 'RS256' }
      );
    });

    it('should set correct expiration time', async () => {
      const mockJwtToken = 'mock.jwt.token';
      vi.mocked(jwt.sign).mockResolvedValue(mockJwtToken);
      
      const beforeTime = Math.floor(Date.now() / 1000);
      
      await jwtManager.createAccessToken({
        sub: 'user123',
        aud: 'mcp:example.com:filesystem'
      });

      const callArgs = vi.mocked(jwt.sign).mock.calls[0][0] as any;
      const afterTime = Math.floor(Date.now() / 1000);
      
      expect(callArgs.exp).toBeGreaterThanOrEqual(beforeTime + TOKEN_CONSTANTS.ACCESS_TOKEN_LIFETIME);
      expect(callArgs.exp).toBeLessThanOrEqual(afterTime + TOKEN_CONSTANTS.ACCESS_TOKEN_LIFETIME);
    });

    it('should throw JWTError when jwt.sign fails', async () => {
      vi.mocked(jwt.sign).mockRejectedValue(new Error('Signing failed'));

      await expect(
        jwtManager.createAccessToken({
          sub: 'user123',
          aud: 'mcp:example.com:filesystem'
        })
      ).rejects.toThrow(JWTError);
    });
  });

  describe('createRefreshToken', () => {
    it('should create a valid refresh token with encryption', async () => {
      const mockJwtToken = 'mock.jwt.token';
      vi.mocked(jwt.sign).mockResolvedValue(mockJwtToken);
      
      const payload = {
        sub: 'user123',
        aud: 'mcp:example.com:filesystem',
        email: 'test@example.com'
      };

      const result = await jwtManager.createRefreshToken(payload);

      expect(jwt.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          sub: 'user123',
          aud: 'mcp:example.com:filesystem',
          email: 'test@example.com',
          token_type: 'refresh',
          iss: mockEnv.WORKER_BASE_URL,
          exp: expect.any(Number)
        }),
        mockEnv.JWT_PRIVATE_KEY,
        { algorithm: 'RS256' }
      );

      expect(mockEncryption.encrypt).toHaveBeenCalledWith(mockJwtToken);
      expect(result).toBe(`${TOKEN_CONSTANTS.REFRESH_TOKEN_PREFIX}encoded-encrypted-data`);
    });

    it('should set correct expiration time for refresh token', async () => {
      const mockJwtToken = 'mock.jwt.token';
      vi.mocked(jwt.sign).mockResolvedValue(mockJwtToken);
      
      const beforeTime = Math.floor(Date.now() / 1000);
      
      await jwtManager.createRefreshToken({
        sub: 'user123',
        aud: 'mcp:example.com:filesystem'
      });

      const callArgs = vi.mocked(jwt.sign).mock.calls[0][0] as any;
      const afterTime = Math.floor(Date.now() / 1000);
      
      expect(callArgs.exp).toBeGreaterThanOrEqual(beforeTime + TOKEN_CONSTANTS.REFRESH_TOKEN_LIFETIME);
      expect(callArgs.exp).toBeLessThanOrEqual(afterTime + TOKEN_CONSTANTS.REFRESH_TOKEN_LIFETIME);
    });

    it('should throw JWTError when encryption fails', async () => {
      const mockJwtToken = 'mock.jwt.token';
      vi.mocked(jwt.sign).mockResolvedValue(mockJwtToken);
      mockEncryption.encrypt.mockRejectedValue(new Error('Encryption failed'));

      await expect(
        jwtManager.createRefreshToken({
          sub: 'user123',
          aud: 'mcp:example.com:filesystem'
        })
      ).rejects.toThrow(JWTError);
    });
  });

  describe('verifyAccessToken', () => {
    it('should verify a valid access token', async () => {
      const token = `${TOKEN_CONSTANTS.ACCESS_TOKEN_PREFIX}valid.jwt.token`;
      const mockPayload = {
        token_type: 'access',
        sub: 'user123',
        aud: 'mcp:example.com:filesystem',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iss: mockEnv.WORKER_BASE_URL,
        email: 'test@example.com'
      };

      vi.mocked(jwt.verify).mockResolvedValue(true);
      vi.mocked(jwt.decode).mockReturnValue({ payload: mockPayload });

      const result = await jwtManager.verifyAccessToken(token);

      expect(jwt.verify).toHaveBeenCalledWith(
        'valid.jwt.token',
        mockEnv.JWT_PUBLIC_KEY,
        { algorithm: 'RS256' }
      );
      expect(result).toEqual(mockPayload);
    });

    it('should throw JWTError for invalid token format', async () => {
      await expect(
        jwtManager.verifyAccessToken('invalid-token-format')
      ).rejects.toThrow(JWTError);
    });

    it('should throw JWTError for invalid signature', async () => {
      const token = `${TOKEN_CONSTANTS.ACCESS_TOKEN_PREFIX}invalid.jwt.token`;
      vi.mocked(jwt.verify).mockResolvedValue(false);

      await expect(
        jwtManager.verifyAccessToken(token)
      ).rejects.toThrow(JWTError);
    });

    it('should throw JWTError for expired token', async () => {
      const token = `${TOKEN_CONSTANTS.ACCESS_TOKEN_PREFIX}expired.jwt.token`;
      const mockPayload = {
        token_type: 'access',
        sub: 'user123',
        aud: 'mcp:example.com:filesystem',
        exp: Math.floor(Date.now() / 1000) - 3600, // Expired 1 hour ago
        iss: mockEnv.WORKER_BASE_URL
      };

      vi.mocked(jwt.verify).mockResolvedValue(true);
      vi.mocked(jwt.decode).mockReturnValue({ payload: mockPayload });

      await expect(
        jwtManager.verifyAccessToken(token)
      ).rejects.toThrow(JWTError);
    });

    it('should throw JWTError for wrong token type', async () => {
      const token = `${TOKEN_CONSTANTS.ACCESS_TOKEN_PREFIX}refresh.jwt.token`;
      const mockPayload = {
        token_type: 'refresh', // Wrong type
        sub: 'user123',
        aud: 'mcp:example.com:filesystem',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iss: mockEnv.WORKER_BASE_URL
      };

      vi.mocked(jwt.verify).mockResolvedValue(true);
      vi.mocked(jwt.decode).mockReturnValue({ payload: mockPayload });

      await expect(
        jwtManager.verifyAccessToken(token)
      ).rejects.toThrow(JWTError);
    });

    it('should throw JWTError for invalid payload', async () => {
      const token = `${TOKEN_CONSTANTS.ACCESS_TOKEN_PREFIX}invalid.jwt.token`;
      vi.mocked(jwt.verify).mockResolvedValue(true);
      vi.mocked(jwt.decode).mockReturnValue({ payload: null });

      await expect(
        jwtManager.verifyAccessToken(token)
      ).rejects.toThrow(JWTError);
    });
  });

  describe('verifyRefreshToken', () => {
    it('should verify a valid refresh token', async () => {
      const token = `${TOKEN_CONSTANTS.REFRESH_TOKEN_PREFIX}encrypted-token`;
      const mockPayload = {
        token_type: 'refresh',
        sub: 'user123',
        aud: 'mcp:example.com:filesystem',
        exp: Math.floor(Date.now() / 1000) + 86400,
        iss: mockEnv.WORKER_BASE_URL,
        email: 'test@example.com'
      };

      vi.mocked(jwt.verify).mockResolvedValue(true);
      vi.mocked(jwt.decode).mockReturnValue({ payload: mockPayload });

      const result = await jwtManager.verifyRefreshToken(token);

      expect(mockEncryption.decrypt).toHaveBeenCalled();
      expect(jwt.verify).toHaveBeenCalledWith(
        'decrypted-jwt-token',
        mockEnv.JWT_PUBLIC_KEY,
        { algorithm: 'RS256' }
      );
      expect(result).toEqual(mockPayload);
    });

    it('should throw JWTError for invalid refresh token format', async () => {
      await expect(
        jwtManager.verifyRefreshToken('invalid-token-format')
      ).rejects.toThrow(JWTError);
    });

    it('should throw JWTError when decryption fails', async () => {
      const token = `${TOKEN_CONSTANTS.REFRESH_TOKEN_PREFIX}encrypted-token`;
      mockEncryption.decrypt.mockRejectedValue(new Error('Decryption failed'));

      await expect(
        jwtManager.verifyRefreshToken(token)
      ).rejects.toThrow(JWTError);
    });

    it('should throw JWTError for expired refresh token', async () => {
      const token = `${TOKEN_CONSTANTS.REFRESH_TOKEN_PREFIX}encrypted-token`;
      const mockPayload = {
        token_type: 'refresh',
        sub: 'user123',
        aud: 'mcp:example.com:filesystem',
        exp: Math.floor(Date.now() / 1000) - 3600, // Expired
        iss: mockEnv.WORKER_BASE_URL
      };

      vi.mocked(jwt.verify).mockResolvedValue(true);
      vi.mocked(jwt.decode).mockReturnValue({ payload: mockPayload });

      await expect(
        jwtManager.verifyRefreshToken(token)
      ).rejects.toThrow(JWTError);
    });

    it('should throw JWTError for wrong token type in refresh token', async () => {
      const token = `${TOKEN_CONSTANTS.REFRESH_TOKEN_PREFIX}encrypted-token`;
      const mockPayload = {
        token_type: 'access', // Wrong type
        sub: 'user123',
        aud: 'mcp:example.com:filesystem',
        exp: Math.floor(Date.now() / 1000) + 86400,
        iss: mockEnv.WORKER_BASE_URL
      };

      vi.mocked(jwt.verify).mockResolvedValue(true);
      vi.mocked(jwt.decode).mockReturnValue({ payload: mockPayload });

      await expect(
        jwtManager.verifyRefreshToken(token)
      ).rejects.toThrow(JWTError);
    });
  });

  describe('extractTokenFromBearer', () => {
    it('should extract token from valid Bearer header', async () => {
      const result = await jwtManager.extractTokenFromBearer('Bearer test-token-123');
      expect(result).toBe('test-token-123');
    });

    it('should throw JWTError for missing authorization header', async () => {
      await expect(
        jwtManager.extractTokenFromBearer(null)
      ).rejects.toThrow(JWTError);
    });

    it('should throw JWTError for invalid authorization header format', async () => {
      await expect(
        jwtManager.extractTokenFromBearer('InvalidFormat test-token')
      ).rejects.toThrow(JWTError);
    });

    it('should throw JWTError for malformed Bearer header', async () => {
      await expect(
        jwtManager.extractTokenFromBearer('Bearer')
      ).rejects.toThrow(JWTError);
    });
  });

  describe('generateTokenId', () => {
    it('should generate a UUID', () => {
      // Mock crypto.randomUUID
      const mockUUID = 'test-uuid-123';
      global.crypto = {
        randomUUID: vi.fn().mockReturnValue(mockUUID)
      } as any;

      const result = jwtManager.generateTokenId();
      expect(result).toBe(mockUUID);
      expect(crypto.randomUUID).toHaveBeenCalled();
    });
  });

  describe('edge cases and error handling', () => {
    it('should handle jwt.verify throwing an error', async () => {
      const token = `${TOKEN_CONSTANTS.ACCESS_TOKEN_PREFIX}valid.jwt.token`;
      vi.mocked(jwt.verify).mockRejectedValue(new Error('Verification failed'));

      await expect(
        jwtManager.verifyAccessToken(token)
      ).rejects.toThrow(JWTError);
    });

    it('should handle jwt.decode returning undefined', async () => {
      const token = `${TOKEN_CONSTANTS.ACCESS_TOKEN_PREFIX}valid.jwt.token`;
      vi.mocked(jwt.verify).mockResolvedValue(true);
      vi.mocked(jwt.decode).mockReturnValue(undefined as any);

      await expect(
        jwtManager.verifyAccessToken(token)
      ).rejects.toThrow(JWTError);
    });

    it('should handle missing payload in decoded token', async () => {
      const token = `${TOKEN_CONSTANTS.ACCESS_TOKEN_PREFIX}valid.jwt.token`;
      vi.mocked(jwt.verify).mockResolvedValue(true);
      vi.mocked(jwt.decode).mockReturnValue({} as any);

      await expect(
        jwtManager.verifyAccessToken(token)
      ).rejects.toThrow(JWTError);
    });
  });
});
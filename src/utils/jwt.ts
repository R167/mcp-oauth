import jwt from '@tsndr/cloudflare-worker-jwt';
import { Environment, AccessToken, RefreshToken, TOKEN_CONSTANTS } from '../types';
import { EncryptionManager, encodeEncryptedData, decodeEncryptedData } from './encryption';

export class JWTError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JWTError';
  }
}

export class JWTManager {
  private encryptionManager: EncryptionManager;

  constructor(private env: Environment) {
    this.encryptionManager = new EncryptionManager(env);
  }

  async createAccessToken(payload: Omit<AccessToken, 'token_type' | 'iss' | 'exp'>): Promise<string> {
    try {
      const now = Math.floor(Date.now() / 1000);
      const token: AccessToken = {
        ...payload,
        token_type: 'access',
        iss: this.env.WORKER_BASE_URL,
        exp: now + TOKEN_CONSTANTS.ACCESS_TOKEN_LIFETIME,
      };

      const jwtToken = await jwt.sign(token, this.env.JWT_PRIVATE_KEY, { algorithm: 'RS256' });
      return `${TOKEN_CONSTANTS.ACCESS_TOKEN_PREFIX}${jwtToken}`;
    } catch (error) {
      throw new JWTError(`Failed to create access token: ${error}`);
    }
  }

  async createRefreshToken(payload: Omit<RefreshToken, 'token_type' | 'iss' | 'exp'>): Promise<string> {
    try {
      const now = Math.floor(Date.now() / 1000);
      const token: RefreshToken = {
        ...payload,
        token_type: 'refresh',
        iss: this.env.WORKER_BASE_URL,
        exp: now + TOKEN_CONSTANTS.REFRESH_TOKEN_LIFETIME,
      };

      const jwtToken = await jwt.sign(token, this.env.JWT_PRIVATE_KEY, { algorithm: 'RS256' });
      const encryptedData = await this.encryptionManager.encrypt(jwtToken);
      const encodedData = encodeEncryptedData(encryptedData);
      
      return `${TOKEN_CONSTANTS.REFRESH_TOKEN_PREFIX}${encodedData}`;
    } catch (error) {
      throw new JWTError(`Failed to create refresh token: ${error}`);
    }
  }

  async verifyAccessToken(token: string): Promise<AccessToken> {
    try {
      if (!token.startsWith(TOKEN_CONSTANTS.ACCESS_TOKEN_PREFIX)) {
        throw new JWTError('Invalid access token format');
      }

      const jwtToken = token.slice(TOKEN_CONSTANTS.ACCESS_TOKEN_PREFIX.length);
      const isValid = await jwt.verify(jwtToken, this.env.JWT_PUBLIC_KEY, { algorithm: 'RS256' });
      
      if (!isValid) {
        throw new JWTError('Invalid access token signature');
      }

      const payload = jwt.decode(jwtToken);
      if (!payload || !payload.payload) {
        throw new JWTError('Invalid access token payload');
      }

      const tokenData = payload.payload as AccessToken;
      
      if (tokenData.token_type !== 'access') {
        throw new JWTError('Token is not an access token');
      }

      const now = Math.floor(Date.now() / 1000);
      if (tokenData.exp < now) {
        throw new JWTError('Access token has expired');
      }

      return tokenData;
    } catch (error) {
      if (error instanceof JWTError) {
        throw error;
      }
      throw new JWTError(`Failed to verify access token: ${error}`);
    }
  }

  async verifyRefreshToken(token: string): Promise<RefreshToken> {
    try {
      if (!token.startsWith(TOKEN_CONSTANTS.REFRESH_TOKEN_PREFIX)) {
        throw new JWTError('Invalid refresh token format');
      }

      const encodedData = token.slice(TOKEN_CONSTANTS.REFRESH_TOKEN_PREFIX.length);
      const encryptedData = decodeEncryptedData(encodedData);
      const jwtToken = await this.encryptionManager.decrypt(encryptedData);

      const isValid = await jwt.verify(jwtToken, this.env.JWT_PUBLIC_KEY, { algorithm: 'RS256' });
      
      if (!isValid) {
        throw new JWTError('Invalid refresh token signature');
      }

      const payload = jwt.decode(jwtToken);
      if (!payload || !payload.payload) {
        throw new JWTError('Invalid refresh token payload');
      }

      const tokenData = payload.payload as RefreshToken;
      
      if (tokenData.token_type !== 'refresh') {
        throw new JWTError('Token is not a refresh token');
      }

      const now = Math.floor(Date.now() / 1000);
      if (tokenData.exp < now) {
        throw new JWTError('Refresh token has expired');
      }

      return tokenData;
    } catch (error) {
      if (error instanceof JWTError) {
        throw error;
      }
      throw new JWTError(`Failed to verify refresh token: ${error}`);
    }
  }

  async extractTokenFromBearer(authHeader: string | null): Promise<string> {
    if (!authHeader) {
      throw new JWTError('Authorization header missing');
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      throw new JWTError('Invalid authorization header format');
    }

    return parts[1];
  }

  generateTokenId(): string {
    return crypto.randomUUID();
  }
}
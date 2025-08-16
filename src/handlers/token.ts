import { Environment, TokenRequest, TokenResponse, OAuthError } from '../types';
import { JWTManager } from '../utils/jwt';
import { StorageManager } from '../utils/storage';
import { ScopeValidator } from '../utils/scopes';

export class TokenHandler {
  private jwtManager: JWTManager;
  private storage: StorageManager;
  private scopeValidator: ScopeValidator;

  constructor(private env: Environment) {
    this.jwtManager = new JWTManager(env);
    this.storage = new StorageManager(env);
    this.scopeValidator = new ScopeValidator();
  }

  async handle(request: Request): Promise<Response> {
    try {
      if (request.method !== 'POST') {
        return this.createErrorResponse({
          error: 'invalid_request',
          error_description: 'Method not allowed'
        }, 405);
      }

      const contentType = request.headers.get('Content-Type');
      if (!contentType?.includes('application/x-www-form-urlencoded')) {
        return this.createErrorResponse({
          error: 'invalid_request',
          error_description: 'Content-Type must be application/x-www-form-urlencoded'
        }, 400);
      }

      const formData = await request.formData();
      const tokenRequest = this.parseTokenRequest(formData);
      
      if (tokenRequest.grant_type === 'authorization_code') {
        return await this.handleAuthorizationCodeGrant(tokenRequest);
      } else if (tokenRequest.grant_type === 'refresh_token') {
        return await this.handleRefreshTokenGrant(tokenRequest);
      } else {
        return this.createErrorResponse({
          error: 'unsupported_grant_type',
          error_description: 'Supported grant types: authorization_code, refresh_token'
        }, 400);
      }

    } catch (error) {
      console.error('Token error:', error);
      return this.createErrorResponse({
        error: 'server_error',
        error_description: 'Internal server error'
      }, 500);
    }
  }

  private async handleAuthorizationCodeGrant(tokenRequest: TokenRequest): Promise<Response> {
    const validation = this.validateAuthorizationCodeRequest(tokenRequest);
    if (!validation.valid) {
      return this.createErrorResponse({
        error: validation.error!,
        error_description: validation.error_description
      }, 400);
    }

    const authCode = await this.storage.getAuthorizationCode(tokenRequest.code!);
    if (!authCode) {
      return this.createErrorResponse({
        error: 'invalid_grant',
        error_description: 'Authorization code not found or expired'
      }, 400);
    }

    if (authCode.client_id !== tokenRequest.client_id) {
      return this.createErrorResponse({
        error: 'invalid_grant',
        error_description: 'Client ID mismatch'
      }, 400);
    }

    if (authCode.redirect_uri !== tokenRequest.redirect_uri) {
      return this.createErrorResponse({
        error: 'invalid_grant',
        error_description: 'Redirect URI mismatch'
      }, 400);
    }

    if (!this.verifyPKCE(tokenRequest.code_verifier!, authCode.code_challenge)) {
      return this.createErrorResponse({
        error: 'invalid_grant',
        error_description: 'PKCE verification failed'
      }, 400);
    }

    await this.storage.deleteAuthorizationCode(tokenRequest.code!);

    const scopes = authCode.scope.split(' ');
    const mcpScope = scopes.find(scope => scope.startsWith('mcp:'))!;
    const includeEmail = scopes.includes('user:email');

    const tokenId = this.jwtManager.generateTokenId();
    const accessToken = await this.jwtManager.createAccessToken({
      sub: authCode.user_id,
      aud: mcpScope,
      email: includeEmail ? authCode.email : undefined
    });

    const refreshToken = await this.jwtManager.createRefreshToken({
      sub: authCode.user_id,
      aud: mcpScope,
      email: includeEmail ? authCode.email : undefined
    });

    await this.storage.storeRefreshToken(
      tokenId,
      authCode.user_id,
      authCode.scope,
      authCode.email
    );

    const response: TokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: authCode.scope
    };

    return new Response(JSON.stringify(response), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      }
    });
  }

  private async handleRefreshTokenGrant(tokenRequest: TokenRequest): Promise<Response> {
    if (!tokenRequest.refresh_token) {
      return this.createErrorResponse({
        error: 'invalid_request',
        error_description: 'refresh_token is required'
      }, 400);
    }

    try {
      const refreshTokenPayload = await this.jwtManager.verifyRefreshToken(tokenRequest.refresh_token);
      
      const tokenData = await this.storage.getRefreshTokenData(refreshTokenPayload.sub);
      if (!tokenData) {
        return this.createErrorResponse({
          error: 'invalid_grant',
          error_description: 'Refresh token not found or revoked'
        }, 400);
      }

      const scopes = tokenData.scope.split(' ');
      const mcpScope = scopes.find(scope => scope.startsWith('mcp:'))!;
      const includeEmail = scopes.includes('user:email');

      const newAccessToken = await this.jwtManager.createAccessToken({
        sub: refreshTokenPayload.sub,
        aud: mcpScope,
        email: includeEmail ? tokenData.email : undefined
      });

      const newRefreshToken = await this.jwtManager.createRefreshToken({
        sub: refreshTokenPayload.sub,
        aud: mcpScope,
        email: includeEmail ? tokenData.email : undefined
      });

      const newTokenId = this.jwtManager.generateTokenId();
      await this.storage.deleteRefreshToken(refreshTokenPayload.sub);
      await this.storage.storeRefreshToken(
        newTokenId,
        refreshTokenPayload.sub,
        tokenData.scope,
        tokenData.email
      );

      const response: TokenResponse = {
        access_token: newAccessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: newRefreshToken,
        scope: tokenData.scope
      };

      return new Response(JSON.stringify(response), {
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store'
        }
      });

    } catch (error) {
      console.error('Refresh token error:', error);
      return this.createErrorResponse({
        error: 'invalid_grant',
        error_description: 'Invalid or expired refresh token'
      }, 400);
    }
  }

  private parseTokenRequest(formData: FormData): TokenRequest {
    return {
      grant_type: formData.get('grant_type') as string || '',
      code: formData.get('code') as string || undefined,
      redirect_uri: formData.get('redirect_uri') as string || undefined,
      client_id: formData.get('client_id') as string || '',
      code_verifier: formData.get('code_verifier') as string || undefined,
      refresh_token: formData.get('refresh_token') as string || undefined
    };
  }

  private validateAuthorizationCodeRequest(request: TokenRequest): {
    valid: boolean;
    error?: string;
    error_description?: string;
  } {
    if (!request.code) {
      return {
        valid: false,
        error: 'invalid_request',
        error_description: 'code is required'
      };
    }

    if (!request.client_id) {
      return {
        valid: false,
        error: 'invalid_request',
        error_description: 'client_id is required'
      };
    }

    if (!request.redirect_uri) {
      return {
        valid: false,
        error: 'invalid_request',
        error_description: 'redirect_uri is required'
      };
    }

    if (!request.code_verifier) {
      return {
        valid: false,
        error: 'invalid_request',
        error_description: 'code_verifier is required for PKCE'
      };
    }

    return { valid: true };
  }

  private async verifyPKCE(codeVerifier: string, codeChallenge: string): Promise<boolean> {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(codeVerifier);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = new Uint8Array(hashBuffer);
      const challengeCalculated = btoa(String.fromCharCode(...hashArray))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      
      return challengeCalculated === codeChallenge;
    } catch (error) {
      console.error('PKCE verification error:', error);
      return false;
    }
  }

  private createErrorResponse(error: OAuthError, status: number = 400): Response {
    return new Response(JSON.stringify(error), {
      status,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      }
    });
  }
}
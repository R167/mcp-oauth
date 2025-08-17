import type { AuthorizationCode, RefreshTokenMetadata, UserSession, ClientRegistration } from "../types.js";

export class StorageManager {
  constructor(private readonly db: D1Database) {}

  async initialize(): Promise<void> {
    // Create tables if they don't exist - using prepare() for better local compatibility
    const statements = [
      "CREATE TABLE IF NOT EXISTS authorization_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, scope TEXT NOT NULL, user_id TEXT NOT NULL, code_challenge TEXT NOT NULL, expires_at INTEGER NOT NULL, email TEXT, created_at INTEGER DEFAULT (strftime('%s', 'now')))",
      "CREATE TABLE IF NOT EXISTS refresh_tokens (token_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, client_id TEXT NOT NULL, scope TEXT NOT NULL, expires_at INTEGER NOT NULL, email TEXT, created_at INTEGER DEFAULT (strftime('%s', 'now')))",
      "CREATE TABLE IF NOT EXISTS user_sessions (session_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, email TEXT, name TEXT, expires_at INTEGER NOT NULL, created_at INTEGER DEFAULT (strftime('%s', 'now')))",
      "CREATE TABLE IF NOT EXISTS client_approvals (user_id TEXT NOT NULL, client_id TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER DEFAULT (strftime('%s', 'now')), PRIMARY KEY (user_id, client_id))",
      "CREATE TABLE IF NOT EXISTS revoked_tokens (token_id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, created_at INTEGER DEFAULT (strftime('%s', 'now')))",
      "CREATE TABLE IF NOT EXISTS registered_clients (client_id TEXT PRIMARY KEY, client_name TEXT NOT NULL, redirect_uris TEXT NOT NULL, scope TEXT NOT NULL, created_at INTEGER NOT NULL, last_used INTEGER NOT NULL, expires_at INTEGER NOT NULL)",
      "CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON authorization_codes(expires_at)",
      "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at)",
      "CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at)",
      "CREATE INDEX IF NOT EXISTS idx_client_approvals_expires ON client_approvals(expires_at)",
      "CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at)",
      "CREATE INDEX IF NOT EXISTS idx_registered_clients_expires ON registered_clients(expires_at)",
      "CREATE INDEX IF NOT EXISTS idx_registered_clients_last_used ON registered_clients(last_used)",
    ];

    for (const statement of statements) {
      try {
        await this.db.prepare(statement).run();
      } catch (error) {
        // Ignore errors for indexes that already exist
        if (!(error as Error).message?.includes("already exists")) {
          console.error("Failed to create table/index:", statement, error);
        }
      }
    }
  }

  // Authorization Codes (10 minute TTL)
  async storeAuthorizationCode(code: string, data: AuthorizationCode): Promise<void> {
    await this.db
      .prepare(
        `
			INSERT INTO authorization_codes (code, client_id, redirect_uri, scope, user_id, code_challenge, expires_at, email)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`,
      )
      .bind(code, data.client_id, data.redirect_uri, data.scope, data.user_id, data.code_challenge, data.expires_at, data.email || null)
      .run();
  }

  async getAuthorizationCode(code: string): Promise<AuthorizationCode | null> {
    const result = await this.db
      .prepare(
        `
			SELECT * FROM authorization_codes WHERE code = ? AND expires_at > strftime('%s', 'now')
		`,
      )
      .bind(code)
      .first();

    if (!result) return null;

    return {
      client_id: result.client_id as string,
      redirect_uri: result.redirect_uri as string,
      scope: result.scope as string,
      user_id: result.user_id as string,
      code_challenge: result.code_challenge as string,
      expires_at: result.expires_at as number,
      email: result.email as string | undefined,
    };
  }

  async deleteAuthorizationCode(code: string): Promise<void> {
    await this.db.prepare("DELETE FROM authorization_codes WHERE code = ?").bind(code).run();
  }

  // Refresh Token Metadata (30 day TTL)
  async storeRefreshTokenMetadata(tokenId: string, data: RefreshTokenMetadata): Promise<void> {
    await this.db
      .prepare(
        `
			INSERT INTO refresh_tokens (token_id, user_id, client_id, scope, expires_at, email)
			VALUES (?, ?, ?, ?, ?, ?)
		`,
      )
      .bind(tokenId, data.user_id, data.client_id, data.scope, data.expires_at, data.email || null)
      .run();
  }

  async getRefreshTokenMetadata(tokenId: string): Promise<RefreshTokenMetadata | null> {
    const result = await this.db
      .prepare(
        `
			SELECT * FROM refresh_tokens WHERE token_id = ? AND expires_at > strftime('%s', 'now')
		`,
      )
      .bind(tokenId)
      .first();

    if (!result) return null;

    return {
      user_id: result.user_id as string,
      client_id: result.client_id as string,
      scope: result.scope as string,
      expires_at: result.expires_at as number,
      email: result.email as string | undefined,
    };
  }

  async deleteRefreshTokenMetadata(tokenId: string): Promise<void> {
    await this.db.prepare("DELETE FROM refresh_tokens WHERE token_id = ?").bind(tokenId).run();
  }

  // User Sessions (30 minute TTL)
  async storeUserSession(sessionId: string, data: UserSession): Promise<void> {
    await this.db
      .prepare(
        `
			INSERT OR REPLACE INTO user_sessions (session_id, user_id, email, name, expires_at)
			VALUES (?, ?, ?, ?, ?)
		`,
      )
      .bind(sessionId, data.user_id, data.email || null, data.name || null, data.expires_at)
      .run();
  }

  async getUserSession(sessionId: string): Promise<UserSession | null> {
    const result = await this.db
      .prepare(
        `
			SELECT * FROM user_sessions WHERE session_id = ? AND expires_at > strftime('%s', 'now')
		`,
      )
      .bind(sessionId)
      .first();

    if (!result) return null;

    return {
      user_id: result.user_id as string,
      email: result.email as string | undefined,
      name: result.name as string | undefined,
      expires_at: result.expires_at as number,
    };
  }

  async deleteUserSession(sessionId: string): Promise<void> {
    await this.db.prepare("DELETE FROM user_sessions WHERE session_id = ?").bind(sessionId).run();
  }

  // Client approvals for consent bypass
  async storeClientApproval(userId: string, clientId: string): Promise<void> {
    const expiresAt = Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60; // 30 days
    await this.db
      .prepare(
        `
			INSERT OR REPLACE INTO client_approvals (user_id, client_id, expires_at)
			VALUES (?, ?, ?)
		`,
      )
      .bind(userId, clientId, expiresAt)
      .run();
  }

  async isClientApproved(userId: string, clientId: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `
			SELECT 1 FROM client_approvals 
			WHERE user_id = ? AND client_id = ? AND expires_at > strftime('%s', 'now')
		`,
      )
      .bind(userId, clientId)
      .first();

    return !!result;
  }

  // Revoked tokens (track for the duration of their validity)
  async revokeRefreshToken(tokenId: string, expiresAt: number): Promise<void> {
    await this.db
      .prepare(
        `
			INSERT OR REPLACE INTO revoked_tokens (token_id, expires_at)
			VALUES (?, ?)
		`,
      )
      .bind(tokenId, expiresAt)
      .run();
  }

  async isTokenRevoked(tokenId: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `
			SELECT 1 FROM revoked_tokens 
			WHERE token_id = ? AND expires_at > strftime('%s', 'now')
		`,
      )
      .bind(tokenId)
      .first();

    return !!result;
  }

  // Registered clients (60 day inactivity expiration)
  async storeRegisteredClient(client: ClientRegistration): Promise<void> {
    await this.db
      .prepare(
        `
			INSERT INTO registered_clients (client_id, client_name, redirect_uris, scope, created_at, last_used, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`,
      )
      .bind(
        client.client_id,
        client.client_name,
        JSON.stringify(client.redirect_uris),
        client.scope,
        client.created_at,
        client.last_used,
        client.expires_at
      )
      .run();
  }

  async getRegisteredClient(clientId: string): Promise<ClientRegistration | null> {
    const result = await this.db
      .prepare(
        `
			SELECT * FROM registered_clients WHERE client_id = ? AND expires_at > strftime('%s', 'now')
		`,
      )
      .bind(clientId)
      .first();

    if (!result) return null;

    return {
      client_id: result.client_id as string,
      client_name: result.client_name as string,
      redirect_uris: JSON.parse(result.redirect_uris as string),
      scope: result.scope as string,
      created_at: result.created_at as number,
      last_used: result.last_used as number,
      expires_at: result.expires_at as number,
    };
  }

  async updateClientLastUsed(clientId: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + (60 * 24 * 60 * 60); // 60 days from now

    await this.db
      .prepare(
        `
			UPDATE registered_clients 
			SET last_used = ?, expires_at = ?
			WHERE client_id = ?
		`,
      )
      .bind(now, expiresAt, clientId)
      .run();
  }

  async isValidClient(clientId: string, redirectUri: string): Promise<boolean> {
    const client = await this.getRegisteredClient(clientId);
    if (!client) return false;

    return client.redirect_uris.includes(redirectUri);
  }

  // Cleanup expired records
  async cleanupExpired(): Promise<void> {
    const now = Math.floor(Date.now() / 1000);

    await this.db.batch([
      this.db.prepare("DELETE FROM authorization_codes WHERE expires_at < ?").bind(now),
      this.db.prepare("DELETE FROM refresh_tokens WHERE expires_at < ?").bind(now),
      this.db.prepare("DELETE FROM user_sessions WHERE expires_at < ?").bind(now),
      this.db.prepare("DELETE FROM client_approvals WHERE expires_at < ?").bind(now),
      this.db.prepare("DELETE FROM revoked_tokens WHERE expires_at < ?").bind(now),
      this.db.prepare("DELETE FROM registered_clients WHERE expires_at < ?").bind(now),
    ]);
  }
}

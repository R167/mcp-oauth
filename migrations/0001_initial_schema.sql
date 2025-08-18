-- Initial database schema for MCP OAuth Authorization Server
-- Authorization codes (10 minute TTL)
CREATE TABLE IF NOT EXISTS authorization_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    user_id TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    email TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Refresh token metadata (30 day TTL)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    email TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- User authentication sessions (30 minute TTL)
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    email TEXT,
    name TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Client consent approvals (30 day TTL)
CREATE TABLE IF NOT EXISTS client_approvals (
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (user_id, client_id)
);

-- Revoked tokens tracking
CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_id TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Registered OAuth clients (60 day inactivity expiration)
CREATE TABLE IF NOT EXISTS registered_clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    scope TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
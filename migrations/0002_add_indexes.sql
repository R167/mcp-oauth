-- Add performance indexes for all tables

-- Authorization codes indexes
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON authorization_codes(expires_at);

-- Refresh tokens indexes  
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);

-- User sessions indexes
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);

-- Client approvals indexes
CREATE INDEX IF NOT EXISTS idx_client_approvals_expires ON client_approvals(expires_at);

-- Revoked tokens indexes
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at);

-- Registered clients indexes
CREATE INDEX IF NOT EXISTS idx_registered_clients_expires ON registered_clients(expires_at);
CREATE INDEX IF NOT EXISTS idx_registered_clients_last_used ON registered_clients(last_used);
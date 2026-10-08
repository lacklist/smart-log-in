/*
# Create Session Workspace tables

1. New Tables
- `app_users` — custom user accounts (email + password hash) for the session vault.
  Not linked to Supabase auth; the edge function handles registration/login itself.
- `vaults` — one encrypted snapshot per user (envelope is AES-GCM ciphertext produced client-side).
- `auth_sessions` — server-issued bearer tokens (SHA-256 hashed) with 8-hour TTL.

2. Security
- RLS enabled on ALL tables with NO policies.
- This locks the tables so the anon key and authenticated users cannot read/write
  anything directly through the Supabase REST API.
- The edge function uses the service-role key, which bypasses RLS, to perform all
  database operations.  Authorization is enforced inside the function.

3. Important Notes
- `app_users` is intentionally separate from `auth.users` — the app runs its own
  credential flow (PBKDF2 password hashing, bearer-token sessions) inside the
  edge function.
- `vaults.envelope` stores a JSONB blob that is encrypted on the client; the
  server never sees the master password or plaintext cookies.
*/

CREATE TABLE IF NOT EXISTS app_users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT NOT NULL UNIQUE,
  salt          TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vaults (
  user_id    UUID PRIMARY KEY REFERENCES app_users(id) ON DELETE CASCADE,
  envelope   JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions(expires_at);

ALTER TABLE app_users    ENABLE ROW LEVEL SECURITY;
ALTER TABLE vaults       ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;

import pg from 'pg';

const { Pool } = pg;
pg.types.setTypeParser(1082, (value) => value);

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: process.env.VERCEL === '1' ? 1 : 5,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 5000
});

let schemaReady;

export async function ensureDatabase() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL не настроен.');
  schemaReady ||= pool.query(`
    CREATE TABLE IF NOT EXISTS trees (
      id UUID PRIMARY KEY,
      name VARCHAR(48) NOT NULL,
      planted_by VARCHAR(32) NOT NULL,
      planted_on DATE NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('planted', 'watered', 'established')),
      care_notes VARCHAR(1000) NOT NULL DEFAULT '',
      next_watering_on DATE
    );
    CREATE TABLE IF NOT EXISTS activity (
      id UUID PRIMARY KEY,
      tree_name TEXT NOT NULL,
      planted_by TEXT NOT NULL DEFAULT '',
      action TEXT NOT NULL,
      timestamp TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      username VARCHAR(32) NOT NULL UNIQUE,
      role TEXT NOT NULL CHECK (role IN ('admin', 'editor', 'viewer')),
      salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      password_parameters JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS activity_timestamp_idx ON activity(timestamp DESC);
    CREATE TABLE IF NOT EXISTS login_attempts (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      client_key TEXT NOT NULL,
      attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS login_attempts_lookup_idx ON login_attempts(client_key, attempted_at DESC);
  `).catch((error) => {
    schemaReady = undefined;
    throw error;
  });
  await schemaReady;
}
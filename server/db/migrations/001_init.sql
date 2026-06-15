-- SNR V3 — initial Postgres schema (ported from the V2 node:sqlite schema).
--
-- Type mapping rationale (chosen to preserve exact V2 behavior):
--   * epoch-millisecond timestamps  -> BIGINT  (code does Date.now() integer math)
--   * boolean/flag columns          -> INTEGER (code compares to 0/1)
--   * JSON blobs (result_json, tags, aliases, ...) -> TEXT (readers JSON.parse the
--     string; json functions cast ::jsonb inline where needed)
--   * case-insensitive email        -> plain TEXT + UNIQUE INDEX on LOWER(email)
--
-- All objects use IF NOT EXISTS so re-running is safe.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin','analyst','viewer')),
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  last_login_at BIGINT,
  disabled INTEGER NOT NULL DEFAULT 0,
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until BIGINT NOT NULL DEFAULT 0,
  password_changed_at BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users (LOWER(email));

CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS team_members (
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('lead','member')),
  joined_at BIGINT NOT NULL,
  PRIMARY KEY (team_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);

CREATE TABLE IF NOT EXISTS team_settings (
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (team_id, key)
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  incident_id TEXT,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  severity TEXT,
  audience TEXT,
  version INTEGER DEFAULT 1,
  input_hash TEXT,
  status TEXT DEFAULT 'pending',
  team_id TEXT REFERENCES teams(id),
  created_by TEXT REFERENCES users(id),
  tags TEXT DEFAULT '[]',
  deleted_at BIGINT
);
CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_team ON sessions(team_id);
CREATE INDEX IF NOT EXISTS idx_sessions_created_by ON sessions(created_by);
CREATE INDEX IF NOT EXISTS idx_sessions_deleted ON sessions(deleted_at);

CREATE TABLE IF NOT EXISTS session_inputs (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  input_type TEXT NOT NULL CHECK (input_type IN ('siem','log','text')),
  content TEXT NOT NULL,
  filename TEXT,
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_inputs_session ON session_inputs(session_id);

CREATE TABLE IF NOT EXISTS analysis_results (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  version INTEGER NOT NULL DEFAULT 1,
  result_json TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  analyst_overrides TEXT
);
CREATE INDEX IF NOT EXISTS idx_analysis_results_session ON analysis_results(session_id);

CREATE TABLE IF NOT EXISTS analyst_notes (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyst_notes_session ON analyst_notes(session_id);

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  timestamp BIGINT NOT NULL,
  analyst_name TEXT NOT NULL,
  user_id TEXT REFERENCES users(id),
  session_id TEXT,
  action TEXT NOT NULL,
  input_hash TEXT,
  outputs_generated TEXT,
  techniques_identified TEXT,
  details TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_session ON audit_log(session_id);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti TEXT PRIMARY KEY,
  revoked_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revoked_expires ON revoked_tokens(expires_at);

CREATE TABLE IF NOT EXISTS threat_actors (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  aliases TEXT DEFAULT '[]',
  motivation TEXT,
  attribution_confidence TEXT CHECK (attribution_confidence IN ('High','Medium','Low')),
  intrusion_set TEXT,
  campaign_name TEXT,
  malware_families TEXT DEFAULT '[]',
  description TEXT DEFAULT '',
  team_id TEXT REFERENCES teams(id),
  created_by TEXT REFERENCES users(id),
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threat_actors_team ON threat_actors(team_id);
CREATE INDEX IF NOT EXISTS idx_threat_actors_name ON threat_actors(LOWER(name));

CREATE TABLE IF NOT EXISTS session_threat_actors (
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  threat_actor_id TEXT NOT NULL REFERENCES threat_actors(id) ON DELETE CASCADE,
  link_type TEXT NOT NULL DEFAULT 'auto' CHECK (link_type IN ('auto','manual')),
  linked_at BIGINT NOT NULL,
  linked_by TEXT REFERENCES users(id),
  PRIMARY KEY (session_id, threat_actor_id)
);
CREATE INDEX IF NOT EXISTS idx_sta_threat_actor ON session_threat_actors(threat_actor_id);
CREATE INDEX IF NOT EXISTS idx_sta_session ON session_threat_actors(session_id);

CREATE TABLE IF NOT EXISTS threat_actor_merges (
  id TEXT PRIMARY KEY,
  source_actor_id TEXT NOT NULL,
  target_actor_id TEXT NOT NULL REFERENCES threat_actors(id),
  source_actor_name TEXT NOT NULL,
  merged_by TEXT REFERENCES users(id),
  merged_at BIGINT NOT NULL
);

-- Helper: extract a JSON array at `key` from a TEXT JSON blob and return its
-- elements as a set of jsonb. Mirrors SQLite's json_each(text, '$.key'); returns
-- no rows when the key is missing or not an array (instead of erroring).
CREATE OR REPLACE FUNCTION snr_json_array(txt text, key text)
RETURNS SETOF jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_array_elements(
    CASE WHEN txt IS NOT NULL AND jsonb_typeof((txt::jsonb) -> key) = 'array'
         THEN (txt::jsonb) -> key
         ELSE '[]'::jsonb END)
$$;

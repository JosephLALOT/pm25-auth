-- "auth" schema of the database "pm25", owned by pm25-auth (ADR 0009).
--
-- Applied as the owner user with golang-migrate and its own history table:
--   migrate -path db/migrations \
--     -database "$OWNER_DATABASE_URL&x-migrations-table=auth_schema_migrations" up
-- Privileges are granted afterwards by db/roles.sql of pm25-platform.
--
-- Other tables refer to users by id (audit_event.user_id,
-- collection_run.triggered_by) without a foreign key: a user is never deleted,
-- only deactivated.

CREATE SCHEMA auth;

CREATE TYPE auth.user_role AS ENUM ('user', 'admin');

-- Registered users of the website and the Android app
CREATE TABLE auth.user_account (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         text NOT NULL UNIQUE CHECK (email = lower(email)),  -- stored lower-case
  password_hash text NOT NULL,                                      -- argon2id, PHC string format
  display_name  text NOT NULL,
  role          auth.user_role NOT NULL DEFAULT 'user',
  is_active     boolean NOT NULL DEFAULT true,                      -- deactivated, never deleted
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz
);

-- Long-lived refresh tokens (the short-lived access JWT is never stored)
CREATE TABLE auth.refresh_token (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES auth.user_account(id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE,   -- SHA-256 of the opaque token sent to the client
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX refresh_token_user_idx ON auth.refresh_token (user_id);

-- Called every night by "pm25-auth purge"
CREATE FUNCTION auth.purge_expired_tokens(grace interval DEFAULT '7 days')
RETURNS bigint
LANGUAGE sql AS $$
  WITH deleted AS (
    DELETE FROM auth.refresh_token WHERE expires_at < now() - grace RETURNING 1
  )
  SELECT count(*) FROM deleted;
$$;

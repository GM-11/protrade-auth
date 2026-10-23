-- account ids start at 1000 so they never collide with the dev/bot accounts
-- already used in order_gateway/devkeys (1, 21, ...)
CREATE TABLE accounts (
  id            BIGINT GENERATED ALWAYS AS IDENTITY (START WITH 1000) PRIMARY KEY,
  email         TEXT        NOT NULL,            -- stored lower-cased and trimmed
  display_name  TEXT        NOT NULL,
  password_hash TEXT,                            -- NULL = no password login (Google-only)
  google_sub    TEXT,                            -- Google's stable user id
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX accounts_email_uq      ON accounts (email);
CREATE UNIQUE INDEX accounts_google_sub_uq ON accounts (google_sub) WHERE google_sub IS NOT NULL;

CREATE TABLE refresh_tokens (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  account_id  BIGINT      NOT NULL REFERENCES accounts(id),
  family_id   UUID        NOT NULL,              -- one login = one family; rotation keeps the family
  token_sha256 BYTEA      NOT NULL UNIQUE,       -- SHA-256 of the opaque token; the token itself is never stored
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL,              -- per-token expiry (REFRESH_TOKEN_TTL, default 30 d)
  family_expires_at TIMESTAMPTZ NOT NULL,        -- absolute cap for the whole login chain (default 90 d), copied to each rotated token
  used_at     TIMESTAMPTZ,                       -- set when rotated
  revoked_at  TIMESTAMPTZ
);
CREATE INDEX refresh_tokens_family_idx  ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_account_idx ON refresh_tokens (account_id);

-- server-issued, single-use nonces for the id_token shape of POST /v1/auth/google
CREATE TABLE google_nonces (
  nonce_sha256 BYTEA PRIMARY KEY,   -- SHA-256 of the nonce; the nonce itself is never stored
  expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX google_nonces_expires_idx ON google_nonces (expires_at);

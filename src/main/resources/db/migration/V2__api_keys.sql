CREATE TABLE api_keys (
  key_id        TEXT PRIMARY KEY,            -- "PK" + 16 base32 chars, same format as order_gateway/cmd/newkey
  account_id    BIGINT NOT NULL REFERENCES accounts(id),
  secret_sha256 CHAR(64) NOT NULL,           -- lower-case hex of SHA-256(secret)
  label         TEXT NOT NULL DEFAULT '',
  disabled      BOOLEAN NOT NULL DEFAULT false,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX api_keys_account_idx ON api_keys (account_id);

-- one row; the version the gateway polls on. Starts at 1 (the gateway rejects version < 1).
CREATE TABLE api_key_version (id BOOLEAN PRIMARY KEY DEFAULT true CHECK (id), version BIGINT NOT NULL);
INSERT INTO api_key_version VALUES (true, 1);

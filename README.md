# authentication

Auth + Accounts service of the trading game (contract: `../docs/api-contracts.md` §3.1 and §4.1).

**What it does**

- Creates accounts (`signup`), logs users in (password or Google), rotates refresh tokens, logs out.
- Signs the access tokens (JWT, EdDSA/Ed25519) and publishes the public keys at `/.well-known/jwks.json`.
- Issues API keys for bots and serves the key table the order gateway polls (`/internal/v1/api-keys`, internal port only).

**What it does not do**

- It is not on the trading hot path. The gateway fetches the JWKS and the key table by polling and verifies everything locally, so if this service is down, new logins stop but already-logged-in users keep trading.
- It does not call the cash owner. The cash owner creates the account on its first deposit.
- Not built yet (marked `later:` in the code): email verification, password reset, rate limiting (`429`), MFA, Apple sign-in, key-rotation automation, admin UI, account deletion.

## Access-token lifetime caveat

An access token that was already issued stays valid until it expires (at most 1 hour) even after `logout`, because the gateway checks tokens locally and never asks this service. That is the price of keeping it off the hot path, and it is why the lifetime is capped at 1 hour (the gateway rejects anything longer). `logout` revokes the refresh-token family, so no new access token can be obtained.

## Configuration

All settings are environment variables (mapped in `src/main/resources/application.yml`).

| Variable | Default | Meaning |
|---|---|---|
| `DB_URL` | `jdbc:postgresql://localhost:5432/authentication` | Postgres JDBC URL |
| `DB_USER` / `DB_PASSWORD` | `postgres` / `postgres` | Postgres credentials |
| `SERVER_PORT` | `8082` | public port (user API + JWKS) |
| `INTERNAL_PORT` | `8081` | internal port (`/internal/**` only); `0` disables it |
| `INTERNAL_BIND_ADDRESS` | `127.0.0.1` | address the internal port listens on. **In Docker or Kubernetes set `0.0.0.0`** (otherwise the gateway can't reach it) and keep the port off every public route |
| `JWT_ISSUER` | `protrader-identity` | `iss` claim; must equal the gateway's `JWT_ISSUER` |
| `JWT_AUDIENCE` | `order-gateway` | `aud` claim; must equal the gateway's `JWT_AUDIENCE` |
| `JWT_PRIVATE_KEY_FILE` | – | Ed25519 private key, PKCS#8 (PEM or bare base64). Required unless profile `dev` |
| `JWT_KID` | – | key id published in the JWKS; required with `JWT_PRIVATE_KEY_FILE` |
| `JWT_RETIRED_PUBLIC_KEYS_DIR` | – | directory of `*.json` / `*.jwk` public JWKs of old signers, still published and accepted (rotation without logging everyone out) |
| `ACCESS_TOKEN_TTL` | `1h` | startup fails if above 1 h |
| `REFRESH_TOKEN_TTL` | `30d` | lifetime of one refresh token |
| `REFRESH_FAMILY_MAX_TTL` | `90d` | absolute cap for one login chain, however active the user is |
| `REFRESH_REUSE_GRACE` | `10s` | a refresh token rotated this recently may be presented again (lost response / concurrent refresh); see below |
| `RATE_LIMIT_PER_IP_PER_MINUTE` | `20` | per client IP, per endpoint, on signup / login / refresh / google / google/nonce |
| `RATE_LIMIT_LOGIN_FAILURES_PER_EMAIL` | `5` | login attempts that fail, per lower-cased email, per window |
| `RATE_LIMIT_LOGIN_FAILURE_WINDOW` | `15m` | the window for the line above |
| `TRUSTED_PROXY_CIDRS` | – | comma list of proxy IPs / CIDRs whose `X-Forwarded-For` is believed; empty = never |
| `GOOGLE_CLIENT_ID` | – | Google web client id |
| `GOOGLE_CLIENT_SECRET` | – | Google web client secret (env / secret store only, never commit it) |
| `GOOGLE_ALLOWED_REDIRECT_URIS` | – | comma list, exact string match |
| `GOOGLE_EXTRA_AUDIENCES` | – | comma list of Android/iOS client ids; accepted only for the `id_token` request shape |
| `GOOGLE_DISCOVERY_URL` | Google's OpenID discovery URL | token endpoint and JWKS URI are read from it |
| `CORS_ALLOWED_ORIGINS` | – | comma list; empty = no CORS headers at all |

Profiles: `dev` (an ephemeral signing key is generated if none is configured; **kid changes on every restart and every token issued so far dies**, a loud WARN says so) and `prod` (refuses to start without a key). With no profile the service behaves like `prod`.

Make a signing key: `openssl genpkey -algorithm ed25519 -out jwt-key.pem` and set `JWT_PRIVATE_KEY_FILE=jwt-key.pem JWT_KID=2026-10-a`.

## Run locally

```sh
docker run -d --rm --name auth-pg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=authentication -p 5432:5432 postgres:17-alpine
DB_PASSWORD=pw ./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
./mvnw verify        # tests start their own Postgres through Testcontainers (needs Docker)
```

Flyway creates the schema on start (`src/main/resources/db/migration`).

## Try it

```sh
curl -s localhost:8082/v1/auth/signup -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","password":"correct horse","display_name":"Me"}'
# {"account_id":"1000"}

curl -s localhost:8082/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","password":"correct horse"}'
# {"access_token":"eyJ...","token_type":"Bearer","expires_in":3600,"refresh_token":"...","account_id":"1000"}

curl -s localhost:8082/v1/me -H "Authorization: Bearer $ACCESS"

curl -s localhost:8082/v1/auth/refresh -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REFRESH\"}"
# the old refresh token is now dead; use the new one. Presenting an old one again revokes the whole login.

curl -s -i localhost:8082/v1/auth/logout -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REFRESH\"}"
# 204 (also for unknown tokens, so it is safe to repeat)

curl -s localhost:8082/v1/api-keys -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' -d '{"label":"my bot"}'
# {"key_id":"PK...","secret":"...","label":"my bot","created_at":"..."}   <- the secret is shown once
```

## Pointing the order gateway at it

```sh
JWKS_URL=http://127.0.0.1:8082/.well-known/jwks.json \
JWT_ISSUER=protrader-identity \
JWT_AUDIENCE=order-gateway \
API_KEYS_SOURCE=http://127.0.0.1:8081/internal/v1/api-keys \
GATEWAY_ID=gw-1 ./order_gateway
```

The gateway polls the key table every 30 s, so a new or disabled API key takes up to 30 s to take effect.

> **Do not route port 8081 through the public load balancer.** `/internal/**` has no authentication (the gateway sends no credentials); the separate port is the protection. The public port answers 404 for `/internal/**` and the internal port answers 404 for everything else except `/healthz` and `/readyz`.
>
> The internal port listens on `127.0.0.1` by default. **In Docker or Kubernetes you must set `INTERNAL_BIND_ADDRESS=0.0.0.0`** for the gateway to reach it from another container or pod, and then keep 8081 off every public route (no Ingress rule, no public Service, no published port).

## Behaviour worth knowing

- Wrong email and wrong password give the same `401 bad_credentials` body, after the same amount of BCrypt work.
- Refresh tokens rotate on every use. Presenting a token that was already rotated:
  - **within `REFRESH_REUSE_GRACE` (10 s) of the rotation** is treated as a retry after a lost response, or the loser of two simultaneous refreshes: it gets a fresh sibling token in the same family, nothing is revoked, both descendants stay valid;
  - **after the window** is treated as a stolen copy: the whole family is revoked and the answer is `401 bad_refresh_token`.

  The trade-off: a thief who replays a stolen token *inside* the 10 s window is not detected, and gets a working token of their own. We accept that because the thief would need the token within seconds of its rotation, while without a window every dropped response (mobile networks, a closed tab, two tabs refreshing together) would log the user out. Set `REFRESH_REUSE_GRACE=0s` for strict single-use.
- Rate limits (`429 rate_limited`, with `Retry-After` in seconds), checked before any BCrypt work:
  - per client IP, per endpoint, 20 requests a minute on `signup`, `login`, `refresh`, `google` and `google/nonce` (a token bucket);
  - on `login` only, additionally 5 *failed* attempts per lower-cased email per 15 minutes (the same bucket for existing and unknown emails). A successful login gives its attempt back. The account is never locked: once the bucket refills, the right password works again.
  - **The state is per instance, in memory.** With N instances behind a load balancer, the effective limits are up to N times higher, and a restart forgets everything. Idle entries are evicted and the maps are size-bounded.
  - The client IP is the socket peer. `X-Forwarded-For` is read only when the peer is inside `TRUSTED_PROXY_CIDRS` (empty by default), taking the right-most entry that is not itself a trusted proxy. IPv6 clients are limited per /64. Behind a load balancer you must set `TRUSTED_PROXY_CIDRS`, otherwise every user shares the balancer's bucket.
- Signing in with Google for an email that already has a password account links the Google identity to it, **removes the password and revokes that account's refresh tokens**. Signup does not verify email ownership yet, so without this an attacker could pre-register someone's address with a password they know.
- **Access tokens already issued survive the Google link.** The link drops the password and revokes the refresh tokens, but an access token someone obtained with the old password stays valid for up to 1 hour (the gateway verifies tokens locally and never calls us).
- A Google identity whose email belongs to an account already linked to a *different* Google identity is refused (`401`), never taken over.
- Request handling mirrors the gateway: `415 content_type_must_be_json`, `413 request_too_large` (16 KB), `400 invalid_json` (unparseable or unknown field), `400 malformed_json` (data after the JSON object). Every error is `{"error":...}` JSON.
- Expired refresh-token rows are deleted daily (at 03:17), 7 days after expiry.

## Google sign-in

### Create the OAuth clients

In Google Cloud Console, project → APIs & Services → Credentials:

1. **Web client** (type "Web application"). Add each redirect URI your SPA/mobile redirect page uses under *Authorized redirect URIs*, e.g. `https://app.example.com/auth/callback`. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` from it, and list the same URIs in `GOOGLE_ALLOWED_REDIRECT_URIS` (exact match, no wildcards).
2. **Android / iOS clients** (only if the apps use the native Google Sign-In SDK and send an ID token): put their client ids in `GOOGLE_EXTRA_AUDIENCES`. They are accepted only on the `id_token` request shape.

Scopes: `openid email profile` only. We do not request offline access.

### `POST /v1/auth/google`

Two request shapes, exactly one of them:

```json
{"code":"4/0A...","code_verifier":"<43-128 chars>","redirect_uri":"https://app.example.com/auth/callback"}
{"id_token":"<Google ID token>","nonce":"<from POST /v1/auth/google/nonce>"}
```

**The `id_token` shape needs a server-issued nonce** (a nonce the client picks proves nothing about freshness, so it can't stop a stolen ID token being replayed):

1. `POST /v1/auth/google/nonce` (no auth, no body) returns `{"nonce":"<32 random bytes, base64url>","expires_in":300}`. Only its SHA-256 is stored.
2. The app passes that nonce to Google's sign-in as the `nonce` parameter, so it ends up in the ID token's `nonce` claim.
3. The app sends `{"id_token", "nonce"}`. We burn the nonce atomically *before* looking at the token (unknown, expired or already used gives `401 bad_credentials`), then require the token's `nonce` claim to equal it. A missing `nonce` is `422 invalid_field` with `field:"nonce"`.

Each nonce works once and expires after 5 minutes. The code + PKCE shape is unchanged (the code is single-use by itself).

The answer is the same as login. Errors: `422 invalid_field` (+`field`), `401 bad_credentials` for anything Google or our checks reject (never says why), `503 google_unavailable`.

### Worked web example (authorization code + PKCE)

```js
// 1. make verifier, challenge, state, nonce; keep verifier + state in sessionStorage
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const rand = (n) => b64url(crypto.getRandomValues(new Uint8Array(n)));

const verifier = rand(48);                                  // 64 chars, within 43-128
const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
const state = rand(16), nonce = rand(16);
sessionStorage.setItem('pkce', JSON.stringify({ verifier, state, nonce }));

// 2. send the user to Google
location = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
  client_id: GOOGLE_CLIENT_ID,
  redirect_uri: 'https://app.example.com/auth/callback',
  response_type: 'code',
  scope: 'openid email profile',
  code_challenge: challenge,
  code_challenge_method: 'S256',
  state,
  nonce,
});

// 3. on /auth/callback?code=...&state=...  (the SPA checks state: that is the CSRF defence)
const q = new URLSearchParams(location.search);
const saved = JSON.parse(sessionStorage.getItem('pkce'));
if (q.get('state') !== saved.state) throw new Error('state mismatch');

const res = await fetch('https://auth.example.com/v1/auth/google', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    code: q.get('code'),
    code_verifier: saved.verifier,
    redirect_uri: 'https://app.example.com/auth/callback',
  }),
});
const { access_token, refresh_token, account_id } = await res.json();
```

Our server then exchanges the code with Google (with the client secret and the verifier), validates the returned ID token (signature against Google's JWKS, `iss`, `aud`, expiry, `sub`, `email_verified`) and signs the user in. The `nonce` in the ID token was created by the SPA, so the SPA checks it; we only check a nonce sent with the `id_token` shape.

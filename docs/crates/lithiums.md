# lithiums: the Lithium relay server

The REST server for the Lithium messenger, built on the Poem 
framework with a PostgreSQL database (via SeaORM). The server is 
openly **untrusted**, it stores and forwards encrypted data, never 
decrypts message content, and has no access to clients' private 
keys.

## Place in the architecture

```
lithiumg (GUI)
  | IPC
lithiumd (client daemon)          uses lithiums as the relay
  | HTTPS + KyberBox (X25519 + ML-KEM-1024)
lithiums (relay server)   <- this crate
  - PostgreSQL: user records + message queuing
  - EphemeralStoreManager: in-memory TTL cache (session keys, JWT, limits, replay)
  - KeyManager<PlainFileMkProvider>: the server's signing/encryption keys
```

```
src/
  main.rs               entry point: env vars, KeyManager, DB, MkRotator, the Poem server
  lib.rs                route table, wiring CryptoMiddleware + GuardMiddleware
  state.rs              AppState (shared across handlers)
  error.rs              AppError -> HTTP response
  mk_rotator.rs         background MK rotation task
  transport/
    mod.rs            CryptoMode, AuthMode, JWT, limits, request decryption, response encryption
  middleware/
    crypto.rs         CryptoMiddleware (decryption/authentication per route)
    guard.rs          GuardMiddleware (size limits, anti-replay, IP rate limiting)
  api/
    handshake.rs      POST /shake
    user.rs           POST /user/register, POST /user/login
    messages.rs       POST /msg/send, POST /msg/fetch
  db/
    mod.rs            PostgreSQL connection from DATABASE_URL
    models.rs         SeaORM entity definitions (users, messages)
    repo.rs           ServerDbExt: DB operations with envelope encryption
```

## Configuration

`lithiums` listens on plain HTTP. TLS is terminated by a reverse 
proxy (nginx, Caddy, etc.) placed in front of the process. The 
default bind `127.0.0.1` assumes the proxy runs on the same host.

All configuration is through environment variables (`.env` support 
via `dotenvy`):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_HOST` | yes | - | PostgreSQL host |
| `DB_PORT` | no | `5432` | PostgreSQL port |
| `DB_USER` | yes | - | Database user |
| `DB_PASSWORD_FILE` | yes | - | Path to the password file (Docker secret) |
| `DB_NAME` | yes | - | Database name |
| `DB_MAX_CONNECTIONS` | no | `20` | Max connections in the pool |
| `DB_MIN_CONNECTIONS` | no | `2` | Min connections kept |
| `LITHIUM_KEYS_DIR` | no | `/var/lib/lithiums` | Directory for key files and server.identity |
| `LITHIUM_BIND` | no | `127.0.0.1` | Listen address |
| `LITHIUM_PORT` | no | `4108` | Listen port |
| `LITHIUM_MK_ROTATE_SECS` | no | `3600` | MK rotation interval in seconds |
| `LITHIUMS_SEND_POW_BITS` | no | `18` | Proof-of-work difficulty (leading zero bits) on `/msg/send` |

The master key providers (`LITHIUM_MK_PROVIDER`) and the TPM 
variables are in 
[deploy-instructions.md](../operations/deploy-instructions.md).

Other pool parameters: connect/acquire timeout 10 s, idle timeout 
600 s, max connection lifetime 1800 s.

## Startup sequence

1. Parse and validate the environment variables
2. Load/initialize `KeyManager<PlainFileMkProvider>` from 
   `LITHIUM_KEYS_DIR` (on the first run it generates new keys)
3. Start the `MkRotator` task in the background (a 30 s tick, 
   rotates if `LITHIUM_MK_ROTATE_SECS` has passed)
4. Connect to PostgreSQL (`DATABASE_URL`), call 
   `DataManager::init()` (migrations, database DEK initialization)
5. Build `AppState`, register the Poem routes, start the HTTP 
   server

## State (`AppState`)

```rust
pub struct AppState {
    pub key_manager: Arc<Mutex<KeyManager<PlainFileMkProvider>>>,
    pub store: EphemeralStoreManager,
    pub db: Arc<DataManager<PlainFileMkProvider>>,
}
```

- **`key_manager`**, the server's long-term keys: X25519, 
  ML-KEM-1024, Ed25519, ML-DSA-87; accessed through a `Mutex`; used 
  to decrypt requests (Shake mode) and sign responses
- **`store`**, an in-memory TTL cache built on a `BTreeMap` with 
  automatic expiry and value zeroization on drop; used for session 
  keys, JWT tokens, rate-limit counters, anti-replay hashes, and 
  message decryption keys
- **`db`**, a `DataManager` wrapping the PostgreSQL connection; 
  handles envelope encryption of DB blobs using the server-managed 
  DEK

## API routes

All routes are wrapped in `GuardMiddleware` (outer) and a 
per-route `CryptoMiddleware`.

| Method | Path | Crypto mode | Auth mode | Description |
|--------|------|-------------|-----------|-------------|
| GET | `/` | - | - | Greeting |
| GET | `/health` | - | - | Health check (reaper and MK rotation status) |
| POST | `/shake` | Shake | KeysInHeaders | Session key exchange |
| POST | `/user/register/start` | Session | KeysInHeaders | OPAQUE registration, phase 1 |
| POST | `/user/register/finish` | Session | KeysInHeaders | OPAQUE registration, phase 2 |
| POST | `/user/login/start` | Session | LoginByHandler | OPAQUE login, phase 1 |
| POST | `/user/login/finish` | Session | LoginByHandler | OPAQUE login, phase 2 (JWT + DEK) |
| POST | `/user/revoke` | Session | KeysInHeaders | Account deletion by capability (no login) |
| POST | `/user/delete` | Session | JwtUser | Account deletion by a logged-in user |
| POST | `/msg/send` | Session | KeysInHeaders | Send a message (anonymous, + PoW) |
| POST | `/msg/fetch` | Session | KeysInHeaders | Fetch and delete pending messages |

---

## Middleware layer

Every request passes through two middleware layers:

### GuardMiddleware (outer)

Applied globally to all routes. It runs **before** any 
cryptographic processing.

1. **Pre-replay rate limiting per IP**, checks the per-IP lock key 
   in `EphemeralStore`; if locked, `429 Too Many Requests`
2. **Body size check**, rejects bodies over 1 MB
3. **Header size check**, rejects total header data over 1 MB
4. **Pre-replay counter increment**, increments the per-IP failure 
   counter (window: 10s); activates exponential backoff once the 
   threshold (200 hits) is exceeded:
   ```
   backoff = min(5s * 2^(hits - 200), 60s)
   ```
5. **Anti-replay check**, computes `SHA256(raw_body_bytes)`, calls 
   `store.set_if_absent` with TTL = 600s; if the hash already 
   exists, `400 replay_detected`
6. Stores the raw body in the request extensions as `CipherBody` 
   for `CryptoMiddleware`

### CryptoMiddleware (per route)

Each route has its own instance configured by `CryptoCfg` with a 
`CryptoMode` and an `AuthMode`.

It calls `build_crypto_context`, which:
1. Extracts all headers (lowercase)
2. Decrypts the body according to `CryptoMode`
3. Parses the decrypted JSON body
4. Validates the `ts` (timestamp) header: must be within +/-60s of 
   the server clock
5. Verifies the dual signature (Ed25519 + ML-DSA-87) over the raw 
   bytes of the decrypted JSON
6. Applies `AuthMode` to fill in `ctx.user`
7. Injects `CryptoContext` into the request extensions as 
   `CryptoReq`

---

## Transport layer

### Crypto modes

The server implements the two transport modes described in 
[crypto-protocol.md](../protocol/crypto-protocol.md#transport-layer-daemon-server), 
**Shake** (session init, the client's ephemeral keys in headers, 
TTL 60 s) and **Session** (after Shake, the `ses-x`/`ses-k` 
identifiers, TTL 120 s). The server specifics: the private session 
keys are held in `EphemeralStoreManager` under random `ses-x`/`ses-k` 
identifiers, and after each response new pairs are generated 
(rolling session).

### Authentication modes

| Mode | Behavior |
|------|----------|
| `KeysInHeaders` | Extracts the client's public keys from the headers (`key-ed`, `key-dili`); `ctx.user` is `None` |
| `LoginByHandler` | Reads `handler` from the decrypted body, loads `UserRecord` from the DB; `ctx.user` is set. The password is **not** verified here, the OPAQUE flow in the login handler does that; the server never sees the password or its hash |
| `JwtUser` | Reads the `token` field from the decrypted body (the JWT hex-encoded), validates the HS256 signature, calls `store.take` (one-time), loads the user by user_id; `ctx.user` is set |

### Request headers (cleartext HTTP)

| Header | Description |
|--------|-------------|
| `key-x` | The client's ephemeral X25519 public key (hex), for the server to decrypt with |
| `key-k` | The client's ephemeral ML-KEM-1024 public key (hex), for the server to decrypt with |
| `seed` | The encrypted KEM seed |
| `data` | The blob of encrypted application headers (KyberBox) |
| `ses-x` | A random X25519 session identifier (hex), private-key lookup in EphemeralStore; Session mode only |
| `ses-k` | A random ML-KEM-1024 session identifier (hex), private-key lookup in EphemeralStore; Session mode only |

The fields `key-ed`, `key-dili`, `sig-ed`, `sig-dili` are carried 
in the **encrypted application headers** (`data`), not in 
cleartext. The `timestamp` field is carried in the **encrypted 
JSON body**. The `token` field (JWT hex) is carried in the body 
(only in `JwtUser` mode).

### Response headers

After successful processing, `reply_ok` / `reply_ok_authed` 
generates the response:

1. Generates new X25519 + ML-KEM-1024 session key pairs and random 
   `session_x_id`, `session_k_id` identifiers (32 random bytes 
   each); stores the private keys in `EphemeralStore` under those 
   identifiers with the session TTL
2. Puts the identifiers (`ses-x`, `ses-k`) in the JSON headers 
   encrypted by KyberBox, the client reads them after decryption 
   and sends them back in the headers of the next request
3. Dual-signs the encrypted response body with the server's 
   Ed25519 + ML-DSA-87 keys
4. Pads the body (to a 32-64 KB block) and the headers (to a 4-8 KB 
   block) to hide sizes
5. Sets the cleartext HTTP response headers: `sig-ed`, `sig-dili`, 
   `data` (the encrypted-headers blob), `seed` (the encrypted KEM 
   seed), `key-x` (the new session's X25519 public key, the client 
   encrypts the next request to it), `key-k` (the new session's 
   ML-KEM-1024 public key)

### JWT

- Algorithm: HS256
- The `sub` field: `hex(HMAC-SHA256(user_id_bytes, 
  random_seed_bytes))`, an opaque identifier not directly linked 
  to the handler
- The token is stored in `EphemeralStore` under the HMAC `sub` 
  value with `session_ttl`
- The token is **one-time**, `get_user_from_token` uses 
  `store.take` (removes it after the first use)
- The token is hex-encoded before being placed in the JSON 
  response body (the `tok_hex` field)

### Rate limiting (transport layer)

All counters are stored in `EphemeralStoreManager`.

#### Login (`/user/login/start`)

| Parameter | Value |
|-----------|-------|
| Failure window | 15 minutes |
| Max failures before lock | 5 |
| Base backoff | 30 seconds |
| Backoff formula | `30s * 2^(failures - 1)` |
| Max backoff | 15 minutes |

Store keys: `login:fail:{handler}`, `login:lock:{handler}`

#### Registration (`/user/register/start`)

| Parameter | Value |
|-----------|-------|
| Failure window | 1 hour |
| Max failures before lock | 3 |
| Lock time | 1 hour |

A registration failure is an attempt to take an already existing 
handler. A success resets the counters.

Store keys: `reg:fail:{handler}`, `reg:lock:{handler}`

---

## Database

### Schema

#### `users` table

| Column | Type | Description |
|--------|------|-------------|
| `id` | `BYTEA` PK | The deterministically encrypted UUID v5 of the normalized handler |
| `opaque_record` | `BYTEA` | OPAQUE record (envelope), encrypted with the server DEK |
| `ed_key` | `BYTEA` | The client's Ed25519 public key (raw bytes), encrypted with the server DEK |
| `dili_key` | `BYTEA` | The client's ML-DSA-87 public key (raw bytes), encrypted with the server DEK |
| `dek` | `BYTEA` | The client-side DEK (hex string), encrypted with the server DEK |
| `delete_token_hash` | `BYTEA` | `SHA256(remote_delete_capability)`, the lookup key for `/user/revoke` (not DEK-encrypted) |

#### `messages` table

| Column | Type | Description |
|--------|------|-------------|
| `id` | `BIGINT` auto-increment PK | Message ID |
| `mailbox` | `BYTEA` | The mailbox address (16 or 32 bytes) |
| `content` | `BYTEA` | The encrypted message blob (`ver(1) \| nonce(12) \| AES-256-GCM-SIV ciphertext`) |
| `expires_at` | `TIMESTAMPTZ` | Expiry time (TTL = 24 hours from insertion) |

### User lookup path

```
handler string
  -> normalize (trim + lowercase)
  -> UUID v5(db_namespace, normalized_handler)
  -> id_enc: AES-256-GCM-SIV(uuid_bytes, db_dek, nonce=HKDF(uuid, dek, label), aad="user-idenc/v1")
  -> PK lookup in the users table
```

User IDs are encrypted **deterministically**, the nonce is derived 
by `HKDF(uuid_bytes, key=db_dek, info=UIDENC_NONCE_LABEL)`, so the 
same handler always maps to the same ciphertext. This enables 
indexed PK lookup without storing the plaintext identifiers. The 
trade-off is the equality observability of user IDs across DB 
snapshots.

### User field encryption

Each user field in the DB is individually sealed under the server 
DEK by `DataManager::encrypt_db_blob` / `decrypt_db_blob`. Each 
field uses a separate constant AAD:

| Field | AAD |
|-------|-----|
| `opaque_record` | `"user-opaque-record/v1"` |
| `ed_key` | `"user-ed-key/v1"` |
| `dili_key` | `"user-dili-key/v1"` |
| `dek` | `"user-dek/v1"` |

### Message encryption

Messages use a **random key per message** (`random_32()`) instead 
of the global database DEK:

1. On `add_message`: generates a random `msg_key`, seals the 
   content with `AES-256-GCM-SIV(content, msg_key, 
   AAD="message-content/v1" || mailbox_bytes)`, stores the 
   encrypted blob in the DB; saves `msg_key` in `EphemeralStore` 
   under the key `message_id.to_string()` with TTL = 24h
2. On `get_messages`: fetches and **deletes** rows in one `SELECT 
   FOR UPDATE SKIP LOCKED` + `DELETE` transaction; for each row 
   calls `store.take(message_id)` to fetch and remove the key; 
   decrypts the blob

**Consequence**: a server process restart destroys all message 
keys in `EphemeralStore`, and stored messages become permanently 
undecryptable (ephemeral key forward-secrecy at the relay level). 
The server can't read message content even during normal 
operation, because the content is encrypted by the client before 
it reaches the server.

### Atomic one-time message fetch

Fetch runs inside a DB transaction with `SELECT FOR UPDATE SKIP 
LOCKED`:
- Only one concurrent fetcher can take a given mailbox's messages
- All fetched messages are deleted within the same transaction
- Messages past `expires_at` are filtered out before selection
- Returned to the client as an array of hex-encoded blobs

---

## API handler details

### `GET /`

No cryptographic processing. Returns:
```json
{"message": "Welcome to Lithium, real private messenger"}
```

### `POST /shake`

Performs a key exchange in Shake mode. The handler itself does 
nothing beyond calling `reply_ok`. Its only purpose is to give the 
client new session key pairs (`key-x`, `key-k`) in the response, 
used afterwards for Session-mode requests.

### `POST /user/register/start` + `/user/register/finish`

OPAQUE registration is two-phase, the server **never** sees the 
password or its hash; it stores only the OPAQUE record.

Body fields (start): `handler`, `flow`, the OPAQUE material 
(`RegistrationRequest`).
Body fields (finish): `handler`, `flow`, `opaque` 
(`RegistrationUpload`), `dek`, the hex-encoded client DEK blob 
wrapped under the OPAQUE `export_key` (opaque to the server; stored 
encrypted and returned at login).

Request headers (besides the transport ones): `key-ed`, `key-dili` 
(the client's long-term signing public keys, the server stores 
them in `users`).

Behavior (finish phase):
1. Checks the registration limit
2. Validates the OPAQUE material and that `dek` is valid hex
3. Calls `create_user` (stores the `opaque_record`, the keys, the 
   wrapped `dek`); if the handler already exists, it increments the 
   failure counter and returns success (no handler-enumeration 
   leak)
4. On success: resets the counter

Response: `{"msg": "Ok"}` (no JWT on registration)

### `POST /user/login/start` + `/user/login/finish`

OPAQUE login is two-phase. The `LoginByHandler` auth mode loads the 
`UserRecord` from the DB before the handler runs.

Body fields (start): `handler`, `flow`, the OPAQUE material 
(`CredentialRequest`).
Body fields (finish): `handler`, `flow`, `opaque` 
(`CredentialFinalization`).

Behavior (finish phase):
1. Checks the login limit
2. Finishes the OPAQUE flow; a failure (wrong password or unknown 
   user) increments the counter and returns `401 invalid_credentials`, 
   the same code for both cases, no leak of user existence
3. On success: resets the counter, issues a JWT through 
   `reply_ok_authed(session_ttl=120)`

Response body: `{"msg": "Ok", "dek": "<client_dek_hex>", "tok_hex": 
"<jwt_hex>"}` plus new session key pairs in the response headers.

The `dek` field holds the client's wrapped DEK registered earlier, 
the server stores and returns it but never uses it.

### `POST /msg/send`

Auth `KeysInHeaders`, anonymous, **no** JWT (sending isn't tied to 
an account identity). Requires proof-of-work.

Request body fields:
- `mailbox`, the hex-encoded mailbox address (after decoding it 
  must be 16 or 32 bytes)
- `content`, the hex-encoded message blob (already encrypted by 
  the client)
- `pow`, the proof-of-work nonce; the server computes `challenge = 
  SHA256("lithium/send-pow/v1" || u32_le(len(mailbox)) || mailbox 
  || content)` and requires `leading_zero_bits(SHA256(challenge || 
  u64_le(nonce))) >= LITHIUMS_SEND_POW_BITS` (18 by default). A 
  failed PoW gives `400 invalid_pow`.

The `content` blob is opaque to the server, the server wraps it in 
an extra encryption layer (a random key per message) and stores it 
in the `messages` table.

TTL: 24 hours.

Response: `{"msg": "Message sent"}`

### `POST /msg/fetch`

Uses `KeysInHeaders` auth (no JWT required, the mailbox address 
serves as the capability).

Request body fields:
- `mailbox`, the hex-encoded mailbox address (16 or 32 bytes)

Returns all pending, non-expired messages for the mailbox and 
deletes them atomically. Messages are returned as an array of hex 
strings (the original blobs encrypted by the client).

Response: `{"msg": "Ok", "data": ["<hex>", ...]}`

---

## MK rotation

The `MkRotator` task runs in the background for the whole life of 
the server:

- Wakes every **30 seconds** and calls `km.maybe_rotate_mk()`
- `maybe_rotate_mk()` checks the time; if `LITHIUM_MK_ROTATE_SECS` 
  (3600s by default) has passed, it rotates the master key
- Rotation uses `PlainFileMkProvider`: the keys are stored as plain 
  files in `LITHIUM_KEYS_DIR` (no password encryption on the server 
  side, the key directory must be protected at the OS/filesystem 
  level)
- An MK rotation **rewraps the DEK file** (re-encrypts the DEK 
  under the new MK); existing data in the DB is **not** 
  re-encrypted, because the DEK value stays the same
- `MkRotatorHandle` holds a `watch::Sender<bool>` for a graceful 
  stop

---

## Error responses

All errors return JSON:
```json
{"ok": false, "error": "<error_code>"}
```

Server errors (5xx) are logged at the `ERROR` level with the full 
source chain. Client errors (4xx) are logged at the `WARN` level.

| Code | Meaning |
|------|---------|
| 400 `invalid_body` | Malformed request body |
| 400 `replay_detected` | An exact body repeat within the 600s window |
| 400 `body_too_large` | The body exceeds 1 MB |
| 400 `headers_too_large` | Total header data exceeds 1 MB |
| 400 `invalid_dek` | The `dek` field is not valid hex |
| 400 `invalid_mailbox` | The mailbox is neither 16 nor 32 bytes |
| 400 `invalid_content` | The `content` field is not valid hex |
| 400 `invalid_pow` | Missing or wrong proof-of-work nonce (`/msg/send`) |
| 401 `invalid_credentials` | OPAQUE login failed (wrong password or unknown user) |
| 429 `try_later` | Rate limiting (login/registration/pre-replay) |
| 500 `internal_error` | An unexpected server-side error |
| 500 `db_error` | A database operation error |

---

## Security model

The global "server as a hostile relay" model (what the server sees 
per request, what is protected from it) is in 
[security-model.md](../security-model.md). The server-specific 
mechanisms that implement it:

- **Anti-replay**, the body SHA256 stored for 600 s; the +/-60 s 
  timestamp window rejects repeats and stale requests.
- **One-time JWT**, the token is consumed on use (`store.take`), 
  no replay of authenticated requests.
- **Opaque `sub`**, `HMAC-SHA256(user_id, random_seed)` instead of 
  a raw ID in the JWT.
- **DB field isolation**, each user field under a separate AAD; a 
  DEK with the wrong AAD won't decrypt another field.
- **Size padding**, response bodies and headers padded to blocks 
  to hide lengths.

What the server doesn't have and doesn't see: clients' private 
keys, content plaintext (the E2E layer), and, after a one-time 
fetch or a restart, `msg_key` (pending messages then become 
permanently undecryptable).

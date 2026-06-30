# Lithium daemon IPC reference

The `lithiumd` daemon exposes a local IPC endpoint that lets the 
GUI (or another client) drive all cryptographic operations. The 
private keys exist only on the daemon side.

## Transport

- **Linux / macOS**: a Unix socket, default 
  `{XDG_RUNTIME_DIR}/lithiumd.sock`, permissions `0o600`
- **Windows**: a named pipe, default `\\.\pipe\lithiumd`, 
  `reject_remote_clients(true)`

Protocol: **JSON-lines**, one request = one JSON line ending in 
`\n`, one response = one JSON line ending in `\n`.

Maximum line size: **4 MiB** (`IPC_MAX_LINE_BYTES`). Exceeding it 
closes the connection.

Idle timeout: **300 seconds** (default; configurable via 
`LITHIUMD_IPC_IDLE_TIMEOUT_SECS`, min 5).

Maximum number of parallel connections: **1** (default; 
configurable via `LITHIUMD_IPC_MAX_CONNECTIONS`, min 1). An excess 
connection is rejected at `accept` (the client gets no response, 
on the client side it looks like an immediate EOF/reset).

## Request format

```json
{
    "id": 1,
    "auth_token": "hex_token_64_chars",
    "cmd": "command_name",
    ...command fields...
}
```

- `id`, any integer; the response returns the same `id`. On a JSON 
  parse error (`bad_json`) the response returns `id: 0`, because 
  the request wasn't read yet.
- `auth_token`, required for most commands; omitted (or `null`) for 
  `ping`, `unlock_keystore`, `remote_delete`, `set_server_identity`, 
  `set_server_url`
- `cmd`, the command name (snake_case, matching the `IpcCommand` 
  variants in `lithiumd/src/ipc/types.rs`)

## Response format

```json
{
    "id": 1,
    "ok": true,
    "result": { ... },
    "error": null
}
```

On error:
```json
{
    "id": 1,
    "ok": false,
    "error": "error_code"
}
```

`result` and `error` are omitted from the JSON when `None` 
(`skip_serializing_if`), not serialized as `null`.

## IPC authorization

These work without a token: `ping`, `unlock_keystore`, 
`remote_delete`, `set_server_identity`, `set_server_url` 
(`cmd_requires_auth` in `lithiumd/src/ipc/mod.rs`). All other 
commands need an `auth_token` in every request.

The session token is emitted after a successful `unlock_keystore` 
as the `ipc_auth_token` field, added to that response's `result`. 
The token = 64 hex characters (32 random bytes). It is issued on 
**every** successful `unlock_keystore`, including when the 
keystore was already unlocked and the same password was given 
again.

On **Linux** the token is additionally bound to the client's UID 
and PID (read via `SO_PEERCRED`). Requests from a different PID or 
UID return `ipc_auth_failed`. The token comparison is 
constant-time (`subtle::ConstantTimeEq`).

The token is invalidated by `lock_keystore` and `wipe_local`.

### Authorization error codes

| Code | Meaning |
|------|---------|
| `ipc_auth_required` | No token (empty or `null`) or no active session |
| `ipc_auth_failed` | Wrong token or mismatched UID/PID |
| `ipc_auth_issue_failed` | Only after `unlock_keystore`: failed to generate a token (`random_32` failed) |

### LITHIUMD_IPC_ALLOWED_UID

Independently of the session token, on Linux 
`LITHIUMD_IPC_ALLOWED_UID` limits who can even open a connection. 
The check happens **before** any line is read, a connection from a 
disallowed UID is simply dropped (`continue` in the `accept` loop 
in `lithiumd/src/ipc/unix.rs`), the client gets no JSON response, 
not `ipc_auth_failed`, not anything else. This is a different 
denial mechanism than the auth token errors above.

## Daemon state

The daemon moves through a sequence of states. Commands called out 
of order return an error.

```
start
  -> set_server_url (required first, unlock_keystore returns server_url_not_set without it)
  -> set_server_identity (not blocked by daemon state, but without it every network request
     to the server fails anyway, so in practice done at the same moment as set_server_url)
  -> keystore_locked (ui_state=keystore_locked)
  -> unlock_keystore
  -> ipc_auth_token emitted, ui_state=needs_credentials
  -> set_credentials (required after every unlock_keystore, credentials are memory-only)
  -> ui_state=needs_register (if needs_register) or storage_locked
  -> [register] (only when needs_register=true)
  -> unlock_storage
  -> ui_state=ready, contact commands available
```

`set_server_url` and `set_server_identity` aren't part of the 
state driven by `ui_state` (they have no phase of their own in 
`ui_state`), `ping.status.has_server_url`/`has_server_identity` 
exist as separate, independent flags. The client (for example the 
`lithiumg` GUI) must check them itself and ask the user for the 
URL/identity before calling `unlock_keystore`, otherwise it gets 
`server_url_not_set`. `lithiumg` does it exactly in this order, 
the first two onboarding screens are "Server URL" and "Server 
identity", before the keystore password screen appears.

Even though those two steps are adjacent in onboarding, they are 
two independent inputs from disjoint sources: `set_server_url` 
takes an address typed by the user (used only to open the HTTP 
connection), and `set_server_identity` takes the bytes of a file 
the user must get over an out-of-band channel from the server 
operator and pick manually from disk (`server_identity_path` + 
`Browse...` in the GUI). The daemon never fetches the `data` for 
`set_server_identity` itself, not from the address set by 
`set_server_url`, not from any other network address, there is no 
endpoint for automatically distributing the server identity and 
there won't be one. This is deliberate, automatic fetching of a 
new identity would let the operator (or someone who took over the 
server) swap the server keys without the user's knowledge.

`ping` returns the current state in all phases, see the full 
description of the `status` field below.

## Commands

### `ping`

No authorization.

```json
{ "id": 1, "cmd": "ping" }
```

Response, returns the raw state (`status`), the synthesized phase 
(`ui_state`), and the list of commands the client should call now 
(`actions_needed`):

```json
{
    "id": 1,
    "ok": true,
    "result": {
        "pong": true,
        "status": {
            "has_proto": false,
            "has_keys": false,
            "has_credentials": false,
            "has_data_password": false,
            "needs_register": true,
            "has_dek": false,
            "has_local_db": false,
            "has_server_url": false,
            "has_server_identity": false,
            "has_keystore_on_disk": false,
            "is_registered_on_disk": false,
            "has_local_db_on_disk": false,
            "first_run": true,
            "mk_rotation_error": false
        },
        "ui_state": "keystore_locked",
        "actions_needed": ["unlock_keystore"]
    }
}
```

`ui_state` is one of: `keystore_locked`, `needs_credentials`, 
`needs_register`, `storage_locked`, `ready`.

---

### `unlock_keystore`

No authorization.

Unlocks the local keystore with the data password 
(`PasswordFileMkProvider`), starts `MkRotator`, creates 
`ProtocolManager`. Emits the IPC session token.

```json
{
    "id": 1,
    "cmd": "unlock_keystore",
    "data_password": "PasswordMin12Chars!"
}
```

`data_password` requirements are validated by 
`PasswordPolicy::default()` (`validate_password`).

If the keystore is already unlocked, it compares the password to 
the current one constant-time; on a match it returns success (a 
new token is issued again), on a mismatch `bad_data_password`.

Response:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "unlocked": true,
        "ipc_auth_token": "64hex..."
    }
}
```

| Error code | Meaning |
|------------|---------|
| `bad_data_password` | The password doesn't meet the policy, or doesn't match the one already set |
| `passwords_must_be_distinct` | The data password is identical to the already set account password |
| `crypto_error` | `KeyManager::start` failed (e.g. a corrupt key file) |
| `internal_error` | `EphemeralStoreManager::new` failed |
| `server_url_not_set` | `set_server_url` hasn't been called yet |

---

### `lock_keystore`

Requires auth.

Locks the keystore and removes all secrets from memory 
(`dek_plain`, `data_pass`, `account_creds`, `proto`, `local_db`, 
`keys`), invalidates the IPC token. Stops `MkRotator`. Always 
succeeds.

```json
{ "id": 1, "auth_token": "...", "cmd": "lock_keystore" }
```

Response:
```json
{ "id": 1, "ok": true, "result": { "locked": true } }
```

---

### `set_credentials`

Requires auth.

Sets the handler and the server account password. The data is held 
only in memory (`SecretString`). Required after every 
`unlock_keystore` before `register`/`unlock_storage`.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "set_credentials",
    "handler": "alice",
    "password": "AccountPass!1"
}
```

- `password` passes `validate_password` (`PasswordPolicy`)
- `password` must differ from `data_password` (if already set)

Response:
```json
{ "id": 1, "ok": true, "result": { "stored": true } }
```

| Error code | Meaning |
|------------|---------|
| `bad_account_password` | The account password doesn't meet the policy |
| `passwords_must_be_distinct` | The account password is identical to the keystore password |

---

### `register`

Requires auth + an unlocked keystore (`proto` set).

Registers the account on the server. **Idempotent**: if 
`needs_register == false`, it returns success with no network 
action.

```json
{ "id": 1, "auth_token": "...", "cmd": "register" }
```

Generates a random DEK (32B), encrypts it with the account 
password (`Argon2id + AES-256-GCM-SIV`), sends it to the server. 
The server stores the encrypted blob and returns it on every 
login.

Response (first registration):
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "registered": true,
        "capability": "hex..."
    }
}
```

Response (already registered, called again):
```json
{ "id": 1, "ok": true, "result": { "registered": true } }
```
(no `capability` field, it isn't regenerated).

`capability` is a token for emergency account deletion without 
logging in (see `remote_delete`). The server stores only its hash. 
**The daemon doesn't store `capability`, after being shown in this 
one response it is gone.** Losing it means the owner can't delete 
the account remotely.

| Error code | Meaning |
|------------|---------|
| `keystore_locked` | `proto` not set (keystore locked) |
| `missing_data_password` | No `data_password` in memory |
| `missing_account_credentials` | No `set_credentials` |
| `passwords_must_be_distinct` | Data password = account password |
| `crypto_error` | DEK generation or wrap failed |
| `protocol_error` | Network or server response error |
| `internal_error` | DEK conversion to `Byte32` failed |
| `internal_state_error` | An unexpected state combination (shouldn't occur) |

---

### `unlock_storage`

Requires auth + an unlocked keystore + registered.

Fetches the encrypted DEK from the server, decrypts it, and 
initializes the local SQLite database (if not already in memory).

```json
{ "id": 1, "auth_token": "...", "cmd": "unlock_storage" }
```

Response:
```json
{ "id": 1, "ok": true, "result": { "unlocked": true } }
```

| Error code | Meaning |
|------------|---------|
| `keystore_locked` | `proto` not set |
| `register_required` | `needs_register == true` |
| `missing_data_password` | No `data_password` in memory |
| `protocol_error` | DEK fetch from the server failed (e.g. no `set_credentials`/login) |
| `crypto_error` | DEK decryption failed |
| `internal_error` | DEK conversion to `Byte32` failed |
| `storage_init_failed` | Local SQLite database initialization failed |
| `internal_state_error` | An unexpected state combination |

---

### `create_invite`

Requires auth + unlocked storage.

Step 1 of 4 of commit-reveal pairing. Creates the invite 
**commitment** (`SHA256("lithiumd/pair-commit/v1" || code)`) for a 
new or existing contact, the raw `lci1:` code doesn't leave the 
daemon at this stage.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "create_invite",
    "contact_id": null
}
```

- `contact_id`: `null` = a new contact; hex = an existing contact 
  (a re-invite, generates a code from the current public keys)

New contact: generates `contact_id` (32B random) and a full set of 
per-contact keys (X25519, ML-KEM-1024, Ed25519, ML-DSA-87, 3 
mailbox pairs). Stores the state in SQLite.

Response:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "contact_id": "hex64...",
        "commitment": "hex64..."
    }
}
```

| Error code | Meaning |
|------------|---------|
| `storage_locked` | Storage not unlocked |
| `invalid_contact_id` | The given `contact_id` isn't valid hex |
| `contact_not_found` | The given `contact_id` doesn't exist in the DB |
| `self_state_corrupt` | The contact state in the DB doesn't deserialize |
| `json_error` | Serialization of the new state failed |
| `storage_error` | DB read/write error |
| `internal_error` | Invite code encoding failed |

---

### `accept_commitment`

Requires auth + unlocked storage.

Step 2 of 4. The accepting side (B) stores the creator's (A) 
commitment and generates **its own** code to send back to A.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "accept_commitment",
    "commitment": "hex64...",
    "label": "Alice"
}
```

- `commitment`, the 32-byte commitment (hex) received from A's 
  `create_invite`
- `label`, the local contact label

Generates a new `contact_id` and a full set of per-contact keys, 
stores `pending_commit = commitment` in the peer state.

Response (`code` is B's code to send back to A):
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "contact_id": "hex64...",
        "code": "lci1:hex..."
    }
}
```

| Error code | Meaning |
|------------|---------|
| `storage_locked` | Storage not unlocked |
| `invalid_commitment` | The commitment isn't 32-byte hex |
| `self_state_corrupt` | The contact state in the DB doesn't deserialize |
| `json_error` | Serialization of the new state failed |

---

### `reveal_invite`

Requires auth + unlocked storage.

Step 3 of 4. The creator (A), after receiving B's code, sets the 
peer to the identity from B's code and reveals **its own** code to 
send back to B. The daemon enforces the order: its own code is 
emitted only after the peer's code is given.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "reveal_invite",
    "contact_id": "hex64...",
    "peer_code": "lci1:hex...",
    "label": "Bob"
}
```

- `contact_id`, contact A created by `create_invite`
- `peer_code`, B's code (`lci1:`) received from `accept_commitment`
- `label`, the local contact label

Response (`code` is A's code to send back to B):
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "code": "lci1:hex..."
    }
}
```

| Error code | Meaning |
|------------|---------|
| `storage_locked` | Storage not unlocked |
| `invalid_contact_id` | `contact_id` isn't valid hex |
| `invalid_invite_code` | `peer_code` doesn't deserialize (wrong magic/version/length) |
| `contact_not_found` | `contact_id` doesn't exist in the DB |
| `peer_already_set` | The contact already has a peer set |
| `peer_state_corrupt` / `self_state_corrupt` | The contact state in the DB doesn't deserialize |
| `json_error` | Serialization of the new state failed |

---

### `finalize_pairing`

Requires auth + unlocked storage.

Step 4 of 4. The accepting side (B) verifies A's revealed code 
against the stored commitment (`ct_eq(SHA256("lithiumd/pair-commit/v1" 
|| code_A), pending_commit)`) and sets the peer to A's identity. 
After this step both sides have `peer_set=true`.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "finalize_pairing",
    "contact_id": "hex64...",
    "peer_code": "lci1:hex..."
}
```

- `contact_id`, contact B created by `accept_commitment`
- `peer_code`, A's code (`lci1:`) received from `reveal_invite`

Response:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "ok": true
    }
}
```

| Error code | Meaning |
|------------|---------|
| `storage_locked` | Storage not unlocked |
| `invalid_contact_id` | `contact_id` isn't valid hex |
| `invalid_invite_code` | `peer_code` doesn't deserialize |
| `contact_not_found` | `contact_id` doesn't exist in the DB |
| `peer_already_set` | The contact already has a peer set |
| `no_pending_commit` | No stored commitment for this contact |
| `commitment_mismatch` | The revealed code's hash doesn't match the commitment, possible channel tampering |
| `peer_state_corrupt` / `self_state_corrupt` | The contact state in the DB doesn't deserialize |
| `json_error` | Serialization of the new state failed |

---

### `contacts_list`

Requires auth + unlocked storage.

```json
{ "id": 1, "auth_token": "...", "cmd": "contacts_list" }
```

Response:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "contacts": [
            { "contact_id": "hex64...", "label": "Alice", "peer_set": true }
        ]
    }
}
```

| Error code | Meaning |
|------------|---------|
| `storage_locked` | Storage not unlocked |
| `storage_error` | DB read error |
| `peer_state_corrupt` | The contact state in the DB doesn't deserialize |

---

### `contact_send`

Requires auth + unlocked storage + unlocked keystore (`proto`).

Encrypts and sends a message to a contact. The encryption mode 
(`bootstrap`/`ratchet`/`prekey_recover`) is chosen automatically 
inside `encrypt_for_peer`, the client doesn't pick it in the 
request.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "contact_send",
    "contact_id": "hex64...",
    "plaintext": "Message content"
}
```

Response:
```json
{
    "id": 1,
    "ok": true,
    "result": { "sent": true, "mailbox_gen": 0 }
}
```

| Error code | Meaning |
|------------|---------|
| `storage_locked` | Storage not unlocked |
| `keystore_locked` | `proto` not set |
| `invalid_contact_id` | `contact_id` isn't valid 32-byte hex |
| `contact_not_found` | The contact doesn't exist in the DB |
| `self_state_corrupt` / `peer_state_corrupt` | The contact state in the DB doesn't deserialize |
| `crypto_error` | Keyring/mailbox initialization or encryption failed |
| `invalid_prekey_id` / `storage_error` | Generating/storing local prekeys failed |
| `need_recover_but_no_remote_prekey` | The peer needs recovery but published no prekey |
| `protocol_error` | The send to the server (`/msg/send`) failed |
| `json_error` | Serialization of the new state or the message to store failed |

`peer_set == false` isn't a separate error, in practice it ends in 
one of the contact-state errors above, because no peer means no 
keys to encrypt with.

---

### Fetching messages: automatic (no IPC command)

The manual `contact_fetch` was removed. Fetching incoming messages 
is done in the background by the daemon's fixed-cadence fetch 
dispatcher (`lithiumd/src/traffic.rs`): one `MsgFetch` per tick, 
round-robin over the inbound mailboxes of all contacts (up to 4 
generations: `peer_tx_gen_seen - 2` .. `+ 1`) plus the cover 
mailbox. The server deletes a message on read (one-time fetch); 
the daemon dedups by `msg_id`. The client doesn't initiate a 
fetch, it reads the local store through `messages_list` (polling 
every few seconds).

---

### `messages_list`

Requires auth + unlocked storage.

Returns a page of messages with a given contact (pagination).

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "messages_list",
    "contact_id": "hex64...",
    "limit": 50,
    "before_id": null
}
```

- `limit`: default 50, clamped to 1-200
- `before_id`: `null` = newest; a message ID = older than the 
  given one

Results are returned in chronological order (oldest to newest 
within the current page).

Response:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "messages": [
            {
                "id": 42,
                "direction": "in",
                "kind": "text",
                "text": "Content",
                "ui": {},
                "created_at": "2024-01-01T12:00:00+00:00"
            }
        ],
        "paging": {
            "has_more": false,
            "next_before_id": null
        }
    }
}
```

`direction` is `"in"` or `"out"` (not `"inbound"`/`"outbound"`). 
`kind` comes from the stored message (`"text"` for plain content, 
`"unknown"` when it couldn't be decoded). `paging` is nested, not 
flattened.

| Error code | Meaning |
|------------|---------|
| `storage_locked` | Storage not unlocked |
| `invalid_contact_id` | `contact_id` isn't valid hex |
| `storage_error` | DB read error |

---

### `contact_verify_emoji`

Requires auth + unlocked storage.

Generates a 6-character SAS (fingerprint) for out-of-band 
identity verification. Both sides must call it and compare the 
results. The verification is purely local, it needs no server 
connection. The full derivation is in 
[crypto-protocol.md](crypto-protocol.md#out-of-band-identity-verification).

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "contact_verify_emoji",
    "contact_id": "hex64..."
}
```

Response, the field is called `emojis` (plural), not `emoji`:
```json
{
    "id": 1,
    "ok": true,
    "result": {
        "emojis": ["A", "B", "C", "D", "E", "F"]
    }
}
```

| Error code | Meaning |
|------------|---------|
| `storage_locked` | Storage not unlocked |
| `invalid_contact_id` | `contact_id` isn't valid hex |
| `contact_not_found` | The contact doesn't exist in the DB |
| `self_state_corrupt` / `peer_state_corrupt` | The contact state in the DB doesn't deserialize |
| `peer_not_set` | The peer hasn't sent back its invite code yet |
| `internal_error` | SAS derivation failed |

---

### `contact_forget`

Requires auth + unlocked storage.

Removes the contact and all its messages and prekeys from the 
local database. Irreversible.

```json
{
    "id": 1,
    "auth_token": "...",
    "cmd": "contact_forget",
    "contact_id": "hex64..."
}
```

Response, the field is called `forgot`, not `forgotten`:
```json
{ "id": 1, "ok": true, "result": { "forgot": true } }
```

| Error code | Meaning |
|------------|---------|
| `storage_locked` | Storage not unlocked |
| `invalid_contact_id` | `contact_id` isn't valid hex |
| `contact_not_found` | The contact doesn't exist in the DB |
| `storage_error` | DB deletion error |

---

### `set_server_url`

No authorization.

Sets the daemon's relay server URL, saves it persistently to the 
`{data_dir}/server_url` file.

```json
{
    "id": 1,
    "cmd": "set_server_url",
    "url": "https://relay.example.com"
}
```

Response:
```json
{ "id": 1, "ok": true, "result": { "saved": true } }
```

| Error code | Meaning |
|------------|---------|
| `invalid_url` | The URL doesn't parse |
| `write_failed` | Writing the `server_url` file failed |

---

### `set_server_identity`

No authorization.

Sets the server identity (four public keys, encoded as described 
in 
[crypto-protocol.md](crypto-protocol.md#serveridentity-file-format)), 
**not** a path to a file on disk. The client must load the 
`server.identity` file itself (delivered by the server admin over 
an OOB channel) and send its content as hex in the `data` field.

```json
{
    "id": 1,
    "cmd": "set_server_identity",
    "data": "hex-encoded bytes of the server.identity file"
}
```

Writes the bytes to `state.identity_path` on disk and immediately 
invalidates the bootstrap cache 
(`proto.invalidate_bootstrap_cache()`), the new identity takes 
effect from the next request to the server, without needing 
`lock_keystore`/`unlock_keystore`. See 
[security-model.md](../security-model.md#changing-serveridentity-is-deliberately-painful).

Response:
```json
{ "id": 1, "ok": true, "result": { "saved": true } }
```

| Error code | Meaning |
|------------|---------|
| `server_identity_bad_hex` | `data` isn't valid hex |
| `server_identity_invalid:<detail>` | The data doesn't parse as a valid `server.identity` (e.g. wrong magic, a missing key) |
| `internal_error` | Writing the file to disk failed |

---

### `remote_delete`

No authorization.

Deletes the account from the server using the capability obtained 
at registration. It needs no active session or password, it works 
offline, independent of the keystore state.

```json
{
    "id": 1,
    "cmd": "remote_delete",
    "capability": "hex..."
}
```

Response:
```json
{ "id": 1, "ok": true, "result": { "remote_delete_requested": true } }
```

The server always returns 204 regardless of whether the capability 
is correct, the daemon reports success if the request reached the 
server, not whether the account was actually deleted.

| Error code | Meaning |
|------------|---------|
| `internal_error` | `EphemeralStoreManager`/HTTP client initialization failed |
| `server_url_not_set` | `set_server_url` hasn't been called yet |
| `protocol_error` | A network error during the send |

---

### `delete_account`

Requires auth + an unlocked keystore.

A different mechanism than `remote_delete`: it deletes the account 
through an active server session (`Endpoint::Delete`, 
`AuthMode::JwtUser`, requires being logged in), not through an 
offline capability token. After a successful deletion on the 
server, it performs a full local wipe (like `wipe_local`).

```json
{ "id": 1, "auth_token": "...", "cmd": "delete_account" }
```

Response:
```json
{ "id": 1, "ok": true, "result": { "deleted": true } }
```

| Error code | Meaning |
|------------|---------|
| `keystore_locked` | `proto` not set |
| `protocol_error` | Account deletion on the server failed (e.g. no login), local data is **not** deleted in this case |
| `account_deleted_but_local_wipe_failed` | The account was deleted on the server, but the local wipe failed, an inconsistent state needing manual intervention |

---

### `wipe_local`

Requires auth.

Removes the whole `{data_dir}`, all keys, the SQLite database, the 
local state. Irreversible. Does not contact the server.

```json
{ "id": 1, "auth_token": "...", "cmd": "wipe_local" }
```

Sequence:
1. Locks the keystore (removes secrets from memory)
2. Overwrites every file with random bytes (1 MB chunks, `fsync` 
   after each file)
3. `fsync` the directory (Unix)
4. Removes the files and directories
5. Sets the `needs_register` flag

Response:
```json
{ "id": 1, "ok": true, "result": { "wiped": true, "best_effort": true } }
```

`best_effort: true` means the overwriting is best-effort, on 
copy-on-write filesystems or SSDs with wear leveling the physical 
deletion of data isn't guaranteed.

| Error code | Meaning |
|------------|---------|
| `wipe_failed` | Overwriting or removing the files failed |

---

### `shutdown`

Requires auth.

Sends a shutdown signal to the daemon's main loop, locks the 
keystore. Always returns success, regardless of whether the 
shutdown signal was still available (idempotent, a second call 
after the first `shutdown` simply sends nothing but still returns 
`ok: true`).

```json
{ "id": 1, "auth_token": "...", "cmd": "shutdown" }
```

Response, the field is called `shutting_down`, not `shutdown`:
```json
{ "id": 1, "ok": true, "result": { "shutting_down": true } }
```

## Full error code list

| Code | Command(s) | Meaning |
|------|------------|---------|
| `bad_json` | all (line parse level) | The line doesn't parse as an `IpcRequest` |
| `ipc_auth_required` | commands requiring auth | No token or no active session |
| `ipc_auth_failed` | commands requiring auth | Wrong token or UID/PID mismatch |
| `ipc_auth_issue_failed` | `unlock_keystore` | Session token generation error |
| `bad_data_password` | `unlock_keystore` | The password doesn't meet the policy or doesn't match the current one |
| `bad_account_password` | `set_credentials` | The account password doesn't meet the policy |
| `passwords_must_be_distinct` | `unlock_keystore`, `set_credentials`, `register` | Account password = data password |
| `keystore_locked` | `register`, `unlock_storage`, `contact_send`, `delete_account` | `proto` not set (keystore locked) |
| `send_queue_full` | `contact_send` | The send dispatcher queue is full (throughput capped by the cover-traffic rate) |
| `missing_data_password` | `register`, `unlock_storage` | No `data_password` in memory |
| `missing_account_credentials` | `register` | No `set_credentials` |
| `register_required` | `unlock_storage` | `needs_register == true` |
| `storage_locked` | contact and message commands | The local database isn't initialized |
| `storage_init_failed` | `unlock_storage` | Local SQLite database initialization failed |
| `storage_error` | commands operating on the DB | SQLite read/write error |
| `internal_state_error` | `register`, `unlock_storage` | An unexpected state combination |
| `crypto_error` | `unlock_keystore`, `register`, `unlock_storage`, `contact_send` | A cryptographic error (decryption, key generation) |
| `protocol_error` | commands contacting the server | Network or server response error |
| `internal_error` | many | An unexpected internal error |
| `invalid_contact_id` | contact commands | `contact_id` isn't valid hex / 32 bytes |
| `contact_not_found` | contact commands | Unknown `contact_id` |
| `self_state_corrupt` / `peer_state_corrupt` | contact commands | The contact state in the DB doesn't deserialize |
| `peer_not_set` | `contact_verify_emoji` | The peer hasn't sent back the invite code |
| `peer_already_set` | `reveal_invite`, `finalize_pairing` | The contact already has a peer, can't accept again |
| `invalid_invite_code` | `reveal_invite`, `finalize_pairing` | The code (`peer_code`) doesn't parse |
| `invalid_commitment` | `accept_commitment` | The commitment isn't 32-byte hex |
| `no_pending_commit` | `finalize_pairing` | No stored commitment for the contact |
| `commitment_mismatch` | `finalize_pairing` | The revealed code's hash doesn't match the commitment (possible tampering) |
| `need_recover_but_no_remote_prekey` | `contact_send` | Recovery needed, but the peer published no prekey |
| `json_error` | commands that store state | Serialization of the contact/message state failed |
| `invalid_url` | `set_server_url` | The URL doesn't parse |
| `write_failed` | `set_server_url` | Writing the `server_url` file failed |
| `server_identity_bad_hex` | `set_server_identity` | `data` isn't valid hex |
| `server_identity_invalid:<...>` | `set_server_identity` | The data isn't a valid `server.identity` |
| `server_url_not_set` | `unlock_keystore`, `remote_delete` | `set_server_url` wasn't called |
| `account_deleted_but_local_wipe_failed` | `delete_account` | The account was deleted on the server, the local wipe failed |
| `wipe_failed` | `wipe_local` | File deletion error |

Auto-fetch (`traffic.rs`) handles per-message errors silently 
(`invalid_hex`, `bad_wire`, `invalid_utf8`, `duplicate`, 
`potentially_harmful_message`, `decrypt_failed`, `to_id_unknown`, 
`prekey_lookup_failed`, `prekey_recovery_failed`): a faulty 
message is skipped, the rest of the mailbox is processed. There is 
no IPC channel here, so these codes don't reach the client.

## Environment variables

The daemon's runtime variables (`LITHIUMD_*`: data directory, IPC 
paths, connection policy, cover-traffic cadence) are collected in 
[daemon-runtime.md](../operations/daemon-runtime.md#environment-variables).

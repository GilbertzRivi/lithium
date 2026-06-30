# lithiumd

The local Lithium cryptographic daemon. It runs on the user's 
machine and is the only component with access to the private keys 
and message plaintext. The server (`lithiums`) never sees 
unencrypted data, the daemon mediates between the GUI and the 
server, doing all cryptographic operations locally.

## Place in the architecture

```
lithiumg (GUI)
  | JSON-lines / Unix socket or Windows named pipe
lithiumd (daemon)   <- this crate
  | HTTPS + KyberBox (X25519 + ML-KEM-1024)
lithiums (relay server)
```

## Running

The server's public keys are **not** configured through 
environment variables, the daemon loads them from the 
`server.identity` file (default `{data_dir}/server.identity`, 
override `LITHIUMD_SERVER_IDENTITY`). The relay address and the 
server identity are set at runtime with the IPC commands 
`set_server_url` and `set_server_identity`; the identity file is 
loaded over an out-of-band channel (see 
[security-model.md](../security-model.md)).

```bash
export LITHIUMD_DATA_DIR=/home/user/.local/share/lithiumd   # optional
```

The default data directory (Linux): `{XDG_DATA_HOME}/lithiumd` or 
`~/.local/share/lithiumd/`. The IPC socket: 
`{XDG_RUNTIME_DIR}/lithiumd.sock` (Linux/macOS, override 
`LITHIUMD_SOCKET_PATH`) or `\\.\pipe\lithiumd` (Windows).

---

## IPC

The daemon exposes an IPC socket (Unix socket / named pipe on 
Windows, the JSON-lines protocol). The full contract, requests, 
responses, error codes, the state machine, the token policy, is in 
[ipc-reference.md](../protocol/ipc-reference.md); the endpoint 
lifecycle and connection policy (idle timeout, connection limit, 
`LITHIUMD_IPC_ALLOWED_UID`) are in 
[daemon-runtime.md](../operations/daemon-runtime.md).

What matters from the daemon's side: the session token emitted at 
`unlock_keystore` is, on Linux, bound to the sender's UID+PID 
(`SO_PEERCRED`, constant-time comparison) and invalidated by 
`lock_keystore`/`wipe_local`. IPC is a process trust boundary, see 
"Security model".

The internal handling of individual commands is covered by the 
architecture sections below: state and its wiping ("Daemon 
state"), sending and receiving ("E2E system", "Mailbox system"), 
server access ("ProtocolManager"), MK rotation, and the SQLite 
database.

## Daemon state: `DaemonState`

```rust
pub struct DaemonState {
    // Active components (None = locked)
    proto:        Arc<Mutex<Option<Arc<ProtocolManager<PasswordFileMkProvider>>>>>,
    mk_rotator:   Arc<Mutex<Option<MkRotator>>>,
    traffic:      Arc<Mutex<Option<Traffic>>>,                        // cover-traffic dispatcher
    send_tx:      Arc<Mutex<Option<mpsc::Sender<PendingSend>>>>,      // send dispatcher queue
    keys:         Arc<Mutex<Option<SharedKeyManager>>>,
    local_db:     Arc<Mutex<Option<Arc<DataManager<PasswordFileMkProvider>>>>>,

    // Sensitive data (zeroized on lock)
    data_pass:    Arc<Mutex<Option<SecretString>>>,                   // data_password
    account_creds: Arc<Mutex<Option<(SecretString, SecretString)>>>,  // (handler, password)
    dek_plain:    Arc<Mutex<Option<Byte32>>>,                         // the decrypted DEK

    // Flags
    needs_register:    Arc<Mutex<bool>>,
    mk_rotation_error: Arc<Mutex<bool>>,                             // the last MK rotation failed

    // IPC authorization
    ipc_auth:    Arc<Mutex<IpcAuthState>>,

    // Per-contact fetch locks
    contact_fetch_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,

    // Configuration
    base_dir:      PathBuf,
    base_url:      Arc<RwLock<Option<Url>>>,
    identity_path: PathBuf,
}
```

`lock_keystore()` wipes from memory: `dek_plain`, `data_pass`, 
`account_creds`, `proto`, `local_db`, `keys`, 
`ipc_auth.session_token`. It also stops the `MkRotator`.

---

## `PasswordFileMkProvider`

The `MkProvider` implementation specific to lithiumd. It combines 
the data password with a server component, so that recovering the 
local disk without the server isn't enough to decrypt the keys.

### MK file format (`mk.enc`)

```
[LMK1: 4 bytes magic]
[salt_len: 1 byte = 32]
[salt: 32 bytes]
[blob_len: 4 bytes LE]
[blob: AES-256-GCM-SIV(MK, key=Argon2id(password, salt), aad="lithium/mkfile/v1")]
```

### Deriving the MK read key

```
user_key = Argon2id(data_password, salt)   // 64 MB, 3 iterations, 1 thread
MK = AES-256-GCM-SIV_decrypt(blob, user_key)
```

### Deriving secrets (e.g. the database DEK)

`PasswordFileMkProvider::derive_secret32` **ignores** the `mk` from 
`KeyManager` and instead uses:

```
password_root   = Argon2id(data_password, salt=root.salt)   // random per-install salt from the root.salt file
combined_root   = HKDF(input=server_dek, salt=password_root, info="lithium/user-provider/combined/v1")
secret          = HKDF(combined_root, info=label)
```

**Consequence**: without `server_dek` (fetched from the server by 
`UnlockStorage`) the DB secrets can't be derived, even with the 
password and the local disk. This is a deliberate property of the 
security model.

---

## `ProtocolManager`: transport to the server

Manages all HTTP communication with the server. Every request is 
encrypted with KyberBox (X25519 + ML-KEM-1024) and dual-signed 
(Ed25519 + ML-DSA-87).

### Session state in `EphemeralStoreManager`

| Key | Content | TTL |
|-----|---------|-----|
| `proto/server/ses_x` | Session X25519 hex (from the server) | 120 s |
| `proto/server/ses_k` | Session ML-KEM hex (from the server) | 120 s |
| `proto/server/peer_x` | Server's ephemeral X25519 (from the last response) | 120 s |
| `proto/server/peer_k` | Server's ephemeral ML-KEM (from the last response) | 120 s |
| `proto/server/jwt` | JWT token | 120 s |
| `proto/server/dek_enc` | Encrypted DEK (hex) | 3600 s |

### Endpoints and their properties

| Endpoint | Path | Session | JWT | Keys in headers |
|----------|------|---------|-----|-----------------|
| `Shake` | `/shake` | no | no | ephemeral |
| `RegisterStart` | `/user/register/start` | yes | no | identity |
| `RegisterFinish` | `/user/register/finish` | yes | no | identity |
| `LoginStart` | `/user/login/start` | yes | no | none (verified by `handler`) |
| `LoginFinish` | `/user/login/finish` | yes | no | none (verified by `handler`) |
| `Revoke` | `/user/revoke` | yes | no | ephemeral |
| `Delete` | `/user/delete` | yes | **yes** | none (identity from JWT) |
| `MsgSend` | `/msg/send` | yes | no | ephemeral (+ PoW) |
| `MsgFetch` | `/msg/fetch` | yes | no | ephemeral |

### Request padding

The body and headers are padded before encryption, so the payload 
size doesn't reveal the content:
- **Body**: `data || 0x80 || 0x00...` to a multiple of a random 
  32-64 KB block.
- **Headers**: padded to a multiple of a random 4-8 KB block.

### Verifying the server response

Every response is verified by two signatures (Ed25519 + ML-DSA-87) 
against the server's public keys loaded from the `server.identity` 
file. Both algorithms must pass verification.

### Session key rotation

After each response the server may send back new `ses-x` and 
`ses-k` in the response headers. They are updated automatically in 
the ephemeral store.

---

## E2E system: end-to-end encryption

E2E encryption works independently of the transport encryption. 
Even if the transport were compromised, messages stay encrypted 
under per-contact keys.

### The `WireV1` format (binary message format)

```
[LM1: 3 bytes magic]
[VER: 1 byte = 1]
[to_id: 32 bytes]           <- recipient key identifier
[from_x_pub: 32 bytes]      <- sender's ephemeral X25519
[kem_ct_len: 2 bytes BE]
[kem_ct: kem_ct_len bytes]  <- ML-KEM ciphertext
[hdr_len: 4 bytes BE]
[enc_headers: hdr_len bytes]
[body_len: 4 bytes BE]
[enc_body: body_len bytes]
```

`to_id` = `HKDF(x_pub_bytes || k_pub_bytes, 
info="lithiumd/e2e-peer-kid/v1")`, the identifier of the 
recipient's receiving key pair.

### Encryption modes

**`bootstrap`**, the first message to a contact:
- Targets the bootstrap keys from the invite (`x_pub`, `k_pub`).
- The sender doesn't have reply keys from the peer yet.

**`ratchet`**, after receiving the first reply:
- Targets the `reply` keys from the last received message 
  (`e2e_peer.id`, `e2e_peer.x_pub`, `e2e_peer.k_pub`).
- The reply keys are rotated on every received message.

**`prekey_recover`**, recovery after a state desync:
- Targets a prekey published by the peer (`prekeys_remote`).
- Lets communication resume without a new invite exchange.

### Signing E2E messages

Every message is dual-signed with the contact's identity keys 
(Ed25519 + ML-DSA-87):

```
sig_input = "lithiumd/e2e-msg-sig/v1" || to_id || from_x_pub
            || u32(len(hdr_unsigned)) || hdr_unsigned
            || u32(len(body)) || body
```

`hdr_unsigned` is the header JSON **without** the `auth` fields. 
The signatures are embedded in the encrypted header 
(`enc_headers`), so the server doesn't see them.

### Receiving keys (RX keyring)

On every send the sender generates a new RX pair (X25519 + 
ML-KEM-1024) and sends the public part in the header (`reply`). The 
peer encrypts the next message to those keys.

The RX keys are stored in `self_state["e2e_rx"]["keys"]` with a 
sequence number (`seq`). GC removes keys older than `window=32` 
sequences from the last acknowledgement (`ack_seq`).

The bootstrap keys are removed from `self_state` (securely erased 
through `SecretJson::drop`) once both conditions hold: the peer 
confirmed receipt (`ack_seq > 0` or `retire_ok`) and the peer has 
`e2e_peer` set.

### Prekeys

On the first send the daemon generates a set of prekeys (5 by 
default) and attaches their public parts to the message header. 
The peer stores them in `peer_state["prekeys_remote"]`. In 
`prekey_recover` mode the peer reaches for a prekey to encrypt the 
recovery message.

The private parts of the prekeys are stored in the `prekeys` table 
in SQLite (encrypted with the DEK, AAD=`lithiumd/prekey/v1`). A 
prekey is removed after use (`take_prekey`).

---

## Mailbox system

A mailbox is an address on the server from which the recipient 
fetches messages. The address is derived cryptographically, the 
server doesn't know who writes to whom.

### Mailbox address derivation

```
shared = ECDH(sender_out_priv, receiver_in_pub)
salt   = sender_cid || receiver_cid || generation (8 bytes BE)
address = HKDF(shared, salt=salt, info="lithium/mbox/address/v1")  -> 32 bytes
```

The sender and recipient compute the address independently, 
without communicating. The server sees only the address as an 
opaque 32-byte identifier.

### Mailbox keys

Each contact has in `self_state`:
- `mbox_in_priv`/`mbox_in_pub`, a stable receiving key (immutable, 
  for receiving from a given peer).
- `mbox_out_cur_priv`/`mbox_out_cur_pub`, the current sending key.
- `mbox_out_next_priv`/`mbox_out_next_pub`, the next sending key 
  (prepared ahead of time).

### Sending key rotation

After sending `rotate_every` (32 by default) messages: `cur <- 
next`, generate a new `next`. Messages tell the peer about the 
current and next public keys 
(`header["mailbox"]["sender_cur_x_pub"]`, `sender_next_x_pub"`).

### Fetch

Auto-fetch (`traffic.rs`) checks generations: `peer_tx_gen_seen - 
2` to `peer_tx_gen_seen + 1`, up to 4 generations in total. It 
guarantees receipt even if a generation was skipped.

---

## SQLite database

The local database in `{data_dir}/storage/lithiumd.sqlite`. WAL 
mode, `synchronous=NORMAL`, `foreign_keys=ON`, 
`temp_store=MEMORY`, `busy_timeout=5000ms`.

### Schema

**`contacts`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | i64 PK | - |
| `contact_id` | BLOB UNIQUE | 32 bytes, the contact identifier |
| `peer_state_enc` | BLOB | Encrypted peer state (AAD: `lithiumd/contact-peer/v1`) |
| `self_state_enc` | BLOB | Encrypted own state (AAD: `lithiumd/contact-self/v1`) |
| `created_at` | TIMESTAMP | - |
| `updated_at` | TIMESTAMP | - |

**`messages`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | i64 PK | - |
| `contact_id` | BLOB | FK to contacts |
| `mailbox` | BLOB | The mailbox address it was fetched from |
| `direction` | i32 | 0 = inbound, 1 = outbound |
| `content_enc` | BLOB | Encrypted content (AAD: `lithiumd/message/v1`) |
| `msg_id` | BLOB UNIQUE | Message identifier for dedup (NULL = none) |
| `created_at` | TIMESTAMP | - |

**`prekeys`**

| Column | Type | Description |
|--------|------|-------------|
| `id` | i64 PK | - |
| `contact_id` | BLOB | FK to contacts |
| `prekey_id` | BLOB UNIQUE | The prekey identifier |
| `key_enc` | BLOB | Encrypted prekey material (AAD: `lithiumd/prekey/v1`) |
| `created_at` | TIMESTAMP | - |
| `expires_at` | TIMESTAMP | - |
| `used_at` | TIMESTAMP | NULL = unused |

All `*_enc` blobs are encrypted with AES-256-GCM-SIV through 
`DataManager::encrypt_db_blob`. The database DEK = 
`derive_secret32(b"lithium/db-dek/v1")`, derived from 
`combined_root` (password + server DEK).

---

## Master Key rotation

`MkRotator` is a background task spawned by `UnlockKeystore`. Every 
**30 seconds** it calls `KeyManager::maybe_rotate_mk()`, which by 
the `lithium_core` logic rotates the MK every **3600 seconds** (1 
hour).

Rotation is crash-safe (details in the `lithium_core` 
[docs](../../lithium_core/README.md)). After an MK rotation:
- All asymmetric-key and secret `.keyf` files are rewrapped under 
  the new MK.
- The JWT secret is regenerated.
- The database DEK **doesn't change value**, the rewrap touches 
  only the key file, not the encrypted data in SQLite.

`MkRotator` is stopped synchronously on `lock_keystore()`, 
`stop_tx.send(true)` + `.await` on the `JoinHandle`.

---

## Invite code format

```
lci1:<HEX>
```

The binary content (hex-encoded):

```
[LCI1: 4 bytes magic]
[VER: 1 byte = 1]
[contact_id: 32 bytes]
[x_pub: 32 bytes]              <- X25519 (E2E)
[k_pub_len: 2 bytes BE = 1568]
[k_pub: 1568 bytes]           <- ML-KEM-1024 (E2E)
[ed_pub: 32 bytes]            <- Ed25519 (signatures)
[dili_pub_len: 2 bytes BE = 2592]
[dili_pub: 2592 bytes]        <- ML-DSA-87 (signatures)
[mbox_in_pub: 32 bytes]       <- stable mailbox receiving key
[mbox_out_cur_pub: 32 bytes]  <- current mailbox sending key
[mbox_out_next_pub: 32 bytes] <- next mailbox sending key
```

Total binary size: **4361 bytes** -> **8722 hex characters** after 
`lci1:`.

---

## Data directory layout

```
{data_dir}/                      (0o700)
  keystore/
    user/
      mk.enc              Master Key wrapped by the data password
      root.salt           random per-install Argon2 salt (DEK)
    pub/                  public keys (cache)
    priv/                 private keys (*.keyf, wrapped by the MK)
    secrets/              derived secrets (*.keyf, wrapped by the MK)
    .rotate/              temporary MK rotation directory
  storage/
    lithiumd.sqlite       SQLite (contacts, messages, prekeys)
  server.identity        server public keys (or LITHIUMD_SERVER_IDENTITY)
  server_url             relay address (text)
  registered.flag        registration marker (0o600)

The IPC socket does not live in the data directory, by default it's
{XDG_RUNTIME_DIR}/lithiumd.sock.
```

---

## Security model

**Two-factor rule for DB secrets:** local data can only be 
decrypted when both `data_password` (the user's password) and 
`server_dek` (the server component) are available at the same 
time. Losing control of the device without knowing the password, 
or losing access to the server, means losing the ability to read 
the data. This is deliberate.

**Per-contact isolation:** each contact has an independent set of 
keys (`contact_id`, X25519, ML-KEM, Ed25519, ML-DSA-87, mailbox 
keys). Compromising one contact doesn't compromise the others.

**The server takes no part in E2E cryptography:** the server sees 
only encrypted payloads and mailbox addresses. It can't decrypt 
content, can't forge a peer's identity, and can't correlate who 
writes to whom (mailbox addresses are pseudo-random).

**GC of sensitive material:** bootstrap private keys are securely 
erased (`SecretJson::drop` with zeroization) as soon as the peer 
has confirmed communication. Old RX keys are erased once the 
window (32) is exceeded.

**IPC as a privileged boundary:** breaching IPC gives access to all 
of the daemon's cryptographic operations, including plaintext and 
keys. Binding the token to UID/PID (Linux) limits the risk, see 
[security-model.md](../security-model.md).

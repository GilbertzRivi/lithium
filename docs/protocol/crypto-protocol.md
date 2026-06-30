# Lithium cryptographic protocol specification

This document describes the full Lithium cryptographic protocol in 
two independent layers: transport (daemon-server) and E2E 
(daemon-daemon). Meant for auditors and implementers.

## Two independent encryption layers

Every message goes through two independent encryption layers:

1. **The E2E layer**, encryption between daemons, invisible to the 
   server. The server never has the keys to this layer.
2. **The transport layer**, encryption of the daemon-server 
   connection. It protects the request metadata and the E2E 
   payload from a network observer. The server decrypts this 
   layer, but the content is already encrypted by the E2E layer.

A compromise of the transport layer doesn't reveal message 
content, it stays encrypted under per-contact E2E keys.

## Cryptographic primitives

| Purpose | Algorithm |
|---------|-----------|
| Hybrid KEM | X25519 + ML-KEM-1024 (via KyberBox) |
| AEAD | AES-256-GCM-SIV |
| KDF | HKDF-SHA256 |
| Signatures | Ed25519 + ML-DSA-87 (dual-sign) |
| Password authentication (PAKE) | OPAQUE (ristretto255 + Argon2id) |
| KSF / password derivation | Argon2id |
| CSRNG | `rand::rngs::SysRng` |

A detailed analysis of KyberBox is in the `lithium_core` 
[docs](../../lithium_core/README.md).

## Transport layer (daemon-server)

### Shake mode

Used to initialize a session. The client doesn't have the server's 
session keys yet.

The client sends in cleartext HTTP headers:
- `key-x`, the client's ephemeral X25519 public key (hex 32B)
- `key-k`, the client's ephemeral ML-KEM-1024 public key (hex 
  1568B)
- `seed`, the encrypted KEM seed
- `data`, the blob of encrypted application headers

The client encrypts the request body with KyberBox under the 
context `"shake-req"` (the server response is encrypted under 
`"shake-resp"`), using the server's long-term public keys as the 
recipient (X25519 and ML-KEM-1024 from the `server.identity` file) 
and its own ephemeral X25519 private key as the sender. The server 
decrypts the body with its long-term X25519 private key and the 
client's ephemeral public key from the `key-x` header.

In the encrypted application headers (`data`) the client puts:
- `key-ed`, the ephemeral Ed25519 public key (hex 32B)
- `key-dili`, the ephemeral ML-DSA-87 public key (hex 2592B)
- `sig-ed`, the Ed25519 signature over the request body
- `sig-dili`, the ML-DSA-87 signature over the request body

The decrypted JSON body must contain a `timestamp` field (Unix 
timestamp in seconds, hex 16 chars, big-endian). The server 
validates `timestamp` to be within +/-60s of its clock. The 
server verifies the signature using `key-ed` and `key-dili` from 
the encrypted headers.

The server's response carries in cleartext HTTP headers:
- `key-x`, the new session's X25519 public key (the client 
  encrypts the next request to it)
- `key-k`, the new session's ML-KEM-1024 public key
- `data`, the blob of encrypted response headers (KyberBox)
- `seed`, the encrypted KEM seed
- `sig-ed`, the server's Ed25519 signature over the response body
- `sig-dili`, the server's ML-DSA-87 signature over the response 
  body

In the encrypted response headers (`data`):
- `ses-x`, a random identifier of the session's X25519 private key 
  in `EphemeralStoreManager`
- `ses-k`, a random identifier of the session's ML-KEM-1024 
  private key in `EphemeralStoreManager`

The client sends these identifiers back in the next request's 
headers (`ses-x`, `ses-k`), and the server uses them to look up 
the private key. The private session keys are held in 
`EphemeralStoreManager` with a TTL of 60s (Shake) / 120s 
(Session).

### Session mode

Used after Shake. The client has the session public keys from the 
previous response.

The client sends in cleartext HTTP headers:
- `ses-x`, a random 32-byte X25519 session identifier (hex), 
  received from the encrypted headers of the previous response
- `ses-k`, a random 32-byte ML-KEM-1024 session identifier (hex), 
  received from the encrypted headers of the previous response
- `seed`, the encrypted KEM seed
- `data`, the blob of encrypted application headers

In the encrypted application headers (`data`) the client puts 
`sig-ed`, `sig-dili`, and optionally `key-ed`/`key-dili`, 
depending on the endpoint (see the table below).

The client encrypts the body with KyberBox under the context 
`"{endpoint}-req"` (the response under `"{endpoint}-resp"`), the 
context label is built per endpoint by `ctx_req`/`ctx_resp` from 
the endpoint name (`register_start`, `login_start`, `msg_send`, 
`msg_fetch`, ...; `lithium_core/src/contract/protocol.rs`); there 
is no single shared `"session"` context. The recipient is the 
server's session public keys (received in the previous response in 
cleartext HTTP headers as `key-x`, `key-k`). The server uses 
`ses-x`/`ses-k` as lookup keys into `EphemeralStoreManager`, from 
which it gets the matching private session keys, and decrypts the 
body. Session TTL: 120s.

After each response the server generates new session key pairs and 
puts them in the headers, the client uses the new keys for the 
next request.

### Anti-replay

`GuardMiddleware` applies two mechanisms:

1. **Body hash**: `SHA256(raw_body_bytes)` held in 
   `EphemeralStoreManager` with a 600s TTL. The first request with 
   a given hash passes. Reusing the same body within 600s returns 
   `400 replay_detected`. Applies only to POST requests, GETs are 
   exempt.

2. **Timestamp**: the `timestamp` field in the decrypted body must 
   be within +/-60s of the server clock. Outside that window the 
   request is rejected.

### Signing and verification

Every request is dual-signed (Ed25519 + ML-DSA-87). The signing 
keys and the signatures are placed in the encrypted application 
headers, the server verifies them after decryption. The server 
always verifies both signatures, both must pass.

Per-endpoint behavior:

| Endpoint | `key-ed`/`key-dili` in headers | `AuthMode` | Server-side verification |
|----------|--------------------------------|------------|--------------------------|
| `Shake`, `RemoteDelete`, `MsgSend`, `MsgFetch` | ephemeral (generated per request) | `KeysInHeaders` | from the encrypted request headers |
| `RegisterStart`, `RegisterFinish` | long-term identity keys | `KeysInHeaders` | from the encrypted request headers (the server stores them in the DB) |
| `LoginStart`, `LoginFinish` | none | `LoginByHandler` | with keys stored in the DB, looked up by `handler` |
| `Delete` | none | `JwtUser` | the user identity from the JWT issued at login (not from keys in headers) |

The server dual-signs every response with its keys. The client 
verifies under the keys loaded from the `server.identity` file.

### JWT (one-time authorization token)

The JWT is issued on a successful login (`/user/login/finish`), 
required by the only endpoint with `AuthMode::JwtUser`: account 
deletion (`/user/delete`). Sending a message (`/msg/send`) is 
anonymous (`KeysInHeaders`) and doesn't use a JWT.

There is no IPC `login` command and no GUI login screen. OPAQUE 
login (`/user/login/start` + `/user/login/finish`) is called 
automatically and invisibly by `ProtocolManager::ensure_login` 
(`lithiumd/src/protocol_manager.rs`) whenever an operation needing 
a JWT (`delete_account`; `Endpoint::Delete` is the only 
`requires_jwt()`) or a DEK (`unlock_storage`, `get_dek`, login 
returns the encrypted DEK) no longer has a cached, unused token, 
using the account handler/password from `set_credentials`, kept 
only in memory. `contact_send`/`msg/send` is anonymous 
(`KeysInHeaders`) and does **not** need a JWT. The JWT is one-time 
(`store.take`), so every subsequent `delete_account` after the 
previous token is spent triggers another, equally invisible 
background login.

- Algorithm: HS256
- The `sub` field: `hex(HMAC-SHA256(user_id_bytes, 
  random_seed_bytes))`, an opaque identifier
- The token is stored in `EphemeralStoreManager` under the HMAC 
  `sub` value with the session TTL
- The token is **one-time**, `store.take` removes it on first use
- In the JSON body as `tok_hex` (hex-encoded)

Losing the token or hijacking the session doesn't allow reuse, the 
token is spent.

### Transport endpoints

| Endpoint | Path | Crypto mode | `key-ed`/`key-dili` in encrypted headers |
|----------|------|-------------|------------------------------------------|
| Shake | POST `/shake` | Shake | ephemeral |
| Register (start) | POST `/user/register/start` | Session | identity (stored in the DB) |
| Register (finish) | POST `/user/register/finish` | Session | identity |
| Login (start) | POST `/user/login/start` | Session | none (server verifies by `handler` from the DB) |
| Login (finish) | POST `/user/login/finish` | Session | none (server verifies by `handler` from the DB) |
| Delete | POST `/user/delete` | Session | none (server verifies via JWT) |
| Send | POST `/msg/send` | Session | ephemeral (anonymous `KeysInHeaders` + PoW, no JWT) |
| Remote delete | POST `/user/revoke` | Session | ephemeral |
| Fetch | POST `/msg/fetch` | Session | ephemeral |
| Root | GET `/` | none | none |
| Health | GET `/health` | none | none |

### Proof-of-Work on send

`/msg/send` requires proof-of-work (anti-spam, independent of the 
JWT). The server computes a challenge from the mailbox address and 
the content, the client attaches a matching `nonce`:

```
challenge = SHA256("lithium/send-pow/v1" || u32_le(len(mailbox)) || mailbox || content)
ok        = leading_zero_bits(SHA256(challenge || u64_le(nonce))) >= bits
```

The `nonce` goes into the JSON body as the `pow` field. The 
difficulty `bits` is set by `LITHIUMS_SEND_POW_BITS` (18 by 
default; `lithium_core/src/pow.rs`). A failed PoW is rejected as 
`400 invalid_pow`.

### Size padding

The body and headers are padded randomly before encryption:
- Body: `data || 0x80 || 0x00...` to a multiple of a random 32-64 
  KB block
- Headers: padded to a multiple of a random 4-8 KB block

This hides the length and the type of operation from a network 
observer.

## E2E layer (daemon-daemon)

### WireV1 format: the binary message format

```
[LM1: 3 bytes magic]
[VER: 1 byte = 1]
[to_id: 32 bytes]        recipient key identifier
[from_x_pub: 32 bytes]   sender's ephemeral X25519
[seed_len: 2 bytes BE]
[seed: seed_len bytes]   ML-KEM ciphertext + encrypted seed
[hdr_len: 4 bytes BE]
[enc_headers: hdr_len bytes]
[body_len: 4 bytes BE]
[enc_body: body_len bytes]
```

`to_id = HKDF(x_pub_bytes || k_pub_bytes, 
info="lithiumd/e2e-peer-kid/v1")`, the identifier of the 
recipient's receiving key pair.

`enc_headers` and `enc_body` are KyberBox blobs under the context 
`"lithiumd/e2e-msg/v1"`.

### E2E encryption (KyberBox in the E2E context)

Encryption uses per-contact keys, not transport keys. The client 
encrypts to the peer's public keys (`peer_pub_x`, `peer_k_pub`), 
using a freshly generated ephemeral X25519 key (`from_x_pub`).

`headers` carry metadata (message mode, reply keys, mailbox info, 
signatures). `body` carries the message content.

### E2E encryption modes

**Bootstrap**, the first message to a contact:
- Targets the bootstrap keys from the invite (`x_pub`, `k_pub` 
  from the `lci1:` code)
- The sender has no reply keys from the peer
- The bootstrap keys are removed from `self_state` once the peer 
  confirms receipt (`ack_seq > 0` or `retire_ok`) and has 
  `e2e_peer` set

**Ratchet**, after receiving the first reply:
- Targets the `reply` keys from the last received message 
  (`e2e_peer.id`, `e2e_peer.x_pub`, `e2e_peer.k_pub`)
- The RX keys are rotated on every received message
- RX keys older than the window of 32 sequences from `ack_seq` are 
  removed

**Prekey recover**, recovery after a state desync:
- Targets a prekey published by the peer (`prekeys_remote`)
- Lets communication resume without a new invite exchange
- The prekey is removed after use

### Signing E2E messages

Every message is dual-signed with the contact's identity keys 
(Ed25519 + ML-DSA-87):

```
sig_input = "lithiumd/e2e-msg-sig/v1" || to_id || from_x_pub
            || u32(len(hdr_unsigned)) || hdr_unsigned
            || u32(len(body)) || body
```

`hdr_unsigned` is the header JSON **without** the `auth` fields. 
The signatures are embedded in `enc_headers`, the server doesn't 
see them.

The recipient verifies both signatures under the peer's keys 
stored during the invite exchange. An unverifiable signature means 
the message is rejected.

### Receiving keys (RX keyring)

On every send the sender generates a new RX pair (X25519 + 
ML-KEM-1024) and sends the public keys in the encrypted header 
(`reply`). The peer encrypts the next message to those keys.

The RX keys are held in `self_state["e2e_rx"]["keys"]` with a 
sequence number (`seq`). Window: 32 keys from `ack_seq`. Older 
ones are securely erased.

### Prekeys

On the first send a set of prekeys is generated (5 by default). 
The public parts are attached to the message header. The peer 
stores them in `peer_state["prekeys_remote"]`.

The private parts are held in the `prekeys` table in SQLite 
(encrypted with the DEK, AAD=`lithiumd/prekey/v1`). A prekey is 
removed after use (`take_prekey`).

## Mailbox system

### Addressing

A mailbox address is a cryptographically pseudo-random 32-byte 
mailbox identifier on the server. The server sees only the 
address, it doesn't know who writes to whom.

```
shared  = ECDH(sender_out_priv, receiver_in_pub)
salt    = sender_cid || receiver_cid || generation (8 bytes BE)
address = HKDF(shared, salt=salt, info="lithium/mbox/address/v1")  -> 32 bytes
```

The sender and recipient compute the address independently, 
without talking to the server.

### Per-contact mailbox keys

The mailbox keys are **dedicated** X25519 pairs generated only for 
mailbox addressing. They are independent of the keys used to 
encrypt message content (bootstrap keys, ratchet RX, prekey), the 
two key spaces are entirely separate.

Each contact has in `self_state`:
- `mbox_in_priv` / `mbox_in_pub`, a stable receiving key 
  (immutable)
- `mbox_out_cur_priv` / `mbox_out_cur_pub`, the current sending 
  key
- `mbox_out_next_priv` / `mbox_out_next_pub`, the next sending key 
  (prepared ahead of time)

### Sending key rotation

After `rotate_every` (32 by default) sent messages: `cur <- next`, 
generate a new `next`. The encrypted E2E headers (`enc_headers`) 
pass the peer the public keys `sender_cur_x_pub` and 
`sender_next_x_pub`, the server doesn't see them.

### Fetch range

`ContactFetch` checks generations `peer_tx_gen_seen - 2` to 
`peer_tx_gen_seen + 1`, up to 4 generations. It ensures receipt 
even if the sender skipped a generation.

## Invite exchange (contact pairing)

### The `lci1:` invite code format

```
lci1:<HEX>
```

The binary content (hex-encoded):

```
[LCI1: 4 bytes magic]
[VER: 1 byte = 1]
[contact_id: 32 bytes]
[x_pub: 32 bytes]              X25519 (E2E)
[k_pub_len: 2 bytes BE = 1568]
[k_pub: 1568 bytes]           ML-KEM-1024 (E2E)
[ed_pub: 32 bytes]            Ed25519 (signatures)
[dili_pub_len: 2 bytes BE = 2592]
[dili_pub: 2592 bytes]        ML-DSA-87 (signatures)
[mbox_in_pub: 32 bytes]       stable mailbox receiving key
[mbox_out_cur_pub: 32 bytes]  current mailbox sending key
[mbox_out_next_pub: 32 bytes] next mailbox sending key
```

Total binary size: **4361 bytes**, **8722 hex characters** after 
`lci1:`.

### The exchange flow (commit-reveal)

Pairing is a **one-sided commit-reveal**. The creator (A) first 
publishes only a *commitment* to their code, never the raw code; 
the acceptor (B) reveals their code only after receiving A's 
commitment; A reveals their code only after receiving B's code; at 
the end B verifies A's revealed code against the commitment. The 
reveal order is **enforced by the daemon**: `CreateInvite` returns 
only the commitment (A's code never leaves the daemon at this 
stage), and `RevealInvite` requires the peer's code as input 
before it emits its own code.

```
commitment = SHA256("lithiumd/pair-commit/v1" || decoded_code)   -> 32 bytes (hex)

(4 messages over an OOB channel: email, phone, other)
A: CreateInvite{contact_id=null}                      -> commitment_A    [A->B: commitment_A]
B: AcceptCommitment{commitment_A, label}              -> code_B          [B->A: code_B]
   (B stores pending_commit = commitment_A)
A: RevealInvite{contact_id=A, peer_code=code_B, label} -> code_A         [A->B: code_A]
   (A sets peer = B's identity)
B: FinalizePairing{contact_id=B, peer_code=code_A}
   (B verifies ct_eq(SHA256(code_A), pending_commit), sets peer = A's identity)

Both sides: peer_set=true -> can write
```

The commitment needs no confidential or authenticated channel, it 
is a public hash and its only role is to enforce the order (commit 
before reveal). The server takes no part in the invite exchange, 
all four messages are exchanged off the server.

### Out-of-band identity verification

After the exchange, both sides verify a **6-symbol** fingerprint 
(SAS, Short Authentication String, a 64-symbol alphabet: letters, 
digits, symbols, Greek letters, `VERIFY_EMOJI_TABLE`/`VERIFY_EMOJI_LEN` 
in `lithiumd/src/commands/contact_verify_emoji.rs`) over a voice 
or in-person channel.

Each side first computes its own "party transcript", an HKDF over 
the concatenation of 8 identity fields (its own `cid`, `x_pub`, 
`ed_pub`, `dili_pub`, `k_pub`, and 3 mailbox keys: `mbox_in_pub`, 
`mbox_out_cur_pub`, `mbox_out_next_pub`) under the label 
`PARTY_TRANSCRIPT_LABEL` (`"lithiumd/party-transcript/v1"`):

```
bundle  = cid || x_pub || ed_pub || dili_pub || k_pub || mbox_in_pub || mbox_out_cur_pub || mbox_out_next_pub
t_self  = HKDF(bundle, info="lithiumd/party-transcript/v1")          -> 32 bytes
t_peer  = HKDF(bundle_peer, info="lithiumd/party-transcript/v1")     -> 32 bytes (the same fields, for the peer)
```

Then both transcripts are sorted (`t_a, t_b = sorted(t_self, 
t_peer)`), so both sides compute an identical `info`, and the 
fingerprint is computed from an ECDH:

```
shared    = ECDH(self_x_priv, peer_x_pub)
sas32     = HKDF(shared, info="lithiumd/contact-verify-emoji/v1" || t_a || t_b)  -> 32 bytes
emoji[i]  = EMOJI_TABLE[sas32[i] mod 64]   for i = 0..6   (6 symbols; 256 = 4*64, no modulo bias)
```

Including `t_a`/`t_b` in the `info` binds the fingerprint not just 
to the X25519 key but to the full set of identities and mailbox 
keys of both sides, swapping any of the 8 fields on either side 
changes the resulting SAS. Identical emoji on both sides confirms 
there was no MITM in the exchange.

The length of 6 symbols (a 64-symbol alphabet -> 36 bits) is 
enough **only because of the commit-reveal** described in "The 
exchange flow". Without the commitment a MITM controlling the OOB 
channel could grind their own key set offline against the victim's 
SAS (the grind is HKDF-dependent, cheap on a GPU); a birthday 
collision on a 36-bit SAS is then about 2^18 evaluations, trivial. 
The commit-reveal closes this: the MITM has to lock in the 
substituted keys toward each side *before* that side reveals its 
code (the acceptor reveals their code only after receiving the 
creator's commitment; the creator reveals their code only after 
receiving the acceptor's code, the daemon enforces the order). 
Because the SAS mixes both sides' codes, and at the moment the 
MITM finalizes the choice at least one real code is still 
unrevealed, the offline attack is impossible. The MITM gets **one 
blind shot at 2^-36 for the whole ceremony** (which requires a 
live SAS comparison), which is infeasible.

**Coupling invariant (don't change independently):** the SAS 
length and commit-reveal are coupled. Shortening the SAS *or* 
removing commit-reveal in isolation reopens the offline grind 
(~2^18). Either change may only be made with a parallel 
compensation in the other mechanism (a longer SAS without the 
commitment, or the commitment with a shorter SAS).

## Key lifecycle

The full key catalog, derivation, storage, lifetime, rotation, and 
leak analysis, is in 
[key-hierarchy.md](../key-hierarchy.md). The crash-safe MK rotation 
mechanics (atomic rewrap of `.keyf` files without decrypting the 
payload) are in the `lithium_core` 
[docs](../../lithium_core/README.md).

In short, for this protocol:
- **At-rest (client):** `data_password` -> MK -> the DEK of the 
  `.keyf` files; the local database under `db_dek`, which needs 
  both `password_root` (from the password) and `server_dek` (from 
  the server), a deliberate two-factor.
- **Per contact:** an independent set (X25519+ML-KEM for E2E, 
  Ed25519+ML-DSA for signatures, 3 mailbox keys, bootstrap, RX, 
  prekeys), isolation between contacts.
- **Ephemeral:** transport session keys (TTL 60 s Shake / 120 s 
  Session) and `msg_key` per message on the server (TTL 24 h), a 
  server restart destroys `msg_key`, making pending messages 
  permanently undecryptable.

## Database encryption (server)

### User field encryption scheme

The sensitive fields in the `users` table are encrypted 
individually under the server DEK (AES-256-GCM-SIV), each with a 
separate AAD (`lithiums/src/labels.rs`):

| Field | AAD |
|-------|-----|
| `opaque_record` | `"user-opaque-record/v1"` |
| `ed_key` | `"user-ed-key/v1"` |
| `dili_key` | `"user-dili-key/v1"` |
| `dek` | `"user-dek/v1"` |

The `id` column is the deterministic `id_enc` (a separate scheme 
below). `delete_token_hash` is not DEK-encrypted, it is 
`SHA256(remote_delete_capability)`, used only as a lookup key for 
`/user/revoke`. There is no `handler` column, the handler is sent 
transiently and mapped to the deterministic `id`. Swapping the DEK 
or using a wrong AAD causes an AEAD decryption failure.

### Deterministic user ID

```
handler (normalized) -> UUID v5(namespace, handler) -> id_bytes
id_enc = AES-256-GCM-SIV(id_bytes, db_dek, nonce=HKDF(id_bytes, db_dek, UIDENC_NONCE_LABEL), aad="user-idenc/v1")
```

The same handler always gives the same `id_enc`, which enables PK 
lookup without storing the plaintext handler. The deliberate 
trade-off is described in 
[security-model.md](../security-model.md).

## Key file format (.keyf)

Private keys and secrets are stored in `.keyf` files with double 
wrapping:

```
[KEYF magic: 4 bytes][version: u8][alg_id: u8][dek_len: u16]
[salt_len: u16][salt: 32 bytes]
[nonce_wrap_len: u16][nonce_wrap: 12 bytes]
[ct_wrap_len: u16][ct_wrap: N bytes]        AES-256-GCM-SIV(DEK, KEK)
[nonce_payload_len: u16][nonce_payload: 12 bytes]
[ct_payload_len: u32][ct_payload: M bytes]  AES-256-GCM-SIV(secret, DEK)
```

- **KEK** = `HKDF(MasterKey, salt, info="kek/v1")`
- **DEK** = a random 32-byte key per file
- The AAD carries the version and key type, a wrong type means a 
  decryption failure

Atomic write: `tmp + rename` with `fsync` and `0o600` permissions 
(Unix).

Rewrapping (changing the MK without decrypting the payload):
```
rewrap_keyfile_dek(path, old_mk, new_mk, key_type)
```
It decrypts and re-encrypts only the DEK layer, the cryptographic 
payload stays untouched.

## server.identity file format

A binary file generated by the server on the first run. The format 
(`lithium_core/src/contract/identity_file.rs`): an 8-byte magic, a 
version, an entry count, then a sequence of TLV (tag + length + 
data) per key, not a fixed layout:

```
[magic: 8 bytes = "LITHIUPK"]
[version: u8 = 1]
[count: u8 = 4]
4x [tag_len: u8][tag: ASCII][data_len: u16 LE][data]
    tags: "x25519" (32B), "ed25519" (32B), "mlkem1024" (1568B), "mldsa87" (2592B)
```

Unknown tags are ignored on deserialization (forward-compat). The 
four known keys must be present and have exactly the expected 
length (32/32/1568/2592), `decode` rejects a file with a missing 
or wrong-length key before `set_server_identity` accepts it. The 
actual size of a file with 4 entries: **4275 bytes** (10 bytes of 
header + 41 bytes of TLV overhead + 32 + 32 + 1568 + 2592 bytes of 
data).

The client loads this file at startup and verifies every server 
response under it. Changing the server keys without updating the 
file on the client side breaks communication permanently at the 
cryptographic level (the server's decryption of the request, or 
the client's verification of the response signature, fails), this 
is deliberate, see [security-model.md](../security-model.md).

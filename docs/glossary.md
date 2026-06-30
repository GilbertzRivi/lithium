# Glossary

Short definitions of Lithium's own terms. Deeper descriptions: 
protocol [crypto-protocol.md](protocol/crypto-protocol.md), keys 
[key-hierarchy.md](key-hierarchy.md), KyberBox in the `lithium_core` 
[docs](../lithium_core/README.md), IPC commands 
[ipc-reference.md](protocol/ipc-reference.md).

**AEAD** - Authenticated Encryption with Associated Data. In 
Lithium always AES-256-GCM-SIV.

**aPAKE** - asymmetric Password-Authenticated Key Exchange. Done 
with OPAQUE: the client proves it knows the password without 
showing it to the server.

**Argon2id** - key-stretching function (KSF) and password 
derivation; parameters 64 MiB, t=3, p=1. Used in OPAQUE and for 
`password_root`.

**AuthMode** - authorization mode of a server endpoint: 
`KeysInHeaders` (ephemeral keys in headers, anonymous), 
`LoginByHandler` (checks `handler` during OPAQUE), `JwtUser` 
(identity from JWT, only `/user/delete`).

**bootstrap** - keys (X25519 + ML-KEM) taken from the `lci1:` 
invite code and used for the first message to a contact; removed 
from `self_state` once the peer confirms receipt and the ratchet 
is set up. Also the E2E encryption mode that uses these keys.

**cid** - see **contact_id**.

**combined_root** - `HKDF(server_dek, salt=password_root, 
"lithium/user-provider/combined/v1")`; source of `db_dek`. RAM 
only.

**commitment** - `SHA256("lithiumd/pair-commit/v1" || 
invite_code)`. A public hash published before the code is 
revealed.

**commit-reveal** - one sided pairing protocol (4 OOB messages) 
where the creator publishes the commitment first, and the codes 
are revealed in an order the daemon enforces. Coupled with the 
short **SAS** (see [design-decisions.md](design-decisions.md) #3).

**contact_id (cid)** - 32-byte random contact identifier, local 
to each side (A has `cid_a_b`, B has `cid_b_a`).

**cover traffic** - fixed-rate traffic that hides the timing and 
volume of real communication; real messages go in the slots, 
dummy ones fill the gaps to a self-loop cover mailbox. Receiving 
is automatic (no manual fetch).

**CryptoMiddleware** - per-route server middleware: decrypts the 
body (Shake/Session), checks the timestamp and dual signature, 
applies `AuthMode`.

**DataManager** - the encrypted database layer (SQLite on the 
client, PostgreSQL on the server); `encrypt_db_blob` / 
`decrypt_db_blob` under the DEK with a separate AAD per field.

**db_dek** - the database DEK, `HKDF(..., "lithium/db-dek/v1")`. On 
the client derived from `combined_root`, on the server from the 
server MK.

**DEK (Data Encryption Key)** - the key that encrypts data: in a 
`.keyf` file it's random per file (wrapped under the KEK), in the 
database it's `db_dek`.

**EphemeralStore / EphemeralStoreManager** - in-memory store with 
TTL: transport session keys, `msg_key`, JWT, rate-limit counters. 
A process restart wipes all of it.

**export_key** - a secret derived client-side from OPAQUE that 
wraps `server_dek`.

**generation (mailbox)** - rotation counter of the mailbox's 
sending key. A fetch checks the window -2..+1 around the last 
seen generation.

**GuardMiddleware** - the outer server middleware: pre-replay 
rate-limit per IP, size limits (1 MiB body/headers), anti-replay 
on `SHA256(body)`.

**handler** - the username (login). Normalized (trim + 
lowercase); never stored in the clear on the server, it's mapped 
to a deterministic `id_enc`.

**harvest-now-decrypt-later** - an attacker who records ciphertext 
today to decrypt it with a quantum computer later. The reason for 
the post-quantum hybrid.

**id_enc** - deterministic ciphertext of the UUID v5 of the 
normalized handler; primary key of the `users` row. Lets you look 
users up without the plaintext handler (at the cost of equality 
being observable).

**IPC** - the channel between the GUI and the daemon: JSON-lines 
over a Unix socket (Linux/macOS) or a named pipe (Windows).

**JWT** - a one-time HS256 token issued at OPAQUE login; consumed 
on use (`store.take`); required only by `/user/delete`.

**KEK (Key Encryption Key)** - `HKDF(MK, file_salt, "kek/v1")`; 
wraps the DEK inside a `.keyf` file.

**KEM** - Key Encapsulation Mechanism; in Lithium the X25519 + 
ML-KEM-1024 hybrid.

**KeyManager** - manages `.keyf` key files and Master Key 
rotation.

**`.keyf`** - key file format with double wrapping: payload under 
the DEK, DEK under the KEK (from the MK). Magic `KEYF`.

**KyberBox** - hybrid KEM-DEM construction: ML-KEM-1024 + X25519 
feed HKDF, then AES-256-GCM-SIV for `body` and `headers`. See the 
`lithium_core` [docs](../lithium_core/README.md).

**lci1** - prefix and binary format of the invite code (hex after 
`lci1:`); version 1, 4361 bytes of data.

**lithium_core / lithiumd / lithiumg / lithiums** - the crates: 
shared library / client daemon / GUI / relay server.

**Master Key (MK)** - the top key that encrypts `.keyf` files. On 
the client it's wrapped with the data password; rotated every 
hour.

**mailbox (mailbox address)** - a pseudo-random 32-byte address on 
the server, computed independently by sender and receiver from 
ECDH+HKDF. The server only sees the address, it doesn't know who 
talks to whom.

**MkProvider** - pluggable source of the MK: `PlainFileMkProvider` 
(file), `TpmMkProvider` (sealed in the TPM), `ServerMkProvider` 
(enum that dispatches on the server).

**MkRotator** - background task that wakes every 30 s and rotates 
the MK once the interval passes (3600 s by default).

**ML-DSA-87** (Dilithium) - post-quantum signature scheme; part of 
the dual-sign.

**ML-KEM-1024** (Kyber) - post-quantum KEM; part of the encryption 
hybrid.

**msg_id** - random 16-byte message identifier in the signed 
header; deduplicated by a `UNIQUE` constraint.

**msg_key** - random per-message key on the server 
(`EphemeralStore`, TTL 24 h). A server restart makes pending 
messages permanently undecryptable.

**one-time fetch** - the server deletes a message atomically on 
the first fetch (`SELECT FOR UPDATE SKIP LOCKED` + `DELETE`).

**OPAQUE** - the aPAKE (`opaque-ke 4.0.1`, ristretto255 + Argon2) 
used for account authentication; registration and login are 
two-phase (`start`/`finish`).

**party transcript** - `HKDF` over the concatenation of a side's 8 
identity fields (`cid`, `x_pub`, `ed_pub`, `dili_pub`, `k_pub`, 3 
mailbox keys); the sorted `t_a`/`t_b` go into the `info` when 
computing the SAS, binding it to the full identity of both sides.

**password_root** - `Argon2id(data_password, root.salt)`; the 
password factor of `db_dek`. Cached in RAM.

**peer_set** - contact flag: the other side accepted the pairing 
and keys were exchanged, so you can send messages.

**pinning (server identity)** - the client pins the server's 
public keys from the `server.identity` file. There is no endpoint 
to fetch them, the file always reaches the client out-of-band.

**PoW (proof-of-work)** - anti-spam on `/msg/send`: SHA-256 with a 
required number of leading zero bits (`LITHIUMS_SEND_POW_BITS`, 18 
by default).

**prekey** - a key pair (X25519 + ML-KEM) published to a peer; 
lets you resume after desync. Deleted after use.

**prekey recover** - E2E mode that targets a peer's published 
prekey; recovers the channel without a new invite exchange.

**ProtocolManager** - the daemon's HTTP transport client to the 
server; encrypts with KyberBox, dual-signs, manages the session, 
JWT and DEK.

**ratchet** - E2E mode after the first reply: targets the rotated 
`reply` keys (RX keyring) of the last received message.

**relay (hostile)** - the Lithium server as openly untrusted; it 
stores and forwards only ciphertext, never sees plaintext.

**root.salt** - random, per-install 32-byte Argon2 salt for 
`password_root`; file `keystore/user/root.salt`.

**RX keyring (reply keys)** - rotated receiving keys generated on 
every send; the peer encrypts the next message to them. A window 
of 32 sequences from `ack_seq`, older ones safely deleted.

**SAS (Short Authentication String)** - 6-symbol fingerprint 
(64-symbol alphabet) for verifying identity over a voice or 
in-person channel. Safe because it's coupled with commit-reveal.

**server_dek** - random DEK kept on the server (wrapped under 
`export_key`, returned at login); the second factor of the 
client's `db_dek`. Never on the client's disk.

**server.identity** - file with the server's public keys (TLV 
format: x25519, ed25519, mlkem1024, mldsa87). Pinned on the 
client.

**Session (mode)** - transport mode after Shake: the client uses 
the session keys from the previous response; TTL 120 s.

**Shake (mode)** - session init mode: the client's ephemeral keys 
+ the server's long-term keys from `server.identity`; TTL 60 s.

**to_id** - `HKDF(x_pub || k_pub, "lithiumd/e2e-peer-kid/v1")`; 
identifier of the recipient's receiving key pair in the `WireV1` 
header.

**TPM sealing** - sealing the server's Master Key in the TPM as a 
KEYEDHASH object under an ECC P-256 parent derived from the owner 
seed (the parent is never persisted).

**two-factor DEK** - `db_dek` needs both `password_root` (from the 
password) and `server_dek` (from the server); neither factor is 
enough on its own.

**WireV1** - binary format of an E2E message (magic `LM1`): 
`to_id`, ephemeral `from_x_pub`, `seed` (ML-KEM), `enc_headers`, 
`enc_body`.

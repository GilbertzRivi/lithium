# Data lifecycle and privacy inventory

One view: what data exists, where it rests (RAM / client disk / 
server / network), how long it lives, and who can see it. It 
complements [security-model.md](security-model.md) ("what the 
server sees per request") and 
[key-hierarchy.md](key-hierarchy.md) (the keys). The actors 
throughout: the **user**, the **client daemon** (`lithiumd`, has 
plaintext when unlocked), the **relay server** (`lithiums`, 
hostile), the **network observer** (passive), the **reverse proxy 
operator** (terminates TLS), and the **contact** (a paired peer).

## Data inventory

| Data | Where it rests | Form / protection | Retention |
|------|----------------|-------------------|-----------|
| Message content (plaintext) | client RAM only (composing/displaying) | none, live plaintext | ephemeral; never on disk in plaintext |
| Message content (local history) | client disk, `storage/lithiumd.sqlite` | AES-256-GCM-SIV under `db_dek` (AAD `lithiumd/message/v1`) | until `contact_forget` / `wipe_local` |
| Message content (in transit / on server) | wire to server (PostgreSQL `messages`) | E2E (KyberBox) + an extra server layer (`msg_key`) | on the server until first fetch (one-time) or a 24 h TTL |
| Contact state / per-contact keys | client disk, SQLite (`contacts`) | AES-256-GCM-SIV under `db_dek` (AAD `contact-self/v1`/`contact-peer/v1`) | until `contact_forget` / `wipe_local` |
| Mailbox address | in the encrypted request body; on the server in `messages.mailbox` | pseudo-random 32 B; unlinked from identity | as the message |
| Handler (username) | server (as deterministic `id_enc`) | UUID v5 -> AES-256-GCM-SIV; no plaintext | until `delete_account` |
| Account password / data password | client RAM only (`SecretString`) | zeroized on `lock_keystore`; never to disk or to the server | session |
| `server_dek` | server (`users.dek`) | wrapped under `export_key`, then AAD `user-dek/v1` | until `delete_account` |
| Local keys (`.keyf`: MK, identity, secrets) | client disk, `keystore/` | payload under the DEK, DEK under the KEK (from the MK); MK under Argon2(password) | persistent (until `wipe_local`) |
| User record (opaque, ed/dili, dek) | server (`users`) | each field AES-256-GCM-SIV under the server `db_dek`, separate AAD | until `delete_account` |
| `db_dek` / `password_root` / `combined_root` / `dek_plain` | RAM only (client and server) | derived on demand | session (until `lock`) |
| Transport session keys | server RAM (`EphemeralStore`) | ephemeral | TTL 60 s (Shake) / 120 s (Session) |
| `msg_key` (per-message key) | server RAM (`EphemeralStore`) | random 32 B | TTL 24 h; lost on server restart |
| JWT | server RAM (`EphemeralStore`) + client RAM | HS256, one-time (`store.take`) | session TTL 120 s |
| Rate-limit counters / replay hashes | server RAM (`EphemeralStore`) | - | windows 10 s / 15 min / 1 h; replay 600 s |
| `server.identity` / `server_url` / `registered.flag` | client disk | public keys / URL / marker, not sensitive | persistent |
| Network metadata (IP, time, volume) | at the proxy / observer | TLS; size padding; cover traffic | outside Lithium (operator logs) |

## A message's life (hop by hop)

```
[1] Sender writes plaintext         -> sender daemon's RAM only
[2] contact_send: E2E encryption    -> WireV1 (KyberBox), local write (outbound, db_dek)
[3] Transport to the server         -> transport KyberBox in a cover-traffic slot; PoW
[4] Server receives                 -> sees the mailbox address + E2E ciphertext; wraps with msg_key; writes to `messages`
[5] Recipient auto-fetch (in background) -> fetch + atomic delete (one-time); msg_key consumed
[6] Recipient daemon decrypts       -> verifies the dual signature, local write (inbound, db_dek)
[7] Recipient GUI displays          -> plaintext in RAM only
```

On no network hop (3) and not on the server (4) is the content 
readable, E2E is independent of the transport, and the server has 
no per-contact keys.

## What rests where

**Client disk** (`{data_dir}`, `0o700`): `keystore/` (`.keyf` 
wrapped by the MK, `mk.enc` under Argon2(password), `root.salt`), 
`storage/lithiumd.sqlite` (contacts/messages/prekeys, blobs under 
`db_dek`), `server.identity` (public), `server_url`, 
`registered.flag`. **Never** in plaintext: content, private keys, 
the password.

**Client RAM** (unlocked): the data and account passwords, 
`dek_plain`, `password_root`, the MK, the per-contact keys in use, 
the plaintext of the displayed message. Zeroized on 
`lock_keystore`.

**Server disk**: PostgreSQL (`users`, fields encrypted under the 
server `db_dek`, except the deterministic `id_enc`; `messages`, 
content double-encrypted), the server keystore (`.keyf`), the 
sealed MK blob (TPM). **Does not hold**: the password, the E2E 
keys, the content plaintext.

**Server RAM** (`EphemeralStore`): private session keys, 
`msg_key`, JWT, rate-limit counters, replay hashes. A restart 
wipes everything, so pending messages become permanently 
undecryptable.

**Wire / reverse proxy**: the proxy terminates TLS and sees the 
cleartext HTTP headers (ephemeral public keys, session 
identifiers, `kem-ct`, signatures) and the **encrypted** body 
(KyberBox to the server's keys), it can't read the content or even 
the transport plaintext. It also sees the client IP, timings, and 
sizes (padded to blocks of 32-64 KB / 4-8 KB). A passive observer 
before the proxy sees only TLS traffic to the relay.

## Retention, short version

| Item | Lifetime |
|------|----------|
| Content plaintext (client RAM) | ephemeral |
| Secrets in RAM (password, `db_dek`, keys) | until `lock_keystore` |
| Transport session keys | 60 s / 120 s |
| JWT | 120 s, one-time |
| `msg_key` + message on the server | until first fetch or 24 h |
| Replay body-hash | 600 s |
| Local history / contacts / `.keyf` keys | until `forget` / `wipe_local` |
| User record + `server_dek` | until `delete_account` |

## Who sees what

| Data | User | Daemon (unlocked) | Server | Observer/Proxy | Contact |
|------|------|-------------------|--------|----------------|---------|
| Message content | yes | yes | **no** | **no** | yes (what was sent to them) |
| Who they talk to | yes | yes | **no** (pseudo-random addresses) | **no** | only themselves |
| The user's handler | yes | yes | **no** (only `id_enc`) | **no** | yes (the peer's, after pairing) |
| Password | yes | yes (RAM) | **no** | **no** | **no** |
| The fact of connecting to the relay | yes | yes | yes | yes (IP/time) | **no** |
| Time/volume of real traffic | yes | yes | partially (mailboxes) | **no** (cover traffic) | **no** |

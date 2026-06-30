# Lithium

**Post-quantum end-to-end encrypted messenger, designed for high-security environments.**

Lithium is not a consumer messenger. It was built for organizations and users
who can't afford for the content of their communication to be available to
anyone except the direct participants — including the operator, the
infrastructure provider, or a court issuing an order.

> **Design priority:** Content confidentiality is more important than
> convenience. If these two values collide, Lithium chooses confidentiality.

> **Status: pre-audit (unaudited).** Lithium has not yet gone through an
> independent cryptographic audit and has no production releases. Despite the
> high security goals, **do not use it to protect actually sensitive
> communication** until the implementation has been independently audited. The
> code is published for inspection, review, and integration — not as a finished
> product.

---

## Who Lithium is for

Lithium is meant for environments where:

* the server, operator, or infrastructure can be **monitored, compromised, or
  legally forced to cooperate**,
* classic messengers, even encrypted ones, are unacceptable because they require
  **trust in the operator**,
* the organization needs a messenger that **mathematically prevents the service
  provider from revealing the content**,
* there is a real risk that **the client's disk will be seized** by an
  adversary,
* regulatory or operational requirements require **minimal retention** and no
  way for the operator to reconstruct history.

Example audiences: law firms, companies handling negotiations and mergers,
journalist organizations and NGOs working in difficult environments, financial
institutions that require confidentiality of internal communication.

---

## Key properties

### The operator mathematically can't reveal the content

The Lithium server is treated as a hostile relay. It only stores and forwards
encrypted data. It has no access to:

* message content,
* users' private keys,
* relations between participants (mailbox addresses are cryptographically
  pseudorandom).

Even under legal pressure, the operator can't provide plaintext — not because
it refuses, but because **it does not have it**.

### Post-quantum resistance

All cryptographic operations are hybrid: they are done with a classic and a
post-quantum algorithm at the same time. Breaking one of them does not break
the system — both have to be broken at the same time.

| Purpose              | Algorithms                      |
| -------------------- | ------------------------------- |
| Key exchange         | X25519 + ML-KEM-1024 (NIST PQC) |
| Symmetric encryption | AES-256-GCM-SIV                 |
| Digital signatures   | Ed25519 + ML-DSA-87 (NIST PQC)  |
| Key derivation       | HKDF-SHA256                     |
| Password hashing     | Argon2id                        |

The post-quantum algorithms (ML-KEM-1024, ML-DSA-87) are standards approved by
NIST in 2024 as target algorithms for environments that require resistance to
quantum computers.

### Forward secrecy — the past is safe even after a key is revealed

* **Per ratchet epoch:** every message carries a fresh ML-KEM seed and a fresh
  ephemeral sender key, and receiver keys (RX) rotate with each peer reply and
  are deleted after leaving the window of 32. After an RX key is deleted,
  messages encrypted to it become undecryptable. The X25519 component is shared
  by messages inside one epoch (until the next peer reply), so the guarantee
  works at epoch boundaries, not per single message — details in
  `lithium_core/docs/kyberbox.md`.
* **Per generation:** mailbox keys rotate every 32 messages; old private keys
  are securely deleted.
* **Transport:** transport session keys have a TTL of 60–120 seconds;
  compromising a session does not let you decrypt earlier traffic.

### Two-factor protection of local data

Decrypting data stored on the device requires both:

1. the user's password (local data),
2. a server component (DEK fetched on every login).

The DEK (data encryption key) is generated randomly by the client during
registration — the server does not create it, know it, or reconstruct it. The
client sends it to the server already encrypted with its own password, and the
server stores it as an opaque blob, returning it on every login. The server is
only a carrier here — without the client's password, it can't use it.

Stealing the device disk without knowing the password **and** without access to
the server gives no plaintext. This is a design decision, not a limitation.

### Cryptographic uniqueness per installation

Every daemon installation independently generates its own cryptographic
material — asymmetric keys, master key seed, mailbox keys — using the system
random number generator (CSRNG). There is no shared secret or installation
seed. Two installations on two devices have no cryptographic relation, even if
they belong to the same user.

### Server identity pinning and protection against replacement

The server identity — a set of four public keys (X25519, ML-KEM-1024, Ed25519,
ML-DSA-87) — is stored as the binary file `server.identity`, generated by the
server on first start. The client daemon loads this file and verifies every
server response against it.

`server.identity` does not have and never will have any URL or endpoint from
which it can be fetched automatically — this is a separate security layer,
independent of the relay server URL (that is set with a separate command,
`set_server_url`, and is used only to make an HTTP connection, not to verify
identity). The file has to be delivered out-of-band and imported manually, as a
conscious user action. This is intentional: if the client could download
`server.identity` by itself over the network, replacing the server keys by an
attacker who took over the server would be invisible to users — automatically
fetching a new identity would remove the whole protection this file is meant to
provide.

Consequence: **any change to server keys — whether by replacement or external
interference — immediately and permanently breaks communication with all
existing clients.** A client can't connect to a server whose identity it does
not recognize. Resuming requires a conscious decision by the users: manually
importing a new `server.identity` file. This is intentional — replacing server
keys without users knowing is impossible.

### One-shot messages

Messages are deleted from the server atomically on first fetch. The server does
not store history. History exists only in the client's local database,
encrypted per device.

### Identity verification without the server

The server is not a source of trust. The peer's identity is verified by
comparing an emoji fingerprint over an out-of-band channel (for example by
phone). The server can't forge either side's identity.

---

## System architecture

```
┌─────────────────────────────────────┐
│  lithiumg  (GUI — Linux / Windows)  │
│  User interface                     │
└────────────────┬────────────────────┘
                 │ JSON / Unix socket / Windows named pipe
                 │ (local connections only)
┌────────────────▼────────────────────┐
│  lithiumd  (client daemon)          │
│  Private keys · SQLite · crypto     │
│  The only place with plaintext      │
└────────────────┬────────────────────┘
                 │ HTTPS
                 │ Kyberbox (X25519 + ML-KEM-1024)
                 │ dual-sign (Ed25519 + ML-DSA-87)
┌────────────────▼────────────────────┐
│  lithiums  (relay server)           │
│  PostgreSQL · ciphertexts only      │
│  Does not see plaintext             │
└─────────────────────────────────────┘
```

The system has four components:

| Component      | Role                                                                  |
| -------------- | --------------------------------------------------------------------- |
| `lithium_core` | Cryptographic library — shared by the daemon and the server           |
| `lithiumd`     | Client daemon — stores keys, does encryption, exposes IPC for the GUI |
| `lithiumg`     | Graphical interface — talks to the daemon, never touches keys itself  |
| `lithiums`     | Relay server — accepts and forwards encrypted messages, PostgreSQL    |

### Cryptographic isolation

Private keys and plaintext exist only in `lithiumd` on the user's device. The
GUI (`lithiumg`) talks to the daemon through a local socket and never has access
to key material. The server (`lithiums`) sees only encrypted blobs — it does not
participate in any E2E cryptographic operation.

---

## Message flow

### Sending

```
User types text in the GUI
  → GUI sends IPC to the daemon: contact_send(contact_id, plaintext)
  → daemon encrypts: WireV1 (X25519 + ML-KEM + AES-256-GCM-SIV + dual-sign)
  → daemon sends the encrypted blob over HTTPS to the server
  → server wraps the blob with an additional random per-message key
  → stores it in PostgreSQL (TTL 24h)
```

### Receiving

```
Background daemon (fixed cadence, traffic.rs) polls mailboxes by itself — no user action
  → daemon calculates mailbox addresses (ECDH with mailbox keys) and fetches blobs over HTTPS
  → server atomically returns + deletes messages from the database (one-shot fetch)
  → daemon decrypts, verifies signatures, stores plaintext in local SQLite
  → GUI refreshes the view through messages_list (poll from local database — no fetch command)
```

### Adding a contact (invite exchange)

Pairing is done by exchanging invite codes (`lci1:HEX`) — outside the server,
over an out-of-band channel (email, phone, other). The invite code contains only
public keys — no private data.

```
Side A: [New contact] → lci1:HEX code (A public keys)
Side B: selects this contact, pastes A's code into the invite field + [Accept invite]
        → B contact already has peer_set=true, receives its own lci1:HEX code (B public keys)
Side A: selects this (still pending) contact, pastes B's code into the same field + [Accept invite]
→ both sides have peer_set=true → they can write
```

It is the same "Accept invite" button on both sides — the only difference is
which contact is currently selected (new, without `contact_id`, vs. previously
created, waiting for a reply). The separate "Reply to invite" button in the GUI
does not consume the pasted code — it only regenerates/displays your own
`lci1:HEX` code for the selected pending contact (useful when it has to be sent
to the other side again).

After the exchange, both sides verify the emoji fingerprint over a voice or
in-person channel — only this confirms that no MITM attack happened.

---

## Security properties — summary

| Property                                              | Mechanism                                                                                                                                                                                                                                                                                      |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Post-quantum resistance                               | ML-KEM-1024 + ML-DSA-87 in parallel with X25519 + Ed25519; both algorithms have to be broken at the same time                                                                                                                                                                                  |
| Forward secrecy (per ratchet epoch)                   | Fresh ML-KEM seed in every message; receiver keys rotate per peer reply and are deleted outside the window of 32. X25519 component shared inside an epoch → guarantee at epoch boundaries, not per message (`lithium_core/docs/kyberbox.md`)                                                   |
| Forward secrecy per generation                        | Mailbox key rotation every 32 messages; old sender private keys deleted                                                                                                                                                                                                                        |
| Transport forward secrecy                             | Session key TTL 60–120s; ephemeral X25519 + ML-KEM keys per request (Shake mode)                                                                                                                                                                                                               |
| Post-compromise security (limited, passive adversary) | Fresh ML-KEM seeds and rotating RX keys introduce entropy unknown to an adversary who is passive after compromise → confidentiality of new messages rebuilds. Identity keys (Ed25519/ML-DSA) do not rotate — an active adversary keeps impersonation and MITM ability (`docs/threat-model.md`) |
| No plaintext on the server                            | Content is encrypted by the client before it reaches the server; the server adds a second layer, but does not read it                                                                                                                                                                          |
| One-shot messages                                     | Atomic deletion on first fetch; the server can't reconstruct them                                                                                                                                                                                                                              |
| Ephemeral message keys                                | Per-message keys live only in server memory; server restart destroys the keys                                                                                                                                                                                                                  |
| Protection against handle enumeration                 | Trying to claim an existing login returns success — no distinguishable response                                                                                                                                                                                                                |
| Anti-replay                                           | SHA256(body) stored for 600s; request timestamp validated ±60s                                                                                                                                                                                                                                 |
| One-shot JWT                                          | Token is consumed on use — a stolen token can't be replayed                                                                                                                                                                                                                                    |
| Database field isolation                              | Every field is encrypted with a separate AAD domain; wrong AAD → decryption error                                                                                                                                                                                                              |
| Size padding                                          | Bodies padded to 32–64 KB blocks, headers to 4–8 KB — hides operation length and type                                                                                                                                                                                                          |
| Identity verification                                 | Out-of-band emoji fingerprint — MITM during invite exchange is detectable by users                                                                                                                                                                                                             |
| Two-factor protection of local data                   | Password + server component; disk theft without password and server = no access                                                                                                                                                                                                                |
| Memory zeroization                                    | All secret types erase memory on drop (`zeroize`); keys do not remain in memory                                                                                                                                                                                                                |
| Atomic file operations                                | Keys written with `tmp + rename + fsync`; interruption does not corrupt state                                                                                                                                                                                                                  |
| Crash-safe key rotation                               | Unfinished rotation is detected and completed on startup                                                                                                                                                                                                                                       |
| Server identity pinning                               | Client verifies every response against keys from `server.identity`; changing server keys breaks the connection with all clients                                                                                                                                                                |
| Emergency account removal                             | On registration, the server generates a one-shot capability (32 random bytes); SHA-256 in DB; enough to delete the account without login after device loss                                                                                                                                     |
| Uniqueness per installation                           | All keys and seeds generated independently from CSRNG per device; no shared installation secrets                                                                                                                                                                                               |
| DEK generated by the client                           | Data encryption key created randomly by the client; sent to the server encrypted with the password; server stores an opaque blob                                                                                                                                                               |

---

## What Lithium intentionally is NOT

The limitations below are **features of the design**, not bugs. They come
directly from the security model.

* **It is not a mass-market messenger.** No groups, channels, presence status,
  reactions, threads, avatars.
* **There is no password recovery.** Losing the keystore password = permanent
  loss of access. There is no reset mechanism — not email, not SMS, not through
  the operator. This is intentional.
* **It does not store server-side history.** Messages are deleted on fetch.
  History exists only locally.
* **It does not support multiple devices.** One account = one daemon on one
  device. No synchronization between devices.
* **There are no push notifications.** Pull model — the client polls the server
  by itself. No APNs, FCM, or any push infrastructure.
* **It does not guarantee delivery of every message.** The server can refuse to
  work, lose data, affect availability. The server is not a trusted component —
  and that has an operational cost.
* **It does not work fully offline.** Decrypting local data requires a component
  from the server. This is intentional — losing access is preferred over the
  risk of reading data after device theft.
* **There is no interoperability.** Custom WireV1 protocol and custom invite
  format — intentionally no compatibility with Signal, Matrix, XMPP, or other
  systems.
* **There is no web version or SaaS.** It requires a locally running daemon. The
  operator can't provide a SaaS availability guarantee without also breaking the
  trust model.

---

## Deployment

### Requirements

* **Rust** (stable, edition 2024) — for building from source
* **PostgreSQL** — for the relay server (`lithiums`)
* **SQLite** — embedded, for the client daemon (`lithiumd`)
* **Linux or Windows** — client and server
* **Linux: `libgtk-3-dev` and `libappindicator3-dev`** (or the
  `libayatana-appindicator` equivalent) — `lithiumd` embeds an icon in the
  system tray; without these packages the build fails at the pkg-config step for
  `*-sys` crates

### Building

```bash
# All components
cargo build --release

# Relay server only
cargo build --release -p lithiums

# Client only (daemon + GUI)
cargo build --release -p lithiumd -p lithiumg
```

### Running the relay server

`lithiums` listens on plain HTTP. TLS is terminated by a reverse proxy (nginx,
Caddy, etc.) in front of the server process.

The target deployment environment is Docker Compose — all server configuration
is done through environment variables, the database password is passed through a
file (Docker secret), and the keys directory is mounted as a volume.

```bash
export DB_HOST=localhost
export DB_USER=lithium
export DB_PASSWORD_FILE=/run/secrets/db_password
export DB_NAME=lithium
export LITHIUM_KEYS_DIR=/var/lib/lithiums/keys
export LITHIUM_BIND=0.0.0.0
export LITHIUM_PORT=4108

lithiums
```

On first start, the server generates its own keys in `LITHIUM_KEYS_DIR` and
writes the `server.identity` file containing four public keys (X25519,
ML-KEM-1024, Ed25519, ML-DSA-87) in a binary format with magic bytes. This file
is the only artifact for distributing server identity — it has to be passed to
users out-of-band.

### Client daemon configuration

```bash
export LITHIUMD_SERVER_IDENTITY=/path/to/server.identity   # optional; default: {data_dir}/server.identity

lithiumd
```

The relay server address is **not** an environment variable — it is set after
the daemon starts with the IPC command `set_server_url` (from the GUI: in the
first-run configuration step). The server identity (`server.identity`) is also
imported through IPC (`set_server_identity`), not pointed to by path —
`LITHIUMD_SERVER_IDENTITY` only changes where the daemon keeps the local copy
after import. The `server.identity` file has to be delivered by the server
administrator out-of-band before the first connection. Details:
[`docs/protocol/ipc-reference.md`](docs/protocol/ipc-reference.md#set_server_url).

### Running the GUI

```bash
# Daemon must be running
lithiumg
```

On first run, the GUI walks through configuration in this order:

1. Enter the relay server URL
2. Import the `server.identity` file (server identity verification)
3. Set the keystore password (encrypts private keys on disk)
4. Enter the account name and password for the server account
5. Register the profile on the server — after registration, the GUI shows the
   **emergency account removal capability** (see below); it must be saved
6. Unlock local storage (initializes the local SQLite database — one click,
   happens automatically after registration)

### Emergency remote account removal

During registration, the server generates a random 32-byte token
(`remote_delete_capability`) and returns it to the client. The database stores
only SHA-256 of this token — the server does not know the plaintext capability
value.

If the device is lost or stolen, the user can delete their account from the
server without logging in — the capability and access to the `server.identity`
file are enough:

```
GUI → [Emergency account removal] → paste capability → [Remove]
```

The capability does not require a password or an active session. It can't be
reconstructed — losing the capability = permanently losing the ability for the
owner to remove the account. Administrative intervention is not an alternative:
handles are not stored in plaintext — the database contains only a UUID v5
derived from the handle, deterministically encrypted with the server key. The
operator can't identify or find the record by handle, username, or any other
plain identifier.

---

## Master key rotation

The daemon and the server rotate the master key every hour (by default).
Rotation is atomic and crash-safe — unfinished rotation is automatically
detected and completed on startup. Rotation rewraps keys under the new master
key without re-encrypting database data.

---

## Cryptographic foundations — libraries

| Library         | Version | Role                                       |
| --------------- | ------- | ------------------------------------------ |
| `aes-gcm-siv`   | 0.11.1  | AES-256-GCM-SIV (AEAD)                     |
| `hkdf`          | 0.12    | HKDF-SHA256 (KDF)                          |
| `pqcrypto`      | 0.18.1  | ML-KEM-1024 (Kyber), ML-DSA-87 (Dilithium) |
| `ed25519-dalek` | 2.2.0   | Ed25519 (classic signatures)               |
| `x25519-dalek`  | 2.0.1   | X25519 (classic ECDH)                      |
| `argon2`        | 0.5.3   | Argon2id (passwords, DEK wrapping)         |
| `zeroize`       | 1.8.2   | Memory zeroization on Drop                 |
| `secrecy`       | 0.10.3  | Secret types (SecretBox)                   |

All of `lithium_core` has `#![forbid(unsafe_code)]`.

---

## Security model — summary

Lithium assumes that:

* the server is or can be hostile, monitored, or legally forced to cooperate,
* the client's disk can be seized,
* the operator is not and can't be a trusted party for content confidentiality.

In response to these assumptions:

* the server mathematically can't decrypt message content,
* the operator does not participate in user pairing or identity verification,
* server compromise does not give access to message history,
* client disk compromise without the password and without the server gives no
  access to data,
* losing key material leads to loss of access — never to recovery by a third
  party.

**Lithium is not meant to be convenient. It is meant to be hard to betray.**

---

## Technical documentation

* [`docs/`](docs/index.md) — documentation index (for auditors and integrators)

  * [`docs/security-model.md`](docs/security-model.md) — trust model, priorities, conscious trade-offs, classification of audit findings
  * [`docs/protocol/crypto-protocol.md`](docs/protocol/crypto-protocol.md) — cryptographic protocol specification: transport, E2E, mailbox, pairing
  * [`docs/protocol/ipc-reference.md`](docs/protocol/ipc-reference.md) — daemon IPC protocol reference
  * [`lithium_core/docs/kyberbox.md`](lithium_core/docs/kyberbox.md) — security analysis of the KyberBox scheme
  * [`docs/operations/deploy-instructions.md`](docs/operations/deploy-instructions.md) — `lithiums` deployment (Docker, TPM, environment variables)
* [`lithium_core/README.md`](lithium_core/README.md) — cryptography, secret types, key management
* [`lithiumd/README.md`](lithiumd/README.md) — client daemon: IPC, E2E, mailbox, SQLite
* [`lithiums/README.md`](lithiums/README.md) — relay server: REST API, middleware, transport, PostgreSQL
* [`lithiumg/README.md`](lithiumg/README.md) — GUI: state machine, thread model

---

## License

Lithium is released under the **GNU AGPL-3.0-only** license (file
[`LICENSE`](LICENSE)) — free open-source software. Anyone can read, audit,
modify, and use it, as long as they comply with the AGPL (including providing
source code also to users who access the software over a network).

**Dual licensing.** For uses that can't comply with the AGPL (for example,
including it in a closed-source product), a separate **commercial license** is
available. Evaluation is welcome; for a commercial license or
deployment/integration work, write to **[oktawia.handerek@gmail.com](mailto:oktawia.handerek@gmail.com)**.

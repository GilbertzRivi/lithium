# Lithium: security model and design assumptions

## Project goal

Lithium is not a consumer messenger.

It is a messenger designed for environments where the server, the 
operator, the infrastructure, the storage, and the local runtime 
may be partly or completely untrusted.

The project's priority isn't convenience. The priority is limiting 
trust.

## Priorities

Lithium's priorities are, in order:

1. content confidentiality,
2. limiting trust in the operator and the server,
3. minimizing metadata,
4. limiting retention,
5. making later data recovery harder,
6. and only last, convenience and the classic reliability of a 
   messenger.

If convenience clashes with privacy or the trust model, privacy 
wins.

## Trust model

Lithium assumes that:

* the server may be malicious, compromised, monitored, or legally 
  compelled to cooperate,
* the operator cannot be treated as trusted for data 
  confidentiality,
* the client's storage may be seized,
* operating memory may be seized or dumped,
* the client's local environment is not secure by default,
* the out-of-band channel used to bootstrap trust is a required 
  part of the security model.

## What Lithium should provide

Lithium aims for:

* the server not knowing message content,
* the server not being a source of trust between users,
* the operator being mathematically unable to reveal data,
* a server compromise giving access to as close to nothing as 
  possible,
* a disk compromise not allowing data recovery,
* losing part of the state being allowed to mean losing data, if 
  that reduces the risk of compromise.

## Deliberate trade-offs

The following are not bugs. They are features that follow from the 
project model.

### No delivery guarantee

Lithium does not guarantee that every message is delivered.

### Limited retention

Messages are ephemeral and kept on the server only for a limited 
time.

### One-time fetch

Messages are designed as one-time fetch and are deleted after 
retrieval.

### Constant-rate auto-fetch (cover traffic)

The daemon sends and fetches at a fixed cadence 
(`lithiumd/src/traffic.rs`): one send emission and one fetch per 
tick, regardless of real activity. Real messages ride the slots of 
that same cadence, and empty slots are filled with dummies to the 
daemon's own cover mailbox (self-loop), which the daemon drains 
with its own fetch. This way the server (a local passive 
adversary) can't tell *when* or *how much* you really send, or 
which mailboxes are real conversations. Manual fetch was removed: 
fixed-cadence polling is the only path, because bursty real 
traffic on top of the noise would leak through timing.

Limits: the throughput of real sends is capped by the rate (one 
slot per tick), and receive latency grows with the number of 
mailboxes in rotation (contacts times the generation window) times 
the fetch interval. The mere fact of being online stays metadata, 
the defense is against the server, not against a global passive 
adversary (24/7 traffic is out of scope).

### No full offline unlock

Offline unlock is not a project goal.

Decrypting local data depends in part on a component recovered 
from the server, that is a deliberate decision. Losing the ability 
to decrypt data is preferred over leaving it recoverable after 
loss of control over the device.

### Recoverability loses to security

In many places Lithium prefers irreversible loss of access over 
convenient recovery.

This is not a UX bug. It is an assumption.

### Deterministic encryption of the user identifier on the server

The user identifier in the server database is derived 
deterministically from the handler (`UUID v5`) and encrypted 
deterministically (the nonce is derived from the UUID and the 
DEK).

This is a deliberate trade-off required by the lookup semantics, 
without determinism the server would have to store the plaintext 
handler or an extra mapping table.

Consequence: the same user always gives the same `id_enc`. But 
because the database holds exactly one row per user, repeats in the 
database aren't possible. Two database snapshots reveal nothing 
beyond the fact that a given row still exists, the handler can't be 
reconstructed from it because it is encrypted and hashed.

This is not a vulnerability in Lithium's model, but it is a 
deliberate departure from the semantics of non-deterministic 
encryption.

### Local resource exhaustion

Some in-memory structures grow in proportion to the number of 
unique values in requests. Example: `contact_fetch_locks` in 
`lithiumd`, the map grows with the number of unique `contact_id` 
values and is never cleared.

In normal use this is a few dozen entries and is irrelevant. Under 
intentional flooding with random identifiers the map grows 
without bound.

This is a deliberate decision. Lithium is not a messenger for 
anonymous, untrusted clients. A party that has access to a mailbox 
is an authenticated party, and someone who deliberately exhausts 
their own resources is hurting themselves. Bounded resource 
exhaustion by untrusted requesting parties is not a threat in 
Lithium's model, because it doesn't violate the confidentiality or 
integrity of data.

## The server

The server is by definition untrusted for confidentiality.

The server may:

* refuse to operate,
* lose data,
* delete data,
* affect availability,
* try to correlate user behavior.

The server should not be able to:

* decrypt content,
* establish trust between peers,
* take part in pairing users.

## What the server sees per request

Every request is encrypted with KyberBox (X25519 + ML-KEM-1024, 
AEAD AES-256-GCM-SIV) and padded to a random block (32-64 KB for 
the body, an eighth of that for headers) before it even reaches 
the server logic. The server strips the padding only after 
decryption. TLS itself is terminated by the reverse proxy in front 
of `lithiums`. From this it follows that the server knows neither 
the content nor the real plaintext size. The table below says what 
the server actually sees.

| Endpoint | Mode / Auth | What the server sees | What it doesn't see |
|---|---|---|---|
| `shake` | Shake / keys in headers | a one-time handshake, ephemeral public keys | identities, content |
| `register_start/finish` | Session / keys in headers | the handler (transiently), OPAQUE messages, the client's encrypted DEK | passwords, content |
| `login_start/finish` | Session / handler | the handler, the OPAQUE flow; returns the encrypted DEK | passwords, content |
| `msg/send` | Session / keys in headers + PoW | the mailbox address (16/32 B, pseudo-random), the padded content blob, the PoW nonce | sender, recipient, content |
| `msg/fetch` | Session / keys in headers | the mailbox address | who reads, content |
| `revoke` | Session / keys in headers | a remote-delete capability | the owner's identity |
| `delete` | Session / JWT | a session token pointing at an account | passwords, content |

The handler is visible transiently only at register and login, 
because it is needed as the identifier of the OPAQUE credential 
and to compute `id_enc`. It is never stored raw and never comes 
with a password. The only thing that leaks from this is the 
existence of a given nick, not its content or any link to 
activity. The storage mechanics are in the "Deterministic 
encryption of the user identifier on the server" section.

The keys that sign the `msg/send` request are ephemeral, generated 
per request, so the server doesn't link the sender to their 
identity. The mailbox address is pseudo-random and unlinkable to 
an account, the server routes by mailbox, not by identity.

The IP and request time are inherent to every HTTP connection, 
because they come from the TCP layer, not from the Lithium 
protocol. Hiding them is pushed onto the user (Tor, VPN) and 
remains a deliberate non-goal.

## The local client and IPC

The local daemon and IPC are a privileged boundary.

This is one of the most important security boundaries in the whole 
system, because the daemon has access to:

* plaintext,
* the unlocked cryptographic state,
* destructive operations,
* administrative operations,
* operations on identity and local state.

In practice this means that breaking IPC or the local permission 
model can bypass a large part of the network protections.

That is why issues around IPC, local authorization, permissions, 
and the state model are real security problems.

### The IPC authorization model

The socket is created with `0600` permissions, and on Linux the 
peer is identified by `SO_PEERCRED`, the boundary is the same UID. 
Protected commands need a session token issued by `unlock_keystore` 
and (on Linux) bound to the UID+PID of the connection that 
received it. The token is invalidated by `lock_keystore` and 
`wipe_local`.

Without a token, only the commands that by nature don't need one 
work:

* `ping`,
* `unlock_keystore`, which issues the token itself,
* `remote_delete`, where the capability is the authenticating 
  secret and must work without an unlocked keystore (deleting the 
  account on the server when it can no longer be unlocked locally).

`set_server_url` and `set_server_identity` are bootstrap 
configuration: `unlock_keystore` refuses to start until the URL is 
set, and the token only exists after unlock, so on first run they 
can't be token-gated. They are therefore allowed without a token 
**only as long as no active session exists**; when a session is 
active, they need a token like everything else. This way a 
same-UID process that hasn't unlocked the keystore (has no token) 
can't quietly redirect the client to another server or swap the 
pinned server identity on a live session. A legitimate client 
attaches a token to every request after unlock anyway, so the 
change is transparent to it.

## Logging and observability

Lithium logs minimally and **does not log sensitive material**. 
Across the whole codebase there is no logging of message 
plaintext, handlers, passwords, the DEK or keys, mailbox 
addresses, or `contact_id`.

What actually reaches the output:

* `lithiumd`: `eprintln!("fatal: {e}")` on a critical startup 
  error (an error code, no secrets).
* `lithiumg`: emoji font loading messages (`eprintln!`).
* `lithiums`: a one-time `tracing::info` on the first run (`wrote 
  server.identity to {path}`) and `tracing::error` from the 
  background tasks (`mk_rotator`, `msg_reaper`) on failure, an 
  error message, no user data.

The server **keeps no** structured request log or access log, has 
no telemetry and no "phone-home". The mailbox addresses visible to 
the server are not logged.

**Operational caveat:** the reverse proxy in front of `lithiums` 
(terminating TLS) may, on its own, log client IP addresses and 
timestamps, that is outside the application's control and depends 
on the operator's configuration. The anti-flood guard 
(`pre-replay`) keys on the connection's `remote_addr`; the 
consequences of running behind a proxy are in 
[deploy-instructions.md](operations/deploy-instructions.md).

## Destructive operations

Lithium accepts an asymmetry:

* decryption should be harder,
* destroying local state may be easier.

A missing secret leads to data loss.
A missing secret must not lead to data recovery.

Wipe local is a destructive operation. It is not recovery.

## What should be audited as a real problem

The real problems are the things that break Lithium's assumptions, 
in particular:

* bypassing the identity model,
* MITM or peer substitution despite the OOB model,
* breaching the IPC and local daemon boundary,
* crash consistency and key rotation bugs,
* silent loss of integrity or keys,
* bugs causing an implicit overwrite of cryptographic state,
* bugs revealing plaintext or sensitive key material outside the 
  assumed model,
* bugs that break the explicitly declared security guarantees.

## What not to report as a vulnerability without context

The following should not be automatically classified as 
vulnerabilities without reference to the threat model and the 
non-goals:

* no delivery guarantee,
* constant-rate auto-fetch (polling) instead of manual fetch,
* one-time fetch + delete,
* limited retention,
* no offline unlock,
* no recovery through the operator,
* the possibility of data loss after losing the server component,
* preferring destruction of local state over its recovery,
* resource exhaustion triggered by an authenticated party on its 
  own endpoint (local DoS).

## Classification of audit findings

Every finding should be classified as one of:

1. **vulnerability**, breaks Lithium's security assumptions,
2. **trade-off**, consistent with the model but costly 
   operationally or in UX,
3. **non-goal**, concerns something Lithium deliberately doesn't 
   provide.

Without this distinction the system will be assessed wrongly.

## Changing server.identity is deliberately painful

The daemon caches `ServerBootstrap` (the server public keys loaded 
from the local `server.identity`) for the lifetime of the process 
(`ProtocolManager::bootstrap_cache`). If the operator changes 
`server.identity` on the server (for example after a re-key 
following a compromise), the client must manually obtain the new 
file (over an OOB channel) and load it with the IPC 
`set_server_identity` command, which immediately invalidates the 
cache (`proto.invalidate_bootstrap_cache()`), the new identity 
takes effect from the next request, without needing 
`lock_keystore`/`unlock_keystore`.

The key property doesn't depend on the cache mechanics, only on 
the cryptographic construction: until the client loads the new 
identity, every attempt to talk to the rotated server ends in a 
hard error, not silent degradation. The client encrypts `Shake` to 
the `shake_pub_x/k` from the old file, the server, decrypting with 
the real (already rotated) private key, gets a different shared 
secret and AEAD rejects the request. Even if the request somehow 
got through, the server's response signature is verified under the 
old `server_sig_ed/dili`, and with a signature by the new keys the 
verification fails (`server_signature_invalid`). There is no 
retry, no fallback, and no automatic fetch of the new identity 
from the server, the client simply can't talk to the server until 
the operator distributes the new file OOB and the user loads it 
manually.

This is a deliberate decision. The operator has no access to 
clients' devices and can't force a trust update without their 
knowledge and a deliberate action. Automatic server-key updates 
would open a vector for an operator who wants to swap keys without 
the user's knowledge.

This applies not only to a re-key after compromise, but to 
`server.identity` in general: the protocol defines no URL or 
endpoint from which this file could be fetched automatically, 
neither on first run nor on refresh. Such an endpoint never 
existed and is not planned. The only path is the out-of-band 
channel and manually loading the file with the `set_server_identity` 
command, always, with no exceptions.

The hardness of this block (communication breaks entirely, it 
doesn't degrade) is a security feature, not a UX flaw.

## Audit as a new construction

Part of the Lithium protocol is home-grown and should be analyzed 
as a new cryptographic construction, not as a composition of 
known, reviewed blocks:

* KyberBox, the KEM-DEM hybrid (`lithium_core/src/crypto/kyberbox.rs`),
* the Shake and Session transport (`lithiums/src/transport/mod.rs`),
* the WireV1 E2E layer with the ratchet (`lithiumd/src/e2e/`).

These parts are bespoke for historical reasons, not out of a 
principled choice. The protocol grew organically (Python + RSA 
moved to a post-quantum construction) and there is no honest 
"home-grown over the standard" justification for it. The right 
framing to the auditor is simple: this is a home-grown hybrid 
construction, please analyze it as a new one.

The newer protocol elements are deliberately integrations of 
reviewed standards, not hand-rolled:

* OPAQUE through the `opaque-ke 4.0.1` library 
  (draft-irtf-cfrg-opaque),
* PoW = hashcash (`lithium_core/src/pow.rs`).

There the audit is a review of the integration (how the standard 
was wired in), not a review of the construction. Hand-rolling 
OPAQUE would recreate exactly the bespoke-surface problem these 
integrations avoid.

The primitives and their versions (current, patched):

| Layer | Primitive | Implementation |
|---|---|---|
| Classical encryption | X25519 | x25519-dalek 2.0.1 |
| PQ encryption | ML-KEM-1024 | pqcrypto 0.18.1 (FFI to PQClean C) |
| AEAD | AES-256-GCM-SIV | aes-gcm-siv 0.11.1 |
| Classical signature | Ed25519 | ed25519-dalek 2.2.0 |
| PQ signature | ML-DSA-87 | pqcrypto 0.18.1 (FFI to PQClean C) |
| KDF | HKDF-SHA256 | hkdf 0.12 |
| Passwords | Argon2 | argon2 0.5.3 |
| PAKE | OPAQUE (ristretto255 + argon2) | opaque-ke 4.0.1 |

Scope boundary: the PQClean C code, used through FFI in 
`pqcrypto`, is an unaudited external dependency and stays outside 
the scope of reviewing the Lithium construction.

## Summary

Lithium is not meant to be convenient. It is meant to be hard to 
betray.

If a feature increases recoverability, convenience, or classic 
user comfort at the cost of more trust in the operator, more 
metadata, or more data recoverability after a compromise, then 
that feature is not a benefit by default.

In Lithium it is very often the other way around.

This is not a design mistake. It is the design.

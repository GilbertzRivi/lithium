# Threat model (adversary-oriented)

A companion to [security-model.md](security-model.md), which 
describes the trust model, the priorities, and the deliberate 
trade-offs. This document comes at it from the **adversary** side: 
for each attacker class it lists the capabilities, Lithium's 
defense, and the residual risk. The cryptographic mechanics are in 
[crypto-protocol.md](protocol/crypto-protocol.md), and the key map 
is in [key-hierarchy.md](key-hierarchy.md).

## Protected assets

1. **Message content** (highest priority)
2. **The social graph**, who talks to whom
3. **Per-contact keys and identity**
4. **Account credential** (password) and local data at rest
5. **Metadata** (time, volume), to a lesser degree

## Adversary classes

### 1. Passive network observer

| | |
|---|---|
| **Capabilities** | Eavesdrops the client-server traffic: ciphertext, time, volume, IP addresses |
| **Defense** | TLS (at the proxy) + KyberBox transport encryption + the E2E layer; constant-rate cover traffic hides the time and volume of real messages; padding hides sizes |
| **Residual risk** | The fact a connection to the relay exists and a coarse online/offline state; the client IP (no built-in Tor) |

### 2. Active network attacker / MITM

| | |
|---|---|
| **Capabilities** | Intercept, modify, inject, attempt downgrade and replay |
| **Defense** | Pinned server identity (`server.identity`); dual-signed requests and responses; a +/-60 s timestamp window; anti-replay on the body hash (600 s); the cryptography doesn't trust TLS (KyberBox to pinned keys). MITM at pairing is closed by commit-reveal + SAS |
| **Residual risk** | DoS by cutting off traffic (no delivery guarantee, deliberate); the `server.identity` bootstrap must arrive out-of-band |

### 3. Malicious or compromised relay server (the main adversary)

| | |
|---|---|
| **Capabilities** | Reads all stored ciphertext; sees mailbox addresses + time; can drop, reorder, withhold, attempt re-injection/replay, lie about state, deny service, attempt correlation |
| **Defense** | Never has the E2E keys, so it can't read content; mailbox addresses are pseudo-random, so it can't link who-to-whom; one-time fetch (atomic delete); per-message keys are ephemeral (a restart makes them undecryptable); deterministic `id_enc` reveals only equality; the dual signature means it can't forge a peer's identity or impersonate |
| **Residual risk** | Mailbox metadata analysis (time/volume, mitigated by cover traffic); withholding/DoS (deliberate); the equality observability of `id_enc` across DB snapshots (a deliberate trade-off); it can drop, but not forge |

### 4. Device thief, without the data password

| | |
|---|---|
| **Capabilities** | A full disk image, working offline |
| **Defense** | The MK behind `Argon2id(data_password, ...)` (64 MiB, t=3); `db_dek` needs the password **and** `server_dek`; `.keyf` files encrypted; the data directory `0o700` |
| **Residual risk** | Offline brute-force of a weak password (the Argon2 cost; a min 12-character policy). `server_dek` is the second factor |

### 5. Device thief, with the data password, without the server

| | |
|---|---|
| **Capabilities** | The disk + knowledge of the data password, but no access to the server |
| **Defense** | `db_dek` still needs `server_dek` (held by the server), so the local message/contact database stays inaccessible offline |
| **Residual risk** | If the attacker also has a live server session (full account takeover), then full data. The two-factor only holds without the server's cooperation |

### 6. Malicious contact (peer)

| | |
|---|---|
| **Capabilities** | A paired contact sends crafted/malformed messages, attempts state corruption, replay, takeover of the contact slot |
| **Defense** | Per-contact isolation; dual-signature verification (unforgeable per contact); `msg_id` dedup (UNIQUE); sequence numbers only go forward (no state regression); commit-reveal blocks takeover of an established slot; fuzzed parsers |
| **Residual risk** | The contact sees what you send them (by definition); they can stop responding (DoS within that contact) |

### 7. Malicious local process (same UID)

| | |
|---|---|
| **Capabilities** | A process of the same user tries to talk to the IPC socket, read files, dump RAM |
| **Defense** | Socket `0o600` (owner only); the IPC token bound to UID+PID (Linux `SO_PEERCRED`); the token only after `unlock`; secrets zeroized on `lock`; gating of setup/RemoteDelete commands while a session is active |
| **Residual risk** | A same-UID process is largely **inside** the trust boundary, it reads the (encrypted) files, and on a race or token capture it drives the daemon; a RAM dump of an unlocked daemon reveals live keys (deliberate, "memory may be dumped"). IPC is a privileged boundary |

### 8. Supply chain / dependencies

| | |
|---|---|
| **Capabilities** | A malicious or vulnerable dependency (PQClean C, opaque-ke, ...), compromise of the build process |
| **Defense** | Pinned dependency versions; fuzzing of the parsing surfaces; OPAQUE/ML-KEM through vetted libraries (not hand-rolled) |
| **Residual risk** | The PQClean C code is unaudited (noted in the `lithium_core` [docs](../lithium_core/README.md)), inherited side channels / memory bugs; no documented reproducible-build/SBOM guarantee; outside the project's direct control |

### 9. Quantum adversary (harvest-now-decrypt-later)

| | |
|---|---|
| **Capabilities** | Records ciphertext today, decrypts it later with a quantum computer |
| **Defense** | The PQ hybrid everywhere: ML-KEM-1024 + X25519 (KEM), ML-DSA-87 + Ed25519 (signatures); breaking it requires beating the PQ half; Argon2/AES-256/SHA-256 resist realistic quantum speedup |
| **Residual risk** | If ML-KEM **alone** falls (cryptanalysis, not quantum), the X25519 half falls to quantum, so both die; this is the standard hybrid assumption. PQClean correctness is assumed |

## Forward secrecy and post-compromise security guarantees (E2E layer)

This pins down the protection limits of the E2E layer 
(`lithiumd/src/e2e/`) against an attacker who **at time T takes 
over an unlocked device** and reads `self_state` + `peer_state` 
(classes 4-7 in the full-compromise variant). The key mechanics 
are in [crypto-protocol.md](protocol/crypto-protocol.md) and the 
`lithium_core` [docs](../lithium_core/README.md); this is about 
the limits of the guarantee.

**What the attacker has at time T:** a contact's identity keys 
`ed_priv` + `dili_priv` (per contact, they **don't rotate** within 
a pairing); the RX keyring, the private keys (X25519 + ML-KEM) of 
all reply keys in the window of 32 from `ack_seq`; the bootstrap 
keys, if the bootstrap KEM hasn't been retired yet; the mailbox 
keys and the private prekeys.

**Forward secrecy (messages before T), windowed, not 
per-message.** RX keys older than the window of 32 from `ack_seq` 
are deleted and zeroized (`gc_after_ack`, `RxKey: ZeroizeOnDrop`); 
messages encrypted to those keys are undecryptable at time T. 
Messages still in the window (up to the ~32 most recent reply-key 
epochs) **are** decryptable from the compromised keyring, that is 
a trailing window exposed on compromise. The ML-KEM seed is fresh 
per message, but the X25519 component is shared within an epoch, 
so one RX key exposes the whole epoch encrypted to it. As long as 
the bootstrap hasn't been retired, the bootstrap keys expose a 
contact's first messages.

**Post-compromise security (messages after T), conditional, 
confidentiality only, against a passive attacker only.** Every 
message injects new entropy (a fresh ML-KEM seed, a fresh sender 
ephemeral, rotating RX keys). If after T the attacker is 
**passive**, then once both sides move to RX keys generated after 
T (which it didn't intercept), the confidentiality of new messages 
**rebuilds**, the identity keys aren't used for decryption, so 
holding them doesn't help here. The rebuild rides on ordinary 
traffic; there is no separate re-key ceremony. **Authentication 
never rebuilds:** since `ed_priv`/`dili_priv` don't rotate, an 
**active** attacker signs in the victim's name indefinitely and 
MITMs future key advertisements, and through the MITM breaks the 
confidentiality of future messages again. Against an active 
attacker, PCS does not hold.

**Residual risk.** The trailing window (the last ~32 epochs) is a 
deliberate cost of tolerating reordering, see the replay window in 
the `lithium_core` [docs](../lithium_core/README.md). The lack of 
identity rotation makes a full device compromise **permanent** in 
the authentication dimension: the only answer is to re-pair the 
contact with a new invite code (per-contact isolation, a new 
pairing is a new identity). This is consistent with the non-goal 
"endpoint compromise with a live, unlocked daemon" 
([security-model.md](security-model.md)), this section says *how 
far* the effects reach, it doesn't promise protection from them.

## Out of scope (non-goals)

Deliberately not covered, details in 
[security-model.md](security-model.md):

- **Delivery guarantee**, the model allows a message to be lost; 
  no acknowledgements and no guaranteed queues.
- **Recovery after losing the password or keys**, losing key 
  material is preferred over recovery vectors.
- **Hiding the very fact of using the relay**, an attacker who 
  sees the network knows the client connects to the server (no 
  built-in connection-layer anonymization).
- **Endpoint compromise with a live, unlocked daemon**, with an 
  active session the keys are in RAM.
- **Protection from your own paired contacts**, what you send 
  them, they will see.

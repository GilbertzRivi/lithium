# Security Audit — Lithium

**Date**: 2026-03-09
**Scope**: `lithium_core/`, `lithiumd/`, `lithiums/` (GUI excluded — MVP only)
**Method**: Manual code review of all cryptographic and security-relevant source files
**Update**: 2026-03-09 — uzupełniony o pełny przegląd kodu serwera (`lithiums/`)

---

## HIGH

### H-4: Private keys serialized into plain `serde_json::Value` during invite creation

**File**: `lithiumd/src/commands/invite_codec.rs`, function `gen_self_state` (approx. lines 160–172)
**Description**: The `gen_self_state` function serializes private keys (Ed25519 seed, X25519 seed, Kyber SK bytes, Dilithium SK bytes) as hex strings into a plain `serde_json::Value`. This `Value` does not implement `Zeroize` and will linger in heap memory after the function returns.
**Impact**: Private key material may persist in process memory longer than necessary, increasing exposure in the event of a memory dump or use-after-free.
**Recommendation**: Use a custom `SecretJson`/`SecretBytes` wrapper that implements `Zeroize` + `Drop`. Alternatively, write a dedicated encrypted binary format instead of JSON for the DB blob.

### H-5: E2E messages have no explicit sender identity binding

**File**: `lithiumd/src/commands/e2e.rs`, function `decrypt_for_us`
**Description**: Decrypted E2E message payloads are accepted based solely on which mailbox they arrived in. The mailbox address is derived from both parties' X25519 static keys via DH, which provides implicit authentication — but only if those keys are trusted. If peer keys were substituted (see H-3), the mailbox computation silently succeeds and the attacker's messages pass as authentic. There is no explicit sender signature on the message payload.
**Impact**: Combines with H-3 to allow full impersonation if keys were MITM'd at invite time.
**Recommendation**: Sign message payloads with the sender's Ed25519 or ML-DSA-87 key. Verify the signature against the stored peer public key on receipt.

### H-6: Intermediate AEAD key not zeroized in `kyberbox`

**File**: `lithium_core/src/crypto/kyberbox.rs`, lines 92–113, 174–176
**Description**: In both `encrypt` and `decrypt`, a 32-byte `aead_key: [u8; 32]` array is filled from HKDF output and then moved into `Byte32::new(aead_key)`. After `Byte32::new()`, the local array on the stack is not explicitly zeroized. Similarly, intermediate `shared_secret` byte arrays from both X25519 and ML-KEM are passed directly into HKDF without explicit zeroization after use.
**Impact**: Stack/heap residue of ephemeral key material. Low practical risk on modern OSes with ASLR, but violates the zeroization guarantee maintained elsewhere in the codebase.
**Recommendation**: Use `zeroize::Zeroizing<[u8; 32]>` for intermediate key arrays, or call `.zeroize()` explicitly before the variable goes out of scope.

---

## MEDIUM

### M-1: `PasswordFileMkProvider::derive_secret32` ignores the `mk` parameter

**File**: `lithiumd/src/password_provider.rs`, line 158
**Description**: The `MkProvider` trait's `derive_secret32(&self, mk: &Byte32, label: &[u8])` method is overridden in `PasswordFileMkProvider` as `derive_secret32(&self, _mk: &Byte32, label: &[u8])` — the master key argument is intentionally discarded. Instead, the method derives a `combined_root` from `HKDF(server_dek, Argon2(password))`. This is architecturally intentional (binding keys to both password and server DEK) but deviates from the trait contract silently. Any caller that passes a different `mk` gets the same result regardless, which is surprising and error-prone.
**Impact**: Potential confusion if the MkProvider is used in contexts where callers expect `mk` to influence the derived secret. No immediate vulnerability, but a maintenance hazard.
**Recommendation**: Document the deviation explicitly in a comment, or restructure the trait to avoid the misleading parameter.

### M-2: DEK wrap salt is only 16 bytes; rest of codebase uses 32

**File**: `lithium_core/src/passwords/passwords.rs`, line 14 (`WRAP_SALT_LEN: usize = 16`)
**Description**: The salt used when wrapping the server-side DEK (via Argon2id) is 16 bytes, while all other salt/nonce values in the codebase are 32 bytes. The NIST minimum for Argon2 salts is 16 bytes, so this is not technically a violation, but it is inconsistent and below the project's own standard.
**Impact**: Marginally reduced precomputation resistance compared to 32-byte salts.
**Recommendation**: Increase `WRAP_SALT_LEN` to 32 bytes for consistency with the rest of the codebase.

### M-3: Account password handler (handler hex) logged at debug/warn level

**File**: `lithiums/src/api/user.rs`, lines 32 and 51
**Description**: The `handler` variable (a hex-encoded password hash or token derived from the account password) is logged with `tracing::debug!` / `tracing::warn!` macros. If debug logging is enabled in production (e.g., `RUST_LOG=debug`), password-equivalent data is written to logs.
**Impact**: Log exfiltration → account compromise.
**Recommendation**: Never log any password-derived value. Replace with a non-sensitive surrogate (e.g., account ID or a truncated HMAC for correlation).

### M-4: Anti-replay TTL (600s) inconsistent with timestamp skew window (60s)

**File**: `lithiums/src/middleware/guard.rs`
**Description**: The anti-replay store keeps request nonces (SHA-256 of ciphertext) for 600 seconds, but the timestamp validity window is only ±60 seconds. A replayed request is rejected by the timestamp check after 60s, but the nonce store holds it for 600s. The inverse mismatch — where TTL < timestamp window — is the dangerous one, but this inconsistency suggests the TTL was chosen arbitrarily and could easily regress to a dangerous value.
**Impact**: Currently benign, but a future change increasing the timestamp window above 600s would open a replay window.
**Recommendation**: Set the anti-replay TTL equal to the timestamp window (60s) or document why they differ.

### M-5: Deterministic nonce for user ID encryption

**File**: `lithiums/src/db/repo.rs`
**Description**: User IDs are encrypted in the database with a deterministic nonce derived via `HKDF(UUID || DEK, ...)`, enabling lookup without storing the plaintext. This reuses the same nonce for the same user ID every time. AES-256-GCM-SIV (used throughout) is specifically nonce-misuse resistant, so this is not a catastrophic flaw, but it creates a deterministic ciphertext that reveals when two records share the same user ID.
**Impact**: Under AES-GCM-SIV, nonce reuse does not break confidentiality, but it does break ciphertext unlinkability. An attacker with DB read access can correlate records belonging to the same user.
**Recommendation**: Document this as an intentional trade-off. Consider adding a second encrypted index that maps a random token → user ID if unlinkability is required.

### M-6: No connection limit or timeout on IPC socket

**File**: `lithiumd/src/ipc/mod.rs`
**Description**: There is no limit on the number of concurrent IPC connections accepted by the daemon, and no idle or request timeout. A local process can open many connections and hold them open indefinitely, exhausting file descriptors or blocking the event loop.
**Impact**: Local denial of service of the daemon.
**Recommendation**: Limit concurrent connections (e.g., max 8) and add a per-connection idle timeout (e.g., 30s).

---

## LOW

### L-1: `eprintln!` used instead of structured logging

**File**: `lithiumd/src/ipc/unix.rs:31`, `lithiumd/src/commands/unlock_keystore.rs:93`
**Description**: Some error paths use `eprintln!` for output instead of the project's `tracing` logging framework. This bypasses log level filtering, log aggregation, and structured log fields.
**Impact**: Operational; no security impact. Error messages may appear in unexpected places or be silenced in non-terminal environments.
**Recommendation**: Replace `eprintln!` with `tracing::error!` or `tracing::warn!`.

### L-2: Contact ID not length-validated after hex decode

**File**: `lithiumd/src/commands/contact_send.rs`, `contact_fetch.rs`
**Description**: The contact ID is decoded from hex and used to derive the mailbox address via X25519 DH and HKDF, but its length is not explicitly validated before use. If a malformed (wrong-length) CID passes hex decoding, downstream operations may panic or silently truncate.
**Impact**: Potential panic or incorrect mailbox derivation with a malformed CID. Exploitable only by a local attacker who controls IPC input.
**Recommendation**: Assert or return an error if the decoded CID is not exactly 32 bytes before passing it into cryptographic functions.

### L-3: Server URL in invite code not validated

**File**: `lithiumd/src/commands/invite_create.rs`
**Description**: The server URL embedded in the invite code is taken from configuration and included in the invite without scheme validation. An invite could contain a non-HTTPS URL (e.g., `http://...`) and the daemon would connect over plaintext.
**Impact**: Downgrade to plaintext transport if an attacker can influence the server URL in the invite.
**Recommendation**: Validate that the URL scheme is `https` before including it in the invite, and reject `http://` URLs at invite-accept time.

### L-4: Prekey consumption is not atomic

**File**: `lithiumd/src/db/repo.rs` (contact state / prekey take)
**Description**: The operation of reading a prekey bundle and marking it consumed involves separate DB read and write operations without a transaction lock visible in the reviewed code. A race condition (e.g., two simultaneous `contact_send` calls) could cause the same prekey to be consumed twice.
**Impact**: Prekey reuse — both senders would derive the same KEM shared secret, weakening forward secrecy for that exchange.
**Recommendation**: Wrap the prekey read+mark-consumed operation in a single atomic transaction or use a DB-level row lock.

---

## Server-side findings (lithiums)

### S-C1: No rate limiting on `/user/register` endpoint

**File**: `lithiums/src/api/user.rs`, `lithiums/src/db/repo.rs::create_user`
**Description**: Registration runs full Argon2id (m=64MB, t=3) for each attempt (password hash + handler hash = 2× Argon2). Without rate limiting, an attacker can submit thousands of registrations consuming all server CPU and RAM. Unlike login, registration failure returns `"user_exists"` or success — this also allows username enumeration: submitting a registration with a known username returns `"user_exists"`.
**Impact**: (1) DoS via Argon2 exhaustion. (2) Username enumeration — attacker learns which handles are taken.
**Recommendation**: Rate-limit registration by IP (e.g., max 3 per hour). Consider returning the same success response regardless of whether user exists (or always returning 202 Accepted with deferred processing).

---

### S-H1: Message key lost on server restart — permanent data loss

**File**: `lithiums/src/db/repo.rs`, `add_message` (lines 273–304)

Per-message encryption key (`msg_key: Byte32`) is generated randomly and stored only in the in-memory `EphemeralStoreManager` with TTL=24h. The encrypted message body is written to the DB. On server restart, the EphemeralStore is wiped — all pending message keys are lost. The DB rows remain but are permanently undecryptable. A receiver who hasn't fetched their messages within the server's uptime window loses them silently.

**Impact**: Silent, permanent message loss on server restart within the 24h delivery window.
**Recommendation**: Either (a) derive `msg_key` deterministically from the message ID and a persistent server secret (so it can be recovered after restart), or (b) document prominently that the server must not restart during the delivery window and implement a graceful shutdown that flushes the store to encrypted persistent storage.

---

### S-H2: JWT tokens are single-use but this is not communicated to the client

**File**: `lithiums/src/transport/mod.rs`, `get_user_from_token` (line 207)

```rust
let value = store.take(&format!("token:{token}")).await?  // destructive read
```

Every JWT is removed from the store on first use (`take` not `peek`). This makes JWTs single-use — sending the same JWT twice causes a "invalid jwt 2" error. The client in `lithiumd/src/protocol_manager.rs` handles this correctly (always fetches a fresh JWT before each authenticated request), but this behavior is implicit and not documented. Any other client implementation that reuses a JWT will silently fail to authenticate.

**Impact**: Interoperability risk; difficult to debug for future client implementors.
**Recommendation**: Document the single-use JWT property explicitly in the API specification.

---

### S-H3: Server's `PlainFileMkProvider` stores master key in plaintext on disk

**File**: `lithiums/src/main.rs`, line 102; `lithium_core/src/keys/manager.rs`, lines 49–57

The server uses `KeyManager::<PlainFileMkProvider>::start_plain(...)`. `PlainFileMkProvider` stores the master key as raw bytes on disk with 0o600 permissions — no password protection, no HSM, no encryption at rest. All server private keys (X25519, ML-KEM-1024, Ed25519, ML-DSA-87) are derived from this plaintext master key.

**Impact**: If an attacker reads the `mk` file (e.g., via path traversal, backup misconfiguration, or file system snapshot), they obtain all server long-term private keys. This allows decryption of all past session establishment (Shake) handshakes and forgery of server signatures.
**Recommendation**: For production, protect the MK file using OS-level key management (e.g., Linux Keyring, TPM, or an HSM). At minimum, document that the `mk` file is the single point of key trust for the entire server and must be protected with filesystem-level access controls, full-disk encryption, and backup isolation.

---

### S-H4: Username (`handler`) exposed in plaintext in `warn!` log on failed registration

**File**: `lithiums/src/api/user.rs`, line 71–74

```rust
warn!(
    handler = %handler.expose(),   // plaintext username in production log
    "register user_exists"
);
```

This `warn!` fires for every attempt to register an already-taken username. At `RUST_LOG=warn` (appropriate for production), every such attempt logs the attempted username in plaintext. Combined with S-C1 (no rate limiting), an attacker can enumerate all registered usernames and watch them appear in server logs.

**Impact**: PII leakage; enables username enumeration via logs.
**Recommendation**: Replace `handler = %handler.expose()` with a non-reversible token (e.g., `handler_hash = %sha256_hex(handler.expose().as_bytes())`).

---

### S-M1: `build_crypto_context` logs decrypted body field names at `debug` level

**File**: `lithiums/src/transport/mod.rs`, lines 378–383

```rust
debug!(
    body_keys = ?body_keys,         // field names of decrypted request body
    app_header_keys = ?header_keys,
    "parsed decrypted json"
);
```

With `RUST_LOG=debug`, every request logs the field names of the decrypted application-layer body. While field names are not sensitive by themselves, this demonstrates that debug logging partially pierces the application-layer encryption — a pattern that could be extended accidentally by future developers.

**Impact**: Metadata leakage in debug mode; encourages pattern of logging decrypted content.
**Recommendation**: Remove body field name logging entirely, or log only at trace level with an explicit "dangerous-for-production" comment.

---

### S-M2: Anti-replay store uses `set_if_absent` on full ciphertext hash — DOS risk at scale

**File**: `lithiums/src/middleware/guard.rs`, `anti_replay_check`

```rust
let key = format!("replay:{}", hex::encode(Sha256::digest(body)));
```

The replay store key is `"replay:"` + SHA-256(raw_ciphertext_body). For a server with many users, the EphemeralStore grows by one entry per request, held for 600 seconds. At 1000 req/s, that's 600,000 entries in RAM simultaneously. Each entry stores `"1"` as value but the key string is 78 bytes ("replay:" + 64 hex chars). At 1000 req/s this is ~50MB/s of store growth (bounded by 600s TTL cleanup).

There is no per-IP throttling at this layer — the only limit is the 1MB body check. An attacker can send millions of small (valid or invalid) requests and fill the replay store.

**Impact**: Memory exhaustion DoS on high-traffic servers.
**Recommendation**: Add per-IP rate limiting before the anti-replay check. Consider using a Bloom filter or time-bucketed counter for replay detection at scale.

---

### S-M3: Session keys stored in EphemeralStore with `session_id` as hex of random 32 bytes — predictability concern

**File**: `lithiums/src/transport/mod.rs`, `reply_ok` (lines 494–518)

```rust
let session_x_id = keys::random_32()?.to_hex();  // 64-char hex session ID
self.state.store.set(&session_x_id.expose(), &SecretBytes::from_slice(session_priv_x.as_slice()), ...).await?;
```

Session key IDs are random 32-byte hex strings used as EphemeralStore lookup keys. These IDs are sent to the client in the response headers (`ses-x`, `ses-k`) — the client echoes them back in subsequent requests. If an attacker can observe these IDs (e.g., from a compromised TLS layer or server log), they could attempt to look up the session key in the store.

The store is in-memory and not accessible externally, so this is low-risk in practice. However, the session ID and the session key are stored under the same key — there is no additional MAC or binding between the session ID and the client's identity.

**Impact**: Low in isolation, but the session key lookup has no client-identity binding — any request that includes the `ses-x`/`ses-k` headers can consume the session keys, even if it's not from the original client.
**Recommendation**: This is an architectural note. Consider binding session keys to the client's ephemeral public key (already present as `key-x` in headers) to prevent session key hijacking.

---

### S-M4: `get_messages` deletes DB rows before decrypting — message loss if key missing

**File**: `lithiums/src/db/repo.rs`, `get_messages` (lines 307–364)

```rust
// Inside transaction:
for m in &ms {
    messages::Entity::delete_by_id(m.id).exec(txn).await?;
}
// After transaction committed:
for (id, blob) in rows {
    let Some(kbox) = store.take(key_str.expose()).await? else { continue; };  // if key missing: skip silently!
    if let Ok(pt) = open_msg(...) { out.push(pt.to_hex()); }  // if decrypt fails: skip silently!
}
```

Messages are deleted from the DB within the transaction before attempting to retrieve their decryption keys from the EphemeralStore. If `store.take()` returns `None` (key expired or server restarted), the message is silently skipped — it has already been deleted from the DB. The client receives a truncated list with no indication that messages were lost.

**Impact**: Silent message loss; client cannot distinguish "no new messages" from "messages lost".
**Recommendation**: Reverse the order: look up all keys from the store first, then delete only the DB rows whose keys were successfully retrieved. Return an error to the client if any key is missing.

---

---

## Findings from `keys/manager.rs`, `contact_fetch.rs`, `contact_send.rs`, `messages.rs`

**Update**: 2026-03-09 — dodatkowy przegląd `lithium_core/src/keys/manager.rs`,
`lithiumd/src/commands/contact_fetch.rs`, `contact_send.rs`, `lithiums/src/api/messages.rs`

---

### N-H1: `ensure_kyber`/`ensure_dilithium` silently generate a new keypair when public key file is missing

**File**: `lithium_core/src/keys/manager.rs`, lines 203–234

When the private key file exists but the public key file is missing, `ensure_kyber` and
`ensure_dilithium` do **not** recover the public key from the stored private key. Instead:

```rust
if priv_path.exists() {
    let _ = keyfile::load_bytes_decrypted(&priv_path, mk, KT_KYBER)?;  // reads and discards
    if !pub_path.exists() {
        let (pk, sk) = mlkem1024::keypair();         // generates a BRAND NEW keypair
        keyfile::save_bytes_encrypted(&priv_path, mk, sk.as_bytes(), KT_KYBER)?;  // overwrites!
        keyfile::write_secure(&pub_path, pk.as_bytes())?;
    }
}
```

Contrast with the correct implementation for Ed25519 and X25519, which correctly derive the
public key from the stored private key bytes. The PQ variants silently overwrite the private
key with a newly generated one.

**Trigger scenarios**: Any accidental deletion of the `.pub` file, or a deployment that
copies only the private key files. On next startup, all four key pairs become inconsistent —
the public keys distributed to peers no longer match the server's private keys.

**Impact**: If triggered on a server with active users:
- All existing contacts can no longer decrypt messages (wrong Kyber SK)
- All server signature verifications fail for clients holding the old Ed25519/ML-DSA-87 public keys
- No error is returned — startup succeeds, the system silently uses new incompatible keys

**Recommendation**: Derive the public key from the stored private key, or assert a panic/error
if the public key file is missing while the private key exists. For ML-KEM-1024, if the
`pqcrypto` API does not support public-key derivation, store a copy of the public key inside
the encrypted private key file.

---

### N-H2: `wipe_local` does not securely erase key material from disk

**File**: `lithiumd/src/commands/wipe_local.rs`, `lithiumd/src/util.rs:133–138`

```rust
pub fn wipe_dir_all(p: &Path) -> std::io::Result<()> {
    if p.exists() {
        fs::remove_dir_all(p)?;  // just unlinks directory entries
    }
    Ok(())
}
```

`fs::remove_dir_all` removes directory entries (dentries) from the filesystem. On all
common filesystems (ext4, btrfs, APFS, NTFS, FAT32, SQLite WAL), it **does not overwrite
the underlying file data**. The blocks containing key material remain on disk until the
filesystem reuses them, which may never happen on SSDs with wear-leveling.

The `base_dir` contains:
- Encrypted keyfiles (`ed25519.keyf`, `x25519.keyf`, `kyber-mlkem1024.keyf`, `dilithium-mldsa87.keyf`, `mk.enc`) — MK-encrypted private keys
- SQLite database — contains `self_state` blobs with private key hex strings (see H-4, Z-2), prekey private blobs, message content
- The `registered.flag` marker

After `wipe_local`, a forensic examiner with disk access can recover all of the above using
standard tools (e.g., `extundelete`, `foremost`, SSD flash dump).

**Impact**: "Wipe" command provides false security guarantees. On stolen or confiscated devices,
private key material and message history are recoverable after user-initiated wipe.

**Recommendation**: Overwrite file contents with zeros before unlinking:
```rust
fn secure_delete(path: &Path) -> io::Result<()> {
    let len = path.metadata()?.len();
    let mut f = OpenOptions::new().write(true).open(path)?;
    let zeros = vec![0u8; len as usize];
    f.write_all(&zeros)?;
    f.sync_all()?;
    drop(f);
    fs::remove_file(path)
}
```
Note: on SSDs, even this is not guaranteed due to wear-leveling. Consider using OS-provided
secure deletion APIs (e.g., `BLKSECDISCARD`) or encrypting all local data under a key that
can be atomically destroyed (key-erasure pattern).

---

### N-M1: Non-atomic master key rotation in `maybe_rotate_mk`

**File**: `lithium_core/src/keys/manager.rs`, lines 153–165

```rust
pub fn maybe_rotate_mk(&mut self) -> Result<()> {
    let old_mk = self.mk_provider.load_mk()?;
    let new_mk = keys::random_master_key32()?;
    keyfile::rewrap_keyfile_dek(&self.priv_dir.join(ED_PRIV), &old_mk, &new_mk, ...)?;   // step 1
    keyfile::rewrap_keyfile_dek(&self.priv_dir.join(X_PRIV), &old_mk, &new_mk, ...)?;    // step 2
    keyfile::rewrap_keyfile_dek(&self.priv_dir.join(KYBER_PRIV), &old_mk, &new_mk, ...)?;// step 3
    keyfile::rewrap_keyfile_dek(&self.priv_dir.join(DILI_PRIV), &old_mk, &new_mk, ...)?; // step 4
    self.mk_provider.store_mk(&new_mk)?;                                                   // step 5
}
```

If the process is killed or crashes between steps 1–4 and step 5, the MK on disk is still the
old one, but some keyfiles have already been re-encrypted with `new_mk`. On the next startup,
`load_mk()` returns `old_mk` and decryption of the re-wrapped key files fails — the daemon
cannot start.

**Impact**: Permanent key loss (and daemon unavailability) if a crash occurs during MK rotation.
MK rotation happens every 3600 seconds by default.

**Recommendation**: Write the new MK to a `.pending` file before starting rewrap, and commit
(rename) it to the final path only after all four keyfiles have been successfully rewrapped.
On startup, check for a `.pending` file and resume or roll back accordingly.

---

### N-M2: Race condition in `contact_fetch` — double state write allows concurrent corruption

**File**: `lithiumd/src/commands/contact_fetch.rs`, lines 87–108 and 288–308

`contact_fetch` writes the contact state to the DB **twice** in one call:
1. Early save (lines 87–108): after `ensure_self_keyring` + `ensure_mailbox_state`
2. Final save (lines 288–308): after the entire message fetch and decrypt loop

If two concurrent `contact_fetch` calls are made for the same contact (possible if the UI
triggers two fetch operations simultaneously), the timeline can be:

```
Call A: read state → save state (write 1) → fetch messages → modify peer_v (note_inbound_generation_seen) → save state (write 2)
Call B: read state → ...                 → save state (write 1, overwrites A's write 2) → ...
```

Call B reads state before A's final write, modifies it based on a different set of fetched
messages, and overwrites A's final write. The result is that some acknowledged inbound
generations are "un-acknowledged" by the interleaved write.

**Impact**: Ratchet generation tracking inconsistency; duplicate message delivery or missed
acknowledgements on concurrent fetches.

**Recommendation**: Hold a per-contact mutex during the entire fetch-modify-save cycle, or
use optimistic locking (read version field, compare-and-swap on write).

---

### N-M3a: `unlock_keystore` aborts running MK rotator task — additional trigger for N-M1

**File**: `lithiumd/src/commands/unlock_keystore.rs`, lines 80–83

```rust
if let Some(old) = state.mk_rotator.lock().await.take() {
    let _ = old.stop_tx.send(true);
    old.handle.abort();  // Tokio task abort — cancels at next await point
}
```

When the user re-unlocks the keystore (calling `unlock_keystore` while a previous session is
active), the old MK rotation task is cancelled via `handle.abort()`. Tokio's task abort
drops the task at its next `.await` point without executing `Drop` impls for any stack
variables.

If the rotator is mid-way through `maybe_rotate_mk()` — specifically between two
`rewrap_keyfile_dek` calls — the abort leaves keyfiles in the inconsistent state described
in N-M1: some re-encrypted under the new MK, some still under the old, with neither MK
written to disk yet. On next startup, key load fails.

This makes N-M1 exploitable not only by OS crashes but by **normal user operations**
(re-authentication). The probability is low (rotation window is 30-second poll × actual
rotation work), but non-zero.

**Recommendation**: Use `old.stop_tx.send(true)` and await graceful shutdown instead of
`abort()`. Fix N-M1 (two-phase MK commit) to make this irrelevant regardless.

---

### N-M3: `contact_send` commits contact state before local message is stored

**File**: `lithiumd/src/commands/contact_send.rs`, lines 206–230

```rust
// Step 1: update contact state (advances mailbox generation)
dm.upsert_contact(contact_id.clone(), ..., new_self_bytes, ...).await?;

// Step 2: store message locally
dm.add_message(contact_id.clone(), ..., stored).await?;  // if this fails, state already advanced
```

The outbound mailbox generation counter is incremented and persisted in step 1. If the local
`add_message` call in step 2 fails (DB error), the counter is permanently advanced but the
message is not in the local store. The next send will use `mailbox_gen + 2` instead of
`mailbox_gen + 1`, creating a gap in the outbound sequence. If the receiving party depends
on generation continuity for ACKs, this can cause protocol desync.

**Impact**: Mailbox generation skip on local DB write failure; potential for missed ACKs or
ratchet desynchronization on the next send.

**Recommendation**: Wrap both operations in a single DB transaction, or reorder: store the
message locally first, then commit the state update.

---

### N-M4: E2E ratchet — reply private keys not deleted on use (forward secrecy limited)

**File**: `lithiumd/src/commands/e2e.rs`, `gc_after_ack` (560–584), `decrypt_for_us` (790–821)

After successfully decrypting a message with a reply key (`decrypt_for_us`), the private key
is **not immediately deleted**. GC runs via `gc_after_ack` which removes keys with
`seq < ack_seq - window` where `window = 64`:

```rust
let min_keep_seq = ack.saturating_sub(window);   // e.g. if ack=10, keep seq >= 10-64 = 0
// keys with seq < min_keep_seq are removed
// the just-used key has seq == ack → it stays for at least 64 more rounds
```

The just-used reply key has `seq == ack_seq` (the highest current value), so it remains in
`e2e_rx.keys` for at minimum the next 64 message exchanges. Combined with the fact that
`e2e_rx.keys` is stored in the local SQLite DB as part of `self_state` (see H-4), this means:

- At any point in time, up to `window` (64) reply key private keys are simultaneously on disk
- An attacker who exfiltrates the local DB can use these to decrypt any already-received
  messages whose ciphertext they also possess (e.g., by independently fetching from the server
  before the recipient does — see N-L1 delivery-DoS)
- If sending many messages without receiving any, all the pending reply private keys accumulate

**Additionally**: reply keys in `e2e_rx.keys` have no per-key TTL. If the peer never sends
a reply (one-way communication, lost contact, or network partition), the accumulated reply
private keys stay in the DB indefinitely — they are never subject to expiry-based cleanup.

**Impact**: The forward secrecy guarantee is bounded by `window = 64` message rounds rather
than being immediate-on-use. This weakens forward secrecy to a sliding-window model.

**Recommendation**: Delete the used reply key from `e2e_rx.keys` immediately after successful
decryption. For the out-of-order delivery use case, retain only a small window (e.g., 5 keys)
rather than 64. Add a per-key TTL (e.g., 7 days) after which unused reply private keys are
expired regardless of whether they've been ACK'd.

---

### N-M5: E2E ratchet — no client-side replay check on decrypted messages

**File**: `lithiumd/src/commands/e2e.rs`, `decrypt_for_us` (790–821)

After successful decryption, neither the `to_id` nor the `msg_id` is marked as consumed at
the client side. If the same ciphertext blob arrives twice (e.g., via a different transport
path, a network bug delivering the same blob twice, or if the server-side anti-replay is
somehow bypassed), `decrypt_for_us` will successfully decrypt it again as long as the reply
private key hasn't been GC'd.

Server-side anti-replay (SHA-256(ciphertext) with 600s TTL) prevents immediate replay via
the standard server path. However:
- The 600s TTL window means replays after 10 minutes are not caught at the server
- The client has no independent replay protection

**Impact**: In the 64-round window during which old reply keys are retained, a ciphertext
could potentially be replayed if the server anti-replay is bypassed or has expired.

**Recommendation**: Maintain a client-side set of recently-seen `msg_id` values (from the
decrypted header) with a TTL matching the key window. Reject decryption if `msg_id` was
already seen. This provides defense-in-depth independent of server anti-replay.

---

### N-L1: `msg/fetch` unauthenticated by design — informational note

**File**: `lithiums/src/api/messages.rs`, `lithiums/src/main.rs`

The `fetch` handler does not verify a JWT user — it accepts any request that passes the
KyberBox + signature middleware. This is a deliberate design choice with two layers of
protection that make it sound:

1. **Mailbox address confidentiality**: The mailbox address is derived from
   `HKDF(DH(x_priv_sender, x_pub_receiver), salt=cid_A||cid_B||gen)` — the DH output is
   effectively 32 bytes of keyed randomness. An attacker cannot enumerate or guess valid
   mailbox addresses; brute force is computationally infeasible.

2. **Recipient-keyed encryption**: Even if an attacker knows a mailbox address and fetches
   its contents, the blobs are encrypted with KyberBox under the recipient's X25519 and
   ML-KEM-1024 public keys. Without the recipient's private keys, the content is opaque.

The one residual concern is a **delivery DoS**: an attacker who already knows a mailbox
address (e.g., by compromising one party's static X25519 key) can drain messages before the
legitimate recipient fetches them. The messages are deleted from the DB on fetch (see S-M4),
so a malicious drain is permanent. This is not a privacy breach — only a delivery failure —
but it does not require decryption capability.

**Impact**: Informational — the security model is correct and the design is sound.
**Recommendation**: Document explicitly in code that the mailbox address serves as the
access credential. The residual delivery-DoS scenario is only relevant under full key
compromise, at which point message delivery is the least of the concerns.

---

## Summary Table

| ID   | Severity | Title |
|------|----------|-------|
| C-1  | Critical | No rate limiting on login endpoint |
| S-C1 | Critical | No rate limiting on register endpoint — DoS + username enumeration |
| H-1  | High     | TOCTOU race on IPC socket permissions |
| H-2  | High     | No IPC authentication |
| H-3  | High     | Unauthenticated invite key exchange (MITM) |
| H-4  | High     | Private keys in plain `serde_json::Value` |
| H-5  | High     | No sender identity binding in E2E messages |
| H-6  | High     | Intermediate AEAD key not zeroized in kyberbox |
| S-H1 | High     | Server message keys lost on restart — permanent message loss |
| S-H2 | High     | Single-use JWT undocumented — interoperability risk |
| S-H3 | High     | Server master key stored in plaintext on disk (PlainFileMkProvider) |
| S-H4 | High     | Username in plaintext `warn!` log on failed registration |
| M-1  | Medium   | `derive_secret32` ignores `mk` parameter |
| M-2  | Medium   | DEK wrap salt only 16 bytes |
| M-3  | Medium   | Password-derived value logged at debug level |
| M-4  | Medium   | Anti-replay TTL inconsistent with timestamp window |
| M-5  | Medium   | Deterministic nonce for user ID encryption |
| M-6  | Medium   | No IPC connection limit or timeout |
| S-M1 | Medium   | Decrypted body field names logged at debug level |
| S-M2 | Medium   | Replay store unbounded growth under DoS |
| S-M3 | Medium   | Session keys not bound to client identity |
| S-M4 | Medium   | Messages deleted before key lookup — silent loss on missing key |
| N-H1 | High     | `ensure_kyber`/`ensure_dilithium` silently generate new keypair when pub key file missing |
| N-H2 | High     | `wipe_local` uses `fs::remove_dir_all` — not a secure erase, key material stays on disk |
| N-M1 | Medium   | Non-atomic MK rotation — crash between rewrap steps leaves inconsistent key state |
| N-M2 | Medium   | Concurrent `contact_fetch` calls race on double state write |
| N-M3a| Medium   | `unlock_keystore` aborts MK rotator task mid-rotation — additional trigger for N-M1 |
| N-M3 | Medium   | `contact_send` commits state before local message store — mailbox gen skips on failure |
| N-M4 | Medium   | E2E ratchet — reply private keys not deleted on use; forward secrecy window = 64 rounds |
| N-M5 | Medium   | E2E ratchet — no client-side replay check; relies entirely on server anti-replay TTL |
| L-1  | Low      | `eprintln!` instead of structured logging |
| L-2  | Low      | Contact ID length not validated after hex decode |
| L-3  | Low      | Server URL scheme not validated in invite |
| L-4  | Low      | Prekey consumption not atomic |
| N-L1 | Info     | `msg/fetch` unauthenticated by design — sound model; delivery-DoS under full key compromise only |

---

## Positive findings

The following aspects of the cryptographic design are well-implemented:

- **Hybrid PQ encryption** (X25519 + ML-KEM-1024 + AES-256-GCM-SIV in `kyberbox`) is correctly layered with independent HKDF derivations for each component's shared secret.
- **AES-256-GCM-SIV** throughout eliminates catastrophic nonce-reuse failures present with plain GCM.
- **Argon2id** with m=64MB, t=3, p=1 for password-based key derivation is appropriate.
- **Server signature keys are now mandatory** (Ed25519 + ML-DSA-87) and verification is always executed — eliminating the previous optional-signature MITM vector.
- **Anti-replay** via SHA-256(ciphertext) with TTL store prevents replay attacks.
- **Keyfile two-layer encryption** (MK→KEK→payload) with per-file random salt+nonce is correctly implemented.
- **Atomic keyfile writes** via `rename(2)` prevent partial-write corruption.
- **Mailbox derivation** uses X25519 DH between both parties' static keys + HKDF with directional labels, providing implicit authentication and preventing cross-directional replay.
- **EphemeralStoreManager** zeroizes secrets on expiry.
- **`SecretString`/`SecretBytes`/`Byte32`** wrappers implement `Zeroize` + `Drop` and prevent accidental logging throughout most of the codebase.
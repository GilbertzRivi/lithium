# Cryptographic Implementation Audit — Lithium

**Date**: 2026-03-09
**Scope**: `lithium_core/src/crypto/`, `lithium_core/src/keys/`, `lithium_core/src/secrets/`,
           `lithium_core/src/passwords/`, `lithiumd/src/commands/e2e.rs`,
           `lithiumd/src/commands/invite_codec.rs`, `lithiumd/src/commands/contact_mailbox.rs`,
           `lithiumd/src/protocol_manager.rs`, `lithiumd/src/password_provider.rs`,
           `lithiumd/src/db/repo.rs`, `lithium_core/src/utils/store.rs`,
           `lithiums/src/transport/mod.rs`, `lithiums/src/db/repo.rs`, `lithiums/src/middleware/`
**Update**: 2026-03-09 — uzupełniony o pełny przegląd kodu serwera (`lithiums/`)
**Method**: Line-by-line manual code review, focused on:
  - Cryptographic correctness and algorithm usage
  - Secret/key lifetime and zeroization in memory
  - Intermediate heap/stack residue of key material
  - Memory handling of pqcrypto types

---

## Overview: What is correct

Before listing issues, the following aspects of the implementation are **correct**:

- **AEAD**: `aes-gcm-siv` (AES-256-GCM-SIV) is used throughout. The library correctly appends the 16-byte authentication tag to the ciphertext. Nonces are 12 bytes (correct for GCM-SIV). Every call to `encrypt` passes a fresh random nonce. AES-GCM-SIV's nonce-misuse resistance provides a safety margin.
- **HKDF**: `Hkdf<Sha256>` (RFC 5869) is used correctly. When `salt = None`, HKDF defaults to a 32-byte zero salt (conformant per the RFC). Context labels (`info`) are distinct for every derived key. No domain separation violations found.
- **KEM hybrid**: KyberBox correctly combines X25519 ECDH and ML-KEM-1024 independently, then combines their outputs via HKDF with a shared salt derived from `SHA-256(KEM_ciphertext)`. The two components (classical and post-quantum) are bound together in the AEAD AAD (`kyberbox/v1|kem=mlkem1024|aead=aes256-gcm-siv|...`). Breaking one algorithm does not break the overall encryption.
- **Key derivation tree**: Every derived key has a unique, versioned label (e.g., `lithiumd/e2e-msg/v1/body-key/v1`). No label reuse was found.
- **AAD binding**: Every AEAD call includes a non-empty AAD that encodes the purpose of the ciphertext (e.g., `lithiumd/contact-self/v1`). Ciphertexts are not interchangeable across different contexts.
- **Dual signature scheme**: Server responses are now (post-fix) always signed with both Ed25519 and ML-DSA-87. The client verifies both before accepting the response.
- **EphemeralStoreManager**: `SecretBytes` is used throughout. Entries are zeroized on TTL expiry (`as_mut_vec().zeroize()`), on `take`, and on `del`. Correct.
- **SecretJson**: `Drop` implementation recursively zeroizes all string values. Correct.
- **Random number generation**: All randomness uses `SysRng` (→ `getrandom(2)` on Linux), the OS CSPRNG. No user-space PRNG is used for key material.
- **Keyfile format**: Two-layer encryption (MK→KEK→DEK→payload) with independent random 32-byte salt and 12-byte nonces per layer, per file. Atomic write via `rename(2)`. Key rewrapping zeroizes old salt/nonce/ciphertext bytes.
- **Argon2id parameters**: m=64 MB, t=3, p=1 — above OWASP minimum.

---

### D-6: Mailbox derivation uses raw X25519 output without domain separation from key agreement

**File**: `lithiumd/src/commands/contact_mailbox.rs:59–75`

```rust
let self_sk = StaticSecret::from(hex_to_32(self_x_priv_hex)?);
let peer_pk = PublicKey::from(hex_to_32(peer_x_pub_hex)?);
let shared = self_sk.diffie_hellman(&peer_pk);

kdf::derive32(
    &SecretBytes::from_slice(shared.as_bytes()),
    Some(&salt_sb),        // CID_low || CID_high || generation_bytes
    &label(LABEL_LOW_TO_HIGH),
)
```

The X25519 static-static DH output (`shared`) is passed directly as HKDF input key material.
This is the **same static X25519 key** used for the E2E message encryption (`kyberbox::encrypt`
passes `priv_x` as the client's static key). Using the same static key pair for both mailbox
address derivation and as the DH base for message encryption creates a **key reuse** situation.

In `kyberbox::encrypt`, the ECDH is between the *message's ephemeral* X25519 key and the
*recipient's static* X25519 key. In `contact_mailbox`, it is between the *sender's static* key
and the *recipient's static* key. The two operations use different HKDF labels, so there is no
direct key confusion. However, the same static secret is participating in two distinct
cryptographic contexts. If the static X25519 key is compromised, both the mailbox addresses
AND the hybrid KEM base layer (for all past messages that used this static key) are compromised.

This is an architectural choice (single identity key pair per contact), not a bug, but it is
worth explicitly documenting.

---

### D-7: `lock_keystore` resets `needs_register` to `true` unconditionally

**File**: `lithiumd/src/state.rs:63`

```rust
pub async fn lock_keystore(&self) {
    ...
    *self.needs_register.lock().await = true;
}
```

After the keystore is locked, `needs_register` is forced to `true`. On the next
`unlock_storage` call, the code checks `if *state.needs_register.lock().await` and returns
`register_required`. This means that after any keystore lock-unlock cycle, `unlock_storage`
would fail with `register_required` even for a previously registered user.

This may be intentional (requiring re-authentication flow) or a logic error. If it is
intentional, the reason should be documented. If it prevents normal re-use of an
already-registered account, it is a functional crypto-adjacent bug.

---

## Server-side findings (`lithiums/`)

The following findings apply specifically to the server implementation.

### S-Z1: `id_enc_from_uuid` — deterministic nonce in plain `[u8; 12]` (server DB encryption)

**File**: `lithiums/src/db/repo.rs` (`id_enc_from_uuid`)

The function derives a deterministic AES-GCM-SIV nonce for user-ID encryption via:

```rust
let nonce_bytes = hkdf_expand(uuid, dek, "user-idenc/nonce/v1");  // [u8; 12]
```

The intermediate `[u8; 12]` is not explicitly zeroized before being moved into `Byte12::new()`.
This is the same class of issue as Z-5 (stack residue of derived material). The nonce itself
is not secret (only derived from the public UUID), so the **practical impact is low** — but it
is inconsistent with the rest of the zeroization approach.

**Recommendation**: Wrap in `Zeroizing<[u8; 12]>` for consistency, even though the value is
not a secret.

---

### S-Z2: `create_token_for_user` — HMAC seed zeroization is too late (copy already made)

**File**: `lithiums/src/transport/mod.rs` (`create_token_for_user`)

```rust
let mut value = [seed.as_bytes(), user.id.as_bytes()].concat();  // plain Vec<u8>
let secret = SecretBytes::from_slice(&value);  // copies into SecretBox
value.zeroize();                               // zeroizes the original — correct
```

The `value` binding (a plain `Vec<u8>` containing `seed || user.id`) is correctly zeroized
*after* `SecretBytes::from_slice` has taken a copy. However, `from_slice` makes a copy via
`to_vec()` — so there are two buffers: the `SecretBytes`-owned copy (which will be zeroized
on drop) and the original `value` (which is explicitly zeroized here).

This is **correct** — the explicit `value.zeroize()` compensates for the plain `Vec` allocation.
However, the pattern is fragile: if the `value.zeroize()` line were moved before the
`SecretBytes::from_slice` call, or removed during refactoring, the seed would leak. The seed is
32 bytes of key material used as the HMAC key for JWT subject binding.

**Recommendation**: Construct `value` as a `Zeroizing<Vec<u8>>` to make zeroization automatic:
```rust
let value = Zeroizing::new([seed.as_bytes(), user.id.as_bytes()].concat());
let secret = SecretBytes::from_slice(&value);
// value auto-zeroized on drop
```

---

### S-Z3: `reply_ok` — `pad_data()` intermediate result is a plain `Vec<u8>`

**File**: `lithiums/src/transport/mod.rs` (`reply_ok`)

```rust
let padded = pad_data(&body_bytes);                    // plain Vec<u8>
let ct = kyberbox::encrypt(&padded, peer_x_pub, peer_k_pub, &our_x_priv, &our_k_pub)?;
```

`pad_data` returns `Vec<u8>`. The `padded` variable holds the plaintext message body with
ISO/IEC 7816-4 padding applied, as a plain, unzeroized `Vec<u8>`. For message payloads this
may contain sensitive user data (message content). The plaintext body sits unprotected in
`padded` from the time `pad_data` returns until `kyberbox::encrypt` finishes and `padded`
is dropped.

**Impact**: Plaintext message body (post-padding, pre-encryption) lives briefly as a plain
heap allocation. In normal operation this is a very short window. On process crash or with
memory-safe languages this window is not exploitable. However, it is inconsistent with the
explicit use of `SecretBytes` elsewhere for sensitive data.

**Recommendation**: `pad_data` should return `SecretBytes` or `Zeroizing<Vec<u8>>`.

---

### S-D1: Non-standard JWT subject binding via random HMAC seed

**File**: `lithiums/src/transport/mod.rs` (`hmac_id`, `create_token_for_user`, `get_user_from_token`)

The server creates JWTs signed with HS256, and separately creates a subject binding using a
random 32-byte `seed` as an HMAC-SHA256 key:

```rust
fn hmac_id(seed: &[u8], uid: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(seed).unwrap();
    mac.update(uid);
    hex::encode(mac.finalize().into_bytes())
}
```

The `seed || user.id` is stored in EphemeralStore keyed by `tok` (the JWT string). On
token validation, the store is `take()`n (making the JWT single-use), and the HMAC is
recomputed to verify the `sub` claim. This effectively binds the `sub` to the server's
ephemeral `seed`, making the JWT non-transferable across server restarts.

This is a **correct** and reasonable approach to single-use, replay-resistant JWTs.
However, it is entirely non-standard (not in RFC 7519). The HMAC seed is not preserved
on restart, so all active JWTs are invalidated on server restart — a known and documented
behavior (partially documented in `SECURITY_AUDIT.md` finding S-H2).

**Analysis**: The construction is sound. Potential concern: if the JWT HS256 key (derived
from MK) is the same key as the HMAC seed, the two constructions would use the same key
for different purposes. Looking at the code, the `seed` is a fresh `SysRng` random value
per token, and the JWT signing key is `mk.hkdf("jwt-secret/v1")` — these are distinct.
No issue here.

**Recommendation**: Document the non-standard JWT extension explicitly in code comments.
Consider replacing the external HMAC binding with a JWT claim that is standard (e.g., `jti`
stored in the replay store) to simplify the protocol for future auditors.

---

### S-D2: `get_messages` deletes DB rows before retrieving decryption keys — silent message loss

**File**: `lithiums/src/db/repo.rs` (`get_messages`)

```rust
// Step 1: delete rows
sqlx::query!("DELETE FROM messages WHERE ... RETURNING id").fetch_all(tx).await?;
// Step 2: look up per-message key in EphemeralStore
let key = self.store.get(format!("msg_key:{}", id)).await?;
```

The DB rows are **deleted before** the decryption key is retrieved from `EphemeralStore`.
If the store lookup fails (key expired, store entry missing due to restart, or concurrent
deletion), the DB row is already gone. The message is silently lost — the client receives
an empty response with no error indication.

This is a **correctness** issue with cryptographic consequences: because keys are in-memory
only (EphemeralStore, not persisted), a server restart between message insertion and retrieval
causes permanent, undetectable message loss. The DB delete-before-key-lookup ordering
makes recovery impossible.

**Recommendation**: Reverse the order: retrieve the key first, then delete the row only if
the key is found. Alternatively, persist message keys to the DB (encrypted with server MK)
to survive restarts. Add explicit error logging when a row is deleted but the key is absent.

---

### S-D3: Server `verify_signature` — same correct dual-evaluation pattern as daemon

**File**: `lithiums/src/transport/mod.rs` (`verify_signature`)

The server-side signature verification uses the same correct pattern as the daemon (D-1):

```rust
let ok_ed = sign::verify_signature(&body, &sig_ed, &ctx.server_sig_ed);
let ok_dili = sign::verify_signature_dili(&body, &sig_dili, &ctx.server_sig_dili);
if !(ok_ed && ok_dili) { ... }
```

Both are evaluated as separate `let` bindings before the `if` — **this is correct**.
The same documentation recommendation from D-1 applies here: add a comment stating that
the eager evaluation is intentional.

---

---

## Additional findings from second-pass review

---

### N-D8 [HIGH]: `ensure_kyber` and `ensure_dilithium` silently overwrite stored private keys

**File**: `lithium_core/src/keys/manager.rs`, lines 203–234

When the private key file exists but the public key file is absent, both `ensure_kyber` and
`ensure_dilithium` generate a **brand new** keypair and save it, overwriting the stored private
key:

```rust
// Bug: should recover public key from stored private key — instead generates new pair
if priv_path.exists() {
    let _ = keyfile::load_bytes_decrypted(&priv_path, mk, KT_KYBER)?;  // load + discard
    if !pub_path.exists() {
        let (pk, sk) = mlkem1024::keypair();                            // NEW keypair!
        keyfile::save_bytes_encrypted(&priv_path, mk, sk.as_bytes(), KT_KYBER)?;  // overwrites!
        keyfile::write_secure(&pub_path, pk.as_bytes())?;
    }
}
```

Compare with the **correct** implementations for Ed25519 and X25519, which reconstruct the
public key from the stored seed:

```rust
// Correct (Ed25519):
let seed = keyfile::load_secret32_decrypted(&priv_path, mk, KT_ED25519)?;
let signing = SigningKey::from_bytes(seed.as_array());
let vk = signing.verifying_key().to_bytes();  // derived, not newly generated
keyfile::write_secure(&pub_path, &vk)?;
```

For ML-KEM-1024 and ML-DSA-87, the `pqcrypto` crate stores the secret key as raw bytes
(including the public key seed in some implementations). It should be possible to reconstruct
the public key. At minimum, the public key should be included in the encrypted private key file
so it can be recovered without regeneration.

**Impact**: Silently replaces the PQ key pair used for all existing E2E sessions. Any contact
that previously encrypted messages to the old Kyber public key can no longer decrypt with the
new private key. Server signature verification fails for clients holding the old ML-DSA-87
public key. This is a **cryptographic correctness bug** that causes silent, irreversible
data loss without any error being surfaced.

**Recommendation**: For ML-KEM-1024 and ML-DSA-87, store a copy of the public key inside
the encrypted private key file (alongside the private key bytes). On recovery, decrypt the
private key file and extract both. Never regenerate a keypair when the private key already exists.

---

### N-D9 [MEDIUM]: `maybe_rotate_mk` rewraps keyfiles non-atomically

**File**: `lithium_core/src/keys/manager.rs`, lines 153–165

The MK rotation procedure rewraps four key files sequentially:

```rust
keyfile::rewrap_keyfile_dek(ED_PRIV, &old_mk, &new_mk, ...)?;    // file 1
keyfile::rewrap_keyfile_dek(X_PRIV, &old_mk, &new_mk, ...)?;     // file 2
keyfile::rewrap_keyfile_dek(KYBER_PRIV, &old_mk, &new_mk, ...)?; // file 3
keyfile::rewrap_keyfile_dek(DILI_PRIV, &old_mk, &new_mk, ...)?;  // file 4
self.mk_provider.store_mk(&new_mk)?;                               // step 5: commit new MK
```

Each `rewrap_keyfile_dek` atomically rewrites one keyfile via `rename(2)`. However, between
steps 1–4, the keyfiles are inconsistent with each other: some are encrypted under `new_mk`,
some under `old_mk`. The new MK is only committed to disk at step 5.

**Failure scenario**: If the process crashes after step 1 but before step 5, on next startup
`load_mk()` returns `old_mk` (step 5 never ran), but `ED_PRIV` was already rewrapped with
`new_mk`. Decryption of `ED_PRIV` fails. The daemon cannot reconstruct the Ed25519 key.

**Impact**: Crash during hourly MK rotation causes permanent loss of the private keys that
had already been rewrapped. In the worst case (crash after step 4, before step 5), all four
private keys are unreadable — complete key loss.

**Recommendation**: Use a two-phase commit pattern:
1. Write the new MK to `mk.pending` (atomically via `rename`)
2. Rewrap all keyfiles
3. Rename `mk.pending` → `mk` (commit)
4. On startup, if `mk.pending` exists: complete or roll back the rotation.

---

### N-D11 [MEDIUM]: E2E ratchet — reply private key not zeroized on consumption

**File**: `lithiumd/src/commands/e2e.rs`, `decrypt_for_us` (790–821), `gc_after_ack` (560–584)

After a reply key is used for decryption, it is removed from `e2e_rx.keys` only when
`gc_after_ack` determines its `seq < ack_seq - window`. The `gc` removal uses:

```rust
keys.remove(&k);  // removes the Value entry from the JSON map
```

`serde_json::Map::remove` drops the `Value::Object` containing `"x_priv"` and `"k_priv"` as
plain `String` fields. Since `serde_json::Value` does not implement `Zeroize`, the private key
hex strings are **not overwritten before deallocation** — this is the Z-1 issue applied
specifically to the GC path.

Furthermore, the entire `self_v["e2e_rx"]["keys"]` map containing all retained reply private
keys (up to 64 at any time) is serialized into the DB on every `contact_fetch`/`contact_send`
call. The serialization produces a plain `Vec<u8>` blob containing all private key hex strings
which is stored in SQLite without any in-process zeroization of the intermediate buffer.

**Impact**: Up to 64 reply private keys persist in:
1. Daemon process memory (unzeroized `Value` fields)
2. SQLite `self_state` blob (plaintext private keys in hex, encrypted by DEK on disk but
   decryptable by anyone with the DEK — i.e., anyone who unlocks the keystore)
3. The serialization buffer between the in-memory state and the DB write

**Recommendation**: On removal of a key from `e2e_rx.keys` during GC, explicitly zeroize
the hex string fields before dropping. Better: replace the `Value`-based keyring with a typed
struct using `zeroize::Zeroize` derive. Reduce the window from 64 to a smaller value.

---

### N-D10 [LOW]: `random_kyber_mlkem1024_keypair` and `random_dilithium_mldsa87_keypair` return `(sk, pk)` — opposite of pqcrypto convention

**File**: `lithium_core/src/crypto/keys.rs`, lines 44–53

```rust
pub fn random_kyber_mlkem1024_keypair() -> Result<(SecretBytes, SecretBytes)> {
    let (pk, sk) = mlkem1024::keypair();  // pqcrypto returns (pk, sk)
    Ok((SecretBytes::from_slice(sk.as_bytes()), SecretBytes::from_slice(pk.as_bytes())))
    //   ^ first = sk (private)             ^ second = pk (public)  — swapped!
}
```

`pqcrypto::kem::mlkem1024::keypair()` returns `(PublicKey, SecretKey)` — public key first.
The wrapper function reverses this to `(SecretKey, PublicKey)` — private key first.
`random_dilithium_mldsa87_keypair()` has the same reversal.

All current callers use the correct destructuring (`let (k_priv, k_pub) = ...`), so there
is no bug today. However, the convention mismatch creates a footgun: a developer following
the pqcrypto API documentation and writing `let (pk, sk) = random_kyber_mlkem1024_keypair()?`
would silently swap public and private keys, storing the private key as if it were public
and vice versa. This would cause catastrophic key confusion with no compile-time error.

**Recommendation**: Rename the return type to make the order unambiguous, or return a named
struct `KyberKeyPair { public: SecretBytes, secret: SecretBytes }` to prevent positional
confusion. Add a doc comment documenting the return order explicitly.

---

### N-Z10 [LOW]: Decrypted/plaintext message content not explicitly zeroized

**Files**: `lithiumd/src/commands/contact_send.rs:90`, `lithiumd/src/commands/contact_fetch.rs:169,240`

In `contact_send`, the outgoing plaintext is a plain `String` parameter:
```rust
pub async fn handle(id: u64, contact_id_hex: String, plaintext: String, ...) -> IpcResponse {
    // plaintext passed to encrypt_for_peer as bytes — never zeroized
    let (wire, ui_meta) = encrypt_for_peer(..., plaintext.as_bytes(), ...)?;
    // plaintext still alive here, also copied into build_stored_message
    let stored = build_stored_message(&plaintext, ...)?;
    // plaintext dropped at end of function without zeroize
}
```

In `contact_fetch`, the decrypted text after `decrypt_for_us` is:
```rust
let text = String::from_utf8(pt.clone())?;  // pt is Vec<u8>, text is plain String
// text passed to build_stored_message, out.push(json!({..., "text": text, ...}))
// neither pt nor text is zeroized
```

These are the final plaintext message contents of user communications. They live as plain
`String`/`Vec<u8>` in daemon memory for the duration of the handle function.

**Impact**: Message contents may linger in heap memory without zeroization until the allocator
reuses the memory. During normal operation this window is short. However, it is inconsistent
with the rest of the codebase's approach to sensitive data.

**Recommendation**: Use `Zeroizing<String>` for `plaintext` in `contact_send`. Wrap `pt` in
`Zeroizing<Vec<u8>>` in `contact_fetch`. Note that the IpcResponse JSON (`"text": text`) will
still contain the plaintext — this is unavoidable at the IPC boundary but the intermediate
String copies should be minimized.

---

## Summary Table

| ID  | Severity | Category  | Description |
|-----|----------|-----------|-------------|
| Z-1 | High     | Memory    | E2E reply private keys in plain `serde_json::Value` — no zeroization |
| Z-2 | High     | Memory    | `gen_self_state` intermediate `Value` with all static private keys not zeroized |
| Z-3 | High     | Memory    | `gen_local_prekey_material` private key hex in plain `Value` |
| Z-4 | Medium   | Memory    | `hex_to_32` intermediate plain `Vec<u8>` / `[u8; 32]` for key material |
| Z-5 | Medium   | Memory    | Stack `[u8; 32]` output buffers in HKDF/Argon2/signing not zeroized |
| Z-6 | Medium   | Memory    | pqcrypto KEM/sign types (`KyberSharedSecret`, `SecretKey`) may not auto-zeroize |
| Z-7 | Medium   | Memory    | `x25519_dalek::SharedSecret` zeroization depends on crate feature flag |
| D-1 | Medium   | Correctness | `!(ok1 && ok2)` pattern — correct as written but brittle; document intent |
| D-2 | Medium   | Correctness | `from_zeroizing_vec` bypasses the `Zeroizing` wrapper via `mem::take` |
| D-3 | Medium   | Memory    | Raw keyfile bytes in plain `Vec<u8>` before `SecretBytes` wrapping |
| D-4 | Medium   | Memory    | JWT token and session keys returned as plain `String`/`Vec<u8>` from store |
| Z-8 | Low      | Memory    | `Byte32::clone` unzeroized stack copy |
| Z-9 | Low      | Correctness | `from_hex_relaxed` silently truncates/pads — dangerous footgun |
| D-5 | Low      | Memory    | AES key schedule zeroization depends on `aes` crate feature flag |
| D-6 | Low      | Design    | Same static X25519 key used for mailbox derivation AND KEM base layer |
| D-7 | Low      | Logic     | `lock_keystore` unconditionally resets `needs_register = true` |
| S-Z1 | Low     | Memory    | `id_enc_from_uuid` — `[u8; 12]` nonce intermediate not zeroized (non-secret, inconsistent) |
| S-Z2 | Medium  | Memory    | `create_token_for_user` — HMAC seed in plain `Vec<u8>`; zeroization relies on manual call |
| S-Z3 | Medium  | Memory    | `reply_ok` — padded plaintext body in plain `Vec<u8>` before `kyberbox::encrypt` |
| S-D1 | Low     | Design    | Non-standard JWT subject binding via ephemeral HMAC seed — correct but undocumented |
| S-D2 | High    | Correctness | `get_messages` deletes DB rows before retrieving decryption keys — silent message loss |
| S-D3 | Info    | Correctness | Server `verify_signature` dual-evaluation pattern is correct; add comment |
| N-D8 | High    | Correctness | `ensure_kyber`/`ensure_dilithium` generates new keypair instead of recovering — silent key loss |
| N-D9 | Medium  | Correctness | `maybe_rotate_mk` rewraps keyfiles non-atomically — crash causes permanent key loss |
| N-D11 | Medium | Memory      | E2E ratchet GC removes reply keys via `Value::remove` — no zeroization of private key strings |
| N-D10 | Low    | Correctness | `random_kyber_mlkem1024_keypair` returns `(sk, pk)` — opposite of pqcrypto convention, footgun |
| N-Z10 | Low    | Memory      | Decrypted/plaintext message content (`String`/`Vec<u8>`) not explicitly zeroized |

---

## Priority Recommendations

1. **(Z-1, Z-2, Z-3)** — Replace `serde_json::Value` for any structure that contains private
   key material with a `SecretJson` (for the entire e2e state) or a dedicated zeroizable struct.
   The e2e key ratchet state should live in `SecretJson` from the moment it is deserialized from
   the DB until the moment it is re-serialized. Every `json!({...})` macro call that includes
   `.expose()` on private key material is a potential memory leak.

2. **(Z-4, Z-5)** — Audit all `hex::decode` calls on private key material and wrap results
   in `Zeroizing<Vec<u8>>`. Change all intermediate `[u8; 32]` HKDF/Argon2 output buffers to
   `Zeroizing<[u8; 32]>`.

3. **(Z-6, Z-7, D-5)** — Pin the `pqcrypto`, `x25519-dalek`, and `aes-gcm-siv` crates to
   versions that guarantee zeroization, and explicitly declare the `zeroize` feature flag in
   `Cargo.toml`. Consider opening issues upstream with the `pqcrypto` crate to request
   `Zeroize` impl on KEM secret key and shared secret types.

4. **(D-2)** — Fix `from_zeroizing_vec` to actually benefit from the `Zeroizing` wrapper.

5. **(D-4)** — Change `take_string` in `ProtocolManager` to return `SecretString` for
   secrets (JWT, passwords), and update callers accordingly.

6. **(S-D2)** — Reverse the delete/key-lookup order in `get_messages`: fetch the key first,
   delete the DB row only on success. This is the highest-priority server-side finding —
   it causes permanent, silent message loss on server restart or key-store eviction.

7. **(S-Z2, S-Z3)** — Wrap the HMAC seed buffer in `Zeroizing<Vec<u8>>` in
   `create_token_for_user`. Change `pad_data` to return `Zeroizing<Vec<u8>>` or `SecretBytes`
   to ensure the plaintext message body is not left in an unzeroized heap allocation.

8. **(S-D1)** — Document the non-standard JWT subject-binding mechanism (random HMAC seed
   stored in EphemeralStore) with code comments for future auditors.
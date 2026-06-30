# lithium_core

The shared library of cryptography, secret types, and key 
management for the Lithium project.

Lithium is a messenger designed for environments where the server, 
the operator, and the infrastructure may be completely untrusted. 
The goal isn't convenience, it's to mathematically limit what even 
the operator can reveal. `lithium_core` implements all the 
cryptographic foundations of that model.

## Place in the architecture

```
lithiumg (GUI)
  | IPC
lithiumd (daemon)      uses lithium_core
  | HTTPS
lithiums (server)      uses lithium_core
```

`lithium_core` is a shared dependency of `lithiumd` and 
`lithiums`. It holds everything that isn't specific to one layer: 
the cryptography, the secret types, key management, and the 
database integration.

## Modules

### `crypto`: cryptographic operations

#### `crypto::aead`: symmetric encryption

AES-256-GCM-SIV with an authenticated ciphertext (AEAD).

```
encrypt_raw(plaintext, key, nonce, aad) -> SecretBytes   // raw AES-256-GCM-SIV
decrypt_raw(ciphertext, key, nonce, aad) -> SecretBytes

encrypt(plaintext, key, nonce, aad) -> SecretBytes       // versioned blob with nonce
decrypt(blob, key, aad) -> SecretBytes                   // parses the blob automatically
```

`encrypt` blob format:
```
[version: u8 = 1][nonce: 12 bytes][ciphertext + tag: N bytes]
```

AAD is always required, a wrong or empty AAD causes a decryption 
failure.

#### `crypto::kdf`: key derivation

HKDF-SHA256. One call derives 32 bytes of key.

```
derive32(input, salt, info) -> Byte32
```

`salt` is optional. `info` is always required and is used for 
domain separation.

#### `crypto::sign`: digital signatures

Dual signature: every message is signed classically and 
post-quantum at the same time.

```
// Ed25519 (classical)
sign_message(message, priv_ed_seed) -> SecretBytes       // 64 bytes
verify_signature(message, signature, pub_key) -> bool

// ML-DSA-87 / Dilithium (post-quantum)
sign_message_dili(message, dili_sk_bytes) -> SecretBytes
verify_signature_dili(message, signature, dili_pk_bytes) -> bool
```

#### `crypto::keys`: generating cryptographic material

Key-pair and random-material generators. All use the system CSRNG 
(`SysRng`).

```
random_fixed::<N>() -> FixedBytes<N>
random_12() -> Nonce12
random_32() -> SessionId32
random_master_key32() -> MasterKey32

random_x25519_keypair() -> (FixedBytes<32>, FixedBytes<32>)      // (seed_sk, pk)
random_ed25519_keypair() -> (FixedBytes<32>, FixedBytes<32>)     // (seed, pk)
random_kyber_mlkem1024_keypair() -> (SecretBytes, SecretBytes)   // (sk, pk)
random_dilithium_mldsa87_keypair() -> (SecretBytes, SecretBytes) // (sk, pk)
```

#### `crypto::kyberbox`: hybrid asymmetric encryption

`kyberbox` is a hybrid scheme that joins X25519 (ECDH) with 
ML-KEM-1024 (Kyber). Security depends on both algorithms at once, 
breaking one does not compromise the encryption. The combiner is 
an instance of the UniversalCombiner 
(`draft-irtf-cfrg-hybrid-kems`); see [`combiner.md`](combiner.md).

The scheme for one message:

```
1. ECDH: shared = X25519(priv_x, peer_pub_x)
2. ecdh_key = HKDF(shared, info="{ctx}/ecdh-key/v1")
3. (ss_kem, ct_kem) = ML-KEM-1024.Encapsulate(peer_kyber_pub)
4. base_key = HKDF(ecdh_key, salt=ss_kem,
                   info="{ctx}/base-key/v1" || ct_T || ek_T || SHA256(ct_kem))
5. body_key = HKDF(base_key, info="{ctx}/body-key/v1")
6. headers_key = HKDF(base_key, info="{ctx}/headers-key/v1")
7. enc_body = AES-256-GCM-SIV(body, body_key)
8. enc_headers = AES-256-GCM-SIV(headers, headers_key)
```

`WirePayload` output format:

```rust
pub struct WirePayload {
    pub enc_body: SecretBytes,
    pub enc_headers: SecretBytes,
    pub kem_ct: SecretBytes,   // ML-KEM ciphertext
}
```

Internal format of `kem_ct`:
```
[ver: u8][kem_id: u8][kyber_ciphertext: N bytes]
```

`ct_T` is the sender's ephemeral X25519 public key, `ek_T` the 
recipient's X25519 public key. Both are bound into the `base_key` 
info, along with `SHA256(ct_kem)`.

Interface:

```
encrypt(ctx, priv_x, peer_pub_x, peer_k_pub, body, headers) -> WirePayload
decrypt(ctx, priv_x, peer_pub_x, kyber_priv, wire) -> (body, headers)
```

`ctx` is a context string that separates domains (for example 
`"shake"`, `"session"`).

The full construction, properties, and open questions: 
[`kyberbox.md`](kyberbox.md).

---

### `keys`: key management

#### `keys::manager`: `KeyManager<P>`

The central component that manages all cryptographic material of 
one identity (a server or a user). A key security element, it 
stores private keys encrypted under the Master Key, handles MK 
rotation, and recovers an interrupted rotation.

**On-disk directory layout:**

```
{base_dir}/{kind}/{name}/
  pub/
    ed25519.pub
    x25519.pub
    kyber-mlkem1024.pub
    dilithium-mldsa87.pub
  priv/
    ed25519.keyf            (encrypted keyfile)
    x25519.keyf
    kyber-mlkem1024.keyf
    dilithium-mldsa87.keyf
  secrets/
    {hex_label}.keyf        (arbitrary derived secrets)
  .rotate/                  (temporary MK rotation dir)
    next-mk-old.keyf
    next-mk-new.keyf
    staged/                 (files before commit)
    ready                   (readiness marker)
  mk                        (Master Key, PlainFileMkProvider)
```

**Master Key rotation:**

MK rotation is atomic and crash-safe. The protocol:

1. Write the old and new MK to `.rotate/` (both encrypted).
2. Prepare every `.keyf` file with the old wrapping and the new 
   wrapping in `.rotate/staged/`.
3. Write the `.rotate/ready` marker.
4. Apply the staged files to their target locations.
5. Update the MK at the provider.
6. Remove the `.rotate/` directory.

On startup `KeyManager` checks for an unfinished rotation and 
tries to finish or roll it back before loading keys. The default 
rotation interval is **3600 seconds** (1 hour).

**The `MkProvider` trait:**

```rust
pub trait MkProvider {
    fn load_mk(&self) -> Result<Byte32>;
    fn store_mk(&self, mk: &Byte32) -> Result<()>;
    fn derive_secret32(&self, mk: &Byte32, label: &[u8]) -> Result<Byte32>;
}
```

The default `PlainFileMkProvider` stores the MK as a binary file. 
The trait is pluggable, `lithiumd` can plug in its own provider 
based on the user's password and a server component.

**API:**

```rust
// Initialization
KeyManager::start(base_dir, kind, name, mk_provider) -> Result<KeyManager<P>>
KeyManager::start_plain(base_dir, kind, name) -> Result<KeyManager<PlainFileMkProvider>>

// Access to private keys (callback pattern, the key never leaves scope)
manager.with_ed_sk(|seed| { ... }) -> Result<R>
manager.with_x25519_sk(|seed| { ... }) -> Result<R>
manager.with_kyber_sk(|sk| { ... }) -> Result<R>
manager.with_dilithium_sk(|sk| { ... }) -> Result<R>
manager.with_x25519_and_kyber_sk(|x_seed, kyber_sk| { ... }) -> Result<R>

// Public keys
manager.public_keys() -> &PublicKeys

// Derived secrets (label-based)
manager.derive_secret32(label: &[u8]) -> Result<Byte32>

// JWT secret (rotated together with the MK)
manager.jwt_secret() -> &Byte32

// Rotation
manager.maybe_rotate_mk() -> Result<()>
```

**`PublicKeys`:**

```rust
pub struct PublicKeys {
    pub ed25519: Byte32,
    pub x25519: Byte32,
    pub kyber: SecretBytes,
    pub dilithium: SecretBytes,
}
```

#### `keys::keyfile`: the key file format

A binary `.keyf` format implementing envelope encryption:

```
[KEYF magic: 4 bytes][version: u8][alg_id: u8][dek_len: u16]
[salt_len: u16][salt: 32 bytes]
[nonce_wrap_len: u16][nonce_wrap: 12 bytes]
[ct_wrap_len: u16][ct_wrap: N bytes]        // AES-256-GCM-SIV(DEK, KEK)
[nonce_payload_len: u16][nonce_payload: 12 bytes]
[ct_payload_len: u32][ct_payload: M bytes]  // AES-256-GCM-SIV(secret, DEK)
```

Encryption scheme:
- **KEK** = HKDF(MasterKey, salt, info=`"kek/v1"`)
- **DEK** = a random 32-byte key per file
- The payload is encrypted with the DEK, the DEK is encrypted with 
  the KEK
- The AAD carries the version and key type (`"keyfile:v1|{key_type}"`), 
  a wrong type causes a decryption failure

Writing through `write_secure` uses a `tmp + rename` pattern with 
`fsync` and `0o600` permissions (Unix).

Rewrapping (changing the MK without decrypting the payload):

```
rewrap_keyfile_dek(path, old_mk, new_mk, key_type) -> Result<()>
rewrap_keyfile_dek_to_bytes(path, old_mk, new_mk, key_type) -> Result<SecretBytes>
```

---

### `secrets`: secret types

All secret types provide:
- No `Display`/`Debug` that reveals the content (they print 
  `<redacted>` or `FixedBytes<N>(..)`).
- Memory zeroization on `Drop` (through `secrecy::SecretBox` + 
  `zeroize`).
- No automatic conversion to `String` and no serialization to 
  logs.

#### `FixedBytes<N>` and aliases

A fixed-length secret buffer. Held in `SecretBox<[u8; N]>`.

```rust
pub type Byte12 = FixedBytes<12>;   // nonce
pub type Byte32 = FixedBytes<32>;   // key, seed, hash
pub type Byte64 = FixedBytes<64>;   // Ed25519 signature
pub type Byte2048 = FixedBytes<2048>;
```

Selected methods:
```rust
FixedBytes::new(bytes: [u8; N]) -> Self
FixedBytes::from_slice(slice: &[u8]) -> Result<Self>
FixedBytes::from_hex(s: &str) -> Result<Self>    // requires lowercase, rejects a 0x prefix
FixedBytes::new_zeroed() -> Self
FixedBytes::to_hex() -> SecretString
FixedBytes::as_array() -> &[u8; N]
FixedBytes::as_slice() -> &[u8]
```

#### `SecretBytes`

A variable-length secret buffer. Held in `SecretBox<Vec<u8>>`.

```rust
SecretBytes::new(v: Vec<u8>) -> Self
SecretBytes::from_slice(v: &[u8]) -> Self
SecretBytes::from_hex(s: &str) -> Result<Self>
SecretBytes::as_slice() -> &[u8]
SecretBytes::to_hex() -> SecretString
```

#### `SecretString`

A secret UTF-8 string. Implements `Display` as `<redacted>`.

```rust
SecretString::new(s: String) -> Self
SecretString::new_checked(s: String) -> Result<Self>   // rejects null bytes
SecretString::expose() -> &str                          // the only access method
SecretString::from_utf8_bytes(bytes: &[u8]) -> Result<Self>
SecretString::decode_hex() -> Result<Zeroizing<Vec<u8>>>
SecretString::decode_hex_fixed::<N>() -> Result<FixedBytes<N>>
```

#### `SecretJson`

A secret JSON document that zeroizes on `Drop`. Recursively 
zeroizes all strings and object keys.

```rust
SecretJson::from_str(s: &str) -> Result<Self>
SecretJson::from_bytes(bytes: &[u8]) -> Result<Self>
SecretJson::get_string(key) -> Result<SecretString>
SecretJson::get_integer(key) -> Result<SecretBox<i64>>
SecretJson::get_bool(key) -> Result<bool>
SecretJson::take_string(key) -> Result<SecretString>   // removes the field from the map
SecretJson::with_exposed(|value| { ... }) -> R         // access to serde_json::Value
```

#### Type aliases (`secrets::types`)

```rust
pub type MasterKey32 = Byte32;
pub type Nonce12 = Byte12;
pub type SessionId32 = Byte32;
```

---

### `passwords`: password handling

#### Hashing (Argon2id)

Standard parameters: 64 MB memory, 3 iterations, 1 thread, 32-byte 
output.

```rust
hash_password_phc(password: &SecretString) -> Result<String>       // PHC string
verify_password_phc(phc: &str, password: &SecretString) -> Result<bool>
```

#### Password validation

```rust
pub struct PasswordPolicy {
    pub min_len: usize,          // default: 8
    pub max_len: usize,          // default: 1024
    pub require_lowercase: bool, // default: true
    pub require_uppercase: bool, // default: true
    pub require_digit: bool,     // default: true
    pub require_special: bool,   // default: true
    pub allow_whitespace: bool,  // default: false
}

validate_password(password: &SecretString, pol: PasswordPolicy) -> Result<()>
validate_passwords_distinct(a: &SecretString, b: &SecretString) -> Result<()>
```

#### DEK (Data Encryption Key): wrapping with a password

The scheme used to store a DEK on the server encrypted under the 
data password:

```rust
generate_dek() -> Result<Byte32>
wrap_dek_for_server_hex(dek, data_password) -> Result<SecretString>   // hex blob
unwrap_dek_from_server_hex(blob_hex, data_password) -> Result<Byte32>
```

DEK blob format (hex-encoded):
```
[ver: u8 = 1][salt: 32 bytes][aead_blob: N bytes]
```

The wrapping key = `Argon2id(data_password, salt)`. AAD = 
`"lithium/dek-wrap/v1"`.

---

### `db`: database integration

#### `db::DataManager<P>`

A facade that joins a `DatabaseConnection` (SeaORM) with a 
`KeyManager`. It manages encryption of blobs in the database.

```rust
DataManager::new(db, key_manager) -> Self
manager.db() -> &DatabaseConnection
manager.load_db_dek() -> Result<Byte32>             // from the label "lithium/db-dek/v1"
manager.users_uuid_namespace() -> Result<Uuid>      // deterministic UUID namespace
manager.encrypt_db_blob(plaintext, aad) -> Result<SecretBytes>
manager.decrypt_db_blob(blob, aad) -> Result<SecretBytes>
```

The database DEK is derived from the MK through `derive_secret32` 
with the label `b"lithium/db-dek/v1"`. The DEK is stored as a 
`.keyf` file in the `secrets/` directory. MK rotation **rewraps 
the DEK file** (swaps its encryption to the new MK), but does not 
change the key value itself, so the data in the database stays 
encrypted under the same DEK and doesn't need re-encryption.

The users' UUID namespace is deterministic and derived from the 
MK, the same identity always generates the same UUID for a given 
login.

---

### `utils`: helpers

#### `utils::store`: `EphemeralStoreManager`

An in-memory store with TTL and zeroization on expiry. Used among 
other things to hold temporary session tokens.

```rust
store.set(key, value, ttl) -> Result<()>
store.set_if_absent(key, value, ttl) -> Result<bool>
store.peek(key) -> Result<Option<SecretBytes>>   // read without removing
store.take(key) -> Result<Option<SecretBytes>>   // read and remove
store.del(key) -> Result<()>
```

An internal task (`tokio::spawn`) sweeps expired entries every 500 
ms. When an expired entry is removed, the `SecretBytes` content is 
zeroized before `drop`.

#### `utils::headers`

Helpers for parsing HTTP headers as secret types.

```rust
header_str(headers, name) -> Result<SecretString>
header_hex::<N>(headers, name) -> Result<FixedBytes<N>>
header_hex_bytes(headers, name) -> Result<SecretBytes>
```

---

### `error`: error handling

```rust
pub type Result<T> = core::result::Result<T, LithiumError>;

pub struct LithiumError {
    pub kind: CryptoErrorKind,
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}
```

In `debug_assertions` mode (`LithiumError::is_verbose()`) errors 
print details. In release they print only the category, without 
internal details that could leak through logs.

Selected `CryptoErrorKind` variants:
- `AeadFailed`: decryption or authenticity failure
- `KdfFailed`: key derivation failure
- `InvalidLength { expected, got }`: wrong buffer length
- `InvalidHex` / `HexMustBeLowercase` / `HexDisallowedPrefix`: hex 
  parsing errors
- `StringPolicy`: a password/string policy violation
- `InvalidCredentials { msg }`: authentication failure
- `InvalidPermissions { msg }`: a permissions violation
- `Io`: an I/O error
- `Internal`: an internal error (reveals no details in release)

`From` is implemented for: `std::io::Error`, `hex::FromHexError`, 
`serde_json::Error`, `hkdf::InvalidLength`, 
`aes_gcm_siv::aead::Error`, `rand::rngs::SysError`.

---

## Cryptographic dependencies

| Crate           | Version     | Role                                       |
|-----------------|-------------|--------------------------------------------|
| `aes-gcm-siv`   | 0.11.1      | AEAD: AES-256-GCM-SIV                      |
| `hkdf`          | 0.12        | KDF: HKDF-SHA256                           |
| `sha2`          | 0.10.9      | SHA-256 (KDF salt, verification)           |
| `pqcrypto`      | 0.18.1      | ML-KEM-1024 (Kyber), ML-DSA-87 (Dilithium) |
| `ed25519-dalek` | 2.2.0       | Ed25519 (signatures)                       |
| `x25519-dalek`  | 2.0.1       | X25519 (ECDH)                              |
| `argon2`        | 0.5.3       | Argon2id (password hash, DEK wrap)         |
| `zeroize`       | 1.8.2       | Memory zeroization                         |
| `secrecy`       | 0.10.3      | Secret types (`SecretBox`)                 |
| `rand`          | 0.10.0      | CSRNG (`SysRng`)                           |

The whole crate is `#![forbid(unsafe_code)]`.

---

## Security model

The library's guarantee boundary (what `lithium_core` provides and 
what is the caller's responsibility) is in 
[`threat-model.md`](threat-model.md); the hybrid encryption 
argument is in [`kyberbox.md`](kyberbox.md). The concrete 
mechanisms behind those guarantees:

- **Private-key confidentiality**: access only through a callback 
  (`with_ed_sk`, `with_kyber_sk`), the value never leaks past the 
  call scope.
- **Domain separation**: every KDF/AEAD operation runs under a 
  unique `info`/`aad` label.
- **Zeroization**: `FixedBytes`/`SecretBytes`/`SecretString`/`SecretJson` 
  clear memory on `Drop`.
- **Rotation crash-safety**: an unfinished MK rotation is finished 
  or rolled back on startup.
- **I/O safety**: atomic `tmp + rename` writes with `fsync`, 
  `0o600` permissions.
- **Opaque errors in release**: `LithiumError` reveals only the 
  category, not internal details.

## Non-goals

By the project model, `lithium_core` deliberately does not 
provide:

- Recovery after losing the Master Key, no key means lost data.
- Key synchronization between devices.
- Offline operation without access to the MK.
- Message delivery guarantees, this is not the transport layer.

The absence of these is on purpose. Recovery is worse than losing 
data if the alternative is weaker security.

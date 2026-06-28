# lithium_core

Post-quantum **hybrid** cryptography and at-rest key management, extracted from the
[Lithium](../README.md) messenger as a standalone Rust library.

Every construction combines a classical and a post-quantum primitive, so it stays secure as long
as *either* one holds:

- **Encryption** — X25519 + ML-KEM-1024, sealed with AES-256-GCM-SIV (`crypto::kyberbox`)
- **Signatures** — Ed25519 + ML-DSA-87, dual-signed (`crypto::sign`)
- **KDF / passwords** — HKDF-SHA256, Argon2

The crate is `#![forbid(unsafe_code)]`, secret types zeroize on drop, and all domain-separation
labels are supplied by the caller — the crypto itself is application-agnostic.

## Two pillars

### 1. At-rest key management (`keys`, `secrets`)

`KeyManager` owns an on-disk keyfile: it generates the hybrid identity, seals private keys under
a master key from a pluggable `MkProvider` (plain file or TPM), and performs crash-safe hourly
rotation and rewrap. Secret types (`Byte32`, `SecretBytes`, `MasterKey32`, …) zeroize on drop.

### 2. Hybrid encryption (`crypto`)

`crypto::kyberbox` is the X25519 + ML-KEM-1024 AEAD construction: the KEM encapsulates a fresh
seed per message that is mixed with the ECDH output through HKDF, so recovering the message key
requires breaking *both* branches. See [`docs/combiner.md`](../docs/security/combiner.md) for the exact
construction and its rationale, and [`docs/kyberbox.md`](../docs/security/kyberbox.md) for the wire format.

## Helpers

Secondary, deployment-agnostic building blocks layered on the pillars: `opaque` (OPAQUE PAKE +
export-key DEK wrapping), `pow` (proof-of-work), `passwords` (policy + DEK generation),
`utils::store` (TTL secret store).

## Examples

```bash
cargo run -p lithium_core --example kyberbox   # hybrid encrypt/decrypt round-trip
cargo run -p lithium_core --example keyfile    # KeyManager identity persistence
```

```rust
use lithium_core::crypto::{keys, kyberbox};
use lithium_core::secrets::bytes::SecretBytes;

let ctx = "myapp/message/v1";
let (recipient_priv_x, recipient_pub_x) = keys::random_x25519_keypair()?;
let (recipient_kyber_priv, recipient_kyber_pub) = keys::random_kyber_mlkem1024_keypair()?;
let (sender_priv_x, sender_pub_x) = keys::random_x25519_keypair()?;

let wire = kyberbox::encrypt(
    ctx, &sender_priv_x, &recipient_pub_x, &recipient_kyber_pub,
    &SecretBytes::from_slice(b"attack at dawn"),
    &SecretBytes::from_slice(b"to: alice"),
)?;
let (body, headers) =
    kyberbox::decrypt(ctx, &recipient_priv_x, &sender_pub_x, &recipient_kyber_priv, &wire)?;
```

## Security status

**Not yet independently audited.** The constructions, the hybrid-combiner rationale and the open
questions for an auditor are documented under [`docs/`](../docs): `combiner.md`, `kyberbox.md`,
`lithium_core-threat-model.md`. The public API is intended to be frozen at `0.1` through the audit.

## License

GNU AGPL-3.0-only, with a commercial license available (dual licensing) — see [`LICENSE`](../LICENSE).

# Threat model: the `lithium_core` library

The scope here is the `lithium_core` crate alone, as a 
cryptography and at-rest key-management library, not the 
application around it. The boundary matters for the audit: we 
audit the tight surface of the library, not the messenger that 
uses it.

## Scope

In scope: the two pillars (`keys`/`secrets`, `crypto`) and the 
helpers (`opaque`, `pow`, `passwords`, `utils::store`). Out of 
scope (the application layers in `lithiumd`/`lithiums`/`lithiumg`): 
the network, the relay server, REST transport, handshake/invite, 
IPC, the cover-traffic policy, the unlock UX.

## What the library guarantees (when the assumptions below hold)

- **Message confidentiality**: `crypto::kyberbox` (X25519 + 
  ML-KEM-1024, AES-256-GCM-SIV). Hybrid: recovering the message 
  key requires breaking **both** branches (see 
  [`combiner.md`](combiner.md)).
- **Authenticity/integrity**: `crypto::sign` (Ed25519 + ML-DSA-87, 
  dual signature), when the caller signs and verifies.
- **At-rest key protection**: private keys sealed under a master 
  key supplied by `MkProvider` (file or TPM); secret types zeroize 
  on drop; crash-safe rotation with rewrap.
- **Post-quantum resistance (harvest-now-decrypt-later)**: the 
  ML-KEM-1024 branch protects traffic recorded today against a 
  future quantum adversary.

## Assumptions (the caller's responsibility, the library boundary)

KyberBox and the signatures are primitives; security depends on 
the caller upholding:

- **Authenticity of the recipient's public keys.** KyberBox does 
  not verify that `peer_pub_x` or `peer_k_pub` belong to the 
  intended recipient. Substituting the keys encrypts for the wrong 
  party. Binding identity is the messenger's invite/handshake 
  layer, not the library.
- **Domain-separation labels.** All contexts (`ctx`, OPAQUE/POW/DEK 
  labels) are supplied by the caller; they must be unique per use 
  and consistent between sides. The library is deliberately 
  label-agnostic.
- **No replay protection at the crypto level.** KyberBox does not 
  bind the ciphertext to a counter or state; replay detection is 
  in the messenger's session/storage layer (a window on `step` + 
  `msg_id` dedup), see [`kyberbox.md`](kyberbox.md).
- **No transport security.** TLS / anti-MITM at the network level 
  is the server/proxy layer.
- **Randomness quality.** The constructions rely on the system 
  CSRNG (fresh nonces and `seed_plain`).

## Adversary view (at the library level)

- **Ciphertext only (`WirePayload`).** Must break X25519 *and* 
  ML-KEM-1024 (hybrid). Nonce reuse is tolerated by 
  AES-256-GCM-SIV as defense-in-depth.
- **At-rest files without the master key.** Private keys are 
  sealed; without the MK (file/TPM) they are unreadable. Security 
  reduces to protecting the MK through `MkProvider`.
- **Adaptive attacker on decapsulation.** The `SHA256(ct_kem)` 
  filter before decapsulation is meant to limit using the blob as 
  an oracle, whether it is enough against adaptive CCA is the open 
  question D4 in [`combiner.md`](combiner.md).

## Forward secrecy / post-compromise

The library provides the primitives (fresh `seed_plain` per 
message, rotating RX keys). The actual FS/PCS guarantees of the 
E2E layer (epoch boundaries, passive vs active attacker, identity 
keys don't rotate) are a property of how `session.rs` uses 
KyberBox.

## Out of scope (the library's non-goals)

- Key distribution / PKI / identity verification.
- Side-channel resistance beyond what the primitives give. Note: 
  ML-KEM/ML-DSA come from `pqcrypto` (C code), the constant-time 
  assumptions are inherited from those implementations.
- Process memory safety against a local attacker with the same UID 
  (handled at the messenger layer).

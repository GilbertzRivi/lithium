//! Post-quantum hybrid cryptography and at-rest key management, usable as a standalone library.
//!
//! Every construction is hybrid classical + post-quantum: X25519 + ML-KEM-1024 for encryption,
//! Ed25519 + ML-DSA-87 for signatures, AES-256-GCM-SIV / HKDF-SHA256 / Argon2 underneath. The
//! crate is `#![forbid(unsafe_code)]`. All domain-separation labels are supplied by the caller,
//! so the crypto stays application-agnostic.
//!
//! # Two pillars
//!
//! - **At-rest key management** ([`keys`], [`secrets`]): [`keys::KeyManager`] owns the on-disk
//!   keyfile, pluggable master-key providers, crash-safe hourly rotation and rewrap. Secret
//!   types ([`secrets::Byte32`], [`secrets::SecretBytes`], [`secrets::MasterKey32`]) zeroize on
//!   drop.
//! - **Hybrid encryption** ([`crypto`]): [`crypto::kyberbox`] is the X25519 + ML-KEM-1024 AEAD
//!   construction; [`crypto::sign`] dual-signs Ed25519 + ML-DSA-87; [`crypto::aead`],
//!   [`crypto::kdf`], [`crypto::keys`] are the AEAD / KDF / keypair primitives beneath them.
//!
//! # Helpers
//!
//! Secondary, deployment-agnostic building blocks layered on the pillars: [`opaque`] (OPAQUE
//! PAKE + export-key DEK wrapping), [`pow`] (proof-of-work), [`passwords`] (password policy +
//! DEK generation), [`utils::store`] (TTL secret store), [`error`].
//!
//! # Security status
//!
//! Not yet independently audited. The constructions, their hybrid-combiner rationale and the
//! open questions for an auditor live under `docs/` (`combiner.md`, `lithium_core-threat-model.md`).
//!
//! The public surface is intended to be stable through the audit; treat it as frozen at `0.1`.
#![forbid(unsafe_code)]

/// Hybrid encryption pillar: KyberBox AEAD, dual signatures, and the AEAD/KDF/keypair primitives.
pub mod crypto;
/// Shared error type returned across the crate.
pub mod error;
/// At-rest key management pillar: keyfile, master-key providers, rotation and rewrap.
pub mod keys;
/// Helper: OPAQUE PAKE and export-key DEK wrapping for password-authenticated key retrieval.
pub mod opaque;
/// Helper: password policy validation and data-encryption-key generation.
pub mod passwords;
/// Helper: SHA-256 proof-of-work challenge/solve/verify.
pub mod pow;
/// At-rest key management pillar: zeroize-on-drop secret types.
pub mod secrets;
/// Helper: in-memory TTL store for ephemeral secrets.
pub mod utils;

pub use error::{CryptoErrorKind, LithiumError, Result};

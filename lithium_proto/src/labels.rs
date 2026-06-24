//! Lithium-specific domain-separation labels passed into the generic `lithium_core` primitives.
//!
//! `lithium_core` takes these as parameters so the crypto stays application-agnostic; the concrete
//! byte values that bind the Lithium deployment live here.

pub const OPAQUE_SERVER_ID: &[u8] = b"lithium-server";
pub const OPAQUE_SERVER_SETUP_LABEL: &[u8] = b"lithium/opaque-server-setup/v1";
pub const POW_CTX: &[u8] = b"lithium/send-pow/v1";
pub const DEK_WRAP_AAD: &[u8] = b"lithium/dek-wrap/v1";

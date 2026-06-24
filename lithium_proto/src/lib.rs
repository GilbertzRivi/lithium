//! Lithium-specific protocol and application glue layered on top of `lithium_core`.
//!
//! `lithium_core` is the generic, reusable post-quantum crypto library. Everything that is
//! specific to the Lithium messenger — the wire/REST contract, the SeaORM-backed data manager,
//! HTTP header parsing, and the domain-separation labels — lives here.

pub mod contract;
pub mod db;
pub mod headers;
pub mod labels;

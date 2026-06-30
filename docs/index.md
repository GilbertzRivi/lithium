# Lithium documentation

This is the documentation of the Lithium messenger as a whole, the 
daemon, the GUI, the relay server, and how they talk to each 
other. The cryptographic library at the bottom of all of it, 
`lithium_core`, has its own self-contained documentation that 
travels with the crate: see 
[`lithium_core/README.md`](../lithium_core/README.md) and the 
dossier in `lithium_core/docs/` (the combiner, KyberBox, the core 
threat model, the audit guide).

## Security and trust

- [security-model.md](security-model.md): the trust model, 
  priorities, assumptions, the deliberate trade-offs, what the 
  server sees per request, the primitives
- [threat-model.md](threat-model.md): the structured threat model, 
  the adversary classes and their capabilities, the defense and 
  residual risk, the forward secrecy and post-compromise 
  guarantees of the E2E layer
- [key-hierarchy.md](key-hierarchy.md): the catalog and hierarchy 
  of all keys, derivation, storage, lifetime, leak analysis
- [data-lifecycle.md](data-lifecycle.md): the data lifecycle and 
  privacy inventory, where data rests, retention, who sees what
- [reproducible-build.md](reproducible-build.md): the reproducible 
  client build, the pins, the container, checking a published 
  binary against the source

## Protocol

- [protocol/crypto-protocol.md](protocol/crypto-protocol.md): the 
  crypto protocol spec, transport (Shake/Session), E2E (WireV1), 
  the mailbox, contact pairing
- [protocol/ipc-reference.md](protocol/ipc-reference.md): the 
  daemon IPC protocol reference, the format, authorization, the 
  state machine, the full command list, env vars
- [protocol/versioning.md](protocol/versioning.md): format 
  versioning and the protocol evolution philosophy

## Crates

- [crates/lithiumd.md](crates/lithiumd.md): the client daemon, 
  IPC, E2E, the mailbox, SQLite, PlainFileMkProvider
- [crates/lithiumg.md](crates/lithiumg.md): the GUI, the state 
  machine, the threading model
- [crates/lithiums.md](crates/lithiums.md): the relay server, the 
  REST API, the middleware, transport, the PostgreSQL schema

## Operations

- [operations/deploy-instructions.md](operations/deploy-instructions.md): 
  deploying `lithiums`, env vars, master key providers, 
  Docker/Docker Compose
- [operations/daemon-runtime.md](operations/daemon-runtime.md): the 
  `lithiumd` daemon runtime, the process model, the system tray, 
  the lifecycle, the IPC endpoint, env vars, the data directory 
  layout
- [operations/development.md](operations/development.md): building, 
  version pinning and reproducibility (`Cargo.lock` + 
  `rust-toolchain.toml`), system dependencies, feature flags, 
  tests, fuzzing

## The rest

- [design-decisions.md](design-decisions.md): the "why" register 
  of the system-level design decisions, the reasons and the costs
- [glossary.md](glossary.md): the glossary of Lithium's own terms
- [`README.md`](../README.md): the project description, 
  architecture, security properties, deployment

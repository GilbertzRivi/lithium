# lithium_core: audit and grant guide

This is the entry point for auditing `lithium_core` as a 
standalone cryptography and key-management library, and the 
reading order for the grant review. The library is the subject; 
the wider Lithium messenger is only context that shows it isn't 
built in a vacuum.

## Scope

The subject is the `lithium_core` library, not the whole 
messenger. The boundary is set by 
[`threat-model.md`](threat-model.md): what the library guarantees 
and what is the caller's job (authenticity of the recipient's 
public keys, unique domain-separation labels, replay protection, 
transport). The central piece is the hybrid KyberBox combiner, and 
its correctness is the main finding.

**In scope:** the two pillars of `lithium_core`, key management at 
rest (`keys`, `secrets`) and hybrid encryption (`crypto`), plus 
the helpers (`opaque`, `pow`, `passwords`, `utils::store`).

**Out of scope:** the application layers, `lithiumd` (IPC, E2E 
session), `lithiums` (relay, REST transport, rate limiting), 
`lithiumg` (GUI). The library is consumed by them; they describe 
the usage contract the messenger follows and the library assumes, 
but they are not the target of the audit.

## Reading order

1. [`threat-model.md`](threat-model.md): the audit boundary, 
   guarantees vs the caller's responsibility.
2. [`combiner.md`](combiner.md): the central deliverable, the 
   combiner construction, comparison with X-Wing, the hybrid 
   argument, and deviations D1-D4 put plainly for the audit to 
   settle.
3. [`kyberbox.md`](kyberbox.md): the full wire and key flow of 
   KyberBox and the detailed construction-level risks (the "Open 
   risks and questions for the auditor" section).
4. [`key-hierarchy.md`](key-hierarchy.md): the at-rest key catalog 
   (MK, KEK, DEK, `.keyf`, the MkProvider, rotation).
5. [`reference.md`](reference.md): the API module by module; plus 
   the crate `README.md` and rustdoc (`cargo doc -p lithium_core`).

## Central questions

D1-D4 in [`combiner.md`](combiner.md): ciphertext binding in 
`base_key` (no explicit `msg_x_pub`/`ct_kem`), the KEM-DEM on the 
PQ branch, `ecdh_ss` as a non-uniform IKM with no salt, and 
`SHA256(ct_kem)` as the HKDF salt in seed transport. These are the 
declared open points, the scope the audit should settle.

## Reproducibility and coverage

- Dependencies are pinned in `Cargo.lock`; the toolchain is pinned 
  in `rust-toolchain.toml` (`1.96.0`). The full bit-for-bit 
  reproducibility of the messenger client binary is documented in 
  the main Lithium repo.
- Known-answer vectors (KAT): `tests/golden_tests.rs` (3 tests) on 
  data in `tests/testdata/` (`kyberbox_golden_v1`, 
  `mldsa87_verify_golden_v1`).
- Public API tests: `crypto_tests` (93), `secret_tests` (66), 
  `password_tests` (21), `store_tests` (14).
- Fuzzing: 13 `cargo-fuzz` targets on the surfaces that parse 
  untrusted input (the KyberBox wire format, the `.keyf` parser, 
  hex and JSON decoding).

## What the auditor gets

- The crate source: `lithium_core/src/`.
- This dossier, self-contained under `lithium_core/docs/`.
- The combiner mapping onto the literature (in `combiner.md`) and 
  the deviations D1-D4 as the scope to settle.

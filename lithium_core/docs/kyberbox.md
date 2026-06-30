# KyberBox: security analysis

This document describes the KyberBox construction in 
`lithium_core/src/crypto/kyberbox.rs` and its use in 
`lithiumd/src/e2e/session.rs`. It explains the goal of the 
composition, the exact key flow, the properties that follow from 
the construction, the responsibility boundary, and the open 
questions that matter for an audit.

## Goal

KyberBox is a hybrid encryption scheme that encrypts two 
independent plaintexts (`body` and `headers`) in one 
cryptographic operation, producing three opaque blobs: 
`enc_body`, `enc_headers`, `seed_enc`. The construction is 
designed so that breaking only the classical component (X25519) 
is not enough to decrypt a message, the attacker also has to break 
the post-quantum component (ML-KEM-1024). The same holds the other 
way: breaking only the post-quantum component is not enough either.

KyberBox aims to provide **confidentiality only**. It does not 
authenticate the sender, does not bind the ciphertext to the 
sender's identity, and does not protect against replay. Those 
responsibilities sit in the layers above.

## Primitives

All versions are pinned in `Cargo.lock`.

| Primitive | Implementation | Version |
|---|---|---|
| X25519 ECDH | `x25519-dalek` / `curve25519-dalek` | 2.0.1 / 4.1.3 |
| ML-KEM-1024 | `pqcrypto-mlkem` (PQClean `ml-kem-1024`) | 0.1.1 |
| AES-256-GCM-SIV | `aes-gcm-siv` | 0.11.1 |
| HKDF-SHA256 | `hkdf` + `sha2` | 0.12.4 / 0.10.9 |
| CSRNG | `rand::rngs::SysRng` | - |

The ML-KEM-1024 implementation comes from PQClean (`ml-kem-1024`, 
the clean reference implementation in C), not from the `kyber1024` 
directory, which matches the pre-standard CRYSTALS-Kyber draft 
(both directories exist in the bundled PQClean tree, but they are 
inconsistent at the format level and not mutually compatible). The 
FFI prefix `PQCLEAN_MLKEM1024_CLEAN_` and the constant 
`PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES = 32`, consistent with FIPS 
203, confirm this. The AVX2 and NEON paths are on by default.

## Key flow

On the encryption side the caller provides:
- `priv_x`: the sender's ephemeral X25519 private key (generated 
  fresh per message in `session.rs`)
- `peer_pub_x`: the recipient's X25519 public key (their 
  advertised reply/ratchet key)
- `peer_k_pub`: the recipient's ML-KEM-1024 public key
- `body`, `headers`: the plaintexts
- `ctx`: a context string for domain separation 
  (`"lithiumd/e2e-msg/v1"` in practice)

```
seed_plain (32B) <-- CSRNG
msg_x_priv (32B) <-- CSRNG  -->  msg_x_pub (sent as from_x_pub in WireV1)

Step 1: ECDH
  ecdh_ss  = X25519(msg_x_priv, peer_pub_x)
  ecdh_key = HKDF-SHA256(IKM=ecdh_ss, salt=none, info="{ctx}/ecdh-key/v1")

Step 2: Encrypt the seed (ML-KEM path)
  (ss_kem, ct_kem) = ML-KEM-1024.Encapsulate(peer_k_pub)
  aead_key_kem     = HKDF-SHA256(IKM=ss_kem, salt=SHA256(ct_kem),
                                 info="kemdem/kyber-mlkem1024/v1")
  aad_seed         = [0x01] || "kyberbox/v1|kem=mlkem1024|aead=aes256-gcm-siv|"
                   || [0x01, 0x01, 0x01, 0x20] || SHA256(ct_kem)
                   || "{ctx}/seed/v1"
  seed_enc         = [header 36B] || [u16be len(ct_kem)] || ct_kem
                   || AES-256-GCM-SIV(seed_plain, aead_key_kem, nonce_s, aad_seed)

Step 3: Base key (combination of both paths)
  base_key = HKDF-SHA256(IKM=ecdh_key, salt=seed_plain, info="{ctx}/base-key/v1")

Step 4: Encrypt the payloads
  body_key    = HKDF-SHA256(IKM=base_key, salt=none, info="{ctx}/body-key/v1")
  headers_key = HKDF-SHA256(IKM=base_key, salt=none, info="{ctx}/headers-key/v1")
  enc_body    = [0x01] || nonce_b || AES-256-GCM-SIV(body, body_key, nonce_b,
                                                       "{ctx}/body/v1")
  enc_headers = [0x01] || nonce_h || AES-256-GCM-SIV(headers, headers_key, nonce_h,
                                                       "{ctx}/headers/v1")

Result: WirePayload { enc_body, enc_headers, seed_enc }
```

All nonces (`nonce_s`, `nonce_b`, `nonce_h`) are 12 random bytes 
from the CSRNG, generated independently on each encryption call.

Decryption reverses the order: it parses `seed_enc`, verifies 
`SHA256(ct_kem)` against the stored salt *before* decapsulation, 
decapsulates `ss_kem`, derives `aead_key_kem`, decrypts 
`seed_plain`, then rebuilds the key chain from `ecdh_key` and 
`seed_plain` and decrypts the body and headers.

## Properties from the construction

The properties below follow from the design intent and the 
analysis of the construction. KyberBox has not had a formal 
analysis or an external audit, the stated properties are what the 
construction *should* provide, as long as the primitives meet 
their standard security assumptions.

**Hybrid security.** `base_key` is derived from both branches: 
`ecdh_key` (the X25519 path) and `seed_plain` (recovered through 
ML-KEM). Concretely: `seed_plain` is the HKDF salt in the 
`base_key` derivation, and `ecdh_key` is the IKM. To compute 
`base_key` without both inputs, the attacker would have to break 
X25519 (to compute `ecdh_key` without the private key) or 
ML-KEM-1024 (to recover `seed_plain` without the private key), as 
long as HKDF-SHA256 has no weakness that lets one input be 
skipped. Both branches are independent and, by the design, both 
are required. This construction is not home-grown: 
`HKDF-Extract(salt, IKM)` with one secret in each position is the 
known **dualPRF / split-key-PRF combiner** (Bindel et al., 
PQCrypto 2019; Giacon et al., PKC 2018), whose robustness 
(breaking one branch gives no advantage) is proven under the 
assumption that HMAC is a dual-PRF (Bellare-Lysyanskaya). The 
mapping of KyberBox onto this combiner and its deviations: 
[`combiner.md`](combiner.md).

**Fresh key per message.** Even if the recipient's X25519 and 
ML-KEM-1024 public keys are reused across several received 
messages (which happens until the recipient sends a reply), every 
message generates a fresh `seed_plain` through ML-KEM 
encapsulation. Because `seed_plain` is the salt in the `base_key` 
derivation, every message has a unique `base_key` and unique AEAD 
keys for body and headers.

**Nonce-reuse resistance.** AES-256-GCM-SIV is used instead of 
AES-256-GCM. The SIV construction tolerates nonce reuse, the 
effect of a collision is revealing that two messages under the 
same key are identical, but not the key or the plaintext. With 
96-bit random nonces, a collision needs on the order of 2^48 
encrypted blobs under the same AEAD key, which is out of reach in 
practice and would require reusing `base_key` (which doesn't 
happen). The SIV choice removes the catastrophic consequences of 
reuse as a defense-in-depth measure.

**Body-headers separation.** Body and headers are encrypted under 
different keys, derived with different labels. Swapping or 
exchanging `enc_body`/`enc_headers` with each other or with an 
`enc_body` from another message fails AEAD authentication, the 
keys don't match. A correctly decrypted body and headers share the 
same origin in one `base_key`, so they are implicitly bound to 
each other.

**Integrity check before decapsulation.** In `decrypt_kyber_seed`, 
`SHA256(ct_kem)` is verified against the stored salt in the blob 
*before* decapsulation happens. This prevents using the blob as a 
decapsulation oracle for attacker-chosen ciphertexts (at least at 
the level of deterministic filtering). Whether this filter is 
enough against an adaptive attacker needs to be checked in 
ML-KEM's specific security model. It also means a corrupted 
`ct_kem` is detected before the ML-KEM C code is called.

## Assumptions

KyberBox makes the following assumptions, which the caller has to 
uphold:

**The recipient's public keys are authentic.** KyberBox does not 
verify that `peer_pub_x` or `peer_k_pub` belong to the intended 
recipient. An attacker substituting these keys causes the message 
to be encrypted for the wrong party. In `session.rs` these keys 
come from stored contact state; their authenticity is the 
responsibility of the invite/handshake layer.

**The context string is unique to this use.** Domain separation 
through `ctx` only works if different protocols or uses of 
KyberBox use different values. Currently the only caller is 
`session.rs` with `"lithiumd/e2e-msg/v1"`. If KyberBox were reused 
with the same `ctx` in a different context, cross-protocol attacks 
would be possible.

**The caller passes `from_x_pub` correctly into the decrypt 
call.** KyberBox does not verify any relation between the X25519 
key passed to `decrypt` and any value in `seed_enc`. On the 
decryption side `decrypt_with_privs` in `session.rs` reads 
`from_x_pub` from the wire frame and passes it as `peer_pub_x`. 
Modifying `from_x_pub` in transit makes ECDH produce the wrong 
shared secret, which fails AEAD decryption, so the attack does not 
go through, but the detection happens through an AEAD failure, not 
through an explicit identity check inside KyberBox.

**The CSRNG is not compromised.** `seed_plain`, the ephemeral 
X25519 key, and all AEAD nonces come from `SysRng`. Any bias or 
predictability in the system generator breaks the fresh-key-per-
message property.

## What KyberBox does not guarantee

**Sender authentication.** Nothing in KyberBox binds the 
ciphertext to a specific sender. Any party that knows `peer_k_pub` 
and `peer_pub_x` (or intercepts `from_x_pub` during transmission) 
can produce a valid `WirePayload`. In the Lithium protocol, 
authentication is provided externally by the Ed25519 + ML-DSA-87 
dual signature over the plaintext headers and body, verified in 
`session.rs` before the decrypted content is returned.

**Replay protection (at the KyberBox level).** A recorded valid 
`WirePayload` can be sent again to the same recipient and AEAD 
will succeed, KyberBox itself does not bind the ciphertext to any 
counter or state, and the RX key is not consumed on decryption 
(the `self_get_rx_privs` lookup is a read, not a delete). Replay 
detection is done by two independent layers above.

**Layer 1: the replay window in `session.rs`.** Each header 
carries a monotonically increasing sender counter `step` (part of 
the **signed** header). After the signature is verified, and 
before any mutation of peer state, `decrypt_with_privs` calls 
`peer_st.replay.check_and_record(hdr.step)` (`ReplayWindow`, 
`state.rs:117-145`). This is a sliding window (like in 
IPsec/DTLS) of width 64: an exact duplicate `step`, or a `step` 
that fell below the window, is rejected with 
`replayed_message_err()`. The window **deliberately tolerates 
reordering** of different, not-yet-seen `step` values within its 
range, because the RX key layer accepts out-of-order messages 
anyway. The order of operations (signature -> replay -> mutation) 
matters: a forged `step` won't poison the window, and a rejected 
replay leaves no partial state.

**Layer 2: `msg_id` deduplication in the storage layer 
(defense-in-depth).** Each message carries a random `msg_id` (16 
B) in the signed header; auto-fetch (`traffic.rs`) stores it 
through `add_message` into a table with a `UNIQUE(msg_id)` 
constraint. A repeated `msg_id` returns `Ok(false)` -> the item is 
marked `duplicate`, not written to history and not shown. On top 
of that the server deletes a message atomically on the first fetch 
(one-time fetch), so a real replay needs a malicious server 
re-injecting the frame into the mailbox anyway. If a replay slipped 
past both mechanisms, re-decryption has idempotent side effects: 
sequence numbers and generations only move forward (no state 
regression).

**Forward secrecy at the X25519 level within one ratchet epoch.** 
The recipient's X25519 key (`rx_x_priv`) is kept until the 
recipient sends a reply and the sender starts using a new key. All 
messages sent to the recipient in that epoch share the X25519 
component. Compromising `rx_x_priv` lets an attacker retroactively 
decrypt the ECDH component of all messages encrypted for that key. 
The ML-KEM path still gives per-message separation (each has a 
unique `seed_plain`), but if ML-KEM is broken, recovering 
`rx_x_priv` would let all messages in the epoch be decrypted.

**Explicit binding between `seed_enc`, `enc_body` and 
`enc_headers`.** The three `WirePayload` fields are independently 
authenticated AEAD blobs. There is no shared MAC or commitment 
covering all of them together. The binding is implicit: `enc_body` 
and `enc_headers` are only decryptable if `seed_plain` is 
recovered correctly from `seed_enc`, and only if `seed_plain` is 
the same one used during encryption. Substituting any field from 
another message causes an AEAD failure, but it is an AEAD failure, 
not a higher-level protocol violation that the recipient could 
tell apart from ordinary transmission corruption.

## Open risks and questions for the auditor

The consolidated rationale for the hybrid combiner itself 
(comparison with X-Wing and the questions Q1-Q4 put plainly as the 
scope for the auditor) is in [`combiner.md`](combiner.md). The 
detailed construction-level risks are below.

**HKDF with no salt in `derive_ecdh_key`.** The call is 
`HKDF-SHA256(IKM=ecdh_ss, salt=None, info=...)`. Per RFC 5869 
§2.2, no salt makes HKDF-Extract use an HMAC key of zeros of 
length `HashLen`. The X25519 output is then taken directly as the 
IKM. The X25519 output is a 32-byte value on the Curve25519 group, 
not uniformly random over the full 256 bits (the top bit is always 
0, the low bits are cleared by clamping). This is standard 
practice used in many protocols, but the auditor should check that 
the specific security proof covers this IKM distribution.

**Storing the X25519 private key as a raw seed before clamping.** 
`random_x25519_keypair` returns and stores `sk_seed`, 32 bytes 
before clamping, not the clamped scalar. Clamping is applied on 
every use through `XStaticSecret::from(seed_array)`. The pattern is 
correct and consistent inside the codebase, but any future code 
that interpreted the stored bytes directly as a Curve25519 scalar 
would be wrong. The auditor should check all use sites to make 
sure the private key always goes through `XStaticSecret::from()`.

**The PQClean C code is an unaudited external dependency.** The 
ML-KEM-1024 implementation is the PQClean reference C code, 
compiled through FFI. The AVX2 and NEON paths are on by default. 
The Lithium team has not audited this code. Any timing side 
channel, memory safety problem, or FIPS 203 mismatch in the 
PQClean code would be inherited. This is a standard dependency 
risk, but worth noting explicitly given the threat model.

**No explicit binding of `from_x_pub` inside KyberBox (deviation 
D1, see `combiner.md`).** The sender's ephemeral X25519 public key 
(`from_x_pub` in `WireV1`) is used as `peer_pub_x` in the 
`decrypt` call, but it is not included in any HKDF info or any AEAD 
AAD inside kyberbox.rs. Modifying `from_x_pub` in transit causes an 
AEAD failure (different ECDH output -> different `base_key`), so an 
active attacker can't silently substitute it. But KyberBox by 
itself does not say *which* public key was used, attributing a 
message to a specific sender is the caller's job. In `session.rs` 
this is handled by verifying the external signature. Important: in 
the combiner role `from_x_pub` is the classical ciphertext 
(`ct_T`), which *both* IETF combiners 
(`draft-irtf-cfrg-hybrid-kems`) bind explicitly in the KDF, 
because X25519 has no C2PRI; KyberBox binds it only implicitly, 
through `ecdh_ss`. The cheap fix: add `msg_x_pub` (and `ct_kem`) 
to the `info` in the `base_key` derivation, which makes the 
construction an instance of the UniversalCombiner.

## Summary

KyberBox is a simple hybrid KEM-DEM construction: ML-KEM-1024 
encapsulates a fresh 32-byte seed, X25519 provides a second 
independent shared secret, both are joined through HKDF into 
`base_key`, and body and headers are encrypted with 
AES-256-GCM-SIV under keys derived from `base_key`. The scheme 
aims for fresh-key-per-message through the random seed, hybrid 
classical/post-quantum security through the combined key 
derivation, and nonce-reuse resistance through the SIV 
construction, as long as the primitives meet their standard 
security assumptions.

KyberBox by itself does not provide authentication, replay 
protection, or forward secrecy, those sit in the layers above. 
Authentication (dual-sign) and forward secrecy are done by the 
session layer (`lithiumd/src/e2e/session.rs`). Replay protection 
is **two-layered**: a sliding window on the signed `step` counter 
in `session.rs` (`ReplayWindow`), and `msg_id` deduplication with 
a `UNIQUE` constraint in the storage layer (auto-fetch in 
`traffic.rs` + `add_message`), backed by one-time fetch on the 
server side.

The main items needing external validation are: the ML-KEM-1024 C 
implementation from PQClean, the X25519 clamping convention 
everywhere keys are stored and used, and the specific security of 
HKDF-SHA256 with the X25519 output as IKM and no explicit salt.

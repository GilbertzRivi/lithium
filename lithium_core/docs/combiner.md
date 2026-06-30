# The combiner story: hybrid composition of KyberBox

This document justifies the **hybrid combiner** used in 
`lithium_core/src/crypto/kyberbox.rs`: what exactly composes the 
classical branch (X25519) with the post-quantum one 
(ML-KEM-1024), which published result it stands on, and which 
deviations from the canon are left for the auditor to confirm.

Starting point: **the combiner is not new and not home-grown.** 
The core of it (joining two secrets through HKDF, where one is the 
IKM and the other the salt) is a **dualPRF / split-key-PRF 
combiner**, a construction described and proven in the literature. 
KyberBox is an instance of it with a few deviations; those 
deviations, not the idea itself, are what gets validated.

The construction at the wire and key-flow level: 
[`kyberbox.md`](kyberbox.md). Here we focus on the combiner itself 
and its rationale.

## 1. Construction (short)

KyberBox isn't a "KEM that returns a shared secret", it's a full 
AEAD that encrypts `body` and `headers`. The keys come from two 
independent branches joined by HKDF-SHA256:

```
Classical branch (X25519):
  ecdh_ss  = X25519(priv_x, peer_pub_x)
  ecdh_key = HKDF-SHA256(IKM=ecdh_ss, salt=none, info="{ctx}/ecdh-key/v1")

Post-quantum branch (ML-KEM-1024, KEM-DEM over a random seed):
  seed_plain        <-- CSRNG (32B, fresh per message)
  (ss_kem, ct_kem)  = ML-KEM-1024.Encapsulate(peer_k_pub)
  aead_key_kem      = HKDF-SHA256(IKM=ss_kem, salt=SHA256(ct_kem), info="kemdem/...")
  seed_enc          = AES-256-GCM-SIV(seed_plain, aead_key_kem, ...)   # seed transport

Combiner:
  base_key   = HKDF-SHA256(IKM=ecdh_key, salt=seed_plain, info="{ctx}/base-key/v1")
  body_key   = HKDF-SHA256(IKM=base_key, salt=none, info="{ctx}/body-key/v1")
  headers_key= HKDF-SHA256(IKM=base_key, salt=none, info="{ctx}/headers-key/v1")
```

The key moment of the combination: **`ecdh_key` is the IKM and 
`seed_plain` (recovered through ML-KEM) is the salt** in the 
`base_key` derivation. Both branches go into one HKDF; without 
both you can't compute `base_key`.

## 2. What it stands on (literature)

`base_key` is an instance of the canonical hybrid combiner. The 
mapping:

```
Canon (dualPRF combiner):  k        = HKDF-Expand( HKDF-Extract(salt=k1, IKM=k2), info=c1||c2 )
KyberBox:                  base_key = HKDF-Expand( HKDF-Extract(salt=seed_plain, IKM=ecdh_key), info="base-key/v1" )
```

The `HKDF-Extract(salt, IKM)` part is exactly a dual-PRF: 
pseudorandom when *either* of the two arguments is random. That is 
what gives hybrid security, breaking one branch gives no 
advantage. Sources:

- **Bindel, Brendel, Fischlin, Gonçalves, Stebila**, *Hybrid Key 
  Encapsulation Mechanisms and Authenticated Key Exchange*, 
  PQCrypto 2019 (eprint 2018/903), sec. 3.2: defines the 
  **dualPRF combiner** `PRF(dPRF(k1,k2), c1||c2)` with 
  `dPRF=HKDF-Extract`, `PRF=HKDF-Expand`, modeled on TLS 1.3; 
  robust under the assumption that HMAC is a dual-PRF.
- **Bellare, Lysyanskaya**, generic validation of the dual-PRF 
  assumption for HMAC.
- **Giacon, Heuer, Poettering**, *KEM Combiners* (PKC 2018): the 
  **split-key PRF**, if the combiner is a split-key-PRF and at 
  least one component KEM is IND-CCA, the combined KEM is IND-CCA.
- **draft-irtf-cfrg-hybrid-kems** (CFRG, in progress): the 
  recommended **UniversalCombiner** and **C2PRICombiner** 
  constructions (see sec. 3).
- **Barbosa et al.**, *X-Wing: The Hybrid KEM You've Been Looking 
  For* (eprint 2024/039): the proof that the ML-KEM ciphertext can 
  be dropped under the C2PRI assumption.

Takeaway: no proof from scratch is needed. What's needed is to 
show that KyberBox maps onto these constructions, and to judge the 
deviations in sec. 4.

## 3. How it differs from X-Wing and the canon

X-Wing is a standardized hybrid KEM:

```
X-Wing: ML-KEM-768 + X25519:
  ss = SHA3-256( ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || XWingLabel )
```

KyberBox differs in three things, but only one is a real question:

1. **Security level (harmless).** ML-KEM-**1024** (cat. 5) instead 
   of 768 (cat. 1). The whole stack (ML-DSA-87) is picked for cat. 
   5. A parameter change, not a construction change.
2. **KEM vs AEAD + KEM-DEM (to confirm).** X-Wing returns a shared 
   secret; KyberBox is a full AEAD, and the ML-KEM branch 
   transports a fresh `seed_plain` (KEM-DEM). Consequence: the 
   C2PRI assumption then applies to the KEM-DEM construction, not 
   to bare ML-KEM. To confirm.
3. **Ciphertext binding (the real question).** Both IETF combiners 
   bind the classical ciphertext `ct_T`:
   - **UniversalCombiner**: `KDF(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)`, binds both.
   - **C2PRICombiner**: `KDF(ss_PQ, ss_T, ct_T, ek_T, label)`, may drop `ct_PQ` (= `ct_kem`) under C2PRI, but `ct_T` (= the ephemeral X25519 key `msg_x_pub`) stays.

   KyberBox **does not bind** `ct_kem` or `msg_x_pub` in `info`. 
   `msg_x_pub` is bound only implicitly, through `ecdh_ss`. 
   Dropping `ct_kem` is consistent with C2PRICombiner/X-Wing. 
   Dropping the explicit `msg_x_pub` is a **deviation from both 
   IETF combiners** (see D1 below).

## 4. Deviations for the auditor to settle

Numbering D1-D4. The preliminary verdict is what the literature 
already says; it needs confirmation.

- **D1: ciphertext binding in `base_key` (most important).** No 
  `ct_T` (`msg_x_pub`) in `info`, while both IETF combiners bind 
  it (X25519 has no C2PRI). **Preliminary verdict:** a real 
  deviation; the cheap fix is to bind `msg_x_pub` (and `ct_kem` 
  for safety) in `info`, which turns KyberBox into an instance of 
  the UniversalCombiner. **Question for the auditor:** is the 
  implicit binding through `ecdh_ss` enough for the required 
  binding properties (MAL-BIND-K-CT/PK), or is explicit binding 
  necessary.
- **D2: KEM-DEM on the PQ branch.** `seed_plain` (transported) 
  instead of bare `ss_kem` as the combiner input. **Preliminary 
  verdict:** probably fine, but then C2PRI applies to the KEM-DEM 
  construction. **Question:** does the KEM-DEM keep the C2PRI 
  needed to drop `ct_kem`.
- **D3: `ecdh_ss`/`ecdh_key` as a non-uniform IKM with no salt.** 
  The X25519 output isn't uniform (clamping, top bit zero). 
  **Preliminary verdict:** covered, HKDF-Extract is designed for 
  non-uniform IKM (Krawczyk 2010, RFC 5869), and in `base_key` the 
  random `seed_plain` as salt helps further. The smallest risk.
- **D4: `SHA256(ct_kem)` as the HKDF salt in seed transport.** The 
  salt is a hash of the visible ciphertext. **Preliminary 
  verdict:** standard and acceptable (an HKDF salt only has to be 
  non-secret and unique per ciphertext; the actual key material is 
  `ss_kem`). **Question for the auditor:** can an attacker who 
  chooses `ct_kem` adaptively force a salt that weakens 
  `aead_key_kem` in ML-KEM's IND-CCA2 model. The one most worth an 
  expert eye.

## 5. What the auditor gets

- The combiner code: `lithium_core/src/crypto/kyberbox.rs` (plus 
  `crypto/kdf.rs`, `crypto/aead.rs`).
- The wire and key-flow description: [`kyberbox.md`](kyberbox.md).
- The library's responsibility boundary: 
  [`threat-model.md`](threat-model.md).
- The mapping onto the literature (sec. 2) and the deviations 
  D1-D4 (sec. 4) as the scope to settle.

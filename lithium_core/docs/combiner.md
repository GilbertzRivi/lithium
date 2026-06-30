# KyberBox hybrid combiner

What this covers:

- how the X25519 branch and the ML-KEM-1024 branch are joined
- which published result the join comes from
- what an auditor checks

The combiner is not new. It is the UniversalCombiner from 
`draft-irtf-cfrg-hybrid-kems`, on top of the dualPRF / 
split-key-PRF combiner from the literature. The audit checks the 
mapping and the code, not a new proof.

Wire and key flow: [`kyberbox.md`](kyberbox.md).

## Construction

KyberBox is not a KEM that returns a shared secret. It is a full 
AEAD over `body` and `headers`. Two branches feed one HKDF:

```
Classical branch (X25519):
  ecdh_ss  = X25519(priv_x, peer_pub_x)
  ecdh_key = HKDF-SHA256(IKM=ecdh_ss, salt=none, info="{ctx}/ecdh-key/v1")

Post-quantum branch (ML-KEM-1024):
  (ss_kem, ct_kem) = ML-KEM-1024.Encapsulate(peer_k_pub)

Combiner:
  base_key   = HKDF-SHA256(IKM=ecdh_key, salt=ss_kem,
                           info="{ctx}/base-key/v1" || ct_T || ek_T
                                || SHA256(ct_kem))
  body_key   = HKDF-SHA256(IKM=base_key, salt=none, info="{ctx}/body-key/v1")
  headers_key= HKDF-SHA256(IKM=base_key, salt=none, info="{ctx}/headers-key/v1")
```

The pieces:

- `ct_T`: sender's ephemeral X25519 public key
- `ek_T`: recipient's X25519 public key
- `ss_kem`: ML-KEM shared secret; goes straight into the combiner
- `ct_kem`: the only PQ value on the wire; the recipient 
  decapsulates it back to `ss_kem`

The combiner step:

- IKM: `ecdh_key`
- salt: `ss_kem`
- info: the label plus the bound transcript (`ct_T`, `ek_T`, 
  `SHA256(ct_kem)`)

You need both branches to get `base_key`.

## Where it comes from

`base_key` is the canonical hybrid combiner:

```
Canon (dualPRF combiner):  k        = HKDF-Expand( HKDF-Extract(salt=k1, IKM=k2), info=c1||c2 )
KyberBox:                  base_key = HKDF-Expand( HKDF-Extract(salt=ss_kem, IKM=ecdh_key), info=transcript )
```

`HKDF-Extract(salt, IKM)` is a dual-PRF: random when either input 
is random. That gives the hybrid property. Break one branch, gain 
nothing.

Sources:

- **Bindel, Brendel, Fischlin, Goncalves, Stebila**, *Hybrid Key 
  Encapsulation Mechanisms and Authenticated Key Exchange*, 
  PQCrypto 2019 (eprint 2018/903), sec. 3.2: the **dualPRF 
  combiner** `PRF(dPRF(k1,k2), c1||c2)`, with `dPRF=HKDF-Extract`, 
  `PRF=HKDF-Expand`, modeled on TLS 1.3. Robust when HMAC is a 
  dual-PRF.
- **Bellare, Lysyanskaya**: the dual-PRF assumption for HMAC.
- **Giacon, Heuer, Poettering**, *KEM Combiners* (PKC 2018): the 
  **split-key PRF**. If the combiner is a split-key-PRF and one 
  component KEM is IND-CCA, the combined KEM is IND-CCA.
- **draft-irtf-cfrg-hybrid-kems** (CFRG, in progress): the 
  **UniversalCombiner**, `KDF(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, 
  ek_T, label)`, which binds the full transcript.
- **Barbosa et al.**, *X-Wing: The Hybrid KEM You've Been Looking 
  For* (eprint 2024/039): the binding for the classical branch 
  (bind `ct_T` and `ek_T`).

No proof from scratch. The job: show KyberBox maps onto these, and 
the code matches.

## Map to X-Wing and the UniversalCombiner

X-Wing (a standardized hybrid KEM):

```
X-Wing: ML-KEM-768 + X25519:
  ss = SHA3-256( ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || XWingLabel )
```

KyberBox uses the same binding logic. Two differences, both 
parameters not construction:

- ML-KEM-**1024** (cat. 5), not 768 (cat. 1). The stack 
  (ML-DSA-87) is cat. 5.
- AEAD, not a bare KEM. `base_key` encrypts `body` and `headers` 
  with AES-256-GCM-SIV. The combiner up to `base_key` is the same.

What gets bound:

- Classical branch: `ct_T` and `ek_T` go in `info`. X25519 has no 
  binding of its own, so both are explicit (the X-Wing pattern).
- PQ branch: `ct_kem` is bound through `SHA256(ct_kem)`. `ek_PQ` 
  (the recipient's ML-KEM key) is already inside `ss_kem` via 
  ML-KEM's `H(ek)` (FIPS 203), so it is not repeated.

The full transcript is bound, so no C2PRI assumption is needed. 
This is the UniversalCombiner, not the weaker C2PRICombiner.

## What the auditor checks

- the mapping: `base_key` is the dualPRF combiner, `ss_kem` as 
  salt, `ecdh_key` as IKM, transcript in `info`
- the X25519 IKM: not uniform (clamping, top bit zero). 
  HKDF-Extract handles non-uniform IKM (Krawczyk 2010, RFC 5869); 
  `ss_kem` as salt adds entropy on top
- serialization and domain separation: field order in `info`, the 
  `ctx` labels, the AEAD AADs
- code hygiene: zeroization, error handling, the Rust/FFI boundary 
  to PQClean ML-KEM-1024

Code: `lithium_core/src/crypto/kyberbox.rs` (plus `crypto/kdf.rs`, 
`crypto/aead.rs`). Wire and key flow: 
[`kyberbox.md`](kyberbox.md). Boundary: 
[`threat-model.md`](threat-model.md).

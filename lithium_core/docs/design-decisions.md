# Design decisions

The "why" behind lithium_core's core cryptographic choices, their 
reasons, and their cost.

## 1. Classic + PQ Hybrid

**Decision**: Each KEM is X25519 + ML-KEM-1024, each signature is
Ed25519 + ML-DSA-87. All secrets are combined so the attacker has to
break both.

**Why**: Protects from "harvest now decrypt later" strategy without
giving up standard encryption which has been battle-tested for many
years now. In case the PQ turns out to be flawed, the classic
encryption holds, and vice versa.

**Cost**: Performance, bigger keys, and a C-code dependency (the
unaudited PQClean ML-KEM, see [`kyberbox.md`](kyberbox.md)).

## 2. AES-256-GCM-SIV as the sole AEAD

**Decision**: All AEAD in lithium_core uses AES-256-GCM-SIV.

**Why**: In case the nonce is reused, it reveals only that the
plaintext is the same, rather than causing a catastrophe like
standard GCM. It acts as a "safety net" against errors in nonce
management.

**Cost**: It's deterministic, which requires attention when
randomness is required.

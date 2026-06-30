# Glossary

Short definitions of the terms used across the `lithium_core` 
dossier.

**AEAD** - Authenticated Encryption with Associated Data. In 
lithium_core always AES-256-GCM-SIV.

**AES-256-GCM-SIV** - the sole AEAD. Nonce-misuse-resistant (SIV), 
so a repeated nonce reveals only that two plaintexts are equal, 
not the key.

**aPAKE / OPAQUE** - asymmetric Password-Authenticated Key 
Exchange. The `opaque` helper wraps `opaque-ke` (ristretto255 + 
Argon2) so the caller can authenticate without a server ever 
seeing the password.

**Argon2id** - key-stretching function and password derivation; 
parameters 64 MiB, t=3, p=1. Used for password hashing and DEK 
wrapping.

**DataManager** - the `db` facade joining a SeaORM connection with 
a KeyManager; encrypts and decrypts database blobs under a DEK 
with a separate AAD per field.

**DEK (Data Encryption Key)** - the key that encrypts data: in a 
`.keyf` file it's random per file (wrapped under the KEK); a caller 
may also derive a database DEK from the MK.

**EphemeralStore** - in-memory store with TTL (`utils::store`); 
zeroizes entries on expiry. A process restart wipes it.

**harvest-now-decrypt-later** - an attacker who records ciphertext 
today to decrypt it with a quantum computer later. The reason for 
the post-quantum hybrid.

**HKDF** - HKDF-SHA256, the key derivation function. `info` is 
always required (domain separation); `salt` is optional.

**KEK (Key Encryption Key)** - `HKDF(MK, file_salt, "kek/v1")`; 
wraps the DEK inside a `.keyf` file.

**KEM** - Key Encapsulation Mechanism; here the X25519 + 
ML-KEM-1024 hybrid.

**KeyManager** - the component that manages one identity's key 
material: it stores private keys sealed under the MK, handles 
rotation, and recovers an interrupted rotation.

**`.keyf`** - the key file format with double wrapping: payload 
under the DEK, DEK under the KEK (from the MK). Magic `KEYF`.

**KyberBox** - the hybrid KEM-DEM construction: ML-KEM-1024 + 
X25519 feed HKDF, then AES-256-GCM-SIV for `body` and `headers`. 
See [`kyberbox.md`](kyberbox.md).

**Master Key (MK)** - the top key that encrypts `.keyf` files, 
supplied by an MkProvider; rotated every hour.

**MkProvider** - the pluggable source of the MK: 
`PlainFileMkProvider` (file) or `TpmMkProvider` (sealed in the 
TPM).

**MkRotator** - the background task that wakes every 30 s and 
rotates the MK once the interval passes (3600 s by default).

**ML-DSA-87** (Dilithium) - post-quantum signature scheme; part of 
the dual signature.

**ML-KEM-1024** (Kyber) - post-quantum KEM; part of the encryption 
hybrid.

**PoW (proof-of-work)** - the `pow` helper: SHA-256 with a 
required number of leading zero bits, used by the caller as 
anti-spam.

**TPM sealing** - sealing the Master Key in the TPM as a KEYEDHASH 
object under an ECC P-256 parent derived from the owner seed (the 
parent is never persisted). The `TpmMkProvider` path.

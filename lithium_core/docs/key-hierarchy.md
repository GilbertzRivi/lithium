# Key catalog and hierarchy

The at-rest key management that `lithium_core` provides: where the 
keys come from, where they live, how long they last, and what they 
protect. All labels are pinned by tests 
(`registry_values_are_pinned`).

## The `.keyf` wrapping

```
master key (from MkProvider) -> KEK = HKDF(MK, file_salt, "kek/v1") -> DEK (random per file) -> payload (private keys / secrets)
```

Double wrapping: the payload is sealed under a per-file DEK, and 
the DEK is sealed under the KEK derived from the master key. The 
master key never touches the payload directly.

## At-rest keys

| Key | Type | Derivation / source | Storage | Lifetime / rotation | Protects |
|-----|------|--------------------|---------|--------------------|----------|
| Master Key (MK) | 32 B random | supplied/sealed by an `MkProvider` (file or TPM) | provider-specific (see below) | rotated every 1 h (`MkRotator`, 30 s tick) | every `.keyf` file (through the KEK) |
| KEK | 32 B | `HKDF(MK, file_salt, info="kek/v1")` | not stored (derived on use) | with the MK | wrapping the DEK in a `.keyf` |
| `.keyf` DEK | 32 B random | random per file | in the `.keyf`, wrapped under the KEK | rewrapped on MK rotation (value unchanged) | the key/secret payload in the file |

The caller can also derive application-specific 32-byte secrets 
straight from the MK with its own label (`derive_secret32(label)`); 
those outputs and their labels are the caller's responsibility.

## MkProvider

The master key source is pluggable:

- **`PlainFileMkProvider`**: the MK lives in a file. The caller 
  can wrap it under a passphrase, for example 
  `AES-256-GCM-SIV(MK, Argon2id(passphrase, salt), aad="lithium/mkfile/v1")` 
  stored at `keystore/user/mk.enc`.
- **`TpmMkProvider`** (default when the `tpm` feature is on): the 
  MK is sealed as a KEYEDHASH object in the TPM under an ECC P-256 
  restricted decryption parent, derived deterministically from the 
  owner seed. The parent is **never persisted**. The sealed blob 
  goes to `LITHIUM_TPM_SEALED_PATH`. Falls back to the plain file 
  provider when `LITHIUM_MK_PROVIDER=plain`.

The same library serves both client and server; they differ only 
in which `MkProvider` supplies the MK.

## Rotation

`MkRotator` wakes every 30 s and rotates the MK once the interval 
passes (1 h by default). Rotation rewraps each `.keyf` DEK under 
the new MK; the DEK values themselves don't change, so the payload 
is untouched. The rewrap is crash-safe.

## Secret types

`Byte32`, `SecretBytes`, `SecretString`, `MasterKey32` all zeroize 
on drop, so key material doesn't linger in process memory after 
use.

## At-rest leak analysis

What the library's at-rest protection holds against:

| Compromise | What's exposed | What's still protected |
|------------|----------------|------------------------|
| The disk alone, without the MK (or its passphrase/TPM) | nothing, `.keyf` files are encrypted | all key material |
| Breaking ML-KEM **or** X25519 on its own | nothing, the other half of the hybrid still holds | message content (both must break) |

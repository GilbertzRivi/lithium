# Versioning and protocol evolution

How Lithium versions its formats and the current philosophy for 
changing them. The concrete formats are in 
[crypto-protocol.md](crypto-protocol.md); the list of labels is in 
[key-hierarchy.md](../key-hierarchy.md).

## Two layers of versioning

**1. Domain labels `/vN`**: strings used as the `info` in HKDF, 
the AAD in AEAD, and as KyberBox contexts. Their job is **domain 
separation**: the same key material under a different label gives 
different keys, and a ciphertext made with one label won't decrypt 
under another. Examples: `kek/v1`, `lithium/db-dek/v1`, 
`lithium/mbox/address/v1`, `lithiumd/e2e-msg/v1`, 
`lithiumd/pair-commit/v1`, `lithiumd/contact-verify-emoji/v1`, 
`user-opaque-record/v1`, `lithium/send-pow/v1`. Transport contexts 
are built per endpoint by `ctx_req`/`ctx_resp` (for example 
`shake-req`, `msg_send-resp`).

**2. `VER` bytes + magics**: in the binary formats. Their job is 
to **identify and reject** an unknown format (fail-closed). The 
current state:

| Format | Magic | Version |
|--------|-------|---------|
| AEAD blob | - | 1 (first byte) |
| KyberBox (`kem_ct`) | - | 1 (+ `kem_id=1`) |
| Key file `.keyf` | `KEYF` | 1 |
| E2E message `WireV1` | `LM1` | 1 |
| Invite code `lci1:` | `LCI1` | 1 |
| MK file | `LMK1` | 1 |
| `server.identity` | `LITHIUPK` | 1 |
| DEK wrapping (OPAQUE) | - | 1 (`DEK_WRAP_VER`) |
| `id_enc` / server message | - | 1 (`UIDENC_VER` / `MSG_VER`) |

## Stance: "v1-only, fail-closed"

Everything is at version **1** today. Decoders **reject** any 
other version byte instead of trying to interpret it, there is no 
version negotiation and no parallel handling of several versions. 
A wrong version, wrong magic, or wrong length is a hard error (for 
example an AEAD blob with a version other than 1 won't decrypt; an 
`lci1:` with a version other than 1 is rejected). This is on 
purpose: no "soft" tolerance limits the attack surface on the 
parsers.

The only forward-compat exception: `server.identity` **ignores 
unknown TLV tags** on deserialization (so future keys can be added 
without breaking old clients), but the four known tags must be 
present and have the exact length.

## Pinning values

Every label, magic, and version byte is pinned by the 
`registry_values_are_pinned` tests (`lithium_core/src/labels.rs`, 
`lithiums/src/labels.rs`, `lithium_core/src/contract/protocol.rs` 
and the E2E equivalents). The test asserts the exact bytes. The 
consequence: a label/version is a **contract**, not an incidental 
string, an accidental change (a typo, a refactor) breaks the tests 
before it reaches the wire. Every deliberate change needs the pin 
updated alongside it.

## Evolution philosophy

Lithium **is not deployed yet**, there is no installed client base 
and no production data that needs wire compatibility. From that 
follows the rule **correct-by-construction over backward 
compatibility**: when a format has to change, it changes cleanly 
instead of growing compatibility shims.

In practice, a format change is one coherent step:
1. Change the `VER` byte or the label (`/v1` -> `/v2`).
2. Update the encoder and decoder on both sides **at the same 
   time**.
3. Update the pinning test.
4. Do **not** add a handling path for the old version or a feature 
   flag, backwards-compat shims and re-exports for removed code 
   aren't allowed in this project.

Once the project is deployed, this stance will have to change to 
proper migration (parallel handling of `vN`/`vN+1`, a transition 
window), that is a deliberate future turning point, not the 
current state.

## What is coupled (don't version in isolation)

Some values are tied together, and changing one needs compensation 
elsewhere:

- **Directional transport contexts** (`-req`/`-resp`) and the AEAD 
  labels must be identical on both sides of a wrap, otherwise 
  decryption fails.
- **The SAS length and commit-reveal** are coupled (see 
  [design-decisions.md](../design-decisions.md) #5): shortening 
  one without the other reopens the offline grind.
- **Derivation labels** (`combined/v1`, `db-dek/v1`, ...) define 
  the identity of the derived keys, changing a label's version 
  invalidates all data encrypted under the old key.

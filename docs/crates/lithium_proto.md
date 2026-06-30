# lithium_proto: Lithium-specific protocol glue

The messenger-specific layer that sits on top of `lithium_core`. 
`lithium_core` is the generic, reusable post-quantum crypto 
library and knows nothing about Lithium; everything that is 
specific to this deployment lives here: the wire/REST contract, 
the server-identity file format, the encrypted-at-rest data 
manager, HTTP header parsing, and the domain-separation labels.

The split exists so the crypto stays application-agnostic. 
`lithium_core` takes every domain-separation label as a parameter; 
the concrete byte values that bind the Lithium deployment are 
defined in this crate, not in the library.

## Place in the architecture

```
lithium_core (generic PQ crypto + at-rest key management)
  ^                      uses, supplies labels/contract from
lithium_proto   <- this crate
  ^
  +-- lithiumd          (client daemon)
  +-- lithiums          (relay server)
  +-- lithium_itest     (integration tests)
```

`lithiumg` does not depend on `lithium_proto`; the GUI talks to 
`lithiumd` over IPC and never touches the wire contract directly.

```
src/
  lib.rs                re-exports the four modules
  labels.rs             domain-separation label constants passed into lithium_core
                        (OPAQUE_SERVER_ID, OPAQUE_SERVER_SETUP_LABEL, POW_CTX, DEK_WRAP_AAD)
  headers.rs            HTTP header parsing helpers (header_str, header_hex, header_hex_bytes)
  db.rs                 DataManager<P: MkProvider>: SeaORM connection plus at-rest blob
                        decryption through KeyManager
  contract/
    mod.rs            module wiring
    protocol.rs       wire/REST field-name constants (key-x, key-k, kem-ct, sig-ed,
                      sig-dili, handler, opaque, pow, dek, token, mailbox, ...)
    identity_file.rs  binary server.identity format: magic "LITHIUPK", encode/decode
                      of ServerIdentityKeys (the four server public keys)
```

## Boundary with lithium_core

The rule is one-directional: `lithium_proto` depends on 
`lithium_core`, never the reverse. If a value is generic crypto 
(a primitive, a key type, the keyfile format) it belongs in 
`lithium_core`. If it only means something to the Lithium 
messenger (a header name, a label string, the `server.identity` 
layout) it belongs here. Keeping that line clean is what lets 
`lithium_core` be extracted and reused on its own.

The wire format these constants describe is documented in 
[`../protocol/crypto-protocol.md`](../protocol/crypto-protocol.md). 
The crypto they feed is documented in the `lithium_core` dossier 
([`../../lithium_core/docs/index.md`](../../lithium_core/docs/index.md)).

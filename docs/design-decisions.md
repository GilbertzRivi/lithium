# Design decisions 

Answers the "why" questions about the main architectural decisions, explains 
their reasons, and cost. The priorities are described in [security-model.md](security-model.md).
These are the system-level decisions; the ones that belong to the crypto 
library (the classic + PQ hybrid, AES-256-GCM-SIV) are in the `lithium_core` 
[docs](../lithium_core/README.md).

## 1. OPAQUE 

**Decision**: Authentication with OPAQUE (aPAKE, `opaque-ke 4.0.1`, 
ristretto255 + Argon2 as KSF).

**Why**: Server (hostile relay) never should see the password or the hash. 
This way there is nothing to steal from the server, nothing to crack. 
People also tend to reuse their passwords on many platforms, this way 
the server can't leak them, because it never holds them.

**Cost**: More complicated authentication and handshake. Dependency
on OPAQUE lib.

## 2. Anonymous mailboxes

**Decision**: Server never routes messages based on the identity.

**Why**: Server is a hostile relay, so it shouldn't be able to make a social
graph who talks to whom. Instead, both clients calculate the mailbox address 
using ECDH and rotate it once per a few messages.

**Cost**: Complexity, no simple inbox. 

## 3. Commit reveal + short SAS

**Decision**: Adding a contact is a 1 sided commit reveal, and the
identity verification is a 36 bit SAS.

**Why**: A short SAS is safe because it's commit reveal, without it an offline
grind is possible (2^18 to grind vs 1 shot with a 2^-36 chance).

**Cost**: Shortening the SAS or removing commit-reveal makes offline MITM grind
possible again.

## 4. Constant-rate cover traffic

**Decision**: The daemon sends and fetches at a fixed rate. Real messages go in
the slots, dummy ones fill the gaps, and there is no manual fetch.

**Why**: Otherwise when and how much you send leaks how active you are, 
even when the content is encrypted. A fixed rate hides that from the 
server and the network. A manual fetch would make a visible pattern too.

**Cost**: Constant bandwidth even when idle, and real messages are capped
by the rate.

## 5. Two-factor DEK

**Decision**: The database key comes from two parts combined, 
one from your password and one from the server. Both are required.

**Why**: It splits two threats. Stealing the disk isn't enough 
without the server, and the server never has the password. 
You need both to read the local data.

**Cost**: No offline access, unlocking the storage needs a 
server session to get server_dek.

## 6. Sealing the server Master Key in the TPM

**Decision**: By default the server's master key is sealed in 
the TPM, not stored as a plain file.

**Why**: So stealing the server's disk doesn't give you the 
master key without that exact TPM.

**Cost**: Needs a TPM 2.0 and the `tpm` build feature. There is 
a plaintext fallback, but it gives up the guarantee.

## 7. Deterministic encryption of the user id

**Decision**: The encrypted user id is deterministic, so the 
same handle always maps to the same row.

**Why**: This way the server can look users up by handle without 
storing the plain handle or a separate mapping table.

**Cost**: You can see equality, across DB snapshots you can tell 
two rows are the same user. Never who, just if they exist or 
are the same.

## 8. Losing key material instead of recovery

**Decision**: No password or key recovery, no seed backup. 
Losing them means losing the data.

**Why**: Every recovery option (escrow, security questions, 
server-side codes) is something to attack and something to 
force out of you legally. That breaks the whole point, that 
the server can't reveal anything. Lithium picks loss over 
recovery on purpose.

**Cost**: A forgotten password or a lost device can't be 
recovered, so the weight goes on UX and warning the user.
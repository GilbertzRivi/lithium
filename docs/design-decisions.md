# Design decisions

Answers the "why" questions about the main architectural 
decisions, their reasons, and their cost. The priorities are in 
[security-model.md](security-model.md). These are the system-level 
decisions; the crypto-library ones (the classic + PQ hybrid, 
AES-256-GCM-SIV) are in the `lithium_core` 
[docs](../lithium_core/README.md).

## 1. OPAQUE

**Decision**: Authentication with OPAQUE (aPAKE, `opaque-ke 
4.0.1`, ristretto255 + Argon2 as KSF).

**Why**: The server (a hostile relay) must never see the password 
or its hash. Then there is nothing to steal and nothing to crack. 
People reuse passwords across sites; a server that never holds 
them can't leak them.

**Cost**: More complicated authentication and handshake. A 
dependency on the OPAQUE lib.

## 2. Anonymous mailboxes

**Decision**: The server never routes messages by identity.

**Why**: A hostile relay must not be able to build a social graph 
of who talks to whom. Both clients compute the mailbox address 
with ECDH and rotate it every few messages.

**Cost**: Complexity, no simple inbox.

## 3. Commit reveal + short SAS

**Decision**: Adding a contact is a one-sided commit-reveal, and 
identity verification is a 36-bit SAS.

**Why**: Commit-reveal makes a short SAS safe. Without it an 
offline grind is possible (2^18 to grind vs one shot at 2^-36).

**Cost**: Shortening the SAS or dropping commit-reveal makes the 
offline MITM grind possible again.

## 4. Constant-rate cover traffic

**Decision**: The daemon sends and fetches at a fixed rate. Real 
messages go in the slots, dummies fill the gaps, and there is no 
manual fetch.

**Why**: Otherwise when and how much you send leaks how active you 
are, even with encrypted content. A fixed rate hides that from the 
server and the network. A manual fetch would make a visible 
pattern too.

**Cost**: Constant bandwidth even when idle, and real messages are 
capped by the rate.

## 5. Two-factor DEK

**Decision**: The database key comes from two parts combined, one 
from your password and one from the server. Both are required.

**Why**: It splits two threats. Stealing the disk isn't enough 
without the server, and the server never has the password. You 
need both to read the local data.

**Cost**: No offline access, unlocking the storage needs a server 
session to get server_dek.

## 6. Sealing the server Master Key in the TPM

**Decision**: By default the server's master key is sealed in the 
TPM, not stored as a plain file.

**Why**: So stealing the server's disk doesn't give you the master 
key without that exact TPM.

**Cost**: Needs a TPM 2.0 and the `tpm` build feature. There is a 
plaintext fallback, but it gives up the guarantee.

## 7. Deterministic encryption of the user id

**Decision**: The encrypted user id is deterministic, so the same 
handle always maps to the same row.

**Why**: The server can then look users up by handle without 
storing the plain handle or a separate mapping table.

**Cost**: You can see equality, across DB snapshots you can tell 
two rows are the same user. Never who, just if they exist or are 
the same.

## 8. Losing key material instead of recovery

**Decision**: No password or key recovery, no seed backup. Losing 
them means losing the data.

**Why**: Every recovery option (escrow, security questions, 
server-side codes) is something to attack and something to force 
out of you legally. That breaks the whole point, that the server 
can't reveal anything. Lithium picks loss over recovery on 
purpose.

**Cost**: A forgotten password or a lost device can't be 
recovered, so the weight goes on UX and warning the user.

# Security policy

> **Status: pre-audit.** The implementation has not gone through an independent
> cryptographic audit and has no production releases. You use it at your own
> risk - not to protect actually sensitive communication before the audit.

## Reporting vulnerabilities

Send reports privately to **[oktawia.handerek@gmail.com](mailto:oktawia.handerek@gmail.com)**. Do not open a public
issue for vulnerabilities.

PGP for encrypted reports: *fingerprint to be added*. Until it is published, do
not include a sensitive PoC in the email body - ask for the key first.

Please use coordinated disclosure: give time for a fix before disclosing details
publicly (default up to 90 days from confirmation). Report acknowledgement - as
soon as possible; this is a small project, there is no 24/7 on-call rotation.

## Before you report

Lithium has conscious design trade-offs and behaviors that look like bugs, but
are intentional (the server is a hostile relay by design and sees the metadata
described in the model; some operations are intentionally painful or
irreversible). Before reporting, check `docs/security-model.md`:

* [What should be audited as a real problem](docs/security-model.md#what-should-be-audited-as-a-real-problem)
* [What not to report as a vulnerability without context](docs/security-model.md#what-not-to-report-as-a-vulnerability-without-context)
* [Classification of audit findings](docs/security-model.md#classification-of-audit-findings)

Full trust model and responsibility boundaries:
[`docs/security-model.md`](docs/security-model.md),
[`docs/threat-model.md`](docs/threat-model.md),
[`docs/kyberbox.md`](https://github.com/GilbertzRivi/lithium-core/blob/main/docs/kyberbox.md).

## Scope

In scope: `lithium_core` (crypto, KDF, secret types), `lithiumd` (IPC, E2E,
mailbox), `lithiums` (transport, rate limiting). Out of scope: properties that
the trust model consciously accepts as cost - server-side metadata visibility,
no delivery guarantee, no recovery for lost key material.

## Supported versions

Pre-audit project, no production releases. Only current `main` is supported.

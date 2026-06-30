# Contributing to Lithium

Thanks for your interest. A few things to know before you send a change.

## Licensing of contributions (important)

Lithium is released under **AGPL-3.0-only** and is also offered under a separate **commercial
license** (dual licensing). For dual licensing to remain possible, the project must hold sufficient
rights over every contribution.

By submitting a contribution (a pull request, patch, or any code/content), you agree that:

1. Your contribution is licensed to the project and its users under **AGPL-3.0-only**; and
2. You grant the Lithium Project a perpetual, worldwide, irrevocable, royalty-free right to also
   license your contribution under **other terms, including commercial/proprietary licenses**; and
3. You have the right to grant the above — the work is yours, or you are authorised to contribute it,
   and it is not encumbered by an employer or third party.

If you cannot agree to all three, please do not submit the contribution. For anything substantial,
the simplest path is to open an issue first so we can confirm fit before you spend time.

Add a `Signed-off-by:` line to your commits (`git commit -s`) to certify the above — this follows
the [Developer Certificate of Origin](https://developercertificate.org/).

## Code

- Every new source file starts with the two-line SPDX header used across the tree:
  ```
  // SPDX-FileCopyrightText: 2026 Lithium Project
  // SPDX-License-Identifier: AGPL-3.0-only
  ```
- Before opening a PR, make sure these pass:
  ```
  cargo fmt --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  ```
- Match the surrounding code. Comments explain *why*, not *what*.

## Security

Do not open public issues for vulnerabilities. See [`SECURITY.md`](SECURITY.md) for how to report
privately.

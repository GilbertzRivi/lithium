// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) const E2E_WIRE_MAGIC: &[u8; 3] = b"LM1";
pub(crate) const E2E_WIRE_VER: u8 = 1;
pub(crate) const E2E_LABEL: &str = "lithiumd/e2e-msg/v1";
pub(crate) const E2E_SIG_LABEL: &[u8] = b"lithiumd/e2e-msg-sig/v1";
pub(crate) const KID_LABEL: &[u8] = b"lithiumd/e2e-peer-kid/v1";

pub(crate) const LABEL_MAILBOX: &[u8] = b"lithium/mbox/address/v1";
pub(crate) const LABEL_MAILBOX_COVER: &[u8] = b"lithium/mbox/cover/v1";

pub(crate) const PARTY_TRANSCRIPT_LABEL: &[u8] = b"lithiumd/party-transcript/v1";
pub(crate) const VERIFY_EMOJI_LABEL: &[u8] = b"lithiumd/contact-verify-emoji/v1";

pub(crate) const AAD_CONTACT_SELF: &[u8] = b"lithiumd/contact-self/v1";
pub(crate) const AAD_CONTACT_PEER: &[u8] = b"lithiumd/contact-peer/v1";
pub(crate) const AAD_MESSAGE: &[u8] = b"lithiumd/message/v1";
pub(crate) const AAD_PREKEY: &[u8] = b"lithiumd/prekey/v1";

pub(crate) const INV_MAGIC: &[u8; 4] = b"LCI1";
pub(crate) const INV_VER: u8 = 1;

pub(crate) const PAIR_COMMIT_LABEL: &[u8] = b"lithiumd/pair-commit/v1";

pub(crate) const MKFILE_MAGIC: &[u8; 4] = b"LMK1";
pub(crate) const MKFILE_AAD: &[u8] = b"lithium/mkfile/v1";
pub(crate) const MKFILE_SALT_LEN: usize = 32;
pub(crate) const USER_COMBINED_LABEL: &[u8] = b"lithium/user-provider/combined/v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_values_are_pinned() {
        assert_eq!(E2E_WIRE_MAGIC, b"LM1");
        assert_eq!(E2E_WIRE_VER, 1);
        assert_eq!(E2E_LABEL, "lithiumd/e2e-msg/v1");
        assert_eq!(E2E_SIG_LABEL, b"lithiumd/e2e-msg-sig/v1");
        assert_eq!(KID_LABEL, b"lithiumd/e2e-peer-kid/v1");

        assert_eq!(LABEL_MAILBOX, b"lithium/mbox/address/v1");
        assert_eq!(LABEL_MAILBOX_COVER, b"lithium/mbox/cover/v1");

        assert_eq!(PARTY_TRANSCRIPT_LABEL, b"lithiumd/party-transcript/v1");
        assert_eq!(VERIFY_EMOJI_LABEL, b"lithiumd/contact-verify-emoji/v1");

        assert_eq!(AAD_CONTACT_SELF, b"lithiumd/contact-self/v1");
        assert_eq!(AAD_CONTACT_PEER, b"lithiumd/contact-peer/v1");
        assert_eq!(AAD_MESSAGE, b"lithiumd/message/v1");
        assert_eq!(AAD_PREKEY, b"lithiumd/prekey/v1");

        assert_eq!(INV_MAGIC, b"LCI1");
        assert_eq!(INV_VER, 1);

        assert_eq!(PAIR_COMMIT_LABEL, b"lithiumd/pair-commit/v1");

        assert_eq!(MKFILE_MAGIC, b"LMK1");
        assert_eq!(MKFILE_AAD, b"lithium/mkfile/v1");
        assert_eq!(MKFILE_SALT_LEN, 32);
        assert_eq!(USER_COMBINED_LABEL, b"lithium/user-provider/combined/v1");
    }
}

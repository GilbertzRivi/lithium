pub(crate) const UIDENC_VER: u8 = 1;
pub(crate) const MSG_VER: u8 = 1;

pub(crate) const AAD_UIDENC: &[u8] = b"user-idenc/v1";
pub(crate) const UIDENC_NONCE_LABEL: &[u8] = b"user-idenc/nonce/v1";

pub(crate) const AAD_MSG: &[u8] = b"message-content/v1";

pub(crate) const AAD_USER_PASSWORD_HASH: &[u8] = b"user-password-hash/v1";
pub(crate) const AAD_USER_ED_KEY: &[u8] = b"user-ed-key/v1";
pub(crate) const AAD_USER_DILI_KEY: &[u8] = b"user-dili-key/v1";
pub(crate) const AAD_USER_DEK: &[u8] = b"user-dek/v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_values_are_pinned() {
        assert_eq!(UIDENC_VER, 1);
        assert_eq!(MSG_VER, 1);
        assert_eq!(AAD_UIDENC, b"user-idenc/v1");
        assert_eq!(UIDENC_NONCE_LABEL, b"user-idenc/nonce/v1");
        assert_eq!(AAD_MSG, b"message-content/v1");
        assert_eq!(AAD_USER_PASSWORD_HASH, b"user-password-hash/v1");
        assert_eq!(AAD_USER_ED_KEY, b"user-ed-key/v1");
        assert_eq!(AAD_USER_DILI_KEY, b"user-dili-key/v1");
        assert_eq!(AAD_USER_DEK, b"user-dek/v1");
    }
}

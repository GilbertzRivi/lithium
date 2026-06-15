pub(crate) const AEAD_VERSION: u8 = 1;
pub(crate) const KYBER_BOX_VERSION: u8 = 1;
pub(crate) const KYBER_KEM_ID: u8 = 1;
pub(crate) const KYBER_AEAD_ID: u8 = 1;
pub(crate) const KYBER_SALT_LEN: u8 = 32;
pub(crate) const KYBERBOX_AAD_PREFIX: &[u8] = b"kyberbox/v1|kem=mlkem1024|aead=aes256-gcm-siv|";
pub(crate) const KYBER_KEMDEM_INFO: &[u8] = b"kemdem/kyber-mlkem1024/v1";

pub(crate) const AEAD_BLOB_VERSION: u8 = 1;

pub(crate) const KEYFILE_MAGIC: &[u8; 4] = b"KEYF";
pub(crate) const KEYFILE_VERSION: u8 = 1;
pub(crate) const ALG_ID_AES256_GCM_SIV: u8 = 1;
pub(crate) const DEK_LEN: u16 = 32;
pub(crate) const KEYFILE_KEK_INFO: &[u8] = b"kek/v1";

pub(crate) const JWT_LABEL: &[u8] = b"lithium/jwt-secret/v1";

pub(crate) const DB_DEK_LABEL: &[u8] = b"lithium/db-dek/v1";
pub(crate) const USERS_UUID_NAMESPACE_LABEL: &[u8] = b"lithium/users-uuid-namespace/v1";

pub(crate) const DEK_WRAP_VER: u8 = 1;
pub(crate) const DEK_WRAP_AAD: &[u8] = b"lithium/dek-wrap/v1";
pub(crate) const DEK_WRAP_SALT_LEN: usize = 32;

pub(crate) const ARGON2_M_COST: u32 = 64 * 1024;
pub(crate) const ARGON2_T_COST: u32 = 3;
pub(crate) const ARGON2_P_COST: u32 = 1;
pub(crate) const ARGON2_OUT_LEN: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_values_are_pinned() {
        assert_eq!(AEAD_VERSION, 1);
        assert_eq!(KYBER_BOX_VERSION, 1);
        assert_eq!(KYBER_KEM_ID, 1);
        assert_eq!(KYBER_AEAD_ID, 1);
        assert_eq!(KYBER_SALT_LEN, 32);
        assert_eq!(KYBERBOX_AAD_PREFIX, b"kyberbox/v1|kem=mlkem1024|aead=aes256-gcm-siv|");
        assert_eq!(KYBER_KEMDEM_INFO, b"kemdem/kyber-mlkem1024/v1");

        assert_eq!(AEAD_BLOB_VERSION, 1);

        assert_eq!(KEYFILE_MAGIC, b"KEYF");
        assert_eq!(KEYFILE_VERSION, 1);
        assert_eq!(ALG_ID_AES256_GCM_SIV, 1);
        assert_eq!(DEK_LEN, 32);
        assert_eq!(KEYFILE_KEK_INFO, b"kek/v1");

        assert_eq!(JWT_LABEL, b"lithium/jwt-secret/v1");

        assert_eq!(DB_DEK_LABEL, b"lithium/db-dek/v1");
        assert_eq!(USERS_UUID_NAMESPACE_LABEL, b"lithium/users-uuid-namespace/v1");

        assert_eq!(DEK_WRAP_VER, 1);
        assert_eq!(DEK_WRAP_AAD, b"lithium/dek-wrap/v1");
        assert_eq!(DEK_WRAP_SALT_LEN, 32);

        assert_eq!(ARGON2_M_COST, 64 * 1024);
        assert_eq!(ARGON2_T_COST, 3);
        assert_eq!(ARGON2_P_COST, 1);
        assert_eq!(ARGON2_OUT_LEN, 32);
    }
}

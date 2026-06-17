use std::sync::Arc;

use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    crypto::{aead, keys},
    error::Result,
    keys::{KeyManager, MkProvider},
    labels::{DB_DEK_LABEL, USERS_UUID_NAMESPACE_LABEL},
    secrets::Byte32,
    secrets::bytes::SecretBytes,
};

pub struct DataManager<P: MkProvider> {
    db: DatabaseConnection,
    key_manager: Arc<Mutex<KeyManager<P>>>,
}

impl<P: MkProvider + Send + Sync + 'static> DataManager<P> {
    pub fn new(db: DatabaseConnection, key_manager: Arc<Mutex<KeyManager<P>>>) -> Self {
        Self { db, key_manager }
    }

    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    pub async fn load_db_dek(&self) -> Result<Byte32> {
        self.key_manager.lock().await.derive_secret32(DB_DEK_LABEL)
    }

    pub async fn users_uuid_namespace(&self) -> Result<Uuid> {
        let d = self
            .key_manager
            .lock()
            .await
            .derive_secret32(USERS_UUID_NAMESPACE_LABEL)?;
        let mut b = [0u8; 16];
        b.copy_from_slice(&d.as_slice()[..16]);
        b[6] = (b[6] & 0x0f) | 0x50;
        b[8] = (b[8] & 0x3f) | 0x80;
        Ok(Uuid::from_bytes(b))
    }

    pub async fn encrypt_db_blob(
        &self,
        plaintext: &SecretBytes,
        aad: &SecretBytes,
    ) -> Result<SecretBytes> {
        let dek = self.load_db_dek().await?;
        let nonce = keys::random_12()?;
        aead::encrypt(plaintext, &dek, &nonce, aad)
    }

    pub async fn decrypt_db_blob(
        &self,
        blob: &SecretBytes,
        aad: &SecretBytes,
    ) -> Result<SecretBytes> {
        let dek = self.load_db_dek().await?;
        aead::decrypt(blob, &dek, aad)
    }

    pub fn decrypt_db_blob_with(
        &self,
        dek: &Byte32,
        blob: &SecretBytes,
        aad: &SecretBytes,
    ) -> Result<SecretBytes> {
        aead::decrypt(blob, dek, aad)
    }

    /// Gracefully close the underlying database connection, releasing any file locks.
    pub async fn close_by_ref(&self) {
        let _ = self.db.close_by_ref().await;
    }
}

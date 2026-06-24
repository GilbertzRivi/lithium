use std::sync::Arc;

use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;
use uuid::Uuid;

use lithium_core::crypto::aead;
use lithium_core::error::Result;
use lithium_core::keys::{KeyManager, MkProvider};
use lithium_core::secrets::Byte32;
use lithium_core::secrets::bytes::SecretBytes;

const DB_DEK_LABEL: &[u8] = b"lithium/db-dek/v1";
const USERS_UUID_NAMESPACE_LABEL: &[u8] = b"lithium/users-uuid-namespace/v1";

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
        self.key_manager
            .lock()
            .await
            .encrypt_with_derived(DB_DEK_LABEL, plaintext, aad)
    }

    pub async fn decrypt_db_blob(
        &self,
        blob: &SecretBytes,
        aad: &SecretBytes,
    ) -> Result<SecretBytes> {
        self.key_manager
            .lock()
            .await
            .decrypt_with_derived(DB_DEK_LABEL, blob, aad)
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

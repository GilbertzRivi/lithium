use std::time::Duration;

use chrono::Utc;
use sea_orm::sea_query::{LockBehavior, LockType};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set,
    TransactionTrait,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use lithium_core::{
    crypto::{aead, kdf, keys},
    db::manager::DataManager,
    error::{LithiumError, Result},
    keys::MkProvider,
    passwords::passwords::hash_password_phc,
    secrets::{Byte12, Byte32, SecretString},
    utils::store::EphemeralStoreManager,
};
use lithium_core::secrets::bytes::SecretBytes;

use crate::db::models::{messages, users};
use crate::error::{AppError, AppResult};
use crate::labels::{
    AAD_MSG, AAD_UIDENC, AAD_USER_DEK, AAD_USER_DILI_KEY, AAD_USER_ED_KEY, AAD_USER_PASSWORD_HASH,
    MSG_VER, UIDENC_NONCE_LABEL, UIDENC_VER,
};

const MSG_KEY_TTL: Duration = Duration::from_secs(24 * 3600);

#[derive(Clone, Debug)]
pub struct UserRecord {
    pub id: Vec<u8>,
    pub password_hash: SecretString,
    pub ed_key: Byte32,
    pub dili_key: SecretBytes,
    pub dek: SecretString,
}

async fn uuid5_from_handler<P: MkProvider + Send + Sync + 'static>(
    dm: &DataManager<P>,
    handler: &str,
) -> Result<Uuid> {
    let ns = dm.users_uuid_namespace().await?;
    Ok(Uuid::new_v5(&ns, handler.trim().to_lowercase().as_bytes()))
}

// NOTE:
// User IDs are encrypted deterministically on purpose so we can perform
// stable lookups by derived UUID without storing plaintext identifiers.
// This leaks equality of the encrypted user ID across rows / snapshots:
// the same logical user always maps to the same ciphertext under the same DEK.
// We accept this trade-off for indexed lookup semantics.
async fn id_enc_from_uuid<P: MkProvider + Send + Sync + 'static>(
    dm: &DataManager<P>,
    id: &Uuid,
) -> Result<SecretBytes> {
    let dek: Byte32 = dm.load_db_dek().await?;

    let n32 = kdf::derive32(
        &SecretBytes::from_slice(id.as_bytes()),
        Some(&SecretBytes::from_slice(dek.as_slice())),
        &SecretBytes::from_slice(UIDENC_NONCE_LABEL),
    )?;
    let nonce = Byte12::from_slice(&n32.as_slice()[..12])?;

    let ct = aead::encrypt_raw(
        &SecretBytes::from_slice(id.as_bytes()),
        &dek,
        &nonce,
        &SecretBytes::from_slice(AAD_UIDENC),
    )?;

    let mut out = Vec::with_capacity(1 + 12 + ct.expose_as_slice().len());
    out.push(UIDENC_VER);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(ct.expose_as_slice());
    Ok(SecretBytes::new(out))
}

fn seal_msg(plaintext: &SecretBytes, key: &Byte32, aad: &SecretBytes) -> Result<SecretBytes> {
    let nonce: Byte12 = keys::random_12()?;
    let ct = aead::encrypt_raw(plaintext, key, &nonce, aad)?;

    let mut out = Vec::with_capacity(1 + 12 + ct.expose_as_slice().len());
    out.push(MSG_VER);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(ct.expose_as_slice());
    Ok(SecretBytes::new(out))
}

fn open_msg(blob: &[u8], key: &Byte32, aad: &[u8]) -> Result<SecretBytes> {
    if blob.len() < 1 + 12 + 16 {
        return Err(LithiumError::aead_failed());
    }
    if blob[0] != MSG_VER {
        return Err(LithiumError::aead_failed());
    }

    let nonce = Byte12::from_slice(&blob[1..13])?;
    let ct = &blob[13..];

    aead::decrypt_raw(
        &SecretBytes::from_slice(ct),
        key,
        &nonce,
        &SecretBytes::from_slice(aad),
    )
}

async fn decrypt_user_row<P: MkProvider + Send + Sync + 'static>(
    dm: &DataManager<P>,
    row: users::Model,
) -> AppResult<UserRecord> {
    let password_hash_plain = dm
        .decrypt_db_blob(
            &SecretBytes::from_slice(row.password_hash.as_slice()),
            &SecretBytes::from_slice(AAD_USER_PASSWORD_HASH),
        )
        .await?;

    let ed_key_plain = dm
        .decrypt_db_blob(
            &SecretBytes::from_slice(row.ed_key.as_slice()),
            &SecretBytes::from_slice(AAD_USER_ED_KEY),
        )
        .await?;

    let dili_key_plain = dm
        .decrypt_db_blob(
            &SecretBytes::from_slice(row.dili_key.as_slice()),
            &SecretBytes::from_slice(AAD_USER_DILI_KEY),
        )
        .await?;

    let dek_plain = dm
        .decrypt_db_blob(
            &SecretBytes::from_slice(row.dek.as_slice()),
            &SecretBytes::from_slice(AAD_USER_DEK),
        )
        .await?;

    Ok(UserRecord {
        id: row.id,
        password_hash: SecretString::from_utf8_bytes(password_hash_plain.expose_as_slice())
            .map_err(AppError::from)?,
        ed_key: Byte32::from_slice(ed_key_plain.expose_as_slice()).map_err(AppError::from)?,
        dili_key: dili_key_plain,
        dek: SecretString::from_utf8_bytes(dek_plain.expose_as_slice()).map_err(AppError::from)?,
    })
}

#[allow(async_fn_in_trait)]
pub trait ServerDbExt<P: MkProvider + Send + Sync + 'static> {
    async fn create_user(
        &self,
        handler: &str,
        password: &str,
        ed_key: &[u8],
        dili_key: &[u8],
        dek: &[u8],
    ) -> AppResult<Option<SecretString>>;

    async fn get_user(&self, handler: &str) -> AppResult<Option<UserRecord>>;
    async fn get_user_by_id(&self, id: &[u8]) -> AppResult<Option<UserRecord>>;

    async fn delete_user_by_remote_delete_capability(
        &self,
        remote_delete_capability_hex: &str,
    ) -> AppResult<bool>;

    async fn delete_user_by_id(&self, id: &[u8]) -> AppResult<bool>;

    async fn add_message(
        &self,
        store: &EphemeralStoreManager,
        mailbox: Vec<u8>,
        content: SecretBytes,
        ttl: Duration,
    ) -> AppResult<()>;

    async fn get_messages(
        &self,
        store: &EphemeralStoreManager,
        mailbox: Vec<u8>,
    ) -> AppResult<Vec<SecretString>>;

    async fn delete_expired_messages(&self) -> AppResult<u64>;
}

impl<P: MkProvider + Send + Sync + 'static> ServerDbExt<P> for DataManager<P> {
    async fn create_user(
        &self,
        handler: &str,
        password: &str,
        ed_key: &[u8],
        dili_key: &[u8],
        dek: &[u8],
    ) -> AppResult<Option<SecretString>> {
        let uid = uuid5_from_handler(self, handler).await?;
        let id_enc = id_enc_from_uuid(self, &uid).await?;

        if users::Entity::find_by_id(id_enc.expose_as_slice().to_vec())
            .one(self.db())
            .await
            .map_err(LithiumError::io)?
            .is_some()
        {
            return Ok(None);
        }

        let pw = SecretString::new(password.to_owned());
        let password_hash = hash_password_phc(&pw)?;

        let password_hash_enc = self
            .encrypt_db_blob(
                &SecretBytes::from_slice(password_hash.as_bytes()),
                &SecretBytes::from_slice(AAD_USER_PASSWORD_HASH),
            )
            .await?;

        let ed_key_enc = self
            .encrypt_db_blob(
                &SecretBytes::from_slice(ed_key),
                &SecretBytes::from_slice(AAD_USER_ED_KEY),
            )
            .await?;

        let dili_key_enc = self
            .encrypt_db_blob(
                &SecretBytes::from_slice(dili_key),
                &SecretBytes::from_slice(AAD_USER_DILI_KEY),
            )
            .await?;

        let dek_enc = self
            .encrypt_db_blob(
                &SecretBytes::from_slice(dek),
                &SecretBytes::from_slice(AAD_USER_DEK),
            )
            .await?;

        let remote_delete_capability_raw: Byte32 = keys::random_32()?;
        let remote_delete_capability = remote_delete_capability_raw.to_hex();
        let delete_token_hash =
            Sha256::digest(remote_delete_capability_raw.as_slice()).to_vec();

        let am = users::ActiveModel {
            id: Set(id_enc.expose_as_slice().to_vec()),
            password_hash: Set(password_hash_enc.expose_as_slice().to_vec()),
            ed_key: Set(ed_key_enc.expose_as_slice().to_vec()),
            dili_key: Set(dili_key_enc.expose_as_slice().to_vec()),
            dek: Set(dek_enc.expose_as_slice().to_vec()),
            delete_token_hash: Set(delete_token_hash),
        };

        match am.insert(self.db()).await {
            Ok(_) => Ok(Some(remote_delete_capability)),
            Err(e) => {
                let s = e.to_string();
                if s.contains("duplicate key") || s.contains("unique") {
                    Ok(None)
                } else {
                    Err(AppError::from(LithiumError::io(e)))
                }
            }
        }
    }

    async fn get_user(&self, handler: &str) -> AppResult<Option<UserRecord>> {
        let uid = uuid5_from_handler(self, handler).await?;
        let id_enc = id_enc_from_uuid(self, &uid).await?;

        let Some(row) = users::Entity::find_by_id(id_enc.expose_as_slice().to_vec())
            .one(self.db())
            .await
            .map_err(LithiumError::io)?
        else {
            return Ok(None);
        };

        Ok(Some(decrypt_user_row(self, row).await?))
    }

    async fn get_user_by_id(&self, id: &[u8]) -> AppResult<Option<UserRecord>> {
        let Some(row) = users::Entity::find_by_id(id.to_vec())
            .one(self.db())
            .await
            .map_err(LithiumError::io)?
        else {
            return Ok(None);
        };

        Ok(Some(decrypt_user_row(self, row).await?))
    }

    async fn delete_user_by_remote_delete_capability(
        &self,
        remote_delete_capability_hex: &str,
    ) -> AppResult<bool> {
        let capability = match SecretBytes::from_hex(remote_delete_capability_hex) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };

        if capability.len() != 32 {
            return Ok(false);
        }

        let delete_token_hash = Sha256::digest(capability.expose_as_slice()).to_vec();

        let Some(row) = users::Entity::find()
            .filter(users::Column::DeleteTokenHash.eq(delete_token_hash))
            .one(self.db())
            .await
            .map_err(LithiumError::io)?
        else {
            return Ok(false);
        };

        users::Entity::delete_by_id(row.id)
            .exec(self.db())
            .await
            .map_err(LithiumError::io)?;

        Ok(true)
    }

    async fn delete_user_by_id(&self, id: &[u8]) -> AppResult<bool> {
        let res = users::Entity::delete_by_id(id.to_vec())
            .exec(self.db())
            .await
            .map_err(LithiumError::io)?;

        Ok(res.rows_affected > 0)
    }

    async fn add_message(
        &self,
        store: &EphemeralStoreManager,
        mailbox: Vec<u8>,
        content: SecretBytes,
        ttl: Duration,
    ) -> AppResult<()> {
        let expires_at =
            Utc::now() + chrono::TimeDelta::from_std(ttl).map_err(|_| LithiumError::internal())?;

        let msg_key: Byte32 = keys::random_32()?;
        let id = keys::random_32()?.as_slice().to_vec();

        let mut aad = Vec::with_capacity(AAD_MSG.len() + mailbox.len());
        aad.extend_from_slice(AAD_MSG);
        aad.extend_from_slice(&mailbox);

        let blob = seal_msg(&content, &msg_key, &SecretBytes::new(aad))?;
        drop(content);

        let am = messages::ActiveModel {
            id: Set(id.clone()),
            mailbox: Set(mailbox),
            content: Set(blob.expose_as_slice().to_vec()),
            expires_at: Set(expires_at),
        };

        am.insert(self.db()).await.map_err(LithiumError::io)?;

        if let Err(e) = store
            .set(
                &hex::encode(&id),
                &SecretBytes::from_slice(msg_key.as_slice()),
                MSG_KEY_TTL,
            )
            .await
        {
            let _ = messages::Entity::delete_by_id(id).exec(self.db()).await;
            return Err(AppError::from(e));
        }

        Ok(())
    }

    async fn get_messages(
        &self,
        store: &EphemeralStoreManager,
        mailbox: Vec<u8>,
    ) -> AppResult<Vec<SecretString>> {
        let now = Utc::now();

        let rows: Vec<(Vec<u8>, Vec<u8>)> = self
            .db()
            .transaction(|txn| {
                let mailbox = mailbox.clone();
                Box::pin(async move {
                    let mut q = messages::Entity::find()
                        .filter(messages::Column::Mailbox.eq(mailbox))
                        .filter(messages::Column::ExpiresAt.gt(now))
                        .order_by_asc(messages::Column::ExpiresAt);

                    q = q.lock_with_behavior(LockType::Update, LockBehavior::SkipLocked);

                    let ms = q.all(txn).await?;

                    for m in &ms {
                        messages::Entity::delete_by_id(m.id.clone()).exec(txn).await?;
                    }

                    Ok::<_, sea_orm::DbErr>(ms.into_iter().map(|m| (m.id, m.content)).collect())
                })
            })
            .await
            .map_err(LithiumError::io)?;

        if rows.is_empty() {
            return Ok(vec![]);
        }

        let mut aad = Vec::with_capacity(AAD_MSG.len() + mailbox.len());
        aad.extend_from_slice(AAD_MSG);
        aad.extend_from_slice(&mailbox);

        let mut out: Vec<SecretString> = Vec::with_capacity(rows.len());

        for (id, blob) in rows {
            let Some(kbox) = store.take(&hex::encode(&id)).await? else {
                continue;
            };

            let kb = kbox.expose_as_slice();
            if kb.len() != 32 {
                continue;
            }
            let key = Byte32::from_slice(kb).map_err(|_| LithiumError::aead_failed())?;

            if let Ok(pt) = open_msg(&blob, &key, &aad) {
                out.push(pt.to_hex());
            }
        }

        Ok(out)
    }

    async fn delete_expired_messages(&self) -> AppResult<u64> {
        let now = Utc::now();
        let res = messages::Entity::delete_many()
            .filter(messages::Column::ExpiresAt.lte(now))
            .exec(self.db())
            .await
            .map_err(LithiumError::io)?;
        Ok(res.rows_affected)
    }
}
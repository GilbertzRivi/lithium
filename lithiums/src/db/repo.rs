use std::time::Duration;
use chrono::Utc;
use sea_orm::sea_query::{LockBehavior, LockType};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    Set, TransactionTrait,
};

use uuid::Uuid;

use lithium_core::{
    crypto::{aead, kdf, keys},
    db::manager::DataManager,
    error::{LithiumError, Result},
    keys::MkProvider,
    passwords::passwords::{hash_password_phc, verify_password_phc},
    secrets::{Byte12, Byte32},
    utils::store::EphemeralStoreManager,
};
use lithium_core::secrets::bytes::SecretBytes;
use lithium_core::secrets::SecretString;

use crate::db::models::{messages, users};
use crate::error::{AppError, AppResult};

const UIDENC_VER: u8 = 1;
const MSG_VER: u8 = 1;

const AAD_UIDENC: &[u8] = b"user-idenc/v1";
const UIDENC_NONCE_LABEL: &[u8] = b"user-idenc/nonce/v1";

const AAD_MSG: &[u8] = b"message-content/v1";

const AAD_USER_HANDLER: &[u8] = b"user-handler/v1";
const AAD_USER_DEK: &[u8] = b"user-dek/v1";
const MSG_KEY_TTL: Duration = Duration::from_secs(24 * 3600);

#[inline]
fn normalize_handler(handler: &str) -> String {
    handler.trim().to_lowercase()
}

async fn uuid5_from_handler<P: MkProvider + Send + Sync + 'static>(
    dm: &DataManager<P>,
    handler: &str,
) -> Result<Uuid> {
    let ns = dm.users_uuid_namespace().await?;
    let name = normalize_handler(handler);
    Ok(Uuid::new_v5(&ns, name.as_bytes()))
}

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
    let mut nb = [0u8; 12];
    nb.copy_from_slice(&n32.as_slice()[..12]);
    let nonce = Byte12::new(nb);

    let ct = aead::encrypt_raw(
        &SecretBytes::from_slice(id.as_bytes()),
        &dek,
        &nonce,
        &SecretBytes::from_slice(AAD_UIDENC),
    )?;

    let mut out = Vec::with_capacity(1 + 12 + ct.as_slice().len());
    out.push(UIDENC_VER);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct.as_slice());
    Ok(SecretBytes::from_vec(out))
}

fn seal_msg(plaintext: &SecretBytes, key: &Byte32, aad: &SecretBytes) -> Result<SecretBytes> {
    let nonce: Byte12 = keys::random_12()?;
    let ct = aead::encrypt_raw(plaintext, key, &nonce, aad)?;

    let mut out = Vec::with_capacity(1 + 12 + ct.as_slice().len());
    out.push(MSG_VER);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct.as_slice());
    Ok(SecretBytes::from_vec(out))
}

fn open_msg(blob: &[u8], key: &Byte32, aad: &[u8]) -> Result<SecretBytes> {
    if blob.len() < 1 + 12 + 16 {
        return Err(LithiumError::aead_failed());
    }
    if blob[0] != MSG_VER {
        return Err(LithiumError::aead_failed());
    }
    let mut nb = [0u8; 12];
    nb.copy_from_slice(&blob[1..13]);
    let nonce = Byte12::new(nb);
    let ct = &blob[13..];
    aead::decrypt_raw(
        &SecretBytes::from_slice(ct),
        key,
        &nonce,
        &SecretBytes::from_slice(aad),
    )
}

#[allow(async_fn_in_trait)]
pub trait ServerDbExt<P: MkProvider + Send + Sync + 'static> {
    // users
    async fn create_user(
        &self,
        handler: &str,
        password: &str,
        ed_key: &[u8],
        dili_key: &[u8],
        dek: &[u8],
    ) -> AppResult<bool>;

    async fn try_login(&self, handler: &str, password: &str) -> AppResult<Option<users::Model>>;
    async fn get_user(&self, handler: &str) -> AppResult<Option<users::Model>>;
    async fn get_user_by_id(&self, id: &[u8]) -> AppResult<Option<users::Model>>;
    async fn get_dek_for_user(&self, user: &users::Model) -> AppResult<SecretString>;

    // messages (mailbox-based)
    async fn add_message(
        &self,
        store: &EphemeralStoreManager,
        mailbox: Vec<u8>,
        content: SecretBytes,
        ttl: Duration,
    ) -> AppResult<i64>;

    async fn get_messages(
        &self,
        store: &EphemeralStoreManager,
        mailbox: Vec<u8>,
    ) -> AppResult<Vec<SecretString>>;
}

impl<P: MkProvider + Send + Sync + 'static> ServerDbExt<P> for DataManager<P> {
    async fn create_user(
        &self,
        handler: &str,
        password: &str,
        ed_key: &[u8],
        dili_key: &[u8],
        dek: &[u8],
    ) -> AppResult<bool> {
        let uid = uuid5_from_handler(self, handler).await?;
        let id_enc = id_enc_from_uuid(self, &uid).await?;

        if users::Entity::find_by_id(id_enc.as_slice().to_vec())
            .one(self.db())
            .await
            .map_err(LithiumError::io)?
            .is_some()
        {
            return Ok(false);
        }

        let pw = SecretString::new(password.to_owned());
        let password_hash = hash_password_phc(&pw)?;

        let norm = normalize_handler(handler);
        let handler_phc = hash_password_phc(&SecretString::new(norm))?;
        let handler_enc = self
            .encrypt_db_blob(
                &SecretBytes::from_slice(handler_phc.as_bytes()),
                &SecretBytes::from_slice(AAD_USER_HANDLER),
            )
            .await?;

        let dek_enc = self
            .encrypt_db_blob(
                &SecretBytes::from_slice(dek),
                &SecretBytes::from_slice(AAD_USER_DEK),
            )
            .await?;

        let am = users::ActiveModel {
            id: Set(id_enc.as_slice().to_vec()),
            password_hash: Set(password_hash),
            handler: Set(handler_enc.as_slice().to_vec()),
            ed_key: Set(ed_key.to_vec()),
            dili_key: Set(dili_key.to_vec()),
            dek: Set(dek_enc.as_slice().to_vec()),
        };

        match am.insert(self.db()).await {
            Ok(_) => Ok(true),
            Err(e) => {
                let s = e.to_string();
                if s.contains("duplicate key") || s.contains("unique") {
                    Ok(false)
                } else {
                    Err(AppError::from(LithiumError::io(e)))
                }
            }
        }
    }

    async fn try_login(&self, handler: &str, password: &str) -> AppResult<Option<users::Model>> {
        let uid = uuid5_from_handler(self, handler).await?;
        let id_enc = id_enc_from_uuid(self, &uid).await?;

        let Some(row) = users::Entity::find_by_id(id_enc.as_slice().to_vec())
            .one(self.db())
            .await
            .map_err(LithiumError::io)?
        else {
            return Ok(None);
        };

        let pw = SecretString::new(password.to_owned());
        let ok = verify_password_phc(&row.password_hash, &pw)?;

        Ok(if ok { Some(row) } else { None })
    }

    async fn get_user(&self, handler: &str) -> AppResult<Option<users::Model>> {
        let uid = uuid5_from_handler(self, handler).await?;
        let id_enc = id_enc_from_uuid(self, &uid).await?;

        let Some(row) = users::Entity::find_by_id(id_enc.as_slice().to_vec())
            .one(self.db())
            .await
            .map_err(LithiumError::io)?
        else {
            return Ok(None);
        };
        Ok(Some(row))
    }

    async fn get_user_by_id(&self, id: &[u8]) -> AppResult<Option<users::Model>> {
        let Some(row) = users::Entity::find_by_id(id.to_vec())
            .one(self.db())
            .await
            .map_err(LithiumError::io)?
        else {
            return Ok(None);
        };
        Ok(Some(row))
    }

    async fn get_dek_for_user(&self, user: &users::Model) -> AppResult<SecretString> {
        let dek_plain = self
            .decrypt_db_blob(
                &SecretBytes::from_slice(user.dek.as_slice()),
                &SecretBytes::from_slice(AAD_USER_DEK),
            )
            .await?;

        let dek_str = std::str::from_utf8(dek_plain.as_slice())
            .map_err(|_| AppError::internal("invalid_stored_dek"))?;

        Ok(SecretString::new(dek_str.to_owned()))
    }

    async fn add_message(
        &self,
        store: &EphemeralStoreManager,
        mailbox: Vec<u8>,
        content: SecretBytes,
        ttl: Duration,
    ) -> AppResult<i64> {
        let expires_at =
            Utc::now() + chrono::TimeDelta::from_std(ttl).map_err(|_| LithiumError::internal())?;

        let msg_key: Byte32 = keys::random_32()?;

        let mut aad = Vec::with_capacity(AAD_MSG.len() + mailbox.len());
        aad.extend_from_slice(AAD_MSG);
        aad.extend_from_slice(&mailbox);

        let blob = seal_msg(&content, &msg_key, &SecretBytes::from_vec(aad))?;
        drop(content);

        let am = messages::ActiveModel {
            id: Default::default(),
            mailbox: Set(mailbox),
            content: Set(blob.as_slice().to_vec()),
            expires_at: Set(expires_at),
        };

        let inserted = am.insert(self.db()).await.map_err(LithiumError::io)?;
        let id = inserted.id;

        if let Err(e) = store
            .set(
                &id.to_string(),
                &SecretBytes::from_slice(msg_key.as_slice()),
                MSG_KEY_TTL,
            )
            .await
        {
            let _ = messages::Entity::delete_by_id(id).exec(self.db()).await;
            return Err(AppError::from(e));
        }

        Ok(id)
    }

    async fn get_messages(
        &self,
        store: &EphemeralStoreManager,
        mailbox: Vec<u8>,
    ) -> AppResult<Vec<SecretString>> {
        let now = Utc::now();

        let rows: Vec<(i64, Vec<u8>)> = self
            .db()
            .transaction(|txn| {
                let mailbox = mailbox.clone();
                Box::pin(async move {
                    let mut q = messages::Entity::find()
                        .filter(messages::Column::Mailbox.eq(mailbox))
                        .filter(messages::Column::ExpiresAt.gt(now))
                        .order_by_asc(messages::Column::Id);

                    q = q.lock_with_behavior(LockType::Update, LockBehavior::SkipLocked);

                    let ms = q.all(txn).await?;

                    for m in &ms {
                        messages::Entity::delete_by_id(m.id).exec(txn).await?;
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
            let key_str = SecretString::new(id.to_string());
            let Some(kbox) = store.take(key_str.expose()).await? else { continue; };

            let kb = kbox.as_slice();
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
}

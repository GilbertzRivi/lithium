use chrono::Utc;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set,
    TransactionTrait,
};

use lithium_core::{
    db::manager::DataManager,
    error::{LithiumError, Result},
    keys::MkProvider,
    secrets::bytes::SecretBytes,
};

use super::models::{contacts, messages, prekeys};

const AAD_CONTACT_SELF: &[u8] = b"lithiumd/contact-self/v1";
const AAD_CONTACT_PEER: &[u8] = b"lithiumd/contact-peer/v1";
const AAD_MESSAGE: &[u8] = b"lithiumd/message/v1";
const AAD_PREKEY: &[u8] = b"lithiumd/prekey/v1";

#[derive(Clone)]
#[allow(dead_code)]
pub struct ContactRow {
    pub contact_id: Vec<u8>,
    pub server: String,
    pub peer_state: SecretBytes,
    pub self_state: SecretBytes,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct MessageRow {
    pub id: i64,
    pub contact_id: Vec<u8>,
    pub mailbox: Vec<u8>,
    pub direction: i32,
    pub content: SecretBytes,
    pub created_at: chrono::DateTime<Utc>,
}

#[allow(async_fn_in_trait)]
pub trait DaemonDbExt<P: MkProvider + Send + Sync + 'static> {
    async fn upsert_contact(
        &self,
        contact_id: Vec<u8>,
        server: String,
        peer_state: SecretBytes,
        self_state: SecretBytes,
    ) -> Result<()>;

    async fn get_contact(&self, contact_id: &[u8]) -> Result<Option<ContactRow>>;

    async fn add_message(
        &self,
        contact_id: Vec<u8>,
        mailbox: Vec<u8>,
        direction: i32,
        content: SecretBytes,
    ) -> Result<i64>;

    async fn list_messages_page(
        &self,
        contact_id: &[u8],
        before_id: Option<i64>,
        limit: u64,
    ) -> Result<Vec<MessageRow>>;

    async fn put_prekey(
        &self,
        contact_id: Vec<u8>,
        prekey_id: Vec<u8>,
        key: SecretBytes,
        ttl: std::time::Duration,
    ) -> Result<()>;

    async fn take_prekey(&self, prekey_id: &[u8]) -> Result<Option<SecretBytes>>;
}

impl<P: MkProvider + Send + Sync + 'static> DaemonDbExt<P> for DataManager<P> {
    async fn upsert_contact(
        &self,
        contact_id: Vec<u8>,
        server: String,
        peer_state: SecretBytes,
        self_state: SecretBytes,
    ) -> Result<()> {
        let now = Utc::now();

        let peer_enc = self
            .encrypt_db_blob(&peer_state, &SecretBytes::from_slice(AAD_CONTACT_PEER))
            .await?;
        let self_enc = self
            .encrypt_db_blob(&self_state, &SecretBytes::from_slice(AAD_CONTACT_SELF))
            .await?;

        if let Some(row) = contacts::Entity::find()
            .filter(contacts::Column::ContactId.eq(contact_id.clone()))
            .one(self.db())
            .await
            .map_err(LithiumError::io)?
        {
            let mut am: contacts::ActiveModel = row.into();
            am.server = Set(server);
            am.peer_state_enc = Set(peer_enc.expose_as_slice().to_vec());
            am.self_state_enc = Set(self_enc.expose_as_slice().to_vec());
            am.updated_at = Set(now);
            am.update(self.db()).await.map_err(LithiumError::io)?;
            return Ok(());
        }

        let am = contacts::ActiveModel {
            id: Default::default(),
            contact_id: Set(contact_id),
            server: Set(server),
            peer_state_enc: Set(peer_enc.expose_as_slice().to_vec()),
            self_state_enc: Set(self_enc.expose_as_slice().to_vec()),
            created_at: Set(now),
            updated_at: Set(now),
        };

        am.insert(self.db()).await.map_err(LithiumError::io)?;
        Ok(())
    }

    async fn get_contact(&self, contact_id: &[u8]) -> Result<Option<ContactRow>> {
        let Some(row) = contacts::Entity::find()
            .filter(contacts::Column::ContactId.eq(contact_id.to_vec()))
            .one(self.db())
            .await
            .map_err(LithiumError::io)?
        else {
            return Ok(None);
        };

        let peer = self
            .decrypt_db_blob(
                &SecretBytes::from_vec(row.peer_state_enc.clone()),
                &SecretBytes::from_slice(AAD_CONTACT_PEER),
            )
            .await?;
        let self_state = self
            .decrypt_db_blob(
                &SecretBytes::from_vec(row.self_state_enc.clone()),
                &SecretBytes::from_slice(AAD_CONTACT_SELF),
            )
            .await?;

        Ok(Some(ContactRow {
            contact_id: row.contact_id,
            server: row.server,
            peer_state: peer,
            self_state,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }))
    }

    async fn add_message(
        &self,
        contact_id: Vec<u8>,
        mailbox: Vec<u8>,
        direction: i32,
        content: SecretBytes,
    ) -> Result<i64> {
        let now = Utc::now();

        let enc = self
            .encrypt_db_blob(&content, &SecretBytes::from_slice(AAD_MESSAGE))
            .await?;

        let am = messages::ActiveModel {
            id: Default::default(),
            contact_id: Set(contact_id),
            mailbox: Set(mailbox),
            direction: Set(direction),
            content_enc: Set(enc.expose_as_slice().to_vec()),
            created_at: Set(now),
        };

        let inserted = am.insert(self.db()).await.map_err(LithiumError::io)?;
        Ok(inserted.id)
    }

    async fn list_messages_page(
        &self,
        contact_id: &[u8],
        before_id: Option<i64>,
        limit: u64,
    ) -> Result<Vec<MessageRow>> {
        let mut q = messages::Entity::find()
            .filter(messages::Column::ContactId.eq(contact_id.to_vec()))
            .order_by_desc(messages::Column::Id)
            .limit(limit);

        if let Some(before_id) = before_id {
            q = q.filter(messages::Column::Id.lt(before_id));
        }

        let rows = q.all(self.db()).await.map_err(LithiumError::io)?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let pt = self
                .decrypt_db_blob(
                    &SecretBytes::from_vec(r.content_enc.clone()),
                    &SecretBytes::from_slice(AAD_MESSAGE),
                )
                .await?;

            out.push(MessageRow {
                id: r.id,
                contact_id: r.contact_id,
                mailbox: r.mailbox,
                direction: r.direction,
                content: pt,
                created_at: r.created_at,
            });
        }
        Ok(out)
    }

    async fn put_prekey(
        &self,
        contact_id: Vec<u8>,
        prekey_id: Vec<u8>,
        key: SecretBytes,
        ttl: std::time::Duration,
    ) -> Result<()> {
        let now = Utc::now();
        let expires_at =
            now + chrono::Duration::from_std(ttl).map_err(|_| LithiumError::internal())?;

        let key_enc = self
            .encrypt_db_blob(&key, &SecretBytes::from_slice(AAD_PREKEY))
            .await?;

        let _ = prekeys::Entity::delete_many()
            .filter(prekeys::Column::PrekeyId.eq(prekey_id.clone()))
            .exec(self.db())
            .await;

        let am = prekeys::ActiveModel {
            id: Default::default(),
            contact_id: Set(contact_id),
            prekey_id: Set(prekey_id),
            key_enc: Set(key_enc.expose_as_slice().to_vec()),
            created_at: Set(now),
            expires_at: Set(expires_at),
            used_at: Set(None),
        };

        am.insert(self.db()).await.map_err(LithiumError::io)?;
        Ok(())
    }

    async fn take_prekey(&self, prekey_id: &[u8]) -> Result<Option<SecretBytes>> {
        let now = Utc::now();
        let prekey_id = prekey_id.to_vec();

        let key_enc_opt = self
            .db()
            .transaction(|txn| {
                let prekey_id = prekey_id.clone();
                let now = now;

                Box::pin(async move {
                    let Some(row) = prekeys::Entity::find()
                        .filter(prekeys::Column::PrekeyId.eq(prekey_id))
                        .filter(prekeys::Column::ExpiresAt.gt(now))
                        .filter(prekeys::Column::UsedAt.is_null())
                        .one(txn)
                        .await?
                    else {
                        return Ok::<_, sea_orm::DbErr>(None);
                    };

                    let claim = prekeys::Entity::update_many()
                        .col_expr(prekeys::Column::UsedAt, Expr::value(now))
                        .filter(prekeys::Column::Id.eq(row.id))
                        .filter(prekeys::Column::UsedAt.is_null())
                        .exec(txn)
                        .await?;

                    if claim.rows_affected != 1 {
                        return Ok::<_, sea_orm::DbErr>(None);
                    }

                    prekeys::Entity::delete_by_id(row.id).exec(txn).await?;
                    Ok::<_, sea_orm::DbErr>(Some(row.key_enc))
                })
            })
            .await
            .map_err(LithiumError::io)?;

        let Some(key_enc) = key_enc_opt else {
            return Ok(None);
        };

        let pt = self
            .decrypt_db_blob(
                &SecretBytes::from_vec(key_enc),
                &SecretBytes::from_slice(AAD_PREKEY),
            )
            .await?;

        Ok(Some(pt))
    }
}
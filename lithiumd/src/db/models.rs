// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use sea_orm::entity::prelude::*;

pub mod contacts {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "contacts")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i64,

        #[sea_orm(unique)]
        pub contact_id: Vec<u8>,

        pub peer_state_enc: Vec<u8>,
        pub self_state_enc: Vec<u8>,

        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod messages {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "messages")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i64,

        pub contact_id: Vec<u8>,
        pub mailbox: Vec<u8>,
        pub direction: i32,
        pub content_enc: Vec<u8>,

        #[sea_orm(unique)]
        pub msg_id: Option<Vec<u8>>,

        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod prekeys {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "prekeys")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i64,

        pub contact_id: Vec<u8>,

        #[sea_orm(unique)]
        pub prekey_id: Vec<u8>,
        pub key_enc: Vec<u8>,

        pub created_at: DateTimeUtc,
        pub expires_at: DateTimeUtc,
        pub used_at: Option<DateTimeUtc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

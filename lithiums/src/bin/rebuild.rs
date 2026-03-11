use sea_orm::{ConnectionTrait, Schema};
use sea_orm::sea_query::Table;

use lithium_core::error::{LithiumError, Result};
use lithiums::db::{self, models::{messages, users}};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let db = db::connect_from_env().await?;
    let schema = Schema::new(db.get_database_backend());

    let mut drop_messages = Table::drop();
    drop_messages.table(messages::Entity);
    drop_messages.if_exists();

    db.execute(db.get_database_backend().build(&drop_messages))
        .await
        .map_err(LithiumError::io)?;

    let mut drop_users = Table::drop();
    drop_users.table(users::Entity);
    drop_users.if_exists();

    db.execute(db.get_database_backend().build(&drop_users))
        .await
        .map_err(LithiumError::io)?;

    let mut create_users = schema.create_table_from_entity(users::Entity);
    create_users.if_not_exists();

    db.execute(db.get_database_backend().build(&create_users))
        .await
        .map_err(LithiumError::io)?;

    let mut create_messages = schema.create_table_from_entity(messages::Entity);
    create_messages.if_not_exists();

    db.execute(db.get_database_backend().build(&create_messages))
        .await
        .map_err(LithiumError::io)?;

    println!("database schema rebuilt");
    Ok(())
}
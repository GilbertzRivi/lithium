use lithium_core::error::{LithiumError, Result};
use sea_orm::{Database, DatabaseConnection};
use std::env;

pub mod models;
pub mod repo;

pub async fn connect_from_env() -> Result<DatabaseConnection> {
    let url = env::var("DATABASE_URL").map_err(|e| LithiumError::internal().with_source(e))?;
    Database::connect(url).await.map_err(LithiumError::io)
}

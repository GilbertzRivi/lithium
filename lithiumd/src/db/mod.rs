use std::path::{Path, PathBuf};

use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Schema};

use lithium_core::{
    db::manager::DataManager,
    error::{LithiumError, Result},
    keys::{KeyManager, MkProvider},
};
use tokio::sync::Mutex;
use std::sync::Arc;

pub mod models;
pub mod repo;

fn default_db_path(base_dir: &Path) -> PathBuf {
    base_dir.join("storage").join("lithiumd.sqlite")
}

pub async fn connect_local_sqlite(base_dir: &Path) -> Result<DatabaseConnection> {
    let db_path = default_db_path(base_dir);
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(LithiumError::io)?;
    }

    let url = format!("sqlite://{}?mode=rwc", db_path.display());
    let db = Database::connect(url).await.map_err(LithiumError::io)?;

    let _ = db.execute_unprepared("PRAGMA journal_mode=WAL;").await;
    let _ = db.execute_unprepared("PRAGMA synchronous=NORMAL;").await;
    let _ = db.execute_unprepared("PRAGMA foreign_keys=ON;").await;
    let _ = db.execute_unprepared("PRAGMA temp_store=MEMORY;").await;
    let _ = db.execute_unprepared("PRAGMA busy_timeout=5000;").await;

    Ok(db)
}

pub async fn ensure_schema_sqlite(db: &DatabaseConnection) -> Result<()> {
    let schema = Schema::new(DbBackend::Sqlite);

    let mut t_contacts = schema.create_table_from_entity(models::contacts::Entity);
    t_contacts.if_not_exists();
    db.execute(db.get_database_backend().build(&t_contacts))
        .await
        .map_err(LithiumError::io)?;

    let mut t_messages = schema.create_table_from_entity(models::messages::Entity);
    t_messages.if_not_exists();
    db.execute(db.get_database_backend().build(&t_messages))
        .await
        .map_err(LithiumError::io)?;

    let mut t_prekeys = schema.create_table_from_entity(models::prekeys::Entity);
    t_prekeys.if_not_exists();
    db.execute(db.get_database_backend().build(&t_prekeys))
        .await
        .map_err(LithiumError::io)?;

    Ok(())
}

pub async fn init_local_data_manager<P: MkProvider + Send + Sync + 'static>(
    base_dir: &Path,
    key_manager: Arc<Mutex<KeyManager<P>>>,
) -> Result<Arc<DataManager<P>>> {
    let db = connect_local_sqlite(base_dir).await?;
    ensure_schema_sqlite(&db).await?;

    let dm = DataManager::new(db, key_manager);
    dm.init().await?;

    Ok(Arc::new(dm))
}

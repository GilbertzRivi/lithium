use std::{env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use poem::{listener::TcpListener, Server};
use tokio::sync::Mutex;

use lithium_core::{
    db::manager::DataManager,
    error::LithiumError,
    keys::{KeyManager, KeyStoreKind, PlainFileMkProvider},
    utils::store::EphemeralStoreManager,
};
use lithiums::{build_app, db, error::AppResult, identity, mk_rotator, state};

#[tokio::main]
async fn main() -> AppResult<()> {
    let bind_host = env::var("LITHIUM_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let bind_port = env::var("LITHIUM_PORT").unwrap_or_else(|_| "4108".to_string());
    let bind: SocketAddr = format!("{bind_host}:{bind_port}")
        .parse()
        .map_err(|e| LithiumError::internal().with_source(e))?;

    let keys_dir = PathBuf::from(
        env::var("LITHIUM_KEYS_DIR").unwrap_or_else(|_| "/var/lib/lithiums".to_string()),
    );
    let rotate_secs: u64 = env::var("LITHIUM_MK_ROTATE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600);

    let mut km =
        KeyManager::<PlainFileMkProvider>::start_plain(&keys_dir, KeyStoreKind::Server)?;
    km.set_rotate_interval(Duration::from_secs(rotate_secs));

    let identity_path = keys_dir.join("server.identity");
    if !identity_path.exists() {
        identity::write_server_identity(&identity_path, km.public_keys())
            .map_err(LithiumError::io)?;
        tracing::info!("wrote server.identity to {}", identity_path.display());
    }

    let key_manager = Arc::new(Mutex::new(km));
    let _mk_rotator =
        mk_rotator::spawn_mk_rotator(Arc::clone(&key_manager), Duration::from_secs(30));

    let db_conn = db::connect_from_env().await?;
    db::migrate(&db_conn).await?;
    let dbm = Arc::new(DataManager::new(db_conn, Arc::clone(&key_manager)));

    let app_state = Arc::new(state::AppState {
        key_manager,
        store: EphemeralStoreManager::new()?,
        db: dbm,
    });

    let app = build_app(app_state);

    Server::new(TcpListener::bind(bind))
        .run(app)
        .await
        .map_err(LithiumError::io)?;

    Ok(())
}
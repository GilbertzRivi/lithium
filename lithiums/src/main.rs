use std::{env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use poem::{listener::TcpListener, EndpointExt, Server};
use poem::middleware::Tracing;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use lithium_core::{
    db::manager::DataManager,
    error::{LithiumError, Result},
    keys::{KeyManager, KeyStoreKind},
    utils::store::EphemeralStoreManager,
};
use lithium_core::keys::PlainFileMkProvider;

use lithiums::{api_routes, db, error, state::AppState};

#[tokio::main]
async fn main() -> error::AppResult<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let bind: SocketAddr = env::var("LITHIUM_BIND")
        .unwrap_or_else(|_| "0.0.0.0:4108".to_string())
        .parse()
        .map_err(|e| LithiumError::internal().with_source(e))?;

    let keys_dir = PathBuf::from(
        env::var("LITHIUM_KEYS_DIR").map_err(|e| LithiumError::internal().with_source(e))?,
    );
    let server_name = env::var("LITHIUM_SERVER_NAME").unwrap_or_else(|_| "default".to_string());

    let rotate_secs: u64 = env::var("LITHIUM_MK_ROTATE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600);

    let mut km =
        KeyManager::<PlainFileMkProvider>::start_plain(&keys_dir, KeyStoreKind::Server, &server_name)?;
    km.set_rotate_interval(Duration::from_secs(rotate_secs));

    let key_manager = Arc::new(Mutex::new(km));
    let db = db::connect_from_env().await?;

    let dbm = Arc::new(DataManager::new(db, key_manager.clone()));
    dbm.init().await?;

    let state = Arc::new(AppState {
        key_manager,
        store: EphemeralStoreManager::new()?,
        db: dbm,
    });

    let app = api_routes(state).with(Tracing);

    Server::new(TcpListener::bind(bind))
        .run(app)
        .await
        .map_err(LithiumError::io)?;

    Ok(())
}
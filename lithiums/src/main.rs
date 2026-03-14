use std::{env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use poem::{get, handler, post, Endpoint, EndpointExt, Route};
use poem::{listener::TcpListener, Server};
use poem::web::Json;
use serde_json::json;
use tokio::sync::Mutex;

use lithium_core::{
    db::manager::DataManager,
    error::LithiumError,
    keys::{KeyManager, KeyStoreKind, PlainFileMkProvider},
    utils::store::EphemeralStoreManager,
};

use middleware::crypto::CryptoMiddleware;
use middleware::guard::GuardMiddleware;
use transport::{AuthMode, CryptoCfg};

mod api;
mod db;
mod error;
mod identity;
mod middleware;
mod mk_rotator;
mod state;
mod transport;

#[handler]
async fn root() -> Json<serde_json::Value> {
    Json(json!({
        "message": "Welcome to Lithium, real private messenger"
    }))
}

fn api_routes(state: state::SharedState) -> impl Endpoint {
    Route::new()
        .at("/", get(root))
        .at(
            "/shake",
            post(api::handshake::handshake).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::shake("shake").auth(AuthMode::KeysInHeaders),
            )),
        )
        .at(
            "/user/register",
            post(api::user::register).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session("register").auth(AuthMode::KeysInHeaders),
            )),
        )
        .at(
            "/user/login",
            post(api::user::login).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session("login").auth(AuthMode::LoginByHandler),
            )),
        )
        .at(
            "/user/revoke",
            post(api::user::revoke).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session("revoke").auth(AuthMode::KeysInHeaders),
            )),
        )
        .at(
            "/user/delete",
            post(api::user::delete).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session("delete").auth(AuthMode::JwtUser),
            )),
        )
        .at(
            "/msg/send",
            post(api::messages::send).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session("msg_send").auth(AuthMode::JwtUser),
            )),
        )
        .at(
            "/msg/fetch",
            post(api::messages::fetch).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session("msg_fetch").auth(AuthMode::KeysInHeaders),
            )),
        )
        .with(GuardMiddleware::new(state))
}

#[tokio::main]
async fn main() -> error::AppResult<()> {
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
    let _mk_rotator = mk_rotator::spawn_mk_rotator(Arc::clone(&key_manager), Duration::from_secs(30));

    let db = db::connect_from_env().await?;
    db::migrate(&db).await?;
    let dbm = Arc::new(DataManager::new(db, Arc::clone(&key_manager)));
    dbm.init().await?;

    let state = Arc::new(state::AppState {
        key_manager,
        store: EphemeralStoreManager::new()?,
        db: dbm,
    });

    let app = api_routes(state);

    Server::new(TcpListener::bind(bind))
        .run(app)
        .await
        .map_err(LithiumError::io)?;

    Ok(())
}
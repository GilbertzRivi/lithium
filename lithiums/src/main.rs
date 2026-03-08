use std::{env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use poem::{
    get, handler, listener::TcpListener, middleware::Tracing, post, Endpoint, EndpointExt, Route,
    Server,
};
use poem::web::Json;
use serde_json::json;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use lithium_core::db::manager::DataManager;
use lithium_core::error::LithiumError;
use lithium_core::keys::manager::{KeyManager, KeyStoreKind};
use lithium_core::keys::PlainFileMkProvider;
use lithium_core::utils::store::EphemeralStoreManager;
use log::info;
use crate::middleware::crypto::CryptoMiddleware;
use crate::middleware::guard::GuardMiddleware;
use crate::state::AppState;
use crate::transport::{AuthMode, CryptoCfg};

mod api;
mod db;
mod error;
mod middleware;
mod state;
mod transport;

#[handler]
async fn root() -> Json<serde_json::Value> {
    Json(json!({
        "message": "Welcome to Lithium, real private messenger"
    }))
}

pub fn api_routes(state: state::SharedState) -> impl Endpoint {
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
                CryptoCfg::session("msg_fetch")
                    .auth(AuthMode::KeysInHeaders)
            )),
        )
        .with(GuardMiddleware::new(state))
}

#[tokio::main]
async fn main() -> Result<(), error::AppError> {
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

    // let pk = {
    //     let guard = key_manager.lock().await;
    //     guard.public_keys().clone()
    // };
    //
    // info!(
    //     "PublicKeys {{ ed25519: {}, x25519: {}, kyber: {}, dilithium: {} }}",
    //     hex::encode(pk.ed25519.as_slice()),
    //     hex::encode(pk.x25519.as_slice()),
    //     hex::encode(pk.kyber.as_slice()),
    //     hex::encode(pk.dilithium.as_slice()),
    // );

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

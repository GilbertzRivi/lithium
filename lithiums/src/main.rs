use std::{env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use poem::{Server, listener::TcpListener};
use tokio::sync::Mutex;

use lithium_proto::db::DataManager;
use lithium_proto::labels;

use lithium_core::{
    error::LithiumError,
    keys::{KeyManager, KeyStoreKind, PlainFileMkProvider},
    opaque::server::ServerSetup,
    pow,
    secrets::bytes::SecretBytes,
    utils::store::EphemeralStoreManager,
};
use lithiums::{
    build_app, db, error::AppResult, health::HealthState, identity, mk_rotator, msg_reaper,
    provider::ServerMkProvider, state,
};

#[cfg(feature = "tpm")]
use lithiums::tpm_provider::TpmMkProvider;

fn make_provider(keys_dir: &std::path::Path) -> ServerMkProvider {
    #[cfg(feature = "tpm")]
    if env::var("LITHIUM_MK_PROVIDER").as_deref() != Ok("plain") {
        let sealed_path = env::var("LITHIUM_TPM_SEALED_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| keys_dir.join("server").join("mk.sealed"));
        return ServerMkProvider::Tpm(TpmMkProvider::new(sealed_path));
    }

    ServerMkProvider::Plain(PlainFileMkProvider::new(keys_dir.join("server").join("mk")))
}

#[tokio::main]
async fn main() -> AppResult<()> {
    tracing_subscriber::fmt::init();
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

    let mut km = KeyManager::start(&keys_dir, KeyStoreKind::Server, make_provider(&keys_dir))?;
    km.set_rotate_interval(Duration::from_secs(rotate_secs));

    let opaque_setup = {
        let blob = km.load_or_create_sealed_blob(labels::OPAQUE_SERVER_SETUP_LABEL, || {
            Ok(SecretBytes::new(ServerSetup::generate().serialize()))
        })?;
        Arc::new(ServerSetup::deserialize(blob.expose_as_slice())?)
    };

    let send_pow_bits: u32 = env::var("LITHIUMS_SEND_POW_BITS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(pow::DEFAULT_SEND_POW_BITS);

    let identity_path = keys_dir.join("server.identity");
    if !identity_path.exists() {
        identity::write_server_identity(&identity_path, km.public_keys())
            .map_err(LithiumError::io)?;
        tracing::info!("wrote server.identity to {}", identity_path.display());
    }

    let key_manager = Arc::new(Mutex::new(km));
    let health = HealthState::new();

    let _mk_rotator = mk_rotator::spawn_mk_rotator(
        Arc::clone(&key_manager),
        Arc::clone(&health),
        Duration::from_secs(30),
    );

    let db_conn = db::connect_from_env().await?;
    db::migrate(&db_conn).await?;
    let dbm = Arc::new(DataManager::new(db_conn, Arc::clone(&key_manager)));
    let _msg_reaper = msg_reaper::spawn_msg_reaper(
        Arc::clone(&dbm),
        Arc::clone(&health),
        Duration::from_secs(300),
    );

    let app_state = Arc::new(state::AppState {
        key_manager,
        store: EphemeralStoreManager::new()?,
        db: dbm,
        health,
        opaque_setup,
        send_pow_bits,
    });

    let app = build_app(app_state);

    #[cfg(unix)]
    let mut sigterm = {
        use tokio::signal::unix::{SignalKind, signal};
        signal(SignalKind::terminate()).map_err(LithiumError::io)?
    };

    let shutdown = async move {
        #[cfg(unix)]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    };

    // Plain HTTP — TLS is terminated by the reverse proxy in front of this process.
    Server::new(TcpListener::bind(bind))
        .run_with_graceful_shutdown(app, shutdown, Some(Duration::from_secs(30)))
        .await
        .map_err(LithiumError::io)?;

    Ok(())
}

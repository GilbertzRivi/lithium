use std::{net::SocketAddr, sync::Arc, time::Duration};

use lithium_core::{
    db::manager::DataManager,
    keys::{KeyManager, KeyStoreKind, PlainFileMkProvider},
    utils::store::EphemeralStoreManager,
};
use lithiums::{build_app, db, health::HealthState, mk_rotator, provider::ServerMkProvider, state};
use poem::{Server, listener::TcpListener};
use tokio::sync::{Mutex, OnceCell};
use uuid::Uuid;

use crate::client::{ServerBootstrap, TestLithiumClient};

// Low difficulty keeps the test suite fast while still exercising the PoW path.
pub const TEST_SEND_POW_BITS: u32 = 8;

// One Docker container (lithium_itest_pg, port 15432) is shared across all test
// binaries in a cargo test run. The container is not removed on exit because multiple
// binaries run concurrently - the first to exit would kill it for the rest. Reuse on
// the next run via `docker start`. Full reset: `docker rm -f lithium_itest_pg`.

struct SharedPg {
    port: u16,
    container_name: &'static str,
}

static SHARED_PG: OnceCell<SharedPg> = OnceCell::const_new();

async fn ensure_postgres() -> &'static SharedPg {
    SHARED_PG
        .get_or_init(|| async {
            const NAME: &str = "lithium_itest_pg";
            const PORT: u16 = 15432;

            let started = tokio::process::Command::new("docker")
                .args(["start", NAME])
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);

            if !started {
                let out = tokio::process::Command::new("docker")
                    .args([
                        "run",
                        "-d",
                        "--name",
                        NAME,
                        "-p",
                        &format!("{PORT}:5432"),
                        "-e",
                        "POSTGRES_PASSWORD=test",
                        "-e",
                        "POSTGRES_USER=test",
                        "-e",
                        "POSTGRES_DB=postgres",
                        "postgres:17-alpine",
                    ])
                    .output()
                    .await
                    .expect(
                        "docker run failed — is Docker installed and running?\n\
                         Alternatively set LITHIUM_TEST_DATABASE_URL to skip Docker.",
                    );

                assert!(
                    out.status.success(),
                    "docker run postgres failed:\n{}",
                    String::from_utf8_lossy(&out.stderr),
                );
            }

            wait_for_postgres(NAME).await;

            SharedPg {
                port: PORT,
                container_name: NAME,
            }
        })
        .await
}

async fn wait_for_postgres(container_name: &str) {
    for _ in 0..60 {
        let ok = tokio::process::Command::new("docker")
            .args(["exec", container_name, "pg_isready", "-U", "test"])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("PostgreSQL in '{container_name}' did not become ready after 30 s");
}

struct DbGuard {
    container_name: &'static str,
    db_name: String,
}

impl Drop for DbGuard {
    fn drop(&mut self) {
        // sync drop is fine at test teardown
        std::process::Command::new("docker")
            .args([
                "exec",
                self.container_name,
                "psql",
                "-U",
                "test",
                "-d",
                "postgres",
                "-c",
                &format!("DROP DATABASE IF EXISTS \"{}\";", self.db_name),
            ])
            .output()
            .ok();
    }
}

async fn create_test_db(pg: &'static SharedPg) -> (String, DbGuard) {
    let db_name = format!("lithium_t_{}", Uuid::new_v4().simple());

    let out = tokio::process::Command::new("docker")
        .args([
            "exec",
            pg.container_name,
            "psql",
            "-U",
            "test",
            "-d",
            "postgres",
            "-c",
            &format!("CREATE DATABASE \"{db_name}\";"),
        ])
        .output()
        .await
        .expect("docker exec psql CREATE DATABASE failed");

    assert!(
        out.status.success(),
        "CREATE DATABASE failed:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );

    let url = format!("postgres://test:test@127.0.0.1:{}/{db_name}", pg.port);
    let guard = DbGuard {
        container_name: pg.container_name,
        db_name,
    };
    (url, guard)
}

pub struct TestServer {
    pub addr: SocketAddr,
    pub bootstrap: ServerBootstrap,
    _db: Option<DbGuard>,
}

impl TestServer {
    pub async fn start() -> Self {
        let (db_url, db_guard) = match std::env::var("LITHIUM_TEST_DATABASE_URL") {
            Ok(url) => (url, None),
            Err(_) => {
                let pg = ensure_postgres().await;
                let (url, guard) = create_test_db(pg).await;
                (url, Some(guard))
            }
        };

        let keys_path = tempfile::tempdir().expect("tempdir").keep();

        let mk_path = keys_path.join("server").join("mk");
        let mut km = KeyManager::start(
            &keys_path,
            KeyStoreKind::Server,
            ServerMkProvider::Plain(PlainFileMkProvider::new(mk_path)),
        )
        .expect("KeyManager init");

        let pub_keys = km.public_keys().clone();
        km.set_rotate_interval(Duration::from_secs(3600));

        let opaque_setup = {
            let blob = km
                .load_or_create_sealed_blob(lithium_core::opaque::SERVER_SETUP_LABEL, || {
                    Ok(lithium_core::secrets::bytes::SecretBytes::new(
                        lithium_core::opaque::server::ServerSetup::generate().serialize(),
                    ))
                })
                .expect("opaque setup");
            Arc::new(
                lithium_core::opaque::server::ServerSetup::deserialize(blob.expose_as_slice())
                    .expect("opaque setup deserialize"),
            )
        };

        let key_manager = Arc::new(Mutex::new(km));

        let health = HealthState::new();
        let _rotator = mk_rotator::spawn_mk_rotator(
            Arc::clone(&key_manager),
            Arc::clone(&health),
            Duration::from_secs(3600),
        );

        let db_conn = db::connect_url(&db_url).await.expect("db connect");
        db::migrate(&db_conn).await.expect("db migrate");
        let dbm = Arc::new(DataManager::new(db_conn, Arc::clone(&key_manager)));

        let app_state = Arc::new(state::AppState {
            key_manager,
            store: EphemeralStoreManager::new().expect("store"),
            db: dbm,
            health,
            opaque_setup,
            send_pow_bits: TEST_SEND_POW_BITS,
        });

        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind :0");
            listener.local_addr().expect("local_addr").port()
        };

        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let bind_str = addr.to_string();
        let app = build_app(app_state);

        tokio::spawn(async move {
            let _keep = keys_path;
            Server::new(TcpListener::bind(bind_str))
                .run(app)
                .await
                .expect("server error");
        });

        tokio::time::sleep(Duration::from_millis(80)).await;

        let bootstrap = ServerBootstrap {
            shake_pub_x: lithium_core::secrets::Byte32::from_slice(pub_keys.x25519.as_slice())
                .expect("x25519 pub"),
            shake_pub_k: lithium_core::secrets::bytes::SecretBytes::from_slice(
                pub_keys.kyber.expose_as_slice(),
            ),
            server_sig_ed: lithium_core::secrets::Byte32::from_slice(pub_keys.ed25519.as_slice())
                .expect("ed25519 pub"),
            server_sig_dili: lithium_core::secrets::bytes::SecretBytes::from_slice(
                pub_keys.dilithium.expose_as_slice(),
            ),
        };

        TestServer {
            addr,
            bootstrap,
            _db: db_guard,
        }
    }

    pub fn client(&self) -> TestLithiumClient {
        TestLithiumClient::new(format!("http://{}", self.addr), self.bootstrap.clone())
    }
}

pub fn unique_handle(prefix: &str) -> String {
    format!("{}_{}", prefix, Uuid::new_v4().simple())
}

pub fn random_dek_hex() -> String {
    use lithium_core::crypto::keys;
    keys::random_32()
        .expect("random_32")
        .to_hex()
        .expose()
        .to_string()
}

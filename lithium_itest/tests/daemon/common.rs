#![allow(dead_code, unused_imports)]

use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::Duration,
};

pub use lithium_itest::{client::ServerBootstrap, helpers::{TestServer, unique_handle}};
pub use serde_json::{json, Value};
pub use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
pub use tokio::net::UnixStream;

pub fn daemon_bin() -> &'static Path {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
        let manifest = env!("CARGO_MANIFEST_DIR");
        let workspace = Path::new(manifest).parent().unwrap();

        let ok = Command::new(&cargo)
            .args(["build", "-p", "lithiumd"])
            .current_dir(workspace)
            .status()
            .expect("failed to run cargo build -p lithiumd")
            .success();

        assert!(ok, "cargo build -p lithiumd failed");
        workspace.join("target").join("debug").join("lithiumd")
    })
}

pub struct DaemonProcess {
    pub child: Option<Child>,
    pub socket_path: PathBuf,
    pub _data_dir: Option<tempfile::TempDir>,
}

impl DaemonProcess {
    pub async fn start() -> Self {
        Self::start_opts(4).await
    }

    pub async fn start_max_conn(n: usize) -> Self {
        Self::start_opts(n).await
    }

    async fn start_opts(max_conn: usize) -> Self {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let socket_path = data_dir.path().join("daemon.sock");
        let child = Self::spawn_child(data_dir.path(), &socket_path, max_conn).await;
        DaemonProcess { child: Some(child), socket_path, _data_dir: Some(data_dir) }
    }

    // Removes any stale socket from a previous daemon so wait_for_socket sees only the new one.
    pub async fn start_in(data_path: &Path) -> Self {
        let socket_path = data_path.join("daemon.sock");
        let _ = tokio::fs::remove_file(&socket_path).await;
        let child = Self::spawn_child(data_path, &socket_path, 4).await;
        DaemonProcess { child: Some(child), socket_path, _data_dir: None }
    }

    pub async fn spawn_child(data_path: &Path, socket_path: &Path, max_conn: usize) -> Child {
        let child = Command::new(daemon_bin())
            .env("LITHIUMD_DATA_DIR", data_path)
            .env("LITHIUMD_SOCKET_PATH", socket_path)
            .env("LITHIUMD_IPC_MAX_CONNECTIONS", max_conn.to_string())
            .env("LITHIUMD_IPC_IDLE_TIMEOUT_SECS", "30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn daemon");

        wait_for_socket(socket_path).await;
        child
    }

    pub fn take_child(&mut self) -> Child {
        self.child.take().expect("child already taken")
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

pub async fn wait_for_socket(path: &Path) {
    // Check file existence only — connecting would consume a connection slot.
    for _ in 0..80 {
        if tokio::fs::metadata(path).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("daemon socket not found at {}", path.display());
}

pub struct IpcClient {
    pub reader: BufReader<tokio::io::ReadHalf<UnixStream>>,
    pub writer: tokio::io::WriteHalf<UnixStream>,
    pub next_id: u64,
}

impl IpcClient {
    pub async fn connect(path: &Path) -> Self {
        let stream = UnixStream::connect(path).await.expect("connect to daemon socket");
        let (r, w) = tokio::io::split(stream);
        IpcClient { reader: BufReader::new(r), writer: w, next_id: 1 }
    }

    pub async fn send(&mut self, mut cmd: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        cmd["id"] = json!(id);
        let line = serde_json::to_string(&cmd).unwrap() + "\n";
        self.writer.write_all(line.as_bytes()).await.expect("write ipc");
        let mut buf = String::new();
        self.reader.read_line(&mut buf).await.expect("read ipc");
        serde_json::from_str(&buf).expect("parse ipc response")
    }

    pub async fn send_raw(&mut self, s: &str) {
        self.writer.write_all(s.as_bytes()).await.expect("write raw ipc");
    }

    pub async fn try_read_line(&mut self) -> Option<String> {
        let mut buf = String::new();
        match tokio::time::timeout(Duration::from_millis(500), self.reader.read_line(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => None,
            Ok(Ok(_)) => Some(buf),
            Ok(Err(_)) => None,
        }
    }
}

// Binary format: [8] magic "LITHIUPK" | [1] version 0x01 | [1] entry_count
// Entry: [1] tag_len | [N] tag | [2 LE] data_len | [M] data
pub fn build_server_identity(bs: &ServerBootstrap) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"LITHIUPK");
    out.push(0x01);
    out.push(4u8);

    let mut add = |tag: &str, data: &[u8]| {
        out.push(tag.len() as u8);
        out.extend_from_slice(tag.as_bytes());
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        out.extend_from_slice(data);
    };

    add("x25519",    bs.shake_pub_x.as_slice());
    add("ed25519",   bs.server_sig_ed.as_slice());
    add("mlkem1024", bs.shake_pub_k.expose_as_slice());
    add("mldsa87",   bs.server_sig_dili.expose_as_slice());
    out
}

pub const DATA_PASS: &str = "DataPass1!";
pub const ACCT_PASS: &str = "AcctPass2@";

pub async fn full_setup(c: &mut IpcClient, srv: &TestServer, handler: &str) -> String {
    c.send(json!({"cmd": "set_server_url",      "url":  format!("http://{}", srv.addr)})).await;
    c.send(json!({"cmd": "set_server_identity", "data": hex::encode(build_server_identity(&srv.bootstrap))})).await;

    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    assert!(r["ok"].as_bool().unwrap(), "unlock_keystore: {:?}", r);
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let r = c.send(json!({"cmd": "set_credentials", "handler": handler, "password": ACCT_PASS, "auth_token": tok})).await;
    assert!(r["ok"].as_bool().unwrap(), "set_credentials: {:?}", r);

    let r = c.send(json!({"cmd": "register", "auth_token": tok})).await;
    assert!(r["ok"].as_bool().unwrap(), "register: {:?}", r);

    let r = c.send(json!({"cmd": "unlock_storage", "auth_token": tok})).await;
    assert!(r["ok"].as_bool().unwrap(), "unlock_storage: {:?}", r);

    tok
}
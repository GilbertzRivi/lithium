// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(dead_code, unused_imports)]

#[path = "../daemon/common.rs"]
mod daemon_common;
pub use daemon_common::*;

use std::process::{Command, Stdio};

// Server-connected tests are slower than pure-daemon tests because each contact_send
// involves two HTTP round-trips (shake + send). Use a longer idle timeout so connections
// don't drop under normal test load.
pub async fn start_daemon() -> DaemonProcess {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let socket_path = data_dir.path().join("daemon.sock");
    let child = Command::new(daemon_bin())
        .env("LITHIUMD_DATA_DIR", data_dir.path())
        .env("LITHIUMD_SOCKET_PATH", &socket_path)
        .env("LITHIUMD_IPC_MAX_CONNECTIONS", "4")
        .env("LITHIUMD_IPC_IDLE_TIMEOUT_SECS", "120")
        .env("LITHIUMD_TRAFFIC_SEND_INTERVAL_SECS", "1")
        .env("LITHIUMD_TRAFFIC_FETCH_INTERVAL_SECS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    wait_for_socket(&socket_path).await;
    DaemonProcess {
        child: Some(child),
        socket_path,
        _data_dir: Some(data_dir),
    }
}

// Returns (cid_a, cid_b) — A's local ID for B and B's local ID for A.
pub async fn connect_pair(
    ca: &mut IpcClient,
    tok_a: &str,
    cb: &mut IpcClient,
    tok_b: &str,
) -> (String, String) {
    let inv = ca
        .send(json!({"cmd": "create_invite", "auth_token": tok_a}))
        .await;
    assert!(inv["ok"].as_bool().unwrap(), "{:?}", inv);
    let cid_a = inv["result"]["contact_id"].as_str().unwrap().to_owned();
    let commitment = inv["result"]["commitment"].as_str().unwrap().to_owned();

    let acc_b = cb
        .send(json!({"cmd": "accept_commitment", "commitment": commitment, "label": "A", "auth_token": tok_b}))
        .await;
    assert!(acc_b["ok"].as_bool().unwrap(), "{:?}", acc_b);
    let cid_b = acc_b["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_b = acc_b["result"]["code"].as_str().unwrap().to_owned();

    let rev = ca
        .send(json!({"cmd": "reveal_invite", "contact_id": cid_a, "peer_code": code_b, "label": "B", "auth_token": tok_a}))
        .await;
    assert!(rev["ok"].as_bool().unwrap(), "{:?}", rev);
    let code_a = rev["result"]["code"].as_str().unwrap().to_owned();

    let fin = cb
        .send(json!({"cmd": "finalize_pairing", "contact_id": cid_b, "peer_code": code_a, "auth_token": tok_b}))
        .await;
    assert!(fin["ok"].as_bool().unwrap(), "{:?}", fin);

    (cid_a, cid_b)
}

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#[path = "common.rs"]
mod common;
use common::*;
use std::time::Duration;

#[tokio::test]
async fn test_parallel_pings_both_succeed() {
    let d = DaemonProcess::start_max_conn(8).await;
    let sp1 = d.socket_path.clone();
    let sp2 = d.socket_path.clone();

    let t1 = tokio::spawn(async move {
        IpcClient::connect(&sp1)
            .await
            .send(json!({"cmd": "ping"}))
            .await
    });
    let t2 = tokio::spawn(async move {
        IpcClient::connect(&sp2)
            .await
            .send(json!({"cmd": "ping"}))
            .await
    });

    let (r1, r2) = tokio::join!(t1, t2);
    assert!(r1.unwrap()["ok"].as_bool().unwrap());
    assert!(r2.unwrap()["ok"].as_bool().unwrap());
}

#[tokio::test]
async fn test_parallel_auth_token_use() {
    let d = DaemonProcess::start_max_conn(8).await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"}))
        .await;
    let r = c
        .send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
        .await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let sp1 = d.socket_path.clone();
    let sp2 = d.socket_path.clone();
    let tok1 = tok.clone();
    let tok2 = tok.clone();

    let t1 = tokio::spawn(async move {
        IpcClient::connect(&sp1)
            .await
            .send(json!({"cmd": "wipe_local", "auth_token": tok1}))
            .await
    });
    let t2 = tokio::spawn(async move {
        IpcClient::connect(&sp2)
            .await
            .send(json!({"cmd": "ping", "auth_token": tok2}))
            .await
    });

    let (r1, r2) = tokio::join!(t1, t2);
    assert!(r1.unwrap()["ok"].as_bool().unwrap());
    assert!(r2.unwrap()["ok"].as_bool().unwrap());
}

#[tokio::test]
async fn test_shutdown_drops_sibling_connection() {
    let d = DaemonProcess::start_max_conn(8).await;

    let mut ca = IpcClient::connect(&d.socket_path).await;
    ca.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"}))
        .await;
    let r = ca
        .send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
        .await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let mut cb = IpcClient::connect(&d.socket_path).await;
    assert!(
        cb.send(json!({"cmd": "ping"})).await["ok"]
            .as_bool()
            .unwrap()
    );

    let r = ca.send(json!({"cmd": "shutdown", "auth_token": tok})).await;
    assert!(r["ok"].as_bool().unwrap());

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        cb.try_read_line().await.is_none(),
        "sibling connection should be closed after shutdown"
    );
}

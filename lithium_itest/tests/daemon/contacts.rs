// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#[path = "common.rs"]
mod common;
use common::*;

#[tokio::test]
async fn test_accept_commitment_invalid() {
    let srv = TestServer::start().await;
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("badinv")).await;

    let r = c.send(json!({"cmd": "accept_commitment", "commitment": "not-a-real-commitment", "label": "X", "auth_token": tok})).await;
    assert_eq!(r["error"].as_str().unwrap(), "invalid_commitment");
}

#[tokio::test]
async fn test_contact_send_unknown_contact() {
    let srv = TestServer::start().await;
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("sndunk")).await;

    let r = c.send(json!({"cmd": "contact_send", "contact_id": "bb".repeat(32), "plaintext": "hi", "auth_token": tok})).await;
    assert_eq!(r["error"].as_str().unwrap(), "contact_not_found");
}

#[tokio::test]
async fn test_contact_forget_twice() {
    let srv = TestServer::start().await;
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("fgt2x")).await;

    let inv = c
        .send(json!({"cmd": "create_invite", "auth_token": tok}))
        .await;
    let cid = inv["result"]["contact_id"].as_str().unwrap().to_owned();

    let r1 = c
        .send(json!({"cmd": "contact_forget", "contact_id": cid, "auth_token": tok}))
        .await;
    assert!(r1["ok"].as_bool().unwrap());

    let r2 = c
        .send(json!({"cmd": "contact_forget", "contact_id": cid, "auth_token": tok}))
        .await;
    assert_eq!(r2["error"].as_str().unwrap(), "contact_not_found");
}

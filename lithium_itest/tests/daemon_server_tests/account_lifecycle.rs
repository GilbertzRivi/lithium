// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#[path = "common.rs"]
mod common;
use common::*;

#[tokio::test]
async fn test_delete_account_resets_to_first_run() {
    let srv = TestServer::start().await;
    let d = start_daemon().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("delfr")).await;

    let r = c
        .send(json!({"cmd": "delete_account", "auth_token": tok}))
        .await;
    assert!(r["ok"].as_bool().unwrap(), "{:?}", r);

    let ping = c.send(json!({"cmd": "ping"})).await;
    assert!(
        ping["result"]["status"]["first_run"].as_bool().unwrap(),
        "{:?}",
        ping
    );
}

#[tokio::test]
async fn test_delete_account_invalidates_session_token() {
    let srv = TestServer::start().await;
    let d = start_daemon().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("deliv")).await;

    c.send(json!({"cmd": "delete_account", "auth_token": tok}))
        .await;

    // delete_account wipes local state, which locks the keystore and clears the session.
    let r = c
        .send(json!({"cmd": "contacts_list", "auth_token": tok}))
        .await;
    assert_eq!(r["error"].as_str().unwrap(), "ipc_auth_required", "{:?}", r);
}

#[tokio::test]
async fn test_handle_freed_after_delete() {
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let handle = unique_handle("freed");
    let tok_a = full_setup(&mut ca, &srv, &handle).await;

    let del = ca
        .send(json!({"cmd": "delete_account", "auth_token": tok_a}))
        .await;
    assert!(del["ok"].as_bool().unwrap(), "{:?}", del);

    let tok_b = full_setup(&mut cb, &srv, &handle).await;
    let ping = cb.send(json!({"cmd": "ping", "auth_token": tok_b})).await;
    assert_eq!(ping["result"]["ui_state"].as_str().unwrap(), "ready");
}

#[tokio::test]
async fn test_register_taken_handle_is_indistinguishable() {
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let handle = unique_handle("taken");
    full_setup(&mut ca, &srv, &handle).await;

    cb.send(json!({"cmd": "set_server_url", "url": format!("http://{}", srv.addr)}))
        .await;
    cb.send(json!({"cmd": "set_server_identity", "data": hex::encode(build_server_identity(&srv.bootstrap))}))
        .await;
    let r = cb
        .send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
        .await;
    let tok_b = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();
    cb.send(json!({"cmd": "set_credentials", "handler": &handle, "password": ACCT_PASS, "auth_token": tok_b}))
        .await;

    let reg = cb
        .send(json!({"cmd": "register", "auth_token": tok_b}))
        .await;
    assert!(reg["ok"].as_bool().unwrap_or(false), "{:?}", reg);
    assert!(
        reg["result"]["capability"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "taken handle must still yield a throwaway capability: {:?}",
        reg
    );
}

#[tokio::test]
async fn test_send_to_deleted_peer_succeeds_server_side() {
    // The server stores messages by mailbox hash without validating recipient account existence.
    // B can still send to A's mailbox after A deletes their account; the ciphertext sits orphaned.
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("dlpeer_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("dlpeer_b")).await;
    let (_cid_a, cid_b) = connect_pair(&mut ca, &tok_a, &mut cb, &tok_b).await;

    let del = ca
        .send(json!({"cmd": "delete_account", "auth_token": tok_a}))
        .await;
    assert!(del["ok"].as_bool().unwrap(), "{:?}", del);

    let r = cb
        .send(json!({"cmd": "contact_send", "contact_id": cid_b, "plaintext": "orphan", "auth_token": tok_b}))
        .await;
    assert!(r["ok"].as_bool().unwrap(), "{:?}", r);
}

#[path = "common.rs"]
mod common;
use common::*;

#[tokio::test]
async fn test_server_url_survives_restart() {
    let data_dir = tempfile::tempdir().expect("tempdir");

    let d = DaemonProcess::start_in(data_dir.path()).await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let r = c
        .send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"}))
        .await;
    assert!(r["ok"].as_bool().unwrap());
    drop(d);

    let d2 = DaemonProcess::start_in(data_dir.path()).await;
    let mut c2 = IpcClient::connect(&d2.socket_path).await;
    assert!(
        c2.send(json!({"cmd": "ping"})).await["result"]["status"]["has_server_url"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn test_server_identity_survives_restart() {
    let srv = TestServer::start().await;
    let data_dir = tempfile::tempdir().expect("tempdir");

    let d = DaemonProcess::start_in(data_dir.path()).await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let r = c.send(json!({"cmd": "set_server_identity", "data": hex::encode(build_server_identity(&srv.bootstrap))})).await;
    assert!(r["ok"].as_bool().unwrap());
    drop(d);

    let d2 = DaemonProcess::start_in(data_dir.path()).await;
    let mut c2 = IpcClient::connect(&d2.socket_path).await;
    assert!(
        c2.send(json!({"cmd": "ping"})).await["result"]["status"]["has_server_identity"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn test_registered_state_after_restart() {
    let srv = TestServer::start().await;
    let data_dir = tempfile::tempdir().expect("tempdir");

    let d = DaemonProcess::start_in(data_dir.path()).await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    full_setup(&mut c, &srv, &unique_handle("rsrt")).await;
    drop(d);

    let d2 = DaemonProcess::start_in(data_dir.path()).await;
    let mut c2 = IpcClient::connect(&d2.socket_path).await;
    let r = c2
        .send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
        .await;
    assert!(r["ok"].as_bool().unwrap(), "{:?}", r);

    let ping = c2.send(json!({"cmd": "ping"})).await;
    assert!(
        ping["result"]["status"]["is_registered_on_disk"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !ping["result"]["status"]["needs_register"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !ping["result"]["status"]["has_credentials"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        ping["result"]["ui_state"].as_str().unwrap(),
        "needs_credentials"
    );
}

#[tokio::test]
async fn test_pending_invite_contact_survives_restart() {
    let srv = TestServer::start().await;
    let data_dir = tempfile::tempdir().expect("tempdir");

    let handler = unique_handle("pinvr");
    let d = DaemonProcess::start_in(data_dir.path()).await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &handler).await;

    let inv = c
        .send(json!({"cmd": "create_invite", "auth_token": tok}))
        .await;
    assert!(inv["ok"].as_bool().unwrap(), "{:?}", inv);
    let cid = inv["result"]["contact_id"].as_str().unwrap().to_owned();
    drop(d);

    let d2 = DaemonProcess::start_in(data_dir.path()).await;
    let mut c2 = IpcClient::connect(&d2.socket_path).await;
    let r = c2
        .send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
        .await;
    assert!(r["ok"].as_bool().unwrap(), "{:?}", r);
    let tok2 = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();
    // account credentials are in-memory only; must be re-supplied after each keystore unlock
    c2.send(json!({"cmd": "set_credentials", "handler": handler, "password": ACCT_PASS, "auth_token": tok2})).await;
    let us = c2
        .send(json!({"cmd": "unlock_storage", "auth_token": tok2}))
        .await;
    assert!(us["ok"].as_bool().unwrap(), "{:?}", us);

    let list = c2
        .send(json!({"cmd": "contacts_list", "auth_token": tok2}))
        .await;
    let contacts = list["result"]["contacts"].as_array().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0]["contact_id"].as_str().unwrap(), cid);
    // invite was created but not accepted — peer_set must be false
    assert!(!contacts[0]["peer_set"].as_bool().unwrap());
}

#[tokio::test]
async fn test_received_message_survives_restart() {
    let srv = TestServer::start().await;
    let data_dir_b = tempfile::tempdir().expect("tempdir");

    let da = DaemonProcess::start().await;
    let db = DaemonProcess::start_in(data_dir_b.path()).await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let handler_b = unique_handle("msgrst_b");
    let tok_a = full_setup(&mut ca, &srv, &unique_handle("msgrst_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &handler_b).await;

    let inv = ca
        .send(json!({"cmd": "create_invite", "auth_token": tok_a}))
        .await;
    let cid_a = inv["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_a = inv["result"]["code"].as_str().unwrap().to_owned();

    let acc_b = cb
        .send(json!({"cmd": "accept_invite", "code": code_a, "label": "A", "auth_token": tok_b}))
        .await;
    let cid_b = acc_b["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_b = acc_b["result"]["my_code"].as_str().unwrap().to_owned();

    ca.send(json!({"cmd": "accept_invite", "code": code_b, "contact_id": cid_a, "label": "B", "auth_token": tok_a})).await;

    ca.send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": "persisted", "auth_token": tok_a})).await;

    // B fetches — message is written to B's local SQLite and deleted from server
    let fetch = cb
        .send(json!({"cmd": "contact_fetch", "contact_id": cid_b, "auth_token": tok_b}))
        .await;
    assert!(fetch["ok"].as_bool().unwrap(), "{:?}", fetch);
    assert_eq!(fetch["result"]["messages"].as_array().unwrap().len(), 1);
    drop(db);

    let db2 = DaemonProcess::start_in(data_dir_b.path()).await;
    let mut cb2 = IpcClient::connect(&db2.socket_path).await;
    let r = cb2
        .send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
        .await;
    assert!(r["ok"].as_bool().unwrap(), "{:?}", r);
    let tok_b2 = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();
    cb2.send(json!({"cmd": "set_credentials", "handler": handler_b, "password": ACCT_PASS, "auth_token": tok_b2})).await;
    let us = cb2
        .send(json!({"cmd": "unlock_storage", "auth_token": tok_b2}))
        .await;
    assert!(us["ok"].as_bool().unwrap(), "{:?}", us);

    let msgs = cb2
        .send(json!({"cmd": "messages_list", "contact_id": cid_b, "auth_token": tok_b2}))
        .await;
    assert!(msgs["ok"].as_bool().unwrap(), "{:?}", msgs);
    let arr = msgs["result"]["messages"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["text"].as_str().unwrap(), "persisted");
    assert_eq!(arr[0]["direction"].as_str().unwrap(), "in");
}

#[tokio::test]
async fn test_wipe_local_then_restart_is_clean() {
    let data_dir = tempfile::tempdir().expect("tempdir");

    let d = DaemonProcess::start_in(data_dir.path()).await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"}))
        .await;
    let r = c
        .send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
        .await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();
    c.send(json!({"cmd": "wipe_local", "auth_token": tok}))
        .await;
    drop(d);

    let d2 = DaemonProcess::start_in(data_dir.path()).await;
    let mut c2 = IpcClient::connect(&d2.socket_path).await;
    let ping = c2.send(json!({"cmd": "ping"})).await;
    assert!(ping["result"]["status"]["first_run"].as_bool().unwrap());
}

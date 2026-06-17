#[path = "common.rs"]
mod common;
use common::*;

#[tokio::test]
async fn test_bad_json_returns_error_connection_survives() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    c.send_raw("{not valid json}\n").await;
    let raw = c.try_read_line().await.expect("expected bad_json response");
    let r: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(r["error"].as_str().unwrap(), "bad_json");
    assert_eq!(r["id"].as_u64().unwrap(), 0);

    assert!(
        c.send(json!({"cmd": "ping"})).await["ok"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn test_repeated_bad_json_does_not_crash_daemon() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    for _ in 0..30 {
        c.send_raw("{garbage}\n").await;
        let raw = c.try_read_line().await.expect("expected response");
        let r: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(r["error"].as_str().unwrap(), "bad_json");
    }

    assert!(
        c.send(json!({"cmd": "ping"})).await["ok"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn test_empty_lines_are_skipped() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    c.send_raw("\n\n   \n").await;
    assert!(
        c.send(json!({"cmd": "ping"})).await["ok"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn test_request_id_echoed() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    let r1 = c.send(json!({"cmd": "ping"})).await;
    let r2 = c.send(json!({"cmd": "ping"})).await;
    assert_eq!(r1["id"].as_u64().unwrap(), 1);
    assert_eq!(r2["id"].as_u64().unwrap(), 2);
}

#[tokio::test]
async fn test_max_connections_enforced() {
    // The second connection is accepted at OS level but the daemon drops the stream
    // when the semaphore is exhausted — client sees EOF immediately.
    let d = DaemonProcess::start_max_conn(1).await;

    let mut c1 = IpcClient::connect(&d.socket_path).await;
    assert!(
        c1.send(json!({"cmd": "ping"})).await["ok"]
            .as_bool()
            .unwrap()
    );

    let mut c2 = IpcClient::connect(&d.socket_path).await;
    assert!(
        c2.try_read_line().await.is_none(),
        "expected EOF on second connection"
    );
}

#[tokio::test]
async fn test_auth_required_commands_without_token() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    for cmd in [
        json!({"cmd": "lock_keystore"}),
        json!({"cmd": "register"}),
        json!({"cmd": "unlock_storage"}),
        json!({"cmd": "contacts_list"}),
        json!({"cmd": "wipe_local"}),
        json!({"cmd": "shutdown"}),
        json!({"cmd": "delete_account"}),
    ] {
        let r = c.send(cmd.clone()).await;
        assert_eq!(
            r["error"].as_str().unwrap(),
            "ipc_auth_required",
            "{:?}",
            cmd
        );
    }
}

#[tokio::test]
async fn test_empty_auth_token_treated_as_missing() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    let r = c.send(json!({"cmd": "wipe_local", "auth_token": ""})).await;
    assert_eq!(r["error"].as_str().unwrap(), "ipc_auth_required");
}

#[tokio::test]
async fn test_wrong_token_rejected() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"}))
        .await;
    c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
        .await;

    let r = c
        .send(json!({"cmd": "lock_keystore", "auth_token": "00".repeat(32)}))
        .await;
    assert_eq!(r["error"].as_str().unwrap(), "ipc_auth_failed");
}

#[tokio::test]
async fn test_token_invalidated_after_lock() {
    // After lock, session_token is None -> ipc_auth_required, not ipc_auth_failed.
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"}))
        .await;
    let r = c
        .send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
        .await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    c.send(json!({"cmd": "lock_keystore", "auth_token": tok}))
        .await;

    let r2 = c
        .send(json!({"cmd": "wipe_local", "auth_token": tok}))
        .await;
    assert_eq!(r2["error"].as_str().unwrap(), "ipc_auth_required");
}

#[tokio::test]
async fn test_token_valid_from_reconnected_same_process() {
    // On Linux the token is bound to UID+PID of the issuing connection.
    // Reconnecting from the same process keeps the same PID so the token must still work.
    let d = DaemonProcess::start().await;

    let tok = {
        let mut c = IpcClient::connect(&d.socket_path).await;
        c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"}))
            .await;
        let r = c
            .send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
            .await;
        r["result"]["ipc_auth_token"].as_str().unwrap().to_owned()
    };

    let mut c2 = IpcClient::connect(&d.socket_path).await;
    let r = c2
        .send(json!({"cmd": "lock_keystore", "auth_token": tok}))
        .await;
    assert!(r["ok"].as_bool().unwrap());
}

#[tokio::test]
async fn test_unlock_fails_without_server_url() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    let r = c
        .send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
        .await;
    assert_eq!(r["error"].as_str().unwrap(), "server_url_not_set");
}

#[tokio::test]
async fn test_unlock_with_weak_password_rejected() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"}))
        .await;

    for bad in [
        "short",
        "alllowercase1!",
        "ALLUPPERCASE1!",
        "NoSpecialChar1",
        "NoDigit!",
    ] {
        let r = c
            .send(json!({"cmd": "unlock_keystore", "data_password": bad}))
            .await;
        assert_eq!(
            r["error"].as_str().unwrap(),
            "bad_data_password",
            "password: {:?}",
            bad
        );
    }
}

#[tokio::test]
async fn test_second_unlock_wrong_password_rejected() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"}))
        .await;
    c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
        .await;

    let r = c
        .send(json!({"cmd": "unlock_keystore", "data_password": "WrongPass123!"}))
        .await;
    assert_eq!(r["error"].as_str().unwrap(), "bad_data_password");
}

#[tokio::test]
async fn test_same_data_and_account_password_rejected() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"}))
        .await;
    let r = c
        .send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
        .await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let r = c.send(json!({"cmd": "set_credentials", "handler": "user", "password": DATA_PASS, "auth_token": tok})).await;
    assert_eq!(r["error"].as_str().unwrap(), "passwords_must_be_distinct");
}

#[tokio::test]
async fn test_set_invalid_url_rejected() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    for bad in ["not a url", ":::bad", "just_text"] {
        let r = c.send(json!({"cmd": "set_server_url", "url": bad})).await;
        assert_eq!(
            r["error"].as_str().unwrap(),
            "invalid_url",
            "url: {:?}",
            bad
        );
    }
}

#[tokio::test]
async fn test_set_server_identity_bad_hex() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    let r = c
        .send(json!({"cmd": "set_server_identity", "data": "not-hex!!"}))
        .await;
    assert_eq!(r["error"].as_str().unwrap(), "server_identity_bad_hex");
}

#[tokio::test]
async fn test_set_server_identity_bad_magic() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    let r = c
        .send(json!({"cmd": "set_server_identity", "data": hex::encode(b"WRONGMAGIC")}))
        .await;
    assert!(
        r["error"]
            .as_str()
            .unwrap()
            .starts_with("server_identity_invalid:"),
        "{:?}",
        r
    );
}

#[tokio::test]
async fn test_set_valid_server_identity_accepted() {
    let srv = TestServer::start().await;
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    let r = c.send(json!({"cmd": "set_server_identity", "data": hex::encode(build_server_identity(&srv.bootstrap))})).await;
    assert!(r["ok"].as_bool().unwrap());
    assert!(
        c.send(json!({"cmd": "ping"})).await["result"]["status"]["has_server_identity"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn test_contacts_list_requires_storage_unlock() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"}))
        .await;
    let r = c
        .send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS}))
        .await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let r = c
        .send(json!({"cmd": "contacts_list", "auth_token": tok}))
        .await;
    assert_eq!(r["error"].as_str().unwrap(), "storage_locked");
}

#[tokio::test]
async fn test_invalid_contact_id_format() {
    let srv = TestServer::start().await;
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("badcid")).await;

    for bad in ["not-hex", "xyz!", "gg"] {
        let r = c
            .send(json!({"cmd": "contact_forget", "contact_id": bad, "auth_token": tok}))
            .await;
        assert_eq!(
            r["error"].as_str().unwrap(),
            "invalid_contact_id",
            "contact_id: {:?}",
            bad
        );
    }
}

#[tokio::test]
async fn test_contact_forget_unknown_id() {
    let srv = TestServer::start().await;
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("fgtunk")).await;

    let r = c
        .send(json!({"cmd": "contact_forget", "contact_id": "aa".repeat(32), "auth_token": tok}))
        .await;
    assert_eq!(r["error"].as_str().unwrap(), "contact_not_found");
}

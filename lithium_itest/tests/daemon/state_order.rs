#[path = "common.rs"]
mod common;
use common::*;

#[tokio::test]
async fn test_register_without_credentials_rejected() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;
    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let r = c.send(json!({"cmd": "register", "auth_token": tok})).await;
    assert_eq!(r["error"].as_str().unwrap(), "missing_account_credentials");
}

#[tokio::test]
async fn test_unlock_storage_before_register_rejected() {
    // needs_register=true on fresh install; unlock_storage must refuse until register completes.
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;
    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();
    c.send(json!({"cmd": "set_credentials", "handler": "user", "password": ACCT_PASS, "auth_token": tok})).await;

    let r = c.send(json!({"cmd": "unlock_storage", "auth_token": tok})).await;
    assert_eq!(r["error"].as_str().unwrap(), "register_required");
}

#[tokio::test]
async fn test_unlock_storage_no_session_returns_auth_required() {
    // unlock_storage requires auth. With no active session (no unlock_keystore done),
    // any token gives ipc_auth_required, not ipc_auth_failed.
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    let r = c.send(json!({"cmd": "unlock_storage", "auth_token": "aa".repeat(32)})).await;
    assert_eq!(r["error"].as_str().unwrap(), "ipc_auth_required");
}

#[tokio::test]
async fn test_create_invite_before_storage_unlock_rejected() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;
    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let r = c.send(json!({"cmd": "create_invite", "auth_token": tok})).await;
    assert_eq!(r["error"].as_str().unwrap(), "storage_locked");
}

#[tokio::test]
async fn test_contact_send_before_storage_unlock_rejected() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;
    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let r = c.send(json!({"cmd": "contact_send", "contact_id": "aa".repeat(32), "plaintext": "hello", "auth_token": tok})).await;
    assert_eq!(r["error"].as_str().unwrap(), "storage_locked");
}

#[tokio::test]
async fn test_contact_fetch_before_storage_unlock() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;
    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let r = c.send(json!({"cmd": "contact_fetch", "contact_id": "aa".repeat(32), "auth_token": tok})).await;
    assert_eq!(r["error"].as_str().unwrap(), "storage_locked");
}

#[tokio::test]
async fn test_messages_list_before_storage_unlock() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;
    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let r = c.send(json!({"cmd": "messages_list", "contact_id": "aa".repeat(32), "auth_token": tok})).await;
    assert_eq!(r["error"].as_str().unwrap(), "storage_locked");
}

#[tokio::test]
async fn test_contact_verify_emoji_before_storage_unlock() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;
    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let r = c.send(json!({"cmd": "contact_verify_emoji", "contact_id": "aa".repeat(32), "auth_token": tok})).await;
    assert_eq!(r["error"].as_str().unwrap(), "storage_locked");
}

#[tokio::test]
async fn test_set_credentials_weak_account_password() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;
    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    for bad in ["short", "alllower1!", "ALLUPPER1!", "NoDigit!", "NoSpecial1"] {
        let r = c.send(json!({"cmd": "set_credentials", "handler": "u", "password": bad, "auth_token": tok})).await;
        assert_eq!(r["error"].as_str().unwrap(), "bad_account_password", "password: {:?}", bad);
    }
}
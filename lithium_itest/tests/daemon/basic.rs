#[path = "common.rs"]
mod common;
use common::*;

#[tokio::test]
async fn test_ping_on_fresh_daemon() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    let r = c.send(json!({"cmd": "ping"})).await;
    assert!(r["ok"].as_bool().unwrap());
    assert_eq!(r["result"]["ui_state"].as_str().unwrap(), "keystore_locked");
    assert!(r["result"]["status"]["first_run"].as_bool().unwrap());
}

#[tokio::test]
async fn test_set_server_url_before_unlock() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    let r = c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;
    assert!(r["ok"].as_bool().unwrap());

    assert!(c.send(json!({"cmd": "ping"})).await["result"]["status"]["has_server_url"].as_bool().unwrap());
}

#[tokio::test]
async fn test_unlock_keystore_local() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;

    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    assert!(r["ok"].as_bool().unwrap(), "{:?}", r);
    assert_eq!(r["result"]["ipc_auth_token"].as_str().unwrap().len(), 64);

    assert_eq!(c.send(json!({"cmd": "ping"})).await["result"]["ui_state"].as_str().unwrap(), "needs_credentials");
}

#[tokio::test]
async fn test_lock_after_unlock() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;
    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let r = c.send(json!({"cmd": "lock_keystore", "auth_token": tok})).await;
    assert!(r["ok"].as_bool().unwrap());

    assert_eq!(c.send(json!({"cmd": "ping"})).await["result"]["ui_state"].as_str().unwrap(), "keystore_locked");
}

#[tokio::test]
async fn test_set_credentials_after_unlock() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;
    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let r = c.send(json!({"cmd": "set_credentials", "handler": "user", "password": ACCT_PASS, "auth_token": tok})).await;
    assert!(r["ok"].as_bool().unwrap());
    assert!(r["result"]["stored"].as_bool().unwrap());
}

#[tokio::test]
async fn test_wipe_local_clears_state() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;
    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let r = c.send(json!({"cmd": "wipe_local", "auth_token": tok})).await;
    assert!(r["ok"].as_bool().unwrap());
    assert!(r["result"]["wiped"].as_bool().unwrap());

    assert_eq!(c.send(json!({"cmd": "ping"})).await["result"]["ui_state"].as_str().unwrap(), "keystore_locked");
}

#[tokio::test]
async fn test_shutdown_exits_process() {
    use std::time::Duration;
    let mut d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    c.send(json!({"cmd": "set_server_url", "url": "http://127.0.0.1:19999"})).await;
    let r = c.send(json!({"cmd": "unlock_keystore", "data_password": DATA_PASS})).await;
    let tok = r["result"]["ipc_auth_token"].as_str().unwrap().to_owned();

    let r = c.send(json!({"cmd": "shutdown", "auth_token": tok})).await;
    assert!(r["ok"].as_bool().unwrap());

    let mut child = d.take_child();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(child.try_wait().expect("try_wait").is_some(), "daemon did not exit");
    let _ = child.wait();
}
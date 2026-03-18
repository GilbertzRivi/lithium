#[path = "common.rs"]
mod common;
use common::*;

#[tokio::test]
async fn test_full_setup_reaches_ready_state() {
    let srv = TestServer::start().await;
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    let tok = full_setup(&mut c, &srv, &unique_handle("dreg")).await;

    let p = c.send(json!({"cmd": "ping", "auth_token": tok})).await;
    assert_eq!(p["result"]["ui_state"].as_str().unwrap(), "ready");
    assert!(p["result"]["status"]["is_registered_on_disk"].as_bool().unwrap());
}

#[tokio::test]
async fn test_contacts_list_empty_after_setup() {
    let srv = TestServer::start().await;
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("dcl")).await;

    let r = c.send(json!({"cmd": "contacts_list", "auth_token": tok})).await;
    assert!(r["ok"].as_bool().unwrap());
    assert_eq!(r["result"]["contacts"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_create_invite_returns_code_and_contact_id() {
    let srv = TestServer::start().await;
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("dinv")).await;

    let r = c.send(json!({"cmd": "create_invite", "auth_token": tok})).await;
    assert!(r["ok"].as_bool().unwrap(), "{:?}", r);
    assert_eq!(r["result"]["contact_id"].as_str().unwrap().len(), 64);
    assert!(!r["result"]["code"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_two_daemon_invite_exchange_and_message() {
    let srv = TestServer::start().await;
    let da = DaemonProcess::start().await;
    let db = DaemonProcess::start().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("msg_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("msg_b")).await;

    let inv = ca.send(json!({"cmd": "create_invite", "auth_token": tok_a})).await;
    assert!(inv["ok"].as_bool().unwrap(), "{:?}", inv);
    let cid_a  = inv["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_a = inv["result"]["code"].as_str().unwrap().to_owned();

    let acc_b = cb.send(json!({"cmd": "accept_invite", "code": code_a, "label": "Alice", "auth_token": tok_b})).await;
    assert!(acc_b["ok"].as_bool().unwrap(), "{:?}", acc_b);
    let cid_b  = acc_b["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_b = acc_b["result"]["my_code"].as_str().unwrap().to_owned();

    let acc_a = ca.send(json!({"cmd": "accept_invite", "code": code_b, "contact_id": cid_a, "label": "Bob", "auth_token": tok_a})).await;
    assert!(acc_a["ok"].as_bool().unwrap(), "{:?}", acc_a);

    let send = ca.send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": "hello from A", "auth_token": tok_a})).await;
    assert!(send["ok"].as_bool().unwrap(), "{:?}", send);

    let fetch = cb.send(json!({"cmd": "contact_fetch", "contact_id": cid_b, "auth_token": tok_b})).await;
    assert!(fetch["ok"].as_bool().unwrap(), "{:?}", fetch);
    let msgs = fetch["result"]["messages"].as_array().expect("messages array");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["text"].as_str().unwrap(), "hello from A");
}
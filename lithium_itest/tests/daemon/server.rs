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
    assert!(
        p["result"]["status"]["is_registered_on_disk"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn test_contacts_list_empty_after_setup() {
    let srv = TestServer::start().await;
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("dcl")).await;

    let r = c
        .send(json!({"cmd": "contacts_list", "auth_token": tok}))
        .await;
    assert!(r["ok"].as_bool().unwrap());
    assert_eq!(r["result"]["contacts"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_create_invite_returns_commitment_and_contact_id() {
    let srv = TestServer::start().await;
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("dinv")).await;

    let r = c
        .send(json!({"cmd": "create_invite", "auth_token": tok}))
        .await;
    assert!(r["ok"].as_bool().unwrap(), "{:?}", r);
    assert_eq!(r["result"]["contact_id"].as_str().unwrap().len(), 64);
    assert_eq!(r["result"]["commitment"].as_str().unwrap().len(), 64);
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

    let inv = ca
        .send(json!({"cmd": "create_invite", "auth_token": tok_a}))
        .await;
    assert!(inv["ok"].as_bool().unwrap(), "{:?}", inv);
    let cid_a = inv["result"]["contact_id"].as_str().unwrap().to_owned();
    let commitment = inv["result"]["commitment"].as_str().unwrap().to_owned();

    let acc_b = cb
        .send(json!({"cmd": "accept_commitment", "commitment": commitment, "label": "Alice", "auth_token": tok_b}))
        .await;
    assert!(acc_b["ok"].as_bool().unwrap(), "{:?}", acc_b);
    let cid_b = acc_b["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_b = acc_b["result"]["code"].as_str().unwrap().to_owned();

    let rev = ca.send(json!({"cmd": "reveal_invite", "contact_id": cid_a, "peer_code": code_b, "label": "Bob", "auth_token": tok_a})).await;
    assert!(rev["ok"].as_bool().unwrap(), "{:?}", rev);
    let code_a = rev["result"]["code"].as_str().unwrap().to_owned();

    let fin = cb.send(json!({"cmd": "finalize_pairing", "contact_id": cid_b, "peer_code": code_a, "auth_token": tok_b})).await;
    assert!(fin["ok"].as_bool().unwrap(), "{:?}", fin);

    let send = ca.send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": "hello from A", "auth_token": tok_a})).await;
    assert!(send["ok"].as_bool().unwrap(), "{:?}", send);

    let msgs = wait_for_inbound(&mut cb, &cid_b, &tok_b, 1).await;
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["text"].as_str().unwrap(), "hello from A");
}

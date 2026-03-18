#[path = "common.rs"]
mod common;
use common::*;

#[tokio::test]
async fn test_multiple_messages_arrive_in_order() {
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("mord_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("mord_b")).await;
    let (cid_a, cid_b) = connect_pair(&mut ca, &tok_a, &mut cb, &tok_b).await;

    for text in ["first", "second", "third"] {
        let r = ca
            .send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": text, "auth_token": tok_a}))
            .await;
        assert!(r["ok"].as_bool().unwrap(), "{:?}", r);
    }

    let fetch = cb
        .send(json!({"cmd": "contact_fetch", "contact_id": cid_b, "auth_token": tok_b}))
        .await;
    assert!(fetch["ok"].as_bool().unwrap(), "{:?}", fetch);
    let msgs = fetch["result"]["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 3);
    assert_eq!(msgs[0]["text"].as_str().unwrap(), "first");
    assert_eq!(msgs[1]["text"].as_str().unwrap(), "second");
    assert_eq!(msgs[2]["text"].as_str().unwrap(), "third");
}

#[tokio::test]
async fn test_bidirectional_messaging() {
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("bidir_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("bidir_b")).await;
    let (cid_a, cid_b) = connect_pair(&mut ca, &tok_a, &mut cb, &tok_b).await;

    ca.send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": "from A", "auth_token": tok_a}))
        .await;
    cb.send(json!({"cmd": "contact_send", "contact_id": cid_b, "plaintext": "from B", "auth_token": tok_b}))
        .await;

    let fetch_b = cb
        .send(json!({"cmd": "contact_fetch", "contact_id": cid_b, "auth_token": tok_b}))
        .await;
    assert!(fetch_b["ok"].as_bool().unwrap(), "{:?}", fetch_b);
    let msgs_b = fetch_b["result"]["messages"].as_array().unwrap();
    assert_eq!(msgs_b.len(), 1);
    assert_eq!(msgs_b[0]["text"].as_str().unwrap(), "from A");

    let fetch_a = ca
        .send(json!({"cmd": "contact_fetch", "contact_id": cid_a, "auth_token": tok_a}))
        .await;
    assert!(fetch_a["ok"].as_bool().unwrap(), "{:?}", fetch_a);
    let msgs_a = fetch_a["result"]["messages"].as_array().unwrap();
    assert_eq!(msgs_a.len(), 1);
    assert_eq!(msgs_a[0]["text"].as_str().unwrap(), "from B");
}

#[tokio::test]
async fn test_contact_fetch_returns_empty_before_any_send() {
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("emp_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("emp_b")).await;
    let (_cid_a, cid_b) = connect_pair(&mut ca, &tok_a, &mut cb, &tok_b).await;

    let fetch = cb
        .send(json!({"cmd": "contact_fetch", "contact_id": cid_b, "auth_token": tok_b}))
        .await;
    assert!(fetch["ok"].as_bool().unwrap(), "{:?}", fetch);
    assert_eq!(fetch["result"]["messages"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_messages_list_shows_outbound_direction() {
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("outd_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("outd_b")).await;
    let (cid_a, _cid_b) = connect_pair(&mut ca, &tok_a, &mut cb, &tok_b).await;

    ca.send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": "outbound", "auth_token": tok_a}))
        .await;

    let list = ca
        .send(json!({"cmd": "messages_list", "contact_id": cid_a, "auth_token": tok_a}))
        .await;
    assert!(list["ok"].as_bool().unwrap(), "{:?}", list);
    let msgs = list["result"]["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["direction"].as_str().unwrap(), "out");
    assert_eq!(msgs[0]["text"].as_str().unwrap(), "outbound");
}

#[tokio::test]
async fn test_second_contact_fetch_empty_server_deleted() {
    // Server deletes messages on first fetch (one-time delivery model).
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("ots_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("ots_b")).await;
    let (cid_a, cid_b) = connect_pair(&mut ca, &tok_a, &mut cb, &tok_b).await;

    ca.send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": "once", "auth_token": tok_a}))
        .await;

    let first = cb
        .send(json!({"cmd": "contact_fetch", "contact_id": cid_b, "auth_token": tok_b}))
        .await;
    assert_eq!(first["result"]["messages"].as_array().unwrap().len(), 1);

    let second = cb
        .send(json!({"cmd": "contact_fetch", "contact_id": cid_b, "auth_token": tok_b}))
        .await;
    assert!(second["ok"].as_bool().unwrap(), "{:?}", second);
    assert_eq!(second["result"]["messages"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_messages_list_after_fetch_shows_inbound() {
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("ind_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("ind_b")).await;
    let (cid_a, cid_b) = connect_pair(&mut ca, &tok_a, &mut cb, &tok_b).await;

    ca.send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": "hello", "auth_token": tok_a}))
        .await;

    cb.send(json!({"cmd": "contact_fetch", "contact_id": cid_b, "auth_token": tok_b}))
        .await;

    let list = cb
        .send(json!({"cmd": "messages_list", "contact_id": cid_b, "auth_token": tok_b}))
        .await;
    assert!(list["ok"].as_bool().unwrap(), "{:?}", list);
    let msgs = list["result"]["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["direction"].as_str().unwrap(), "in");
    assert_eq!(msgs[0]["text"].as_str().unwrap(), "hello");
}
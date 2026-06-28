// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

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

    let msgs = wait_for_inbound(&mut cb, &cid_b, &tok_b, 3).await;
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

    let in_b = wait_for_inbound(&mut cb, &cid_b, &tok_b, 1).await;
    assert_eq!(in_b[0]["text"].as_str().unwrap(), "from A");

    let in_a = wait_for_inbound(&mut ca, &cid_a, &tok_a, 1).await;
    assert_eq!(in_a[0]["text"].as_str().unwrap(), "from B");
}

#[tokio::test]
async fn test_messages_list_empty_before_any_send() {
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("emp_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("emp_b")).await;
    let (_cid_a, cid_b) = connect_pair(&mut ca, &tok_a, &mut cb, &tok_b).await;

    // No send happened; auto-fetch must not invent inbound messages.
    let msgs = messages_now(&mut cb, &cid_b, &tok_b).await;
    assert_eq!(msgs.len(), 0);
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

    // A's own outbound is stored locally at send time, independent of the network cadence.
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
async fn test_inbound_message_not_duplicated_by_repeated_polling() {
    // Server deletes on first fetch (one-time delivery) and the daemon dedups on msg_id, so a
    // message that arrives once must stay at exactly one row no matter how often we poll.
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

    let first = wait_for_inbound(&mut cb, &cid_b, &tok_b, 1).await;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0]["text"].as_str().unwrap(), "once");

    // Give several more fetch cadences a chance to re-poll the same mailbox.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let again: Vec<_> = messages_now(&mut cb, &cid_b, &tok_b)
        .await
        .into_iter()
        .filter(|m| m["direction"].as_str() == Some("in"))
        .collect();
    assert_eq!(
        again.len(),
        1,
        "auto-fetch must not duplicate a delivered message"
    );
}

#[tokio::test]
async fn test_messages_list_shows_inbound() {
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

    let msgs = wait_for_inbound(&mut cb, &cid_b, &tok_b, 1).await;
    assert_eq!(msgs[0]["direction"].as_str().unwrap(), "in");
    assert_eq!(msgs[0]["text"].as_str().unwrap(), "hello");
}

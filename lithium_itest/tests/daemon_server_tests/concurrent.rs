#[path = "common.rs"]
mod common;
use common::*;

#[tokio::test]
async fn test_two_senders_to_same_recipient_both_delivered() {
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let dc = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;
    let mut cc = IpcClient::connect(&dc.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("two_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("two_b")).await;
    let tok_c = full_setup(&mut cc, &srv, &unique_handle("two_c")).await;

    // B creates invite, A accepts — A gets cid_a_b (A's slot for B), B keeps cid_b_a.
    let inv_b = cb
        .send(json!({"cmd": "create_invite", "auth_token": tok_b}))
        .await;
    assert!(inv_b["ok"].as_bool().unwrap(), "{:?}", inv_b);
    let cid_b_a = inv_b["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_b = inv_b["result"]["code"].as_str().unwrap().to_owned();

    let acc_a_b = ca
        .send(json!({"cmd": "accept_invite", "code": code_b, "label": "B", "auth_token": tok_a}))
        .await;
    assert!(acc_a_b["ok"].as_bool().unwrap(), "{:?}", acc_a_b);
    let cid_a_b = acc_a_b["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_a_for_b = acc_a_b["result"]["my_code"].as_str().unwrap().to_owned();

    let fin_b = cb
        .send(json!({"cmd": "accept_invite", "code": code_a_for_b, "contact_id": cid_b_a, "label": "A", "auth_token": tok_b}))
        .await;
    assert!(fin_b["ok"].as_bool().unwrap(), "{:?}", fin_b);

    // C creates invite, A accepts.
    let inv_c = cc
        .send(json!({"cmd": "create_invite", "auth_token": tok_c}))
        .await;
    assert!(inv_c["ok"].as_bool().unwrap(), "{:?}", inv_c);
    let cid_c_a = inv_c["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_c = inv_c["result"]["code"].as_str().unwrap().to_owned();

    let acc_a_c = ca
        .send(json!({"cmd": "accept_invite", "code": code_c, "label": "C", "auth_token": tok_a}))
        .await;
    assert!(acc_a_c["ok"].as_bool().unwrap(), "{:?}", acc_a_c);
    let cid_a_c = acc_a_c["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_a_for_c = acc_a_c["result"]["my_code"].as_str().unwrap().to_owned();

    let fin_c = cc
        .send(json!({"cmd": "accept_invite", "code": code_a_for_c, "contact_id": cid_c_a, "label": "A", "auth_token": tok_c}))
        .await;
    assert!(fin_c["ok"].as_bool().unwrap(), "{:?}", fin_c);

    // B and C each send a message to A.
    let r_b = cb
        .send(json!({"cmd": "contact_send", "contact_id": cid_b_a, "plaintext": "from B", "auth_token": tok_b}))
        .await;
    assert!(r_b["ok"].as_bool().unwrap(), "{:?}", r_b);

    let r_c = cc
        .send(json!({"cmd": "contact_send", "contact_id": cid_c_a, "plaintext": "from C", "auth_token": tok_c}))
        .await;
    assert!(r_c["ok"].as_bool().unwrap(), "{:?}", r_c);

    // A fetches from each contact independently.
    let fetch_b = ca
        .send(json!({"cmd": "contact_fetch", "contact_id": cid_a_b, "auth_token": tok_a}))
        .await;
    assert!(fetch_b["ok"].as_bool().unwrap(), "{:?}", fetch_b);
    assert_eq!(
        fetch_b["result"]["messages"][0]["text"].as_str().unwrap(),
        "from B"
    );

    let fetch_c = ca
        .send(json!({"cmd": "contact_fetch", "contact_id": cid_a_c, "auth_token": tok_a}))
        .await;
    assert!(fetch_c["ok"].as_bool().unwrap(), "{:?}", fetch_c);
    assert_eq!(
        fetch_c["result"]["messages"][0]["text"].as_str().unwrap(),
        "from C"
    );
}

#[tokio::test]
async fn test_send_fetch_cycles_accumulate_correctly() {
    // Each contact_fetch is one-time on the server; subsequent sends land in the next window.
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("cyc_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("cyc_b")).await;
    let (cid_a, cid_b) = connect_pair(&mut ca, &tok_a, &mut cb, &tok_b).await;

    ca.send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": "msg1", "auth_token": tok_a}))
        .await;
    let f1 = cb
        .send(json!({"cmd": "contact_fetch", "contact_id": cid_b, "auth_token": tok_b}))
        .await;
    assert_eq!(f1["result"]["messages"].as_array().unwrap().len(), 1);
    assert_eq!(
        f1["result"]["messages"][0]["text"].as_str().unwrap(),
        "msg1"
    );

    ca.send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": "msg2", "auth_token": tok_a}))
        .await;
    let f2 = cb
        .send(json!({"cmd": "contact_fetch", "contact_id": cid_b, "auth_token": tok_b}))
        .await;
    assert_eq!(f2["result"]["messages"].as_array().unwrap().len(), 1);
    assert_eq!(
        f2["result"]["messages"][0]["text"].as_str().unwrap(),
        "msg2"
    );
}

#[tokio::test]
async fn test_messages_list_accumulates_across_fetches() {
    // Each contact_fetch stores messages locally; messages_list reflects all of them.
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("acc_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("acc_b")).await;
    let (cid_a, cid_b) = connect_pair(&mut ca, &tok_a, &mut cb, &tok_b).await;

    ca.send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": "first", "auth_token": tok_a}))
        .await;
    cb.send(json!({"cmd": "contact_fetch", "contact_id": cid_b, "auth_token": tok_b}))
        .await;

    ca.send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": "second", "auth_token": tok_a}))
        .await;
    cb.send(json!({"cmd": "contact_fetch", "contact_id": cid_b, "auth_token": tok_b}))
        .await;

    let list = cb
        .send(json!({"cmd": "messages_list", "contact_id": cid_b, "auth_token": tok_b}))
        .await;
    assert!(list["ok"].as_bool().unwrap(), "{:?}", list);
    assert_eq!(list["result"]["messages"].as_array().unwrap().len(), 2);
}

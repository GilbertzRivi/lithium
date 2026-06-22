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
    let commitment_b = inv_b["result"]["commitment"].as_str().unwrap().to_owned();

    let acc_a_b = ca
        .send(json!({"cmd": "accept_commitment", "commitment": commitment_b, "label": "B", "auth_token": tok_a}))
        .await;
    assert!(acc_a_b["ok"].as_bool().unwrap(), "{:?}", acc_a_b);
    let cid_a_b = acc_a_b["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_a_for_b = acc_a_b["result"]["code"].as_str().unwrap().to_owned();

    let rev_b = cb
        .send(json!({"cmd": "reveal_invite", "contact_id": cid_b_a, "peer_code": code_a_for_b, "label": "A", "auth_token": tok_b}))
        .await;
    assert!(rev_b["ok"].as_bool().unwrap(), "{:?}", rev_b);
    let code_b = rev_b["result"]["code"].as_str().unwrap().to_owned();

    let fin_b = ca
        .send(json!({"cmd": "finalize_pairing", "contact_id": cid_a_b, "peer_code": code_b, "auth_token": tok_a}))
        .await;
    assert!(fin_b["ok"].as_bool().unwrap(), "{:?}", fin_b);

    // C creates invite, A accepts.
    let inv_c = cc
        .send(json!({"cmd": "create_invite", "auth_token": tok_c}))
        .await;
    assert!(inv_c["ok"].as_bool().unwrap(), "{:?}", inv_c);
    let cid_c_a = inv_c["result"]["contact_id"].as_str().unwrap().to_owned();
    let commitment_c = inv_c["result"]["commitment"].as_str().unwrap().to_owned();

    let acc_a_c = ca
        .send(json!({"cmd": "accept_commitment", "commitment": commitment_c, "label": "C", "auth_token": tok_a}))
        .await;
    assert!(acc_a_c["ok"].as_bool().unwrap(), "{:?}", acc_a_c);
    let cid_a_c = acc_a_c["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_a_for_c = acc_a_c["result"]["code"].as_str().unwrap().to_owned();

    let rev_c = cc
        .send(json!({"cmd": "reveal_invite", "contact_id": cid_c_a, "peer_code": code_a_for_c, "label": "A", "auth_token": tok_c}))
        .await;
    assert!(rev_c["ok"].as_bool().unwrap(), "{:?}", rev_c);
    let code_c = rev_c["result"]["code"].as_str().unwrap().to_owned();

    let fin_c = ca
        .send(json!({"cmd": "finalize_pairing", "contact_id": cid_a_c, "peer_code": code_c, "auth_token": tok_a}))
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

    // A auto-fetches each contact independently via background polling.
    let in_b = wait_for_inbound(&mut ca, &cid_a_b, &tok_a, 1).await;
    assert_eq!(in_b[0]["text"].as_str().unwrap(), "from B");

    let in_c = wait_for_inbound(&mut ca, &cid_a_c, &tok_a, 1).await;
    assert_eq!(in_c[0]["text"].as_str().unwrap(), "from C");
}

#[tokio::test]
async fn test_send_fetch_cycles_accumulate_correctly() {
    // Messages sent across rotations all arrive via auto-fetch and accumulate locally in order.
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
    let in1 = wait_for_inbound(&mut cb, &cid_b, &tok_b, 1).await;
    assert_eq!(in1[0]["text"].as_str().unwrap(), "msg1");

    ca.send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": "msg2", "auth_token": tok_a}))
        .await;
    let in2 = wait_for_inbound(&mut cb, &cid_b, &tok_b, 2).await;
    assert_eq!(in2[1]["text"].as_str().unwrap(), "msg2");
}

#[tokio::test]
async fn test_messages_list_accumulates_across_sends() {
    // Auto-fetch stores each message locally; messages_list reflects all of them.
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
    ca.send(json!({"cmd": "contact_send", "contact_id": cid_a, "plaintext": "second", "auth_token": tok_a}))
        .await;

    let msgs = wait_for_inbound(&mut cb, &cid_b, &tok_b, 2).await;
    assert_eq!(msgs.len(), 2);
}

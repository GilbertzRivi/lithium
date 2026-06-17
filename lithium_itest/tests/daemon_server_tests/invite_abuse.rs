#[path = "common.rs"]
mod common;
use common::*;

#[tokio::test]
async fn test_contact_send_to_pending_invite_fails() {
    let srv = TestServer::start().await;
    let d = start_daemon().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("psnd")).await;

    let inv = c
        .send(json!({"cmd": "create_invite", "auth_token": tok}))
        .await;
    assert!(inv["ok"].as_bool().unwrap(), "{:?}", inv);
    let cid = inv["result"]["contact_id"].as_str().unwrap().to_owned();

    // Peer has not accepted yet — no public key material to encrypt for.
    let r = c
        .send(json!({"cmd": "contact_send", "contact_id": cid, "plaintext": "early", "auth_token": tok}))
        .await;
    assert_eq!(r["error"].as_str().unwrap(), "crypto_error", "{:?}", r);
}

#[tokio::test]
async fn test_contact_fetch_on_pending_invite_fails() {
    // ensure_mailbox_state requires peer.x_pub which doesn't exist until the invite is accepted.
    let srv = TestServer::start().await;
    let d = start_daemon().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("pfch")).await;

    let inv = c
        .send(json!({"cmd": "create_invite", "auth_token": tok}))
        .await;
    let cid = inv["result"]["contact_id"].as_str().unwrap().to_owned();

    let r = c
        .send(json!({"cmd": "contact_fetch", "contact_id": cid, "auth_token": tok}))
        .await;
    assert_eq!(r["error"].as_str().unwrap(), "crypto_error", "{:?}", r);
}

#[tokio::test]
async fn test_accept_invite_with_unknown_contact_id_fails() {
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("ucid_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("ucid_b")).await;

    let inv = ca
        .send(json!({"cmd": "create_invite", "auth_token": tok_a}))
        .await;
    let code_a = inv["result"]["code"].as_str().unwrap().to_owned();

    // B provides a contact_id that does not exist in B's local DB.
    let r = cb
        .send(json!({
            "cmd": "accept_invite",
            "code": code_a,
            "contact_id": "cc".repeat(32),
            "label": "A",
            "auth_token": tok_b
        }))
        .await;
    assert_eq!(r["error"].as_str().unwrap(), "contact_not_found", "{:?}", r);
}

#[tokio::test]
async fn test_peer_takeover_rejected() {
    // Invite codes are self-contained crypto — two different peers can accept the same code.
    // Once A finalizes with B's identity, a subsequent finalization attempt using C's identity
    // must be rejected so C cannot take over A's established contact slot.
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let dc = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;
    let mut cc = IpcClient::connect(&dc.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("ptk_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("ptk_b")).await;
    let tok_c = full_setup(&mut cc, &srv, &unique_handle("ptk_c")).await;

    let inv = ca
        .send(json!({"cmd": "create_invite", "auth_token": tok_a}))
        .await;
    assert!(inv["ok"].as_bool().unwrap(), "{:?}", inv);
    let cid_a = inv["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_a = inv["result"]["code"].as_str().unwrap().to_owned();

    let acc_b = cb
        .send(json!({"cmd": "accept_invite", "code": code_a, "label": "A", "auth_token": tok_b}))
        .await;
    assert!(acc_b["ok"].as_bool().unwrap(), "{:?}", acc_b);
    let code_b = acc_b["result"]["my_code"].as_str().unwrap().to_owned();

    let acc_c = cc
        .send(json!({"cmd": "accept_invite", "code": code_a, "label": "A", "auth_token": tok_c}))
        .await;
    assert!(acc_c["ok"].as_bool().unwrap(), "{:?}", acc_c);
    let code_c = acc_c["result"]["my_code"].as_str().unwrap().to_owned();

    let fin_b = ca
        .send(json!({"cmd": "accept_invite", "code": code_b, "contact_id": cid_a, "label": "B", "auth_token": tok_a}))
        .await;
    assert!(fin_b["ok"].as_bool().unwrap(), "{:?}", fin_b);

    let fin_c = ca
        .send(json!({"cmd": "accept_invite", "code": code_c, "contact_id": cid_a, "label": "C", "auth_token": tok_a}))
        .await;
    assert_eq!(
        fin_c["error"].as_str().unwrap(),
        "peer_already_set",
        "{:?}",
        fin_c
    );
}

#[tokio::test]
async fn test_pending_invite_visible_in_contacts_list() {
    let srv = TestServer::start().await;
    let d = start_daemon().await;
    let mut c = IpcClient::connect(&d.socket_path).await;
    let tok = full_setup(&mut c, &srv, &unique_handle("pcl")).await;

    let inv = c
        .send(json!({"cmd": "create_invite", "auth_token": tok}))
        .await;
    let cid = inv["result"]["contact_id"].as_str().unwrap().to_owned();

    let list = c
        .send(json!({"cmd": "contacts_list", "auth_token": tok}))
        .await;
    assert!(list["ok"].as_bool().unwrap(), "{:?}", list);
    let contacts = list["result"]["contacts"].as_array().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0]["contact_id"].as_str().unwrap(), cid);
    assert!(!contacts[0]["peer_set"].as_bool().unwrap());
}

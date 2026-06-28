// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

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
    assert_eq!(r["error"].as_str().unwrap(), "peer_not_set", "{:?}", r);
}

#[tokio::test]
async fn test_reveal_with_unknown_contact_id_fails() {
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
    let commitment = inv["result"]["commitment"].as_str().unwrap().to_owned();

    let acc_b = cb
        .send(json!({"cmd": "accept_commitment", "commitment": commitment, "label": "A", "auth_token": tok_b}))
        .await;
    let code_b = acc_b["result"]["code"].as_str().unwrap().to_owned();

    // A reveals against a contact_id that does not exist in A's local DB.
    let r = ca
        .send(json!({
            "cmd": "reveal_invite",
            "contact_id": "cc".repeat(32),
            "peer_code": code_b,
            "label": "B",
            "auth_token": tok_a
        }))
        .await;
    assert_eq!(r["error"].as_str().unwrap(), "contact_not_found", "{:?}", r);
}

#[tokio::test]
async fn test_peer_takeover_rejected() {
    // A commitment is public — two different peers can accept the same one. Once A reveals
    // against B's identity, a second reveal using C's identity must be rejected so C cannot
    // take over A's established contact slot.
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
    let commitment = inv["result"]["commitment"].as_str().unwrap().to_owned();

    let acc_b = cb
        .send(json!({"cmd": "accept_commitment", "commitment": commitment, "label": "A", "auth_token": tok_b}))
        .await;
    assert!(acc_b["ok"].as_bool().unwrap(), "{:?}", acc_b);
    let code_b = acc_b["result"]["code"].as_str().unwrap().to_owned();

    let acc_c = cc
        .send(json!({"cmd": "accept_commitment", "commitment": commitment, "label": "A", "auth_token": tok_c}))
        .await;
    assert!(acc_c["ok"].as_bool().unwrap(), "{:?}", acc_c);
    let code_c = acc_c["result"]["code"].as_str().unwrap().to_owned();

    let rev_b = ca
        .send(json!({"cmd": "reveal_invite", "contact_id": cid_a, "peer_code": code_b, "label": "B", "auth_token": tok_a}))
        .await;
    assert!(rev_b["ok"].as_bool().unwrap(), "{:?}", rev_b);

    let rev_c = ca
        .send(json!({"cmd": "reveal_invite", "contact_id": cid_a, "peer_code": code_c, "label": "C", "auth_token": tok_a}))
        .await;
    assert_eq!(
        rev_c["error"].as_str().unwrap(),
        "peer_already_set",
        "{:?}",
        rev_c
    );
}

#[tokio::test]
async fn test_finalize_rejects_wrong_code_then_accepts_correct() {
    let srv = TestServer::start().await;
    let da = start_daemon().await;
    let db = start_daemon().await;
    let mut ca = IpcClient::connect(&da.socket_path).await;
    let mut cb = IpcClient::connect(&db.socket_path).await;

    let tok_a = full_setup(&mut ca, &srv, &unique_handle("mism_a")).await;
    let tok_b = full_setup(&mut cb, &srv, &unique_handle("mism_b")).await;

    let inv = ca
        .send(json!({"cmd": "create_invite", "auth_token": tok_a}))
        .await;
    let cid_a = inv["result"]["contact_id"].as_str().unwrap().to_owned();
    let commitment = inv["result"]["commitment"].as_str().unwrap().to_owned();

    let acc_b = cb
        .send(json!({"cmd": "accept_commitment", "commitment": commitment, "label": "A", "auth_token": tok_b}))
        .await;
    let cid_b = acc_b["result"]["contact_id"].as_str().unwrap().to_owned();
    let code_b = acc_b["result"]["code"].as_str().unwrap().to_owned();

    // A code whose hash does not open the commitment must be rejected — here B's own code
    // stands in for keys a channel attacker swapped after seeing the commitment.
    let bad = cb
        .send(json!({"cmd": "finalize_pairing", "contact_id": cid_b, "peer_code": code_b, "auth_token": tok_b}))
        .await;
    assert_eq!(
        bad["error"].as_str().unwrap(),
        "commitment_mismatch",
        "{:?}",
        bad
    );

    let list = cb
        .send(json!({"cmd": "contacts_list", "auth_token": tok_b}))
        .await;
    let contacts = list["result"]["contacts"].as_array().unwrap();
    assert!(!contacts[0]["peer_set"].as_bool().unwrap());

    let rev = ca
        .send(json!({"cmd": "reveal_invite", "contact_id": cid_a, "peer_code": code_b, "label": "B", "auth_token": tok_a}))
        .await;
    let code_a = rev["result"]["code"].as_str().unwrap().to_owned();

    let fin = cb
        .send(json!({"cmd": "finalize_pairing", "contact_id": cid_b, "peer_code": code_a, "auth_token": tok_b}))
        .await;
    assert!(fin["ok"].as_bool().unwrap(), "{:?}", fin);
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

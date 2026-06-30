// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_itest::{
    client::RawShakeBuilder,
    helpers::{TestServer, random_dek_hex, unique_handle},
};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_root_endpoint() {
    let srv = TestServer::start().await;
    let resp = reqwest::get(format!("http://{}/", srv.addr))
        .await
        .expect("GET /");
    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.expect("json");
    assert!(json["message"].as_str().is_some(), "no message field");
}

#[tokio::test]
async fn test_shake_establishes_session() {
    let srv = TestServer::start().await;
    let mut c = srv.client();
    let r = c.shake().await;

    assert!(
        r.headers.get("ses-x").and_then(|v| v.as_str()).is_some(),
        "ses-x missing from shake response headers"
    );
    assert!(
        r.headers.get("ses-k").and_then(|v| v.as_str()).is_some(),
        "ses-k missing from shake response headers"
    );
}

#[tokio::test]
async fn test_register_new_user_returns_capability() {
    let srv = TestServer::start().await;
    let mut c = srv.client();
    c.generate_user_keys();

    let handle = unique_handle("alice");
    let dek = random_dek_hex();
    let r = c.register(&handle, "Password1!", &dek).await;

    let capability = r.body["capability"].as_str().expect("capability missing");
    assert_eq!(
        capability.len(),
        64,
        "capability must be 32 bytes = 64 hex chars"
    );
    assert_eq!(r.body["msg"].as_str().unwrap_or(""), "Ok");
}

#[tokio::test]
async fn test_register_taken_handle_is_indistinguishable() {
    let srv = TestServer::start().await;
    let handle = unique_handle("bob");
    let dek = random_dek_hex();

    let mut c1 = srv.client();
    c1.generate_user_keys();
    c1.register(&handle, "Password1!", &dek).await;

    let mut c2 = srv.client();
    c2.generate_user_keys();
    let dek2 = random_dek_hex();
    let r = c2.register(&handle, "Password1!", &dek2).await;

    assert_eq!(
        r.body["capability"].as_str().map(str::len),
        Some(64),
        "{:?}",
        r.body
    );
    assert_eq!(r.body["msg"].as_str().unwrap_or(""), "Ok");

    let mut login = srv.client();
    login.copy_keys_from(&c1);
    let r = login.login(&handle, "Password1!").await;
    assert_eq!(
        r.body["dek"].as_str().expect("dek missing"),
        dek,
        "second register must not overwrite the original account"
    );
}

#[tokio::test]
async fn test_login_success_returns_dek_and_token() {
    let srv = TestServer::start().await;
    let handle = unique_handle("carol");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;

    let mut c2 = srv.client();
    c2.copy_keys_from(&c);
    let r = c2.login(&handle, "Password1!").await;

    assert_eq!(r.body["msg"].as_str().unwrap_or(""), "Ok");
    let returned_dek = r.body["dek"].as_str().expect("dek missing");
    assert_eq!(returned_dek, dek, "server returned wrong DEK");
    assert!(
        !r.body["tok"].as_str().unwrap_or("").is_empty(),
        "token empty"
    );
}

#[tokio::test]
async fn test_login_wrong_password_returns_401() {
    let srv = TestServer::start().await;
    let handle = unique_handle("dave");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;

    let mut c2 = srv.client();
    c2.copy_keys_from(&c);
    let raw = c2.login_raw(&handle, "WrongPassword!").await;
    assert_eq!(raw.status, 401);
}

#[tokio::test]
async fn test_login_unknown_user_returns_401() {
    let srv = TestServer::start().await;
    let mut c = srv.client();
    c.generate_user_keys();
    let raw = c.login_raw(&unique_handle("nobody"), "Password1!").await;
    assert_eq!(raw.status, 401);
}

#[tokio::test]
async fn test_send_and_fetch_message() {
    use lithium_core::crypto::keys;

    let srv = TestServer::start().await;
    let handle = unique_handle("eve");
    let dek = random_dek_hex();

    let mut sender = srv.client();
    sender.generate_user_keys();
    sender.register(&handle, "Password1!", &dek).await;
    sender.login(&handle, "Password1!").await;

    let mailbox = hex::encode(keys::random_32().expect("random").as_slice());
    let content = hex::encode(b"hello integration test");
    sender.send_message(&mailbox, &content).await;

    let mut fetcher = srv.client();
    fetcher.generate_user_keys();
    let r = fetcher.fetch_messages(&mailbox).await;

    let data = r.body["data"].as_array().expect("data array");
    assert_eq!(data.len(), 1, "expected exactly one message");

    let fetched_hex = data[0].as_str().expect("message hex");
    let fetched_bytes = hex::decode(fetched_hex).expect("hex decode");
    assert_eq!(fetched_bytes, b"hello integration test");
}

#[tokio::test]
async fn test_fetch_empty_mailbox_returns_empty_array() {
    use lithium_core::crypto::keys;

    let srv = TestServer::start().await;
    let mailbox = hex::encode(keys::random_32().expect("random").as_slice());

    let mut c = srv.client();
    c.generate_user_keys();
    let r = c.fetch_messages(&mailbox).await;

    let data = r.body["data"].as_array().expect("data array");
    assert!(data.is_empty(), "expected no messages in fresh mailbox");
}

#[tokio::test]
async fn test_messages_are_deleted_after_fetch() {
    use lithium_core::crypto::keys;

    let srv = TestServer::start().await;
    let handle = unique_handle("frank");
    let dek = random_dek_hex();

    let mut sender = srv.client();
    sender.generate_user_keys();
    sender.register(&handle, "Password1!", &dek).await;
    sender.login(&handle, "Password1!").await;

    let mailbox = hex::encode(keys::random_32().expect("random").as_slice());
    sender
        .send_message(&mailbox, &hex::encode(b"one-time"))
        .await;

    let mut f1 = srv.client();
    f1.generate_user_keys();
    let r1 = f1.fetch_messages(&mailbox).await;
    assert_eq!(r1.body["data"].as_array().unwrap().len(), 1);

    let mut f2 = srv.client();
    f2.generate_user_keys();
    let r2 = f2.fetch_messages(&mailbox).await;
    assert!(r2.body["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_delete_account_succeeds_and_blocks_login() {
    let srv = TestServer::start().await;
    let handle = unique_handle("grace");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;
    c.login(&handle, "Password1!").await;
    c.delete().await;

    let mut c2 = srv.client();
    c2.copy_keys_from(&c);
    let raw = c2.login_raw(&handle, "Password1!").await;
    assert_eq!(raw.status, 401);
}

#[tokio::test]
async fn test_revoke_with_valid_capability_deletes_account() {
    let srv = TestServer::start().await;
    let handle = unique_handle("henry");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    let reg = c.register(&handle, "Password1!", &dek).await;
    let capability = reg.body["capability"]
        .as_str()
        .expect("capability")
        .to_owned();

    let mut c2 = srv.client();
    c2.generate_user_keys();
    c2.revoke(&capability).await;

    let mut c3 = srv.client();
    c3.copy_keys_from(&c);
    let raw = c3.login_raw(&handle, "Password1!").await;
    assert_eq!(raw.status, 401);
}

#[tokio::test]
async fn test_revoke_with_wrong_capability_is_silent() {
    use lithium_core::crypto::keys;
    let srv = TestServer::start().await;
    let fake_cap = hex::encode(keys::random_32().expect("random").as_slice());

    let mut c = srv.client();
    c.generate_user_keys();
    c.revoke(&fake_cap).await; // must not panic
}

#[tokio::test]
async fn test_duplicate_request_body_is_rejected() {
    let srv = TestServer::start().await;
    let raw = RawShakeBuilder {
        bootstrap: srv.bootstrap.clone(),
        base: format!("http://{}", srv.addr),
    }
    .send_duplicate_body()
    .await;

    assert_eq!(raw.status, 400, "replay must be rejected with 400");
    assert_eq!(raw.error.as_deref(), Some("replay_detected"));
}

#[tokio::test]
async fn test_stale_timestamp_is_rejected() {
    let srv = TestServer::start().await;
    let raw = RawShakeBuilder {
        bootstrap: srv.bootstrap.clone(),
        base: format!("http://{}", srv.addr),
    }
    .send_with_ts(0) // epoch = definitely stale
    .await;

    assert_eq!(raw.status, 400);
    assert_eq!(raw.error.as_deref(), Some("request too old"));
}

#[tokio::test]
async fn test_future_timestamp_is_rejected() {
    let srv = TestServer::start().await;
    let far_future = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 9999;

    let raw = RawShakeBuilder {
        bootstrap: srv.bootstrap.clone(),
        base: format!("http://{}", srv.addr),
    }
    .send_with_ts(far_future)
    .await;

    assert_eq!(raw.status, 400);
    assert_eq!(raw.error.as_deref(), Some("request is from the future"));
}

#[tokio::test]
async fn test_invalid_jwt_is_rejected() {
    let srv = TestServer::start().await;
    let handle = unique_handle("ivan");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;
    c.login(&handle, "Password1!").await;

    c.poison_jwt().await;

    let raw = c.delete_raw().await;
    assert_eq!(raw.status, 401);
}

#[tokio::test]
async fn test_request_without_crypto_headers_is_rejected() {
    let srv = TestServer::start().await;
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("http://{}/shake", srv.addr))
        .body(vec![0u8; 64])
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().as_u16() >= 400,
        "expected 4xx, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_login_rate_limit_triggers_after_threshold() {
    let srv = TestServer::start().await;
    let handle = unique_handle("judy");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;

    // login fail threshold is 5
    for _ in 0..6 {
        let mut cx = srv.client();
        cx.copy_keys_from(&c);
        cx.login_raw(&handle, "WrongPass!").await;
    }

    let mut cx = srv.client();
    cx.copy_keys_from(&c);
    let raw = cx.login_raw(&handle, "Password1!").await;
    assert!(
        raw.status == 401 || raw.status == 429,
        "expected 401 or 429, got {}",
        raw.status
    );
}

#[tokio::test]
async fn test_body_over_limit_rejected() {
    let srv = TestServer::start().await;
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("http://{}/shake", srv.addr))
        .body(vec![0u8; 1024 * 1024 + 1])
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let json: Value = resp.json().await.unwrap_or(Value::Null);
    assert_eq!(status, 400);
    assert_eq!(json["error"].as_str(), Some("body_too_large"));
}

#[tokio::test]
async fn test_garbage_encrypted_body_rejected() {
    let srv = TestServer::start().await;
    let http = reqwest::Client::new();
    // Valid-looking headers, but body is random noise — kyberbox decrypt must fail.
    let resp = http
        .post(format!("http://{}/shake", srv.addr))
        .header("key-x", "ab".repeat(32))
        .header("key-k", "cd".repeat(32))
        .header("kem-ct", "ef".repeat(48))
        .header("data", "12".repeat(48))
        .body(vec![0xffu8; 512])
        .send()
        .await
        .unwrap();
    assert!(resp.status().as_u16() >= 400);
}

#[tokio::test]
async fn test_session_with_nonexistent_ses_keys_rejected() {
    let srv = TestServer::start().await;
    let http = reqwest::Client::new();
    // Valid header set for session mode, but ses-x/ses-k IDs don't exist in server store.
    let resp = http
        .post(format!("http://{}/user/register/start", srv.addr))
        .header("ses-x", "aa".repeat(32))
        .header("ses-k", "bb".repeat(32))
        .header("key-x", "cc".repeat(32))
        .header("key-k", "dd".repeat(32))
        .header("kem-ct", "ee".repeat(48))
        .header("data", "ff".repeat(48))
        .body(vec![0u8; 64])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn test_session_keys_consumed_after_use() {
    let srv = TestServer::start().await;
    let mut c = srv.client();

    let shake_resp = c.shake().await;
    let ses_x = shake_resp.headers["ses-x"].as_str().unwrap().to_owned();
    let ses_k = shake_resp.headers["ses-k"].as_str().unwrap().to_owned();

    c.generate_user_keys();
    c.register(&unique_handle("keyused"), "Password1!", &random_dek_hex())
        .await;

    let http = reqwest::Client::new();
    let resp = http
        .post(format!("http://{}/user/login/start", srv.addr))
        .header("ses-x", &ses_x)
        .header("ses-k", &ses_k)
        .header("key-x", "cc".repeat(32))
        .header("key-k", "dd".repeat(32))
        .header("kem-ct", "ee".repeat(48))
        .header("data", "ff".repeat(48))
        .body(vec![0u8; 64])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn test_register_invalid_dek_rejected() {
    let srv = TestServer::start().await;
    let mut c = srv.client();
    c.generate_user_keys();
    let raw = c
        .register_raw(&unique_handle("baddek"), "Password1!", "not-valid-hex")
        .await;
    assert_eq!(raw.status, 400);
    assert_eq!(raw.error.as_deref(), Some("invalid_dek"));
}

#[tokio::test]
async fn test_login_lockout_blocks_correct_password() {
    let srv = TestServer::start().await;
    let handle = unique_handle("lockout");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "CorrectPassword1!", &dek).await;

    // login fail threshold is 5
    for _ in 0..5 {
        let mut cx = srv.client();
        cx.copy_keys_from(&c);
        cx.login_raw(&handle, "BadPassword!").await;
    }

    let mut cx = srv.client();
    cx.copy_keys_from(&c);
    let raw = cx.login_raw(&handle, "CorrectPassword1!").await;
    assert_eq!(
        raw.status, 429,
        "correct password must be blocked while rate limit lock is active"
    );
}

#[tokio::test]
async fn test_login_rate_limit_case_insensitive() {
    let srv = TestServer::start().await;
    let handle = unique_handle("cilock");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;

    // normalize_login_handler lowercases before keying the rate limit counter,
    // so uppercase and lowercase share the same bucket.
    let handle_upper = handle.to_uppercase();
    for _ in 0..5 {
        let mut cx = srv.client();
        cx.generate_user_keys();
        cx.login_raw(&handle_upper, "Password1!").await;
    }

    let mut cx = srv.client();
    cx.copy_keys_from(&c);
    let raw = cx.login_raw(&handle, "Password1!").await;
    assert_eq!(raw.status, 429);
}

#[tokio::test]
async fn test_register_lockout_after_duplicate_threshold() {
    let srv = TestServer::start().await;
    let handle = unique_handle("reglimit");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;

    // register fail threshold is 3
    for _ in 0..3 {
        let mut cx = srv.client();
        cx.generate_user_keys();
        cx.register_raw(&handle, "Password1!", &random_dek_hex())
            .await;
    }

    let mut cx = srv.client();
    cx.generate_user_keys();
    let raw = cx
        .register_raw(&handle, "Password1!", &random_dek_hex())
        .await;
    assert_eq!(raw.status, 429);
    assert_eq!(raw.error.as_deref(), Some("try_later"));
}

#[tokio::test]
async fn test_fetch_invalid_mailbox_byte_length() {
    let srv = TestServer::start().await;
    let mut c = srv.client();
    c.generate_user_keys();

    // server accepts only 16 or 32 byte mailboxes
    let bad_mailbox = hex::encode([0xaau8; 3]);
    let raw = c.fetch_messages_raw(&bad_mailbox).await;
    assert_eq!(raw.status, 400);
    assert_eq!(raw.error.as_deref(), Some("invalid_mailbox"));
}

#[tokio::test]
async fn test_send_invalid_content_hex_rejected() {
    use lithium_core::crypto::keys;

    let srv = TestServer::start().await;
    let handle = unique_handle("badcontent");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;
    c.login(&handle, "Password1!").await;

    let mailbox = hex::encode(keys::random_32().expect("random").as_slice());
    let raw = c.send_message_raw(&mailbox, "not-valid-hex!").await;
    assert_eq!(raw.status, 400);
    assert_eq!(raw.error.as_deref(), Some("invalid_content"));
}

#[tokio::test]
async fn test_send_mailbox_too_short_rejected() {
    let srv = TestServer::start().await;
    let handle = unique_handle("mbshort");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;
    c.login(&handle, "Password1!").await;

    let bad_mailbox = hex::encode([0xbbu8; 7]);
    let content = hex::encode(b"payload");
    let raw = c.send_message_raw(&bad_mailbox, &content).await;
    assert_eq!(raw.status, 400);
    assert_eq!(raw.error.as_deref(), Some("invalid_mailbox"));
}

#[tokio::test]
async fn test_multiple_senders_all_messages_fetched() {
    use lithium_core::crypto::keys;

    let srv = TestServer::start().await;
    let mailbox = hex::encode(keys::random_32().expect("random").as_slice());
    let dek = random_dek_hex();

    async fn register_login_send(
        srv: &TestServer,
        prefix: &str,
        mailbox: &str,
        payload: &[u8],
    ) -> String {
        let handle = unique_handle(prefix);
        let dek = random_dek_hex();
        let mut c = srv.client();
        c.generate_user_keys();
        c.register(&handle, "Password1!", &dek).await;
        c.login(&handle, "Password1!").await;
        let content = hex::encode(payload);
        c.send_message(mailbox, &content).await;
        hex::encode(payload)
    }

    let _ = dek;
    register_login_send(&srv, "snd1", &mailbox, b"message-from-sender-one").await;
    register_login_send(&srv, "snd2", &mailbox, b"message-from-sender-two").await;
    register_login_send(&srv, "snd3", &mailbox, b"message-from-sender-three").await;

    let mut fetcher = srv.client();
    fetcher.generate_user_keys();
    let r = fetcher.fetch_messages(&mailbox).await;
    let data = r.body["data"].as_array().expect("data array");
    assert_eq!(data.len(), 3, "expected all three messages in one fetch");

    let payloads: Vec<Vec<u8>> = data
        .iter()
        .map(|v| hex::decode(v.as_str().expect("hex str")).expect("hex decode"))
        .collect();

    assert!(payloads.contains(&b"message-from-sender-one".to_vec()));
    assert!(payloads.contains(&b"message-from-sender-two".to_vec()));
    assert!(payloads.contains(&b"message-from-sender-three".to_vec()));
}

#[tokio::test]
async fn test_send_is_anonymous_without_jwt() {
    use lithium_core::crypto::keys;

    let srv = TestServer::start().await;
    let handle = unique_handle("anonsend");
    let dek = random_dek_hex();
    let mailbox = hex::encode(keys::random_32().expect("random").as_slice());
    let content = hex::encode(b"test");

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;

    // After A2 the send endpoint is KeysInHeaders, not JwtUser: a missing or garbage
    // JWT must not affect delivery. No login at all, plus a poisoned token, still sends.
    c.poison_jwt().await;
    let raw = c.send_message_raw(&mailbox, &content).await;
    assert_eq!(raw.status, 200);
}

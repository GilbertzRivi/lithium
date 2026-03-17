//! Integration tests for `lithiums` (the relay server).
//!
//! Requires a PostgreSQL instance.  Set the env var before running:
//!
//!   LITHIUM_TEST_DATABASE_URL=postgres://user:pass@localhost/lithium_test \
//!   cargo test -p lithium_itest -- --test-threads=1
//!
//! `--test-threads=1` avoids port collisions between parallel test servers.

use lithium_itest::{
    client::RawShakeBuilder,
    helpers::{TestServer, random_dek_hex, unique_handle},
};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// GET /
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// POST /shake
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// POST /user/register
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_register_new_user_returns_capability() {
    let srv = TestServer::start().await;
    let mut c = srv.client();
    c.generate_user_keys();

    let handle = unique_handle("alice");
    let dek = random_dek_hex();
    let r = c.register(&handle, "Password1!", &dek).await;

    let capability = r.body["capability"].as_str().expect("capability missing");
    assert_eq!(capability.len(), 64, "capability must be 32 bytes = 64 hex chars");
    assert_eq!(r.body["msg"].as_str().unwrap_or(""), "Ok");
}

#[tokio::test]
async fn test_register_duplicate_user_is_rejected() {
    let srv = TestServer::start().await;
    let handle = unique_handle("bob");
    let dek = random_dek_hex();

    // First registration.
    let mut c1 = srv.client();
    c1.generate_user_keys();
    c1.register(&handle, "Password1!", &dek).await;

    // Second registration with the same handle.
    let mut c2 = srv.client();
    c2.generate_user_keys();
    let raw = c2.register_raw(&handle, "Password1!", &dek).await;

    assert_eq!(raw.status, 400);
    assert_eq!(raw.error.as_deref(), Some("user_exists"));
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /user/login
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_login_success_returns_dek_and_token() {
    let srv = TestServer::start().await;
    let handle = unique_handle("carol");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;

    // New client — same device keys, fresh session.
    let mut c2 = srv.client();
    c2.copy_keys_from(&c);
    let r = c2.login(&handle, "Password1!").await;

    assert_eq!(r.body["msg"].as_str().unwrap_or(""), "Ok");
    let returned_dek = r.body["dek"].as_str().expect("dek missing");
    assert_eq!(returned_dek, dek, "server returned wrong DEK");
    assert!(!r.body["tok"].as_str().unwrap_or("").is_empty(), "token empty");
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

// ─────────────────────────────────────────────────────────────────────────────
// POST /msg/send + POST /msg/fetch
// ─────────────────────────────────────────────────────────────────────────────

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

    // Fetch with a fresh (unauthenticated) client.
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
    sender.send_message(&mailbox, &hex::encode(b"one-time")).await;

    // First fetch — gets the message.
    let mut f1 = srv.client();
    f1.generate_user_keys();
    let r1 = f1.fetch_messages(&mailbox).await;
    assert_eq!(r1.body["data"].as_array().unwrap().len(), 1);

    // Second fetch — mailbox is empty (one-time delivery).
    let mut f2 = srv.client();
    f2.generate_user_keys();
    let r2 = f2.fetch_messages(&mailbox).await;
    assert!(r2.body["data"].as_array().unwrap().is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /user/delete
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// POST /user/revoke
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_revoke_with_valid_capability_deletes_account() {
    let srv = TestServer::start().await;
    let handle = unique_handle("henry");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    let reg = c.register(&handle, "Password1!", &dek).await;
    let capability = reg.body["capability"].as_str().expect("capability").to_owned();

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

// ─────────────────────────────────────────────────────────────────────────────
// Security: anti-replay
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Security: timestamp validation
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Security: invalid JWT
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_invalid_jwt_is_rejected() {
    let srv = TestServer::start().await;
    let handle = unique_handle("ivan");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;
    c.login(&handle, "Password1!").await;

    // Corrupt the JWT so the server rejects it.
    c.poison_jwt().await;

    let raw = c.delete_raw().await;
    assert_eq!(raw.status, 401);
}

// ─────────────────────────────────────────────────────────────────────────────
// Security: missing crypto headers
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Rate limiting: login
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_login_rate_limit_triggers_after_threshold() {
    let srv = TestServer::start().await;
    let handle = unique_handle("judy");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;

    // Threshold is 5; attempt 6 times with wrong password.
    for _ in 0..6 {
        let mut cx = srv.client();
        cx.copy_keys_from(&c);
        cx.login_raw(&handle, "WrongPass!").await;
    }

    // 7th attempt must be 401 (credentials) or 429 (rate limited).
    let mut cx = srv.client();
    cx.copy_keys_from(&c);
    let raw = cx.login_raw(&handle, "Password1!").await;
    assert!(
        raw.status == 401 || raw.status == 429,
        "expected 401 or 429, got {}",
        raw.status
    );
}
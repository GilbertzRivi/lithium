// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::{
    crypto::{keys, kyberbox, sign},
    secrets::bytes::SecretBytes,
};
use lithium_itest::{
    client::{RawShakeBuilder, ServerBootstrap},
    helpers::TestServer,
};
use reqwest::{Client, header::HeaderMap};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn raw(srv: &TestServer) -> RawShakeBuilder {
    RawShakeBuilder {
        bootstrap: srv.bootstrap.clone(),
        base: format!("http://{}", srv.addr),
    }
}

#[tokio::test]
async fn test_timestamp_30s_old_accepted() {
    let srv = TestServer::start().await;
    assert_eq!(raw(&srv).send_with_ts(now_secs() - 30).await.status, 200);
}

#[tokio::test]
async fn test_timestamp_90s_old_rejected() {
    let srv = TestServer::start().await;
    let r = raw(&srv).send_with_ts(now_secs() - 90).await;
    assert_eq!(r.status, 400);
    assert_eq!(r.error.as_deref(), Some("request too old"));
}

#[tokio::test]
async fn test_timestamp_30s_future_accepted() {
    let srv = TestServer::start().await;
    assert_eq!(raw(&srv).send_with_ts(now_secs() + 30).await.status, 200);
}

#[tokio::test]
async fn test_timestamp_90s_future_rejected() {
    let srv = TestServer::start().await;
    let r = raw(&srv).send_with_ts(now_secs() + 90).await;
    assert_eq!(r.status, 400);
    assert_eq!(r.error.as_deref(), Some("request is from the future"));
}

#[tokio::test]
async fn test_cross_endpoint_body_replay_rejected() {
    // GuardMiddleware hashes the raw ciphertext before routing. The same bytes
    // sent to a different endpoint trigger replay_detected, not a crypto error.
    let srv = TestServer::start().await;
    let (wire_body, http_headers) = build_shake_wire(&srv.bootstrap);
    let base = format!("http://{}", srv.addr);
    let http = Client::new();

    let r1 = http
        .post(format!("{}/shake", base))
        .headers(http_headers.clone())
        .body(wire_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status().as_u16(), 200);

    let r2 = http
        .post(format!("{}/user/register", base))
        .headers(http_headers)
        .body(wire_body)
        .send()
        .await
        .unwrap();
    let status2 = r2.status().as_u16();
    let json: Value = r2.json().await.unwrap_or(Value::Null);
    assert_eq!(status2, 400);
    assert_eq!(json["error"].as_str(), Some("replay_detected"));
}

fn pad(mut buf: Vec<u8>, block: usize) -> Vec<u8> {
    let pad_len = (block - ((buf.len() + 1) % block)) % block;
    buf.push(0x80);
    buf.resize(buf.len() + pad_len, 0);
    buf
}

fn build_shake_wire(bootstrap: &ServerBootstrap) -> (Vec<u8>, HeaderMap) {
    let body_bytes =
        serde_json::to_vec(&json!({ "timestamp": format!("{:016x}", now_secs()) })).unwrap();

    let (ed_priv, ed_pub) = keys::random_ed25519_keypair().unwrap();
    let (dili_priv, dili_pub) = keys::random_dilithium_mldsa87_keypair().unwrap();
    let sig_ed = sign::sign_message(&body_bytes, &ed_priv).unwrap();
    let sig_dili = sign::sign_message_dili(&body_bytes, &dili_priv).unwrap();

    let app_headers = json!({
        "key-ed": ed_pub.to_hex().expose().to_string(),
        "key-dili": dili_pub.to_hex().expose().to_string(),
        "sig-ed": sig_ed.to_hex().expose().to_string(),
        "sig-dili": sig_dili.to_hex().expose().to_string(),
    });

    let (req_priv_x, req_pub_x) = keys::random_x25519_keypair().unwrap();
    let (_, req_pub_k) = keys::random_kyber_mlkem1024_keypair().unwrap();

    let wire = kyberbox::encrypt(
        "shake-req",
        &req_priv_x,
        &bootstrap.shake_pub_x,
        &bootstrap.shake_pub_k,
        &SecretBytes::new(pad(body_bytes, 32 * 1024)),
        &SecretBytes::new(pad(serde_json::to_vec(&app_headers).unwrap(), 4 * 1024)),
    )
    .unwrap();

    let mut h = HeaderMap::new();
    h.insert("key-x", hv(hex::encode(req_pub_x.as_slice())));
    h.insert("key-k", hv(hex::encode(req_pub_k.expose_as_slice())));
    h.insert("seed", hv(hex::encode(wire.seed_enc.expose_as_slice())));
    h.insert("data", hv(hex::encode(wire.enc_headers.expose_as_slice())));

    (wire.enc_body.expose_as_slice().to_vec(), h)
}

fn hv(s: impl AsRef<str>) -> reqwest::header::HeaderValue {
    reqwest::header::HeaderValue::from_str(s.as_ref()).unwrap()
}

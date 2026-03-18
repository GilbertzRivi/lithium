// mirrors lithiumd::ProtocolManager - real encrypted requests against a live server
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lithium_core::{
    crypto::{keys, kyberbox, sign},
    secrets::{Byte32, SecretString, bytes::SecretBytes},
    utils::store::EphemeralStoreManager,
};
use reqwest::{header::HeaderMap, Client};
use serde_json::{Value, json};
use zeroize::Zeroize;

const ST_PEER_X: &str = "peer_x";
const ST_PEER_K: &str = "peer_k";
const ST_SES_X: &str = "ses_x";
const ST_SES_K: &str = "ses_k";
const ST_JWT: &str = "jwt";

const SESSION_TTL: Duration = Duration::from_secs(120);
const JWT_TTL: Duration = Duration::from_secs(120);

/// Server public-key bundle.  Built from `KeyManager::public_keys()` in tests.
#[derive(Clone)]
pub struct ServerBootstrap {
    pub shake_pub_x: Byte32,
    pub shake_pub_k: SecretBytes,
    pub server_sig_ed: Byte32,
    pub server_sig_dili: SecretBytes,
}

/// Raw HTTP error for negative-test assertions.
#[derive(Debug)]
pub struct RawResponse {
    pub status: u16,
    pub error: Option<String>,
}

#[derive(Clone, Copy)]
enum Ep {
    Shake,
    Register,
    Login,
    RemoteDelete,
    Delete,
    MsgSend,
    MsgFetch,
}

impl Ep {
    fn path(self) -> &'static str {
        match self {
            Ep::Shake => "/shake",
            Ep::Register => "/user/register",
            Ep::Login => "/user/login",
            Ep::RemoteDelete => "/user/revoke",
            Ep::Delete => "/user/delete",
            Ep::MsgSend => "/msg/send",
            Ep::MsgFetch => "/msg/fetch",
        }
    }

    fn ctx_base(self) -> &'static str {
        match self {
            Ep::Shake => "shake",
            Ep::Register => "register",
            Ep::Login => "login",
            Ep::RemoteDelete => "revoke",
            Ep::Delete => "delete",
            Ep::MsgSend => "msg_send",
            Ep::MsgFetch => "msg_fetch",
        }
    }

    fn ctx_req(self) -> String { format!("{}-req", self.ctx_base()) }
    fn ctx_resp(self) -> String { format!("{}-resp", self.ctx_base()) }
    fn requires_session(self) -> bool { !matches!(self, Ep::Shake) }
    fn returns_204(self) -> bool { matches!(self, Ep::RemoteDelete) }
    fn sign_ephemeral(self) -> bool {
        matches!(self, Ep::Shake | Ep::RemoteDelete | Ep::MsgFetch)
    }
    fn include_identity_keys(self) -> bool {
        matches!(self, Ep::Shake | Ep::Register | Ep::MsgFetch | Ep::RemoteDelete)
    }
}

pub struct TestResponse {
    pub body: Value,
    pub headers: Value,
}

pub struct TestLithiumClient {
    base: String,
    http: Client,
    bootstrap: ServerBootstrap,
    store: EphemeralStoreManager,

    // Ed25519: both keys are 32-byte fixed arrays.
    pub user_ed_priv: Option<Byte32>,
    pub user_ed_pub: Option<Byte32>,
    // Dilithium-87: keys are large; use SecretBytes.
    pub user_dili_priv: Option<SecretBytes>,
    pub user_dili_pub: Option<SecretBytes>,
}

impl TestLithiumClient {
    pub fn new(base: String, bootstrap: ServerBootstrap) -> Self {
        Self {
            base,
            http: Client::builder().build().expect("reqwest client"),
            bootstrap,
            store: EphemeralStoreManager::new().expect("store"),
            user_ed_priv: None,
            user_ed_pub: None,
            user_dili_priv: None,
            user_dili_pub: None,
        }
    }

    /// Generate a fresh user keypair (must be called before register/login).
    pub fn generate_user_keys(&mut self) {
        let (ed_priv, ed_pub) = keys::random_ed25519_keypair().expect("ed25519");
        let (dili_priv, dili_pub) = keys::random_dilithium_mldsa87_keypair().expect("dili");
        self.user_ed_priv = Some(ed_priv);
        self.user_ed_pub = Some(ed_pub);
        self.user_dili_priv = Some(dili_priv);
        self.user_dili_pub = Some(dili_pub);
    }

    /// Copy user identity keys from another client (simulate same device, new session).
    pub fn copy_keys_from(&mut self, other: &TestLithiumClient) {
        self.user_ed_priv = other.user_ed_priv.clone();
        self.user_ed_pub = other.user_ed_pub.clone();
        self.user_dili_priv = other.user_dili_priv.clone();
        self.user_dili_pub = other.user_dili_pub.clone();
    }

    /// Corrupt the stored JWT so the next JWT-authenticated call fails server-side.
    pub async fn poison_jwt(&self) {
        self.store_str(ST_JWT, "garbage.garbage.garbage", JWT_TTL).await;
    }

    pub async fn shake(&mut self) -> TestResponse {
        self.do_shake().await
    }

    pub async fn register(&mut self, handler: &str, password: &str, dek_hex: &str) -> TestResponse {
        self.ensure_shake().await;
        let body = json!({ "handler": handler, "password": password, "dek": dek_hex });
        self.send(Ep::Register, body).await.expect("register failed")
    }

    pub async fn login(&mut self, handler: &str, password: &str) -> TestResponse {
        self.ensure_shake().await;
        let body = json!({ "handler": handler, "password": password });
        self.send(Ep::Login, body).await.expect("login failed")
    }

    pub async fn delete(&mut self) -> TestResponse {
        let tok = self.st_take_str(ST_JWT).await.expect("JWT must be present; call login() first");
        let body = json!({ "token": tok.expose() });
        self.send(Ep::Delete, body).await.expect("delete failed")
    }

    pub async fn revoke(&mut self, capability_hex: &str) -> TestResponse {
        self.ensure_shake().await;
        let body = json!({ "capability": capability_hex });
        self.send(Ep::RemoteDelete, body).await.unwrap_or(TestResponse { body: json!({}), headers: json!({}) })
    }

    pub async fn send_message(&mut self, mailbox_hex: &str, content_hex: &str) -> TestResponse {
        let tok = self.st_take_str(ST_JWT).await.expect("JWT must be present; call login() first");
        let body = json!({ "token": tok.expose(), "mailbox": mailbox_hex, "content": content_hex });
        self.send(Ep::MsgSend, body).await.expect("send_message failed")
    }

    pub async fn fetch_messages(&mut self, mailbox_hex: &str) -> TestResponse {
        self.ensure_shake().await;
        let body = json!({ "mailbox": mailbox_hex });
        self.send(Ep::MsgFetch, body).await.expect("fetch_messages failed")
    }

    pub async fn register_raw(&mut self, handler: &str, password: &str, dek_hex: &str) -> RawResponse {
        self.ensure_shake().await;
        let body = json!({ "handler": handler, "password": password, "dek": dek_hex });
        match self.send(Ep::Register, body).await {
            Ok(_) => RawResponse { status: 200, error: None },
            Err(r) => r,
        }
    }

    pub async fn login_raw(&mut self, handler: &str, password: &str) -> RawResponse {
        self.ensure_shake().await;
        let body = json!({ "handler": handler, "password": password });
        match self.send(Ep::Login, body).await {
            Ok(_) => RawResponse { status: 200, error: None },
            Err(r) => r,
        }
    }

    pub async fn delete_raw(&mut self) -> RawResponse {
        match self.st_take_str(ST_JWT).await {
            None => RawResponse { status: 401, error: Some("no_jwt".to_owned()) },
            Some(tok) => {
                let body = json!({ "token": tok.expose() });
                match self.send(Ep::Delete, body).await {
                    Ok(_) => RawResponse { status: 200, error: None },
                    Err(r) => r,
                }
            }
        }
    }

    pub async fn send_message_raw(
        &mut self,
        mailbox_hex: &str,
        content_hex: &str,
    ) -> RawResponse {
        match self.st_take_str(ST_JWT).await {
            None => RawResponse { status: 401, error: Some("no_jwt".to_owned()) },
            Some(tok) => {
                let body =
                    json!({ "token": tok.expose(), "mailbox": mailbox_hex, "content": content_hex });
                match self.send(Ep::MsgSend, body).await {
                    Ok(_) => RawResponse { status: 200, error: None },
                    Err(r) => r,
                }
            }
        }
    }

    pub async fn fetch_messages_raw(&mut self, mailbox_hex: &str) -> RawResponse {
        self.ensure_shake().await;
        let body = json!({ "mailbox": mailbox_hex });
        match self.send(Ep::MsgFetch, body).await {
            Ok(_) => RawResponse { status: 200, error: None },
            Err(r) => r,
        }
    }

    async fn ensure_shake(&mut self) {
        let has = self.st_peek(ST_SES_X).await.is_some() && self.st_peek(ST_PEER_X).await.is_some();
        if !has {
            self.do_shake().await;
        }
    }

    async fn do_shake(&mut self) -> TestResponse {
        let r = self.send(Ep::Shake, json!({})).await.expect("shake failed");
        if let Some(sx) = r.headers.get("ses-x").and_then(|v| v.as_str()) {
            self.store_str(ST_SES_X, sx, SESSION_TTL).await;
        }
        if let Some(sk) = r.headers.get("ses-k").and_then(|v| v.as_str()) {
            self.store_str(ST_SES_K, sk, SESSION_TTL).await;
        }
        r
    }

    async fn send(&mut self, ep: Ep, mut body: Value) -> Result<TestResponse, RawResponse> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        body["timestamp"] = Value::String(format!("{:016x}", ts));

        let body_bytes = serde_json::to_vec(&body).expect("serialize body");

        let mut app_headers = json!({});
        if ep.sign_ephemeral() {
            let (ed_priv, ed_pub) = keys::random_ed25519_keypair().expect("ed25519");
            let (dili_priv, dili_pub) = keys::random_dilithium_mldsa87_keypair().expect("dili");
            let sig_ed = sign::sign_message(&body_bytes, &ed_priv).expect("sign ed");
            let sig_dili = sign::sign_message_dili(&body_bytes, &dili_priv).expect("sign dili");
            if ep.include_identity_keys() {
                app_headers["key-ed"] = Value::String(ed_pub.to_hex().expose().to_string());
                app_headers["key-dili"] = Value::String(dili_pub.to_hex().expose().to_string());
            }
            app_headers["sig-ed"] = Value::String(sig_ed.to_hex().expose().to_string());
            app_headers["sig-dili"] = Value::String(sig_dili.to_hex().expose().to_string());
        } else {
            let ed_priv = self.user_ed_priv.as_ref().expect("call generate_user_keys() first");
            let dili_priv = self.user_dili_priv.as_ref().expect("call generate_user_keys() first");
            let sig_ed = sign::sign_message(&body_bytes, ed_priv).expect("sign ed");
            let sig_dili = sign::sign_message_dili(&body_bytes, dili_priv).expect("sign dili");
            if ep.include_identity_keys() {
                app_headers["key-ed"] =
                    Value::String(self.user_ed_pub.as_ref().unwrap().to_hex().expose().to_string());
                app_headers["key-dili"] =
                    Value::String(self.user_dili_pub.as_ref().unwrap().to_hex().expose().to_string());
            }
            app_headers["sig-ed"] = Value::String(sig_ed.to_hex().expose().to_string());
            app_headers["sig-dili"] = Value::String(sig_dili.to_hex().expose().to_string());
        }

        let headers_bytes = serde_json::to_vec(&app_headers).expect("serialize headers");

        let (peer_x, peer_k, ses_x_id, ses_k_id) = if matches!(ep, Ep::Shake) {
            (self.bootstrap.shake_pub_x.clone(), self.bootstrap.shake_pub_k.clone(), None, None)
        } else {
            let px = self.st_take_byte32(ST_PEER_X).await
                .expect("server peer_x missing — call shake() first");
            let pk = self.st_take(ST_PEER_K).await
                .expect("server peer_k missing — call shake() first");
            let sx = self.st_take_str(ST_SES_X).await;
            let sk = self.st_take_str(ST_SES_K).await;
            (px, pk, sx, sk)
        };

        let (req_priv_x, req_pub_x) = keys::random_x25519_keypair().expect("x25519");
        let (req_priv_k, req_pub_k) = keys::random_kyber_mlkem1024_keypair().expect("kyber");

        let mut bp = body_bytes;

        pad_data(&mut bp);
        let mut hp = headers_bytes;
        pad_headers(&mut hp);

        let wire = kyberbox::encrypt(
            &ep.ctx_req(),
            &req_priv_x,
            &peer_x,
            &peer_k,
            &SecretBytes::new(bp),
            &SecretBytes::new(hp),
        )
        .expect("kyberbox encrypt");

        let mut h = HeaderMap::new();
        h.insert("key-x", hv(hex::encode(req_pub_x.as_slice())));
        h.insert("key-k", hv(hex::encode(req_pub_k.expose_as_slice())));
        h.insert("seed", hv(hex::encode(wire.seed_enc.expose_as_slice())));
        h.insert("data", hv(hex::encode(wire.enc_headers.expose_as_slice())));

        if ep.requires_session() {
            let sx = ses_x_id.expect("ses-x missing");
            let sk = ses_k_id.expect("ses-k missing");
            h.insert("ses-x", hv(sx.expose().to_owned()));
            h.insert("ses-k", hv(sk.expose().to_owned()));
            h.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/octet-stream"),
            );
        }

        let url = format!("{}{}", self.base, ep.path());
        let resp = self
            .http
            .post(&url)
            .headers(h)
            .body(wire.enc_body.expose_as_slice().to_vec())
            .send()
            .await
            .expect("http send");

        let status = resp.status().as_u16();

        if ep.returns_204() && status == 204 {
            return Ok(TestResponse { body: json!({}), headers: json!({}) });
        }

        if !resp.status().is_success() {
            let json: Value = resp.json().await.unwrap_or(Value::Null);
            return Err(RawResponse {
                status,
                error: json["error"].as_str().map(|s| s.to_owned()),
            });
        }

        let rh = resp.headers().clone();
        let resp_bytes = resp.bytes().await.expect("read body").to_vec();

        let resp_peer_x = Byte32::from_hex(&hdr(&rh, "key-x")).expect("key-x parse");
        let resp_peer_k = hex::decode(&hdr(&rh, "key-k")).expect("key-k hex");
        let resp_seed = hex::decode(&hdr(&rh, "seed")).expect("seed hex");
        let resp_data = hex::decode(&hdr(&rh, "data")).expect("data hex");

        let (mut dec_body, mut dec_headers) = kyberbox::decrypt(
            &ep.ctx_resp(),
            &req_priv_x,
            &resp_peer_x,
            &req_priv_k,
            &kyberbox::WirePayload {
                enc_body: SecretBytes::new(resp_bytes),
                enc_headers: SecretBytes::new(resp_data),
                seed_enc: SecretBytes::new(resp_seed),
            },
        )
        .expect("kyberbox decrypt");

        unpad(dec_body.expose_as_mut_vec()).expect("body unpad");
        unpad(dec_headers.expose_as_mut_vec()).expect("headers unpad");

        let sig_ed = hex::decode(hdr(&rh, "sig-ed")).expect("sig-ed hex");
        let sig_dili = hex::decode(hdr(&rh, "sig-dili")).expect("sig-dili hex");
        assert!(
            sign::verify_signature(dec_body.expose_as_slice(), &sig_ed, &self.bootstrap.server_sig_ed),
            "server Ed25519 signature invalid"
        );
        assert!(
            sign::verify_signature_dili(
                dec_body.expose_as_slice(),
                &sig_dili,
                &self.bootstrap.server_sig_dili,
            ),
            "server Dilithium signature invalid"
        );

        let body_val: Value = serde_json::from_slice(dec_body.expose_as_slice()).expect("body json");
        let headers_val: Value =
            serde_json::from_slice(dec_headers.expose_as_slice()).expect("headers json");

        self.st_set(ST_PEER_X, SecretBytes::from_slice(resp_peer_x.as_slice()), SESSION_TTL).await;
        self.st_set(ST_PEER_K, SecretBytes::new(resp_peer_k), SESSION_TTL).await;

        if let Some(sx) = headers_val.get("ses-x").and_then(|v| v.as_str()) {
            self.store_str(ST_SES_X, sx, SESSION_TTL).await;
        }
        if let Some(sk) = headers_val.get("ses-k").and_then(|v| v.as_str()) {
            self.store_str(ST_SES_K, sk, SESSION_TTL).await;
        }
        if let Some(tok) = body_val.get("tok").and_then(|v| v.as_str()) {
            self.store_str(ST_JWT, tok, JWT_TTL).await;
        }

        Ok(TestResponse { body: body_val, headers: headers_val })
    }

    async fn st_set(&self, key: &str, value: SecretBytes, ttl: Duration) {
        self.store.set(key, &value, ttl).await.expect("store set");
    }

    async fn store_str(&self, key: &str, value: &str, ttl: Duration) {
        self.st_set(key, SecretBytes::from_slice(value.as_bytes()), ttl).await;
    }

    async fn st_peek(&self, key: &str) -> Option<SecretBytes> {
        self.store.peek(key).await.expect("store peek")
    }

    async fn st_take(&self, key: &str) -> Option<SecretBytes> {
        self.store.take(key).await.expect("store take")
    }

    async fn st_take_str(&self, key: &str) -> Option<SecretString> {
        let v = self.st_take(key).await?;
        Some(SecretString::from_utf8_bytes(v.expose_as_slice()).expect("utf8"))
    }

    async fn st_take_byte32(&self, key: &str) -> Option<Byte32> {
        let v = self.st_take(key).await?;
        Some(Byte32::from_slice(v.expose_as_slice()).expect("byte32"))
    }
}

fn pad_block(buf: &mut Vec<u8>, block: usize) {
    let pad = (block - ((buf.len() + 1) % block)) % block;
    buf.push(0x80);
    buf.extend(std::iter::repeat_n(0u8, pad));
}

fn random_block_size() -> usize {
    use rand::{RngExt, rand_core::UnwrapErr, rngs::SysRng};
    UnwrapErr(SysRng).random_range(32 * 1024..=64 * 1024)
}

fn pad_data(buf: &mut Vec<u8>) { pad_block(buf, random_block_size()); }
fn pad_headers(buf: &mut Vec<u8>) { pad_block(buf, random_block_size() / 8); }

fn unpad(data: &mut Vec<u8>) -> Result<(), &'static str> {
    while let Some(&0) = data.last() { data.pop(); }
    if data.last() == Some(&0x80) { data.pop(); Ok(()) } else { data.zeroize(); Err("bad padding") }
}

fn hv(s: impl AsRef<str>) -> reqwest::header::HeaderValue {
    reqwest::header::HeaderValue::from_str(s.as_ref()).expect("header value")
}

fn hdr(h: &HeaderMap, name: &str) -> String {
    h.get(name)
        .unwrap_or_else(|| panic!("response header '{name}' missing"))
        .to_str()
        .expect("header utf8")
        .to_owned()
}

pub struct RawShakeBuilder {
    pub bootstrap: ServerBootstrap,
    pub base: String,
}

impl RawShakeBuilder {
    pub async fn send_with_ts(&self, ts_secs: u64) -> RawResponse {
        let body_json = json!({ "timestamp": format!("{:016x}", ts_secs) });
        let body_bytes = serde_json::to_vec(&body_json).unwrap();

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
        let headers_bytes = serde_json::to_vec(&app_headers).unwrap();

        let (req_priv_x, req_pub_x) = keys::random_x25519_keypair().unwrap();
        let (_, req_pub_k) = keys::random_kyber_mlkem1024_keypair().unwrap();

        let mut bp = body_bytes;
        pad_data(&mut bp);
        let mut hp = headers_bytes;
        pad_headers(&mut hp);

        let wire = kyberbox::encrypt(
            "shake-req",
            &req_priv_x,
            &self.bootstrap.shake_pub_x,
            &self.bootstrap.shake_pub_k,
            &SecretBytes::new(bp),
            &SecretBytes::new(hp),
        )
        .unwrap();

        let mut h = HeaderMap::new();
        h.insert("key-x", hv(hex::encode(req_pub_x.as_slice())));
        h.insert("key-k", hv(hex::encode(req_pub_k.expose_as_slice())));
        h.insert("seed", hv(hex::encode(wire.seed_enc.expose_as_slice())));
        h.insert("data", hv(hex::encode(wire.enc_headers.expose_as_slice())));

        let http = Client::new();
        let resp = http
            .post(format!("{}/shake", self.base))
            .headers(h)
            .body(wire.enc_body.expose_as_slice().to_vec())
            .send()
            .await
            .unwrap();

        let status = resp.status().as_u16();
        let json: Value = resp.json().await.unwrap_or(Value::Null);
        RawResponse { status, error: json["error"].as_str().map(|s| s.to_owned()) }
    }

    /// Send the exact same encrypted body twice; return the second response.
    pub async fn send_duplicate_body(&self) -> RawResponse {
        let body_bytes = {
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let body = json!({ "timestamp": format!("{:016x}", ts) });
            serde_json::to_vec(&body).unwrap()
        };

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
        let headers_bytes = serde_json::to_vec(&app_headers).unwrap();

        let (req_priv_x, req_pub_x) = keys::random_x25519_keypair().unwrap();
        let (_, req_pub_k) = keys::random_kyber_mlkem1024_keypair().unwrap();

        let mut bp = body_bytes;
        pad_data(&mut bp);
        let mut hp = headers_bytes;
        pad_headers(&mut hp);

        let wire = kyberbox::encrypt(
            "shake-req",
            &req_priv_x,
            &self.bootstrap.shake_pub_x,
            &self.bootstrap.shake_pub_k,
            &SecretBytes::new(bp),
            &SecretBytes::new(hp),
        )
        .unwrap();

        let make_headers = || {
            let mut h = HeaderMap::new();
            h.insert("key-x", hv(hex::encode(req_pub_x.as_slice())));
            h.insert("key-k", hv(hex::encode(req_pub_k.expose_as_slice())));
            h.insert("seed", hv(hex::encode(wire.seed_enc.expose_as_slice())));
            h.insert("data", hv(hex::encode(wire.enc_headers.expose_as_slice())));
            h
        };

        let enc_body = wire.enc_body.expose_as_slice().to_vec();
        let url = format!("{}/shake", self.base);
        let http = Client::new();

        // First request must succeed.
        let r1 = http.post(&url).headers(make_headers()).body(enc_body.clone()).send().await.unwrap();
        assert_eq!(r1.status().as_u16(), 200, "first shake should succeed");

        // Second request with identical body bytes.
        let r2 = http.post(&url).headers(make_headers()).body(enc_body).send().await.unwrap();
        let status = r2.status().as_u16();
        let json: Value = r2.json().await.unwrap_or(Value::Null);
        RawResponse { status, error: json["error"].as_str().map(|s| s.to_owned()) }
    }
}
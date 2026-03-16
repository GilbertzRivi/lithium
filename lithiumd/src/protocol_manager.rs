use std::{path::PathBuf, sync::Arc, time::Duration};

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::RngExt;
use reqwest::{header::HeaderMap, Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::sync::Mutex;
use zeroize::Zeroize;

use lithium_core::{
    crypto::{keys, kyberbox, sign},
    error::{LithiumError, Result},
    keys::{KeyManager, MkProvider},
    secrets::{Byte32, SecretString},
    secrets::bytes::SecretBytes,
    utils::store::EphemeralStoreManager,
};

const ST_SERVER_PEER_X: &str = "proto/server/peer_x";
const ST_SERVER_PEER_K: &str = "proto/server/peer_k";
const ST_SES_X: &str = "proto/server/ses_x";
const ST_SES_K: &str = "proto/server/ses_k";
const ST_JWT: &str = "proto/server/jwt";
const ST_DEK_ENC: &str = "proto/server/dek_enc";

const DEK_TTL: Duration = Duration::from_secs(3600);

fn obj_mut(v: &mut Value) -> Result<&mut Map<String, Value>> {
    v.as_object_mut().ok_or_else(LithiumError::json_not_object)
}


#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endpoint {
    Shake,
    Register,
    Login,
    RemoteDelete,
    Delete,
    MsgSend,
    MsgFetch,
}

impl Endpoint {
    pub fn path(&self) -> &str {
        match self {
            Endpoint::Shake => "/shake",
            Endpoint::Register => "/user/register",
            Endpoint::Login => "/user/login",
            Endpoint::RemoteDelete => "/user/revoke",
            Endpoint::Delete => "/user/delete",
            Endpoint::MsgSend => "/msg/send",
            Endpoint::MsgFetch => "/msg/fetch",
        }
    }

    pub fn ctx_base(&self) -> &str {
        match self {
            Endpoint::Shake => "shake",
            Endpoint::Register => "register",
            Endpoint::Login => "login",
            Endpoint::RemoteDelete => "revoke",
            Endpoint::Delete => "delete",
            Endpoint::MsgSend => "msg_send",
            Endpoint::MsgFetch => "msg_fetch",
        }
    }

    pub fn ctx_req(&self) -> String {
        format!("{}-req", self.ctx_base())
    }

    pub fn ctx_resp(&self) -> String {
        format!("{}-resp", self.ctx_base())
    }

    pub fn requires_session(&self) -> bool {
        !matches!(self, Endpoint::Shake)
    }

    pub fn requires_jwt(&self) -> bool {
        match self {
            Endpoint::Shake
            | Endpoint::Register
            | Endpoint::Login
            | Endpoint::RemoteDelete => false,
            Endpoint::Delete | Endpoint::MsgSend => true,
            Endpoint::MsgFetch => false,
        }
    }

    pub fn include_identity_keys_in_app_headers(&self) -> bool {
        matches!(self, Endpoint::Shake | Endpoint::Register | Endpoint::MsgFetch)
    }

    pub fn sign_with_ephemeral_keys(&self) -> bool {
        matches!(self, Endpoint::Shake | Endpoint::RemoteDelete | Endpoint::MsgFetch)
    }
}

#[derive(Clone)]
pub struct ServerBootstrap {
    pub shake_pub_x: Byte32,
    pub shake_pub_k: SecretBytes,
    pub server_sig_ed: Byte32,
    pub server_sig_dili: SecretBytes,
}

#[derive(Debug)]
pub struct ProtocolResponse {
    pub body: Value,
    pub headers: Value,
}

pub struct ProtocolManager<P: MkProvider> {
    base: Url,
    http: Client,
    store: EphemeralStoreManager,
    keys: Option<Arc<Mutex<KeyManager<P>>>>,

    /// Path to the server.identity file; bootstrap is loaded lazily on first connect.
    identity_path: PathBuf,
    bootstrap_cache: Mutex<Option<ServerBootstrap>>,

    session_ttl: Duration,
    jwt_ttl: Duration,

    lock: Mutex<()>,
    creds: Mutex<Option<(SecretString, SecretString)>>,
}

impl<P: MkProvider> ProtocolManager<P> {
    pub fn new(
        base: Url,
        http: Client,
        store: EphemeralStoreManager,
        keys: Option<Arc<Mutex<KeyManager<P>>>>,
        identity_path: PathBuf,
    ) -> Self {
        Self {
            base,
            http,
            store,
            keys,
            identity_path,
            bootstrap_cache: Mutex::new(None),
            session_ttl: Duration::from_secs(120),
            jwt_ttl: Duration::from_secs(120),
            lock: Mutex::new(()),
            creds: Mutex::new(None),
        }
    }

    pub async fn invalidate_bootstrap_cache(&self) {
        self.bootstrap_cache.lock().await.take();
    }

    async fn load_bootstrap(&self) -> Result<ServerBootstrap> {
        let mut guard = self.bootstrap_cache.lock().await;
        if let Some(b) = guard.clone() {
            return Ok(b);
        }
        let b = crate::identity::load(&self.identity_path)?;
        *guard = Some(b.clone());
        Ok(b)
    }

    pub async fn set_credentials(&self, handler: SecretString, password: SecretString) {
        *self.creds.lock().await = Some((handler, password));
    }

    pub async fn register(&self, dek_enc_hex: &str) -> Result<SecretString> {
        let creds = self.creds.lock().await.clone();
        let Some((handler, password)) = creds else {
            return Err(LithiumError::invalid_credentials("handler/password missing"));
        };
        self.register_with(handler, password, dek_enc_hex).await
    }

    pub async fn register_with(
        &self,
        handler: SecretString,
        password: SecretString,
        dek_enc_hex: &str,
    ) -> Result<SecretString> {
        let _g = self.lock.lock().await;
        self.ensure_shake().await?;
        self.do_register(handler, password, dek_enc_hex).await
    }

    pub async fn remote_delete(&self, capability: &SecretString) -> Result<()> {
        let _g = self.lock.lock().await;
        self.ensure_shake().await?;
        self.do_remote_delete(capability).await
    }

    pub async fn delete(&self) -> Result<()> {
        let _ = self.send(Endpoint::Delete, json!({}), json!({})).await?;
        let _ = self.clear_session_and_peer().await;
        let _ = self.store.del(ST_DEK_ENC).await;
        Ok(())
    }

    pub async fn get_dek(&self) -> Result<SecretString> {
        let _g = self.lock.lock().await;

        if let Some(v) = self.peek_string(ST_DEK_ENC).await? {
            return Ok(v);
        }

        self.ensure_shake().await?;
        let creds = self.creds.lock().await.clone();
        let Some((handler, password)) = creds else {
            return Err(LithiumError::invalid_credentials("handler/password missing"));
        };

        self.do_login(handler, password).await?;

        self.peek_string(ST_DEK_ENC)
            .await?
            .ok_or_else(|| LithiumError::state_missing(ST_DEK_ENC))
    }

    pub async fn send(
        &self,
        ep: Endpoint,
        body: Value,
        app_headers: Value,
    ) -> Result<ProtocolResponse> {
        let _g = self.lock.lock().await;

        if ep.requires_session() {
            self.ensure_shake().await?;
        }

        let mut body_try = body.clone();
        let app_headers_try = app_headers.clone();

        if ep.requires_jwt() {
            self.ensure_login().await?;

            let tok = self
                .take_string(ST_JWT)
                .await?
                .ok_or_else(|| LithiumError::state_missing(ST_JWT))?;

            obj_mut(&mut body_try)?
                .insert("token".into(), Value::String(tok.expose().to_owned()));
        }

        self.send_once(&ep, body_try, app_headers_try).await
    }

    async fn ensure_shake(&self) -> Result<()> {
        let has = self.peek_string(ST_SES_X).await?.is_some()
            && self.peek_string(ST_SES_K).await?.is_some()
            && self.peek_bytes(ST_SERVER_PEER_X).await?.is_some()
            && self.peek_bytes(ST_SERVER_PEER_K).await?.is_some();

        if has {
            return Ok(());
        }

        self.do_shake().await
    }

    async fn ensure_login(&self) -> Result<()> {
        if self.peek_string(ST_JWT).await?.is_some() {
            return Ok(());
        }

        let creds = self.creds.lock().await.clone();
        let Some((handler, password)) = creds else {
            return Err(LithiumError::invalid_credentials("handler/password missing"));
        };

        self.do_login(handler, password).await
    }

    async fn do_shake(&self) -> Result<()> {
        self.clear_session_and_peer().await?;
        let resp = self.send_once(&Endpoint::Shake, json!({}), json!({})).await?;

        let ses_x = resp
            .headers
            .get("ses-x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("ses-x"))?;
        let ses_k = resp
            .headers
            .get("ses-k")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("ses-k"))?;

        self.store_string(ST_SES_X, ses_x, self.session_ttl).await?;
        self.store_string(ST_SES_K, ses_k, self.session_ttl).await?;
        Ok(())
    }

    async fn do_login(&self, handler: SecretString, password: SecretString) -> Result<()> {
        let body = json!({
            "handler": handler.expose(),
            "password": password.expose(),
        });

        let resp = self.send_once(&Endpoint::Login, body, json!({})).await?;

        let tok = resp
            .body
            .get("tok")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("tok"))?;
        let dek = resp
            .body
            .get("dek")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("dek"))?;

        let ses_x = resp
            .headers
            .get("ses-x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("ses-x"))?;
        let ses_k = resp
            .headers
            .get("ses-k")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("ses-k"))?;

        self.store_string(ST_SES_X, ses_x, self.session_ttl).await?;
        self.store_string(ST_SES_K, ses_k, self.session_ttl).await?;

        self.store_string(ST_JWT, tok, self.jwt_ttl).await?;
        self.store_string(ST_DEK_ENC, dek, DEK_TTL).await?;
        Ok(())
    }

    async fn do_register(
        &self,
        handler: SecretString,
        password: SecretString,
        dek_enc_hex: &str,
    ) -> Result<SecretString> {
        let body = json!({
            "handler": handler.expose(),
            "password": password.expose(),
            "dek": dek_enc_hex,
        });

        let resp = self.send_once(&Endpoint::Register, body, json!({})).await?;

        let _msg = resp
            .body
            .get("msg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("msg"))?;

        let capability = resp
            .body
            .get("capability")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("capability"))?;

        self.store_string(ST_DEK_ENC, dek_enc_hex, DEK_TTL).await?;
        Ok(SecretString::new(capability.to_owned()))
    }

    async fn do_remote_delete(&self, capability: &SecretString) -> Result<()> {
        let body = json!({
            "capability": capability.expose(),
        });

        let _ = self
            .send_once(&Endpoint::RemoteDelete, body, json!({}))
            .await?;
        Ok(())
    }

    async fn send_once(
        &self,
        ep: &Endpoint,
        mut body: Value,
        mut app_headers: Value,
    ) -> Result<ProtocolResponse> {
        let bootstrap = self.load_bootstrap().await?;
        obj_mut(&mut body)?;
        obj_mut(&mut app_headers)?;

        {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            obj_mut(&mut body)?.insert("timestamp".into(), Value::String(format!("{:016x}", ts)));
        }

        let body_bytes = serde_json::to_vec(&body).map_err(LithiumError::json_parse)?;

        if ep.sign_with_ephemeral_keys() {
            let (ed_pub, sig_ed, dili_pub, sig_dili) = Self::sign_dual_ephemeral(&body_bytes)?;
            obj_mut(&mut app_headers)?.insert(
                "key-ed".into(),
                Value::String(ed_pub.to_hex().expose().to_string()),
            );
            obj_mut(&mut app_headers)?.insert(
                "key-dili".into(),
                Value::String(dili_pub.to_hex().expose().to_string()),
            );
            obj_mut(&mut app_headers)?.insert(
                "sig-ed".into(),
                Value::String(sig_ed.to_hex().expose().to_string()),
            );
            obj_mut(&mut app_headers)?.insert(
                "sig-dili".into(),
                Value::String(sig_dili.to_hex().expose().to_string()),
            );
        } else {
            let (sig_ed, sig_dili) = self.sign_dual(&body_bytes).await?;

            if ep.include_identity_keys_in_app_headers() {
                let Some(keys) = self.keys.as_ref() else {
                    return Err(LithiumError::invalid_credentials("keystore_locked"));
                };

                let km = keys.lock().await;
                obj_mut(&mut app_headers)?.insert(
                    "key-ed".into(),
                    Value::String(km.public_keys().ed25519.to_hex().expose().to_string()),
                );
                obj_mut(&mut app_headers)?.insert(
                    "key-dili".into(),
                    Value::String(km.public_keys().dilithium.to_hex().expose().to_string()),
                );
                drop(km);
            }

            obj_mut(&mut app_headers)?.insert(
                "sig-ed".into(),
                Value::String(sig_ed.to_hex().expose().to_string()),
            );
            obj_mut(&mut app_headers)?.insert(
                "sig-dili".into(),
                Value::String(sig_dili.to_hex().expose().to_string()),
            );
        }

        let headers_bytes = serde_json::to_vec(&app_headers).map_err(LithiumError::json_parse)?;

        let (peer_x, peer_k, ses_x, ses_k) = if matches!(ep, Endpoint::Shake) {
            (
                bootstrap.shake_pub_x.clone(),
                bootstrap.shake_pub_k.clone(),
                None,
                None,
            )
        } else {
            let peer_x = self
                .take_byte32(ST_SERVER_PEER_X)
                .await?
                .ok_or_else(|| LithiumError::state_missing(ST_SERVER_PEER_X))?;
            let peer_k = self
                .take_bytes(ST_SERVER_PEER_K)
                .await?
                .ok_or_else(|| LithiumError::state_missing(ST_SERVER_PEER_K))?;
            let ses_x = self.take_string(ST_SES_X).await?;
            let ses_k = self.take_string(ST_SES_K).await?;
            (peer_x, peer_k, ses_x, ses_k)
        };

        let (req_priv_x, req_pub_x) = keys::random_x25519_keypair()?;
        let (req_priv_k, req_pub_k) = keys::random_kyber_mlkem1024_keypair()?;

        let mut body_plain = body_bytes;
        pad_data(&mut body_plain);
        let mut headers_plain = headers_bytes;
        pad_headers(&mut headers_plain);

        let wire = kyberbox::encrypt(
            &ep.ctx_req(),
            &req_priv_x,
            &peer_x,
            &peer_k,
            &SecretBytes::new(body_plain),
            &SecretBytes::new(headers_plain),
        )?;

        let mut h = HeaderMap::new();
        h.insert("key-x", hv_hex(req_pub_x.as_slice())?);
        h.insert("key-k", hv_hex(req_pub_k.expose_as_slice())?);
        h.insert("seed", hv_hex(wire.seed_enc.expose_as_slice())?);
        h.insert("data", hv_hex(wire.enc_headers.expose_as_slice())?);

        if ep.requires_session() {
            let sx = ses_x.ok_or_else(|| LithiumError::state_missing(ST_SES_X))?;
            let sk = ses_k.ok_or_else(|| LithiumError::state_missing(ST_SES_K))?;
            h.insert(
                "ses-x",
                reqwest::header::HeaderValue::from_str(sx.expose())
                    .map_err(|_| LithiumError::internal())?,
            );
            h.insert(
                "ses-k",
                reqwest::header::HeaderValue::from_str(sk.expose())
                    .map_err(|_| LithiumError::internal())?,
            );
            h.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/octet-stream"),
            );
        }

        let url = self.base.join(ep.path()).map_err(|_| LithiumError::internal())?;
        let resp = self
            .http
            .post(url)
            .headers(h)
            .body(wire.enc_body.expose_as_slice().to_vec())
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    LithiumError::timeout(e)
                } else {
                    LithiumError::transport(e)
                }
            })?;

        let status = resp.status();

        if matches!(ep, Endpoint::RemoteDelete) && status.as_u16() == 204 {
            return Ok(ProtocolResponse {
                body: json!({}),
                headers: json!({}),
            });
        }

        if !status.is_success() {
            return Err(match status.as_u16() {
                401 => LithiumError::invalid_credentials("http_401"),
                403 => LithiumError::invalid_perms("http_403"),
                c => LithiumError::http_status(c),
            });
        }

        let rh = resp.headers().clone();
        let resp_body_bytes = resp.bytes().await.map_err(LithiumError::io)?.to_vec();

        let resp_peer_x = Byte32::from_hex(get_header_str(&rh, "key-x")?.as_str())?;
        let resp_peer_k =
            hex::decode(get_header_str(&rh, "key-k")?).map_err(LithiumError::invalid_hex)?;
        let resp_seed =
            hex::decode(get_header_str(&rh, "seed")?).map_err(LithiumError::invalid_hex)?;
        let resp_data =
            hex::decode(get_header_str(&rh, "data")?).map_err(LithiumError::invalid_hex)?;

        let (dec_body_secret, dec_headers_secret) = kyberbox::decrypt(
            &ep.ctx_resp(),
            &req_priv_x,
            &resp_peer_x,
            &req_priv_k,
            &kyberbox::WirePayload {
                enc_body: SecretBytes::new(resp_body_bytes),
                enc_headers: SecretBytes::new(resp_data),
                seed_enc: SecretBytes::new(resp_seed),
            },
        )?;

        let mut dec_body = dec_body_secret.expose_as_slice().to_vec();
        let mut dec_headers = dec_headers_secret.expose_as_slice().to_vec();

        unpad_block(&mut dec_body)?;
        unpad_block(&mut dec_headers)?;

        let sig_ed =
            hex::decode(get_header_str(&rh, "sig-ed")?).map_err(LithiumError::invalid_hex)?;
        let sig_dili =
            hex::decode(get_header_str(&rh, "sig-dili")?).map_err(LithiumError::invalid_hex)?;

        let ok1 = sign::verify_signature(&dec_body, &sig_ed, &bootstrap.server_sig_ed);
        let ok2 =
            sign::verify_signature_dili(&dec_body, &sig_dili, &bootstrap.server_sig_dili);
        if !(ok1 && ok2) {
            return Err(LithiumError::invalid_credentials("server_signature_invalid"));
        }

        let body_val: Value = serde_json::from_slice(&dec_body).map_err(LithiumError::json_parse)?;
        let headers_val: Value =
            serde_json::from_slice(&dec_headers).map_err(LithiumError::json_parse)?;

        self.store_bytes(ST_SERVER_PEER_X, resp_peer_x.as_slice(), self.session_ttl)
            .await?;
        self.store_bytes(ST_SERVER_PEER_K, resp_peer_k.as_slice(), self.session_ttl)
            .await?;

        if let Some(sx) = headers_val.get("ses-x").and_then(|v| v.as_str()) {
            self.store_string(ST_SES_X, sx, self.session_ttl).await?;
        }
        if let Some(sk) = headers_val.get("ses-k").and_then(|v| v.as_str()) {
            self.store_string(ST_SES_K, sk, self.session_ttl).await?;
        }

        if let Some(tok) = body_val.get("tok").and_then(|v| v.as_str()) {
            self.store_string(ST_JWT, tok, self.jwt_ttl).await?;
        }
        if let Some(dek) = body_val.get("dek").and_then(|v| v.as_str()) {
            self.store_string(ST_DEK_ENC, dek, DEK_TTL).await?;
        }

        Ok(ProtocolResponse {
            body: body_val,
            headers: headers_val,
        })
    }

    async fn sign_dual(&self, msg: &[u8]) -> Result<(SecretBytes, SecretBytes)> {
        let Some(keys) = self.keys.as_ref() else {
            return Err(LithiumError::invalid_credentials("keystore_locked"));
        };

        let km = keys.lock().await;
        let sig_ed = km.with_ed_sk(|sk| sign::sign_message(msg, sk))?;
        let sig_dili = km.with_dilithium_sk(|sk| sign::sign_message_dili(msg, sk))?;
        Ok((sig_ed, sig_dili))
    }

    fn sign_dual_ephemeral(
        msg: &[u8],
    ) -> Result<(Byte32, SecretBytes, SecretBytes, SecretBytes)> {
        let (ed_priv, ed_pub) = keys::random_ed25519_keypair()?;
        let (dili_priv, dili_pub) = keys::random_dilithium_mldsa87_keypair()?;

        let sig_ed = sign::sign_message(msg, &ed_priv)?;
        let sig_dili = sign::sign_message_dili(msg, &dili_priv)?;

        Ok((ed_pub, sig_ed, dili_pub, sig_dili))
    }

    async fn clear_session_and_peer(&self) -> Result<()> {
        let _ = self.store.del(ST_SES_X).await;
        let _ = self.store.del(ST_SES_K).await;
        let _ = self.store.del(ST_SERVER_PEER_X).await;
        let _ = self.store.del(ST_SERVER_PEER_K).await;
        let _ = self.store.del(ST_JWT).await;
        Ok(())
    }

    async fn store_string(&self, key: &str, value: &str, ttl: Duration) -> Result<()> {
        self.store
            .set(key, &SecretBytes::from_slice(value.as_bytes()), ttl)
            .await
    }

    async fn store_bytes(&self, key: &str, value: &[u8], ttl: Duration) -> Result<()> {
        self.store.set(key, &SecretBytes::from_slice(value), ttl).await
    }

    async fn peek_string(&self, key: &str) -> Result<Option<SecretString>> {
        let Some(v) = self.store.peek(key).await? else {
            return Ok(None);
        };
        let s = SecretString::from_utf8_bytes(v.expose_as_slice())?;
        Ok(Some(s))
    }

    async fn take_string(&self, key: &str) -> Result<Option<SecretString>> {
        let Some(v) = self.store.take(key).await? else {
            return Ok(None);
        };
        let s = SecretString::from_utf8_bytes(v.expose_as_slice())?;
        Ok(Some(s))
    }

    async fn peek_bytes(&self, key: &str) -> Result<Option<SecretBytes>> {
        let Some(v) = self.store.peek(key).await? else {
            return Ok(None);
        };
        Ok(Some(v))
    }

    async fn take_bytes(&self, key: &str) -> Result<Option<SecretBytes>> {
        let Some(v) = self.store.take(key).await? else {
            return Ok(None);
        };
        Ok(Some(v))
    }

    async fn take_byte32(&self, key: &str) -> Result<Option<Byte32>> {
        let Some(v) = self.store.take(key).await? else {
            return Ok(None);
        };
        let b = Byte32::from_slice(v.expose_as_slice())?;
        Ok(Some(b))
    }
}

fn hv_hex(bytes: &[u8]) -> Result<reqwest::header::HeaderValue> {
    let s = hex::encode(bytes);
    reqwest::header::HeaderValue::from_str(&s).map_err(|_| LithiumError::internal())
}

fn get_header_str(h: &HeaderMap, name: &'static str) -> Result<String> {
    let v = h.get(name).ok_or_else(|| LithiumError::missing_header(name))?;
    let s = v
        .to_str()
        .map_err(|e| LithiumError::invalid_utf8_header(name, e))?;
    Ok(s.to_string())
}

fn pad_block(buf: &mut Vec<u8>, block_size: usize) {
    let total_len = buf.len() + 1;
    let pad_len = (block_size - (total_len % block_size)) % block_size;
    buf.reserve(1 + pad_len);
    buf.push(0x80);
    buf.extend(std::iter::repeat(0u8).take(pad_len));
}

fn random_block_size() -> usize {
    let min = 32 * 1024;
    let max = 64 * 1024;
    UnwrapErr(SysRng).random_range(min..=max)
}

pub fn pad_data(buf: &mut Vec<u8>) {
    pad_block(buf, random_block_size())
}

pub fn pad_headers(buf: &mut Vec<u8>) {
    pad_block(buf, random_block_size() / 8)
}

pub fn unpad_block(data: &mut Vec<u8>) -> std::result::Result<(), LithiumError> {
    while let Some(&0) = data.last() {
        data.pop();
    }
    match data.last() {
        Some(&0x80) => {
            data.pop();
            Ok(())
        }
        _ => {
            data.zeroize();
            Err(LithiumError::aead_failed())
        }
    }
}
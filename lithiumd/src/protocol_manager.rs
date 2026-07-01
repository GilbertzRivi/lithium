// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::{path::PathBuf, sync::Arc, time::Duration};

use rand::RngExt;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use reqwest::{Client, Url, header::HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;
use zeroize::Zeroize;

use lithium_proto::contract::protocol::{self, ctx, field, header, path};
use lithium_proto::labels;

use lithium_core::{
    crypto::{keys, kyberbox, sign},
    error::{LithiumError, Result},
    keys::{KeyManager, MkProvider},
    opaque::client::{
        client_login_finish, client_login_start, client_registration_finish,
        client_registration_start,
    },
    pow,
    secrets::bytes::SecretBytes,
    secrets::{Byte32, Byte64, SecretString},
    utils::store::EphemeralStoreManager,
};

const ST_SERVER_PEER_X: &str = "proto/server/peer_x";
const ST_SERVER_PEER_K: &str = "proto/server/peer_k";
const ST_SES_X: &str = "proto/server/ses_x";
const ST_SES_K: &str = "proto/server/ses_k";
const ST_JWT: &str = "proto/server/jwt";
const ST_DEK_ENC: &str = "proto/server/dek_enc";
const ST_EXPORT: &str = "proto/server/export_key";

const DEK_TTL: Duration = Duration::from_secs(3600);

fn obj_mut(v: &mut Value) -> Result<&mut Map<String, Value>> {
    v.as_object_mut().ok_or_else(LithiumError::json_not_object)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endpoint {
    Shake,
    RegisterStart,
    RegisterFinish,
    LoginStart,
    LoginFinish,
    RemoteDelete,
    Delete,
    MsgSend,
    MsgFetch,
}

impl Endpoint {
    pub fn path(&self) -> &str {
        match self {
            Endpoint::Shake => path::SHAKE,
            Endpoint::RegisterStart => path::REGISTER_START,
            Endpoint::RegisterFinish => path::REGISTER_FINISH,
            Endpoint::LoginStart => path::LOGIN_START,
            Endpoint::LoginFinish => path::LOGIN_FINISH,
            Endpoint::RemoteDelete => path::REVOKE,
            Endpoint::Delete => path::DELETE,
            Endpoint::MsgSend => path::MSG_SEND,
            Endpoint::MsgFetch => path::MSG_FETCH,
        }
    }

    pub fn ctx_base(&self) -> &str {
        match self {
            Endpoint::Shake => ctx::SHAKE,
            Endpoint::RegisterStart => ctx::REGISTER_START,
            Endpoint::RegisterFinish => ctx::REGISTER_FINISH,
            Endpoint::LoginStart => ctx::LOGIN_START,
            Endpoint::LoginFinish => ctx::LOGIN_FINISH,
            Endpoint::RemoteDelete => ctx::REVOKE,
            Endpoint::Delete => ctx::DELETE,
            Endpoint::MsgSend => ctx::MSG_SEND,
            Endpoint::MsgFetch => ctx::MSG_FETCH,
        }
    }

    pub fn ctx_req(&self) -> String {
        protocol::ctx_req(self.ctx_base())
    }

    pub fn ctx_resp(&self) -> String {
        protocol::ctx_resp(self.ctx_base())
    }

    pub fn requires_session(&self) -> bool {
        !matches!(self, Endpoint::Shake)
    }

    pub fn requires_jwt(&self) -> bool {
        matches!(self, Endpoint::Delete)
    }

    // send/fetch carry no account identity, so they ride a throwaway session
    // never shared with an identity-bound login.
    pub fn is_anonymous(&self) -> bool {
        matches!(self, Endpoint::MsgSend | Endpoint::MsgFetch)
    }

    pub fn include_identity_keys_in_app_headers(&self) -> bool {
        matches!(self, Endpoint::RegisterStart | Endpoint::RegisterFinish)
    }

    pub fn sign_with_ephemeral_keys(&self) -> bool {
        matches!(
            self,
            Endpoint::Shake | Endpoint::RemoteDelete | Endpoint::MsgFetch | Endpoint::MsgSend
        )
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

    pub async fn register(&self, dek: &Byte32) -> Result<SecretString> {
        let creds = self.creds.lock().await.clone();
        let Some((handler, password)) = creds else {
            return Err(LithiumError::invalid_credentials(
                "handler/password missing",
            ));
        };
        self.register_with(handler, password, dek).await
    }

    pub async fn register_with(
        &self,
        handler: SecretString,
        password: SecretString,
        dek: &Byte32,
    ) -> Result<SecretString> {
        let _g = self.lock.lock().await;
        self.ensure_shake().await?;
        self.do_register(handler, password, dek).await
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
            return Err(LithiumError::invalid_credentials(
                "handler/password missing",
            ));
        };

        self.do_login(handler, password).await?;

        self.peek_string(ST_DEK_ENC)
            .await?
            .ok_or_else(|| LithiumError::state_missing(ST_DEK_ENC))
    }

    pub async fn get_export_key(&self) -> Result<Byte64> {
        let _g = self.lock.lock().await;
        let v = self
            .peek_bytes(ST_EXPORT)
            .await?
            .ok_or_else(|| LithiumError::state_missing(ST_EXPORT))?;
        Byte64::from_slice(v.expose_as_slice())
    }

    pub async fn send(
        &self,
        ep: Endpoint,
        body: Value,
        app_headers: Value,
    ) -> Result<ProtocolResponse> {
        let _g = self.lock.lock().await;

        let mut body_try = body;

        if ep.is_anonymous() {
            let bits = self.fresh_anon_shake().await?;
            if matches!(ep, Endpoint::MsgSend) {
                self.attach_pow(&mut body_try, bits)?;
            }
            let result = self.send_once(&ep, body_try, app_headers).await;
            let _ = self.clear_anon_session().await;
            return result;
        }

        if ep.requires_session() {
            self.ensure_shake().await?;
        }

        if ep.requires_jwt() {
            self.ensure_login().await?;

            let tok = self
                .take_string(ST_JWT)
                .await?
                .ok_or_else(|| LithiumError::state_missing(ST_JWT))?;

            obj_mut(&mut body_try)?
                .insert(field::TOKEN.into(), Value::String(tok.expose().to_owned()));
        }

        self.send_once(&ep, body_try, app_headers).await
    }

    async fn fresh_anon_shake(&self) -> Result<u32> {
        self.clear_anon_session().await?;
        let resp = self
            .send_once(&Endpoint::Shake, json!({}), json!({}))
            .await?;
        let bits = resp
            .body
            .get(field::POW)
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        Ok(bits)
    }

    async fn clear_anon_session(&self) -> Result<()> {
        let _ = self.store.del(ST_SES_X).await;
        let _ = self.store.del(ST_SES_K).await;
        let _ = self.store.del(ST_SERVER_PEER_X).await;
        let _ = self.store.del(ST_SERVER_PEER_K).await;
        Ok(())
    }

    fn attach_pow(&self, body: &mut Value, bits: u32) -> Result<()> {
        let obj = obj_mut(body)?;
        let mailbox = hex::decode(
            obj.get(field::MAILBOX)
                .and_then(|v| v.as_str())
                .ok_or_else(|| LithiumError::json_missing_field(field::MAILBOX))?,
        )
        .map_err(LithiumError::invalid_hex)?;
        let content = hex::decode(
            obj.get(field::CONTENT)
                .and_then(|v| v.as_str())
                .ok_or_else(|| LithiumError::json_missing_field(field::CONTENT))?,
        )
        .map_err(LithiumError::invalid_hex)?;

        let challenge = pow::challenge(labels::POW_CTX, &mailbox, &content);
        let budget = (1u64 << bits.min(24)).saturating_mul(256);
        let nonce = pow::try_solve(&challenge, bits, budget).ok_or_else(LithiumError::internal)?;
        obj.insert(field::POW.into(), Value::String(nonce.to_string()));
        Ok(())
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
            return Err(LithiumError::invalid_credentials(
                "handler/password missing",
            ));
        };

        self.do_login(handler, password).await
    }

    async fn do_shake(&self) -> Result<()> {
        self.clear_session_and_peer().await?;
        let resp = self
            .send_once(&Endpoint::Shake, json!({}), json!({}))
            .await?;

        let ses_x = resp
            .headers
            .get(header::SES_X)
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field(header::SES_X))?;
        let ses_k = resp
            .headers
            .get(header::SES_K)
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field(header::SES_K))?;

        self.store_string(ST_SES_X, ses_x, self.session_ttl).await?;
        self.store_string(ST_SES_K, ses_k, self.session_ttl).await?;
        Ok(())
    }

    async fn do_login(&self, handler: SecretString, password: SecretString) -> Result<()> {
        let handler_norm = protocol::normalize_handler(handler.expose());

        let (request, client_state) = client_login_start(&password)?;
        let body1 = json!({
            field::HANDLER: handler.expose(),
            field::OPAQUE: hex::encode(request),
        });
        let resp1 = self
            .send_once(&Endpoint::LoginStart, body1, json!({}))
            .await?;

        let response = hex::decode(
            resp1
                .body
                .get(field::OPAQUE)
                .and_then(|v| v.as_str())
                .ok_or_else(|| LithiumError::json_missing_field(field::OPAQUE))?,
        )
        .map_err(LithiumError::invalid_hex)?;
        let flow = resp1
            .body
            .get(field::FLOW)
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field(field::FLOW))?
            .to_owned();

        let (finalization, export_key) = client_login_finish(
            client_state,
            &response,
            &password,
            handler_norm.as_bytes(),
            labels::OPAQUE_SERVER_ID,
        )?;

        let body2 = json!({
            field::HANDLER: handler.expose(),
            field::FLOW: flow,
            field::OPAQUE: hex::encode(finalization),
        });
        let _ = self
            .send_once(&Endpoint::LoginFinish, body2, json!({}))
            .await?;

        self.store_bytes(ST_EXPORT, export_key.as_slice(), DEK_TTL)
            .await?;
        Ok(())
    }

    async fn do_register(
        &self,
        handler: SecretString,
        password: SecretString,
        dek: &Byte32,
    ) -> Result<SecretString> {
        let handler_norm = protocol::normalize_handler(handler.expose());

        let (request, client_state) = client_registration_start(&password)?;
        let body1 = json!({
            field::HANDLER: handler.expose(),
            field::OPAQUE: hex::encode(request),
        });
        let resp1 = self
            .send_once(&Endpoint::RegisterStart, body1, json!({}))
            .await?;

        let response = hex::decode(
            resp1
                .body
                .get(field::OPAQUE)
                .and_then(|v| v.as_str())
                .ok_or_else(|| LithiumError::json_missing_field(field::OPAQUE))?,
        )
        .map_err(LithiumError::invalid_hex)?;

        let (upload, export_key) = client_registration_finish(
            client_state,
            &response,
            &password,
            handler_norm.as_bytes(),
            labels::OPAQUE_SERVER_ID,
        )?;

        let dek_enc_hex = lithium_core::opaque::dek::wrap_dek_under_export_key(
            dek,
            &export_key,
            labels::DEK_WRAP_AAD,
        )?;

        let body2 = json!({
            field::HANDLER: handler.expose(),
            field::OPAQUE: hex::encode(upload),
            field::DEK: dek_enc_hex.expose(),
        });
        let resp2 = self
            .send_once(&Endpoint::RegisterFinish, body2, json!({}))
            .await?;

        let capability = resp2
            .body
            .get(field::CAPABILITY)
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field(field::CAPABILITY))?;

        self.store_string(ST_DEK_ENC, dek_enc_hex.expose(), DEK_TTL)
            .await?;
        self.store_bytes(ST_EXPORT, export_key.as_slice(), DEK_TTL)
            .await?;
        Ok(SecretString::new(capability.to_owned()))
    }

    async fn do_remote_delete(&self, capability: &SecretString) -> Result<()> {
        let body = json!({
            field::CAPABILITY: capability.expose(),
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
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            obj_mut(&mut body)?.insert(
                field::TIMESTAMP.into(),
                Value::String(protocol::format_timestamp(ts)),
            );
        }

        let body_bytes = serde_json::to_vec(&body).map_err(LithiumError::json_parse)?;

        if ep.sign_with_ephemeral_keys() {
            let (ed_pub, sig_ed, dili_pub, sig_dili) = Self::sign_dual_ephemeral(&body_bytes)?;
            obj_mut(&mut app_headers)?.insert(
                header::KEY_ED.into(),
                Value::String(ed_pub.to_hex().expose().to_string()),
            );
            obj_mut(&mut app_headers)?.insert(
                header::KEY_DILI.into(),
                Value::String(dili_pub.to_hex().expose().to_string()),
            );
            obj_mut(&mut app_headers)?.insert(
                header::SIG_ED.into(),
                Value::String(sig_ed.to_hex().expose().to_string()),
            );
            obj_mut(&mut app_headers)?.insert(
                header::SIG_DILI.into(),
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
                    header::KEY_ED.into(),
                    Value::String(km.public_keys().ed25519.to_hex().expose().to_string()),
                );
                obj_mut(&mut app_headers)?.insert(
                    header::KEY_DILI.into(),
                    Value::String(km.public_keys().dilithium.to_hex().expose().to_string()),
                );
                drop(km);
            }

            obj_mut(&mut app_headers)?.insert(
                header::SIG_ED.into(),
                Value::String(sig_ed.to_hex().expose().to_string()),
            );
            obj_mut(&mut app_headers)?.insert(
                header::SIG_DILI.into(),
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
        h.insert(header::KEY_X, hv_hex(req_pub_x.as_slice())?);
        h.insert(header::KEY_K, hv_hex(req_pub_k.expose_as_slice())?);
        h.insert(header::KEM_CT, hv_hex(wire.kem_ct.expose_as_slice())?);
        h.insert(header::DATA, hv_hex(wire.enc_headers.expose_as_slice())?);

        if ep.requires_session() {
            let sx = ses_x.ok_or_else(|| LithiumError::state_missing(ST_SES_X))?;
            let sk = ses_k.ok_or_else(|| LithiumError::state_missing(ST_SES_K))?;
            h.insert(
                header::SES_X,
                reqwest::header::HeaderValue::from_str(sx.expose())
                    .map_err(|_| LithiumError::internal())?,
            );
            h.insert(
                header::SES_K,
                reqwest::header::HeaderValue::from_str(sk.expose())
                    .map_err(|_| LithiumError::internal())?,
            );
            h.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/octet-stream"),
            );
        }

        let url = self
            .base
            .join(ep.path())
            .map_err(|_| LithiumError::internal())?;
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

        let resp_peer_x = Byte32::from_hex(get_header_str(&rh, header::KEY_X)?.as_str())?;
        let resp_peer_k =
            hex::decode(get_header_str(&rh, header::KEY_K)?).map_err(LithiumError::invalid_hex)?;
        let resp_kem_ct =
            hex::decode(get_header_str(&rh, header::KEM_CT)?).map_err(LithiumError::invalid_hex)?;
        let resp_data =
            hex::decode(get_header_str(&rh, header::DATA)?).map_err(LithiumError::invalid_hex)?;

        let (dec_body_secret, dec_headers_secret) = kyberbox::decrypt(
            &ep.ctx_resp(),
            &req_priv_x,
            &resp_peer_x,
            &req_priv_k,
            &kyberbox::WirePayload {
                enc_body: SecretBytes::new(resp_body_bytes),
                enc_headers: SecretBytes::new(resp_data),
                kem_ct: SecretBytes::new(resp_kem_ct),
            },
        )?;

        let mut dec_body = dec_body_secret.expose_as_slice().to_vec();
        let mut dec_headers = dec_headers_secret.expose_as_slice().to_vec();

        unpad_block(&mut dec_body)?;
        unpad_block(&mut dec_headers)?;

        let sig_ed =
            hex::decode(get_header_str(&rh, header::SIG_ED)?).map_err(LithiumError::invalid_hex)?;
        let sig_dili = hex::decode(get_header_str(&rh, header::SIG_DILI)?)
            .map_err(LithiumError::invalid_hex)?;

        let ok1 = sign::verify_signature(&dec_body, &sig_ed, &bootstrap.server_sig_ed);
        let ok2 = sign::verify_signature_dili(&dec_body, &sig_dili, &bootstrap.server_sig_dili);
        if !(ok1 && ok2) {
            return Err(LithiumError::invalid_credentials(
                "server_signature_invalid",
            ));
        }

        let body_val: Value =
            serde_json::from_slice(&dec_body).map_err(LithiumError::json_parse)?;
        let headers_val: Value =
            serde_json::from_slice(&dec_headers).map_err(LithiumError::json_parse)?;

        self.store_bytes(ST_SERVER_PEER_X, resp_peer_x.as_slice(), self.session_ttl)
            .await?;
        self.store_bytes(ST_SERVER_PEER_K, resp_peer_k.as_slice(), self.session_ttl)
            .await?;

        if let Some(sx) = headers_val.get(header::SES_X).and_then(|v| v.as_str()) {
            self.store_string(ST_SES_X, sx, self.session_ttl).await?;
        }
        if let Some(sk) = headers_val.get(header::SES_K).and_then(|v| v.as_str()) {
            self.store_string(ST_SES_K, sk, self.session_ttl).await?;
        }

        if let Some(tok) = body_val.get(field::TOK).and_then(|v| v.as_str()) {
            self.store_string(ST_JWT, tok, self.jwt_ttl).await?;
        }
        if let Some(dek) = body_val.get(field::DEK).and_then(|v| v.as_str()) {
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
        km.with_signing_keys(|ed_sk, dili_sk| {
            Ok((
                sign::sign_message(msg, ed_sk)?,
                sign::sign_message_dili(msg, dili_sk)?,
            ))
        })
    }

    fn sign_dual_ephemeral(msg: &[u8]) -> Result<(Byte32, SecretBytes, SecretBytes, SecretBytes)> {
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
        self.store
            .set(key, &SecretBytes::from_slice(value), ttl)
            .await
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
    let v = h
        .get(name)
        .ok_or_else(|| LithiumError::missing_header(name))?;
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
    buf.extend(std::iter::repeat_n(0u8, pad_len));
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

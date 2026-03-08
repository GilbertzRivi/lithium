use rand::distr::{Alphanumeric, Distribution};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use poem::{
    http::header,
    http::StatusCode,
    Body, Error as PoemError, FromRequest, Request, RequestBody, Response,
    Result as PoemResult,
};
use rand::{rngs::SysRng, RngExt};
use rand::rand_core::UnwrapErr;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{Mutex, MutexGuard};
use zeroize::Zeroize;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use lithium_core::crypto::{keys, kyberbox, sign};
use lithium_core::crypto::kyberbox::WirePayload;
use lithium_core::db::manager::DataManager;
use lithium_core::error::LithiumError;
use lithium_core::keys::PlainFileMkProvider;
use lithium_core::secrets::{Byte32, Byte64, SecretJson, SecretString};
use lithium_core::secrets::bytes::SecretBytes;
use lithium_core::utils::headers::{header_hex, header_hex_bytes, header_str};
use lithium_core::utils::store::EphemeralStoreManager;

use crate::db::models;
use crate::db::repo::ServerDbExt;
use crate::error::AppError;
use crate::state::SharedState;

type HmacSha256 = Hmac<Sha256>;
#[derive(Clone, Copy, Debug)]
pub enum CryptoMode {
    Shake,
    Session,
}

#[derive(Clone, Copy, Debug)]
pub enum AuthMode {
    KeysInHeaders,
    LoginByHandler,
    JwtUser
}

#[derive(Clone, Debug)]
pub struct CryptoCfg {
    pub endpoint: &'static str,
    pub mode: CryptoMode,
    pub auth: AuthMode,
    pub ts_skew: Duration,
    pub session_ttl: Duration,
}

impl CryptoCfg {
    pub fn shake(endpoint: &'static str) -> Self {
        Self {
            endpoint,
            mode: CryptoMode::Shake,
            auth: AuthMode::KeysInHeaders,
            ts_skew: Duration::from_secs(60),
            session_ttl: Duration::from_secs(60),
        }
    }

    pub fn session(endpoint: &'static str) -> Self {
        Self {
            endpoint,
            mode: CryptoMode::Session,
            auth: AuthMode::JwtUser,
            ts_skew: Duration::from_secs(60),
            session_ttl: Duration::from_secs(120),
        }
    }

    pub fn auth(mut self, auth: AuthMode) -> Self {
        self.auth = auth;
        self
    }
}

pub struct CryptoContext {
    pub state: SharedState,
    pub cfg: CryptoCfg,
    pub resp_label: String,
    pub peer_key_x: Byte32,
    pub peer_key_k: SecretBytes,
    pub body: SecretJson,
    pub client_ed_key: Option<Byte32>,
    pub client_dili_key: Option<SecretBytes>,

    pub user: Option<models::users::Model>,
}

#[derive(Clone)]
pub struct CryptoReq(pub Arc<Mutex<CryptoContext>>);

impl CryptoReq {
    pub async fn lock(&self) -> MutexGuard<'_, CryptoContext> {
        self.0.lock().await
    }
}

impl<'a> FromRequest<'a> for CryptoReq {
    async fn from_request(req: &'a Request, _body: &mut RequestBody) -> PoemResult<Self> {
        req.extensions()
            .get::<CryptoReq>()
            .cloned()
            .ok_or_else(|| {
                PoemError::from_string(
                    "crypto context missing",
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub jti: String,
}

fn hmac_id(user_id: &[u8], seed: &[u8]) -> Result<String, LithiumError> {
    let mut mac = HmacSha256::new_from_slice(seed).map_err(|_| LithiumError::internal())?;
    mac.update(user_id);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub async fn create_token_for_user(
    user: &models::users::Model,
    ttl_seconds: u64,
    secret: &Byte32,
    store: &EphemeralStoreManager,
) -> Result<SecretString, AppError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::internal("system clock error"))?
        .as_secs();

    let expiration = now + ttl_seconds;

    let seed = keys::random_32()?;
    let sub = hmac_id(&user.id, seed.as_slice())?;

    let jti: String = Alphanumeric
        .sample_iter(&mut UnwrapErr(SysRng))
        .take(64)
        .map(char::from)
        .collect();

    let claims = Claims {
        sub: sub.clone(),
        exp: expiration as usize,
        jti,
    };

    let header = Header::new(Algorithm::HS256);
    let token_string = encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_slice()),
    )
        .map_err(|_| AppError::internal("jwt encode error"))?;

    let mut value = Vec::with_capacity(32 + user.id.len());
    value.extend_from_slice(seed.as_slice());
    value.extend_from_slice(user.id.as_slice());

    store
        .set(
            &format!("token:{token_string}"),
            &SecretBytes::from_slice(value.as_slice()),
            Duration::from_secs(ttl_seconds),
        )
        .await?;

    value.zeroize();
    Ok(SecretString::new(token_string))
}

pub async fn get_user_from_token(
    token: &str,
    secret: &Byte32,
    dbm: &Arc<DataManager<PlainFileMkProvider>>,
    store: &EphemeralStoreManager,
) -> Result<models::users::Model, AppError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_slice()),
        &validation,
    )
        .map_err(|_| AppError::unauthorized("invalid jwt 1"))?;

    let value = store
        .take(&format!("token:{token}"))
        .await?
        .ok_or(AppError::unauthorized("invalid jwt 2"))?;

    if value.len() < 32 {
        return Err(AppError::unauthorized("invalid jwt 3"));
    }

    let seed = &value.as_slice()[..32];
    let id = &value.as_slice()[32..];

    let sub = token_data.claims.sub;
    if hmac_id(id, seed)? != sub {
        return Err(AppError::unauthorized("invalid jwt 4"));
    }

    let user = dbm
        .get_user_by_id(id)
        .await?
        .ok_or(AppError::unauthorized("invalid jwt 5"))?;

    Ok(user)
}

pub async fn build_crypto_context(
    state: SharedState,
    cfg: CryptoCfg,
    headers_map: &HashMap<String, Vec<u8>>,
    cipher_body: SecretBytes,
) -> Result<CryptoReq, AppError> {
    debug!(
        endpoint = cfg.endpoint,
        mode = ?cfg.mode,
        auth = ?cfg.auth,
        body_len = cipher_body.as_slice().len(),
        "build_crypto_context start"
    );
    match cfg.mode {
        CryptoMode::Shake => verify_headers(headers_map, &["key-x", "key-k", "seed", "data"])?,
        CryptoMode::Session => {
            verify_headers(headers_map, &["data", "key-x", "ses-x", "key-k", "ses-k", "seed"])?
        }
    }

    let mut user: Option<models::users::Model> = None;

    let peer_key_x_arr = header_hex::<32>(headers_map, "key-x")?;
    let peer_key_x = Byte32::from_slice(peer_key_x_arr.as_slice())?;

    let peer_key_k = header_hex_bytes(headers_map, "key-k")?;
    let enc_headers_z = header_hex_bytes(headers_map, "data")?;
    let seed_enc_z = header_hex_bytes(headers_map, "seed")?;

    let req_label = format!("{}-req", cfg.endpoint);
    let resp_label = format!("{}-resp", cfg.endpoint);

    let (mut dec_body, mut dec_headers) = match cfg.mode {
        CryptoMode::Shake => {
            let wire = WirePayload {
                enc_body: cipher_body,
                enc_headers: enc_headers_z,
                seed_enc: seed_enc_z,
            };

            match state
                .key_manager
                .lock()
                .await
                .with_x25519_and_kyber_sk(|x_priv, k_priv| {
                    kyberbox::decrypt(
                        req_label.as_str(),
                        &x_priv,
                        &peer_key_x,
                        &k_priv,
                        &wire,
                    )
                }) {
                Ok(v) => {
                    debug!(endpoint = cfg.endpoint, "shake decrypt ok");
                    v
                }
                Err(e) => {
                    error!(
                    endpoint = cfg.endpoint,
                    label = %req_label,
                    error = ?e,
                    "shake decrypt failed"
                );
                    return Err(AppError::from(e));
                }
            }
        }
        CryptoMode::Session => {
            let ses_x_id = header_str(headers_map, "ses-x")?;
            let ses_k_id = header_str(headers_map, "ses-k")?;

            let x_priv = state
                .store
                .take(ses_x_id.expose())
                .await?
                .ok_or_else(|| AppError::bad_request("invalid session x"))?;

            let k_priv = state
                .store
                .take(ses_k_id.expose())
                .await?
                .ok_or_else(|| AppError::bad_request("invalid session k"))?;

            let x_byte = Byte32::from_slice(x_priv.as_slice())?;
            let k_byte = k_priv;

            match kyberbox::decrypt(
                req_label.as_str(),
                &x_byte,
                &peer_key_x,
                &k_byte,
                &WirePayload {
                    enc_body: cipher_body,
                    enc_headers: enc_headers_z,
                    seed_enc: seed_enc_z,
                },
            ) {
                Ok(v) => {
                    debug!(endpoint = cfg.endpoint, "session decrypt ok");
                    v
                }
                Err(e) => {
                    error!(
                    endpoint = cfg.endpoint,
                    label = %req_label,
                    error = ?e,
                    "session decrypt failed"
                );
                    return Err(AppError::from(e));
                }
            }
        }
    };

    unpad_block(dec_body.as_mut_vec()).map_err(|e| {
        error!(endpoint = cfg.endpoint, error = ?e, "body unpad failed");
        e
    })?;

    unpad_block(dec_headers.as_mut_vec()).map_err(|e| {
        error!(endpoint = cfg.endpoint, error = ?e, "headers unpad failed");
        e
    })?;

    let body_json = SecretJson::from_vec(dec_body.into_vec()).map_err(|e| {
        error!(endpoint = cfg.endpoint, error = ?e, "body json parse failed");
        AppError::from(e)
    })?;

    let headers_json = SecretJson::from_vec(dec_headers.into_vec()).map_err(|e| {
        error!(endpoint = cfg.endpoint, error = ?e, "headers json parse failed");
        AppError::from(e)
    })?;

    let body_keys = body_json.with_exposed(|v| {
        v.as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    });

    let header_keys = headers_json.with_exposed(|v| {
        v.as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    });

    debug!(
    endpoint = cfg.endpoint,
    body_keys = ?body_keys,
    app_header_keys = ?header_keys,
    "parsed decrypted json"
);

    let ts = body_json.get_string("timestamp").map_err(|e| {
        error!(endpoint = cfg.endpoint, error = ?e, "timestamp missing");
        AppError::from(e)
    })?;

    validate_timestamp(ts.expose(), cfg.ts_skew, cfg.ts_skew).map_err(|e| {
        error!(
        endpoint = cfg.endpoint,
        timestamp = %ts.expose(),
        error = ?e,
        "timestamp invalid"
    );
        e
    })?;

    let mut client_ed_key: Option<Byte32> = None;
    let mut client_dili_key: Option<SecretBytes> = None;

    match cfg.auth {
        AuthMode::KeysInHeaders => {
            let key_ed_raw = headers_json.get_string("key-ed")?;
            let key_dili_raw = headers_json.get_string("key-dili")?;

            let peer_key_ed = Byte32::from_hex(key_ed_raw.expose()).map_err(|e| {
                error!(
            endpoint = cfg.endpoint,
            key_ed = %key_ed_raw.expose(),
            error = ?e,
            "invalid key-ed"
        );
                AppError::bad_request("invalid_key_ed")
            })?;

            let peer_key_dili = SecretBytes::from_hex(key_dili_raw.expose()).map_err(|e| {
                error!(
            endpoint = cfg.endpoint,
            key_dili_len = key_dili_raw.expose().len(),
            error = ?e,
            "invalid key-dili"
        );
                AppError::bad_request("invalid_key_dili")
            })?;

            verify_signature(&headers_json, &body_json, &peer_key_ed, &peer_key_dili).map_err(|e| {
                error!(endpoint = cfg.endpoint, error = ?e, "signature verification failed");
                e
            })?;

            client_ed_key = Some(peer_key_ed);
            client_dili_key = Some(peer_key_dili);
        }

        AuthMode::LoginByHandler => {
            let handler = body_json.get_string("handler")?;

            let u = state
                .db
                .get_user(handler.expose())
                .await?
                .ok_or_else(|| AppError::bad_request("invalid credentials"))?;

            let ed = Byte32::from_slice(u.ed_key.as_slice())?;
            let dili = SecretBytes::from_vec(u.dili_key.clone());

            verify_signature(&headers_json, &body_json, &ed, &dili)?;
            user = Some(u);
        }

        AuthMode::JwtUser => {
            let token_hex = body_json.get_string("token")?;

            let token_bytes =
                hex::decode(token_hex.expose()).map_err(|_| AppError::unauthorized("invalid jwt"))?;
            let token_str = std::str::from_utf8(&token_bytes)
                .map_err(|_| AppError::unauthorized("invalid jwt"))?;

            let jwt_secret = { state.key_manager.lock().await.jwt_secret().clone() };

            let u = get_user_from_token(token_str, &jwt_secret, &state.db, &state.store).await?;
            let ed = Byte32::from_slice(u.ed_key.as_slice())?;
            let dili = SecretBytes::from_vec(u.dili_key.clone());

            verify_signature(&headers_json, &body_json, &ed, &dili)?;
            user = Some(u);
        }
    }

    let ctx = CryptoContext {
        state,
        cfg,
        resp_label,
        peer_key_x,
        peer_key_k,
        body: body_json,
        client_ed_key,
        client_dili_key,
        user,
    };

    Ok(CryptoReq(Arc::new(Mutex::new(ctx))))
}

impl CryptoContext {
    pub async fn reply_ok(&mut self, mut body: Value) -> Result<Response, AppError> {
        let now = get_now()?;
        if body.get("timestamp").is_none() {
            body["timestamp"] = Value::String(format!("{:016x}", now));
        }

        let (session_priv_x, session_pub_x) = keys::random_x25519_keypair()?;
        let session_x_id = keys::random_32()?.to_hex();
        self.state
            .store
            .set(
                &session_x_id.expose(),
                &SecretBytes::from_slice(session_priv_x.as_slice()),
                self.cfg.session_ttl,
            )
            .await?;

        let (session_priv_k, session_pub_k) = keys::random_kyber_mlkem1024_keypair()?;
        let session_k_id = keys::random_32()?.to_hex();
        self.state
            .store
            .set(
                &session_k_id.expose(),
                &SecretBytes::from_slice(session_priv_k.as_slice()),
                self.cfg.session_ttl,
            )
            .await?;

        let response_headers = json!({
            "ses-x": &session_x_id.expose(),
            "ses-k": &session_k_id.expose(),
        });

        let response_body_s = SecretString::new(serde_json::to_string(&body)?);
        let response_headers_s = SecretString::new(serde_json::to_string(&response_headers)?);

        let resp_sig_ed = self
            .state
            .key_manager
            .lock()
            .await
            .with_ed_sk(|sk| sign::sign_message(response_body_s.expose().as_bytes(), sk))?;

        let resp_sig_dili = self
            .state
            .key_manager
            .lock()
            .await
            .with_dilithium_sk(|sk| sign::sign_message_dili(response_body_s.expose().as_bytes(), sk))?;

        let response_body_pad =
            SecretBytes::from_vec(pad_data(response_body_s.expose().as_bytes()));
        let response_headers_pad =
            SecretBytes::from_vec(pad_headers(response_headers_s.expose().as_bytes()));

        let encrypted = kyberbox::encrypt(
            self.resp_label.as_str(),
            &session_priv_x,
            &self.peer_key_x,
            &self.peer_key_k,
            &response_body_pad,
            &response_headers_pad,
        )?;

        let clear_headers = json!({
            "sig-ed": hex::encode(resp_sig_ed.as_slice()),
            "sig-dili": hex::encode(resp_sig_dili.as_slice()),
            "data": hex::encode(encrypted.enc_headers.as_slice()),
            "seed": hex::encode(encrypted.seed_enc.as_slice()),
            "key-x": hex::encode(session_pub_x.as_slice()),
            "key-k": hex::encode(session_pub_k.as_slice()),
        });

        Ok(api_success(encrypted.enc_body, clear_headers))
    }

    pub async fn reply_ok_authed(
        &mut self,
        ttl_seconds: u64,
        mut body: Value,
    ) -> Result<Response, AppError> {
        let user = self
            .user
            .as_ref()
            .ok_or(AppError::unauthorized("unauthorized"))?;

        let jwt_secret = { self.state.key_manager.lock().await.jwt_secret().clone() };
        let tok = create_token_for_user(user, ttl_seconds, &jwt_secret, &self.state.store).await?;

        let tok_hex = hex::encode(tok.expose().as_bytes());
        body["tok"] = Value::String(tok_hex);

        self.reply_ok(body).await
    }
}

#[inline]
pub fn api_success(blob: SecretBytes, meta: Value) -> Response {
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream");

    if let Some(obj) = meta.as_object() {
        for (k, v) in obj {
            if !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                continue;
            }

            let vs = v.to_string();
            let vs = vs.trim_matches('"').to_string();
            if vs.is_empty() {
                continue;
            }

            resp = resp.header(k, vs);
        }
    }

    resp.body(Body::from(blob.as_slice().to_vec()))
}

pub fn verify_headers(
    headers: &HashMap<String, Vec<u8>>,
    required: &[&str],
) -> Result<(), AppError> {
    let missing: Vec<String> = required
        .iter()
        .filter(|h| !headers.contains_key(&h.to_ascii_lowercase()))
        .map(|h| h.to_string())
        .collect();

    if missing.is_empty() {
        Ok(())
    } else {
        Err(AppError::bad_request("missing request headers"))
    }
}

pub fn verify_signature(
    headers_json: &SecretJson,
    body_json: &SecretJson,
    peer_pub_ed_key: &Byte32,
    peer_pub_dili_key: &SecretBytes,
) -> Result<(), AppError> {
    let sig_ed = Byte64::from_hex(headers_json.get_string("sig-ed")?.expose())
        .map_err(|_| AppError::bad_request("invalid_sig_ed"))?;

    let sig_dili = SecretBytes::from_hex(headers_json.get_string("sig-dili")?.expose())
        .map_err(|_| AppError::bad_request("invalid_sig_dili"))?;

    let raw_json = body_json
        .raw_json()
        .ok_or(AppError::bad_request("missing request body"))?;

    let ok_ed = sign::verify_signature(
        raw_json.expose().as_bytes(),
        sig_ed.as_slice(),
        peer_pub_ed_key,
    );

    let ok_dili = sign::verify_signature_dili(
        raw_json.expose().as_bytes(),
        sig_dili.as_slice(),
        peer_pub_dili_key,
    );

    if !(ok_ed && ok_dili) {
        return Err(AppError::unauthorized("invalid signatures"));
    }

    Ok(())
}

pub fn validate_timestamp(
    ts_hex_str: &str,
    max_age: Duration,
    max_skew: Duration,
) -> Result<(), AppError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::internal("system clock error"))?
        .as_secs();

    let ts_bytes =
        hex::decode(ts_hex_str).map_err(|_| AppError::bad_request("invalid timestamp"))?;
    let ts_bytes_8: [u8; 8] = ts_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AppError::bad_request("invalid timestamp"))?;
    let ts = u64::from_be_bytes(ts_bytes_8);

    if ts <= now {
        let age = now - ts;
        if age > max_age.as_secs() {
            return Err(AppError::bad_request("request too old"));
        }
    } else {
        let skew = ts - now;
        if skew > max_skew.as_secs() {
            return Err(AppError::bad_request("request is from the future"));
        }
    }

    Ok(())
}

pub fn get_now() -> Result<u64, AppError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::internal("system clock error"))?
        .as_secs())
}

fn pad_block(input: &[u8], block_size: usize) -> Vec<u8> {
    let total_len = input.len() + 1;
    let pad_len = (block_size - (total_len % block_size)) % block_size;

    let mut out = Vec::with_capacity(total_len + pad_len);
    out.extend_from_slice(input);
    out.push(0x80);
    out.resize(out.len() + pad_len, 0u8);

    out
}

fn random_block_size() -> usize {
    let min = 32 * 1024;
    let max = 64 * 1024;

    let mut rng = UnwrapErr(SysRng);
    rng.random_range(min..=max)
}

pub fn pad_data(input: &[u8]) -> Vec<u8> {
    pad_block(input, random_block_size())
}

pub fn pad_headers(input: &[u8]) -> Vec<u8> {
    pad_block(input, random_block_size() / 8)
}

pub fn unpad_block(data: &mut Vec<u8>) -> Result<(), AppError> {
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
            Err(AppError::bad_request("invalid padding"))
        }
    }
}
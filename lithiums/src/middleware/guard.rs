use std::{collections::HashMap, time::Duration};

use poem::{Body, Endpoint, IntoResponse, Middleware, Request, Result as PoemResult};
use sha2::{Digest, Sha256};

use lithium_core::secrets::bytes::SecretBytes;

use crate::error::AppError;
use crate::state::SharedState;
use crate::store_keys;
use crate::transport::parse_u32_ascii;

#[derive(Clone)]
pub struct CipherBody(pub SecretBytes);

const PRE_REPLAY_WINDOW_SECS: u64 = 10;
const PRE_REPLAY_LOCK_BASE_SECS: u64 = 5;
const PRE_REPLAY_LOCK_MAX_SECS: u64 = 60;
const PRE_REPLAY_THRESHOLD: u32 = 200;


#[inline]
fn normalize_guard_remote(remote: &str) -> String {
    let remote = remote.trim();
    if remote.is_empty() {
        return "unknown".to_string();
    }

    hex::encode(Sha256::digest(remote.as_bytes()))
}

#[inline]
fn pre_replay_fail_key(remote: &str) -> String {
    store_keys::pre_replay_fail(&normalize_guard_remote(remote))
}

#[inline]
fn pre_replay_lock_key(remote: &str) -> String {
    store_keys::pre_replay_lock(&normalize_guard_remote(remote))
}

#[inline]
fn pre_replay_backoff_secs(hits: u32) -> u64 {
    if hits < PRE_REPLAY_THRESHOLD {
        return 0;
    }

    let exp = (hits - PRE_REPLAY_THRESHOLD).min(10);
    PRE_REPLAY_LOCK_BASE_SECS
        .saturating_mul(1u64 << exp)
        .min(PRE_REPLAY_LOCK_MAX_SECS)
}

async fn pre_replay_rate_limit_check(
    state: &SharedState,
    remote: &str,
) -> Result<(), AppError> {
    let lock_key = pre_replay_lock_key(remote);

    if state.store.peek(&lock_key).await?.is_some() {
        return Err(AppError::too_many_requests("try_later"));
    }

    Ok(())
}

async fn pre_replay_rate_limit_hit(
    state: &SharedState,
    remote: &str,
) -> Result<(), AppError> {
    let fail_key = pre_replay_fail_key(remote);

    let current = match state.store.peek(&fail_key).await? {
        Some(v) => parse_u32_ascii(v.expose_as_slice()),
        None => 0,
    };

    let next = current.saturating_add(1);

    state
        .store
        .set(
            &fail_key,
            &SecretBytes::from_slice(next.to_string().as_bytes()),
            Duration::from_secs(PRE_REPLAY_WINDOW_SECS),
        )
        .await?;

    let backoff = pre_replay_backoff_secs(next);
    if backoff > 0 {
        let lock_key = pre_replay_lock_key(remote);
        state
            .store
            .set(
                &lock_key,
                &SecretBytes::from_slice(next.to_string().as_bytes()),
                Duration::from_secs(backoff),
            )
            .await?;
    }

    Ok(())
}

async fn anti_replay_check(state: &SharedState, body: &[u8]) -> Result<(), AppError> {
    let key = store_keys::replay(&hex::encode(Sha256::digest(body)));

    // Keep replay cache longer than request freshness window on purpose.
    // Requests are freshness-validated elsewhere (default ~60s), but we retain
    // body hashes for 600s so exact frame reuse is rejected well beyond the
    // timestamp window. If the timestamp window is ever increased, revisit this TTL.
    let ttl = Duration::from_secs(600);

    match state
        .store
        .set_if_absent(&key, &SecretBytes::new(b"1".to_vec()), ttl)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(AppError::bad_request("replay_detected")),
        Err(_) => Err(AppError::internal("anti_replay_check_failed")),
    }
}

#[derive(Clone)]
pub struct GuardMiddleware {
    state: SharedState,
}

impl GuardMiddleware {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }
}

impl<E: Endpoint> Middleware<E> for GuardMiddleware {
    type Output = GuardEndpoint<E>;

    fn transform(&self, ep: E) -> Self::Output {
        GuardEndpoint {
            inner: ep,
            state: self.state.clone(),
        }
    }
}

pub struct GuardEndpoint<E> {
    inner: E,
    state: SharedState,
}

impl<E: Endpoint> Endpoint for GuardEndpoint<E> {
    type Output = E::Output;

    async fn call(&self, mut req: Request) -> PoemResult<Self::Output> {
        let remote = req.remote_addr().to_string();

        pre_replay_rate_limit_check(&self.state, &remote)
            .await
            .map_err(|e| poem::Error::from_response(e.into_response()))?;

        if req.method() == poem::http::Method::GET {
            return self.inner.call(req).await;
        }

        let mut headers = HashMap::with_capacity(req.headers().len());
        for (k, v) in req.headers().iter() {
            headers.insert(k.as_str().to_ascii_lowercase(), v.as_bytes().to_vec());
        }

        let headers_total: usize = headers.iter().map(|(k, v)| k.len() + v.len()).sum();
        if headers_total > 1024 * 1024 {
            return Err(poem::Error::from_response(AppError::bad_request("headers_too_large").into_response()));
        }

        let bytes = req.take_body().into_bytes().await.map_err(|_| {
            poem::Error::from_response(AppError::bad_request("invalid_body").into_response())
        })?;

        if bytes.len() > 1024 * 1024 {
            return Err(poem::Error::from_response(AppError::bad_request("body_too_large").into_response()));
        }

        pre_replay_rate_limit_hit(&self.state, &remote)
            .await
            .map_err(|e| poem::Error::from_response(e.into_response()))?;

        anti_replay_check(&self.state, bytes.as_ref())
            .await
            .map_err(|e| poem::Error::from_response(e.into_response()))?;

        let cipher = SecretBytes::from_slice(bytes.as_ref());
        req.extensions_mut().insert(CipherBody(cipher.clone()));

        req.set_body(Body::from(bytes));

        self.inner.call(req).await
    }
}
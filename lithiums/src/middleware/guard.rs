use std::{collections::HashMap, time::Duration};

use poem::{Body, Endpoint, IntoResponse, Middleware, Request, Result as PoemResult};
use sha2::{Digest, Sha256};

use lithium_core::secrets::bytes::SecretBytes;

use crate::error::AppError;
use crate::state::SharedState;

#[derive(Clone)]
pub struct CipherBody(pub SecretBytes);

fn check_body_size(body: &[u8]) -> Result<(), AppError> {
    if body.len() > 1024 * 1024 {
        return Err(AppError::bad_request("body_too_large"));
    }
    Ok(())
}

fn check_headers_size(headers: &HashMap<String, Vec<u8>>) -> Result<(), AppError> {
    let total: usize = headers.iter().map(|(k, v)| k.len() + v.len()).sum();
    if total > 1024 * 1024 {
        return Err(AppError::bad_request("headers_too_large"));
    }
    Ok(())
}

async fn anti_replay_check(state: &SharedState, body: &[u8]) -> Result<(), AppError> {
    let key = format!("replay:{}", hex::encode(Sha256::digest(body)));
    let ttl = Duration::from_secs(600);

    match state.store.set_if_absent(&key, &SecretBytes::new(b"1".to_vec()), ttl).await {
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
        let mut headers = HashMap::with_capacity(req.headers().len());
        for (k, v) in req.headers().iter() {
            headers.insert(k.as_str().to_ascii_lowercase(), v.as_bytes().to_vec());
        }

        check_headers_size(&headers)
            .map_err(|e| poem::Error::from_response(e.into_response()))?;

        let bytes = req.take_body().into_bytes().await.map_err(|_| {
            poem::Error::from_response(AppError::bad_request("invalid_body").into_response())
        })?;

        check_body_size(bytes.as_ref())
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
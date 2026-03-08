use std::collections::HashMap;
use tracing::{debug, error};
use poem::{Endpoint, IntoResponse, Middleware, Request, Result as PoemResult};

use lithium_core::secrets::bytes::SecretBytes;

use crate::error::AppError;
use crate::middleware::guard::CipherBody;
use crate::state::SharedState;
use crate::transport::{build_crypto_context, CryptoCfg, CryptoReq};

#[derive(Clone)]
pub struct CryptoMiddleware {
    state: SharedState,
    cfg: CryptoCfg,
}

impl CryptoMiddleware {
    pub fn new(state: SharedState, cfg: CryptoCfg) -> Self {
        Self { state, cfg }
    }
}

impl<E: Endpoint> Middleware<E> for CryptoMiddleware {
    type Output = CryptoEndpoint<E>;

    fn transform(&self, ep: E) -> Self::Output {
        CryptoEndpoint {
            ep,
            state: self.state.clone(),
            cfg: self.cfg.clone(),
        }
    }
}

pub struct CryptoEndpoint<E> {
    ep: E,
    state: SharedState,
    cfg: CryptoCfg,
}

impl<E: Endpoint> Endpoint for CryptoEndpoint<E> {
    type Output = E::Output;

    async fn call(&self, mut req: Request) -> PoemResult<Self::Output> {
        let mut headers_map: HashMap<String, Vec<u8>> =
            HashMap::with_capacity(req.headers().len());

        for (k, v) in req.headers().iter() {
            headers_map.insert(k.as_str().to_ascii_lowercase(), v.as_bytes().to_vec());
        }

        let cipher_body = if let Some(CipherBody(blob)) = req.extensions().get::<CipherBody>() {
            blob.clone()
        } else {
            let body_bytes = req.take_body().into_bytes().await.map_err(|_| {
                poem::Error::from_response(AppError::bad_request("invalid_body").into_response())
            })?;
            SecretBytes::from_slice(&body_bytes)
        };

        let header_names: Vec<String> = headers_map.keys().cloned().collect();

        debug!(
            endpoint = self.cfg.endpoint,
            mode = ?self.cfg.mode,
            auth = ?self.cfg.auth,
            body_len = cipher_body.as_slice().len(),
            headers = ?header_names,
            "crypto middleware start"
        );

        let creq: CryptoReq = match build_crypto_context(
            self.state.clone(),
            self.cfg.clone(),
            &headers_map,
            cipher_body,
        )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                error!(
                    endpoint = self.cfg.endpoint,
                    mode = ?self.cfg.mode,
                    auth = ?self.cfg.auth,
                    headers = ?header_names,
                    error = ?e,
                    "build_crypto_context failed"
                );
                return Err(poem::Error::from_response(e.into_response()));
            }
        };

        req.extensions_mut().insert(creq);

        self.ep.call(req).await
    }
}
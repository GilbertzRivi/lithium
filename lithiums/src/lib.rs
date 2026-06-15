pub mod api;
pub mod db;
pub mod error;
pub mod health;
pub mod identity;
pub(crate) mod labels;
pub mod middleware;
pub mod mk_rotator;
pub mod msg_reaper;
pub mod provider;
pub mod state;
pub(crate) mod store_keys;
pub mod transport;

#[cfg(feature = "tpm")]
pub mod tpm_provider;

use poem::{get, handler, post, Endpoint, EndpointExt, Route};
use poem::web::{Data, Json};
use poem::http::StatusCode;
use poem::Response;
use serde_json::json;

use lithium_core::contract::protocol::{ctx, path};

use crate::middleware::crypto::CryptoMiddleware;
use crate::middleware::guard::GuardMiddleware;
use crate::transport::{AuthMode, CryptoCfg};

#[handler]
fn root() -> Json<serde_json::Value> {
    Json(json!({
        "message": "Welcome to Lithium, real private messenger"
    }))
}

#[handler]
fn health_check(state: Data<&state::SharedState>) -> Response {
    let h = &state.health;
    let reaper_last_ok = h.reaper_last_ok.load(std::sync::atomic::Ordering::Relaxed);
    let reaper_errors = h.reaper_errors.load(std::sync::atomic::Ordering::Relaxed);
    let mk_last_ok = h.mk_rotation_last_ok.load(std::sync::atomic::Ordering::Relaxed);
    let mk_errors = h.mk_rotation_errors.load(std::sync::atomic::Ordering::Relaxed);

    let body = json!({
        "reaper": { "last_ok": reaper_last_ok, "errors_total": reaper_errors },
        "mk_rotation": { "last_ok": mk_last_ok, "errors_total": mk_errors },
    });

    // 503 until both subsystems have had at least one successful run
    let status = if reaper_last_ok > 0 && mk_last_ok > 0 {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    Response::builder()
        .status(status)
        .content_type("application/json")
        .body(body.to_string())
}

pub fn build_app(state: state::SharedState) -> impl Endpoint {
    Route::new()
        .at("/", get(root))
        .at("/health", get(health_check.data(state.clone())))
        .at(
            path::SHAKE,
            post(api::handshake::handshake).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::shake(ctx::SHAKE).auth(AuthMode::KeysInHeaders),
            )),
        )
        .at(
            path::REGISTER,
            post(api::user::register).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session(ctx::REGISTER).auth(AuthMode::KeysInHeaders),
            )),
        )
        .at(
            path::LOGIN,
            post(api::user::login).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session(ctx::LOGIN).auth(AuthMode::LoginByHandler),
            )),
        )
        .at(
            path::REVOKE,
            post(api::user::revoke).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session(ctx::REVOKE).auth(AuthMode::KeysInHeaders),
            )),
        )
        .at(
            path::DELETE,
            post(api::user::delete).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session(ctx::DELETE).auth(AuthMode::JwtUser),
            )),
        )
        .at(
            path::MSG_SEND,
            post(api::messages::send).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session(ctx::MSG_SEND).auth(AuthMode::JwtUser),
            )),
        )
        .at(
            path::MSG_FETCH,
            post(api::messages::fetch).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session(ctx::MSG_FETCH).auth(AuthMode::KeysInHeaders),
            )),
        )
        .with(GuardMiddleware::new(state))
}
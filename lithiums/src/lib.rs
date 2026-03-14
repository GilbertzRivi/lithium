use poem::{get, handler, post, Endpoint, EndpointExt, Route};
use poem::web::Json;
use serde_json::json;

use crate::middleware::crypto::CryptoMiddleware;
use crate::middleware::guard::GuardMiddleware;
use crate::transport::{AuthMode, CryptoCfg};

pub mod api;
pub mod db;
pub mod error;
pub mod middleware;
pub mod state;
pub mod transport;
pub mod mk_rotator;

#[handler]
async fn root() -> Json<serde_json::Value> {
    Json(json!({
        "message": "Welcome to Lithium, real private messenger"
    }))
}

pub fn api_routes(state: state::SharedState) -> impl Endpoint {
    Route::new()
        .at("/", get(root))
        .at(
            "/shake",
            post(api::handshake::handshake).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::shake("shake").auth(AuthMode::KeysInHeaders),
            )),
        )
        .at(
            "/user/register",
            post(api::user::register).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session("register").auth(AuthMode::KeysInHeaders),
            )),
        )
        .at(
            "/user/login",
            post(api::user::login).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session("login").auth(AuthMode::LoginByHandler),
            )),
        )
        .at(
            "/user/revoke",
            post(api::user::revoke).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session("revoke").auth(AuthMode::KeysInHeaders),
            )),
        )
        .at(
            "/user/delete",
            post(api::user::delete).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session("delete").auth(AuthMode::JwtUser),
            )),
        )
        .at(
            "/msg/send",
            post(api::messages::send).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session("msg_send").auth(AuthMode::JwtUser),
            )),
        )
        .at(
            "/msg/fetch",
            post(api::messages::fetch).with(CryptoMiddleware::new(
                state.clone(),
                CryptoCfg::session("msg_fetch").auth(AuthMode::KeysInHeaders),
            )),
        )
        .with(GuardMiddleware::new(state))
}
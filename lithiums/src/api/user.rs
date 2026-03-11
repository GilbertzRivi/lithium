use poem::{handler, Response};
use serde_json::json;
use tracing::{debug, warn};

use lithium_core::passwords::passwords::verify_password_phc;

use crate::db::repo::ServerDbExt;
use crate::error::AppError;
use crate::transport::{
    login_rate_limit_check,
    login_rate_limit_fail,
    login_rate_limit_success,
    CryptoReq,
};

use lithium_core::secrets::bytes::SecretBytes;

#[handler]
pub async fn register(req: CryptoReq) -> Result<Response, AppError> {
    let (state, handler, password, dek_hex, ed_key, dili_key) = {
        let mut ctx = req.lock().await;

        let ed_key = ctx
            .client_ed_key
            .clone()
            .ok_or(AppError::bad_request("missing key-ed"))?;

        let dili_key = ctx
            .client_dili_key
            .clone()
            .ok_or(AppError::bad_request("missing key-dili"))?;

        let handler = ctx.body.take_string("handler")?;
        let password = ctx.body.take_string("password")?;
        let dek_hex = ctx.body.take_string("dek")?;

        debug!(
            handler = %handler.expose(),
            dek_hex_len = dek_hex.expose().len(),
            ed_len = ed_key.as_slice().len(),
            dili_len = dili_key.as_slice().len(),
            "register payload extracted"
        );

        (ctx.state.clone(), handler, password, dek_hex, ed_key, dili_key)
    };

    let _dek_blob = SecretBytes::from_hex(dek_hex.expose()).map_err(|_| {
        warn!(
            handler = %handler.expose(),
            dek_hex_len = dek_hex.expose().len(),
            "register invalid_dek: hex decode failed"
        );
        AppError::bad_request("invalid_dek")
    })?;

    let created = state
        .db
        .create_user(
            handler.expose(),
            password.expose(),
            ed_key.as_slice(),
            dili_key.as_slice(),
            dek_hex.expose().as_bytes(),
        )
        .await?;

    if !created {
        warn!(
            handler = %handler.expose(),
            "register user_exists"
        );
        return Err(AppError::bad_request("user_exists"));
    }

    let user = state
        .db
        .get_user(handler.expose())
        .await?
        .ok_or_else(|| AppError::internal("user_create_failed"))?;

    let mut ctx = req.lock().await;
    ctx.user = Some(user);

    ctx.reply_ok_authed(120, json!({"msg":"Ok"})).await
}


#[handler]
pub async fn login(req: CryptoReq) -> Result<Response, AppError> {
    let (state, handler, password, user) = {
        let mut ctx = req.lock().await;

        let handler = ctx.body.take_string("handler")?;
        let password = ctx.body.take_string("password")?;

        let user = ctx
            .user
            .clone()
            .ok_or(AppError::unauthorized("invalid_credentials"))?;

        (ctx.state.clone(), handler, password, user)
    };

    login_rate_limit_check(&state, handler.expose()).await?;

    let ok = verify_password_phc(user.password_hash.expose(), &password)?;

    if !ok {
        login_rate_limit_fail(&state, handler.expose()).await?;
        return Err(AppError::unauthorized("invalid_credentials"));
    }

    login_rate_limit_success(&state, handler.expose()).await?;

    let dek = user.dek.clone();

    let mut ctx = req.lock().await;
    ctx.user = Some(user);

    ctx.reply_ok_authed(
        120,
        json!({
            "msg": "Ok",
            "dek": dek.expose(),
        }),
    )
        .await
}
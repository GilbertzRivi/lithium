use poem::http::StatusCode;
use poem::{Body, Response, handler};
use serde_json::json;

use lithium_core::contract::protocol::field;
use lithium_core::passwords::passwords::verify_password_phc;
use lithium_core::secrets::bytes::SecretBytes;

use crate::db::repo::ServerDbExt;
use crate::error::AppError;
use crate::transport::{
    CryptoReq, login_rate_limit_check, login_rate_limit_fail, login_rate_limit_success,
    register_rate_limit_check, register_rate_limit_note,
};

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

        let handler = ctx.body.take_string(field::HANDLER)?;
        let password = ctx.body.take_string(field::PASSWORD)?;
        let dek_hex = ctx.body.take_string(field::DEK)?;

        (
            ctx.state.clone(),
            handler,
            password,
            dek_hex,
            ed_key,
            dili_key,
        )
    };

    register_rate_limit_check(&state, handler.expose()).await?;

    let _dek_blob = SecretBytes::from_hex(dek_hex.expose())
        .map_err(|_| AppError::bad_request("invalid_dek"))?;

    let capability = state
        .db
        .create_user(
            handler.expose(),
            password.expose(),
            ed_key.as_slice(),
            dili_key.expose_as_slice(),
            dek_hex.expose().as_bytes(),
        )
        .await?;

    register_rate_limit_note(&state, handler.expose()).await?;

    let mut ctx = req.lock().await;
    ctx.reply_ok(json!({
        field::MSG: "Ok",
        field::CAPABILITY: capability.expose(),
    }))
    .await
}

#[handler]
pub async fn login(req: CryptoReq) -> Result<Response, AppError> {
    let (state, handler, password, user) = {
        let mut ctx = req.lock().await;

        let handler = ctx.body.take_string(field::HANDLER)?;
        let password = ctx.body.take_string(field::PASSWORD)?;

        let user = ctx
            .user
            .clone()
            .ok_or(AppError::unauthorized("invalid_credentials"))?;

        (ctx.state.clone(), handler, password, user)
    };

    let handler_norm = crate::transport::normalize_login_handler(handler.expose());

    login_rate_limit_check(&state, handler_norm.as_str()).await?;

    let ok = verify_password_phc(user.password_hash.expose(), &password)?;

    if !ok {
        login_rate_limit_fail(&state, handler_norm.as_str()).await?;
        return Err(AppError::unauthorized("invalid_credentials"));
    }

    login_rate_limit_success(&state, handler_norm.as_str()).await?;

    let dek = user.dek.clone();

    let mut ctx = req.lock().await;
    ctx.user = Some(user);

    ctx.reply_ok_authed(
        120,
        json!({
            field::MSG: "Ok",
            field::DEK: dek.expose(),
        }),
    )
    .await
}

#[handler]
pub async fn revoke(req: CryptoReq) -> Result<Response, AppError> {
    let (state, capability) = {
        let mut ctx = req.lock().await;
        let capability = ctx.body.take_string(field::CAPABILITY)?;
        (ctx.state.clone(), capability)
    };

    let _ = state
        .db
        .delete_user_by_remote_delete_capability(capability.expose())
        .await?;

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty()))
}

#[handler]
pub async fn delete(req: CryptoReq) -> Result<Response, AppError> {
    let (state, user_id) = {
        let ctx = req.lock().await;
        let user = ctx
            .user
            .clone()
            .ok_or(AppError::unauthorized("unauthorized"))?;
        (ctx.state.clone(), user.id)
    };

    let _ = state.db.delete_user_by_id(&user_id).await?;

    let mut ctx = req.lock().await;
    ctx.reply_ok(json!({
        field::MSG: "Ok"
    }))
    .await
}

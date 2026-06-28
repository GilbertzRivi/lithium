// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use poem::http::StatusCode;
use poem::{Body, Response, handler};
use serde_json::json;

use lithium_core::crypto::keys;
use lithium_core::opaque::server::{
    server_login_finish, server_login_start, server_registration_finish, server_registration_start,
};
use lithium_core::secrets::bytes::SecretBytes;
use lithium_proto::contract::protocol::{field, normalize_handler};
use lithium_proto::labels;

use crate::db::repo::ServerDbExt;
use crate::error::AppError;
use crate::store_keys;
use crate::transport::{
    CryptoReq, login_rate_limit_fail, login_rate_limit_success, register_rate_limit_check,
    register_rate_limit_note,
};

const OPAQUE_LOGIN_FLOW_TTL: Duration = Duration::from_secs(30);

#[handler]
pub async fn register_start(req: CryptoReq) -> Result<Response, AppError> {
    let (state, handler, request_hex) = {
        let mut ctx = req.lock().await;
        let handler = ctx.body.take_string(field::HANDLER)?;
        let request_hex = ctx.body.take_string(field::OPAQUE)?;
        (ctx.state.clone(), handler, request_hex)
    };

    register_rate_limit_check(&state, handler.expose()).await?;

    let request = SecretBytes::from_hex(request_hex.expose())
        .map_err(|_| AppError::bad_request("invalid_opaque"))?;
    let cred_id = normalize_handler(handler.expose());

    let response = server_registration_start(
        &state.opaque_setup,
        request.expose_as_slice(),
        cred_id.as_bytes(),
    )?;
    let response_hex = SecretBytes::from_slice(&response).to_hex();

    let mut ctx = req.lock().await;
    ctx.reply_ok(json!({
        field::MSG: "Ok",
        field::OPAQUE: response_hex.expose(),
    }))
    .await
}

#[handler]
pub async fn register_finish(req: CryptoReq) -> Result<Response, AppError> {
    let (state, handler, upload_hex, dek_hex, ed_key, dili_key) = {
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
        let upload_hex = ctx.body.take_string(field::OPAQUE)?;
        let dek_hex = ctx.body.take_string(field::DEK)?;

        (
            ctx.state.clone(),
            handler,
            upload_hex,
            dek_hex,
            ed_key,
            dili_key,
        )
    };

    register_rate_limit_check(&state, handler.expose()).await?;

    let upload = SecretBytes::from_hex(upload_hex.expose())
        .map_err(|_| AppError::bad_request("invalid_opaque"))?;
    let _dek_blob = SecretBytes::from_hex(dek_hex.expose())
        .map_err(|_| AppError::bad_request("invalid_dek"))?;

    let record = server_registration_finish(upload.expose_as_slice())?;

    let capability = state
        .db
        .create_user(
            handler.expose(),
            &record,
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
pub async fn login_start(req: CryptoReq) -> Result<Response, AppError> {
    let (state, handler, request_hex, user) = {
        let mut ctx = req.lock().await;
        let handler = ctx.body.take_string(field::HANDLER)?;
        let request_hex = ctx.body.take_string(field::OPAQUE)?;
        let user = ctx
            .user
            .clone()
            .ok_or(AppError::unauthorized("invalid_credentials"))?;
        (ctx.state.clone(), handler, request_hex, user)
    };

    let request = SecretBytes::from_hex(request_hex.expose())
        .map_err(|_| AppError::bad_request("invalid_opaque"))?;
    let cred_id = normalize_handler(handler.expose());

    let (response, login_state) = server_login_start(
        &state.opaque_setup,
        user.opaque_record.expose_as_slice(),
        request.expose_as_slice(),
        cred_id.as_bytes(),
        cred_id.as_bytes(),
        labels::OPAQUE_SERVER_ID,
    )?;

    let flow = hex::encode(keys::random_32()?.as_slice());
    state
        .store
        .set(
            &store_keys::opaque_login(&flow),
            &SecretBytes::from_slice(&login_state),
            OPAQUE_LOGIN_FLOW_TTL,
        )
        .await?;

    let response_hex = SecretBytes::from_slice(&response).to_hex();

    let mut ctx = req.lock().await;
    ctx.reply_ok(json!({
        field::MSG: "Ok",
        field::OPAQUE: response_hex.expose(),
        field::FLOW: flow,
    }))
    .await
}

#[handler]
pub async fn login_finish(req: CryptoReq) -> Result<Response, AppError> {
    let (state, handler, flow, finalization_hex, user) = {
        let mut ctx = req.lock().await;
        let handler = ctx.body.take_string(field::HANDLER)?;
        let flow = ctx.body.take_string(field::FLOW)?;
        let finalization_hex = ctx.body.take_string(field::OPAQUE)?;
        let user = ctx
            .user
            .clone()
            .ok_or(AppError::unauthorized("invalid_credentials"))?;
        (ctx.state.clone(), handler, flow, finalization_hex, user)
    };

    let handler_norm = normalize_handler(handler.expose());

    let Some(login_state) = state
        .store
        .take(&store_keys::opaque_login(flow.expose()))
        .await?
    else {
        login_rate_limit_fail(&state, &handler_norm).await?;
        return Err(AppError::unauthorized("invalid_credentials"));
    };

    let finalization = SecretBytes::from_hex(finalization_hex.expose())
        .map_err(|_| AppError::bad_request("invalid_opaque"))?;

    if server_login_finish(
        login_state.expose_as_slice(),
        finalization.expose_as_slice(),
        handler_norm.as_bytes(),
        labels::OPAQUE_SERVER_ID,
    )
    .is_err()
    {
        login_rate_limit_fail(&state, &handler_norm).await?;
        return Err(AppError::unauthorized("invalid_credentials"));
    }

    login_rate_limit_success(&state, &handler_norm).await?;

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

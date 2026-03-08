use poem::{handler, Response};
use serde_json::json;
use tracing::{debug, warn};
use crate::db::repo::ServerDbExt;
use crate::error::AppError;
use crate::transport::CryptoReq;

#[handler]
pub async fn register(req: CryptoReq) -> Result<Response, AppError> {
    let (state, handler, password, dek_hex, ed_key, dili_key) = {
        let mut ctx = req.lock().await;

        let ed = ctx
            .client_ed_key
            .clone()
            .ok_or(AppError::bad_request("missing key-ed"))?
            .as_slice()
            .to_vec();

        let dili = ctx
            .client_dili_key
            .clone()
            .ok_or(AppError::bad_request("missing key-dili"))?
            .as_slice()
            .to_vec();

        let handler = ctx.body.take_string("handler")?;
        let password = ctx.body.take_string("password")?;
        let dek_hex = ctx.body.take_string("dek")?;

        debug!(
            handler = %handler.expose(),
            dek_hex_len = dek_hex.expose().len(),
            ed_len = ed.as_slice().len(),
            dili_len = dili.as_slice().len(),
            "register payload extracted"
        );

        (
            ctx.state.clone(),
            handler,
            password,
            dek_hex,
            ed.as_slice().to_vec(),
            dili.as_slice().to_vec(),
        )
    };

    let _dek_blob = hex::decode(dek_hex.expose()).map_err(|_| {
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
            &ed_key,
            &dili_key,
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
    let (state, handler, password) = {
        let mut ctx = req.lock().await;
        let handler = ctx.body.take_string("handler")?;
        let password = ctx.body.take_string("password")?;
        (ctx.state.clone(), handler, password)
    };

    let user = state
        .db
        .try_login(handler.expose(), password.expose())
        .await?
        .ok_or_else(|| AppError::bad_request("invalid_credentials"))?;

    let dek = state.db.get_dek_for_user(&user).await?;

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
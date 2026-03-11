use poem::{handler, Response};
use serde_json::json;

use crate::db::repo::ServerDbExt;
use crate::error::AppError;
use crate::transport::CryptoReq;

use lithium_core::secrets::bytes::SecretBytes;

fn decode_mailbox(hex_str: &str) -> Result<Vec<u8>, AppError> {
    let mb = SecretBytes::from_hex(hex_str).map_err(|_| AppError::bad_request("invalid_mailbox"))?;
    if mb.len() != 16 && mb.len() != 32 {
        return Err(AppError::bad_request("invalid_mailbox"));
    }
    Ok(mb.as_slice().to_vec())
}

#[handler]
pub async fn send(req: CryptoReq) -> Result<Response, AppError> {
    let (state, mailbox_hex, content_hex) = {
        let mut ctx = req.lock().await;

        let _user = ctx.user.clone().ok_or(AppError::unauthorized("unauthorized"))?;

        let mailbox_hex = ctx.body.take_string("mailbox")?;
        let content_hex = ctx.body.take_string("content")?;

        (ctx.state.clone(), mailbox_hex, content_hex)
    };

    let mailbox = decode_mailbox(mailbox_hex.expose())?;
    let content_sb =
        SecretBytes::from_hex(content_hex.expose()).map_err(|_| AppError::bad_request("invalid_content"))?;

    let _ = state
        .db
        .add_message(
            &state.store,
            mailbox,
            content_sb,
            std::time::Duration::from_secs(24 * 60 * 60),
        )
        .await?;

    let mut ctx = req.lock().await;
    ctx.reply_ok_authed(
        120,
        json!({
            "msg": "Message sent"
        }),
    )
        .await
}

#[handler]
pub async fn fetch(req: CryptoReq) -> Result<Response, AppError> {
    let (state, mailbox_hex) = {
        let mut ctx = req.lock().await;

        let mailbox_hex = ctx.body.take_string("mailbox")?;
        (ctx.state.clone(), mailbox_hex)
    };

    let mailbox = decode_mailbox(mailbox_hex.expose())?;

    let data: Vec<String> = state
        .db
        .get_messages(&state.store, mailbox)
        .await?
        .into_iter()
        .map(|z| z.expose().to_string())
        .collect();

    let mut ctx = req.lock().await;
    ctx.reply_ok(json!({
        "msg": "Ok",
        "data": data,
    }))
        .await
}
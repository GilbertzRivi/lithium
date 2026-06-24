use poem::{Response, handler};
use serde_json::json;

use crate::db::repo::ServerDbExt;
use crate::error::AppError;
use crate::transport::CryptoReq;

use lithium_core::pow;
use lithium_core::secrets::bytes::SecretBytes;
use lithium_proto::contract::protocol::field;
use lithium_proto::labels;

fn decode_mailbox(hex_str: &str) -> Result<Vec<u8>, AppError> {
    let mb =
        SecretBytes::from_hex(hex_str).map_err(|_| AppError::bad_request("invalid_mailbox"))?;
    if mb.len() != 16 && mb.len() != 32 {
        return Err(AppError::bad_request("invalid_mailbox"));
    }
    Ok(mb.expose_as_slice().to_vec())
}

#[handler]
pub async fn send(req: CryptoReq) -> Result<Response, AppError> {
    let (state, mailbox_hex, content_hex, pow_nonce) = {
        let mut ctx = req.lock().await;

        let mailbox_hex = ctx.body.take_string(field::MAILBOX)?;
        let content_hex = ctx.body.take_string(field::CONTENT)?;
        let pow_nonce = ctx.body.take_string(field::POW)?;

        (ctx.state.clone(), mailbox_hex, content_hex, pow_nonce)
    };

    let mailbox = decode_mailbox(mailbox_hex.expose())?;
    let content_sb = SecretBytes::from_hex(content_hex.expose())
        .map_err(|_| AppError::bad_request("invalid_content"))?;

    let nonce: u64 = pow_nonce
        .expose()
        .parse()
        .map_err(|_| AppError::bad_request("invalid_pow"))?;
    let challenge = pow::challenge(labels::POW_CTX, &mailbox, content_sb.expose_as_slice());
    if !pow::verify(&challenge, nonce, state.send_pow_bits) {
        return Err(AppError::too_many_requests("pow_required"));
    }

    state
        .db
        .add_message(
            &state.store,
            mailbox,
            content_sb,
            std::time::Duration::from_secs(24 * 60 * 60),
        )
        .await?;

    let mut ctx = req.lock().await;
    ctx.reply_ok(json!({
        field::MSG: "Message sent"
    }))
    .await
}

#[handler]
pub async fn fetch(req: CryptoReq) -> Result<Response, AppError> {
    let (state, mailbox_hex) = {
        let mut ctx = req.lock().await;

        let mailbox_hex = ctx.body.take_string(field::MAILBOX)?;
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
        field::MSG: "Ok",
        field::DATA: data,
    }))
    .await
}

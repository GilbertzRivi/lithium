use poem::{Response, handler};
use serde_json::json;

use lithium_core::contract::protocol::field;

use crate::error::AppError;
use crate::transport::CryptoReq;

#[handler]
pub async fn handshake(req: CryptoReq) -> Result<Response, AppError> {
    let mut ctx = req.lock().await;
    ctx.reply_ok(json!({
        field::MSG: "Ok",
    }))
    .await
}

use poem::{handler, Response};
use serde_json::json;

use crate::error::AppError;
use crate::transport::CryptoReq;

#[handler]
pub async fn handshake(req: CryptoReq) -> Result<Response, AppError> {
    let mut ctx = req.lock().await;
    ctx.reply_ok(json!({
        "msg": "Ok",
    }))
    .await
}

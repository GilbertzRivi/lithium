use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum IpcRequest {
    Ping { id: u64 },
    UnlockKeystore { id: u64, data_password: String },
    SetCredentials { id: u64, handler: String, password: String },
    Register { id: u64 },
    UnlockStorage { id: u64 },
    Shutdown { id: u64 },
    WipeLocal { id: u64 },
    CreateInvite { id: u64, contact_id: Option<String>, server: Option<String> },
    AcceptInvite { id: u64, code: String, contact_id: Option<String>, label: String },
    ContactsList { id: u64 },
    ContactSend { id: u64, contact_id: String, plaintext: String },
    ContactFetch { id: u64, contact_id: String },
    ContactForget { id: u64, contact_id: String },
    MessagesList { id: u64, contact_id: String, limit: Option<u64>, before_id: Option<i64> },
}

#[derive(Debug, Serialize)]
pub struct IpcResponse {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn err_resp(id: u64, msg: impl Into<String>) -> IpcResponse {
    IpcResponse {
        id,
        ok: false,
        result: None,
        error: Some(msg.into()),
    }
}

pub fn bad_json_resp(id: u64) -> IpcResponse {
    err_resp(id, "bad_json")
}

pub fn internal_err(id: u64) -> IpcResponse {
    err_resp(id, "internal_error")
}

pub fn storage_err(id: u64) -> IpcResponse {
    err_resp(id, "storage_error")
}

pub fn protocol_err(id: u64) -> IpcResponse {
    err_resp(id, "protocol_error")
}

pub fn crypto_err(id: u64) -> IpcResponse {
    err_resp(id, "crypto_error")
}

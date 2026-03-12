use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct IpcRequest {
    pub id: u64,

    #[serde(default)]
    pub auth_token: Option<String>,

    #[serde(flatten)]
    pub cmd: IpcCommand,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum IpcCommand {
    Ping,
    UnlockKeystore { data_password: String },
    SetCredentials { handler: String, password: String },
    Register,
    UnlockStorage,
    Shutdown,
    WipeLocal,
    CreateInvite { contact_id: Option<String> },
    AcceptInvite { code: String, contact_id: Option<String>, label: String },
    ContactsList,
    ContactSend { contact_id: String, plaintext: String },
    ContactFetch { contact_id: String },
    ContactForget { contact_id: String },
    MessagesList { contact_id: String, limit: Option<u64>, before_id: Option<i64> },
    ContactVerifyEmoji { contact_id: String },
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
use std::{
    env,
    sync::{Mutex, OnceLock},
};

#[cfg(unix)]
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

#[cfg(unix)]
use tokio::net::UnixStream;

#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use tokio::net::windows::named_pipe::ClientOptions;

#[derive(Debug, Deserialize)]
struct Envelope {
    pub id: u64,
    pub ok: bool,
    pub result: Option<Value>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct UnlockKeystoreResult {
    #[serde(default)]
    pub unlocked: bool,
    #[serde(default)]
    pub ipc_auth_token: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RegisterResult {
    #[serde(default)]
    pub capability: String,
}

static IPC_AUTH_TOKEN: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn auth_slot() -> &'static Mutex<Option<String>> {
    IPC_AUTH_TOKEN.get_or_init(|| Mutex::new(None))
}

fn current_auth_token() -> Option<String> {
    auth_slot().lock().map(|g| g.clone()).unwrap_or(None)
}

fn set_auth_token(token: Option<String>) {
    if let Ok(mut guard) = auth_slot().lock() {
        *guard = token;
    }
}

pub fn has_auth_token() -> bool {
    auth_slot().lock().map(|g| g.is_some()).unwrap_or(false)
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PingStatus {
    #[serde(default)]
    pub has_server_url: bool,
    #[serde(default)]
    pub has_keystore_on_disk: bool,
    #[serde(default)]
    pub has_server_identity: bool,
    #[serde(default)]
    pub first_run: bool,
    #[serde(default)]
    pub mk_rotation_error: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PingResult {
    #[serde(default)]
    pub status: PingStatus,
    #[serde(default)]
    pub ui_state: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ContactInfo {
    #[serde(default)]
    pub contact_id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub peer_set: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ContactsResult {
    #[serde(default)]
    pub contacts: Vec<ContactInfo>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MessageItem {
    #[serde(default)]
    pub direction: String,
    pub text: Option<String>,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MessagesResult {
    #[serde(default)]
    pub messages: Vec<MessageItem>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CreateInviteResult {
    #[serde(default)]
    pub contact_id: String,
    #[serde(default)]
    pub code: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AcceptInviteResult {
    #[serde(default)]
    pub contact_id: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct VerifyEmojiResult {
    #[serde(default)]
    pub emojis: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ContactFetchMessageResult {
    #[serde(default)]
    pub ok: bool,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ContactFetchResult {
    #[serde(default)]
    pub messages: Vec<ContactFetchMessageResult>,
}

async fn send_request(mut req: Value) -> Result<Value, String> {
    if let Some(token) = current_auth_token() {
        if let Some(obj) = req.as_object_mut() {
            obj.insert("auth_token".into(), Value::String(token));
        }
    }

    let line = serde_json::to_string(&req).map_err(|e| format!("json_encode_failed:{e}"))?;

    #[cfg(unix)]
    {
        let path = default_socket_path();
        let stream = UnixStream::connect(&path)
            .await
            .map_err(|e| format!("daemon_connect_failed:{e}"))?;
        return send_over_stream(stream, &line).await;
    }

    #[cfg(windows)]
    {
        let pipe_name = default_pipe_name();
        let stream = connect_named_pipe(&pipe_name).await?;
        return send_over_stream(stream, &line).await;
    }
}

async fn send_over_stream<S>(stream: S, line: &str) -> Result<Value, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (r, mut w) = tokio::io::split(stream);

    w.write_all(line.as_bytes())
        .await
        .map_err(|e| format!("ipc_write_failed:{e}"))?;
    w.write_all(b"\n")
        .await
        .map_err(|e| format!("ipc_write_failed:{e}"))?;
    w.flush()
        .await
        .map_err(|e| format!("ipc_flush_failed:{e}"))?;

    let mut reader = BufReader::new(r);
    let mut resp_line = String::new();

    let n = reader
        .read_line(&mut resp_line)
        .await
        .map_err(|e| format!("ipc_read_failed:{e}"))?;

    if n == 0 {
        return Err("daemon_closed_connection".into());
    }

    let env: Envelope =
        serde_json::from_str(resp_line.trim()).map_err(|e| format!("bad_ipc_response:{e}"))?;

    let _ = env.id;

    if env.ok {
        Ok(env.result.unwrap_or(Value::Null))
    } else {
        let err = env.error.unwrap_or_else(|| "ipc_error".to_string());
        if err == "ipc_auth_failed" || err == "ipc_auth_required" {
            set_auth_token(None);
        }
        Err(err)
    }
}

#[cfg(unix)]
fn default_socket_path() -> PathBuf {
    if let Ok(v) = env::var("LITHIUMD_SOCKET_PATH") {
        return PathBuf::from(v);
    }

    if let Some(xdg) = env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(xdg).join("lithiumd.sock");
    }

    // No safe fallback — connect will fail and the GUI will show DaemonOffline.
    PathBuf::from("/dev/null/lithiumd.sock")
}

#[cfg(windows)]
fn default_pipe_name() -> String {
    env::var("LITHIUMD_PIPE_NAME").unwrap_or_else(|_| r"\\.\pipe\lithiumd".to_string())
}

#[cfg(windows)]
async fn connect_named_pipe(
    name: &str,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, String> {
    let mut last_err = None;

    for _ in 0..40 {
        match ClientOptions::new().open(name) {
            Ok(client) => return Ok(client),
            Err(e) => {
                last_err = Some(e.to_string());
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    Err(format!(
        "daemon_connect_failed:{}",
        last_err.unwrap_or_else(|| "unknown".into())
    ))
}

pub async fn set_server_url(url: &str) -> Result<(), String> {
    let _ = send_request(json!({
        "cmd": "set_server_url",
        "id": 20,
        "url": url
    }))
    .await?;
    Ok(())
}

pub async fn set_server_identity(data: &[u8]) -> Result<(), String> {
    let _ = send_request(json!({
        "cmd": "set_server_identity",
        "id": 19,
        "data": hex::encode(data)
    }))
    .await?;
    Ok(())
}

pub async fn ping() -> Result<PingResult, String> {
    let v = send_request(json!({
        "cmd": "ping",
        "id": 1
    }))
        .await?;

    serde_json::from_value(v).map_err(|e| format!("bad_ping_payload:{e}"))
}

pub async fn unlock_keystore(data_password: &str) -> Result<(), String> {
    set_auth_token(None);

    let v = send_request(json!({
        "cmd": "unlock_keystore",
        "id": 2,
        "data_password": data_password
    }))
        .await?;

    let parsed: UnlockKeystoreResult =
        serde_json::from_value(v).map_err(|e| format!("bad_unlock_payload:{e}"))?;

    if !parsed.unlocked || parsed.ipc_auth_token.is_empty() {
        return Err("bad_unlock_payload:missing_ipc_auth_token".into());
    }

    set_auth_token(Some(parsed.ipc_auth_token));
    Ok(())
}

pub async fn set_credentials(handler: &str, password: &str) -> Result<(), String> {
    let _ = send_request(json!({
        "cmd": "set_credentials",
        "id": 3,
        "handler": handler,
        "password": password
    }))
        .await?;
    Ok(())
}

pub async fn register() -> Result<RegisterResult, String> {
    let v = send_request(json!({
        "cmd": "register",
        "id": 4
    }))
        .await?;

    serde_json::from_value(v).map_err(|e| format!("bad_register_payload:{e}"))
}

pub async fn remote_delete(capability: &str) -> Result<(), String> {
    let _ = send_request(json!({
        "cmd": "remote_delete",
        "id": 15,
        "capability": capability
    }))
        .await?;
    Ok(())
}

pub async fn delete_account() -> Result<(), String> {
    let _ = send_request(json!({
        "cmd": "delete_account",
        "id": 16
    }))
        .await?;
    Ok(())
}

pub async fn unlock_storage() -> Result<(), String> {
    let _ = send_request(json!({
        "cmd": "unlock_storage",
        "id": 5
    }))
        .await?;
    Ok(())
}

pub async fn contacts_list() -> Result<Vec<ContactInfo>, String> {
    let v = send_request(json!({
        "cmd": "contacts_list",
        "id": 6
    }))
        .await?;

    let parsed: ContactsResult =
        serde_json::from_value(v).map_err(|e| format!("bad_contacts_payload:{e}"))?;
    Ok(parsed.contacts)
}

pub async fn messages_list(
    contact_id: &str,
    limit: u64,
    before_id: Option<i64>,
) -> Result<MessagesResult, String> {
    let v = send_request(json!({
        "cmd": "messages_list",
        "id": 7,
        "contact_id": contact_id,
        "limit": limit,
        "before_id": before_id
    }))
        .await?;

    serde_json::from_value(v).map_err(|e| format!("bad_messages_payload:{e}"))
}

pub async fn contact_send(contact_id: &str, plaintext: &str) -> Result<(), String> {
    let _ = send_request(json!({
        "cmd": "contact_send",
        "id": 8,
        "contact_id": contact_id,
        "plaintext": plaintext
    }))
        .await?;
    Ok(())
}

pub async fn contact_fetch(contact_id: &str) -> Result<ContactFetchResult, String> {
    let v = send_request(json!({
        "cmd": "contact_fetch",
        "id": 10,
        "contact_id": contact_id,
    }))
        .await?;

    serde_json::from_value(v).map_err(|e| format!("bad_contact_fetch_response: {e}"))
}

pub async fn create_invite(contact_id: Option<&str>) -> Result<CreateInviteResult, String> {
    let v = send_request(json!({
        "cmd": "create_invite",
        "id": 10,
        "contact_id": contact_id,
        "server": null
    }))
        .await?;

    serde_json::from_value(v).map_err(|e| format!("bad_create_invite_payload:{e}"))
}

pub async fn accept_invite(
    code: &str,
    label: &str,
    contact_id: Option<&str>,
) -> Result<AcceptInviteResult, String> {
    let v = send_request(json!({
        "cmd": "accept_invite",
        "id": 11,
        "code": code,
        "contact_id": contact_id,
        "label": label
    }))
        .await?;

    serde_json::from_value(v).map_err(|e| format!("bad_accept_invite_payload:{e}"))
}

pub async fn contact_forget(contact_id: &str) -> Result<(), String> {
    let _ = send_request(json!({
        "cmd": "contact_forget",
        "id": 12,
        "contact_id": contact_id
    }))
        .await?;
    Ok(())
}

pub async fn contact_verify_emoji(contact_id: &str) -> Result<VerifyEmojiResult, String> {
    let v = send_request(json!({
        "cmd": "contact_verify_emoji",
        "id": 14,
        "contact_id": contact_id
    }))
        .await?;

    serde_json::from_value(v).map_err(|e| format!("bad_contact_verify_emoji_payload:{e}"))
}

pub async fn wipe_local() -> Result<(), String> {
    let _ = send_request(json!({
        "cmd": "wipe_local",
        "id": 13
    }))
        .await?;
    set_auth_token(None);
    Ok(())
}

pub async fn lock_keystore() -> Result<(), String> {
    let _ = send_request(json!({
        "cmd": "lock_keystore",
        "id": 17
    }))
        .await?;
    set_auth_token(None);
    Ok(())
}
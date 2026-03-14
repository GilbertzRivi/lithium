use std::sync::Arc;

use reqwest::Client;
use serde_json::json;

use lithium_core::{
    secrets::SecretString,
    utils::store::EphemeralStoreManager,
};

use crate::{
    ipc::types::{err_resp, internal_err, protocol_err, IpcResponse},
    password_provider::PasswordFileMkProvider,
    protocol_manager::ProtocolManager,
    state::DaemonState,
};

pub async fn handle(
    id: u64,
    capability: SecretString,
    state: Arc<DaemonState>,
) -> IpcResponse {
    let eph = match EphemeralStoreManager::new() {
        Ok(v) => v,
        Err(_) => return internal_err(id),
    };

    let Some(base_url) = state.server_url().await else {
        return err_resp(id, "server_url_not_set");
    };

    let http = Client::builder().http1_only().build().expect("http client");

    let proto = ProtocolManager::<PasswordFileMkProvider>::new(
        base_url,
        http,
        eph,
        None,
        state.identity_path.clone(),
    );

    match proto.remote_delete(&capability).await {
        Ok(()) => IpcResponse {
            id,
            ok: true,
            result: Some(json!({
                "remote_delete_requested": true
            })),
            error: None,
        },
        Err(_) => protocol_err(id),
    }
}
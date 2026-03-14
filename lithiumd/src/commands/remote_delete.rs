use std::sync::Arc;

use reqwest::Client;
use serde_json::json;

use lithium_core::{
    secrets::SecretString,
    utils::store::EphemeralStoreManager,
};

use crate::{
    ipc::types::{internal_err, protocol_err, IpcResponse},
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

    let http = Client::new();

    let proto = ProtocolManager::<PasswordFileMkProvider>::new(
        state.base_url.clone(),
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
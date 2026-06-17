use std::{sync::Arc, time::Duration};

use reqwest::Client;
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, watch};

use lithium_core::{
    keys::{KeyManager, KeyStoreKind},
    passwords::passwords::{PasswordPolicy, validate_password, validate_passwords_distinct},
    secrets::SecretString,
    utils::store::EphemeralStoreManager,
};

use crate::{
    ipc::types::{IpcResponse, crypto_err, err_resp, internal_err},
    password_provider::PasswordFileMkProvider,
    protocol_manager::ProtocolManager,
    state::{DaemonState, MkRotator},
};

pub async fn handle(
    id: u64,
    data_password: SecretString,
    state: Arc<DaemonState>,
    pol: &PasswordPolicy,
) -> IpcResponse {
    let dp = data_password;

    if validate_password(&dp, *pol).is_err() {
        return err_resp(id, "bad_data_password");
    }

    let already = state.proto.lock().await.is_some();
    if already {
        let current = state.data_pass.lock().await.clone();
        return match current {
            Some(cur) if bool::from(cur.expose().as_bytes().ct_eq(dp.expose().as_bytes())) => {
                IpcResponse {
                    id,
                    ok: true,
                    result: Some(json!({"unlocked": true})),
                    error: None,
                }
            }
            _ => err_resp(id, "bad_data_password"),
        };
    }

    let acc_opt = state.account_creds.lock().await.clone();
    let distinct_ok = match acc_opt {
        None => Ok(()),
        Some((_h, ap)) => validate_passwords_distinct(&dp, &ap),
    };
    if distinct_ok.is_err() {
        return err_resp(id, "passwords_must_be_distinct");
    }

    if let Some(old) = state.mk_rotator.lock().await.take() {
        let _ = old.stop_tx.send(true);
        let _ = old.handle.await;
    }

    *state.data_pass.lock().await = Some(dp.clone());

    let mk_path = state.base_dir.join("keystore").join("user").join("mk.enc");
    let mk_provider = PasswordFileMkProvider::new(mk_path, dp);

    let km = match KeyManager::start(
        &state.base_dir.join("keystore"),
        KeyStoreKind::User,
        mk_provider,
    ) {
        Err(_) => return crypto_err(id),
        Ok(km) => km,
    };

    let keys = Arc::new(Mutex::new(km));

    *state.keys.lock().await = Some(Arc::clone(&keys));
    *state.local_db.lock().await = None;

    let (stop_tx, mut stop_rx) = watch::channel(false);
    let keys2 = Arc::clone(&keys);
    let mk_err_flag = Arc::clone(&state.mk_rotation_error);
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    let mut km = keys2.lock().await;
                    let failed = km.maybe_rotate_mk().is_err();
                    *mk_err_flag.lock().await = failed;
                }
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });
    *state.mk_rotator.lock().await = Some(MkRotator { stop_tx, handle });

    let eph = match EphemeralStoreManager::new() {
        Err(_) => return internal_err(id),
        Ok(eph) => eph,
    };

    let Some(base_url) = state.server_url().await else {
        return err_resp(id, "server_url_not_set");
    };

    let http = match Client::builder().http1_only().build() {
        Ok(c) => c,
        Err(_) => return internal_err(id),
    };

    let proto = Arc::new(ProtocolManager::new(
        base_url,
        http,
        eph,
        Some(keys),
        state.identity_path.clone(),
    ));

    let creds_opt = state.account_creds.lock().await.clone();
    if let Some((h, p)) = creds_opt {
        proto.set_credentials(h, p).await;
    }

    *state.proto.lock().await = Some(proto);

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({"unlocked": true})),
        error: None,
    }
}

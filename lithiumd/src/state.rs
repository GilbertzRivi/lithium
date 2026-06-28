// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use reqwest::Url;
use tokio::sync::{Mutex, RwLock, mpsc, watch};

use lithium_core::keys::KeyManager;
use lithium_core::secrets::{Byte32, SecretString};
use lithium_proto::db::DataManager;

use crate::password_provider::PasswordFileMkProvider;
use crate::protocol_manager::ProtocolManager;
use crate::traffic::{PendingSend, Traffic};

type SharedKeyManager = Arc<Mutex<KeyManager<PasswordFileMkProvider>>>;

pub struct MkRotator {
    pub stop_tx: watch::Sender<bool>,
    pub handle: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Debug, Default)]
pub struct IpcAuthState {
    pub session_token: Option<String>,

    #[cfg(target_os = "linux")]
    pub bound_uid: Option<u32>,

    #[cfg(target_os = "linux")]
    pub bound_pid: Option<i32>,
}

#[derive(Clone)]
pub struct DaemonState {
    pub proto: Arc<Mutex<Option<Arc<ProtocolManager<PasswordFileMkProvider>>>>>,
    pub mk_rotator: Arc<Mutex<Option<MkRotator>>>,
    pub traffic: Arc<Mutex<Option<Traffic>>>,
    pub send_tx: Arc<Mutex<Option<mpsc::Sender<PendingSend>>>>,

    pub needs_register: Arc<Mutex<bool>>,
    pub account_creds: Arc<Mutex<Option<(SecretString, SecretString)>>>,
    pub data_pass: Arc<Mutex<Option<SecretString>>>,
    pub dek_plain: Arc<Mutex<Option<Byte32>>>,

    pub keys: Arc<Mutex<Option<SharedKeyManager>>>,
    pub local_db: Arc<Mutex<Option<Arc<DataManager<PasswordFileMkProvider>>>>>,

    pub ipc_auth: Arc<Mutex<IpcAuthState>>,
    pub contact_fetch_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    pub mk_rotation_error: Arc<Mutex<bool>>,

    pub base_dir: PathBuf,
    pub base_url: Arc<RwLock<Option<Url>>>,
    pub identity_path: PathBuf,
}

impl DaemonState {
    pub fn new(
        base_dir: PathBuf,
        base_url: Option<Url>,
        identity_path: PathBuf,
        needs_register: bool,
    ) -> Self {
        Self {
            proto: Arc::new(Mutex::new(None)),
            mk_rotator: Arc::new(Mutex::new(None)),
            traffic: Arc::new(Mutex::new(None)),
            send_tx: Arc::new(Mutex::new(None)),
            needs_register: Arc::new(Mutex::new(needs_register)),
            account_creds: Arc::new(Mutex::new(None)),
            data_pass: Arc::new(Mutex::new(None)),
            dek_plain: Arc::new(Mutex::new(None)),
            keys: Arc::new(Mutex::new(None)),
            local_db: Arc::new(Mutex::new(None)),
            ipc_auth: Arc::new(Mutex::new(IpcAuthState::default())),
            contact_fetch_locks: Arc::new(Mutex::new(HashMap::new())),
            mk_rotation_error: Arc::new(Mutex::new(false)),
            base_dir,
            base_url: Arc::new(RwLock::new(base_url)),
            identity_path,
        }
    }

    pub async fn server_url(&self) -> Option<Url> {
        self.base_url.read().await.clone()
    }

    pub async fn set_server_url(&self, url: Url) {
        *self.base_url.write().await = Some(url);
    }

    pub async fn contact_fetch_lock(&self, contact_id: &[u8]) -> Arc<Mutex<()>> {
        let key = hex::encode(contact_id);
        let mut locks = self.contact_fetch_locks.lock().await;
        locks
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub async fn lock_keystore(&self) {
        *self.send_tx.lock().await = None;
        if let Some(traffic) = self.traffic.lock().await.take() {
            traffic.stop().await;
        }

        if let Some(rot) = self.mk_rotator.lock().await.take() {
            let _ = rot.stop_tx.send(true);
            let _ = rot.handle.await;
        }

        *self.dek_plain.lock().await = None;
        *self.data_pass.lock().await = None;
        *self.account_creds.lock().await = None;
        *self.proto.lock().await = None;
        if let Some(dm) = self.local_db.lock().await.take() {
            dm.close_by_ref().await;
        }
        *self.keys.lock().await = None;
        *self.mk_rotation_error.lock().await = false;

        let mut ipc = self.ipc_auth.lock().await;
        ipc.session_token = None;

        #[cfg(target_os = "linux")]
        {
            ipc.bound_uid = None;
            ipc.bound_pid = None;
        }
    }

    pub async fn mark_needs_register(&self) {
        *self.needs_register.lock().await = true;
    }

    pub async fn clear_needs_register(&self) {
        *self.needs_register.lock().await = false;
    }
}

use std::{path::PathBuf, sync::Arc};

use reqwest::Url;
use tokio::sync::{Mutex, watch};

use lithium_core::db::manager::DataManager;
use lithium_core::keys::KeyManager;
use lithium_core::secrets::{Byte32, SecretString};

use crate::password_provider::PasswordFileMkProvider;
use crate::protocol_manager::{ProtocolManager, ServerBootstrap};

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

    pub needs_register: Arc<Mutex<bool>>,
    pub account_creds: Arc<Mutex<Option<(SecretString, SecretString)>>>,
    pub data_pass: Arc<Mutex<Option<SecretString>>>,
    pub dek_plain: Arc<Mutex<Option<Byte32>>>,

    pub keys: Arc<Mutex<Option<Arc<Mutex<KeyManager<PasswordFileMkProvider>>>>>>,
    pub local_db: Arc<Mutex<Option<Arc<DataManager<PasswordFileMkProvider>>>>>,

    pub ipc_auth: Arc<Mutex<IpcAuthState>>,

    pub base_dir: PathBuf,
    pub base_url: Url,
    pub bootstrap: ServerBootstrap,
}

impl DaemonState {
    pub fn new(
        base_dir: PathBuf,
        base_url: Url,
        bootstrap: ServerBootstrap,
        needs_register: bool,
    ) -> Self {
        Self {
            proto: Arc::new(Mutex::new(None)),
            mk_rotator: Arc::new(Mutex::new(None)),
            needs_register: Arc::new(Mutex::new(needs_register)),
            account_creds: Arc::new(Mutex::new(None)),
            data_pass: Arc::new(Mutex::new(None)),
            dek_plain: Arc::new(Mutex::new(None)),
            keys: Arc::new(Mutex::new(None)),
            local_db: Arc::new(Mutex::new(None)),
            ipc_auth: Arc::new(Mutex::new(IpcAuthState::default())),
            base_dir,
            base_url,
            bootstrap,
        }
    }

    pub async fn lock_keystore(&self) {
        if let Some(rot) = self.mk_rotator.lock().await.take() {
            let _ = rot.stop_tx.send(true);
            rot.handle.abort();
        }

        *self.dek_plain.lock().await = None;
        *self.data_pass.lock().await = None;
        *self.account_creds.lock().await = None;
        *self.proto.lock().await = None;
        *self.local_db.lock().await = None;
        *self.keys.lock().await = None;

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

    pub async fn reset_for_reregister(&self) {
        self.lock_keystore().await;
        *self.needs_register.lock().await = true;
    }
}
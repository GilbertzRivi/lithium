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

    pub base_dir: PathBuf,
    pub base_url: Url,
    pub bootstrap: ServerBootstrap,
}

impl DaemonState {
    pub fn new(base_dir: PathBuf, base_url: Url, bootstrap: ServerBootstrap, needs_register: bool) -> Self {
        Self {
            proto: Arc::new(Mutex::new(None)),
            mk_rotator: Arc::new(Mutex::new(None)),
            needs_register: Arc::new(Mutex::new(needs_register)),
            account_creds: Arc::new(Mutex::new(None)),
            data_pass: Arc::new(Mutex::new(None)),
            dek_plain: Arc::new(Mutex::new(None)),

            keys: Arc::new(Mutex::new(None)),
            local_db: Arc::new(Mutex::new(None)),

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
        *self.needs_register.lock().await = true;

        *self.local_db.lock().await = None;
        *self.keys.lock().await = None;
    }
}

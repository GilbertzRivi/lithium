use std::sync::Arc;
use tokio::sync::Mutex;

use lithium_core::db::manager::DataManager;
use lithium_core::keys::PlainFileMkProvider;
use lithium_core::keys::manager::KeyManager;
use lithium_core::utils::store::EphemeralStoreManager;

pub type SharedState = Arc<AppState>;

pub struct AppState {
    pub key_manager: Arc<Mutex<KeyManager<PlainFileMkProvider>>>,
    pub store: EphemeralStoreManager,
    pub db: Arc<DataManager<PlainFileMkProvider>>,
}

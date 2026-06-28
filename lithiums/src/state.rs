// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use tokio::sync::Mutex;

use lithium_core::keys::manager::KeyManager;
use lithium_core::opaque::server::ServerSetup;
use lithium_core::utils::store::EphemeralStoreManager;
use lithium_proto::db::DataManager;

use crate::health::HealthState;
use crate::provider::ServerMkProvider;

pub type SharedState = Arc<AppState>;

pub struct AppState {
    pub key_manager: Arc<Mutex<KeyManager<ServerMkProvider>>>,
    pub store: EphemeralStoreManager,
    pub db: Arc<DataManager<ServerMkProvider>>,
    pub health: Arc<HealthState>,
    pub opaque_setup: Arc<ServerSetup>,
    pub send_pow_bits: u32,
}

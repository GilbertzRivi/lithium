// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use tokio::{
    sync::{Mutex, watch},
    task::JoinHandle,
};
use tracing::error;

use lithium_core::keys::KeyManager;

use crate::health::HealthState;
use crate::provider::ServerMkProvider;

pub struct MkRotatorHandle {
    _stop_tx: watch::Sender<bool>,
    _handle: JoinHandle<()>,
}

pub fn spawn_mk_rotator(
    km: Arc<Mutex<KeyManager<ServerMkProvider>>>,
    health: Arc<HealthState>,
    tick_every: Duration,
) -> MkRotatorHandle {
    let (stop_tx, mut stop_rx) = watch::channel(false);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(tick_every) => {
                    let mut km = km.lock().await;
                    match km.maybe_rotate_mk() {
                        Ok(_) => health.record_mk_rotation_ok(),
                        Err(e) => {
                            error!(error = ?e, "mk rotation failed");
                            health.record_mk_rotation_err();
                        }
                    }
                }
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });

    MkRotatorHandle {
        _stop_tx: stop_tx,
        _handle: handle,
    }
}

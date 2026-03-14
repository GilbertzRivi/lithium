use std::sync::Arc;
use std::time::Duration;

use tokio::{sync::{watch, Mutex}, task::JoinHandle};
use tracing::error;

use lithium_core::keys::{KeyManager, PlainFileMkProvider};

pub struct MkRotatorHandle {
    _stop_tx: watch::Sender<bool>,
    _handle: JoinHandle<()>,
}

pub fn spawn_mk_rotator(
    km: Arc<Mutex<KeyManager<PlainFileMkProvider>>>,
    tick_every: Duration,
) -> MkRotatorHandle {
    let (stop_tx, mut stop_rx) = watch::channel(false);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(tick_every) => {
                    let mut km = km.lock().await;
                    if let Err(e) = km.maybe_rotate_mk() {
                        error!(error = ?e, "mk rotation failed");
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

    MkRotatorHandle { _stop_tx: stop_tx, _handle: handle }
}
use std::sync::Arc;
use std::time::Duration;

use lithium_core::db::manager::DataManager;
use tokio::{sync::watch, task::JoinHandle};
use tracing::error;

use crate::db::repo::ServerDbExt;
use crate::health::HealthState;
use crate::provider::ServerMkProvider;

pub struct MsgReaperHandle {
    _stop_tx: watch::Sender<bool>,
    _handle: JoinHandle<()>,
}

pub fn spawn_msg_reaper(
    db: Arc<DataManager<ServerMkProvider>>,
    health: Arc<HealthState>,
    tick_every: Duration,
) -> MsgReaperHandle {
    let (stop_tx, mut stop_rx) = watch::channel(false);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(tick_every) => {
                    match db.delete_expired_messages().await {
                        Ok(_) => health.record_reaper_ok(),
                        Err(e) => {
                            error!(error = ?e, "msg reaper failed, database may accumulate trash");
                            health.record_reaper_err();
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

    MsgReaperHandle {
        _stop_tx: stop_tx,
        _handle: handle,
    }
}

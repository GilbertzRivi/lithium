// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngExt;
use rand::TryRng;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sea_orm::{EntityTrait, QueryOrder};
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use lithium_proto::contract::protocol::field;
use lithium_proto::db::DataManager;

use lithium_core::{
    CryptoErrorKind,
    crypto::kdf,
    secrets::{Byte32, SecretString, bytes::SecretBytes},
};

use crate::commands::contact_mailbox::{
    derive_mailboxes_for_generation_from_values, ensure_mailbox_state, inbound_fetch_generations,
    note_inbound_generation_seen,
};
use crate::commands::stored_message;
use crate::db::models::contacts;
use crate::db::repo::DaemonDbExt;
use crate::e2e::state::{MsgMeta, PeerState, SelfState};
use crate::e2e::wire::WireV1;
use crate::e2e::{
    decrypt_for_prekey, decrypt_for_us, drop_bootstrap_private_if_established, ensure_self_keyring,
    local_remove_public_prekey, mark_bootstrap_retire_ready, peer_set_need_recover, unpack_wire,
};
use crate::labels::LABEL_MAILBOX_COVER;
use crate::password_provider::PasswordFileMkProvider;
use crate::protocol_manager::{Endpoint, ProtocolManager};
use crate::state::DaemonState;

type Proto = Arc<ProtocolManager<PasswordFileMkProvider>>;
type Dm = Arc<DataManager<PasswordFileMkProvider>>;

const SEND_QUEUE_CAP: usize = 64;
const MAX_SEND_ATTEMPTS: u8 = 3;

#[derive(Clone, Copy)]
pub struct TrafficConfig {
    pub send_interval: Duration,
    pub fetch_interval: Duration,
}

impl TrafficConfig {
    pub fn from_env() -> Self {
        Self {
            send_interval: env_secs("LITHIUMD_TRAFFIC_SEND_INTERVAL_SECS", 20),
            fetch_interval: env_secs("LITHIUMD_TRAFFIC_FETCH_INTERVAL_SECS", 20),
        }
    }
}

fn env_secs(key: &str, default: u64) -> Duration {
    let secs = std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
        .max(1);
    Duration::from_secs(secs)
}

pub struct PendingSend {
    body: Value,
    attempts: u8,
}

impl PendingSend {
    pub fn new(body: Value) -> Self {
        Self { body, attempts: 0 }
    }
}

pub struct Traffic {
    stop_tx: watch::Sender<bool>,
    send_handle: JoinHandle<()>,
    fetch_handle: JoinHandle<()>,
}

impl Traffic {
    pub async fn stop(self) {
        let _ = self.stop_tx.send(true);
        let _ = self.send_handle.await;
        let _ = self.fetch_handle.await;
    }
}

pub fn spawn(
    proto: Proto,
    dm: Dm,
    state: Arc<DaemonState>,
    dek: Byte32,
    cfg: TrafficConfig,
) -> (Traffic, mpsc::Sender<PendingSend>) {
    let (stop_tx, stop_rx) = watch::channel(false);
    let (tx, rx) = mpsc::channel::<PendingSend>(SEND_QUEUE_CAP);

    let send_handle = tokio::spawn(run_send(
        proto.clone(),
        dek.clone(),
        tx.clone(),
        rx,
        cfg.send_interval,
        stop_rx.clone(),
    ));
    let fetch_handle = tokio::spawn(run_fetch(
        proto,
        dm,
        state,
        dek,
        cfg.fetch_interval,
        stop_rx,
    ));

    (
        Traffic {
            stop_tx,
            send_handle,
            fetch_handle,
        },
        tx,
    )
}

// One network emission per tick, regardless of activity: a queued real send when
// present, otherwise a dummy to our own cover mailbox. A server watching the link
// sees a constant-rate stream it cannot split into real vs noise.
async fn run_send(
    proto: Proto,
    dek: Byte32,
    tx: mpsc::Sender<PendingSend>,
    mut rx: mpsc::Receiver<PendingSend>,
    interval: Duration,
    mut stop_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                match rx.try_recv() {
                    Ok(mut p) => {
                        if proto
                            .send(Endpoint::MsgSend, p.body.clone(), json!({}))
                            .await
                            .is_err()
                        {
                            // No delivery guarantee in the trust model; retry a bounded
                            // number of slots, then drop rather than stall the cadence.
                            p.attempts += 1;
                            if p.attempts < MAX_SEND_ATTEMPTS {
                                let _ = tx.try_send(p);
                            }
                        }
                    }
                    Err(_) => {
                        if let Some(body) = dummy_send_body(&dek) {
                            let _ = proto.send(Endpoint::MsgSend, body, json!({})).await;
                        }
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
}

// One fetch per tick, round-robin over every (contact, inbound generation) mailbox plus
// the cover mailbox. Polling a whole generation window at once would tie those addresses
// together for the server, so each address is drained on its own slot.
async fn run_fetch(
    proto: Proto,
    dm: Dm,
    state: Arc<DaemonState>,
    dek: Byte32,
    interval: Duration,
    mut stop_rx: watch::Receiver<bool>,
) {
    let mut targets: Vec<Target> = Vec::new();
    let mut cursor = 0usize;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                if cursor >= targets.len() {
                    targets = build_targets(&dm).await;
                    targets.push(Target::Cover);
                    cursor = 0;
                }

                let target = targets[cursor].clone();
                cursor += 1;

                match target {
                    Target::Cover => drain_cover(&proto, &dek).await,
                    Target::Contact { contact_id, generation } => {
                        poll_one(&proto, &dm, &state, &contact_id, generation).await;
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
}

#[derive(Clone)]
enum Target {
    Cover,
    Contact {
        contact_id: Vec<u8>,
        generation: u64,
    },
}

async fn build_targets(dm: &Dm) -> Vec<Target> {
    let mut out = Vec::new();

    let Ok(rows) = contacts::Entity::find()
        .order_by_asc(contacts::Column::Id)
        .all(dm.db())
        .await
    else {
        return out;
    };

    for r in rows {
        let Ok(Some(row)) = dm.get_contact(&r.contact_id).await else {
            continue;
        };
        let Ok(peer_st) = PeerState::from_bytes(row.peer_state.expose_as_slice()) else {
            continue;
        };
        if !peer_st.peer_is_set() {
            continue;
        }
        for generation in inbound_fetch_generations(&peer_st) {
            out.push(Target::Contact {
                contact_id: r.contact_id.clone(),
                generation,
            });
        }
    }

    out
}

async fn drain_cover(proto: &Proto, dek: &Byte32) {
    let Some(mailbox) = cover_mailbox(dek) else {
        return;
    };
    let _ = proto
        .send(
            Endpoint::MsgFetch,
            json!({ field::MAILBOX: hex::encode(mailbox) }),
            json!({}),
        )
        .await;
}

async fn poll_one(
    proto: &Proto,
    dm: &Dm,
    state: &Arc<DaemonState>,
    contact_id: &[u8],
    generation: u64,
) {
    let contact_lock = state.contact_fetch_lock(contact_id).await;
    let _guard = contact_lock.lock().await;

    let Ok(Some(row)) = dm.get_contact(contact_id).await else {
        return;
    };
    let Ok(mut self_st) = SelfState::from_bytes(row.self_state.expose_as_slice()) else {
        return;
    };
    let Ok(mut peer_st) = PeerState::from_bytes(row.peer_state.expose_as_slice()) else {
        return;
    };

    if ensure_self_keyring(&mut self_st).is_err() || ensure_mailbox_state(&mut peer_st).is_err() {
        return;
    }

    let Ok((_mbox_out, mbox_in)) =
        derive_mailboxes_for_generation_from_values(&self_st, &peer_st, generation)
    else {
        return;
    };

    let Ok(resp) = proto
        .send(
            Endpoint::MsgFetch,
            json!({ field::MAILBOX: hex::encode(mbox_in) }),
            json!({}),
        )
        .await
    else {
        return;
    };

    if let Some(arr) = resp.body.get(field::DATA).and_then(|v| v.as_array()) {
        for it in arr {
            let Some(h) = it.as_str() else {
                continue;
            };
            let Ok(raw) = SecretBytes::from_hex(h.trim()) else {
                continue;
            };
            let Ok(w) = unpack_wire(raw.expose_as_slice()) else {
                continue;
            };
            process_wire(
                dm,
                &mut self_st,
                &mut peer_st,
                contact_id,
                &mbox_in,
                generation,
                &w,
            )
            .await;
        }
    }

    if let (Ok(self_bytes), Ok(peer_bytes)) = (self_st.to_secret_bytes(), peer_st.to_secret_bytes())
    {
        let _ = dm
            .upsert_contact(contact_id.to_vec(), peer_bytes, self_bytes)
            .await;
    }
}

async fn process_wire(
    dm: &Dm,
    self_st: &mut SelfState,
    peer_st: &mut PeerState,
    contact_id: &[u8],
    mbox_in: &[u8; 32],
    generation: u64,
    w: &WireV1,
) {
    match decrypt_for_us(self_st, peer_st, w) {
        Ok((pt, ui)) => {
            store_inbound(dm, peer_st, contact_id, mbox_in, generation, pt, ui).await;
        }
        Err(err) => {
            if matches!(&err.kind, CryptoErrorKind::InvalidCredentials { msg } if *msg == "potentially_harmful_message")
            {
                return;
            }
            if !matches!(&err.kind, CryptoErrorKind::InvalidCredentials { msg } if *msg == "to_id_unknown")
            {
                return;
            }

            let Ok(Some(blob)) = dm.take_prekey(&w.to_id).await else {
                peer_set_need_recover(peer_st, true);
                return;
            };

            match decrypt_for_prekey(peer_st, w, &blob) {
                Ok((pt, mut ui)) => {
                    local_remove_public_prekey(self_st, &hex::encode(w.to_id));
                    peer_set_need_recover(peer_st, false);
                    mark_bootstrap_retire_ready(self_st);
                    drop_bootstrap_private_if_established(self_st, peer_st);

                    if let Some(obj) = ui.as_object_mut() {
                        obj.insert("recovered".into(), json!(true));
                    }

                    store_inbound(dm, peer_st, contact_id, mbox_in, generation, pt, ui).await;
                }
                Err(err) => {
                    if !matches!(&err.kind, CryptoErrorKind::InvalidCredentials { msg } if *msg == "potentially_harmful_message")
                    {
                        peer_set_need_recover(peer_st, true);
                    }
                }
            }
        }
    }
}

async fn store_inbound(
    dm: &Dm,
    peer_st: &mut PeerState,
    contact_id: &[u8],
    mbox_in: &[u8; 32],
    generation: u64,
    pt: Vec<u8>,
    ui: Value,
) {
    let seen_gen = meta_mailbox_gen(&ui, generation);
    note_inbound_generation_seen(peer_st, seen_gen);

    let Ok(text) = SecretString::from_utf8_vec(pt) else {
        return;
    };
    let Ok(stored) = stored_message::encode(text.expose(), &ui, &hex::encode(mbox_in), seen_gen)
    else {
        return;
    };
    let msg_id = meta_msg_id(&ui);
    let _ = dm
        .add_message(contact_id.to_vec(), mbox_in.to_vec(), 0, stored, msg_id)
        .await;
}

fn meta_mailbox_gen(ui: &Value, fallback: u64) -> u64 {
    serde_json::from_value::<MsgMeta>(ui.clone())
        .map(|m| m.mailbox_gen)
        .unwrap_or(fallback)
}

fn meta_msg_id(ui: &Value) -> Option<Vec<u8>> {
    serde_json::from_value::<MsgMeta>(ui.clone())
        .ok()
        .map(|m| m.msg_id)
        .filter(|s| !s.is_empty())
        .map(|s| s.into_bytes())
}

// Stable per-day address derived from the DEK: the daemon both sends dummies here and
// drains it on the fetch cadence, so to the server the cover mailbox looks like any other
// conversation (it receives and gets read), not an always-silent decoy.
fn cover_mailbox(dek: &Byte32) -> Option<[u8; 32]> {
    let salt = SecretBytes::from_slice(&cover_rotation_counter().to_be_bytes());
    let out = kdf::derive32(
        &SecretBytes::from_slice(dek.as_slice()),
        Some(&salt),
        &SecretBytes::from_slice(LABEL_MAILBOX_COVER),
    )
    .ok()?;
    Some(*out.as_array())
}

fn cover_rotation_counter() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}

fn dummy_send_body(dek: &Byte32) -> Option<Value> {
    let mailbox = cover_mailbox(dek)?;
    let len = UnwrapErr(SysRng).random_range(256..=2048usize);
    let mut content = vec![0u8; len];
    SysRng.try_fill_bytes(&mut content).ok()?;
    Some(json!({
        field::MAILBOX: hex::encode(mailbox),
        field::CONTENT: hex::encode(content),
    }))
}

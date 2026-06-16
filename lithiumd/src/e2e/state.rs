use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::header::E2eMode;
use super::wire::DEFAULT_WINDOW;

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct RemotePrekey {
    pub id: String,
    pub x_pub: String,
    pub k_pub: String,
    #[serde(default)]
    pub seen_at_ms: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct LocalPrekeyPublic {
    pub id: String,
    pub x_pub: String,
    pub k_pub: String,
    pub created_at_ms: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct E2ePeer {
    pub id: String,
    pub x_pub: String,
    pub k_pub: String,
    pub step: u64,
    #[serde(default)]
    pub updated_at_ms: u64,
}

// ZeroizeOnDrop so a reply key evicted from the ratchet map clears its private
// material, matching the old drop_removed_json_key behavior.
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct RxKey {
    pub x_priv: String,
    pub x_pub: String,
    pub k_priv: String,
    pub k_pub: String,
    pub seq: u64,
    pub created_at_ms: u64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub(crate) struct E2eRx {
    pub active: String,
    pub ack_seq: u64,
    pub next_seq: u64,
    pub window: u64,
    pub keys: BTreeMap<String, RxKey>,
}

impl Default for E2eRx {
    fn default() -> Self {
        Self {
            active: String::new(),
            ack_seq: 0,
            next_seq: 1,
            window: DEFAULT_WINDOW,
            keys: BTreeMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub(crate) struct BootstrapState {
    #[serde(default)]
    pub rx_used: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_used: Option<bool>,
    #[serde(default)]
    pub retire_ok: bool,
    #[serde(default)]
    pub retired_at_ms: u64,
}

// kind is read from the header on decrypt but absent on encrypt; skip-if-none keeps both shapes.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct MsgMeta {
    pub ts_ms: u64,
    pub msg_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub step: u64,
    pub mode: E2eMode,
    pub mailbox_gen: u64,
}

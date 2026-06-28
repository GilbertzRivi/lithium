// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use lithium_core::{
    error::{LithiumError, Result},
    secrets::{ZeroizingWriter, bytes::SecretBytes},
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::header::E2eMode;
use super::wire::DEFAULT_WINDOW;

pub(crate) const MAILBOX_ROTATE_EVERY_DEFAULT: u64 = 32;

fn default_doc_version() -> u8 {
    1
}

#[derive(Serialize, Deserialize, Clone, Zeroize)]
pub(crate) struct RemotePrekey {
    pub id: String,
    pub x_pub: String,
    pub k_pub: String,
    #[serde(default)]
    pub seen_at_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Zeroize)]
pub(crate) struct LocalPrekeyPublic {
    pub id: String,
    pub x_pub: String,
    pub k_pub: String,
    pub created_at_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Zeroize)]
pub(crate) struct E2ePeer {
    pub id: String,
    pub x_pub: String,
    pub k_pub: String,
    pub step: u64,
    #[serde(default)]
    pub updated_at_ms: u64,
}

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

// BTreeMap has no Zeroize derive; drain so keys and values are both cleared.
impl Zeroize for E2eRx {
    fn zeroize(&mut self) {
        self.active.zeroize();
        self.ack_seq.zeroize();
        self.next_seq.zeroize();
        self.window.zeroize();
        for (mut k, mut v) in core::mem::take(&mut self.keys) {
            k.zeroize();
            v.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Zeroize)]
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

#[derive(Serialize, Deserialize, Clone, Default, Zeroize)]
pub(crate) struct E2eTx {
    #[serde(default)]
    pub step: u64,
}

#[derive(Serialize, Deserialize, Clone, Default, Zeroize)]
#[serde(default)]
pub(crate) struct ReplayWindow {
    pub max_step: u64,
    pub bits: u64,
}

impl ReplayWindow {
    // Sliding window, not a strict monotonic check: the reply-key layer already accepts reordering
    // up to DEFAULT_WINDOW, so rejecting every step <= max would drop legitimate out-of-order messages.
    pub(crate) fn check_and_record(&mut self, step: u64) -> bool {
        if step == 0 {
            return true;
        }
        if step > self.max_step {
            let shift = step - self.max_step;
            if shift >= 64 {
                self.bits = 0;
            } else {
                self.bits = (self.bits << shift) | (1u64 << (shift - 1));
            }
            self.max_step = step;
            return true;
        }
        let diff = self.max_step - step;
        if diff == 0 || diff > 64 {
            return false;
        }
        let mask = 1u64 << (diff - 1);
        if self.bits & mask != 0 {
            return false;
        }
        self.bits |= mask;
        true
    }
}

#[derive(Serialize, Deserialize, Clone, Zeroize)]
#[serde(default)]
pub(crate) struct SelfMailbox {
    pub tx_gen: u64,
    pub tx_sent: u64,
    pub rotate_every: u64,
}

impl Default for SelfMailbox {
    fn default() -> Self {
        Self {
            tx_gen: 0,
            tx_sent: 0,
            rotate_every: MAILBOX_ROTATE_EVERY_DEFAULT,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub(crate) struct PeerMailbox {
    pub peer_tx_gen_seen: u64,
    pub sender_pubs: BTreeMap<String, String>,
}

// Manual Zeroize for the same reason as E2eRx: drain the map so keys and values clear.
impl Zeroize for PeerMailbox {
    fn zeroize(&mut self) {
        self.peer_tx_gen_seen.zeroize();
        for (mut k, mut v) in core::mem::take(&mut self.sender_pubs) {
            k.zeroize();
            v.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Zeroize)]
pub(crate) struct PeerIdentity {
    pub cid: String,
    pub x_pub: String,
    pub k_pub: String,
    pub ed_pub: String,
    pub dili_pub: String,
    pub mbox_in_pub: String,
    pub mbox_out_cur_pub: String,
    pub mbox_out_next_pub: String,
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

#[derive(Serialize, Deserialize, Zeroize)]
pub(crate) struct SelfState {
    #[serde(default = "default_doc_version")]
    pub v: u8,

    pub cid: String,
    // x_priv/k_priv are dropped once the bootstrap KEM is retired, so they are optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_priv: Option<String>,
    pub x_pub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k_priv: Option<String>,
    pub k_pub: String,
    pub ed_priv: String,
    pub ed_pub: String,
    pub dili_priv: String,
    pub dili_pub: String,

    pub mbox_in_priv: String,
    pub mbox_in_pub: String,
    pub mbox_out_cur_priv: String,
    pub mbox_out_cur_pub: String,
    pub mbox_out_next_priv: String,
    pub mbox_out_next_pub: String,

    #[serde(default)]
    pub e2e_tx: E2eTx,
    #[serde(default)]
    pub e2e_rx: E2eRx,
    #[serde(default)]
    pub bootstrap: BootstrapState,
    #[serde(default)]
    pub mailbox: SelfMailbox,
    #[serde(default)]
    pub prekeys_local_public: Vec<LocalPrekeyPublic>,
    #[serde(default)]
    pub prekeys_advertised: bool,
}

impl Drop for SelfState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Serialize, Deserialize, Zeroize)]
pub(crate) struct PeerState {
    #[serde(default = "default_doc_version")]
    pub v: u8,
    #[serde(default)]
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<PeerIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2e_peer: Option<E2ePeer>,
    #[serde(default)]
    pub bootstrap: BootstrapState,
    #[serde(default)]
    pub prekeys_remote: Vec<RemotePrekey>,
    #[serde(default)]
    pub need_recover: bool,
    #[serde(default)]
    pub mailbox: PeerMailbox,
    #[serde(default)]
    pub replay: ReplayWindow,
}

impl Drop for PeerState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SelfState {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(LithiumError::json_parse)
    }

    pub(crate) fn to_secret_bytes(&self) -> Result<SecretBytes> {
        let mut w = ZeroizingWriter::new();
        serde_json::to_writer(&mut w, self).map_err(LithiumError::json_parse)?;
        Ok(w.into_secret())
    }
}

impl PeerState {
    pub(crate) fn empty() -> Self {
        Self {
            v: default_doc_version(),
            label: String::new(),
            peer: None,
            pending_commit: None,
            e2e_peer: None,
            bootstrap: BootstrapState::default(),
            prekeys_remote: Vec::new(),
            need_recover: false,
            mailbox: PeerMailbox::default(),
            replay: ReplayWindow::default(),
        }
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(LithiumError::json_parse)
    }

    pub(crate) fn to_secret_bytes(&self) -> Result<SecretBytes> {
        let mut w = ZeroizingWriter::new();
        serde_json::to_writer(&mut w, self).map_err(LithiumError::json_parse)?;
        Ok(w.into_secret())
    }

    pub(crate) fn peer_is_set(&self) -> bool {
        self.peer.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::invite_codec::gen_self_state;

    #[test]
    fn self_state_roundtrips_through_bytes() {
        let (_cid, st) = gen_self_state().unwrap();
        let bytes = st.to_secret_bytes().unwrap();
        let back = SelfState::from_bytes(bytes.expose_as_slice()).unwrap();

        assert_eq!(back.cid, st.cid);
        assert_eq!(back.x_priv, st.x_priv);
        assert_eq!(back.k_priv, st.k_priv);
        assert_eq!(back.mbox_out_next_priv, st.mbox_out_next_priv);
        assert_eq!(back.e2e_rx.next_seq, st.e2e_rx.next_seq);
        assert_eq!(back.mailbox.rotate_every, MAILBOX_ROTATE_EVERY_DEFAULT);
    }

    #[test]
    fn self_state_omits_dropped_privs_on_serialize() {
        let (_cid, mut st) = gen_self_state().unwrap();
        st.x_priv = None;
        st.k_priv = None;
        let bytes = st.to_secret_bytes().unwrap();

        let text = std::str::from_utf8(bytes.expose_as_slice()).unwrap();
        assert!(!text.contains("x_priv"));
        assert!(!text.contains("k_priv"));

        let back = SelfState::from_bytes(bytes.expose_as_slice()).unwrap();
        assert!(back.x_priv.is_none());
        assert!(back.k_priv.is_none());
    }

    #[test]
    fn peer_state_roundtrips_empty_and_set() {
        let empty = PeerState::from_bytes(b"{}").unwrap();
        assert!(!empty.peer_is_set());

        let mut p = PeerState::empty();
        p.label = "alice".into();
        p.peer = Some(PeerIdentity {
            cid: "aa".repeat(32),
            x_pub: "bb".repeat(32),
            k_pub: "cc".repeat(32),
            ed_pub: "dd".repeat(32),
            dili_pub: "ee".repeat(32),
            mbox_in_pub: "11".repeat(32),
            mbox_out_cur_pub: "22".repeat(32),
            mbox_out_next_pub: "33".repeat(32),
        });
        p.mailbox.sender_pubs.insert("0".into(), "22".repeat(32));

        let bytes = p.to_secret_bytes().unwrap();
        let back = PeerState::from_bytes(bytes.expose_as_slice()).unwrap();
        assert_eq!(back.label, "alice");
        assert_eq!(back.peer.as_ref().unwrap().cid, "aa".repeat(32));
        assert_eq!(back.mailbox.sender_pubs.get("0").unwrap(), &"22".repeat(32));
    }

    #[test]
    fn replay_accepts_increasing_steps() {
        let mut w = ReplayWindow::default();
        assert!(w.check_and_record(1));
        assert!(w.check_and_record(2));
        assert!(w.check_and_record(3));
    }

    #[test]
    fn replay_rejects_exact_duplicate() {
        let mut w = ReplayWindow::default();
        assert!(w.check_and_record(5));
        assert!(!w.check_and_record(5));
    }

    #[test]
    fn replay_tolerates_reorder_in_window() {
        let mut w = ReplayWindow::default();
        assert!(w.check_and_record(1));
        assert!(w.check_and_record(3));
        assert!(w.check_and_record(2));
        assert!(!w.check_and_record(2));
        assert!(!w.check_and_record(3));
        assert!(!w.check_and_record(1));
    }

    #[test]
    fn replay_rejects_step_below_window() {
        let mut w = ReplayWindow::default();
        assert!(w.check_and_record(100));
        assert!(!w.check_and_record(30));
    }

    #[test]
    fn replay_large_jump_clears_bits() {
        let mut w = ReplayWindow::default();
        assert!(w.check_and_record(1));
        assert!(w.check_and_record(200));
        assert!(!w.check_and_record(1));
    }
}

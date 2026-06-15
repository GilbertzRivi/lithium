pub(crate) const E2E_RX: &str = "e2e_rx";
pub(crate) const E2E_TX: &str = "e2e_tx";
pub(crate) const E2E_PEER: &str = "e2e_peer";
pub(crate) const BOOTSTRAP: &str = "bootstrap";
pub(crate) const NEED_RECOVER: &str = "need_recover";
pub(crate) const PEER: &str = "peer";
pub(crate) const MAILBOX: &str = "mailbox";
pub(crate) const PREKEYS_LOCAL_PUBLIC: &str = "prekeys_local_public";
pub(crate) const PREKEYS_ADVERTISED: &str = "prekeys_advertised";
pub(crate) const PREKEYS_REMOTE: &str = "prekeys_remote";

pub(crate) const ACTIVE: &str = "active";
pub(crate) const ACK_SEQ: &str = "ack_seq";
pub(crate) const NEXT_SEQ: &str = "next_seq";
pub(crate) const WINDOW: &str = "window";
pub(crate) const KEYS: &str = "keys";
pub(crate) const SEQ: &str = "seq";

pub(crate) const CID: &str = "cid";
pub(crate) const ID: &str = "id";
pub(crate) const STEP: &str = "step";
pub(crate) const X_PUB: &str = "x_pub";
pub(crate) const K_PUB: &str = "k_pub";
pub(crate) const ED_PUB: &str = "ed_pub";
pub(crate) const DILI_PUB: &str = "dili_pub";
pub(crate) const X_PRIV: &str = "x_priv";
pub(crate) const K_PRIV: &str = "k_priv";
pub(crate) const ED_PRIV: &str = "ed_priv";
pub(crate) const DILI_PRIV: &str = "dili_priv";

pub(crate) const MBOX_IN_PUB: &str = "mbox_in_pub";
pub(crate) const MBOX_IN_PRIV: &str = "mbox_in_priv";
pub(crate) const MBOX_OUT_CUR_PUB: &str = "mbox_out_cur_pub";
pub(crate) const MBOX_OUT_CUR_PRIV: &str = "mbox_out_cur_priv";
pub(crate) const MBOX_OUT_NEXT_PUB: &str = "mbox_out_next_pub";
pub(crate) const MBOX_OUT_NEXT_PRIV: &str = "mbox_out_next_priv";

pub(crate) const TX_GEN: &str = "tx_gen";
pub(crate) const TX_SENT: &str = "tx_sent";
pub(crate) const ROTATE_EVERY: &str = "rotate_every";
pub(crate) const PEER_TX_GEN_SEEN: &str = "peer_tx_gen_seen";
pub(crate) const SENDER_PUBS: &str = "sender_pubs";

pub(crate) const RX_USED: &str = "rx_used";
pub(crate) const TX_USED: &str = "tx_used";
pub(crate) const RETIRE_OK: &str = "retire_ok";
pub(crate) const RETIRED_AT_MS: &str = "retired_at_ms";

pub(crate) const SEEN_AT_MS: &str = "seen_at_ms";
pub(crate) const CREATED_AT_MS: &str = "created_at_ms";
pub(crate) const UPDATED_AT_MS: &str = "updated_at_ms";

pub(crate) const TS_MS: &str = "ts_ms";
pub(crate) const MSG_ID: &str = "msg_id";
pub(crate) const MODE: &str = "mode";
pub(crate) const KIND: &str = "kind";
pub(crate) const MAILBOX_GEN: &str = "mailbox_gen";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_values_are_pinned() {
        assert_eq!(E2E_RX, "e2e_rx");
        assert_eq!(E2E_TX, "e2e_tx");
        assert_eq!(E2E_PEER, "e2e_peer");
        assert_eq!(BOOTSTRAP, "bootstrap");
        assert_eq!(NEED_RECOVER, "need_recover");
        assert_eq!(PEER, "peer");
        assert_eq!(MAILBOX, "mailbox");
        assert_eq!(PREKEYS_LOCAL_PUBLIC, "prekeys_local_public");
        assert_eq!(PREKEYS_ADVERTISED, "prekeys_advertised");
        assert_eq!(PREKEYS_REMOTE, "prekeys_remote");

        assert_eq!(ACTIVE, "active");
        assert_eq!(ACK_SEQ, "ack_seq");
        assert_eq!(NEXT_SEQ, "next_seq");
        assert_eq!(WINDOW, "window");
        assert_eq!(KEYS, "keys");
        assert_eq!(SEQ, "seq");

        assert_eq!(CID, "cid");
        assert_eq!(ID, "id");
        assert_eq!(STEP, "step");
        assert_eq!(X_PUB, "x_pub");
        assert_eq!(K_PUB, "k_pub");
        assert_eq!(ED_PUB, "ed_pub");
        assert_eq!(DILI_PUB, "dili_pub");
        assert_eq!(X_PRIV, "x_priv");
        assert_eq!(K_PRIV, "k_priv");
        assert_eq!(ED_PRIV, "ed_priv");
        assert_eq!(DILI_PRIV, "dili_priv");

        assert_eq!(MBOX_IN_PUB, "mbox_in_pub");
        assert_eq!(MBOX_IN_PRIV, "mbox_in_priv");
        assert_eq!(MBOX_OUT_CUR_PUB, "mbox_out_cur_pub");
        assert_eq!(MBOX_OUT_CUR_PRIV, "mbox_out_cur_priv");
        assert_eq!(MBOX_OUT_NEXT_PUB, "mbox_out_next_pub");
        assert_eq!(MBOX_OUT_NEXT_PRIV, "mbox_out_next_priv");

        assert_eq!(TX_GEN, "tx_gen");
        assert_eq!(TX_SENT, "tx_sent");
        assert_eq!(ROTATE_EVERY, "rotate_every");
        assert_eq!(PEER_TX_GEN_SEEN, "peer_tx_gen_seen");
        assert_eq!(SENDER_PUBS, "sender_pubs");

        assert_eq!(RX_USED, "rx_used");
        assert_eq!(TX_USED, "tx_used");
        assert_eq!(RETIRE_OK, "retire_ok");
        assert_eq!(RETIRED_AT_MS, "retired_at_ms");

        assert_eq!(SEEN_AT_MS, "seen_at_ms");
        assert_eq!(CREATED_AT_MS, "created_at_ms");
        assert_eq!(UPDATED_AT_MS, "updated_at_ms");

        assert_eq!(TS_MS, "ts_ms");
        assert_eq!(MSG_ID, "msg_id");
        assert_eq!(MODE, "mode");
        assert_eq!(KIND, "kind");
        assert_eq!(MAILBOX_GEN, "mailbox_gen");
    }
}

// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::error::{LithiumError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const SIGNED_HEADER_V: u8 = 1;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum E2eMode {
    Ratchet,
    Bootstrap,
    PrekeyRecover,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Mailbox {
    pub sender_cur_x_pub: String,
    pub sender_next_x_pub: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Reply {
    pub id: String,
    pub x_pub: String,
    pub k_pub: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Auth {
    pub sig_ed: String,
    pub sig_dili: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct SignedHeader {
    pub v: u8,
    pub mode: E2eMode,
    pub ts_ms: u64,
    pub msg_id: String,
    pub kind: String,
    pub step: u64,
    pub mbox_gen: u64,
    pub mailbox: Mailbox,
    pub reply: Reply,
    pub prekeys: Vec<Value>,
}

impl SignedHeader {
    // The only place that produces the bytes covered by the signature. Sender,
    // verifier and the wire envelope all route through this struct, so the signed
    // form is fixed by the field declaration order and cannot drift between them.
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(LithiumError::json_parse)
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SignedHeaderWire {
    pub header: SignedHeader,
    pub auth: Auth,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> SignedHeader {
        SignedHeader {
            v: SIGNED_HEADER_V,
            mode: E2eMode::Ratchet,
            ts_ms: 1_700_000_000_000,
            msg_id: "abcd".into(),
            kind: "text".into(),
            step: 7,
            mbox_gen: 3,
            mailbox: Mailbox {
                sender_cur_x_pub: "aa".into(),
                sender_next_x_pub: "bb".into(),
            },
            reply: Reply {
                id: "11".into(),
                x_pub: "22".into(),
                k_pub: "33".into(),
            },
            prekeys: vec![],
        }
    }

    #[test]
    fn canonical_bytes_is_pinned() {
        let got = String::from_utf8(sample().canonical_bytes().unwrap()).unwrap();
        let want = r#"{"v":1,"mode":"ratchet","ts_ms":1700000000000,"msg_id":"abcd","kind":"text","step":7,"mbox_gen":3,"mailbox":{"sender_cur_x_pub":"aa","sender_next_x_pub":"bb"},"reply":{"id":"11","x_pub":"22","k_pub":"33"},"prekeys":[]}"#;
        assert_eq!(got, want);
    }

    #[test]
    fn wire_roundtrip_reconstructs_signed_bytes() {
        let mut header = sample();
        header.prekeys = vec![json!({"id": "p1", "x_pub": "x", "k_pub": "k"})];
        let signed = header.canonical_bytes().unwrap();

        let wire = SignedHeaderWire {
            header,
            auth: Auth {
                sig_ed: "ed".into(),
                sig_dili: "dili".into(),
            },
        };
        let bytes = serde_json::to_vec(&wire).unwrap();
        let parsed: SignedHeaderWire = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(parsed.header.canonical_bytes().unwrap(), signed);
        assert_eq!(parsed.auth.sig_ed, "ed");
        assert_eq!(parsed.auth.sig_dili, "dili");
    }
}

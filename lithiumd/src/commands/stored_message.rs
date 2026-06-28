// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};
use serde_json::Value;

use lithium_core::secrets::bytes::{SecretBytes, ZeroizingWriter};

pub(crate) const STORED_MSG_V: u8 = 1;
pub(crate) const KIND_TEXT: &str = "text/utf8";

#[derive(Serialize)]
struct Transport<'a> {
    mailbox: &'a str,
    mailbox_gen: u64,
}

#[derive(Serialize)]
struct StoredMessage<'a> {
    v: u8,
    kind: &'a str,
    text: &'a str,
    ui: &'a Value,
    transport: Transport<'a>,
}

#[derive(Deserialize)]
pub(crate) struct Decoded {
    pub kind: Option<String>,
    pub text: Option<String>,
    #[serde(default)]
    pub ui: Value,
}

pub(crate) fn decode(bytes: &[u8]) -> Option<Decoded> {
    serde_json::from_slice(bytes).ok()
}

pub(crate) fn encode(
    text: &str,
    ui: &Value,
    mailbox_hex: &str,
    mailbox_gen: u64,
) -> Result<SecretBytes, serde_json::Error> {
    let payload = StoredMessage {
        v: STORED_MSG_V,
        kind: KIND_TEXT,
        text,
        ui,
        transport: Transport {
            mailbox: mailbox_hex,
            mailbox_gen,
        },
    };

    let mut w = ZeroizingWriter::new();
    serde_json::to_writer(&mut w, &payload)?;
    Ok(w.into_secret())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stored_message_layout_is_pinned() {
        let ui = json!({ "msg_id": "abc" });
        let out = encode("hello", &ui, "aabb", 3).unwrap();
        let got = String::from_utf8(out.expose_as_slice().to_vec()).unwrap();
        let want = r#"{"v":1,"kind":"text/utf8","text":"hello","ui":{"msg_id":"abc"},"transport":{"mailbox":"aabb","mailbox_gen":3}}"#;
        assert_eq!(got, want);
    }
}

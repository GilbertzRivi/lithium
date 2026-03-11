use lithium_core::{
    crypto::{kdf, keys, kyberbox, sign},
    error::{LithiumError, Result},
    secrets::{Byte32, SecretJson},
    secrets::bytes::SecretBytes,
};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::commands::contact_mailbox::{
    current_outbound_mailbox_pubs,
    peer_store_mailbox_sender_keys,
};

const MAGIC: &[u8; 3] = b"LM1";
const VER: u8 = 1;

const E2E_LABEL: &str = "lithiumd/e2e-msg/v1";
const E2E_SIG_LABEL: &[u8] = b"lithiumd/e2e-msg-sig/v1";
const KID_LABEL: &[u8] = b"lithiumd/e2e-peer-kid/v1";

pub const DEFAULT_WINDOW: u64 = 32;
pub const PREKEY_TARGET: usize = 5;

#[derive(Clone)]
pub struct WireV1 {
    pub to_id: [u8; 32],
    pub from_x_pub: [u8; 32],
    pub seed: Vec<u8>,
    pub enc_headers: Vec<u8>,
    pub enc_body: Vec<u8>,
}

#[derive(Serialize)]
struct LocalPrekeyPriv<'a> {
    v: u8,
    id: &'a str,
    x_priv: &'a str,
    x_pub: &'a str,
    k_priv: &'a str,
    k_pub: &'a str,
    created_at_ms: u64,
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn drop_removed_json_key(map: &mut Map<String, Value>, key: &str) {
    if let Some(removed) = map.remove(key) {
        drop(SecretJson::from(removed));
    }
}

fn read_u16_be(b: &[u8], i: &mut usize) -> Result<usize> {
    if *i + 2 > b.len() {
        return Err(LithiumError::invalid_credentials("bad_wire"));
    }
    let v = u16::from_be_bytes([b[*i], b[*i + 1]]) as usize;
    *i += 2;
    Ok(v)
}

fn read_u32_be(b: &[u8], i: &mut usize) -> Result<usize> {
    if *i + 4 > b.len() {
        return Err(LithiumError::invalid_credentials("bad_wire"));
    }
    let v = u32::from_be_bytes([b[*i], b[*i + 1], b[*i + 2], b[*i + 3]]) as usize;
    *i += 4;
    Ok(v)
}

fn take_bytes<'a>(b: &'a [u8], i: &mut usize, n: usize) -> Result<&'a [u8]> {
    if *i + n > b.len() {
        return Err(LithiumError::invalid_credentials("bad_wire"));
    }
    let out = &b[*i..*i + n];
    *i += n;
    Ok(out)
}

pub fn pack_wire(w: &WireV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        3 + 1 + 32 + 32 + 2 + w.seed.len() + 4 + w.enc_headers.len() + 4 + w.enc_body.len(),
    );
    out.extend_from_slice(MAGIC);
    out.push(VER);
    out.extend_from_slice(&w.to_id);
    out.extend_from_slice(&w.from_x_pub);

    out.extend_from_slice(&(w.seed.len() as u16).to_be_bytes());
    out.extend_from_slice(&w.seed);

    out.extend_from_slice(&(w.enc_headers.len() as u32).to_be_bytes());
    out.extend_from_slice(&w.enc_headers);

    out.extend_from_slice(&(w.enc_body.len() as u32).to_be_bytes());
    out.extend_from_slice(&w.enc_body);

    out
}

pub fn unpack_wire(b: &[u8]) -> Result<WireV1> {
    if b.len() < 3 + 1 + 32 + 32 + 2 + 4 + 4 {
        return Err(LithiumError::invalid_credentials("bad_wire"));
    }
    if &b[..3] != MAGIC || b[3] != VER {
        return Err(LithiumError::invalid_credentials("bad_wire"));
    }

    let mut i = 4;

    let to_id_b = take_bytes(b, &mut i, 32)?;
    let mut to_id = [0u8; 32];
    to_id.copy_from_slice(to_id_b);

    let from_x_b = take_bytes(b, &mut i, 32)?;
    let mut from_x_pub = [0u8; 32];
    from_x_pub.copy_from_slice(from_x_b);

    let seed_len = read_u16_be(b, &mut i)?;
    let seed = take_bytes(b, &mut i, seed_len)?.to_vec();

    let hdr_len = read_u32_be(b, &mut i)?;
    let enc_headers = take_bytes(b, &mut i, hdr_len)?.to_vec();

    let body_len = read_u32_be(b, &mut i)?;
    let enc_body = take_bytes(b, &mut i, body_len)?.to_vec();

    Ok(WireV1 {
        to_id,
        from_x_pub,
        seed,
        enc_headers,
        enc_body,
    })
}

fn id_from_peer_pubs(peer_x_pub_hex: &str, peer_k_pub_hex: &str) -> Result<[u8; 32]> {
    let x = Byte32::from_hex(peer_x_pub_hex.trim())?;
    let k = SecretBytes::from_hex(peer_k_pub_hex.trim())?;

    let mut inb = Vec::with_capacity(32 + k.len());
    inb.extend_from_slice(x.as_slice());
    inb.extend_from_slice(k.as_slice());

    let id = kdf::derive32(
        &SecretBytes::from_vec(inb),
        None,
        &SecretBytes::from_slice(KID_LABEL),
    )?;

    Ok(*id.as_array())
}

fn merge_remote_prekeys_into_peer(peer_v: &mut Value, incoming: &[Value], max_keep: usize) {
    if peer_v.get("prekeys_remote").is_none() {
        peer_v["prekeys_remote"] = json!([]);
    }

    let Some(arr) = peer_v.get_mut("prekeys_remote").and_then(|v| v.as_array_mut()) else {
        return;
    };

    for item in incoming {
        let Some(id) = item.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let exists = arr.iter().any(|v| v.get("id").and_then(|x| x.as_str()) == Some(id));
        if exists {
            continue;
        }

        let x_pub = item.get("x_pub").and_then(|v| v.as_str()).unwrap_or("");
        let k_pub = item.get("k_pub").and_then(|v| v.as_str()).unwrap_or("");
        if x_pub.is_empty() || k_pub.is_empty() {
            continue;
        }

        arr.push(json!({
            "id": id,
            "x_pub": x_pub,
            "k_pub": k_pub,
            "seen_at_ms": now_ms()
        }));
    }

    while arr.len() > max_keep {
        arr.remove(0);
    }
}

fn maybe_drop_bootstrap_private(self_v: &mut SecretJson, peer_v: &SecretJson) {
    let peer_established = peer_v.with_exposed(|peer_v| peer_v.get("e2e_peer").is_some());

    let retire_ok = self_v.with_exposed(|self_v| {
        let ack_seq = self_v
            .get("e2e_rx")
            .and_then(|v| v.get("ack_seq"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let marked = self_v
            .get("bootstrap")
            .and_then(|v| v.get("retire_ok"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        ack_seq > 0 || marked
    });

    if !(peer_established && retire_ok) {
        return;
    }

    self_v.with_exposed_mut(|self_v| {
        if self_v.get("bootstrap").is_none() || !self_v["bootstrap"].is_object() {
            self_v["bootstrap"] = json!({});
        }

        if let Some(obj) = self_v.as_object_mut() {
            drop_removed_json_key(obj, "x_priv");
            drop_removed_json_key(obj, "k_priv");
        }

        self_v["bootstrap"]["rx_used"] = json!(true);
        self_v["bootstrap"]["retire_ok"] = json!(true);
        self_v["bootstrap"]["retired_at_ms"] = json!(now_ms());
    });
}

pub fn drop_bootstrap_private_if_established(self_v: &mut SecretJson, peer_v: &SecretJson) {
    maybe_drop_bootstrap_private(self_v, peer_v);
}

pub fn mark_bootstrap_retire_ready(self_v: &mut SecretJson) {
    self_v.with_exposed_mut(|self_v| {
        if self_v.get("bootstrap").is_none() || !self_v["bootstrap"].is_object() {
            self_v["bootstrap"] = json!({});
        }
        self_v["bootstrap"]["retire_ok"] = json!(true);
    });
}

fn malicious_message_err() -> LithiumError {
    LithiumError::invalid_credentials("potentially_harmful_message")
}

fn json_get_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

fn get_self_identity_privs(self_v: &SecretJson) -> Result<(Byte32, SecretBytes)> {
    self_v.with_exposed(|self_v| {
        let ed_priv_hex = self_v
            .get("ed_priv")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("ed_priv"))?;

        let dili_priv_hex = self_v
            .get("dili_priv")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("dili_priv"))?;

        Ok((
            Byte32::from_hex(ed_priv_hex.trim())?,
            SecretBytes::from_hex(dili_priv_hex.trim())?,
        ))
    })
}

fn get_peer_identity_pubs(peer_v: &Value) -> Result<(Byte32, SecretBytes)> {
    let peer_obj = peer_v.get("peer").filter(|v| v.is_object()).unwrap_or(peer_v);

    let ed_pub_hex = json_get_str(peer_obj, "ed_pub")
        .ok_or_else(|| LithiumError::json_missing_field("ed_pub"))?;

    let dili_pub_hex = json_get_str(peer_obj, "dili_pub")
        .ok_or_else(|| LithiumError::json_missing_field("dili_pub"))?;

    Ok((
        Byte32::from_hex(ed_pub_hex.trim())?,
        SecretBytes::from_hex(dili_pub_hex.trim())?,
    ))
}

fn build_sig_input(
    to_id: &[u8; 32],
    from_x_pub: &[u8; 32],
    hdr_unsigned: &[u8],
    pt_body: &[u8],
) -> SecretBytes {
    let mut out = SecretBytes::new(Vec::with_capacity(
        E2E_SIG_LABEL.len() + 32 + 32 + 4 + hdr_unsigned.len() + 4 + pt_body.len(),
    ));

    out.as_mut_vec().extend_from_slice(E2E_SIG_LABEL);
    out.as_mut_vec().extend_from_slice(to_id);
    out.as_mut_vec().extend_from_slice(from_x_pub);
    out.as_mut_vec()
        .extend_from_slice(&(hdr_unsigned.len() as u32).to_be_bytes());
    out.as_mut_vec().extend_from_slice(hdr_unsigned);
    out.as_mut_vec()
        .extend_from_slice(&(pt_body.len() as u32).to_be_bytes());
    out.as_mut_vec().extend_from_slice(pt_body);

    out
}

fn sign_e2e_payload(
    self_v: &SecretJson,
    to_id: &[u8; 32],
    from_x_pub: &[u8; 32],
    hdr_unsigned: &[u8],
    pt_body: &[u8],
) -> Result<(String, String)> {
    let (ed_priv, dili_priv) = get_self_identity_privs(self_v)?;
    let sig_input = build_sig_input(to_id, from_x_pub, hdr_unsigned, pt_body);

    let sig_ed = sign::sign_message(sig_input.as_slice(), ed_priv.as_slice())?;
    let sig_dili = sign::sign_message_dili(sig_input.as_slice(), dili_priv.as_slice())?;

    Ok((
        sig_ed.to_hex().expose().to_owned(),
        sig_dili.to_hex().expose().to_owned(),
    ))
}

fn signed_header_parts(hdr_v: &Value) -> Result<(Vec<u8>, String, String)> {
    let v = hdr_v
        .get("v")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("v"))?;
    let mode = hdr_v
        .get("mode")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("mode"))?;
    let ts_ms = hdr_v
        .get("ts_ms")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("ts_ms"))?;
    let msg_id = hdr_v
        .get("msg_id")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("msg_id"))?;
    let kind = hdr_v
        .get("kind")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("kind"))?;
    let step = hdr_v
        .get("step")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("step"))?;
    let mbox_gen = hdr_v
        .get("mbox_gen")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("mbox_gen"))?;
    let mailbox = hdr_v
        .get("mailbox")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("mailbox"))?;
    let reply = hdr_v
        .get("reply")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("reply"))?;
    let prekeys = hdr_v
        .get("prekeys")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("prekeys"))?;

    let auth = hdr_v
        .get("auth")
        .and_then(|v| v.as_object())
        .ok_or_else(|| LithiumError::json_missing_field("auth"))?;

    let sig_ed = auth
        .get("sig_ed")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("auth.sig_ed"))?
        .to_string();

    let sig_dili = auth
        .get("sig_dili")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("auth.sig_dili"))?
        .to_string();

    let hdr_unsigned = serde_json::to_vec(&json!({
        "v": v,
        "mode": mode,
        "ts_ms": ts_ms,
        "msg_id": msg_id,
        "kind": kind,
        "step": step,
        "mbox_gen": mbox_gen,
        "mailbox": mailbox,
        "reply": reply,
        "prekeys": prekeys
    }))
        .map_err(LithiumError::json_parse)?;

    Ok((hdr_unsigned, sig_ed, sig_dili))
}

fn verify_e2e_payload(
    peer_v: &Value,
    to_id: &[u8; 32],
    from_x_pub: &[u8; 32],
    hdr_unsigned: &[u8],
    pt_body: &[u8],
    sig_ed_hex: &str,
    sig_dili_hex: &str,
) -> Result<()> {
    let (ed_pub, dili_pub) = get_peer_identity_pubs(peer_v)?;
    let sig_input = build_sig_input(to_id, from_x_pub, hdr_unsigned, pt_body);

    let sig_ed = SecretBytes::from_hex(sig_ed_hex.trim())
        .map_err(|_| LithiumError::invalid_credentials("bad_sig_ed_hex"))?;
    let sig_dili = SecretBytes::from_hex(sig_dili_hex.trim())
        .map_err(|_| LithiumError::invalid_credentials("bad_sig_dili_hex"))?;

    if !sign::verify_signature(sig_input.as_slice(), sig_ed.as_slice(), &ed_pub) {
        return Err(malicious_message_err());
    }

    if !sign::verify_signature_dili(sig_input.as_slice(), sig_dili.as_slice(), &dili_pub) {
        return Err(malicious_message_err());
    }

    Ok(())
}

fn decrypt_with_privs(
    peer_v: &mut Value,
    w: &WireV1,
    rx_x_priv: &Byte32,
    rx_k_priv: &SecretBytes,
) -> Result<(Vec<u8>, Value)> {
    let from_x_pub = Byte32::from_slice(&w.from_x_pub)?;
    let seed = SecretBytes::from_vec(w.seed.clone());
    let data = SecretBytes::from_vec(w.enc_headers.clone());
    let body = SecretBytes::from_vec(w.enc_body.clone());

    let (pt_body, pt_headers) = kyberbox::decrypt(
        E2E_LABEL,
        rx_x_priv,
        &from_x_pub,
        rx_k_priv,
        &kyberbox::WirePayload {
            enc_body: body,
            enc_headers: data,
            seed_enc: seed,
        },
    )?;

    let hdr_v: Value =
        serde_json::from_slice(pt_headers.as_slice()).map_err(LithiumError::json_parse)?;

    let (hdr_unsigned, sig_ed_hex, sig_dili_hex) =
        signed_header_parts(&hdr_v).map_err(|_| malicious_message_err())?;

    verify_e2e_payload(
        peer_v,
        &w.to_id,
        &w.from_x_pub,
        &hdr_unsigned,
        pt_body.as_slice(),
        &sig_ed_hex,
        &sig_dili_hex,
    )?;

    if let Some(arr) = hdr_v.get("prekeys").and_then(|v| v.as_array()) {
        merge_remote_prekeys_into_peer(peer_v, arr, PREKEY_TARGET);
    }

    let mode = hdr_v.get("mode").and_then(|v| v.as_str()).unwrap_or("ratchet");
    let step_in = hdr_v.get("step").and_then(|v| v.as_u64()).unwrap_or(0);
    let mailbox_gen = hdr_v
        .get("mbox_gen")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    if let Some(mailbox_obj) = hdr_v.get("mailbox").and_then(|v| v.as_object()) {
        let cur_pub = mailbox_obj
            .get("sender_cur_x_pub")
            .and_then(|v| v.as_str());
        let next_pub = mailbox_obj
            .get("sender_next_x_pub")
            .and_then(|v| v.as_str());

        if let (Some(cur), Some(next)) = (cur_pub, next_pub) {
            peer_store_mailbox_sender_keys(peer_v, mailbox_gen, cur, next);
        }
    }

    let peer_step_cur = peer_v["e2e_peer"]["step"].as_u64().unwrap_or(0);

    if step_in > peer_step_cur {
        let reply = hdr_v
            .get("reply")
            .ok_or_else(|| LithiumError::json_missing_field("reply"))?;
        let reply_id_hex = reply
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("reply.id"))?;
        let reply_x_pub = reply
            .get("x_pub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("reply.x_pub"))?;
        let reply_k_pub = reply
            .get("k_pub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("reply.k_pub"))?;

        let reply_id = Byte32::from_hex(reply_id_hex.trim())?;
        peer_v["e2e_peer"] = json!({
            "id": reply_id.to_hex().expose(),
            "x_pub": reply_x_pub,
            "k_pub": reply_k_pub,
            "step": step_in,
            "updated_at_ms": now_ms()
        });
    }

    peer_v["need_recover"] = json!(false);

    let ts_ms = hdr_v.get("ts_ms").and_then(|v| v.as_u64()).unwrap_or(0);
    let msg_id = hdr_v
        .get("msg_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let kind = hdr_v
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok((
        pt_body.as_slice().to_vec(),
        json!({
            "ts_ms": ts_ms,
            "msg_id": msg_id,
            "kind": kind,
            "step": step_in,
            "mode": mode,
            "mailbox_gen": mailbox_gen
        }),
    ))
}

pub fn ensure_self_keyring(self_v: &mut SecretJson) -> Result<()> {
    self_v.with_exposed_mut(|self_v| {
        if self_v.get("e2e_tx").is_none() {
            self_v["e2e_tx"] = json!({ "step": 0u64 });
        }

        let had_e2e_rx = self_v.get("e2e_rx").is_some();

        if self_v.get("bootstrap").is_none() || !self_v["bootstrap"].is_object() {
            self_v["bootstrap"] = json!({
                "rx_used": false,
                "retire_ok": false
            });
        } else {
            if self_v["bootstrap"].get("rx_used").is_none() {
                self_v["bootstrap"]["rx_used"] = json!(false);
            }
            if self_v["bootstrap"].get("retire_ok").is_none() {
                self_v["bootstrap"]["retire_ok"] = json!(false);
            }
        }

        if self_v.get("e2e_rx").is_some() {
            if self_v["e2e_rx"].get("window").is_none() {
                self_v["e2e_rx"]["window"] = json!(DEFAULT_WINDOW);
            }
            if self_v["e2e_rx"].get("ack_seq").is_none() {
                self_v["e2e_rx"]["ack_seq"] = json!(0u64);
            }
            if self_v["e2e_rx"].get("next_seq").is_none() {
                self_v["e2e_rx"]["next_seq"] = json!(1u64);
            }
            if self_v["e2e_rx"].get("keys").is_none() {
                self_v["e2e_rx"]["keys"] = json!({});
            }
            if self_v["e2e_rx"].get("active").is_none() {
                self_v["e2e_rx"]["active"] = json!("");
            }
        } else {
            self_v["e2e_rx"] = json!({
                "active": "",
                "ack_seq": 0u64,
                "next_seq": 1u64,
                "window": DEFAULT_WINDOW,
                "keys": {}
            });
        }

        let x_pub = self_v
            .get("x_pub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("x_pub"))?
            .to_string();
        let k_pub = self_v
            .get("k_pub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("k_pub"))?
            .to_string();

        let bootstrap_id_hex = hex::encode(id_from_peer_pubs(&x_pub, &k_pub)?);

        if let Some(keys) = self_v["e2e_rx"].get_mut("keys").and_then(|v| v.as_object_mut()) {
            let remove_bootstrap = keys
                .get(&bootstrap_id_hex)
                .and_then(|v| v.get("seq"))
                .and_then(|v| v.as_u64())
                == Some(0);

            if remove_bootstrap {
                drop_removed_json_key(keys, &bootstrap_id_hex);
            }
        }

        if self_v["e2e_rx"]
            .get("active")
            .and_then(|v| v.as_str())
            == Some(bootstrap_id_hex.as_str())
        {
            self_v["e2e_rx"]["active"] = json!("");
        }

        if self_v.get("prekeys_local_public").is_none() {
            self_v["prekeys_local_public"] = json!([]);
        }
        if self_v.get("prekeys_advertised").is_none() {
            self_v["prekeys_advertised"] = json!(false);
        }

        Ok(())
    })
}

fn self_bootstrap_rx_privs(
    self_v: &SecretJson,
    to_id: &[u8; 32],
) -> Option<(Byte32, SecretBytes)> {
    self_v.with_exposed(|self_v| {
        let x_pub_hex = self_v.get("x_pub")?.as_str()?;
        let k_pub_hex = self_v.get("k_pub")?.as_str()?;
        let bootstrap_id = id_from_peer_pubs(x_pub_hex, k_pub_hex).ok()?;

        if &bootstrap_id != to_id {
            return None;
        }

        let x_priv_hex = self_v.get("x_priv")?.as_str()?;
        let k_priv_hex = self_v.get("k_priv")?.as_str()?;

        let x_priv = Byte32::from_hex(x_priv_hex.trim()).ok()?;
        let k_priv = SecretBytes::from_hex(k_priv_hex.trim()).ok()?;

        Some((x_priv, k_priv))
    })
}

pub fn ensure_peer_e2e(peer_v: &mut SecretJson) -> Result<([u8; 32], String, String, u64)> {
    peer_v.with_exposed_mut(|peer_v| {
        let had_e2e = peer_v.get("e2e_peer").is_some();

        if peer_v.get("bootstrap").is_none() || !peer_v["bootstrap"].is_object() {
            peer_v["bootstrap"] = json!({
                "tx_used": had_e2e
            });
        } else if peer_v["bootstrap"].get("tx_used").is_none() {
            peer_v["bootstrap"]["tx_used"] = json!(had_e2e);
        }

        if let Some(e2e) = peer_v.get("e2e_peer") {
            let id_hex = e2e
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let x_pub = e2e
                .get("x_pub")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let k_pub = e2e
                .get("k_pub")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let step = e2e.get("step").and_then(|v| v.as_u64()).unwrap_or(0);

            if !id_hex.is_empty() && !x_pub.is_empty() && !k_pub.is_empty() {
                let id = Byte32::from_hex(id_hex.trim())?;
                return Ok((*id.as_array(), x_pub, k_pub, step));
            }
        }

        Err(LithiumError::invalid_credentials("e2e_peer_not_set"))
    })
}

fn peer_bootstrap_target(peer_v: &SecretJson) -> Option<([u8; 32], String, String)> {
    peer_v.with_exposed(|peer_v| {
        if peer_v.get("e2e_peer").is_some() {
            return None;
        }

        let peer_obj = peer_v.get("peer")?;
        if peer_obj.is_null() {
            return None;
        }

        let x_pub = peer_obj.get("x_pub")?.as_str()?.to_string();
        let k_pub = peer_obj.get("k_pub")?.as_str()?.to_string();
        let id = id_from_peer_pubs(&x_pub, &k_pub).ok()?;

        Some((id, x_pub, k_pub))
    })
}

pub fn peer_need_recover(peer_v: &SecretJson) -> bool {
    peer_v.with_exposed(|peer_v| {
        peer_v
            .get("need_recover")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    })
}

pub fn peer_set_need_recover(peer_v: &mut SecretJson, v: bool) {
    peer_v.with_exposed_mut(|peer_v| {
        peer_v["need_recover"] = json!(v);
    });
}

pub fn peer_pick_remote_prekey(peer_v: &SecretJson) -> Option<(String, String, String)> {
    peer_v.with_exposed(|peer_v| {
        let arr = peer_v.get("prekeys_remote")?.as_array()?;
        let pk = arr.first()?.as_object()?;
        let id = pk.get("id")?.as_str()?.to_string();
        let x_pub = pk.get("x_pub")?.as_str()?.to_string();
        let k_pub = pk.get("k_pub")?.as_str()?.to_string();
        Some((id, x_pub, k_pub))
    })
}

pub fn peer_remove_remote_prekey(peer_v: &mut SecretJson, id_hex: &str) {
    peer_v.with_exposed_mut(|peer_v| {
        let Some(arr) = peer_v
            .get_mut("prekeys_remote")
            .and_then(|v| v.as_array_mut())
        else {
            return;
        };
        arr.retain(|v| v.get("id").and_then(|x| x.as_str()) != Some(id_hex));
    });
}

pub fn prekeys_should_advertise(self_v: &SecretJson) -> bool {
    self_v.with_exposed(|self_v| {
        !self_v
            .get("prekeys_advertised")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    })
}

pub fn prekeys_mark_advertised(self_v: &mut SecretJson) {
    self_v.with_exposed_mut(|self_v| {
        self_v["prekeys_advertised"] = json!(true);
    });
}

pub fn local_public_prekeys(self_v: &SecretJson) -> Vec<Value> {
    self_v.with_exposed(|self_v| {
        self_v
            .get("prekeys_local_public")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
    })
}

pub fn local_remove_public_prekey(self_v: &mut SecretJson, id_hex: &str) {
    self_v.with_exposed_mut(|self_v| {
        let Some(arr) = self_v
            .get_mut("prekeys_local_public")
            .and_then(|v| v.as_array_mut())
        else {
            return;
        };
        arr.retain(|v| v.get("id").and_then(|x| x.as_str()) != Some(id_hex));
        self_v["prekeys_advertised"] = json!(false);
    });
}

pub fn gen_local_prekey_material() -> Result<(String, SecretBytes, Value)> {
    let id = keys::random_32()?;
    let id_hex = id.to_hex();

    let (x_priv_fb, x_pub_fb) = keys::random_x25519_keypair()?;
    let x_priv_hex = x_priv_fb.to_hex();
    let x_pub_hex = x_pub_fb.to_hex();

    let (k_priv, k_pub) = keys::random_kyber_mlkem1024_keypair()?;
    let k_priv_hex = k_priv.to_hex();
    let k_pub_hex = k_pub.to_hex();

    let created_at_ms = now_ms();

    let priv_state = LocalPrekeyPriv {
        v: 1,
        id: id_hex.expose(),
        x_priv: x_priv_hex.expose(),
        x_pub: x_pub_hex.expose(),
        k_priv: k_priv_hex.expose(),
        k_pub: k_pub_hex.expose(),
        created_at_ms,
    };

    let priv_blob = {
        let mut out = SecretBytes::new(Vec::new());
        serde_json::to_writer(out.as_mut_vec(), &priv_state).map_err(LithiumError::json_parse)?;
        out
    };

    let public_item = json!({
        "id": id_hex.expose(),
        "x_pub": x_pub_hex.expose(),
        "k_pub": k_pub_hex.expose(),
        "created_at_ms": created_at_ms
    });

    Ok((id_hex.expose().to_owned(), priv_blob, public_item))
}

pub fn prekey_blob_to_privs(blob: &SecretBytes) -> Result<(Byte32, SecretBytes)> {
    let v = SecretJson::from_bytes(blob.as_slice())?;

    v.with_exposed(|v| -> Result<(Byte32, SecretBytes)> {
        let x_priv_hex = v
            .get("x_priv")
            .and_then(|x| x.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("x_priv"))?;
        let k_priv_hex = v
            .get("k_priv")
            .and_then(|x| x.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("k_priv"))?;

        Ok((
            Byte32::from_hex(x_priv_hex.trim())?,
            SecretBytes::from_hex(k_priv_hex.trim())?,
        ))
    })
}

fn self_next_seq(self_v: &mut SecretJson) -> u64 {
    self_v.with_exposed_mut(|self_v| {
        let n = self_v["e2e_rx"]["next_seq"].as_u64().unwrap_or(1);
        self_v["e2e_rx"]["next_seq"] = json!(n + 1);
        n
    })
}

fn self_find_seq(self_v: &SecretJson, to_id: &[u8; 32]) -> Option<u64> {
    self_v.with_exposed(|self_v| {
        let id_hex = hex::encode(to_id);
        let keys = self_v.get("e2e_rx")?.get("keys")?.as_object()?;
        let item = keys.get(&id_hex)?.as_object()?;
        item.get("seq")?.as_u64()
    })
}

fn self_get_rx_privs(self_v: &SecretJson, to_id: &[u8; 32]) -> Option<(Byte32, SecretBytes)> {
    self_v.with_exposed(|self_v| {
        let id_hex = hex::encode(to_id);
        let keys = self_v.get("e2e_rx")?.get("keys")?.as_object()?;
        let item = keys.get(&id_hex)?.as_object()?;

        let x_priv_hex = item.get("x_priv")?.as_str()?;
        let k_priv_hex = item.get("k_priv")?.as_str()?;

        Some((
            Byte32::from_hex(x_priv_hex.trim()).ok()?,
            SecretBytes::from_hex(k_priv_hex.trim()).ok()?,
        ))
    })
}

fn gc_after_ack(self_v: &mut SecretJson) {
    self_v.with_exposed_mut(|self_v| {
        let window = self_v["e2e_rx"]["window"].as_u64().unwrap_or(DEFAULT_WINDOW);
        let ack = self_v["e2e_rx"]["ack_seq"].as_u64().unwrap_or(0);
        let min_keep_seq = ack.saturating_sub(window);

        let mut remove: Vec<String> = Vec::new();

        if let Some(keys) = self_v["e2e_rx"]["keys"].as_object() {
            for (k, v) in keys.iter() {
                let seq = v.get("seq").and_then(|x| x.as_u64()).unwrap_or(0);
                if seq == 0 {
                    continue;
                }
                if seq < min_keep_seq {
                    remove.push(k.clone());
                }
            }
        }

        if let Some(keys) = self_v["e2e_rx"]["keys"].as_object_mut() {
            for k in remove {
                drop_removed_json_key(keys, &k);
            }
        }
    });
}

fn next_tx_step(self_v: &mut SecretJson) -> u64 {
    self_v.with_exposed_mut(|self_v| {
        let step = self_v["e2e_tx"]["step"].as_u64().unwrap_or(0) + 1;
        self_v["e2e_tx"]["step"] = json!(step);
        step
    })
}

pub fn encrypt_for_peer(
    self_v: &mut SecretJson,
    peer_v: &mut SecretJson,
    plaintext: &[u8],
    kind: &str,
    prekeys_advertise: &[Value],
    use_recovery: bool,
    mailbox_gen: u64,
) -> Result<(WireV1, Value)> {
    ensure_self_keyring(self_v)?;

    let step = next_tx_step(self_v);

    let (target_id, target_x_pub_hex, target_k_pub_hex, mode) = if use_recovery {
        let Some((id_hex, x_pub, k_pub)) = peer_pick_remote_prekey(peer_v) else {
            return Err(LithiumError::invalid_credentials("no_remote_prekey"));
        };
        let id = Byte32::from_hex(id_hex.trim())?;
        (*id.as_array(), x_pub, k_pub, "prekey_recover")
    } else if let Ok((id, x_pub, k_pub, _st)) = ensure_peer_e2e(peer_v) {
        (id, x_pub, k_pub, "ratchet")
    } else if let Some((id, x_pub, k_pub)) = peer_bootstrap_target(peer_v) {
        (id, x_pub, k_pub, "bootstrap")
    } else {
        return Err(LithiumError::invalid_credentials("need_reply_or_prekey"));
    };

    let target_x_pub = Byte32::from_hex(target_x_pub_hex.trim())?;
    let target_k_pub = SecretBytes::from_hex(target_k_pub_hex.trim())?;

    let reply_id = keys::random_32()?;
    let (rx_x_priv_fb, rx_x_pub_fb) = keys::random_x25519_keypair()?;
    let rx_x_priv_hex = rx_x_priv_fb.to_hex();
    let rx_x_pub_hex = rx_x_pub_fb.to_hex();

    let (rx_k_priv, rx_k_pub) = keys::random_kyber_mlkem1024_keypair()?;
    let rx_k_priv_hex = rx_k_priv.to_hex();
    let rx_k_pub_hex = rx_k_pub.to_hex();

    let seq = self_next_seq(self_v);
    self_v.with_exposed_mut(|self_v| -> Result<()> {
        if self_v.get("e2e_rx").is_none() {
            self_v["e2e_rx"] = json!({
                "active": "",
                "ack_seq": 0u64,
                "next_seq": 1u64,
                "window": DEFAULT_WINDOW,
                "keys": {}
            });
        }

        let id_hex = reply_id.to_hex();
        self_v["e2e_rx"]["active"] = Value::String(id_hex.expose().to_owned());

        let keys = self_v["e2e_rx"]
            .get_mut("keys")
            .and_then(|v| v.as_object_mut())
            .ok_or_else(|| LithiumError::json_missing_field("e2e_rx.keys"))?;

        keys.insert(
            id_hex.expose().to_owned(),
            json!({
                "x_priv": rx_x_priv_hex.expose(),
                "x_pub": rx_x_pub_hex.expose(),
                "k_priv": rx_k_priv_hex.expose(),
                "k_pub": rx_k_pub_hex.expose(),
                "seq": seq,
                "created_at_ms": now_ms()
            }),
        );

        Ok(())
    })?;

    let (mailbox_sender_cur_x_pub, mailbox_sender_next_x_pub) = self_v
        .with_exposed(current_outbound_mailbox_pubs)
        .ok_or_else(|| LithiumError::json_missing_field("mbox_out_cur_pub"))?;

    let (msg_x_priv, msg_x_pub) = keys::random_x25519_keypair()?;
    let mut from_x_pub = [0u8; 32];
    from_x_pub.copy_from_slice(msg_x_pub.as_slice());

    let ts_ms = now_ms();
    let msg_id = keys::random_fixed::<16>()?.to_hex().expose().to_owned();

    let hdr_unsigned = json!({
        "v": 1,
        "mode": mode,
        "ts_ms": ts_ms,
        "msg_id": msg_id,
        "kind": kind,
        "step": step,
        "mbox_gen": mailbox_gen,
        "mailbox": {
            "sender_cur_x_pub": mailbox_sender_cur_x_pub,
            "sender_next_x_pub": mailbox_sender_next_x_pub
        },
        "reply": {
            "id": reply_id.to_hex().expose(),
            "x_pub": rx_x_pub_hex.expose(),
            "k_pub": rx_k_pub_hex.expose()
        },
        "prekeys": prekeys_advertise
    });

    let hdr_unsigned_bytes =
        serde_json::to_vec(&hdr_unsigned).map_err(LithiumError::json_parse)?;

    let (sig_ed, sig_dili) = sign_e2e_payload(
        self_v,
        &target_id,
        &from_x_pub,
        &hdr_unsigned_bytes,
        plaintext,
    )?;

    let hdr_plain = serde_json::to_vec(&json!({
        "v": 1,
        "mode": mode,
        "ts_ms": ts_ms,
        "msg_id": msg_id,
        "kind": kind,
        "step": step,
        "mbox_gen": mailbox_gen,
        "mailbox": {
            "sender_cur_x_pub": mailbox_sender_cur_x_pub,
            "sender_next_x_pub": mailbox_sender_next_x_pub
        },
        "reply": {
            "id": reply_id.to_hex().expose(),
            "x_pub": rx_x_pub_hex.expose(),
            "k_pub": rx_k_pub_hex.expose()
        },
        "prekeys": prekeys_advertise,
        "auth": {
            "sig_ed": sig_ed,
            "sig_dili": sig_dili
        }
    }))
        .map_err(LithiumError::json_parse)?;

    let wire = kyberbox::encrypt(
        E2E_LABEL,
        &msg_x_priv,
        &target_x_pub,
        &target_k_pub,
        &SecretBytes::from_slice(plaintext),
        &SecretBytes::from_vec(hdr_plain),
    )?;

    maybe_drop_bootstrap_private(self_v, peer_v);

    Ok((
        WireV1 {
            to_id: target_id,
            from_x_pub,
            seed: wire.seed_enc.as_slice().to_vec(),
            enc_headers: wire.enc_headers.as_slice().to_vec(),
            enc_body: wire.enc_body.as_slice().to_vec(),
        },
        json!({
            "ts_ms": ts_ms,
            "msg_id": msg_id,
            "step": step,
            "mode": mode,
            "mailbox_gen": mailbox_gen
        }),
    ))
}

pub fn decrypt_for_us(
    self_v: &mut SecretJson,
    peer_v: &mut SecretJson,
    w: &WireV1,
) -> Result<(Vec<u8>, Value)> {
    ensure_self_keyring(self_v)?;

    let mut used_ratchet_rx = false;

    let (pt, ui) = if let Some((rx_x_priv, rx_k_priv)) = self_get_rx_privs(self_v, &w.to_id) {
        used_ratchet_rx = true;
        peer_v.with_exposed_mut(|peer_v| decrypt_with_privs(peer_v, w, &rx_x_priv, &rx_k_priv))?
    } else if let Some((rx_x_priv, rx_k_priv)) = self_bootstrap_rx_privs(self_v, &w.to_id) {
        peer_v.with_exposed_mut(|peer_v| decrypt_with_privs(peer_v, w, &rx_x_priv, &rx_k_priv))?
    } else {
        return Err(LithiumError::invalid_credentials("to_id_unknown"));
    };

    if let Some(seq) = self_find_seq(self_v, &w.to_id) {
        self_v.with_exposed_mut(|self_v| {
            let ack = self_v["e2e_rx"]["ack_seq"].as_u64().unwrap_or(0);
            if seq > ack {
                self_v["e2e_rx"]["ack_seq"] = json!(seq);
            }
        });
        gc_after_ack(self_v);
    }

    if used_ratchet_rx {
        mark_bootstrap_retire_ready(self_v);
    }

    maybe_drop_bootstrap_private(self_v, peer_v);

    Ok((pt, ui))
}

pub fn decrypt_for_prekey(
    peer_v: &mut SecretJson,
    w: &WireV1,
    prekey_blob: &SecretBytes,
) -> Result<(Vec<u8>, Value)> {
    let (rx_x_priv, rx_k_priv) = prekey_blob_to_privs(prekey_blob)?;
    peer_v.with_exposed_mut(|peer_v| decrypt_with_privs(peer_v, w, &rx_x_priv, &rx_k_priv))
}
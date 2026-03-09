use lithium_core::{
    crypto::{kdf, keys, kyberbox},
    error::{LithiumError, Result},
    secrets::Byte32,
    secrets::bytes::SecretBytes,
};
use serde_json::{json, Value};

const MAGIC: &[u8; 3] = b"LM1";
const VER: u8 = 1;

const E2E_LABEL: &str = "lithiumd/e2e-msg/v1";
const KID_LABEL: &[u8] = b"lithiumd/e2e-peer-kid/v1";

pub const DEFAULT_WINDOW: u64 = 64;
pub const PREKEY_TARGET: usize = 5;

#[derive(Clone)]
pub struct WireV1 {
    pub to_id: [u8; 32],
    pub from_x_pub: [u8; 32],
    pub seed: Vec<u8>,
    pub enc_headers: Vec<u8>,
    pub enc_body: Vec<u8>,
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn rand32() -> Result<[u8; 32]> {
    let b = keys::random_32()?;
    Ok(*b.as_array())
}

fn rand16_hex() -> Result<String> {
    let b = keys::random_32()?;
    Ok(hex::encode(&b.as_slice()[..16]))
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

fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s.trim()).map_err(LithiumError::invalid_hex)?;
    if b.len() != 32 {
        return Err(LithiumError::invalid_len(32, b.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

fn id_from_peer_pubs(peer_x_pub_hex: &str, peer_k_pub_hex: &str) -> Result<[u8; 32]> {
    let x = hex::decode(peer_x_pub_hex.trim()).map_err(LithiumError::invalid_hex)?;
    let k = hex::decode(peer_k_pub_hex.trim()).map_err(LithiumError::invalid_hex)?;
    if x.len() != 32 {
        return Err(LithiumError::invalid_len(32, x.len()));
    }

    let mut inb = Vec::with_capacity(32 + k.len());
    inb.extend_from_slice(&x);
    inb.extend_from_slice(&k);

    let id = kdf::derive32(
        &SecretBytes::from_vec(inb),
        None,
        &SecretBytes::from_slice(KID_LABEL),
    )?;

    Ok(*id.as_array())
}

pub fn ensure_self_keyring(self_v: &mut Value) -> Result<()> {
    if self_v.get("e2e_tx").is_none() {
        self_v["e2e_tx"] = json!({ "step": 0u64 });
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
    } else {
        let x_priv = self_v
            .get("x_priv")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("x_priv"))?
            .to_string();
        let x_pub = self_v
            .get("x_pub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("x_pub"))?
            .to_string();
        let k_priv = self_v
            .get("k_priv")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("k_priv"))?
            .to_string();
        let k_pub = self_v
            .get("k_pub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("k_pub"))?
            .to_string();

        let base_id = id_from_peer_pubs(&x_pub, &k_pub)?;
        let base_id_hex = hex::encode(base_id);

        self_v["e2e_rx"] = json!({
            "active": base_id_hex.clone(),
            "ack_seq": 0u64,
            "next_seq": 1u64,
            "window": DEFAULT_WINDOW,
            "keys": {
                base_id_hex.clone(): {
                    "x_priv": x_priv,
                    "x_pub": x_pub,
                    "k_priv": k_priv,
                    "k_pub": k_pub,
                    "seq": 0u64,
                    "created_at_ms": now_ms()
                }
            }
        });
    }

    if self_v.get("prekeys_local_public").is_none() {
        self_v["prekeys_local_public"] = json!([]);
    }
    if self_v.get("prekeys_advertised").is_none() {
        self_v["prekeys_advertised"] = json!(false);
    }

    Ok(())
}

pub fn ensure_peer_e2e(peer_v: &mut Value) -> Result<([u8; 32], String, String, u64)> {
    if let Some(e2e) = peer_v.get("e2e_peer") {
        let id_hex = e2e.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let x_pub = e2e.get("x_pub").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let k_pub = e2e.get("k_pub").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let step = e2e.get("step").and_then(|v| v.as_u64()).unwrap_or(0);
        if !id_hex.is_empty() && !x_pub.is_empty() && !k_pub.is_empty() {
            let id = hex_to_32(&id_hex)?;
            return Ok((id, x_pub, k_pub, step));
        }
    }

    let peer_obj = peer_v.get("peer").ok_or_else(|| LithiumError::json_missing_field("peer"))?;
    if peer_obj.is_null() {
        return Err(LithiumError::invalid_credentials("peer_not_set"));
    }

    let x_pub = peer_obj
        .get("x_pub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("peer.x_pub"))?
        .to_string();

    let k_pub = peer_obj
        .get("k_pub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("peer.k_pub"))?
        .to_string();

    let id = id_from_peer_pubs(&x_pub, &k_pub)?;
    peer_v["e2e_peer"] = json!({
        "id": hex::encode(id),
        "x_pub": x_pub,
        "k_pub": k_pub,
        "step": 0u64,
        "updated_at_ms": now_ms()
    });

    let e2e = peer_v.get("e2e_peer").unwrap();
    let id = hex_to_32(e2e["id"].as_str().unwrap_or(""))?;
    Ok((
        id,
        e2e["x_pub"].as_str().unwrap_or("").to_string(),
        e2e["k_pub"].as_str().unwrap_or("").to_string(),
        e2e["step"].as_u64().unwrap_or(0),
    ))
}

pub fn peer_need_recover(peer_v: &Value) -> bool {
    peer_v.get("need_recover").and_then(|v| v.as_bool()).unwrap_or(false)
}

pub fn peer_set_need_recover(peer_v: &mut Value, v: bool) {
    peer_v["need_recover"] = json!(v);
}

pub fn peer_pick_remote_prekey(peer_v: &Value) -> Option<(String, String, String)> {
    let arr = peer_v.get("prekeys_remote")?.as_array()?;
    let pk = arr.first()?.as_object()?;
    let id = pk.get("id")?.as_str()?.to_string();
    let x_pub = pk.get("x_pub")?.as_str()?.to_string();
    let k_pub = pk.get("k_pub")?.as_str()?.to_string();
    Some((id, x_pub, k_pub))
}

pub fn peer_remove_remote_prekey(peer_v: &mut Value, id_hex: &str) {
    let Some(arr) = peer_v.get_mut("prekeys_remote").and_then(|v| v.as_array_mut()) else {
        return;
    };
    arr.retain(|v| v.get("id").and_then(|x| x.as_str()) != Some(id_hex));
}

pub fn peer_merge_remote_prekeys(peer_v: &mut Value, incoming: &[Value], max_keep: usize) {
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

pub fn prekeys_should_advertise(self_v: &Value) -> bool {
    !self_v
        .get("prekeys_advertised")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

pub fn prekeys_mark_advertised(self_v: &mut Value) {
    self_v["prekeys_advertised"] = json!(true);
}

pub fn prekeys_mark_dirty(self_v: &mut Value) {
    self_v["prekeys_advertised"] = json!(false);
}

pub fn local_public_prekeys(self_v: &Value) -> Vec<Value> {
    self_v
        .get("prekeys_local_public")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

pub fn local_remove_public_prekey(self_v: &mut Value, id_hex: &str) {
    let Some(arr) = self_v.get_mut("prekeys_local_public").and_then(|v| v.as_array_mut()) else {
        return;
    };
    arr.retain(|v| v.get("id").and_then(|x| x.as_str()) != Some(id_hex));
    prekeys_mark_dirty(self_v);
}

pub fn gen_local_prekey_material() -> Result<(String, SecretBytes, Value)> {
    let id = rand32()?;
    let id_hex = hex::encode(id);

    let (x_priv_fb, x_pub_fb) = keys::random_x25519_keypair()?;
    let x_priv_hex = hex::encode(x_priv_fb.as_slice());
    let x_pub_hex = hex::encode(x_pub_fb.as_slice());

    let (k_priv, k_pub) = keys::random_kyber_mlkem1024_keypair()?;
    let k_priv_hex = k_priv.to_hex();
    let k_pub_hex = k_pub.to_hex();

    let priv_blob = serde_json::to_vec(&json!({
        "v": 1,
        "id": id_hex,
        "x_priv": x_priv_hex,
        "x_pub": x_pub_hex,
        "k_priv": k_priv_hex.expose(),
        "k_pub": k_pub_hex.expose(),
        "created_at_ms": now_ms()
    }))
        .map_err(LithiumError::json_parse)?;

    let public_item = json!({
        "id": hex::encode(id),
        "x_pub": x_pub_hex,
        "k_pub": k_pub_hex.expose(),
        "created_at_ms": now_ms()
    });

    Ok((hex::encode(id), SecretBytes::from_vec(priv_blob), public_item))
}

pub fn prekey_blob_to_privs(blob: &SecretBytes) -> Result<(Byte32, SecretBytes)> {
    let v: Value = serde_json::from_slice(blob.as_slice()).map_err(LithiumError::json_parse)?;
    let x_priv_hex = v
        .get("x_priv")
        .and_then(|x| x.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("x_priv"))?;
    let k_priv_hex = v
        .get("k_priv")
        .and_then(|x| x.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("k_priv"))?;

    let x_priv = Byte32::from_slice(&hex_to_32(x_priv_hex)?)?;
    let k_priv = SecretBytes::from_vec(hex::decode(k_priv_hex.trim()).map_err(LithiumError::invalid_hex)?);

    Ok((x_priv, k_priv))
}

fn self_next_seq(self_v: &mut Value) -> u64 {
    let n = self_v["e2e_rx"]["next_seq"].as_u64().unwrap_or(1);
    self_v["e2e_rx"]["next_seq"] = json!(n + 1);
    n
}

fn self_find_seq(self_v: &Value, to_id: &[u8; 32]) -> Option<u64> {
    let id_hex = hex::encode(to_id);
    let keys = self_v.get("e2e_rx")?.get("keys")?.as_object()?;
    let item = keys.get(&id_hex)?.as_object()?;
    item.get("seq")?.as_u64()
}

fn self_get_rx_privs(self_v: &Value, to_id: &[u8; 32]) -> Option<(Byte32, SecretBytes)> {
    let id_hex = hex::encode(to_id);
    let keys = self_v.get("e2e_rx")?.get("keys")?.as_object()?;
    let item = keys.get(&id_hex)?.as_object()?;

    let x_priv_hex = item.get("x_priv")?.as_str()?;
    let k_priv_hex = item.get("k_priv")?.as_str()?;

    let x_priv = Byte32::from_slice(&hex_to_32(x_priv_hex).ok()?).ok()?;
    let k_priv = SecretBytes::from_vec(hex::decode(k_priv_hex.trim()).ok()?);

    Some((x_priv, k_priv))
}

fn self_put_rx_key(
    self_v: &mut Value,
    id: &[u8; 32],
    x_priv_hex: &str,
    x_pub_hex: &str,
    k_priv_hex: &str,
    k_pub_hex: &str,
    seq: u64,
) -> Result<()> {
    if self_v.get("e2e_rx").is_none() {
        self_v["e2e_rx"] = json!({
            "active": "",
            "ack_seq": 0u64,
            "next_seq": 1u64,
            "window": DEFAULT_WINDOW,
            "keys": {}
        });
    }

    let id_hex = hex::encode(id);
    self_v["e2e_rx"]["active"] = Value::String(id_hex.clone());

    let keys = self_v["e2e_rx"]
        .get_mut("keys")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| LithiumError::json_missing_field("e2e_rx.keys"))?;

    keys.insert(id_hex, json!({
        "x_priv": x_priv_hex,
        "x_pub": x_pub_hex,
        "k_priv": k_priv_hex,
        "k_pub": k_pub_hex,
        "seq": seq,
        "created_at_ms": now_ms()
    }));

    Ok(())
}

fn gc_after_ack(self_v: &mut Value) {
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
            keys.remove(&k);
        }
    }
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

    if let Some(arr) = hdr_v.get("prekeys").and_then(|v| v.as_array()) {
        peer_merge_remote_prekeys(peer_v, arr, PREKEY_TARGET);
    }

    let mode = hdr_v.get("mode").and_then(|v| v.as_str()).unwrap_or("ratchet");
    let step_in = hdr_v.get("step").and_then(|v| v.as_u64()).unwrap_or(0);
    let mailbox_gen = hdr_v
        .get("mbox_gen")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

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

        let reply_id = hex_to_32(reply_id_hex)?;
        peer_v["e2e_peer"] = json!({
            "id": hex::encode(reply_id),
            "x_pub": reply_x_pub,
            "k_pub": reply_k_pub,
            "step": step_in,
            "updated_at_ms": now_ms()
        });
    }

    peer_set_need_recover(peer_v, false);

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

pub fn encrypt_for_peer(
    self_v: &mut Value,
    peer_v: &mut Value,
    plaintext: &[u8],
    kind: &str,
    prekeys_advertise: &[Value],
    use_recovery: bool,
    mailbox_gen: u64,
) -> Result<(WireV1, Value)> {
    ensure_self_keyring(self_v)?;
    let (_peer_id, _, _, _peer_step) = ensure_peer_e2e(peer_v)?;

    let step = self_v["e2e_tx"]["step"].as_u64().unwrap_or(0) + 1;
    self_v["e2e_tx"]["step"] = json!(step);

    let (target_id, target_x_pub_hex, target_k_pub_hex, mode) = if use_recovery {
        let Some((id_hex, x_pub, k_pub)) = peer_pick_remote_prekey(peer_v) else {
            return Err(LithiumError::invalid_credentials("no_remote_prekey"));
        };
        (hex_to_32(&id_hex)?, x_pub, k_pub, "prekey_recover")
    } else {
        let (id, x_pub, k_pub, _st) = ensure_peer_e2e(peer_v)?;
        (id, x_pub, k_pub, "ratchet")
    };

    let target_x_pub = Byte32::from_slice(&hex_to_32(&target_x_pub_hex)?)?;
    let target_k_pub =
        SecretBytes::from_vec(hex::decode(target_k_pub_hex.trim()).map_err(LithiumError::invalid_hex)?);

    let reply_id = rand32()?;
    let (rx_x_priv_fb, rx_x_pub_fb) = keys::random_x25519_keypair()?;
    let rx_x_priv_hex = hex::encode(rx_x_priv_fb.as_slice());
    let rx_x_pub_hex = hex::encode(rx_x_pub_fb.as_slice());

    let (rx_k_priv, rx_k_pub) = keys::random_kyber_mlkem1024_keypair()?;
    let rx_k_priv_hex = rx_k_priv.to_hex();
    let rx_k_pub_hex = rx_k_pub.to_hex();

    let seq = self_next_seq(self_v);
    self_put_rx_key(
        self_v,
        &reply_id,
        &rx_x_priv_hex,
        &rx_x_pub_hex,
        &rx_k_priv_hex.expose(),
        &rx_k_pub_hex.expose(),
        seq,
    )?;

    let (msg_x_priv, msg_x_pub) = keys::random_x25519_keypair()?;
    let mut from_x_pub = [0u8; 32];
    from_x_pub.copy_from_slice(msg_x_pub.as_slice());

    let ts_ms = now_ms();
    let msg_id = rand16_hex()?;

    let hdr_plain = serde_json::to_vec(&json!({
        "v": 1,
        "mode": mode,
        "ts_ms": ts_ms,
        "msg_id": msg_id,
        "kind": kind,
        "step": step,
        "mbox_gen": mailbox_gen,
        "reply": {
            "id": hex::encode(reply_id),
            "x_pub": rx_x_pub_hex,
            "k_pub": rx_k_pub_hex.expose()
        },
        "prekeys": prekeys_advertise
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
    self_v: &mut Value,
    peer_v: &mut Value,
    w: &WireV1,
) -> Result<(Vec<u8>, Value)> {
    ensure_self_keyring(self_v)?;
    ensure_peer_e2e(peer_v)?;

    let Some((rx_x_priv, rx_k_priv)) = self_get_rx_privs(self_v, &w.to_id) else {
        return Err(LithiumError::invalid_credentials("to_id_unknown"));
    };

    let (pt, ui) = decrypt_with_privs(peer_v, w, &rx_x_priv, &rx_k_priv)?;

    if let Some(seq) = self_find_seq(self_v, &w.to_id) {
        let ack = self_v["e2e_rx"]["ack_seq"].as_u64().unwrap_or(0);
        if seq > ack {
            self_v["e2e_rx"]["ack_seq"] = json!(seq);
            gc_after_ack(self_v);
        }
    }

    Ok((pt, ui))
}

pub fn decrypt_for_prekey(
    peer_v: &mut Value,
    w: &WireV1,
    prekey_blob: &SecretBytes,
) -> Result<(Vec<u8>, Value)> {
    let (rx_x_priv, rx_k_priv) = prekey_blob_to_privs(prekey_blob)?;
    decrypt_with_privs(peer_v, w, &rx_x_priv, &rx_k_priv)
}

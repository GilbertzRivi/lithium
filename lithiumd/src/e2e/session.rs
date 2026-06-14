use lithium_core::{
    crypto::{keys, kyberbox},
    error::{LithiumError, Result},
    secrets::{Byte32, SecretJson, bytes::SecretBytes},
};
use serde_json::{Value, json};

use crate::commands::contact_mailbox::{current_outbound_mailbox_pubs, peer_store_mailbox_sender_keys};
use crate::labels::E2E_LABEL;

use super::{
    crypto::{malicious_message_err, sign_e2e_payload, verify_e2e_payload},
    header::{Auth, Mailbox, Reply, SignedHeader, SignedHeaderWire, SIGNED_HEADER_V},
    prekeys::prekey_blob_to_privs,
    state_peer::{
        ensure_peer_e2e, merge_remote_prekeys_into_peer, peer_bootstrap_target,
        peer_pick_remote_prekey,
    },
    state_self::{
        drop_bootstrap_private_if_established, gc_after_ack, next_tx_step, self_bootstrap_rx_privs,
        self_find_seq, self_get_rx_privs, self_next_seq, ensure_self_keyring,
        mark_bootstrap_retire_ready,
    },
    wire::{DEFAULT_WINDOW, PREKEY_TARGET, WireV1},
};

fn decrypt_with_privs(
    peer_v: &mut Value,
    w: &WireV1,
    rx_x_priv: &Byte32,
    rx_k_priv: &SecretBytes,
) -> Result<(Vec<u8>, Value)> {
    let from_x_pub = Byte32::from_slice(&w.from_x_pub)?;
    let seed = SecretBytes::new(w.seed.clone());
    let data = SecretBytes::new(w.enc_headers.clone());
    let body = SecretBytes::new(w.enc_body.clone());

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

    let wire_hdr: SignedHeaderWire = serde_json::from_slice(pt_headers.expose_as_slice())
        .map_err(|_| malicious_message_err())?;
    let hdr = &wire_hdr.header;

    let hdr_unsigned = hdr.canonical_bytes().map_err(|_| malicious_message_err())?;

    verify_e2e_payload(
        peer_v,
        &w.to_id,
        &w.from_x_pub,
        &hdr_unsigned,
        pt_body.expose_as_slice(),
        &wire_hdr.auth.sig_ed,
        &wire_hdr.auth.sig_dili,
    )?;

    merge_remote_prekeys_into_peer(peer_v, &hdr.prekeys, PREKEY_TARGET);

    let step_in = hdr.step;
    let mailbox_gen = hdr.mbox_gen;

    peer_store_mailbox_sender_keys(
        peer_v,
        mailbox_gen,
        &hdr.mailbox.sender_cur_x_pub,
        &hdr.mailbox.sender_next_x_pub,
    );

    let peer_step_cur = peer_v["e2e_peer"]["step"].as_u64().unwrap_or(0);

    if step_in > peer_step_cur {
        let reply_id = Byte32::from_hex(hdr.reply.id.trim())?;
        peer_v["e2e_peer"] = json!({
            "id": reply_id.to_hex().expose(),
            "x_pub": hdr.reply.x_pub.as_str(),
            "k_pub": hdr.reply.k_pub.as_str(),
            "step": step_in,
            "updated_at_ms": super::wire::now_ms()
        });
    }

    peer_v["need_recover"] = json!(false);

    Ok((
        pt_body.expose_as_slice().to_vec(),
        json!({
            "ts_ms": hdr.ts_ms, "msg_id": hdr.msg_id.as_str(), "kind": hdr.kind.as_str(),
            "step": step_in, "mode": hdr.mode.as_str(), "mailbox_gen": mailbox_gen
        }),
    ))
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
                "created_at_ms": super::wire::now_ms()
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

    let ts_ms = super::wire::now_ms();
    let msg_id = keys::random_fixed::<16>()?.to_hex().expose().to_owned();

    let header = SignedHeader {
        v: SIGNED_HEADER_V,
        mode: mode.to_owned(),
        ts_ms,
        msg_id: msg_id.clone(),
        kind: kind.to_owned(),
        step,
        mbox_gen: mailbox_gen,
        mailbox: Mailbox {
            sender_cur_x_pub: mailbox_sender_cur_x_pub,
            sender_next_x_pub: mailbox_sender_next_x_pub,
        },
        reply: Reply {
            id: reply_id.to_hex().expose().to_owned(),
            x_pub: rx_x_pub_hex.expose().to_owned(),
            k_pub: rx_k_pub_hex.expose().to_owned(),
        },
        prekeys: prekeys_advertise.to_vec(),
    };

    let hdr_unsigned_bytes = header.canonical_bytes()?;

    let (sig_ed, sig_dili) =
        sign_e2e_payload(self_v, &target_id, &from_x_pub, &hdr_unsigned_bytes, plaintext)?;

    let hdr_plain = serde_json::to_vec(&SignedHeaderWire {
        header,
        auth: Auth { sig_ed, sig_dili },
    })
    .map_err(LithiumError::json_parse)?;

    let wire = kyberbox::encrypt(
        E2E_LABEL,
        &msg_x_priv,
        &target_x_pub,
        &target_k_pub,
        &SecretBytes::from_slice(plaintext),
        &SecretBytes::new(hdr_plain),
    )?;

    drop_bootstrap_private_if_established(self_v, peer_v);

    Ok((
        WireV1 {
            to_id: target_id,
            from_x_pub,
            seed: wire.seed_enc.expose_as_slice().to_vec(),
            enc_headers: wire.enc_headers.expose_as_slice().to_vec(),
            enc_body: wire.enc_body.expose_as_slice().to_vec(),
        },
        json!({
            "ts_ms": ts_ms, "msg_id": msg_id,
            "step": step, "mode": mode, "mailbox_gen": mailbox_gen
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

    drop_bootstrap_private_if_established(self_v, peer_v);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::invite_codec::gen_self_state;
    use crate::e2e::{
        prekeys::gen_local_prekey_material,
        state_self::ensure_self_keyring,
        wire::{pack_wire, unpack_wire},
    };

    fn build_peer_v_from_state(state_sj: &SecretJson, cid_bytes: &[u8]) -> SecretJson {
        let cid_hex = hex::encode(cid_bytes);
        state_sj.with_exposed(|v| {
            SecretJson::from(json!({
                "peer": {
                    "cid":      cid_hex,
                    "x_pub":    v.get("x_pub").unwrap(),
                    "k_pub":    v.get("k_pub").unwrap(),
                    "ed_pub":   v.get("ed_pub").unwrap(),
                    "dili_pub": v.get("dili_pub").unwrap(),
                    "mbox_in_pub":       v.get("mbox_in_pub").unwrap_or(v.get("x_pub").unwrap()),
                    "mbox_out_cur_pub":  v.get("mbox_out_cur_pub").unwrap_or(v.get("x_pub").unwrap()),
                    "mbox_out_next_pub": v.get("mbox_out_next_pub").unwrap_or(v.get("x_pub").unwrap()),
                }
            }))
        })
    }

    fn make_real_wire() -> (WireV1, SecretJson, SecretJson, Vec<u8>) {
        let (alice_cid, mut alice_sj) = gen_self_state().unwrap();
        let (bob_cid, bob_sj) = gen_self_state().unwrap();
        let mut bob_pv = build_peer_v_from_state(&bob_sj, &bob_cid);
        let (wire, _) = encrypt_for_peer(
            &mut alice_sj, &mut bob_pv, b"mutation-test", "text", &[], false, 0,
        )
        .unwrap();
        let _ = alice_cid;
        let packed = pack_wire(&wire);
        (wire, alice_sj, bob_sj, packed)
    }

    #[test]
    fn e2e_bootstrap_roundtrip() {
        let (alice_cid, mut alice_self_sj) = gen_self_state().unwrap();
        let (bob_cid, mut bob_self_sj) = gen_self_state().unwrap();
        let mut bob_peer_v = build_peer_v_from_state(&bob_self_sj, &bob_cid);
        let mut alice_peer_v = build_peer_v_from_state(&alice_self_sj, &alice_cid);

        let (wire, meta) = encrypt_for_peer(
            &mut alice_self_sj, &mut bob_peer_v, b"bootstrap message", "text", &[], false, 0,
        )
        .unwrap();

        assert_eq!(
            meta.get("mode").and_then(|v| v.as_str()),
            Some("bootstrap"),
            "first message must use bootstrap mode"
        );

        let (decrypted, _ui) =
            decrypt_for_us(&mut bob_self_sj, &mut alice_peer_v, &wire).unwrap();
        assert_eq!(decrypted, b"bootstrap message");
    }

    #[test]
    fn e2e_decrypt_with_wrong_state_fails() {
        let (alice_cid, mut alice_self_sj) = gen_self_state().unwrap();
        let (_bob_cid, bob_self_sj) = gen_self_state().unwrap();
        let (_wrong_cid, mut wrong_self_sj) = gen_self_state().unwrap();

        let mut bob_peer_v = {
            let (cid, _sj) = gen_self_state().unwrap();
            build_peer_v_from_state(&bob_self_sj, &cid)
        };
        let mut alice_peer_v = build_peer_v_from_state(&alice_self_sj, &alice_cid);

        let (wire, _) = encrypt_for_peer(
            &mut alice_self_sj, &mut bob_peer_v, b"data", "text", &[], false, 0,
        )
        .unwrap();

        let result = decrypt_for_us(&mut wrong_self_sj, &mut alice_peer_v, &wire);
        assert!(result.is_err(), "decryption with wrong state must fail");
    }

    #[test]
    fn e2e_pack_unpack_after_encrypt() {
        let (_alice_cid, mut alice_self_sj) = gen_self_state().unwrap();
        let (bob_cid, bob_self_sj) = gen_self_state().unwrap();
        let mut bob_peer_v = build_peer_v_from_state(&bob_self_sj, &bob_cid);

        let (wire, _) = encrypt_for_peer(
            &mut alice_self_sj, &mut bob_peer_v, b"payload", "text", &[], false, 0,
        )
        .unwrap();

        let packed = pack_wire(&wire);
        let decoded = unpack_wire(&packed).unwrap();
        assert_eq!(decoded.to_id, wire.to_id);
        assert_eq!(decoded.from_x_pub, wire.from_x_pub);
        assert_eq!(decoded.seed.len(), wire.seed.len());
        assert_eq!(decoded.enc_headers.len(), wire.enc_headers.len());
        assert_eq!(decoded.enc_body.len(), wire.enc_body.len());
    }

    #[test]
    fn e2e_prekey_roundtrip() {
        let (alice_cid, mut alice_self_sj) = gen_self_state().unwrap();
        let (_prekey_id, prekey_blob, pub_item) = gen_local_prekey_material().unwrap();
        let pk_x_pub = pub_item.get("x_pub").unwrap().as_str().unwrap().to_owned();
        let pk_k_pub = pub_item.get("k_pub").unwrap().as_str().unwrap().to_owned();
        let pk_id = pub_item.get("id").unwrap().as_str().unwrap().to_owned();

        let (bob_cid, bob_self_sj) = gen_self_state().unwrap();
        let mut bob_peer_v = SecretJson::from(json!({
            "peer": {
                "cid": hex::encode(&bob_cid),
                "x_pub": bob_self_sj.with_exposed(|v| v["x_pub"].as_str().unwrap().to_owned()),
                "k_pub": bob_self_sj.with_exposed(|v| v["k_pub"].as_str().unwrap().to_owned()),
                "ed_pub": bob_self_sj.with_exposed(|v| v["ed_pub"].as_str().unwrap().to_owned()),
                "dili_pub": bob_self_sj.with_exposed(|v| v["dili_pub"].as_str().unwrap().to_owned()),
                "mbox_in_pub": bob_self_sj.with_exposed(|v| v["mbox_in_pub"].as_str().unwrap().to_owned()),
                "mbox_out_cur_pub": bob_self_sj.with_exposed(|v| v["mbox_out_cur_pub"].as_str().unwrap().to_owned()),
                "mbox_out_next_pub": bob_self_sj.with_exposed(|v| v["mbox_out_next_pub"].as_str().unwrap().to_owned()),
            },
            "prekeys_remote": [{"id": pk_id, "x_pub": pk_x_pub, "k_pub": pk_k_pub}]
        }));

        let (wire, meta) = encrypt_for_peer(
            &mut alice_self_sj, &mut bob_peer_v, b"prekey message", "text", &[], true, 0,
        )
        .unwrap();

        assert_eq!(meta.get("mode").and_then(|v| v.as_str()), Some("prekey_recover"));

        let mut alice_peer_v_correct = build_peer_v_from_state(&alice_self_sj, &alice_cid);
        let (decrypted, _ui) =
            decrypt_for_prekey(&mut alice_peer_v_correct, &wire, &prekey_blob).unwrap();
        assert_eq!(decrypted, b"prekey message");
    }

    #[test]
    fn wire_unpack_corrupt_magic_byte_1_fails() {
        let (_, _, _, mut packed) = make_real_wire();
        packed[1] ^= 0xFF;
        assert!(unpack_wire(&packed).is_err());
    }

    #[test]
    fn wire_unpack_corrupt_magic_byte_2_fails() {
        let (_, _, _, mut packed) = make_real_wire();
        packed[2] ^= 0xFF;
        assert!(unpack_wire(&packed).is_err());
    }

    #[test]
    fn wire_unpack_version_0_fails() {
        let (_, _, _, mut packed) = make_real_wire();
        packed[3] = 0;
        assert!(unpack_wire(&packed).is_err());
    }

    #[test]
    fn wire_unpack_version_2_fails() {
        let (_, _, _, mut packed) = make_real_wire();
        packed[3] = 2;
        assert!(unpack_wire(&packed).is_err());
    }

    #[test]
    fn wire_unpack_truncate_at_3_bytes_fails() {
        let (_, _, _, packed) = make_real_wire();
        assert!(unpack_wire(&packed[..3]).is_err());
    }

    #[test]
    fn wire_unpack_truncate_at_36_bytes_fails() {
        let (_, _, _, packed) = make_real_wire();
        assert!(unpack_wire(&packed[..36]).is_err());
    }

    #[test]
    fn wire_unpack_truncate_after_header_no_seed_fails() {
        let (_, _, _, packed) = make_real_wire();
        assert!(unpack_wire(&packed[..68]).is_err());
    }

    #[test]
    fn wire_unpack_seed_len_claims_more_than_available_fails() {
        let (_, _, _, mut packed) = make_real_wire();
        packed[68] = 0xFF;
        packed[69] = 0xFF;
        assert!(unpack_wire(&packed).is_err());
    }

    #[test]
    fn wire_unpack_hdr_len_claims_more_than_available_fails() {
        let (wire, _, _, mut packed) = make_real_wire();
        let hdr_len_offset = 70 + wire.seed.len();
        packed[hdr_len_offset] = 0xFF;
        packed[hdr_len_offset + 1] = 0xFF;
        assert!(unpack_wire(&packed).is_err());
    }

    #[test]
    fn wire_unpack_body_len_claims_more_than_available_fails() {
        let (wire, _, _, mut packed) = make_real_wire();
        let body_len_offset = 70 + wire.seed.len() + 4 + wire.enc_headers.len();
        packed[body_len_offset] = 0xFF;
        packed[body_len_offset + 1] = 0xFF;
        assert!(unpack_wire(&packed).is_err());
    }

    #[test]
    fn wire_unpack_trailing_bytes_succeed() {
        let (_, _, _, mut packed) = make_real_wire();
        packed.extend_from_slice(&[0xFF; 128]);
        assert!(unpack_wire(&packed).is_ok());
    }

    #[test]
    fn wire_corrupt_to_id_causes_to_id_unknown() {
        let (mut wire, _, mut bob_sj, _) = make_real_wire();
        wire.to_id[0] ^= 0xFF;
        let mut fake_peer_v = SecretJson::from(json!({}));
        let result = decrypt_for_us(&mut bob_sj, &mut fake_peer_v, &wire);
        assert!(result.is_err());
    }

    #[test]
    fn wire_corrupt_from_x_pub_decryption_fails() {
        let (mut wire, _, mut bob_sj, _) = make_real_wire();
        let (alice_cid, alice_sj) = gen_self_state().unwrap();
        let mut alice_pv = build_peer_v_from_state(&alice_sj, &alice_cid);
        wire.from_x_pub[0] ^= 0xFF;
        let result = decrypt_for_us(&mut bob_sj, &mut alice_pv, &wire);
        assert!(result.is_err());
    }

    #[test]
    fn wire_corrupt_seed_decryption_fails() {
        let (mut wire, _, mut bob_sj, _) = make_real_wire();
        let (alice_cid, alice_sj) = gen_self_state().unwrap();
        let mut alice_pv = build_peer_v_from_state(&alice_sj, &alice_cid);
        if !wire.seed.is_empty() {
            wire.seed[0] ^= 0xFF;
        }
        let result = decrypt_for_us(&mut bob_sj, &mut alice_pv, &wire);
        assert!(result.is_err());
    }

    #[test]
    fn wire_corrupt_seed_last_byte_decryption_fails() {
        let (mut wire, _, mut bob_sj, _) = make_real_wire();
        let (alice_cid, alice_sj) = gen_self_state().unwrap();
        let mut alice_pv = build_peer_v_from_state(&alice_sj, &alice_cid);
        if !wire.seed.is_empty() {
            let last = wire.seed.len() - 1;
            wire.seed[last] ^= 0x01;
        }
        let result = decrypt_for_us(&mut bob_sj, &mut alice_pv, &wire);
        assert!(result.is_err());
    }

    #[test]
    fn wire_corrupt_enc_headers_tag_decryption_fails() {
        let (mut wire, _, mut bob_sj, _) = make_real_wire();
        let (alice_cid, alice_sj) = gen_self_state().unwrap();
        let mut alice_pv = build_peer_v_from_state(&alice_sj, &alice_cid);
        if !wire.enc_headers.is_empty() {
            let last = wire.enc_headers.len() - 1;
            wire.enc_headers[last] ^= 0x01;
        }
        let result = decrypt_for_us(&mut bob_sj, &mut alice_pv, &wire);
        assert!(result.is_err());
    }

    #[test]
    fn wire_corrupt_enc_body_tag_decryption_fails() {
        let (mut wire, _, mut bob_sj, _) = make_real_wire();
        let (alice_cid, alice_sj) = gen_self_state().unwrap();
        let mut alice_pv = build_peer_v_from_state(&alice_sj, &alice_cid);
        if !wire.enc_body.is_empty() {
            let last = wire.enc_body.len() - 1;
            wire.enc_body[last] ^= 0x01;
        }
        let result = decrypt_for_us(&mut bob_sj, &mut alice_pv, &wire);
        assert!(result.is_err());
    }

    #[test]
    fn wire_swap_enc_body_and_enc_headers_decryption_fails() {
        let (mut wire, _, mut bob_sj, _) = make_real_wire();
        let (alice_cid, alice_sj) = gen_self_state().unwrap();
        let mut alice_pv = build_peer_v_from_state(&alice_sj, &alice_cid);
        std::mem::swap(&mut wire.enc_body, &mut wire.enc_headers);
        let result = decrypt_for_us(&mut bob_sj, &mut alice_pv, &wire);
        assert!(result.is_err());
    }

    #[test]
    fn wire_empty_enc_body_decryption_fails() {
        let (mut wire, _, mut bob_sj, _) = make_real_wire();
        let (alice_cid, alice_sj) = gen_self_state().unwrap();
        let mut alice_pv = build_peer_v_from_state(&alice_sj, &alice_cid);
        wire.enc_body.clear();
        let result = decrypt_for_us(&mut bob_sj, &mut alice_pv, &wire);
        assert!(result.is_err());
    }

    #[test]
    fn e2e_step_counter_increments_each_message() {
        let (_alice_cid, mut alice_sj) = gen_self_state().unwrap();
        let (bob_cid, bob_sj) = gen_self_state().unwrap();
        let mut bob_pv = build_peer_v_from_state(&bob_sj, &bob_cid);

        let (_, m1) = encrypt_for_peer(&mut alice_sj, &mut bob_pv, b"msg1", "text", &[], false, 0).unwrap();
        let (_, m2) = encrypt_for_peer(&mut alice_sj, &mut bob_pv, b"msg2", "text", &[], false, 0).unwrap();
        let (_, m3) = encrypt_for_peer(&mut alice_sj, &mut bob_pv, b"msg3", "text", &[], false, 0).unwrap();

        assert_eq!(m1["step"].as_u64(), Some(1));
        assert_eq!(m2["step"].as_u64(), Some(2));
        assert_eq!(m3["step"].as_u64(), Some(3));
    }

    #[test]
    fn e2e_two_bootstrap_messages_both_decrypt() {
        let (alice_cid, mut alice_sj) = gen_self_state().unwrap();
        let (bob_cid, mut bob_sj) = gen_self_state().unwrap();
        let mut bob_pv = build_peer_v_from_state(&bob_sj, &bob_cid);
        let mut alice_pv = build_peer_v_from_state(&alice_sj, &alice_cid);

        let (wire1, m1) = encrypt_for_peer(&mut alice_sj, &mut bob_pv, b"first", "text", &[], false, 0).unwrap();
        let (wire2, m2) = encrypt_for_peer(&mut alice_sj, &mut bob_pv, b"second", "text", &[], false, 0).unwrap();

        assert_eq!(m1["mode"].as_str(), Some("bootstrap"));
        assert_eq!(m2["mode"].as_str(), Some("bootstrap"));

        let (pt1, _) = decrypt_for_us(&mut bob_sj, &mut alice_pv, &wire1).unwrap();
        let (pt2, _) = decrypt_for_us(&mut bob_sj, &mut alice_pv, &wire2).unwrap();

        assert_eq!(pt1, b"first");
        assert_eq!(pt2, b"second");
    }

    #[test]
    fn e2e_ratchet_mode_after_bootstrap_reply() {
        let (alice_cid, mut alice_sj) = gen_self_state().unwrap();
        let (bob_cid, mut bob_sj) = gen_self_state().unwrap();
        let mut bob_pv_for_alice = build_peer_v_from_state(&bob_sj, &bob_cid);
        let mut alice_pv_for_bob = build_peer_v_from_state(&alice_sj, &alice_cid);

        let (wire_a, _) = encrypt_for_peer(
            &mut alice_sj, &mut bob_pv_for_alice, b"bootstrap", "text", &[], false, 0,
        ).unwrap();

        decrypt_for_us(&mut bob_sj, &mut alice_pv_for_bob, &wire_a).unwrap();

        let (wire_b, meta_b) = encrypt_for_peer(
            &mut bob_sj, &mut alice_pv_for_bob, b"ratchet-reply", "text", &[], false, 0,
        ).unwrap();
        assert_eq!(meta_b["mode"].as_str(), Some("ratchet"),
            "after receiving bootstrap, next send must be ratchet");

        let mut bob_pv_for_alice2 = build_peer_v_from_state(&bob_sj, &bob_cid);
        let (pt, _) = decrypt_for_us(&mut alice_sj, &mut bob_pv_for_alice2, &wire_b).unwrap();
        assert_eq!(pt, b"ratchet-reply");
    }

    #[test]
    fn e2e_ack_seq_advances_after_ratchet_decrypt() {
        let (alice_cid, mut alice_sj) = gen_self_state().unwrap();
        let (bob_cid, mut bob_sj) = gen_self_state().unwrap();
        let mut bob_pv = build_peer_v_from_state(&bob_sj, &bob_cid);
        let mut alice_pv_for_bob = build_peer_v_from_state(&alice_sj, &alice_cid);

        let (wire_a, _) = encrypt_for_peer(
            &mut alice_sj, &mut bob_pv, b"hello", "text", &[], false, 0,
        ).unwrap();
        decrypt_for_us(&mut bob_sj, &mut alice_pv_for_bob, &wire_a).unwrap();

        let (wire_b, _) = encrypt_for_peer(
            &mut bob_sj, &mut alice_pv_for_bob, b"reply", "text", &[], false, 0,
        ).unwrap();

        let ack_before = alice_sj.with_exposed(|v| v["e2e_rx"]["ack_seq"].as_u64().unwrap_or(0));
        let mut bob_pv2 = build_peer_v_from_state(&bob_sj, &bob_cid);
        decrypt_for_us(&mut alice_sj, &mut bob_pv2, &wire_b).unwrap();
        let ack_after = alice_sj.with_exposed(|v| v["e2e_rx"]["ack_seq"].as_u64().unwrap_or(0));

        assert!(ack_after > ack_before,
            "ack_seq must advance: {ack_before} → {ack_after}");
    }

    #[test]
    fn e2e_gc_removes_old_reply_key() {
        let (alice_cid, mut alice_sj) = gen_self_state().unwrap();
        let (bob_cid, mut bob_sj) = gen_self_state().unwrap();

        ensure_self_keyring(&mut alice_sj).unwrap();
        alice_sj.with_exposed_mut(|v| { v["e2e_rx"]["window"] = json!(1u64); });

        let mut bob_pv = build_peer_v_from_state(&bob_sj, &bob_cid);
        let mut alice_pv_for_bob = build_peer_v_from_state(&alice_sj, &alice_cid);

        let (wire_a1, _) = encrypt_for_peer(&mut alice_sj, &mut bob_pv, b"a1", "text", &[], false, 0).unwrap();
        decrypt_for_us(&mut bob_sj, &mut alice_pv_for_bob, &wire_a1).unwrap();

        let (wire_r1, _) = encrypt_for_peer(&mut bob_sj, &mut alice_pv_for_bob, b"r1", "text", &[], false, 0).unwrap();
        let wire_r1_copy = wire_r1.clone();
        let mut bob_pv2 = build_peer_v_from_state(&bob_sj, &bob_cid);
        decrypt_for_us(&mut alice_sj, &mut bob_pv2, &wire_r1).unwrap();

        let mut bob_pv3 = build_peer_v_from_state(&bob_sj, &bob_cid);
        let (wire_a2, _) = encrypt_for_peer(&mut alice_sj, &mut bob_pv3, b"a2", "text", &[], false, 0).unwrap();
        decrypt_for_us(&mut bob_sj, &mut alice_pv_for_bob, &wire_a2).unwrap();

        let (wire_r2, _) = encrypt_for_peer(&mut bob_sj, &mut alice_pv_for_bob, b"r2", "text", &[], false, 0).unwrap();
        let mut bob_pv4 = build_peer_v_from_state(&bob_sj, &bob_cid);
        decrypt_for_us(&mut alice_sj, &mut bob_pv4, &wire_r2).unwrap();

        let mut bob_pv5 = build_peer_v_from_state(&bob_sj, &bob_cid);
        let (wire_a3, _) = encrypt_for_peer(&mut alice_sj, &mut bob_pv5, b"a3", "text", &[], false, 0).unwrap();
        decrypt_for_us(&mut bob_sj, &mut alice_pv_for_bob, &wire_a3).unwrap();

        let (wire_r3, _) = encrypt_for_peer(&mut bob_sj, &mut alice_pv_for_bob, b"r3", "text", &[], false, 0).unwrap();
        let mut bob_pv6 = build_peer_v_from_state(&bob_sj, &bob_cid);
        decrypt_for_us(&mut alice_sj, &mut bob_pv6, &wire_r3).unwrap();

        let mut bob_pv7 = build_peer_v_from_state(&bob_sj, &bob_cid);
        let replay_result = decrypt_for_us(&mut alice_sj, &mut bob_pv7, &wire_r1_copy);
        assert!(replay_result.is_err(), "replayed message must fail after GC removes its key");
    }

    #[test]
    fn e2e_decrypt_without_no_remote_prekey_fails() {
        let (_cid, mut sj) = gen_self_state().unwrap();
        let mut peer_v = SecretJson::from(json!({ "prekeys_remote": [] }));
        let result = encrypt_for_peer(&mut sj, &mut peer_v, b"x", "text", &[], true, 0);
        assert!(result.is_err(), "encrypt with use_recovery=true and no prekeys must fail");
    }

    #[test]
    fn e2e_encrypt_without_peer_keys_fails() {
        let (_cid, mut sj) = gen_self_state().unwrap();
        let mut peer_v = SecretJson::from(json!({}));
        let result = encrypt_for_peer(&mut sj, &mut peer_v, b"x", "text", &[], false, 0);
        assert!(result.is_err(), "encrypt without any peer key material must fail");
    }
}
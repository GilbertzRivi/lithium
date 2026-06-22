use std::collections::VecDeque;

use serde_json::Value;

use crate::commands::invite_codec::gen_self_state;

use super::session::{decrypt_for_us, encrypt_for_peer};
use super::state::{PeerIdentity, PeerState, SelfState};
use super::wire::WireV1;

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug)]
pub enum FuzzOp {
    AEncrypt(Vec<u8>),
    BDecrypt,
    BEncrypt(Vec<u8>),
    ADecrypt,
    ReplayLast,
    DropNext,
    Tamper(u16, u8),
}

pub(crate) fn build_peer_from_state(self_st: &SelfState, cid_bytes: &[u8]) -> PeerState {
    let mut p = PeerState::empty();
    p.peer = Some(PeerIdentity {
        cid: hex::encode(cid_bytes),
        x_pub: self_st.x_pub.clone(),
        k_pub: self_st.k_pub.clone(),
        ed_pub: self_st.ed_pub.clone(),
        dili_pub: self_st.dili_pub.clone(),
        mbox_in_pub: self_st.mbox_in_pub.clone(),
        mbox_out_cur_pub: self_st.mbox_out_cur_pub.clone(),
        mbox_out_next_pub: self_st.mbox_out_next_pub.clone(),
    });
    p
}

enum Side {
    ToBob,
    ToAlice,
}

struct Pending {
    wire: WireV1,
    pt: Vec<u8>,
    tampered: bool,
}

pub fn drive(ops: &[FuzzOp]) {
    let Ok((alice_cid, mut alice_st)) = gen_self_state() else {
        return;
    };
    let Ok((bob_cid, mut bob_st)) = gen_self_state() else {
        return;
    };

    let mut a_view_b = build_peer_from_state(&bob_st, &bob_cid);
    let mut b_view_a = build_peer_from_state(&alice_st, &alice_cid);

    let mut a2b: VecDeque<Pending> = VecDeque::new();
    let mut b2a: VecDeque<Pending> = VecDeque::new();
    let mut last: Option<(Side, WireV1, Vec<u8>)> = None;
    let mut a_step = 0u64;
    let mut b_step = 0u64;

    for op in ops {
        match op {
            FuzzOp::AEncrypt(m) => {
                let m = cap(m);
                if let Ok((wire, meta)) =
                    encrypt_for_peer(&mut alice_st, &mut a_view_b, &m, "text", &[], false, 0)
                {
                    assert_step(&meta, &mut a_step);
                    a2b.push_back(Pending {
                        wire,
                        pt: m,
                        tampered: false,
                    });
                }
            }
            FuzzOp::BEncrypt(m) => {
                let m = cap(m);
                if let Ok((wire, meta)) =
                    encrypt_for_peer(&mut bob_st, &mut b_view_a, &m, "text", &[], false, 0)
                {
                    assert_step(&meta, &mut b_step);
                    b2a.push_back(Pending {
                        wire,
                        pt: m,
                        tampered: false,
                    });
                }
            }
            FuzzOp::BDecrypt => {
                let Some(p) = a2b.pop_front() else { continue };
                if let Ok((pt, _)) = decrypt_for_us(&mut bob_st, &mut b_view_a, &p.wire) {
                    assert!(!p.tampered, "tampered A->B wire decrypted");
                    assert_eq!(pt, p.pt, "A->B plaintext mismatch");
                    last = Some((Side::ToBob, p.wire, p.pt));
                }
            }
            FuzzOp::ADecrypt => {
                let Some(p) = b2a.pop_front() else { continue };
                if let Ok((pt, _)) = decrypt_for_us(&mut alice_st, &mut a_view_b, &p.wire) {
                    assert!(!p.tampered, "tampered B->A wire decrypted");
                    assert_eq!(pt, p.pt, "B->A plaintext mismatch");
                    last = Some((Side::ToAlice, p.wire, p.pt));
                }
            }
            FuzzOp::ReplayLast => {
                if let Some((side, wire, pt)) = &last {
                    let res = match side {
                        Side::ToBob => decrypt_for_us(&mut bob_st, &mut b_view_a, wire),
                        Side::ToAlice => decrypt_for_us(&mut alice_st, &mut a_view_b, wire),
                    };
                    if let Ok((got, _)) = res {
                        assert_eq!(&got, pt, "replay yielded a different plaintext");
                    }
                }
            }
            FuzzOp::DropNext => {
                if a2b.pop_front().is_none() {
                    b2a.pop_front();
                }
            }
            FuzzOp::Tamper(idx, val) => {
                if let Some(p) = a2b.front_mut() {
                    tamper(&mut p.wire, *idx, *val);
                    p.tampered = true;
                } else if let Some(p) = b2a.front_mut() {
                    tamper(&mut p.wire, *idx, *val);
                    p.tampered = true;
                }
            }
        }
    }
}

fn cap(m: &[u8]) -> Vec<u8> {
    m[..m.len().min(1024)].to_vec()
}

fn assert_step(meta: &Value, last: &mut u64) {
    if let Some(step) = meta.get("step").and_then(Value::as_u64) {
        assert!(step > *last, "step regressed: {last} -> {step}");
        *last = step;
    }
}

fn tamper(w: &mut WireV1, idx: u16, val: u8) {
    let flip = val | 1;
    let pos = idx as usize / 5;
    match idx % 5 {
        0 => w.to_id[pos % 32] ^= flip,
        1 => w.from_x_pub[pos % 32] ^= flip,
        2 if !w.seed.is_empty() => {
            let n = w.seed.len();
            w.seed[pos % n] ^= flip;
        }
        3 if !w.enc_headers.is_empty() => {
            let n = w.enc_headers.len();
            w.enc_headers[pos % n] ^= flip;
        }
        4 if !w.enc_body.is_empty() => {
            let n = w.enc_body.len();
            w.enc_body[pos % n] ^= flip;
        }
        _ => w.from_x_pub[pos % 32] ^= flip,
    }
}

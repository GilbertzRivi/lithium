use sha2::{Digest, Sha256};

pub const DEFAULT_SEND_POW_BITS: u32 = 18;

pub fn challenge(ctx: &[u8], mailbox: &[u8], content: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ctx);
    h.update((mailbox.len() as u32).to_le_bytes());
    h.update(mailbox);
    h.update(content);
    h.finalize().into()
}

fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut count = 0;
    for &byte in digest {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

pub fn verify(challenge: &[u8], nonce: u64, bits: u32) -> bool {
    if bits == 0 {
        return true;
    }
    let mut h = Sha256::new();
    h.update(challenge);
    h.update(nonce.to_le_bytes());
    leading_zero_bits(&h.finalize()) >= bits
}

pub fn solve(challenge: &[u8], bits: u32) -> u64 {
    let mut nonce = 0u64;
    while !verify(challenge, nonce, bits) {
        nonce = nonce.wrapping_add(1);
    }
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solved_nonce_verifies() {
        let c = challenge(b"send-pow", b"mailbox", b"content");
        let nonce = solve(&c, 12);
        assert!(verify(&c, nonce, 12));
    }

    #[test]
    fn wrong_nonce_fails() {
        let c = challenge(b"send-pow", b"mailbox", b"content");
        let nonce = solve(&c, 12);
        assert!(!verify(&c, nonce.wrapping_add(1), 20));
    }

    #[test]
    fn zero_bits_always_passes() {
        assert!(verify(&[0xff; 32], 0, 0));
    }
}

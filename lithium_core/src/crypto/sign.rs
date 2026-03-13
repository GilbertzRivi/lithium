use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto::sign::mldsa87::{DetachedSignature, PublicKey, SecretKey, detached_sign, verify_detached_signature};
use pqcrypto::traits::sign::{DetachedSignature as DStrait, PublicKey as PKtrait, SecretKey as SKtrait};
use crate::{error::{LithiumError, Result}, secrets::Byte32, secrets::bytes::SecretBytes};

pub fn sign_message<S: AsRef<[u8]>>(message: &[u8], priv_ed_seed: S) -> Result<SecretBytes> {
    let seed = Byte32::from_slice(priv_ed_seed.as_ref())?;
    let signing = SigningKey::from_bytes(seed.as_array());
    let sig: Signature = signing.sign(message);
    Ok(SecretBytes::from_slice(&sig.to_bytes()))
}

pub fn verify_signature(message: &[u8], signature: &[u8], pub_key: &Byte32) -> bool {
    if signature.len() != 64 { return false; }
    let sig = match Signature::from_slice(signature) { Ok(v) => v, Err(_) => return false };
    let pk = match VerifyingKey::from_bytes(pub_key.as_array()) { Ok(v) => v, Err(_) => return false };
    pk.verify(message, &sig).is_ok()
}

pub fn sign_message_dili<S: AsRef<[u8]>>(message: &[u8], dili_sk_bytes: S) -> Result<SecretBytes> {
    let sig_bytes = {
        let sk = SecretKey::from_bytes(dili_sk_bytes.as_ref()).map_err(|_| LithiumError::internal())?;
        let sig: DetachedSignature = detached_sign(message, &sk);
        SecretBytes::from_slice(sig.as_bytes())
    };
    Ok(sig_bytes)
}

pub fn verify_signature_dili(message: &[u8], signature: &[u8], dili_pk_bytes: &SecretBytes) -> bool {
    let Ok(pk) = PublicKey::from_bytes(dili_pk_bytes.expose_as_slice()) else { return false; };
    let Ok(sig) = DetachedSignature::from_bytes(signature) else { return false; };
    verify_detached_signature(&sig, message, &pk).is_ok()
}

use ed25519_dalek::SigningKey;
use pqcrypto::kem::mlkem1024;
use pqcrypto::sign::mldsa87;
use pqcrypto::traits::kem::{PublicKey as _, SecretKey as _};
use pqcrypto::traits::sign::{PublicKey as SignPub, SecretKey as SignSk};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use rand::rngs::SysRng;
use rand::TryRng;
use crate::error::Result;
use crate::secrets::bytes::{FixedBytes, SecretBytes};
use crate::secrets::types::{MasterKey32, Nonce12, SessionId32};

#[inline]
pub fn random_fixed<const N: usize>() -> Result<FixedBytes<N>> {
    let mut out = [0u8; N];
    let mut rng = SysRng;
    rng.try_fill_bytes(&mut out)?;
    Ok(FixedBytes::new(out))
}
#[inline]
pub fn random_12() -> Result<Nonce12> { Ok(random_fixed::<12>()?) }
#[inline]
pub fn random_32() -> Result<SessionId32> { Ok(random_fixed::<32>()?) }
#[inline]
pub fn random_master_key32() -> Result<MasterKey32> { Ok(random_fixed::<32>()?) }

#[inline]
pub fn random_x25519_keypair() -> Result<(FixedBytes<32>, FixedBytes<32>)> {
    let sk_seed = random_fixed::<32>()?;
    let secret = XStaticSecret::from(*sk_seed.as_array());
    let pk = XPublicKey::from(&secret);
    Ok((sk_seed, FixedBytes::new(*pk.as_bytes())))
}

#[inline]
pub fn random_ed25519_keypair() -> Result<(FixedBytes<32>, FixedBytes<32>)> {
    let seed = random_fixed::<32>()?;
    let signing = SigningKey::from_bytes(seed.as_array());
    let vk = signing.verifying_key().to_bytes();
    Ok((seed, FixedBytes::new(vk)))
}

#[inline]
pub fn random_kyber_mlkem1024_keypair() -> Result<(SecretBytes, SecretBytes)> {
    let (pk, sk) = mlkem1024::keypair();
    Ok((SecretBytes::from_slice(sk.as_bytes()), SecretBytes::from_slice(pk.as_bytes())))
}

#[inline]
pub fn random_dilithium_mldsa87_keypair() -> Result<(SecretBytes, SecretBytes)> {
    let (pk, sk) = mldsa87::keypair();
    Ok((SecretBytes::from_slice(SignSk::as_bytes(&sk)), SecretBytes::from_slice(SignPub::as_bytes(&pk))))
}

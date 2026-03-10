use hkdf::Hkdf;
use sha2::Sha256;

use crate::{error::Result, secrets::Byte32, secrets::bytes::SecretBytes};

pub fn derive32(input: &SecretBytes, salt: Option<&SecretBytes>, info: &SecretBytes) -> Result<Byte32> {
    let hk = Hkdf::<Sha256>::new(salt.map(|s| s.as_slice()), input.as_slice());
    let mut out = Byte32::new_zeroed();
    hk.expand(info.as_slice(), out.as_mut_slice())?;
    Ok(out)
}
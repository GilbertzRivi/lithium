use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use pqcrypto::kem::mlkem1024;
use pqcrypto::sign::mldsa87;
use pqcrypto::traits::kem::{PublicKey as _, SecretKey as _};
use pqcrypto::traits::sign::{PublicKey as SignPub, SecretKey as SignSk};

use crate::crypto::{kdf, keys};
use crate::error::{LithiumError, Result};
use crate::secrets::{Byte32, SecretBytes};

use super::keyfile;

const KT_ED25519: &str = "ed25519-priv";
const KT_X25519: &str = "x25519-priv";
const KT_KYBER: &str = "kyber-mlkem1024-priv";
const KT_DILITHIUM: &str = "dilithium-mldsa87-priv";
const ED_PUB: &str = "ed25519.pub";
const ED_PRIV: &str = "ed25519.keyf";
const X_PUB: &str = "x25519.pub";
const X_PRIV: &str = "x25519.keyf";
const KYBER_PUB: &str = "kyber-mlkem1024.pub";
const KYBER_PRIV: &str = "kyber-mlkem1024.keyf";
const DILI_PUB: &str = "dilithium-mldsa87.pub";
const DILI_PRIV: &str = "dilithium-mldsa87.keyf";
const DEFAULT_ROTATE_EVERY: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStoreKind { Server, User }
impl KeyStoreKind { fn dir_name(self) -> &'static str { match self { Self::Server => "server", Self::User => "user" } } }

pub trait MkProvider {
    fn load_mk(&self) -> Result<Byte32>;
    fn store_mk(&self, mk: &Byte32) -> Result<()>;
}

pub struct PlainFileMkProvider { path: PathBuf }
impl PlainFileMkProvider { pub fn new(path: PathBuf) -> Self { Self { path } } }
impl MkProvider for PlainFileMkProvider {
    fn load_mk(&self) -> Result<Byte32> {
        let bytes = keyfile::read_keyfile_bytes(&self.path)?;
        Byte32::from_slice(&bytes)
    }
    fn store_mk(&self, mk: &Byte32) -> Result<()> { keyfile::write_secure(&self.path, mk.as_slice()) }
}

#[derive(Clone)]
pub struct PublicKeys {
    pub ed25519: Byte32,
    pub x25519: Byte32,
    pub kyber: SecretBytes,
    pub dilithium: SecretBytes,
}

pub struct KeyManager<P: MkProvider> {
    pub_dir: PathBuf,
    priv_dir: PathBuf,
    mk_provider: P,
    public_keys: PublicKeys,
    jwt_secret: Byte32,
    rotate_every: Duration,
    next_rotation_at: Instant,
}

impl<P: MkProvider> KeyManager<P> {
    pub fn start(base_dir: &Path, kind: KeyStoreKind, name: &str, mk_provider: P) -> Result<Self> {
        let root = base_dir.join(kind.dir_name()).join(name);
        let pub_dir = root.join("pub");
        let priv_dir = root.join("priv");
        fs::create_dir_all(&pub_dir).map_err(LithiumError::io)?;
        fs::create_dir_all(&priv_dir).map_err(LithiumError::io)?;
        let mk = match mk_provider.load_mk() {
            Ok(mk) => mk,
            Err(e) if e.is_not_found() => {
                let new_mk = keys::random_master_key32()?;
                mk_provider.store_mk(&new_mk)?;
                new_mk
            }
            Err(e) => return Err(e),
        };
        Self::ensure_ed25519(&pub_dir, &priv_dir, &mk)?;
        Self::ensure_x25519(&pub_dir, &priv_dir, &mk)?;
        Self::ensure_kyber(&pub_dir, &priv_dir, &mk)?;
        Self::ensure_dilithium(&pub_dir, &priv_dir, &mk)?;
        let public_keys = Self::load_public_keys(&pub_dir)?;
        let jwt_secret = Self::derive_secret32_from_mk(&mk, b"lithium/jwt-secret/v1")?;
        Ok(Self { pub_dir, priv_dir, mk_provider, public_keys, jwt_secret, rotate_every: DEFAULT_ROTATE_EVERY, next_rotation_at: Instant::now() + DEFAULT_ROTATE_EVERY })
    }

    pub fn start_plain(base_dir: &Path, kind: KeyStoreKind, name: &str) -> Result<KeyManager<PlainFileMkProvider>> {
        let mk_path = base_dir.join(kind.dir_name()).join(name).join("mk");
        let provider = PlainFileMkProvider::new(mk_path);
        KeyManager::start(base_dir, kind, name, provider)
    }

    pub fn public_keys(&self) -> &PublicKeys { &self.public_keys }
    pub fn jwt_secret(&self) -> &Byte32 { &self.jwt_secret }
    pub fn set_rotate_interval(&mut self, interval: Duration) { self.rotate_every = interval; self.next_rotation_at = Instant::now() + interval; }
    pub fn reload_public_keys(&mut self) -> Result<()> { self.public_keys = Self::load_public_keys(&self.pub_dir)?; Ok(()) }

    pub fn derive_secret32(&self, label: &[u8]) -> Result<Byte32> {
        let mk = self.mk_provider.load_mk()?;
        Self::derive_secret32_from_mk(&mk, label)
    }

    fn derive_secret32_from_mk(mk: &Byte32, label: &[u8]) -> Result<Byte32> {
        kdf::derive32(&SecretBytes::from_slice(mk.as_slice()), None, &SecretBytes::from_slice(label))
    }

    pub fn with_ed_sk<R>(&self, f: impl FnOnce(Byte32) -> Result<R>) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let seed = keyfile::load_secret32_decrypted(&self.priv_dir.join(ED_PRIV), &mk, KT_ED25519)?;
        f(seed)
    }
    pub fn with_x25519_sk<R>(&self, f: impl FnOnce(Byte32) -> Result<R>) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let seed = keyfile::load_secret32_decrypted(&self.priv_dir.join(X_PRIV), &mk, KT_X25519)?;
        f(seed)
    }
    pub fn with_kyber_sk<R>(&self, f: impl FnOnce(SecretBytes) -> Result<R>) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let sk = keyfile::load_bytes_decrypted(&self.priv_dir.join(KYBER_PRIV), &mk, KT_KYBER)?;
        f(sk)
    }
    pub fn with_dilithium_sk<R>(&self, f: impl FnOnce(SecretBytes) -> Result<R>) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let sk = keyfile::load_bytes_decrypted(&self.priv_dir.join(DILI_PRIV), &mk, KT_DILITHIUM)?;
        f(sk)
    }
    pub fn with_x25519_and_kyber_sk<R>(&self, f: impl FnOnce(Byte32, SecretBytes) -> Result<R>) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let x = keyfile::load_secret32_decrypted(&self.priv_dir.join(X_PRIV), &mk, KT_X25519)?;
        let k = keyfile::load_bytes_decrypted(&self.priv_dir.join(KYBER_PRIV), &mk, KT_KYBER)?;
        f(x, k)
    }

    pub fn maybe_rotate_mk(&mut self) -> Result<()> {
        if Instant::now() < self.next_rotation_at { return Ok(()); }
        let old_mk = self.mk_provider.load_mk()?;
        let new_mk = keys::random_master_key32()?;
        keyfile::rewrap_keyfile_dek(&self.priv_dir.join(ED_PRIV), &old_mk, &new_mk, KT_ED25519)?;
        keyfile::rewrap_keyfile_dek(&self.priv_dir.join(X_PRIV), &old_mk, &new_mk, KT_X25519)?;
        keyfile::rewrap_keyfile_dek(&self.priv_dir.join(KYBER_PRIV), &old_mk, &new_mk, KT_KYBER)?;
        keyfile::rewrap_keyfile_dek(&self.priv_dir.join(DILI_PRIV), &old_mk, &new_mk, KT_DILITHIUM)?;
        self.mk_provider.store_mk(&new_mk)?;
        self.jwt_secret = Self::derive_secret32_from_mk(&new_mk, b"lithium/jwt-secret/v1")?;
        self.next_rotation_at = Instant::now() + self.rotate_every;
        Ok(())
    }

    fn ensure_ed25519(pub_dir: &Path, priv_dir: &Path, mk: &Byte32) -> Result<()> {
        let priv_path = priv_dir.join(ED_PRIV); let pub_path = pub_dir.join(ED_PUB);
        if priv_path.exists() {
            let seed = keyfile::load_secret32_decrypted(&priv_path, mk, KT_ED25519)?;
            if !pub_path.exists() {
                let signing = SigningKey::from_bytes(seed.as_array());
                let vk = signing.verifying_key().to_bytes();
                keyfile::write_secure(&pub_path, &vk)?;
            }
        } else {
            let seed = keys::random_fixed::<32>()?;
            let signing = SigningKey::from_bytes(seed.as_array());
            let vk = signing.verifying_key().to_bytes();
            keyfile::save_secret32_encrypted(&priv_path, mk, &seed, KT_ED25519)?;
            keyfile::write_secure(&pub_path, &vk)?;
        }
        Ok(())
    }
    fn ensure_x25519(pub_dir: &Path, priv_dir: &Path, mk: &Byte32) -> Result<()> {
        let priv_path = priv_dir.join(X_PRIV); let pub_path = pub_dir.join(X_PUB);
        if priv_path.exists() {
            let seed = keyfile::load_secret32_decrypted(&priv_path, mk, KT_X25519)?;
            if !pub_path.exists() {
                let secret = XStaticSecret::from(*seed.as_array());
                let pk = XPublicKey::from(&secret);
                keyfile::write_secure(&pub_path, pk.as_bytes())?;
            }
        } else {
            let seed = keys::random_fixed::<32>()?;
            let secret = XStaticSecret::from(*seed.as_array());
            let pk = XPublicKey::from(&secret);
            keyfile::save_secret32_encrypted(&priv_path, mk, &seed, KT_X25519)?;
            keyfile::write_secure(&pub_path, pk.as_bytes())?;
        }
        Ok(())
    }
    fn ensure_kyber(pub_dir: &Path, priv_dir: &Path, mk: &Byte32) -> Result<()> {
        let priv_path = priv_dir.join(KYBER_PRIV); let pub_path = pub_dir.join(KYBER_PUB);
        if priv_path.exists() {
            let _ = keyfile::load_bytes_decrypted(&priv_path, mk, KT_KYBER)?;
            if !pub_path.exists() {
                let (pk, sk) = mlkem1024::keypair();
                keyfile::save_bytes_encrypted(&priv_path, mk, sk.as_bytes(), KT_KYBER)?;
                keyfile::write_secure(&pub_path, pk.as_bytes())?;
            }
        } else {
            let (pk, sk) = mlkem1024::keypair();
            keyfile::save_bytes_encrypted(&priv_path, mk, sk.as_bytes(), KT_KYBER)?;
            keyfile::write_secure(&pub_path, pk.as_bytes())?;
        }
        Ok(())
    }
    fn ensure_dilithium(pub_dir: &Path, priv_dir: &Path, mk: &Byte32) -> Result<()> {
        let priv_path = priv_dir.join(DILI_PRIV); let pub_path = pub_dir.join(DILI_PUB);
        if priv_path.exists() {
            let _ = keyfile::load_bytes_decrypted(&priv_path, mk, KT_DILITHIUM)?;
            if !pub_path.exists() {
                let (pk, sk) = mldsa87::keypair();
                keyfile::save_bytes_encrypted(&priv_path, mk, SignSk::as_bytes(&sk), KT_DILITHIUM)?;
                keyfile::write_secure(&pub_path, SignPub::as_bytes(&pk))?;
            }
        } else {
            let (pk, sk) = mldsa87::keypair();
            keyfile::save_bytes_encrypted(&priv_path, mk, SignSk::as_bytes(&sk), KT_DILITHIUM)?;
            keyfile::write_secure(&pub_path, SignPub::as_bytes(&pk))?;
        }
        Ok(())
    }
    fn load_public_keys(pub_dir: &Path) -> Result<PublicKeys> {
        let ed = fs::read(pub_dir.join(ED_PUB)).map_err(LithiumError::io)?;
        let x = fs::read(pub_dir.join(X_PUB)).map_err(LithiumError::io)?;
        let kyber = fs::read(pub_dir.join(KYBER_PUB)).map_err(LithiumError::io)?;
        let dilithium = fs::read(pub_dir.join(DILI_PUB)).map_err(LithiumError::io)?;
        Ok(PublicKeys { ed25519: Byte32::from_slice(&ed)?, x25519: Byte32::from_slice(&x)?, kyber: SecretBytes::from_vec(kyber), dilithium: SecretBytes::from_vec(dilithium) })
    }
}

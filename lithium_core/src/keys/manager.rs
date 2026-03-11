use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use pqcrypto::kem::mlkem1024;
use pqcrypto::sign::mldsa87;
use pqcrypto::traits::kem::{PublicKey as _, SecretKey as _};
use pqcrypto::traits::sign::{PublicKey as SignPub, SecretKey as SignSk};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::crypto::{kdf, keys};
use crate::error::{LithiumError, Result};
use crate::secrets::{Byte32, SecretBytes};

use super::keyfile;

const KT_STATE: &str = "keystore-state-v1";

const ED_PUB: &str = "ed25519.pub";
const X_PUB: &str = "x25519.pub";
const KYBER_PUB: &str = "kyber-mlkem1024.pub";
const DILI_PUB: &str = "dilithium-mldsa87.pub";

const ED_PRIV: &str = "ed25519.keyf";
const X_PRIV: &str = "x25519.keyf";
const KYBER_PRIV: &str = "kyber-mlkem1024.keyf";
const DILI_PRIV: &str = "dilithium-mldsa87.keyf";

const STATE_FILE: &str = "state.keyf";

const STATE_MAGIC: &[u8; 4] = b"KST1";
const STATE_VER: u8 = 1;

const DEFAULT_ROTATE_EVERY: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStoreKind {
    Server,
    User,
}

impl KeyStoreKind {
    fn dir_name(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::User => "user",
        }
    }
}

pub trait MkProvider {
    fn load_mk(&self) -> Result<Byte32>;
    fn store_mk(&self, mk: &Byte32) -> Result<()>;

    fn derive_secret32(&self, mk: &Byte32, label: &[u8]) -> Result<Byte32> {
        kdf::derive32(
            &SecretBytes::from_slice(mk.as_slice()),
            None,
            &SecretBytes::from_slice(label),
        )
    }
}

pub struct PlainFileMkProvider {
    path: PathBuf,
}

impl PlainFileMkProvider {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl MkProvider for PlainFileMkProvider {
    fn load_mk(&self) -> Result<Byte32> {
        let bytes = keyfile::read_keyfile_bytes(&self.path)?;
        Byte32::from_slice(bytes.as_slice())
    }

    fn store_mk(&self, mk: &Byte32) -> Result<()> {
        keyfile::write_secure(&self.path, mk.as_slice())
    }
}

#[derive(Clone)]
pub struct PublicKeys {
    pub ed25519: Byte32,
    pub x25519: Byte32,
    pub kyber: SecretBytes,
    pub dilithium: SecretBytes,
}

struct KeyStoreState {
    active_mk: Byte32,

    ed25519_seed: Byte32,
    x25519_seed: Byte32,

    kyber_pub: SecretBytes,
    kyber_sk: SecretBytes,

    dilithium_pub: SecretBytes,
    dilithium_sk: SecretBytes,
}

pub struct KeyManager<P: MkProvider> {
    pub_dir: PathBuf,
    state_path: PathBuf,
    mk_provider: P,
    public_keys: PublicKeys,
    jwt_secret: Byte32,
    rotate_every: Duration,
    next_rotation_at: Instant,
}

fn encode_state(state: &KeyStoreState) -> SecretBytes {
    let mut out = SecretBytes::new(Vec::with_capacity(
        4 + 1 + 32 + 32 + 32 + 4 + 4 + 4 + 4
            + state.kyber_pub.len()
            + state.kyber_sk.len()
            + state.dilithium_pub.len()
            + state.dilithium_sk.len(),
    ));

    out.as_mut_vec().extend_from_slice(STATE_MAGIC);
    out.as_mut_vec().push(STATE_VER);

    out.as_mut_vec().extend_from_slice(state.active_mk.as_slice());
    out.as_mut_vec()
        .extend_from_slice(state.ed25519_seed.as_slice());
    out.as_mut_vec()
        .extend_from_slice(state.x25519_seed.as_slice());

    out.as_mut_vec()
        .extend_from_slice(&(state.kyber_pub.len() as u32).to_be_bytes());
    out.as_mut_vec()
        .extend_from_slice(&(state.kyber_sk.len() as u32).to_be_bytes());
    out.as_mut_vec()
        .extend_from_slice(&(state.dilithium_pub.len() as u32).to_be_bytes());
    out.as_mut_vec()
        .extend_from_slice(&(state.dilithium_sk.len() as u32).to_be_bytes());

    out.as_mut_vec().extend_from_slice(state.kyber_pub.as_slice());
    out.as_mut_vec().extend_from_slice(state.kyber_sk.as_slice());
    out.as_mut_vec()
        .extend_from_slice(state.dilithium_pub.as_slice());
    out.as_mut_vec()
        .extend_from_slice(state.dilithium_sk.as_slice());

    out
}

fn decode_state(blob: &[u8]) -> Result<KeyStoreState> {
    if blob.len() < 4 + 1 + 32 + 32 + 32 + 4 + 4 + 4 + 4 {
        return Err(LithiumError::invalid_credentials("keystore_state_invalid"));
    }
    if &blob[..4] != STATE_MAGIC {
        return Err(LithiumError::invalid_credentials("keystore_state_invalid"));
    }
    if blob[4] != STATE_VER {
        return Err(LithiumError::invalid_credentials(
            "keystore_state_version_unsupported",
        ));
    }

    let mut i = 5usize;

    let active_mk = Byte32::from_slice(&blob[i..i + 32])?;
    i += 32;

    let ed25519_seed = Byte32::from_slice(&blob[i..i + 32])?;
    i += 32;

    let x25519_seed = Byte32::from_slice(&blob[i..i + 32])?;
    i += 32;

    let kyber_pub_len = u32::from_be_bytes(
        blob[i..i + 4]
            .try_into()
            .map_err(|_| LithiumError::internal())?,
    ) as usize;
    i += 4;

    let kyber_sk_len = u32::from_be_bytes(
        blob[i..i + 4]
            .try_into()
            .map_err(|_| LithiumError::internal())?,
    ) as usize;
    i += 4;

    let dilithium_pub_len = u32::from_be_bytes(
        blob[i..i + 4]
            .try_into()
            .map_err(|_| LithiumError::internal())?,
    ) as usize;
    i += 4;

    let dilithium_sk_len = u32::from_be_bytes(
        blob[i..i + 4]
            .try_into()
            .map_err(|_| LithiumError::internal())?,
    ) as usize;
    i += 4;

    let total = i
        .checked_add(kyber_pub_len)
        .and_then(|v| v.checked_add(kyber_sk_len))
        .and_then(|v| v.checked_add(dilithium_pub_len))
        .and_then(|v| v.checked_add(dilithium_sk_len))
        .ok_or_else(LithiumError::internal)?;

    if blob.len() != total {
        return Err(LithiumError::invalid_credentials("keystore_state_invalid"));
    }

    let kyber_pub = SecretBytes::from_slice(&blob[i..i + kyber_pub_len]);
    i += kyber_pub_len;

    let kyber_sk = SecretBytes::from_slice(&blob[i..i + kyber_sk_len]);
    i += kyber_sk_len;

    let dilithium_pub = SecretBytes::from_slice(&blob[i..i + dilithium_pub_len]);
    i += dilithium_pub_len;

    let dilithium_sk = SecretBytes::from_slice(&blob[i..i + dilithium_sk_len]);

    Ok(KeyStoreState {
        active_mk,
        ed25519_seed,
        x25519_seed,
        kyber_pub,
        kyber_sk,
        dilithium_pub,
        dilithium_sk,
    })
}

fn derive_public_keys_from_state(state: &KeyStoreState) -> PublicKeys {
    let signing = SigningKey::from_bytes(state.ed25519_seed.as_array());
    let ed_pub = signing.verifying_key().to_bytes();

    let x_secret = XStaticSecret::from(*state.x25519_seed.as_array());
    let x_pub = XPublicKey::from(&x_secret);

    PublicKeys {
        ed25519: Byte32::from(ed_pub),
        x25519: Byte32::from(*x_pub.as_bytes()),
        kyber: state.kyber_pub.clone(),
        dilithium: state.dilithium_pub.clone(),
    }
}

fn save_state(path: &Path, root_mk: &Byte32, state: &KeyStoreState) -> Result<()> {
    let encoded = encode_state(state);
    keyfile::save_bytes_encrypted(path, root_mk, encoded.as_slice(), KT_STATE)
}

fn load_state(path: &Path, root_mk: &Byte32) -> Result<KeyStoreState> {
    let blob = keyfile::load_bytes_decrypted(path, root_mk, KT_STATE)?;
    decode_state(blob.as_slice())
}

fn sync_public_cache(pub_dir: &Path, pks: &PublicKeys) -> Result<()> {
    fs::create_dir_all(pub_dir).map_err(LithiumError::io)?;
    keyfile::write_secure(&pub_dir.join(ED_PUB), pks.ed25519.as_slice())?;
    keyfile::write_secure(&pub_dir.join(X_PUB), pks.x25519.as_slice())?;
    keyfile::write_secure(&pub_dir.join(KYBER_PUB), pks.kyber.as_slice())?;
    keyfile::write_secure(&pub_dir.join(DILI_PUB), pks.dilithium.as_slice())?;
    Ok(())
}

fn legacy_or_inconsistent_layout_present(root_dir: &Path) -> bool {
    let pub_dir = root_dir.join("pub");
    let priv_dir = root_dir.join("priv");

    let candidates = [
        pub_dir.join(ED_PUB),
        pub_dir.join(X_PUB),
        pub_dir.join(KYBER_PUB),
        pub_dir.join(DILI_PUB),
        priv_dir.join(ED_PRIV),
        priv_dir.join(X_PRIV),
        priv_dir.join(KYBER_PRIV),
        priv_dir.join(DILI_PRIV),
    ];

    candidates.iter().any(|p| p.exists())
}

impl<P: MkProvider> KeyManager<P> {
    pub fn start(base_dir: &Path, kind: KeyStoreKind, name: &str, mk_provider: P) -> Result<Self> {
        let root_dir = base_dir.join(kind.dir_name()).join(name);
        let pub_dir = root_dir.join("pub");
        let state_path = root_dir.join(STATE_FILE);

        fs::create_dir_all(&root_dir).map_err(LithiumError::io)?;
        fs::create_dir_all(&pub_dir).map_err(LithiumError::io)?;

        let root_mk = match mk_provider.load_mk() {
            Ok(mk) => mk,
            Err(e) if e.is_not_found() => {
                let new_mk = keys::random_master_key32()?;
                mk_provider.store_mk(&new_mk)?;
                new_mk
            }
            Err(e) => return Err(e),
        };

        let state = if state_path.exists() {
            load_state(&state_path, &root_mk)?
        } else {
            if legacy_or_inconsistent_layout_present(&root_dir) {
                return Err(LithiumError::invalid_credentials(
                    "legacy_keystore_layout_unsupported",
                ));
            }

            let ed25519_seed = keys::random_fixed::<32>()?;
            let x25519_seed = keys::random_fixed::<32>()?;
            let (kyber_pk, kyber_sk) = mlkem1024::keypair();
            let (dili_pk, dili_sk) = mldsa87::keypair();

            let state = KeyStoreState {
                active_mk: keys::random_master_key32()?,
                ed25519_seed,
                x25519_seed,
                kyber_pub: SecretBytes::from_slice(kyber_pk.as_bytes()),
                kyber_sk: SecretBytes::from_slice(kyber_sk.as_bytes()),
                dilithium_pub: SecretBytes::from_slice(SignPub::as_bytes(&dili_pk)),
                dilithium_sk: SecretBytes::from_slice(SignSk::as_bytes(&dili_sk)),
            };

            save_state(&state_path, &root_mk, &state)?;
            state
        };

        let public_keys = derive_public_keys_from_state(&state);
        sync_public_cache(&pub_dir, &public_keys)?;

        let jwt_secret = Self::derive_secret32_from_mk(&state.active_mk, b"lithium/jwt-secret/v1")?;

        Ok(Self {
            pub_dir,
            state_path,
            mk_provider,
            public_keys,
            jwt_secret,
            rotate_every: DEFAULT_ROTATE_EVERY,
            next_rotation_at: Instant::now() + DEFAULT_ROTATE_EVERY,
        })
    }

    pub fn start_plain(
        base_dir: &Path,
        kind: KeyStoreKind,
        name: &str,
    ) -> Result<KeyManager<PlainFileMkProvider>> {
        let mk_path = base_dir.join(kind.dir_name()).join(name).join("mk");
        let provider = PlainFileMkProvider::new(mk_path);
        KeyManager::start(base_dir, kind, name, provider)
    }

    pub fn public_keys(&self) -> &PublicKeys {
        &self.public_keys
    }

    pub fn jwt_secret(&self) -> &Byte32 {
        &self.jwt_secret
    }

    pub fn set_rotate_interval(&mut self, interval: Duration) {
        self.rotate_every = interval;
        self.next_rotation_at = Instant::now() + interval;
    }

    pub fn reload_public_keys(&mut self) -> Result<()> {
        let root_mk = self.mk_provider.load_mk()?;
        let state = load_state(&self.state_path, &root_mk)?;
        self.public_keys = derive_public_keys_from_state(&state);
        sync_public_cache(&self.pub_dir, &self.public_keys)?;
        Ok(())
    }

    pub fn derive_secret32(&self, label: &[u8]) -> Result<Byte32> {
        let root_mk = self.mk_provider.load_mk()?;
        let state = load_state(&self.state_path, &root_mk)?;
        self.mk_provider.derive_secret32(&state.active_mk, label)
    }

    pub fn mk_provider_mut(&mut self) -> &mut P {
        &mut self.mk_provider
    }

    fn derive_secret32_from_mk(mk: &Byte32, label: &[u8]) -> Result<Byte32> {
        kdf::derive32(
            &SecretBytes::from_slice(mk.as_slice()),
            None,
            &SecretBytes::from_slice(label),
        )
    }

    pub fn with_ed_sk<R>(&self, f: impl FnOnce(Byte32) -> Result<R>) -> Result<R> {
        let root_mk = self.mk_provider.load_mk()?;
        let state = load_state(&self.state_path, &root_mk)?;
        f(state.ed25519_seed)
    }

    pub fn with_x25519_sk<R>(&self, f: impl FnOnce(Byte32) -> Result<R>) -> Result<R> {
        let root_mk = self.mk_provider.load_mk()?;
        let state = load_state(&self.state_path, &root_mk)?;
        f(state.x25519_seed)
    }

    pub fn with_kyber_sk<R>(&self, f: impl FnOnce(SecretBytes) -> Result<R>) -> Result<R> {
        let root_mk = self.mk_provider.load_mk()?;
        let state = load_state(&self.state_path, &root_mk)?;
        f(state.kyber_sk)
    }

    pub fn with_dilithium_sk<R>(&self, f: impl FnOnce(SecretBytes) -> Result<R>) -> Result<R> {
        let root_mk = self.mk_provider.load_mk()?;
        let state = load_state(&self.state_path, &root_mk)?;
        f(state.dilithium_sk)
    }

    pub fn with_x25519_and_kyber_sk<R>(
        &self,
        f: impl FnOnce(Byte32, SecretBytes) -> Result<R>,
    ) -> Result<R> {
        let root_mk = self.mk_provider.load_mk()?;
        let state = load_state(&self.state_path, &root_mk)?;
        f(state.x25519_seed, state.kyber_sk)
    }

    pub fn maybe_rotate_mk(&mut self) -> Result<()> {
        if Instant::now() < self.next_rotation_at {
            return Ok(());
        }

        let root_mk = self.mk_provider.load_mk()?;
        let mut state = load_state(&self.state_path, &root_mk)?;

        state.active_mk = keys::random_master_key32()?;
        save_state(&self.state_path, &root_mk, &state)?;

        self.jwt_secret =
            Self::derive_secret32_from_mk(&state.active_mk, b"lithium/jwt-secret/v1")?;
        self.next_rotation_at = Instant::now() + self.rotate_every;

        Ok(())
    }
}
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use pqcrypto::kem::mlkem1024;
use pqcrypto::sign::mldsa87;
use pqcrypto::traits::kem::{PublicKey as _, SecretKey as _};
use pqcrypto::traits::sign::{PublicKey as SignPub, SecretKey as SignSk};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::crypto::keys;
use crate::error::{LithiumError, Result};
use crate::secrets::{Byte32, MasterKey32, SecretBytes};

use super::keyfile;

const DEFAULT_ROTATE_EVERY: Duration = Duration::from_secs(3600);

const PUB_DIR: &str = "pub";
const PRIV_DIR: &str = "priv";
const SECRETS_DIR: &str = "secrets";
const ROTATE_DIR: &str = ".rotate";
const ROTATE_STAGE_DIR: &str = "staged";
const ROTATE_READY_FILE: &str = "ready";
const ROTATE_NEXT_OLD_FILE: &str = "next-mk-old.keyf";
const ROTATE_NEXT_NEW_FILE: &str = "next-mk-new.keyf";

const ED_PUB: &str = "ed25519.pub";
const X_PUB: &str = "x25519.pub";
const KYBER_PUB: &str = "kyber-mlkem1024.pub";
const DILI_PUB: &str = "dilithium-mldsa87.pub";

const ED_PRIV: &str = "ed25519.keyf";
const X_PRIV: &str = "x25519.keyf";
const KYBER_PRIV: &str = "kyber-mlkem1024.keyf";
const DILI_PRIV: &str = "dilithium-mldsa87.keyf";

const LEGACY_STATE_FILE: &str = "state.keyf";

const KT_ED_SEED: &str = "ed25519-seed-v2";
const KT_X_SEED: &str = "x25519-seed-v2";
const KT_KYBER_SK: &str = "kyber-mlkem1024-sk-v2";
const KT_DILI_SK: &str = "dilithium-mldsa87-sk-v2";
const KT_ROTATE_NEXT_OLD: &str = "rotate-next-mk-old-v1";
const KT_ROTATE_NEXT_NEW: &str = "rotate-next-mk-new-v1";

const JWT_LABEL: &[u8] = b"lithium/jwt-secret/v1";

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

    fn derive_secret32(&self, _mk: &Byte32, _label: &[u8]) -> Result<Byte32> {
        Err(LithiumError::invalid_credentials("mk_provider_derive_secret32_unused"))
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
        Byte32::from_slice(bytes.expose_as_slice())
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

pub struct KeyManager<P: MkProvider> {
    root_dir: PathBuf,
    pub_dir: PathBuf,
    priv_dir: PathBuf,
    secrets_dir: PathBuf,
    rotate_dir: PathBuf,
    mk_provider: P,
    public_keys: PublicKeys,
    jwt_secret: Byte32,
    rotate_every: Duration,
    next_rotation_at: Instant,
}

#[derive(Clone)]
struct RewrapTarget {
    live_path: PathBuf,
    relative_path: PathBuf,
    key_type: String,
}

#[inline]
fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        if !path.exists() {
            return Ok(());
        }
        let dir = fs::File::open(path).map_err(LithiumError::io)?;
        dir.sync_all().map_err(LithiumError::io)?;
    }
    let _ = path;
    Ok(())
}

#[inline]
fn write_marker(path: &Path, data: &[u8]) -> Result<()> {
    keyfile::write_secure(path, data)?;
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

#[inline]
fn read_pub32(path: &Path) -> Result<Byte32> {
    let bytes = keyfile::read_keyfile_bytes(path)?;
    Byte32::from_slice(bytes.expose_as_slice())
}

#[inline]
fn read_pub_bytes(path: &Path) -> Result<SecretBytes> {
    keyfile::read_keyfile_bytes(path)
}

fn sync_public_cache(pub_dir: &Path, pks: &PublicKeys) -> Result<()> {
    fs::create_dir_all(pub_dir).map_err(LithiumError::io)?;
    keyfile::write_secure(&pub_dir.join(ED_PUB), pks.ed25519.as_slice())?;
    keyfile::write_secure(&pub_dir.join(X_PUB), pks.x25519.as_slice())?;
    keyfile::write_secure(&pub_dir.join(KYBER_PUB), pks.kyber.expose_as_slice())?;
    keyfile::write_secure(&pub_dir.join(DILI_PUB), pks.dilithium.expose_as_slice())?;
    sync_dir(pub_dir)?;
    Ok(())
}

fn load_public_cache(pub_dir: &Path) -> Result<PublicKeys> {
    Ok(PublicKeys {
        ed25519: read_pub32(&pub_dir.join(ED_PUB))?,
        x25519: read_pub32(&pub_dir.join(X_PUB))?,
        kyber: read_pub_bytes(&pub_dir.join(KYBER_PUB))?,
        dilithium: read_pub_bytes(&pub_dir.join(DILI_PUB))?,
    })
}

fn ensure_secret32_keyfile(
    path: &Path,
    mk: &MasterKey32,
    key_type: &str,
    generator: impl FnOnce() -> Result<Byte32>,
) -> Result<Byte32> {
    if path.exists() {
        return keyfile::load_secret32_decrypted(path, mk, key_type);
    }

    let v = generator()?;
    keyfile::save_secret32_encrypted(path, mk, &v, key_type)?;
    Ok(v)
}

fn label_hex(label: &[u8]) -> String {
    hex::encode(label)
}

fn label_key_type(label: &[u8]) -> String {
    format!("secret32:{}", label_hex(label))
}

fn label_key_type_from_hex(hex_label: &str) -> String {
    format!("secret32:{}", hex_label)
}

fn label_secret_path(secrets_dir: &Path, label: &[u8]) -> PathBuf {
    secrets_dir.join(format!("{}.keyf", label_hex(label)))
}

fn load_or_create_label_secret32(
    secrets_dir: &Path,
    mk: &MasterKey32,
    label: &[u8],
) -> Result<Byte32> {
    let path = label_secret_path(secrets_dir, label);
    let key_type = label_key_type(label);

    if path.exists() {
        return keyfile::load_secret32_decrypted(&path, mk, &key_type);
    }

    let v = keys::random_32()?;
    keyfile::save_secret32_encrypted(&path, mk, &v, &key_type)?;
    Ok(v)
}

fn derive_ed25519_pub(seed: &Byte32) -> Byte32 {
    let sk = SigningKey::from_bytes(seed.as_array());
    Byte32::new(sk.verifying_key().to_bytes())
}

fn derive_x25519_pub(seed: &Byte32) -> Byte32 {
    let sk = XStaticSecret::from(*seed.as_array());
    let pk = XPublicKey::from(&sk);
    Byte32::new(pk.to_bytes())
}

fn ensure_asymmetric_material(
    pub_dir: &Path,
    priv_dir: &Path,
    mk: &MasterKey32,
) -> Result<PublicKeys> {
    fs::create_dir_all(pub_dir).map_err(LithiumError::io)?;
    fs::create_dir_all(priv_dir).map_err(LithiumError::io)?;

    let ed_seed = ensure_secret32_keyfile(
        &priv_dir.join(ED_PRIV),
        mk,
        KT_ED_SEED,
        keys::random_fixed::<32>,
    )?;

    let x_seed = ensure_secret32_keyfile(
        &priv_dir.join(X_PRIV),
        mk,
        KT_X_SEED,
        keys::random_fixed::<32>,
    )?;

    let kyber_pub = {
        let priv_path = priv_dir.join(KYBER_PRIV);
        let pub_path = pub_dir.join(KYBER_PUB);
        if priv_path.exists() && pub_path.exists() {
            let _ = keyfile::load_bytes_decrypted(&priv_path, mk, KT_KYBER_SK)?;
            read_pub_bytes(&pub_path)?
        } else if priv_path.exists() || pub_path.exists() {
            return Err(LithiumError::invalid_credentials("keystore_layout_inconsistent"));
        } else {
            let (pk, sk) = mlkem1024::keypair();
            let sk_bytes = SecretBytes::from_slice(sk.as_bytes());
            let pk_bytes = SecretBytes::from_slice(pk.as_bytes());
            keyfile::save_bytes_encrypted(&priv_path, mk, sk_bytes.expose_as_slice(), KT_KYBER_SK)?;
            keyfile::write_secure(&pub_path, pk_bytes.expose_as_slice())?;
            pk_bytes
        }
    };

    let dili_pub = {
        let priv_path = priv_dir.join(DILI_PRIV);
        let pub_path = pub_dir.join(DILI_PUB);
        if priv_path.exists() && pub_path.exists() {
            let _ = keyfile::load_bytes_decrypted(&priv_path, mk, KT_DILI_SK)?;
            read_pub_bytes(&pub_path)?
        } else if priv_path.exists() || pub_path.exists() {
            return Err(LithiumError::invalid_credentials("keystore_layout_inconsistent"));
        } else {
            let (pk, sk) = mldsa87::keypair();
            let sk_bytes = SecretBytes::from_slice(SignSk::as_bytes(&sk));
            let pk_bytes = SecretBytes::from_slice(SignPub::as_bytes(&pk));
            keyfile::save_bytes_encrypted(&priv_path, mk, sk_bytes.expose_as_slice(), KT_DILI_SK)?;
            keyfile::write_secure(&pub_path, pk_bytes.expose_as_slice())?;
            pk_bytes
        }
    };

    let pks = PublicKeys {
        ed25519: derive_ed25519_pub(&ed_seed),
        x25519: derive_x25519_pub(&x_seed),
        kyber: kyber_pub,
        dilithium: dili_pub,
    };

    sync_public_cache(pub_dir, &pks)?;
    Ok(pks)
}

fn has_legacy_or_inconsistent_layout(root_dir: &Path) -> bool {
    root_dir.join(LEGACY_STATE_FILE).exists()
}

fn list_dir_keyfiles(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for ent in fs::read_dir(dir).map_err(LithiumError::io)? {
        let ent = ent.map_err(LithiumError::io)?;
        let path = ent.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("keyf") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn collect_rewrap_targets(root_dir: &Path, priv_dir: &Path, secrets_dir: &Path) -> Result<Vec<RewrapTarget>> {
    let mut out = Vec::new();

    let fixed = [
        (priv_dir.join(ED_PRIV), KT_ED_SEED.to_owned()),
        (priv_dir.join(X_PRIV), KT_X_SEED.to_owned()),
        (priv_dir.join(KYBER_PRIV), KT_KYBER_SK.to_owned()),
        (priv_dir.join(DILI_PRIV), KT_DILI_SK.to_owned()),
    ];

    for (path, key_type) in fixed {
        if path.exists() {
            let relative_path = path
                .strip_prefix(root_dir)
                .map_err(|_| LithiumError::internal())?
                .to_path_buf();
            out.push(RewrapTarget {
                live_path: path,
                relative_path,
                key_type,
            });
        }
    }

    for path in list_dir_keyfiles(secrets_dir)? {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(LithiumError::internal)?
            .to_owned();

        let relative_path = path
            .strip_prefix(root_dir)
            .map_err(|_| LithiumError::internal())?
            .to_path_buf();

        out.push(RewrapTarget {
            live_path: path,
            relative_path,
            key_type: label_key_type_from_hex(&stem),
        });
    }

    out.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(out)
}

fn stage_target_path(rotate_dir: &Path, relative_path: &Path) -> PathBuf {
    rotate_dir.join(ROTATE_STAGE_DIR).join(relative_path)
}

fn cleanup_rotation_dir(rotate_dir: &Path) -> Result<()> {
    if rotate_dir.exists() {
        fs::remove_dir_all(rotate_dir).map_err(LithiumError::io)?;
        if let Some(parent) = rotate_dir.parent() {
            sync_dir(parent)?;
        }
    }
    Ok(())
}

fn apply_staged_files(rotate_dir: &Path, targets: &[RewrapTarget]) -> Result<()> {
    for target in targets {
        let staged_path = stage_target_path(rotate_dir, &target.relative_path);
        let staged = keyfile::read_keyfile_bytes(&staged_path)?;
        keyfile::write_secure(&target.live_path, staged.expose_as_slice())?;
        if let Some(parent) = target.live_path.parent() {
            sync_dir(parent)?;
        }
    }
    Ok(())
}

fn prepare_staged_files(
    rotate_dir: &Path,
    old_mk: &MasterKey32,
    new_mk: &MasterKey32,
    targets: &[RewrapTarget],
) -> Result<()> {
    let staged_root = rotate_dir.join(ROTATE_STAGE_DIR);
    fs::create_dir_all(&staged_root).map_err(LithiumError::io)?;

    for target in targets {
        let out = keyfile::rewrap_keyfile_dek_to_bytes(
            &target.live_path,
            old_mk,
            new_mk,
            &target.key_type,
        )?;
        let staged_path = stage_target_path(rotate_dir, &target.relative_path);
        if let Some(parent) = staged_path.parent() {
            fs::create_dir_all(parent).map_err(LithiumError::io)?;
        }
        keyfile::write_secure(&staged_path, out.expose_as_slice())?;
        if let Some(parent) = staged_path.parent() {
            sync_dir(parent)?;
        }
    }

    sync_dir(&staged_root)?;
    Ok(())
}

fn recover_pending_rotation_if_any<P: MkProvider>(
    root_dir: &Path,
    priv_dir: &Path,
    secrets_dir: &Path,
    rotate_dir: &Path,
    mk_provider: &P,
) -> Result<()> {
    if !rotate_dir.exists() {
        return Ok(());
    }

    let ready_path = rotate_dir.join(ROTATE_READY_FILE);
    if !ready_path.exists() {
        cleanup_rotation_dir(rotate_dir)?;
        return Ok(());
    }

    let targets = collect_rewrap_targets(root_dir, priv_dir, secrets_dir)?;
    let current_mk = mk_provider.load_mk()?;
    let next_old_path = rotate_dir.join(ROTATE_NEXT_OLD_FILE);
    let next_new_path = rotate_dir.join(ROTATE_NEXT_NEW_FILE);

    let (new_mk, provider_already_switched) = if next_new_path.exists() {
        match keyfile::load_secret32_decrypted(&next_new_path, &current_mk, KT_ROTATE_NEXT_NEW) {
            Ok(candidate) => (candidate, true),
            Err(_) => {
                let candidate = keyfile::load_secret32_decrypted(
                    &next_old_path,
                    &current_mk,
                    KT_ROTATE_NEXT_OLD,
                )?;
                (candidate, false)
            }
        }
    } else {
        let candidate = keyfile::load_secret32_decrypted(
            &next_old_path,
            &current_mk,
            KT_ROTATE_NEXT_OLD,
        )?;
        (candidate, false)
    };

    apply_staged_files(rotate_dir, &targets)?;

    if !provider_already_switched {
        mk_provider.store_mk(&new_mk)?;
    }

    cleanup_rotation_dir(rotate_dir)?;
    Ok(())
}

impl<P: MkProvider> KeyManager<P> {
    pub fn start(base_dir: &Path, kind: KeyStoreKind, mk_provider: P) -> Result<Self> {
        let root_dir = base_dir.join(kind.dir_name());
        let pub_dir = root_dir.join(PUB_DIR);
        let priv_dir = root_dir.join(PRIV_DIR);
        let secrets_dir = root_dir.join(SECRETS_DIR);
        let rotate_dir = root_dir.join(ROTATE_DIR);

        fs::create_dir_all(&root_dir).map_err(LithiumError::io)?;
        fs::create_dir_all(&pub_dir).map_err(LithiumError::io)?;
        fs::create_dir_all(&priv_dir).map_err(LithiumError::io)?;
        fs::create_dir_all(&secrets_dir).map_err(LithiumError::io)?;

        match mk_provider.load_mk() {
            Ok(_) => {}
            Err(e) if e.is_not_found() => {
                let new_mk = keys::random_master_key32()?;
                mk_provider.store_mk(&new_mk)?;
            }
            Err(e) => return Err(e),
        }

        if has_legacy_or_inconsistent_layout(&root_dir) {
            return Err(LithiumError::invalid_credentials(
                "legacy_keystore_layout_unsupported",
            ));
        }

        recover_pending_rotation_if_any(
            &root_dir,
            &priv_dir,
            &secrets_dir,
            &rotate_dir,
            &mk_provider,
        )?;

        let root_mk = mk_provider.load_mk()?;

        let public_keys = ensure_asymmetric_material(&pub_dir, &priv_dir, &root_mk)?;
        let jwt_secret = keys::random_32()?;

        Ok(Self {
            root_dir,
            pub_dir,
            priv_dir,
            secrets_dir,
            rotate_dir,
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
    ) -> Result<KeyManager<PlainFileMkProvider>> {
        let mk_path = base_dir.join(kind.dir_name()).join("mk");
        let provider = PlainFileMkProvider::new(mk_path);
        KeyManager::start(base_dir, kind, provider)
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
        self.public_keys = load_public_cache(&self.pub_dir)?;
        Ok(())
    }

    pub fn derive_secret32(&self, label: &[u8]) -> Result<Byte32> {
        if label == JWT_LABEL {
            return Ok(self.jwt_secret.clone());
        }

        let root_mk = self.mk_provider.load_mk()?;
        load_or_create_label_secret32(&self.secrets_dir, &root_mk, label)
    }

    pub fn mk_provider_mut(&mut self) -> &mut P {
        &mut self.mk_provider
    }

    pub fn with_ed_sk<R>(&self, f: impl FnOnce(Byte32) -> Result<R>) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let seed = keyfile::load_secret32_decrypted(&self.priv_dir.join(ED_PRIV), &mk, KT_ED_SEED)?;
        f(seed)
    }

    pub fn with_x25519_sk<R>(&self, f: impl FnOnce(Byte32) -> Result<R>) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let seed = keyfile::load_secret32_decrypted(&self.priv_dir.join(X_PRIV), &mk, KT_X_SEED)?;
        f(seed)
    }

    pub fn with_kyber_sk<R>(&self, f: impl FnOnce(SecretBytes) -> Result<R>) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let sk = keyfile::load_bytes_decrypted(&self.priv_dir.join(KYBER_PRIV), &mk, KT_KYBER_SK)?;
        f(sk)
    }

    pub fn with_dilithium_sk<R>(&self, f: impl FnOnce(SecretBytes) -> Result<R>) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let sk = keyfile::load_bytes_decrypted(&self.priv_dir.join(DILI_PRIV), &mk, KT_DILI_SK)?;
        f(sk)
    }

    pub fn with_x25519_and_kyber_sk<R>(
        &self,
        f: impl FnOnce(Byte32, SecretBytes) -> Result<R>,
    ) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let x_seed = keyfile::load_secret32_decrypted(&self.priv_dir.join(X_PRIV), &mk, KT_X_SEED)?;
        let kyber_sk = keyfile::load_bytes_decrypted(&self.priv_dir.join(KYBER_PRIV), &mk, KT_KYBER_SK)?;
        f(x_seed, kyber_sk)
    }

    pub fn maybe_rotate_mk(&mut self) -> Result<()> {
        recover_pending_rotation_if_any(
            &self.root_dir,
            &self.priv_dir,
            &self.secrets_dir,
            &self.rotate_dir,
            &self.mk_provider,
        )?;

        if Instant::now() < self.next_rotation_at {
            return Ok(());
        }

        cleanup_rotation_dir(&self.rotate_dir)?;
        fs::create_dir_all(&self.rotate_dir).map_err(LithiumError::io)?;
        sync_dir(&self.rotate_dir)?;

        let old_mk = self.mk_provider.load_mk()?;
        let new_mk = keys::random_master_key32()?;
        let targets = collect_rewrap_targets(&self.root_dir, &self.priv_dir, &self.secrets_dir)?;

        let next_old_path = self.rotate_dir.join(ROTATE_NEXT_OLD_FILE);
        let next_new_path = self.rotate_dir.join(ROTATE_NEXT_NEW_FILE);
        keyfile::save_secret32_encrypted(&next_old_path, &old_mk, &new_mk, KT_ROTATE_NEXT_OLD)?;
        keyfile::save_secret32_encrypted(&next_new_path, &new_mk, &new_mk, KT_ROTATE_NEXT_NEW)?;
        sync_dir(&self.rotate_dir)?;

        prepare_staged_files(&self.rotate_dir, &old_mk, &new_mk, &targets)?;
        write_marker(&self.rotate_dir.join(ROTATE_READY_FILE), b"ready")?;

        apply_staged_files(&self.rotate_dir, &targets)?;
        self.mk_provider.store_mk(&new_mk)?;
        self.jwt_secret = keys::random_32()?;
        self.next_rotation_at = Instant::now() + self.rotate_every;

        cleanup_rotation_dir(&self.rotate_dir)?;
        Ok(())
    }
}
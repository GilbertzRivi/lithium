// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use zeroize::Zeroize;

use crate::error::Result;
use crate::secrets::bytes::SecretBytes;

#[derive(Clone)]
pub struct EphemeralStoreManager {
    inner: Arc<Mutex<StoreInner>>,
}

#[derive(Default)]
struct StoreInner {
    map: HashMap<String, StoreEntry>,
    heap: BinaryHeap<HeapEntry>,
    next_version: u64,
}

struct StoreEntry {
    ciphertext: SecretBytes,
    expires_at: Instant,
    version: u64,
}

#[derive(Clone)]
struct HeapEntry {
    expires_at: Instant,
    version: u64,
    key: String,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .expires_at
            .cmp(&self.expires_at)
            .then_with(|| other.version.cmp(&self.version))
            .then_with(|| other.key.cmp(&self.key))
    }
}
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.expires_at == other.expires_at
            && self.version == other.version
            && self.key == other.key
    }
}
impl Eq for HeapEntry {}

impl EphemeralStoreManager {
    pub fn new() -> Result<Self> {
        let inner = Arc::new(Mutex::new(StoreInner::default()));
        let mgr = Self {
            inner: inner.clone(),
        };
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = EphemeralStoreManager::cleanup_once(&inner).await;
            }
        });
        Ok(mgr)
    }

    async fn cleanup_once(inner: &Arc<Mutex<StoreInner>>) -> Result<()> {
        let now = Instant::now();
        let mut guard = inner.lock().await;
        while let Some(top) = guard.heap.peek().cloned() {
            if top.expires_at > now {
                break;
            }
            guard.heap.pop();
            let should_remove = match guard.map.get(&top.key) {
                Some(cur) => cur.version == top.version && cur.expires_at <= now,
                None => false,
            };
            if should_remove && let Some(mut removed) = guard.map.remove(&top.key) {
                removed.ciphertext.expose_as_mut_vec().zeroize();
            }
        }
        Ok(())
    }

    fn next_version(guard: &mut StoreInner) -> u64 {
        let v = guard.next_version;
        guard.next_version = guard.next_version.wrapping_add(1);
        v
    }

    pub async fn set(&self, key: &str, value: &SecretBytes, ttl: Duration) -> Result<()> {
        if ttl.is_zero() {
            return Ok(());
        }
        let expires_at = Instant::now() + ttl;
        let mut guard = self.inner.lock().await;
        let ver = Self::next_version(&mut guard);
        let entry = StoreEntry {
            ciphertext: value.clone(),
            expires_at,
            version: ver,
        };
        guard.map.insert(key.to_owned(), entry);
        guard.heap.push(HeapEntry {
            expires_at,
            version: ver,
            key: key.to_owned(),
        });
        Ok(())
    }

    pub async fn set_if_absent(
        &self,
        key: &str,
        value: &SecretBytes,
        ttl: Duration,
    ) -> Result<bool> {
        let now = Instant::now();
        let expires_at = now + ttl;
        let mut guard = self.inner.lock().await;
        if let Some(e) = guard.map.get(key)
            && e.expires_at > now
        {
            return Ok(false);
        }
        let ver = Self::next_version(&mut guard);
        guard.map.insert(
            key.to_owned(),
            StoreEntry {
                ciphertext: value.clone(),
                expires_at,
                version: ver,
            },
        );
        guard.heap.push(HeapEntry {
            expires_at,
            version: ver,
            key: key.to_owned(),
        });
        Ok(true)
    }

    pub async fn peek(&self, key: &str) -> Result<Option<SecretBytes>> {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        if let Some(entry) = guard.map.get(key) {
            if entry.expires_at <= now {
                let _ = guard.map.remove(key);
                return Ok(None);
            }
            return Ok(Some(entry.ciphertext.clone()));
        }
        Ok(None)
    }

    pub async fn take(&self, key: &str) -> Result<Option<SecretBytes>> {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        let Some(mut entry) = guard.map.remove(key) else {
            return Ok(None);
        };
        if entry.expires_at <= now {
            entry.ciphertext.expose_as_mut_vec().zeroize();
            return Ok(None);
        }
        Ok(Some(entry.ciphertext))
    }

    pub async fn del(&self, key: &str) -> Result<()> {
        let mut guard = self.inner.lock().await;
        if let Some(mut entry) = guard.map.remove(key) {
            entry.ciphertext.expose_as_mut_vec().zeroize();
        }
        Ok(())
    }
}

pub fn hash_sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

use std::time::Duration;

use lithium_core::secrets::SecretBytes;
use lithium_core::utils::store::EphemeralStoreManager;

fn sb(data: &[u8]) -> SecretBytes {
    SecretBytes::from_slice(data)
}

#[tokio::test]
async fn store_set_and_peek() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_secs(60);

    store.set("key1", &sb(b"value1"), ttl).await.unwrap();
    let found = store.peek("key1").await.unwrap();

    assert!(found.is_some());
    assert_eq!(found.unwrap().expose_as_slice(), b"value1");
}

#[tokio::test]
async fn store_peek_missing_key_returns_none() {
    let store = EphemeralStoreManager::new().unwrap();
    let result = store.peek("nonexistent").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn store_take_removes_value() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_secs(60);

    store.set("takekey", &sb(b"takeval"), ttl).await.unwrap();
    let first = store.take("takekey").await.unwrap();
    let second = store.take("takekey").await.unwrap();

    assert!(first.is_some());
    assert_eq!(first.unwrap().expose_as_slice(), b"takeval");
    assert!(
        second.is_none(),
        "second take must return None after removal"
    );
}

#[tokio::test]
async fn store_del_removes_value() {
    let store = EphemeralStoreManager::new().unwrap();
    store
        .set("delkey", &sb(b"delval"), Duration::from_secs(60))
        .await
        .unwrap();

    store.del("delkey").await.unwrap();
    let result = store.peek("delkey").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn store_del_missing_key_is_noop() {
    let store = EphemeralStoreManager::new().unwrap();
    // Should not panic or error
    store.del("does-not-exist").await.unwrap();
}

#[tokio::test]
async fn store_set_overwrites_existing() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_secs(60);

    store.set("k", &sb(b"old"), ttl).await.unwrap();
    store.set("k", &sb(b"new"), ttl).await.unwrap();

    let result = store.peek("k").await.unwrap().unwrap();
    assert_eq!(result.expose_as_slice(), b"new");
}

#[tokio::test]
async fn store_set_if_absent_inserts_when_absent() {
    let store = EphemeralStoreManager::new().unwrap();
    let inserted = store
        .set_if_absent("fresh", &sb(b"val"), Duration::from_secs(60))
        .await
        .unwrap();

    assert!(inserted, "should return true when key was absent");
    let got = store.peek("fresh").await.unwrap().unwrap();
    assert_eq!(got.expose_as_slice(), b"val");
}

#[tokio::test]
async fn store_set_if_absent_does_not_overwrite() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_secs(60);

    store.set("dup", &sb(b"first"), ttl).await.unwrap();
    let inserted = store
        .set_if_absent("dup", &sb(b"second"), ttl)
        .await
        .unwrap();

    assert!(!inserted, "should return false when key already exists");
    let got = store.peek("dup").await.unwrap().unwrap();
    assert_eq!(
        got.expose_as_slice(),
        b"first",
        "original value must be unchanged"
    );
}

#[tokio::test]
async fn store_peek_does_not_remove() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_secs(60);

    store.set("peekonly", &sb(b"data"), ttl).await.unwrap();

    let first = store.peek("peekonly").await.unwrap();
    let second = store.peek("peekonly").await.unwrap();

    assert!(first.is_some());
    assert!(second.is_some(), "peek must not consume the entry");
}

#[tokio::test]
async fn store_expired_entry_not_returned_by_take() {
    let store = EphemeralStoreManager::new().unwrap();
    // TTL of 1 ms — will expire immediately
    store
        .set("exp", &sb(b"gone"), Duration::from_millis(1))
        .await
        .unwrap();

    // Wait long enough for the entry to expire
    tokio::time::sleep(Duration::from_millis(20)).await;

    let result = store.take("exp").await.unwrap();
    assert!(result.is_none(), "expired entry must return None");
}

#[tokio::test]
async fn store_expired_entry_not_returned_by_peek() {
    let store = EphemeralStoreManager::new().unwrap();
    store
        .set("exppeek", &sb(b"gone"), Duration::from_millis(1))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;

    let result = store.peek("exppeek").await.unwrap();
    assert!(
        result.is_none(),
        "expired entry must not be visible via peek"
    );
}

#[tokio::test]
async fn store_zero_ttl_not_stored() {
    let store = EphemeralStoreManager::new().unwrap();
    // TTL of zero → set() is a no-op per implementation
    store
        .set("zero", &sb(b"val"), Duration::ZERO)
        .await
        .unwrap();

    let result = store.peek("zero").await.unwrap();
    assert!(result.is_none(), "zero-TTL entry should not be present");
}

#[tokio::test]
async fn store_multiple_independent_keys() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_secs(60);

    store.set("a", &sb(b"alpha"), ttl).await.unwrap();
    store.set("b", &sb(b"beta"), ttl).await.unwrap();
    store.set("c", &sb(b"gamma"), ttl).await.unwrap();

    assert_eq!(
        store.peek("a").await.unwrap().unwrap().expose_as_slice(),
        b"alpha"
    );
    assert_eq!(
        store.peek("b").await.unwrap().unwrap().expose_as_slice(),
        b"beta"
    );
    assert_eq!(
        store.peek("c").await.unwrap().unwrap().expose_as_slice(),
        b"gamma"
    );
}

#[tokio::test]
async fn store_set_if_absent_allows_reinsertion_after_expiry() {
    let store = EphemeralStoreManager::new().unwrap();
    let ttl = Duration::from_millis(5);

    let first = store.set_if_absent("key", &sb(b"v1"), ttl).await.unwrap();
    assert!(first);

    // Let it expire
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Now should be able to insert again
    let second = store
        .set_if_absent("key", &sb(b"v2"), Duration::from_secs(60))
        .await
        .unwrap();
    assert!(second, "should succeed after original TTL expired");
    assert_eq!(
        store.peek("key").await.unwrap().unwrap().expose_as_slice(),
        b"v2"
    );
}

use lithium_core::crypto::keys;
use lithium_itest::helpers::{TestServer, random_dek_hex, unique_handle};

async fn authenticated_client(
    srv: &TestServer,
    prefix: &str,
) -> lithium_itest::client::TestLithiumClient {
    let handle = unique_handle(prefix);
    let dek = random_dek_hex();
    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;
    c.login(&handle, "Password1!").await;
    c
}

#[tokio::test]
async fn test_16_byte_mailbox_accepted() {
    let srv = TestServer::start().await;
    let mut c = authenticated_client(&srv, "mb16").await;
    let mailbox = hex::encode([0xaau8; 16]);
    c.send_message(&mailbox, &hex::encode(b"hi")).await;

    let mut f = srv.client();
    f.generate_user_keys();
    let r = f.fetch_messages(&mailbox).await;
    assert_eq!(r.body["data"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_8_byte_mailbox_rejected_on_send() {
    let srv = TestServer::start().await;
    let mut c = authenticated_client(&srv, "mb8s").await;
    let raw = c.send_message_raw(&hex::encode([0xaau8; 8]), &hex::encode(b"hi")).await;
    assert_eq!(raw.status, 400);
    assert_eq!(raw.error.as_deref(), Some("invalid_mailbox"));
}

#[tokio::test]
async fn test_8_byte_mailbox_rejected_on_fetch() {
    let srv = TestServer::start().await;
    let mut c = srv.client();
    c.generate_user_keys();
    let raw = c.fetch_messages_raw(&hex::encode([0xaau8; 8])).await;
    assert_eq!(raw.status, 400);
    assert_eq!(raw.error.as_deref(), Some("invalid_mailbox"));
}

#[tokio::test]
async fn test_odd_length_hex_content_rejected() {
    let srv = TestServer::start().await;
    let mut c = authenticated_client(&srv, "oddcnt").await;
    let mailbox = hex::encode(keys::random_32().unwrap().as_slice());
    let raw = c.send_message_raw(&mailbox, "abc").await;
    assert_eq!(raw.status, 400);
    assert_eq!(raw.error.as_deref(), Some("invalid_content"));
}

#[tokio::test]
async fn test_empty_content_round_trips() {
    // hex("") = "" — server must store and return zero bytes without error.
    let srv = TestServer::start().await;
    let mut c = authenticated_client(&srv, "emptycnt").await;
    let mailbox = hex::encode(keys::random_32().unwrap().as_slice());
    c.send_message(&mailbox, "").await;

    let mut f = srv.client();
    f.generate_user_keys();
    let r = f.fetch_messages(&mailbox).await;
    assert_eq!(r.body["data"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_fetch_preserves_send_order() {
    // Messages are stored with an auto-increment PK and fetched ORDER BY id ASC.
    let srv = TestServer::start().await;
    let mailbox = hex::encode(keys::random_32().unwrap().as_slice());

    for payload in [b"first" as &[u8], b"second", b"third"] {
        let mut c = authenticated_client(&srv, "ord").await;
        c.send_message(&mailbox, &hex::encode(payload)).await;
    }

    let mut f = srv.client();
    f.generate_user_keys();
    let r = f.fetch_messages(&mailbox).await;
    let data = r.body["data"].as_array().unwrap();
    assert_eq!(data.len(), 3);

    let got: Vec<Vec<u8>> = data
        .iter()
        .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
        .collect();

    assert_eq!(got[0], b"first");
    assert_eq!(got[1], b"second");
    assert_eq!(got[2], b"third");
}

#[tokio::test]
async fn test_messages_persist_after_sender_deletes_account() {
    // Messages are not owned by the sender row; deleting the account must not
    // cascade to in-flight messages.
    let srv = TestServer::start().await;
    let mailbox = hex::encode(keys::random_32().unwrap().as_slice());

    let mut sender = authenticated_client(&srv, "delsndr").await;
    sender.send_message(&mailbox, &hex::encode(b"orphan")).await;
    sender.delete().await;

    let mut f = srv.client();
    f.generate_user_keys();
    let r = f.fetch_messages(&mailbox).await;
    let data = r.body["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(hex::decode(data[0].as_str().unwrap()).unwrap(), b"orphan");
}

#[tokio::test]
async fn test_send_with_poisoned_jwt_rejected() {
    let srv = TestServer::start().await;
    let mut c = authenticated_client(&srv, "poisonsend").await;
    let mailbox = hex::encode(keys::random_32().unwrap().as_slice());
    c.poison_jwt().await;
    let raw = c.send_message_raw(&mailbox, &hex::encode(b"nope")).await;
    assert_eq!(raw.status, 401);
}
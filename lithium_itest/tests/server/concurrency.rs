use lithium_core::crypto::keys;
use lithium_itest::helpers::{TestServer, random_dek_hex, unique_handle};

#[tokio::test]
async fn test_concurrent_fetch_same_mailbox_atomic() {
    // get_messages runs SELECT FOR UPDATE SKIP LOCKED + DELETE in one transaction.
    // A second concurrent fetcher must see an empty set, not duplicate messages.
    let srv = TestServer::start().await;
    let mailbox = hex::encode(keys::random_32().unwrap().as_slice());

    let handle = unique_handle("concsndr");
    let mut sender = srv.client();
    sender.generate_user_keys();
    sender.register(&handle, "Password1!", &random_dek_hex()).await;
    sender.login(&handle, "Password1!").await;
    sender.send_message(&mailbox, &hex::encode(b"singleton")).await;

    let mut f1 = srv.client();
    let mut f2 = srv.client();
    f1.generate_user_keys();
    f2.generate_user_keys();

    let (r1, r2) = tokio::join!(f1.fetch_messages(&mailbox), f2.fetch_messages(&mailbox));

    let n1 = r1.body["data"].as_array().unwrap().len();
    let n2 = r2.body["data"].as_array().unwrap().len();
    assert_eq!(n1 + n2, 1, "message delivered {} + {} times", n1, n2);
}

#[tokio::test]
async fn test_concurrent_register_same_handle_one_wins() {
    // Both requests may pass the exists-check before either inserts; the UNIQUE
    // constraint on the encrypted user ID ensures exactly one INSERT succeeds.
    let srv = TestServer::start().await;
    let handle = unique_handle("concreg");
    let dek = random_dek_hex();

    let mut c1 = srv.client();
    let mut c2 = srv.client();
    c1.generate_user_keys();
    c2.generate_user_keys();

    let (r1, r2) = tokio::join!(
        c1.register_raw(&handle, "Password1!", &dek),
        c2.register_raw(&handle, "Password1!", &dek)
    );

    let successes = u32::from(r1.status == 200) + u32::from(r2.status == 200);
    assert_eq!(successes, 1, "statuses: {}, {}", r1.status, r2.status);

    let loser = if r1.status != 200 { &r1 } else { &r2 };
    assert_eq!(loser.error.as_deref(), Some("user_exists"));
}

#[tokio::test]
async fn test_concurrent_send_both_stored() {
    use lithium_itest::client::TestLithiumClient;

    let srv = TestServer::start().await;
    let mailbox = hex::encode(keys::random_32().unwrap().as_slice());

    async fn send_as(
        base: String,
        bootstrap: lithium_itest::client::ServerBootstrap,
        prefix: &str,
        mailbox: String,
        payload: &[u8],
    ) {
        let handle = unique_handle(prefix);
        let dek = random_dek_hex();
        let mut c = TestLithiumClient::new(base, bootstrap);
        c.generate_user_keys();
        c.register(&handle, "Password1!", &dek).await;
        c.login(&handle, "Password1!").await;
        c.send_message(&mailbox, &hex::encode(payload)).await;
    }

    let base = format!("http://{}", srv.addr);
    tokio::join!(
        send_as(base.clone(), srv.bootstrap.clone(), "concsnd1", mailbox.clone(), b"one"),
        send_as(base.clone(), srv.bootstrap.clone(), "concsnd2", mailbox.clone(), b"two")
    );

    let mut f = srv.client();
    f.generate_user_keys();
    let r = f.fetch_messages(&mailbox).await;
    assert_eq!(r.body["data"].as_array().unwrap().len(), 2);
}

// JWT single-use under concurrent load is not testable here without access to
// the raw token string: EphemeralStoreManager does not expose it and the client
// takes (not peeks) the token before sending. The store.take() atomicity is the
// same primitive used by the fetch transaction above, so the property is covered
// transitively. Do not "fix" this by injecting a dummy token string — that would
// bypass the actual code path.
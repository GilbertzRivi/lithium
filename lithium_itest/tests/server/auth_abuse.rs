// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_itest::helpers::{TestServer, random_dek_hex, unique_handle};

#[tokio::test]
async fn test_login_wrong_signing_keys_rejected() {
    // LoginByHandler verifies the signature against stored keys, not the ones
    // presented in the request — different failure path than wrong password.
    let srv = TestServer::start().await;
    let handle = unique_handle("sigfail");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;

    let mut c2 = srv.client();
    c2.generate_user_keys();
    let raw = c2.login_raw(&handle, "Password1!").await;
    assert_eq!(raw.status, 401);
    assert_eq!(raw.error.as_deref(), Some("invalid_credentials"));
}

#[tokio::test]
async fn test_login_case_normalised_handler_resolves_same_user() {
    // uuid5_from_handler lowercases before hashing, so the DB key is the same
    // regardless of the case used at login time.
    let srv = TestServer::start().await;
    let base = unique_handle("norm");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&base, "Password1!", &dek).await;

    let mut c2 = srv.client();
    c2.copy_keys_from(&c);
    let r = c2.login(&base.to_uppercase(), "Password1!").await;
    assert_eq!(r.body["msg"].as_str().unwrap_or(""), "Ok");
    assert_eq!(r.body["dek"].as_str().expect("dek"), dek);
}

#[tokio::test]
async fn test_login_success_resets_fail_counter() {
    // login_rate_limit_success deletes the fail-count key. Without the reset,
    // 4+4 failures would cross the threshold of 5 and the test would fail.
    let srv = TestServer::start().await;
    let handle = unique_handle("resetctr");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;

    for _ in 0..4 {
        let mut cx = srv.client();
        cx.copy_keys_from(&c);
        cx.login_raw(&handle, "BadPassword!").await;
    }

    let mut cx = srv.client();
    cx.copy_keys_from(&c);
    cx.login(&handle, "Password1!").await;

    for _ in 0..4 {
        let mut cx = srv.client();
        cx.copy_keys_from(&c);
        cx.login_raw(&handle, "BadPassword!").await;
    }

    let mut cx = srv.client();
    cx.copy_keys_from(&c);
    let raw = cx.login_raw(&handle, "Password1!").await;
    assert_eq!(raw.status, 200);
}

#[tokio::test]
async fn test_revoke_same_capability_twice_is_silent() {
    let srv = TestServer::start().await;
    let handle = unique_handle("revoke2");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    let reg = c.register(&handle, "Password1!", &dek).await;
    let cap = reg.body["capability"]
        .as_str()
        .expect("capability")
        .to_owned();

    let mut c1 = srv.client();
    c1.generate_user_keys();
    c1.revoke(&cap).await;

    let mut c2 = srv.client();
    c2.generate_user_keys();
    c2.revoke(&cap).await;
}

#[tokio::test]
async fn test_login_failure_modes_indistinguishable() {
    // Wrong password and unknown user must return the same error code.
    // A difference here leaks user existence to an unauthenticated caller.
    let srv = TestServer::start().await;
    let handle = unique_handle("errcmp");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    c.register(&handle, "Password1!", &dek).await;

    let mut cx = srv.client();
    cx.copy_keys_from(&c);
    let wrong_pw = cx.login_raw(&handle, "WrongPassword!").await;

    let mut cy = srv.client();
    cy.generate_user_keys();
    let unknown = cy.login_raw(&unique_handle("ghost"), "Password1!").await;

    assert_eq!(wrong_pw.status, 401);
    assert_eq!(unknown.status, 401);
    assert_eq!(wrong_pw.error, unknown.error);
}

#[tokio::test]
async fn test_delete_frees_handle_for_reregistration() {
    let srv = TestServer::start().await;
    let handle = unique_handle("reclaim");
    let dek = random_dek_hex();

    let mut c = srv.client();
    c.generate_user_keys();
    let reg1 = c.register(&handle, "Password1!", &dek).await;
    let cap1 = reg1.body["capability"].as_str().unwrap().to_owned();
    c.login(&handle, "Password1!").await;
    c.delete().await;

    let mut c2 = srv.client();
    c2.generate_user_keys();
    let reg2 = c2.register(&handle, "Password2!", &dek).await;
    let cap2 = reg2.body["capability"].as_str().expect("new capability");
    assert_ne!(cap1, cap2);

    let mut cx = srv.client();
    cx.generate_user_keys();
    cx.revoke(&cap1).await;

    let mut cy = srv.client();
    cy.copy_keys_from(&c2);
    let r = cy.login(&handle, "Password2!").await;
    assert_eq!(r.body["msg"].as_str().unwrap_or(""), "Ok");
}

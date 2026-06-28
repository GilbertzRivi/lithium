// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::error::CryptoErrorKind;
use lithium_core::opaque::dek::{unwrap_dek_under_export_key, wrap_dek_under_export_key};
use lithium_core::passwords::passwords::{
    PasswordPolicy, generate_dek, validate_password, validate_passwords_distinct,
};
use lithium_core::secrets::{Byte64, SecretString};

const TEST_DEK_AAD: &[u8] = b"lithium-core/test/dek-wrap";

fn pass(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

fn default_policy() -> PasswordPolicy {
    PasswordPolicy::default()
}

fn export_key(seed: u8) -> Byte64 {
    Byte64::from_slice(&[seed; 64]).unwrap()
}

#[test]
fn password_valid_default_policy() {
    assert!(validate_password(&pass("Passw0rd!Abc"), default_policy()).is_ok());
}

#[test]
fn password_too_short() {
    let err = validate_password(&pass("Ab1!"), default_policy()).unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::StringPolicy);
}

#[test]
fn password_too_long() {
    let long = "Aa1!".repeat(300);
    let err = validate_password(&pass(&long), default_policy()).unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::StringPolicy);
}

#[test]
fn password_missing_lowercase() {
    let err = validate_password(&pass("PASSW0RD!ABC"), default_policy()).unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::StringPolicy);
}

#[test]
fn password_missing_uppercase() {
    let err = validate_password(&pass("passw0rd!abc"), default_policy()).unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::StringPolicy);
}

#[test]
fn password_missing_digit() {
    let err = validate_password(&pass("Password!Abc"), default_policy()).unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::StringPolicy);
}

#[test]
fn password_missing_special() {
    let err = validate_password(&pass("Password1Abc"), default_policy()).unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::StringPolicy);
}

#[test]
fn password_with_whitespace_rejected_by_default() {
    let err = validate_password(&pass("Pass w0rd!Ab"), default_policy()).unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::StringPolicy);
}

#[test]
fn password_with_whitespace_allowed_when_permitted() {
    let mut pol = default_policy();
    pol.allow_whitespace = true;
    assert!(validate_password(&pass("Pass w0rd!Ab"), pol).is_ok());
}

#[test]
fn password_custom_policy_no_special_required() {
    let pol = PasswordPolicy {
        require_special: false,
        ..default_policy()
    };
    assert!(validate_password(&pass("Password1Abc"), pol).is_ok());
}

#[test]
fn password_custom_policy_short_min() {
    let pol = PasswordPolicy {
        min_len: 4,
        require_uppercase: false,
        require_digit: false,
        require_special: false,
        ..default_policy()
    };
    assert!(validate_password(&pass("abcd"), pol).is_ok());
}

#[test]
fn password_exactly_min_length() {
    assert!(validate_password(&pass("Passw0rd!Ab2"), default_policy()).is_ok());
}

#[test]
fn passwords_distinct_ok() {
    assert!(validate_passwords_distinct(&pass("first"), &pass("second")).is_ok());
}

#[test]
fn passwords_distinct_same_fails() {
    let err = validate_passwords_distinct(&pass("same"), &pass("same")).unwrap_err();
    assert!(matches!(
        err.kind,
        CryptoErrorKind::InvalidCredentials { .. }
    ));
}

#[test]
fn dek_generate_32_bytes() {
    let dek = generate_dek().unwrap();
    assert_eq!(dek.as_slice().len(), 32);
}

#[test]
fn dek_generate_unique() {
    let d1 = generate_dek().unwrap();
    let d2 = generate_dek().unwrap();
    assert_ne!(d1, d2);
}

#[test]
fn dek_wrap_unwrap_roundtrip() {
    let dek = generate_dek().unwrap();
    let ek = export_key(7);

    let wrapped = wrap_dek_under_export_key(&dek, &ek, TEST_DEK_AAD).unwrap();
    let unwrapped = unwrap_dek_under_export_key(&wrapped, &ek, TEST_DEK_AAD).unwrap();

    assert_eq!(dek, unwrapped);
}

#[test]
fn dek_wrap_wrong_export_key_fails() {
    let dek = generate_dek().unwrap();
    let wrapped = wrap_dek_under_export_key(&dek, &export_key(1), TEST_DEK_AAD).unwrap();
    assert!(unwrap_dek_under_export_key(&wrapped, &export_key(2), TEST_DEK_AAD).is_err());
}

#[test]
fn dek_wrap_produces_hex() {
    let dek = generate_dek().unwrap();
    let wrapped = wrap_dek_under_export_key(&dek, &export_key(3), TEST_DEK_AAD).unwrap();
    let hex_str = wrapped.expose();
    assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(hex_str.len() % 2, 0);
}

#[test]
fn dek_wrap_fresh_nonce_each_time() {
    let dek = generate_dek().unwrap();
    let ek = export_key(4);
    let w1 = wrap_dek_under_export_key(&dek, &ek, TEST_DEK_AAD).unwrap();
    let w2 = wrap_dek_under_export_key(&dek, &ek, TEST_DEK_AAD).unwrap();
    assert_ne!(w1.expose(), w2.expose());
}

#[test]
fn dek_unwrap_truncated_blob_fails() {
    let short_blob = SecretString::new("aabbccdd".to_owned());
    assert!(unwrap_dek_under_export_key(&short_blob, &export_key(5), TEST_DEK_AAD).is_err());
}

use lithium_core::error::CryptoErrorKind;
use lithium_core::passwords::passwords::{
    PasswordPolicy, generate_dek, hash_password_phc, unwrap_dek_from_server_hex, validate_password,
    validate_passwords_distinct, verify_password_phc, wrap_dek_for_server_hex,
};
use lithium_core::secrets::SecretString;

fn pass(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

fn default_policy() -> PasswordPolicy {
    PasswordPolicy::default()
}

// ════════════════════════════════════════════════════════════════════════════
// PasswordPolicy validation
// ════════════════════════════════════════════════════════════════════════════

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
    let long = "Aa1!".repeat(300); // 1200 chars, limit is 1024
    let err = validate_password(&pass(&long), default_policy()).unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::StringPolicy);
}

#[test]
fn password_missing_lowercase() {
    // All uppercase + digit + special
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
    // Default policy: allow_whitespace = false
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
    // min_len = 12, exactly 12 chars that satisfy all requirements
    assert!(validate_password(&pass("Passw0rd!Ab2"), default_policy()).is_ok());
}

// ── distinctness ─────────────────────────────────────────────────────────────

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

// ════════════════════════════════════════════════════════════════════════════
// Password hashing (Argon2id) — slow tests, ~1-3s each
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn hash_password_and_verify_correct() {
    let pw = pass("Correct!Horse7Battery");
    let phc = hash_password_phc(&pw).unwrap();
    assert!(
        phc.starts_with("$argon2id$"),
        "PHC string must use argon2id"
    );
    assert!(verify_password_phc(&phc, &pw).unwrap());
}

#[test]
fn hash_password_wrong_password_fails() {
    let pw = pass("Correct!Horse7Battery");
    let phc = hash_password_phc(&pw).unwrap();
    let wrong = pass("Wrong!Horse7Battery");
    assert!(!verify_password_phc(&phc, &wrong).unwrap());
}

#[test]
fn hash_password_unique_salts() {
    let pw = pass("Passw0rd!");
    let phc1 = hash_password_phc(&pw).unwrap();
    let phc2 = hash_password_phc(&pw).unwrap();
    // Different salts → different PHC strings
    assert_ne!(phc1, phc2);
}

#[test]
fn verify_invalid_phc_string() {
    let err = verify_password_phc("not-a-phc-string", &pass("Passw0rd!")).unwrap_err();
    assert!(matches!(
        err.kind,
        CryptoErrorKind::InvalidCredentials { .. }
    ));
}

// ════════════════════════════════════════════════════════════════════════════
// DEK wrap / unwrap — slow tests (Argon2id), ~2-5s each
// ════════════════════════════════════════════════════════════════════════════

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
    let pw = pass("Roundtrip1Password!");

    let wrapped = wrap_dek_for_server_hex(&dek, &pw).unwrap();
    let unwrapped = unwrap_dek_from_server_hex(&wrapped, &pw).unwrap();

    assert_eq!(dek, unwrapped);
}

#[test]
fn dek_wrap_wrong_password_fails() {
    let dek = generate_dek().unwrap();
    let pw = pass("Correct1Password!");
    let wrong_pw = pass("Wrong1Password!!");

    let wrapped = wrap_dek_for_server_hex(&dek, &pw).unwrap();
    let result = unwrap_dek_from_server_hex(&wrapped, &wrong_pw);
    assert!(result.is_err());
}

#[test]
fn dek_wrap_produces_hex() {
    let dek = generate_dek().unwrap();
    let pw = pass("Test1Password!");

    let wrapped = wrap_dek_for_server_hex(&dek, &pw).unwrap();
    let hex_str = wrapped.expose();
    // Must be valid hex
    assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
    // Must be even length
    assert_eq!(hex_str.len() % 2, 0);
}

#[test]
fn dek_wrap_different_salts_each_time() {
    let dek = generate_dek().unwrap();
    let pw = pass("Test1Password!");

    let w1 = wrap_dek_for_server_hex(&dek, &pw).unwrap();
    let w2 = wrap_dek_for_server_hex(&dek, &pw).unwrap();
    // Different random salts → different ciphertexts
    assert_ne!(w1.expose(), w2.expose());
}

#[test]
fn dek_unwrap_truncated_blob_fails() {
    // Provide a very short hex blob (too short to be valid)
    let short_blob = SecretString::new("aabbccdd".to_owned());
    let pw = pass("Test1Password!");
    let result = unwrap_dek_from_server_hex(&short_blob, &pw);
    assert!(result.is_err());
}

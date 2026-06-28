// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::error::CryptoErrorKind;
use lithium_core::secrets::{Byte12, Byte32, Byte64, SecretBytes, SecretJson, SecretString};

#[test]
fn fixed_bytes_new_and_as_slice() {
    let b = Byte32::new([0xAA; 32]);
    assert_eq!(b.as_slice(), &[0xAAu8; 32]);
}

#[test]
fn fixed_bytes_from_slice_ok() {
    let data = [0x11u8; 32];
    let b = Byte32::from_slice(&data).unwrap();
    assert_eq!(b.as_slice(), &data);
}

#[test]
fn fixed_bytes_from_slice_wrong_length() {
    let err = Byte32::from_slice(&[0u8; 16]).unwrap_err();
    assert!(matches!(
        err.kind,
        CryptoErrorKind::InvalidLength {
            expected: 32,
            got: 16
        }
    ));
}

#[test]
fn fixed_bytes_from_slice_too_long() {
    let err = Byte32::from_slice(&[0u8; 64]).unwrap_err();
    assert!(matches!(
        err.kind,
        CryptoErrorKind::InvalidLength {
            expected: 32,
            got: 64
        }
    ));
}

#[test]
fn fixed_bytes_new_zeroed() {
    let b = Byte32::new_zeroed();
    assert_eq!(b.as_slice(), &[0u8; 32]);
}

#[test]
fn fixed_bytes_clone() {
    let original = Byte32::new([0x55; 32]);
    let cloned = original.clone();
    assert_eq!(original.as_slice(), cloned.as_slice());
}

#[test]
fn fixed_bytes_eq_same() {
    let a = Byte32::new([0x77; 32]);
    let b = Byte32::new([0x77; 32]);
    assert_eq!(a, b);
}

#[test]
fn fixed_bytes_eq_different() {
    let a = Byte32::new([0x77; 32]);
    let b = Byte32::new([0x88; 32]);
    assert_ne!(a, b);
}

#[test]
fn fixed_bytes_from_array() {
    let arr = [0x33u8; 32];
    let b: Byte32 = arr.into();
    assert_eq!(b.as_slice(), &arr);
}

#[test]
fn fixed_bytes_try_from_slice() {
    use std::convert::TryFrom;
    let data = [0x44u8; 32];
    let b = Byte32::try_from(data.as_slice()).unwrap();
    assert_eq!(b.as_slice(), &data);
}

#[test]
fn fixed_bytes_as_ref() {
    let b = Byte32::new([0x22; 32]);
    let slice: &[u8] = b.as_ref();
    assert_eq!(slice, &[0x22u8; 32]);
}

#[test]
fn fixed_bytes_len_const() {
    assert_eq!(Byte32::LEN, 32);
    assert_eq!(Byte12::LEN, 12);
    assert_eq!(Byte64::LEN, 64);
}

#[test]
fn fixed_bytes_debug_redacted() {
    let b = Byte32::new([0xFF; 32]);
    let s = format!("{:?}", b);
    assert!(!s.contains("ff"), "Debug must not reveal bytes: {s}");
    assert!(s.contains("FixedBytes"));
}

#[test]
fn fixed_bytes_to_hex_roundtrip() {
    let original = Byte32::new([0xDE; 32]);
    let hex_str = original.to_hex();
    let recovered = Byte32::from_hex(hex_str.expose()).unwrap();
    assert_eq!(original, recovered);
}

#[test]
fn fixed_bytes_from_hex_correct_length() {
    let valid = "deadbeef".repeat(8);
    let b = Byte32::from_hex(&valid).unwrap();
    assert_eq!(b.as_slice().len(), 32);
}

#[test]
fn fixed_bytes_from_hex_0x_prefix_rejected() {
    let err = Byte32::from_hex("0xdeadbeef").unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::HexDisallowedPrefix);
}

#[test]
fn fixed_bytes_from_hex_uppercase_rejected() {
    let upper = "DEADBEEF".repeat(8);
    let err = Byte32::from_hex(&upper).unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::HexMustBeLowercase);
}

#[test]
fn fixed_bytes_from_hex_wrong_length_rejected() {
    let short = "deadbeef";
    let err = Byte32::from_hex(short).unwrap_err();
    assert!(matches!(
        err.kind,
        CryptoErrorKind::InvalidHexLength { expected: 64, .. }
    ));
}

#[test]
fn fixed_bytes_from_hex_invalid_char_rejected() {
    // 62 valid chars + 2 invalid
    let mut hex = "aa".repeat(31);
    hex.push_str("zz");
    let err = Byte32::from_hex(&hex).unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::InvalidHex);
}

#[test]
fn from_hex_multibyte_input_errors_without_panic() {
    let multibyte = "砜砜";
    assert!(Byte32::from_hex(multibyte).is_err());
    assert!(SecretBytes::from_hex(multibyte).is_err());
}

#[test]
fn secret_bytes_from_slice() {
    let data = b"hello world";
    let sb = SecretBytes::from_slice(data);
    assert_eq!(sb.expose_as_slice(), data);
}

#[test]
fn secret_bytes_len() {
    let sb = SecretBytes::from_slice(b"abcde");
    assert_eq!(sb.len(), 5);
}

#[test]
fn secret_bytes_is_empty_false() {
    let sb = SecretBytes::from_slice(b"x");
    assert!(!sb.is_empty());
}

#[test]
fn secret_bytes_is_empty_true() {
    let sb = SecretBytes::from_slice(b"");
    assert!(sb.is_empty());
}

#[test]
fn secret_bytes_clone() {
    let original = SecretBytes::from_slice(b"clone me");
    let cloned = original.clone();
    assert_eq!(original.expose_as_slice(), cloned.expose_as_slice());
}

#[test]
fn secret_bytes_debug_redacted() {
    let sb = SecretBytes::from_slice(b"top secret");
    let s = format!("{:?}", sb);
    assert!(!s.contains("top secret"), "Debug must not reveal data: {s}");
    assert!(s.contains("SecretBytes"));
}

#[test]
fn secret_bytes_as_ref() {
    let sb = SecretBytes::from_slice(b"data");
    let r: &[u8] = sb.as_ref();
    assert_eq!(r, b"data");
}

#[test]
fn secret_bytes_to_hex_from_hex_roundtrip() {
    let original = SecretBytes::from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    let hex = original.to_hex();
    let recovered = SecretBytes::from_hex(hex.expose()).unwrap();
    assert_eq!(original.expose_as_slice(), recovered.expose_as_slice());
}

#[test]
fn secret_bytes_from_hex_0x_prefix_rejected() {
    let err = SecretBytes::from_hex("0xdeadbeef").unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::HexDisallowedPrefix);
}

#[test]
fn secret_bytes_from_hex_uppercase_rejected() {
    let err = SecretBytes::from_hex("DEADBEEF").unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::HexMustBeLowercase);
}

#[test]
fn secret_bytes_from_hex_odd_length_rejected() {
    let err = SecretBytes::from_hex("abc").unwrap_err();
    assert!(matches!(err.kind, CryptoErrorKind::InvalidHexLength { .. }));
}

#[test]
fn secret_bytes_from_hex_empty() {
    let sb = SecretBytes::from_hex("").unwrap();
    assert!(sb.is_empty());
}

#[test]
fn secret_string_new_expose() {
    let ss = SecretString::new("hello".to_owned());
    assert_eq!(ss.expose(), "hello");
}

#[test]
fn secret_string_new_checked_ok() {
    let ss = SecretString::new_checked("valid string".to_owned()).unwrap();
    assert_eq!(ss.expose(), "valid string");
}

#[test]
fn secret_string_new_checked_null_byte_rejected() {
    let err = SecretString::new_checked("null\0byte".to_owned()).unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::StringPolicy);
}

#[test]
fn secret_string_debug_redacted() {
    let ss = SecretString::new("sensitive data".to_owned());
    let dbg = format!("{:?}", ss);
    assert!(
        !dbg.contains("sensitive"),
        "Debug must not show value: {dbg}"
    );
    assert!(dbg.contains("redacted") || dbg.contains("SecretString"));
}

#[test]
fn secret_string_display_redacted() {
    let ss = SecretString::new("sensitive data".to_owned());
    let disp = format!("{}", ss);
    assert!(
        !disp.contains("sensitive"),
        "Display must not show value: {disp}"
    );
    assert_eq!(disp, "<redacted>");
}

#[test]
fn secret_string_from_utf8_bytes_valid() {
    let ss = SecretString::from_utf8_bytes(b"valid utf8").unwrap();
    assert_eq!(ss.expose(), "valid utf8");
}

#[test]
fn secret_string_from_utf8_bytes_invalid_utf8() {
    let invalid = b"\xff\xfe";
    let err = SecretString::from_utf8_bytes(invalid).unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::StringPolicy);
}

#[test]
fn secret_string_from_utf8_vec_valid() {
    let ss = SecretString::from_utf8_vec(b"from vec".to_vec()).unwrap();
    assert_eq!(ss.expose(), "from vec");
}

#[test]
fn secret_string_decode_hex() {
    let ss = SecretString::new("deadbeef".to_owned());
    let bytes = ss.decode_hex().unwrap();
    assert_eq!(bytes.as_slice(), &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn secret_string_decode_hex_fixed() {
    let hex_str = "aa".repeat(32);
    let ss = SecretString::new(hex_str);
    let b32: Byte32 = ss.decode_hex_fixed().unwrap();
    assert_eq!(b32.as_slice(), &[0xAAu8; 32]);
}

#[test]
fn secret_string_to_zeroizing() {
    let ss = SecretString::new("hello".to_owned());
    let z = ss.to_zeroizing();
    assert_eq!(z.as_str(), "hello");
}

#[test]
fn secret_string_clone() {
    let ss = SecretString::new("clone test".to_owned());
    let cloned = ss.clone();
    assert_eq!(cloned.expose(), ss.expose());
}

#[test]
fn secret_json_from_str_valid() {
    let j = SecretJson::from_str(r#"{"key":"value"}"#).unwrap();
    let s = j.get_string("key").unwrap();
    assert_eq!(s.expose(), "value");
}

#[test]
fn secret_json_from_str_invalid() {
    let err = SecretJson::from_str("not json {{{").unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::JsonParse);
}

#[test]
fn secret_json_not_an_object() {
    let j = SecretJson::from_str(r#"[1, 2, 3]"#).unwrap();
    let err = j.get_string("x").unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::JsonNotObject);
}

#[test]
fn secret_json_missing_field() {
    let j = SecretJson::from_str(r#"{"a":"b"}"#).unwrap();
    let err = j.get_string("missing").unwrap_err();
    assert_eq!(
        err.kind,
        CryptoErrorKind::JsonMissingField { key: "missing" }
    );
}

#[test]
fn secret_json_type_mismatch_string_not_number() {
    let j = SecretJson::from_str(r#"{"n": 42}"#).unwrap();
    let err = j.get_string("n").unwrap_err();
    assert!(matches!(
        err.kind,
        CryptoErrorKind::JsonTypeMismatch { key: "n", .. }
    ));
}

#[test]
fn secret_json_get_integer() {
    use secrecy::ExposeSecret;
    let j = SecretJson::from_str(r#"{"count": 99}"#).unwrap();
    let v = j.get_integer("count").unwrap();
    assert_eq!(*v.expose_secret(), 99i64);
}

#[test]
fn secret_json_get_bool_true() {
    let j = SecretJson::from_str(r#"{"flag": true}"#).unwrap();
    assert!(j.get_bool("flag").unwrap());
}

#[test]
fn secret_json_get_bool_false() {
    let j = SecretJson::from_str(r#"{"flag": false}"#).unwrap();
    assert!(!j.get_bool("flag").unwrap());
}

#[test]
fn secret_json_take_string_removes_field() {
    let mut j = SecretJson::from_str(r#"{"token": "abc123", "other": "keep"}"#).unwrap();
    let taken = j.take_string("token").unwrap();
    assert_eq!(taken.expose(), "abc123");
    let err = j.get_string("token").unwrap_err();
    assert_eq!(err.kind, CryptoErrorKind::JsonMissingField { key: "token" });
    assert_eq!(j.get_string("other").unwrap().expose(), "keep");
}

#[test]
fn secret_json_take_bool() {
    let mut j = SecretJson::from_str(r#"{"enabled": true}"#).unwrap();
    assert!(j.take_bool("enabled").unwrap());
    assert!(j.get_bool("enabled").is_err());
}

#[test]
fn secret_json_take_i64() {
    use secrecy::ExposeSecret;
    let mut j = SecretJson::from_str(r#"{"x": -7}"#).unwrap();
    let v = j.take_i64("x").unwrap();
    assert_eq!(*v.expose_secret(), -7i64);
}

#[test]
fn secret_json_take_u64() {
    use secrecy::ExposeSecret;
    let mut j = SecretJson::from_str(r#"{"big": 9999999}"#).unwrap();
    let v = j.take_u64("big").unwrap();
    assert_eq!(*v.expose_secret(), 9999999u64);
}

#[test]
fn secret_json_take_f64() {
    use secrecy::ExposeSecret;
    let mut j = SecretJson::from_str(r#"{"pi": 3.141592653589793}"#).unwrap();
    let v = j.take_f64("pi").unwrap();
    let pi = *v.expose_secret();
    assert!((pi - std::f64::consts::PI).abs() < 1e-9);
}

#[test]
fn secret_json_get_array() {
    let j = SecretJson::from_str(r#"{"items": ["a", "b", "c"]}"#).unwrap();
    let arr = j.get_array("items").unwrap();
    assert_eq!(arr.len(), 3);
}

#[test]
fn secret_json_get_object() {
    let j = SecretJson::from_str(r#"{"nested": {"x": "y"}}"#).unwrap();
    let nested = j.get_object("nested").unwrap();
    assert_eq!(nested.get_string("x").unwrap().expose(), "y");
}

#[test]
fn secret_json_take_object() {
    let mut j = SecretJson::from_str(r#"{"inner": {"k": "v"}}"#).unwrap();
    let inner = j.take_object("inner").unwrap();
    assert_eq!(inner.get_string("k").unwrap().expose(), "v");
    assert!(j.get_object("inner").is_err());
}

#[test]
fn secret_json_debug_redacted() {
    let j = SecretJson::from_str(r#"{"secret": "mysecret"}"#).unwrap();
    let dbg = format!("{:?}", j);
    assert!(
        !dbg.contains("mysecret"),
        "Debug must not reveal data: {dbg}"
    );
}

#[test]
fn secret_json_display_redacted() {
    let j = SecretJson::from_str(r#"{"secret": "mysecret"}"#).unwrap();
    let disp = format!("{}", j);
    assert!(
        !disp.contains("mysecret"),
        "Display must not reveal data: {disp}"
    );
    assert_eq!(disp, "<redacted>");
}

#[test]
fn secret_json_raw_json_preserved() {
    let raw = r#"{"key":"val"}"#;
    let j = SecretJson::from_str(raw).unwrap();
    let gotten = j.get_raw_json().unwrap();
    assert_eq!(gotten.expose(), raw);
}

#[test]
fn secret_json_take_raw_json_removes_it() {
    let mut j = SecretJson::from_str(r#"{"k":"v"}"#).unwrap();
    let raw = j.take_raw_json().unwrap();
    assert!(j.take_raw_json().is_none());
    assert_eq!(raw.expose(), r#"{"k":"v"}"#);
}

#[test]
fn secret_json_from_bytes_valid() {
    let j = SecretJson::from_bytes(b"{\"a\":1}").unwrap();
    use secrecy::ExposeSecret;
    let v = j.get_integer("a").unwrap();
    assert_eq!(*v.expose_secret(), 1i64);
}

#[test]
fn secret_json_from_vec_valid() {
    let j = SecretJson::from_vec(b"{\"z\":true}".to_vec()).unwrap();
    assert!(j.get_bool("z").unwrap());
}

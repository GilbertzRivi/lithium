#[path = "common.rs"]
mod common;
use common::*;

#[tokio::test]
async fn test_no_id_field_is_bad_json() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    c.send_raw("{\"cmd\":\"ping\"}\n").await;
    let raw = c.try_read_line().await.expect("response");
    let r: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(r["error"].as_str().unwrap(), "bad_json");
    assert_eq!(r["id"].as_u64().unwrap(), 0);
}

#[tokio::test]
async fn test_no_cmd_field_is_bad_json() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    c.send_raw("{\"id\":1}\n").await;
    let raw = c.try_read_line().await.expect("response");
    let r: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(r["error"].as_str().unwrap(), "bad_json");
}

#[tokio::test]
async fn test_unknown_cmd_is_bad_json() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    c.send_raw("{\"id\":1,\"cmd\":\"do_the_magic\"}\n").await;
    let raw = c.try_read_line().await.expect("response");
    let r: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(r["error"].as_str().unwrap(), "bad_json");
}

#[tokio::test]
async fn test_id_string_is_bad_json() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    c.send_raw("{\"id\":\"one\",\"cmd\":\"ping\"}\n").await;
    let raw = c.try_read_line().await.expect("response");
    let r: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(r["error"].as_str().unwrap(), "bad_json");
}

#[tokio::test]
async fn test_auth_token_integer_is_bad_json() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    c.send_raw("{\"id\":1,\"cmd\":\"ping\",\"auth_token\":99}\n")
        .await;
    let raw = c.try_read_line().await.expect("response");
    let r: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(r["error"].as_str().unwrap(), "bad_json");
}

#[tokio::test]
async fn test_extra_fields_ignored() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    c.send_raw("{\"id\":1,\"cmd\":\"ping\",\"unknown_field\":true,\"garbage\":42}\n")
        .await;
    let raw = c.try_read_line().await.expect("response");
    let r: Value = serde_json::from_str(&raw).unwrap();
    assert!(r["ok"].as_bool().unwrap());
}

#[tokio::test]
async fn test_negative_id_is_bad_json() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    // u64 cannot represent -1
    c.send_raw("{\"id\":-1,\"cmd\":\"ping\"}\n").await;
    let raw = c.try_read_line().await.expect("response");
    let r: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(r["error"].as_str().unwrap(), "bad_json");
}

#[tokio::test]
async fn test_float_id_is_bad_json() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    c.send_raw("{\"id\":1.5,\"cmd\":\"ping\"}\n").await;
    let raw = c.try_read_line().await.expect("response");
    let r: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(r["error"].as_str().unwrap(), "bad_json");
}

#[tokio::test]
async fn test_null_for_required_string_field_is_bad_json() {
    let d = DaemonProcess::start().await;
    let mut c = IpcClient::connect(&d.socket_path).await;

    // data_password is SecretString (required), null fails deserialization
    c.send_raw("{\"id\":1,\"cmd\":\"unlock_keystore\",\"data_password\":null}\n")
        .await;
    let raw = c.try_read_line().await.expect("response");
    let r: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(r["error"].as_str().unwrap(), "bad_json");
}

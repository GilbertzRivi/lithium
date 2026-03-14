/// Translate a raw daemon / IPC error code into a user-facing message.
pub fn translate(raw: &str) -> String {
    // Check exact daemon error codes first — some start with "bad_" and would
    // otherwise be swallowed by the prefix check below.
    match raw {
        "bad_data_password" | "crypto_error" => return "Wrong password.".into(),
        "bad_account_password" => {
            return "Account password does not meet the minimum requirements.".into()
        }
        _ => {}
    }

    // IPC transport errors carry structured prefixes from ipc.rs.
    if raw.starts_with("daemon_connect_failed:") {
        return "Cannot reach lithiumd — make sure the daemon is running.".into();
    }
    if raw.starts_with("ipc_write_failed:")
        || raw.starts_with("ipc_read_failed:")
        || raw.starts_with("ipc_flush_failed:")
    {
        return "Connection error with the daemon — please try again.".into();
    }
    if raw.starts_with("json_encode_failed:") {
        return "Internal encoding error — please restart the application.".into();
    }
    if raw.starts_with("bad_ipc_response:") || raw.starts_with("bad_ping_payload:") {
        return "Received an unexpected response from the daemon.".into();
    }
    if raw == "bad_json" {
        return "Daemon did not recognise the command. Make sure you are running a matching version of lithiumd.".into();
    }
    if raw.starts_with("bad_") {
        if raw.contains("missing_ipc_auth_token") {
            // unlock_keystore returned unlocked=false — wrong password.
            return "Wrong password.".into();
        }
        return "Unexpected response from the daemon.".into();
    }

    match raw {
        "daemon_closed_connection" => "Daemon closed the connection — please try again.",
        "ipc_auth_failed" | "ipc_auth_required" => {
            "Session expired — re-enter your data password."
        }
        // Password / crypto
        "passwords_must_be_distinct" => {
            "Data password and account password must be different."
        }
        // Daemon state
        "missing_data_password" => "Data password is not set.",
        "missing_account_credentials" => "Account credentials are not configured.",
        "keystore_locked" => "Keystore is not unlocked.",
        "register_required" => "Account registration is required.",
        // Network / auth
        "protocol_error" => "Server communication failed — check your credentials and try again.",
        "invalid_credentials" | "bad_credentials" => "Wrong username or password.",
        "http_400" => "Request rejected by the server — check your credentials.",
        "http_401" => "Wrong username or password.",
        "http_403" => "Access denied.",
        "http_404" => "Account not found on the server.",
        "http_429" => "Too many attempts — please wait before trying again.",
        "http_500" | "http_502" | "http_503" => "Server error — please try again later.",
        // Storage / internal
        "internal_error" | "internal_state_error" => {
            "Internal daemon error — try restarting lithiumd."
        }
        "storage_error" => "Local storage error.",
        "storage_init_failed" => "Failed to open local storage.",
        "account_deleted_but_local_storage_wipe_failed"
        | "account_deleted_but_registered_flag_remove_failed" => {
            "Account deleted on the server, but some local files could not be removed. \
             Use 'Reset local data' to clean up."
        }
        "handler_taken" => "That username is already taken — choose a different one.",
        "ipc_error" => "Unknown daemon error.",
        _ => return raw.to_string(),
    }
    .into()
}
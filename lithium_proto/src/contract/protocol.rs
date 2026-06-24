pub mod header {
    pub const KEY_X: &str = "key-x";
    pub const KEY_K: &str = "key-k";
    pub const SEED: &str = "seed";
    pub const DATA: &str = "data";
    pub const SES_X: &str = "ses-x";
    pub const SES_K: &str = "ses-k";
    pub const SIG_ED: &str = "sig-ed";
    pub const SIG_DILI: &str = "sig-dili";
    pub const KEY_ED: &str = "key-ed";
    pub const KEY_DILI: &str = "key-dili";
}

pub mod field {
    pub const HANDLER: &str = "handler";
    pub const OPAQUE: &str = "opaque";
    pub const FLOW: &str = "flow";
    pub const POW: &str = "pow";
    pub const DEK: &str = "dek";
    pub const TOKEN: &str = "token";
    pub const TOK: &str = "tok";
    pub const CAPABILITY: &str = "capability";
    pub const MAILBOX: &str = "mailbox";
    pub const CONTENT: &str = "content";
    pub const DATA: &str = "data";
    pub const TIMESTAMP: &str = "timestamp";
    pub const MSG: &str = "msg";
}

pub mod path {
    pub const SHAKE: &str = "/shake";
    pub const REGISTER_START: &str = "/user/register/start";
    pub const REGISTER_FINISH: &str = "/user/register/finish";
    pub const LOGIN_START: &str = "/user/login/start";
    pub const LOGIN_FINISH: &str = "/user/login/finish";
    pub const REVOKE: &str = "/user/revoke";
    pub const DELETE: &str = "/user/delete";
    pub const MSG_SEND: &str = "/msg/send";
    pub const MSG_FETCH: &str = "/msg/fetch";
}

pub mod ctx {
    pub const SHAKE: &str = "shake";
    pub const REGISTER_START: &str = "register_start";
    pub const REGISTER_FINISH: &str = "register_finish";
    pub const LOGIN_START: &str = "login_start";
    pub const LOGIN_FINISH: &str = "login_finish";
    pub const REVOKE: &str = "revoke";
    pub const DELETE: &str = "delete";
    pub const MSG_SEND: &str = "msg_send";
    pub const MSG_FETCH: &str = "msg_fetch";
}

pub fn normalize_handler(handler: &str) -> String {
    handler.trim().to_lowercase()
}

pub fn ctx_req(base: &str) -> String {
    format!("{base}-req")
}

pub fn ctx_resp(base: &str) -> String {
    format!("{base}-resp")
}

pub fn format_timestamp(secs: u64) -> String {
    format!("{secs:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_values_are_pinned() {
        assert_eq!(header::KEY_X, "key-x");
        assert_eq!(header::KEY_K, "key-k");
        assert_eq!(header::SEED, "seed");
        assert_eq!(header::DATA, "data");
        assert_eq!(header::SES_X, "ses-x");
        assert_eq!(header::SES_K, "ses-k");
        assert_eq!(header::SIG_ED, "sig-ed");
        assert_eq!(header::SIG_DILI, "sig-dili");
        assert_eq!(header::KEY_ED, "key-ed");
        assert_eq!(header::KEY_DILI, "key-dili");

        assert_eq!(field::HANDLER, "handler");
        assert_eq!(field::OPAQUE, "opaque");
        assert_eq!(field::FLOW, "flow");
        assert_eq!(field::POW, "pow");
        assert_eq!(field::DEK, "dek");
        assert_eq!(field::TOKEN, "token");
        assert_eq!(field::TOK, "tok");
        assert_eq!(field::CAPABILITY, "capability");
        assert_eq!(field::MAILBOX, "mailbox");
        assert_eq!(field::CONTENT, "content");
        assert_eq!(field::DATA, "data");
        assert_eq!(field::TIMESTAMP, "timestamp");
        assert_eq!(field::MSG, "msg");

        assert_eq!(path::SHAKE, "/shake");
        assert_eq!(path::REGISTER_START, "/user/register/start");
        assert_eq!(path::REGISTER_FINISH, "/user/register/finish");
        assert_eq!(path::LOGIN_START, "/user/login/start");
        assert_eq!(path::LOGIN_FINISH, "/user/login/finish");
        assert_eq!(path::REVOKE, "/user/revoke");
        assert_eq!(path::DELETE, "/user/delete");
        assert_eq!(path::MSG_SEND, "/msg/send");
        assert_eq!(path::MSG_FETCH, "/msg/fetch");

        assert_eq!(ctx::SHAKE, "shake");
        assert_eq!(ctx::REGISTER_START, "register_start");
        assert_eq!(ctx::REGISTER_FINISH, "register_finish");
        assert_eq!(ctx::LOGIN_START, "login_start");
        assert_eq!(ctx::LOGIN_FINISH, "login_finish");
        assert_eq!(ctx::REVOKE, "revoke");
        assert_eq!(ctx::DELETE, "delete");
        assert_eq!(ctx::MSG_SEND, "msg_send");
        assert_eq!(ctx::MSG_FETCH, "msg_fetch");
    }

    #[test]
    fn ctx_direction_suffixes_are_pinned() {
        assert_eq!(ctx_req(ctx::SHAKE), "shake-req");
        assert_eq!(ctx_resp(ctx::MSG_FETCH), "msg_fetch-resp");
    }

    #[test]
    fn timestamp_is_zero_padded_16_hex() {
        assert_eq!(format_timestamp(0), "0000000000000000");
        assert_eq!(format_timestamp(0x1234), "0000000000001234");
    }
}

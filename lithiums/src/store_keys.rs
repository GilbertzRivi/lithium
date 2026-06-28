// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

// Callers pass already-normalized ids (lowercased handler, hashed remote, body-hash hex).

pub(crate) fn login_fail(handler: &str) -> String {
    format!("auth:login:fail:{handler}")
}

pub(crate) fn login_lock(handler: &str) -> String {
    format!("auth:login:lock:{handler}")
}

pub(crate) fn register_fail(handler: &str) -> String {
    format!("auth:register:fail:{handler}")
}

pub(crate) fn register_lock(handler: &str) -> String {
    format!("auth:register:lock:{handler}")
}

pub(crate) fn pre_replay_fail(remote: &str) -> String {
    format!("guard:pre-replay:fail:{remote}")
}

pub(crate) fn pre_replay_lock(remote: &str) -> String {
    format!("guard:pre-replay:lock:{remote}")
}

pub(crate) fn replay(body_hash_hex: &str) -> String {
    format!("replay:{body_hash_hex}")
}

pub(crate) fn token(token: &str) -> String {
    format!("token:{token}")
}

pub(crate) fn opaque_login(flow: &str) -> String {
    format!("opaque:login:{flow}")
}

pub(crate) fn session(id_hex: &str) -> String {
    format!("ses:{id_hex}")
}

pub(crate) fn msg_key(id_hex: &str) -> String {
    format!("msgkey:{id_hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_key_namespaces_are_pinned() {
        assert_eq!(login_fail("h"), "auth:login:fail:h");
        assert_eq!(login_lock("h"), "auth:login:lock:h");
        assert_eq!(register_fail("h"), "auth:register:fail:h");
        assert_eq!(register_lock("h"), "auth:register:lock:h");
        assert_eq!(pre_replay_fail("r"), "guard:pre-replay:fail:r");
        assert_eq!(pre_replay_lock("r"), "guard:pre-replay:lock:r");
        assert_eq!(replay("ab"), "replay:ab");
        assert_eq!(token("t"), "token:t");
        assert_eq!(opaque_login("f"), "opaque:login:f");
        assert_eq!(session("ab"), "ses:ab");
        assert_eq!(msg_key("cd"), "msgkey:cd");
    }
}

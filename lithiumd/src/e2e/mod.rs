// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod crypto;
pub(crate) mod header;
pub mod prekeys;
pub mod session;
pub(crate) mod state;
pub mod state_peer;
pub mod state_self;
pub mod wire;

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) mod seq_driver;

pub use wire::{PREKEY_TARGET, pack_wire, unpack_wire};

pub(crate) use state::{PeerState, SelfState};

pub use state_self::{
    drop_bootstrap_private_if_established, ensure_self_keyring, mark_bootstrap_retire_ready,
};

pub use state_peer::{
    peer_need_recover, peer_pick_remote_prekey, peer_remove_remote_prekey, peer_set_need_recover,
};

pub use prekeys::{
    gen_local_prekey_material, local_public_prekeys, local_remove_public_prekey,
    prekeys_mark_advertised, prekeys_should_advertise,
};

pub use session::{decrypt_for_prekey, decrypt_for_us, encrypt_for_peer};

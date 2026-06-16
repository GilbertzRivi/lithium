pub mod wire;
pub(crate) mod crypto;
pub(crate) mod header;
pub(crate) mod state;
pub mod state_self;
pub mod state_peer;
pub mod prekeys;
pub mod session;

pub use wire::{pack_wire, unpack_wire, PREKEY_TARGET};

pub(crate) use state::{PeerState, SelfState};

pub use state_self::{
    drop_bootstrap_private_if_established,
    ensure_self_keyring,
    mark_bootstrap_retire_ready,
};

pub use state_peer::{
    peer_need_recover,
    peer_set_need_recover,
    peer_pick_remote_prekey,
    peer_remove_remote_prekey,
};

pub use prekeys::{
    gen_local_prekey_material,
    local_public_prekeys,
    local_remove_public_prekey,
    prekeys_mark_advertised,
    prekeys_should_advertise,
};

pub use session::{
    decrypt_for_prekey,
    decrypt_for_us,
    encrypt_for_peer,
};
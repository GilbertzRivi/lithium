// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use tokio::sync::{Mutex, oneshot};

use lithium_core::passwords::passwords::PasswordPolicy;

use crate::ipc::types::{IpcCommand, IpcRequest, IpcResponse};

mod contact_forget;
mod contact_list;
pub(crate) mod contact_mailbox;
mod contact_send;
mod contact_verify_emoji;
mod delete_account;
mod invite_accept_commitment;
pub(crate) mod invite_codec;
mod invite_create;
mod invite_finalize;
mod invite_reveal;
mod lock_keystore;
mod messages_list;
mod ping;
mod register;
mod remote_delete;
mod set_credentials;
mod set_server_identity;
mod set_server_url;
mod shutdown;
pub(crate) mod stored_message;
mod unlock_keystore;
mod unlock_storage;
mod wipe_local;

use crate::state::DaemonState;

pub async fn dispatch(
    req: IpcRequest,
    state: Arc<DaemonState>,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    pol: &PasswordPolicy,
) -> IpcResponse {
    let id = req.id;

    match req.cmd {
        IpcCommand::Ping => ping::handle(id, state).await,
        IpcCommand::SetCredentials { handler, password } => {
            set_credentials::handle(id, handler, password, state, pol).await
        }
        IpcCommand::UnlockKeystore { data_password } => {
            unlock_keystore::handle(id, data_password, state, pol).await
        }
        IpcCommand::Register => register::handle(id, state, pol).await,
        IpcCommand::RemoteDelete { capability } => {
            remote_delete::handle(id, capability, state).await
        }
        IpcCommand::DeleteAccount => delete_account::handle(id, state).await,
        IpcCommand::UnlockStorage => unlock_storage::handle(id, state).await,
        IpcCommand::Shutdown => shutdown::handle(id, state, shutdown_tx).await,
        IpcCommand::WipeLocal => wipe_local::handle(id, state).await,

        IpcCommand::CreateInvite { contact_id } => {
            invite_create::handle(id, contact_id, state).await
        }
        IpcCommand::AcceptCommitment { commitment, label } => {
            invite_accept_commitment::handle(id, commitment, label, state).await
        }
        IpcCommand::RevealInvite {
            contact_id,
            peer_code,
            label,
        } => invite_reveal::handle(id, contact_id, peer_code, label, state).await,
        IpcCommand::FinalizePairing {
            contact_id,
            peer_code,
        } => invite_finalize::handle(id, contact_id, peer_code, state).await,

        IpcCommand::ContactsList => contact_list::handle(id, state).await,
        IpcCommand::ContactSend {
            contact_id,
            plaintext,
        } => contact_send::handle(id, contact_id, plaintext, state).await,
        IpcCommand::ContactForget { contact_id } => {
            contact_forget::handle(id, contact_id, state).await
        }
        IpcCommand::MessagesList {
            contact_id,
            limit,
            before_id,
        } => messages_list::handle(id, contact_id, limit, before_id, state).await,
        IpcCommand::ContactVerifyEmoji { contact_id } => {
            contact_verify_emoji::handle(id, contact_id, state).await
        }
        IpcCommand::LockKeystore => lock_keystore::handle(id, state).await,
        IpcCommand::SetServerIdentity { data } => {
            set_server_identity::handle(id, data, state).await
        }
        IpcCommand::SetServerUrl { url } => set_server_url::handle(id, url, state).await,
    }
}

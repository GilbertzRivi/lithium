use std::sync::Arc;

use tokio::sync::{oneshot, Mutex};

use lithium_core::passwords::passwords::PasswordPolicy;

use crate::ipc::types::{IpcCommand, IpcRequest, IpcResponse};

mod ping;
mod set_credentials;
mod unlock_keystore;
mod register;
mod remote_delete;
mod unlock_storage;
mod shutdown;
mod wipe_local;
mod invite_create;
mod invite_accept;
mod invite_codec;
mod contact_mailbox;
mod contact_list;
mod contact_send;
mod contact_fetch;
mod contact_forget;
mod messages_list;
mod e2e;
mod contact_verify_emoji;
mod delete_account;
mod lock_keystore;

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
        IpcCommand::AcceptInvite { code, contact_id, label } => {
            invite_accept::handle(id, code, contact_id, label, state).await
        }

        IpcCommand::ContactsList => contact_list::handle(id, state).await,
        IpcCommand::ContactSend { contact_id, plaintext } => {
            contact_send::handle(id, contact_id, plaintext, state).await
        }
        IpcCommand::ContactFetch { contact_id } => {
            contact_fetch::handle(id, contact_id, state).await
        }
        IpcCommand::ContactForget { contact_id } => {
            contact_forget::handle(id, contact_id, state).await
        }
        IpcCommand::MessagesList { contact_id, limit, before_id } => {
            messages_list::handle(id, contact_id, limit, before_id, state).await
        }
        IpcCommand::ContactVerifyEmoji { contact_id } => {
            contact_verify_emoji::handle(id, contact_id, state).await
        }
        IpcCommand::LockKeystore => lock_keystore::handle(id, state).await,
    }
}
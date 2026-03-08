use std::sync::Arc;

use tokio::sync::{oneshot, Mutex};

use lithium_core::passwords::passwords::PasswordPolicy;

use crate::ipc::types::{IpcRequest, IpcResponse};

mod ping;
mod set_credentials;
mod unlock_keystore;
mod register;
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

use crate::state::DaemonState;

pub async fn dispatch(
    req: IpcRequest,
    state: Arc<DaemonState>,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    pol: &PasswordPolicy,
) -> IpcResponse {
    match req {
        IpcRequest::Ping { id } => ping::handle(id, state).await,
        IpcRequest::SetCredentials { id, handler, password } => {
            set_credentials::handle(id, handler, password, state, pol).await
        }
        IpcRequest::UnlockKeystore { id, data_password } => {
            unlock_keystore::handle(id, data_password, state, pol).await
        }
        IpcRequest::Register { id } => register::handle(id, state, pol).await,
        IpcRequest::UnlockStorage { id } => unlock_storage::handle(id, state).await,
        IpcRequest::Shutdown { id } => shutdown::handle(id, state, shutdown_tx).await,
        IpcRequest::WipeLocal { id } => wipe_local::handle(id, state).await,

        IpcRequest::CreateInvite { id, contact_id, server } => {
            invite_create::handle(id, contact_id, server, state).await
        }
        IpcRequest::AcceptInvite { id, code, contact_id, label } => {
            invite_accept::handle(id, code, contact_id, label, state).await
        }

        IpcRequest::ContactsList { id } => {
            contact_list::handle(id, state).await
        }
        IpcRequest::ContactSend { id, contact_id, plaintext } => {
            contact_send::handle(id, contact_id, plaintext, state).await
        }
        IpcRequest::ContactFetch { id, contact_id } => {
            contact_fetch::handle(id, contact_id, state).await
        }
        IpcRequest::ContactForget { id, contact_id } => {
            contact_forget::handle(id, contact_id, state).await
        }
        IpcRequest::MessagesList { id, contact_id, limit, before_id } => {
            messages_list::handle(id, contact_id, limit, before_id, state).await
        }
    }
}

use std::{fs, io, path::Path, sync::Arc};

use tokio::{
    net::{UnixListener, UnixStream},
    sync::{oneshot, Mutex, Semaphore},
};

use lithium_core::error::{LithiumError, Result};

use crate::{
    ipc::IpcPeerMeta,
    state::DaemonState,
    util::IpcPolicy,
};

#[cfg(unix)]
fn bind_private_listener(socket_path: &Path) -> Result<UnixListener> {
    use std::os::unix::{
        fs::FileTypeExt,
        net::UnixListener as StdUnixListener,
    };

    struct UmaskGuard(libc::mode_t);

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            unsafe {
                libc::umask(self.0);
            }
        }
    }

    match fs::symlink_metadata(socket_path) {
        Ok(meta) => {
            if meta.file_type().is_socket() {
                fs::remove_file(socket_path).map_err(LithiumError::io)?;
            } else {
                return Err(LithiumError::io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "ipc socket path exists and is not a socket: {}",
                        socket_path.display()
                    ),
                )));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(LithiumError::io(e)),
    }

    let old_umask = unsafe { libc::umask(0o117) };
    let _guard = UmaskGuard(old_umask);

    let std_listener = StdUnixListener::bind(socket_path).map_err(LithiumError::io)?;
    std_listener.set_nonblocking(true).map_err(LithiumError::io)?;

    UnixListener::from_std(std_listener).map_err(LithiumError::io)
}

#[cfg(target_os = "linux")]
fn peer_creds(stream: &UnixStream) -> Result<libc::ucred> {
    use std::{mem, os::fd::AsRawFd};

    let fd = stream.as_raw_fd();

    let mut cred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;

    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };

    if rc != 0 {
        return Err(LithiumError::io(io::Error::last_os_error()));
    }

    if len as usize != mem::size_of::<libc::ucred>() {
        return Err(LithiumError::io(io::Error::new(
            io::ErrorKind::InvalidData,
            "short SO_PEERCRED result",
        )));
    }

    Ok(cred)
}

#[cfg(target_os = "linux")]
fn peer_meta(stream: &UnixStream) -> Result<IpcPeerMeta> {
    let cred = peer_creds(stream)?;
    Ok(IpcPeerMeta {
        uid: Some(cred.uid),
        pid: Some(cred.pid),
    })
}

#[cfg(not(target_os = "linux"))]
fn peer_meta(_stream: &UnixStream) -> Result<IpcPeerMeta> {
    Ok(IpcPeerMeta::default())
}

#[cfg(target_os = "linux")]
fn authorize_peer(peer: IpcPeerMeta, policy: &IpcPolicy) -> Result<()> {
    if let Some(allowed_uid) = policy.allowed_uid {
        if peer.uid != Some(allowed_uid) {
            return Err(LithiumError::invalid_perms("ipc_peer_uid_denied"));
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn authorize_peer(_peer: IpcPeerMeta, _policy: &IpcPolicy) -> Result<()> {
    Ok(())
}

pub async fn run(
    socket_path: &Path,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    state: Arc<DaemonState>,
    policy: IpcPolicy,
) -> Result<()> {
    let listener = bind_private_listener(socket_path)?;
    let limiter = Arc::new(Semaphore::new(policy.max_connections));

    loop {
        let (stream, _addr) = listener.accept().await.map_err(LithiumError::io)?;
        let peer = match peer_meta(&stream) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ipc peercred error: {e:?}");
                continue;
            }
        };

        if let Err(e) = authorize_peer(peer, &policy) {
            eprintln!("ipc auth reject: {e:?}");
            continue;
        }

        let permit = match limiter.clone().try_acquire_owned() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("ipc auth reject: too many connections");
                continue;
            }
        };

        let shutdown_tx = Arc::clone(&shutdown_tx);
        let state = Arc::clone(&state);
        let idle_timeout = policy.idle_timeout;

        tokio::spawn(async move {
            let _permit = permit;

            if let Err(e) = super::handle_conn(stream, shutdown_tx, state, idle_timeout, peer).await {
                eprintln!("ipc conn error: {e:?}");
            }
        });
    }
}
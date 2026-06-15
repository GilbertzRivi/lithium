#![cfg_attr(windows, windows_subsystem = "windows")]

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

use reqwest::Url;
use tokio::sync::{oneshot, watch, Mutex};

use lithium_core::error::Result;

mod commands;
mod db;
mod e2e;
mod identity;
mod ipc;
mod labels;
mod password_provider;
mod protocol_manager;
mod state;
mod state_fields;
mod tray;
mod util;

use state::DaemonState;
use util::IpcEndpoint;

fn main() {
    if let Err(e) = run() {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let base_dir = util::default_data_dir();
    let ipc_endpoint = util::default_ipc_endpoint()?;
    let ipc_policy = util::load_ipc_policy()?;

    util::prepare_private_dir(&base_dir)?;
    util::prepare_ipc_endpoint(&ipc_endpoint)?;

    let server_url_path = util::server_url_path(&base_dir);
    let base_url = std::fs::read_to_string(&server_url_path)
        .ok()
        .and_then(|s| Url::parse(s.trim()).ok());

    // Server identity is read lazily on first connection — only the path is resolved here.
    let identity_path = match std::env::var_os("LITHIUMD_SERVER_IDENTITY") {
        Some(v) => std::path::PathBuf::from(v),
        None => base_dir.join("server.identity"),
    };

    let needs_register = util::load_needs_register(&base_dir);

    let state = Arc::new(DaemonState::new(
        base_dir,
        base_url,
        identity_path,
        needs_register,
    ));

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));

    let (stop_tx, stop_rx) = watch::channel(false);
    let daemon_done = Arc::new(AtomicBool::new(false));
    let daemon_done_clone = Arc::clone(&daemon_done);

    let daemon_thread = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(daemon_async(
            state,
            ipc_endpoint,
            ipc_policy,
            shutdown_tx,
            shutdown_rx,
            stop_rx,
        ));
        daemon_done_clone.store(true, Ordering::Release);
    });

    let action = tray::run(&stop_tx, &daemon_done);

    daemon_thread.join().ok();

    if action == tray::Action::Restart {
        let exe = std::env::current_exe()
            .unwrap_or_else(|_| std::path::PathBuf::from("lithiumd"));
        let _ = std::process::Command::new(exe).spawn();
    }

    Ok(())
}

async fn daemon_async(
    state: Arc<DaemonState>,
    ipc_endpoint: IpcEndpoint,
    ipc_policy: util::IpcPolicy,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    shutdown_rx: oneshot::Receiver<()>,
    mut stop_rx: watch::Receiver<bool>,
) {
    #[cfg(unix)]
    let ipc_task = {
        let IpcEndpoint::Unix(socket_path) = &ipc_endpoint;
        ipc::unix::run(
            socket_path,
            Arc::clone(&shutdown_tx),
            Arc::clone(&state),
            ipc_policy.clone(),
        )
    };

    #[cfg(windows)]
    let ipc_task = {
        let IpcEndpoint::NamedPipe(pipe_name) = &ipc_endpoint;
        ipc::windows::run(
            pipe_name,
            Arc::clone(&shutdown_tx),
            Arc::clone(&state),
            ipc_policy.clone(),
        )
    };

    #[cfg(unix)]
    let mut sigterm = {
        use tokio::signal::unix::{signal, SignalKind};
        signal(SignalKind::terminate()).expect("sigterm handler")
    };

    let signal = async {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    };

    tokio::select! {
        _ = ipc_task => {},
        _ = shutdown_rx => {},
        _ = stop_rx.changed() => {},
        _ = signal => {},
    }
}
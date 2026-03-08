use std::{fs, path::{Path, PathBuf}};

use lithium_core::error::{LithiumError, Result};

#[derive(Clone, Debug)]
pub enum IpcEndpoint {
    #[cfg(unix)]
    Unix(PathBuf),
    #[cfg(windows)]
    NamedPipe(String),
}

pub fn default_data_dir() -> PathBuf {
    if let Some(v) = std::env::var_os("LITHIUMD_DATA_DIR") {
        return PathBuf::from(v);
    }

    #[cfg(windows)]
    {
        if let Some(v) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(v).join("Lithiumd");
        }
        if let Some(v) = std::env::var_os("APPDATA") {
            return PathBuf::from(v).join("Lithiumd");
        }
        if let Some(v) = std::env::var_os("USERPROFILE") {
            return PathBuf::from(v).join("AppData").join("Local").join("Lithiumd");
        }
        return PathBuf::from(".").join("lithiumd-data");
    }

    #[cfg(not(windows))]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".local").join("share").join("lithiumd");
        }
        PathBuf::from(".").join(".lithiumd")
    }
}

pub fn default_ipc_endpoint() -> IpcEndpoint {
    #[cfg(windows)]
    {
        let pipe = std::env::var("LITHIUMD_PIPE_NAME")
            .unwrap_or_else(|_| String::from(r"\\.\pipe\lithiumd"));
        return IpcEndpoint::NamedPipe(pipe);
    }

    #[cfg(unix)]
    {
        if let Some(v) = std::env::var_os("LITHIUMD_SOCKET_PATH") {
            return IpcEndpoint::Unix(PathBuf::from(v));
        }

        if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
            return IpcEndpoint::Unix(PathBuf::from(rt).join("lithiumd.sock"));
        }

        let mut sock_name = String::from("lithiumd.sock");
        if let Some(user) = std::env::var_os("USER") {
            sock_name = format!("lithiumd-{}.sock", user.to_string_lossy());
        }

        IpcEndpoint::Unix(std::env::temp_dir().join(sock_name))
    }
}

pub fn prepare_ipc_endpoint(endpoint: &IpcEndpoint) -> Result<()> {
    match endpoint {
        #[cfg(unix)]
        IpcEndpoint::Unix(path) => prepare_socket(path),
        #[cfg(windows)]
        IpcEndpoint::NamedPipe(_) => Ok(()),
    }
}

#[cfg(unix)]
pub fn prepare_socket(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(LithiumError::io)?;
    }
    if path.exists() {
        fs::remove_file(path).map_err(LithiumError::io)?;
    }
    Ok(())
}

pub fn init_logging() {
    use std::env;
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    let use_json = matches!(
        env::var("LITHIUM_LOG_JSON").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    );

    let builder = fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true);

    if use_json {
        builder.json().init();
    } else {
        builder.compact().init();
    }
}

pub fn registered_marker_path(base_dir: &Path) -> PathBuf {
    base_dir.join("registered.flag")
}

pub fn load_needs_register(base_dir: &Path) -> bool {
    !registered_marker_path(base_dir).exists()
}

pub fn mark_registered(base_dir: &Path) -> std::io::Result<()> {
    let p = registered_marker_path(base_dir);
    fs::write(&p, b"1")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn wipe_dir_all(p: &Path) -> std::io::Result<()> {
    if p.exists() {
        fs::remove_dir_all(p)?;
    }
    Ok(())
}

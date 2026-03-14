use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::Duration,
};
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
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("lithiumd");
        }
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

        // No safe location available — require explicit override via LITHIUMD_SOCKET_PATH.
        panic!("XDG_RUNTIME_DIR is not set; set LITHIUMD_SOCKET_PATH to a private directory")
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

pub fn server_url_path(base_dir: &Path) -> PathBuf {
    base_dir.join("server_url")
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


fn overwrite_regular_file_best_effort(path: &Path, len: u64) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).open(path)?;

    let zeros = [0u8; 1024 * 1024];
    let mut remaining = len;

    while remaining > 0 {
        let n = remaining.min(zeros.len() as u64) as usize;
        f.write_all(&zeros[..n])?;
        remaining -= n as u64;
    }

    f.sync_all()?;
    f.set_len(0)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn wipe_path_best_effort(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    let ft = meta.file_type();

    if ft.is_symlink() {
        fs::remove_file(path)?;
        sync_parent_dir(path)?;
        return Ok(());
    }

    if ft.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            wipe_path_best_effort(&entry.path())?;
        }

        fs::remove_dir(path)?;
        sync_parent_dir(path)?;
        return Ok(());
    }

    if ft.is_file() {
        overwrite_regular_file_best_effort(path, meta.len())?;
        fs::remove_file(path)?;
        sync_parent_dir(path)?;
        return Ok(());
    }

    fs::remove_file(path)?;
    sync_parent_dir(path)?;
    Ok(())
}

pub fn wipe_dir_all(p: &Path) -> std::io::Result<()> {
    if !p.exists() {
        return Ok(());
    }
    wipe_path_best_effort(p)
}

#[derive(Clone, Debug)]
pub struct IpcPolicy {
    pub max_connections: usize,
    pub idle_timeout: Duration,

    #[cfg(target_os = "linux")]
    pub allowed_uid: Option<u32>,
}

pub fn load_ipc_policy() -> Result<IpcPolicy> {
    let max_connections = match std::env::var("LITHIUMD_IPC_MAX_CONNECTIONS") {
        Ok(v) => v
            .parse::<usize>()
            .map_err(|_| LithiumError::env_invalid("LITHIUMD_IPC_MAX_CONNECTIONS"))?,
        Err(_) => 1,
    }
        .max(1);

    let idle_timeout_secs = match std::env::var("LITHIUMD_IPC_IDLE_TIMEOUT_SECS") {
        Ok(v) => v
            .parse::<u64>()
            .map_err(|_| LithiumError::env_invalid("LITHIUMD_IPC_IDLE_TIMEOUT_SECS"))?,
        Err(_) => 300,
    }
        .max(5);

    #[cfg(target_os = "linux")]
    let allowed_uid = match std::env::var("LITHIUMD_IPC_ALLOWED_UID") {
        Ok(v) => Some(
            v.parse::<u32>()
                .map_err(|_| LithiumError::env_invalid("LITHIUMD_IPC_ALLOWED_UID"))?,
        ),
        Err(_) => None,
    };

    Ok(IpcPolicy {
        max_connections,
        idle_timeout: Duration::from_secs(idle_timeout_secs),

        #[cfg(target_os = "linux")]
        allowed_uid,
    })
}

pub fn prepare_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(LithiumError::io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(LithiumError::io)?;
    }

    Ok(())
}
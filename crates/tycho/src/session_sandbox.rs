//! The launcher's side of the session sandbox: the vendor's proxy and the leader's plan.
//!
//! The plan adds the session's files, the vendor's own state and the vendor's socket
//! directories to the grants the core put in the spec.

use std::fmt;
use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use crate::config::CorePorts;
use crate::sandbox::{
    Access, Grant, SandboxConfig, SandboxError, SandboxPlan, SandboxVendor, capability_set,
    core_ports,
};
use crate::session_proxy::{ProxyError, SessionProxy};
use crate::vendors::claude_control::sockets_dirs;

const PRIVATE_DIR_MODE: u32 = 0o700;
/// The git configuration files git reads under `HOME`; each is granted read when present and
/// may be found absent when not.
pub const GIT_CONFIG_FILES: [&str; 5] = [
    ".gitconfig",
    ".gitignore_global",
    ".config/git/config",
    ".config/git/ignore",
    ".config/git/attributes",
];
/// Claude Code's state under `HOME`: its configuration directory and its cache.
pub const CLAUDE_CONFIG_DIR_NAME: &str = ".claude";
pub const CLAUDE_STATE_FILE: &str = ".claude.json";
#[cfg(target_os = "macos")]
pub const CLAUDE_CACHE_DIR: &str = "Library/Caches/claude-cli-nodejs";
#[cfg(not(target_os = "macos"))]
pub const CLAUDE_CACHE_DIR: &str = ".cache/claude-cli-nodejs";

#[derive(Debug)]
pub enum PrepareError {
    Vendor(String),
    State(PathBuf, io::Error),
    Proxy(ProxyError),
    Sandbox(SandboxError),
}

impl fmt::Display for PrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vendor(vendor) => write!(formatter, "no sandbox for a {vendor} session"),
            Self::State(path, error) => write!(formatter, "{}: {error}", path.display()),
            Self::Proxy(error) => write!(formatter, "{error}"),
            Self::Sandbox(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for PrepareError {}

/// What the launcher knows of one session when it prepares the sandbox.
#[derive(Debug, Clone, Copy)]
pub struct SessionPaths<'a> {
    pub vendor: SandboxVendor,
    pub home: &'a Path,
    /// The session's directory the vendor writes its result and progress in.
    pub vendor_files: &'a Path,
    /// The session's Codex home, when the vendor is Codex.
    pub codex_home: Option<&'a Path>,
    /// The grants the core put in the spec.
    pub spec_grants: &'a [Grant],
    pub ports: CorePorts,
    pub uid: u32,
}

/// A started proxy and the plan for the leader, already built once against the
/// configuration so a refusal happens here, before any vendor process exists.
#[derive(Debug)]
pub struct Prepared {
    pub proxy: SessionProxy,
    pub plan: String,
}

/// Creates a directory of the vendor's own state 0700 when it is missing; an existing one
/// must be a real directory of this user.
fn ensure_state_dir(path: &Path, uid: u32) -> Result<(), PrepareError> {
    let state = |error: io::Error| PrepareError::State(path.to_path_buf(), error);
    match DirBuilder::new().mode(PRIVATE_DIR_MODE).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(state(error)),
    }
    let metadata = std::fs::symlink_metadata(path).map_err(state)?;
    if !metadata.file_type().is_dir() || metadata.uid() != uid {
        return Err(state(io::Error::other("not a real directory of this user")));
    }
    Ok(())
}

/// The vendor's socket directories in the order Claude Code tries them: a shared one of
/// another user is passed over, and the first one usable is made when missing.
fn claude_socket_dirs(uid: u32) -> Result<Vec<PathBuf>, PrepareError> {
    let mut granted = Vec::new();
    for dir in sockets_dirs(None, uid) {
        match std::fs::symlink_metadata(&dir) {
            Ok(metadata) if metadata.file_type().is_dir() && metadata.uid() == uid => {
                granted.push(dir);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && granted.is_empty() => {
                ensure_state_dir(&dir, uid)?;
                granted.push(dir);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(PrepareError::State(dir, error)),
        }
    }
    Ok(granted)
}

/// The plan for one session; makes the vendor's state directories it grants when missing.
pub fn session_plan(
    paths: &SessionPaths<'_>,
    proxy_port: u16,
) -> Result<SandboxPlan, PrepareError> {
    let mut grants = paths.spec_grants.to_vec();
    let read_write = |path: PathBuf| Grant {
        path,
        access: Access::ReadWrite,
    };
    grants.push(read_write(paths.vendor_files.to_path_buf()));
    let mut absent_paths = Vec::new();
    for name in GIT_CONFIG_FILES {
        let path = paths.home.join(name);
        if path.is_file() {
            grants.push(Grant {
                path,
                access: Access::Read,
            });
        } else {
            absent_paths.push(path);
        }
    }
    let mut socket_dirs = Vec::new();
    match paths.vendor {
        SandboxVendor::Claude => {
            let config = paths.home.join(CLAUDE_CONFIG_DIR_NAME);
            let cache = paths.home.join(CLAUDE_CACHE_DIR);
            for dir in [&config, &cache] {
                ensure_state_dir(dir, paths.uid)?;
            }
            grants.push(read_write(config));
            grants.push(read_write(cache));
            let state = paths.home.join(CLAUDE_STATE_FILE);
            if state.is_file() {
                grants.push(read_write(state));
            }
            socket_dirs = claude_socket_dirs(paths.uid)?;
        }
        SandboxVendor::Codex => {
            if let Some(home) = paths.codex_home {
                grants.push(read_write(home.to_path_buf()));
            }
        }
    }
    Ok(SandboxPlan {
        proxy_port,
        core_ports: core_ports(paths.ports),
        grants,
        socket_dirs,
        absent_paths,
    })
}

/// Starts the proxy on the vendor's allowlist, writes the plan and builds its set once.
pub fn prepare(paths: &SessionPaths<'_>) -> Result<Prepared, PrepareError> {
    let config = SandboxConfig::embedded()
        .map_err(|error| PrepareError::Sandbox(SandboxError::Config(error)))?
        .value;
    let proxy =
        SessionProxy::start(config.allowed_hosts(paths.vendor)).map_err(PrepareError::Proxy)?;
    let plan = session_plan(paths, proxy.port())?;
    capability_set(&plan, &config).map_err(PrepareError::Sandbox)?;
    let plan = plan.to_json().map_err(PrepareError::Sandbox)?;
    Ok(Prepared { proxy, plan })
}

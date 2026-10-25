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

/// Makes each missing level of `relative` under `home` as `ensure_state_dir` does, one level
/// at a time, so a home without `Library/Caches` still gets the vendor's cache directory.
fn ensure_state_path(home: &Path, relative: &str, uid: u32) -> Result<PathBuf, PrepareError> {
    let mut path = home.to_path_buf();
    for level in Path::new(relative).components() {
        path.push(level);
        ensure_state_dir(&path, uid)?;
    }
    Ok(path)
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
    let mut state_files = Vec::new();
    match paths.vendor {
        SandboxVendor::Claude => {
            let config = ensure_state_path(paths.home, CLAUDE_CONFIG_DIR_NAME, paths.uid)?;
            let cache = ensure_state_path(paths.home, CLAUDE_CACHE_DIR, paths.uid)?;
            grants.push(read_write(config));
            grants.push(read_write(cache));
            state_files.push(nono::try_canonicalize(paths.home).join(CLAUDE_STATE_FILE));
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
        state_files,
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

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use crate::agent_files::current_uid;

    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tycho-plan-{test}-{}", std::process::id()));
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap();
        }
        for level in ["home", "vendor", "codex-home"] {
            std::fs::create_dir_all(dir.join(level)).unwrap();
        }
        dir
    }

    fn codex_paths<'a>(
        codex_home: &'a Path,
        home: &'a Path,
        vendor_files: &'a Path,
    ) -> SessionPaths<'a> {
        SessionPaths {
            vendor: SandboxVendor::Codex,
            home,
            vendor_files,
            codex_home: Some(codex_home),
            spec_grants: &[],
            ports: CorePorts::PRODUCTION,
            uid: current_uid(),
        }
    }

    /// The session's vendor directory is the one directory of the spool the vendor writes,
    /// and the git files of a home that has none are stat-able absences, never grants.
    #[test]
    fn a_plan_grants_the_vendor_directory_and_names_each_absent_git_file() {
        let dir = scratch("absent");
        let (home, vendor_files) = (dir.join("home"), dir.join("vendor"));
        let codex_home = dir.join("codex-home");
        let plan = session_plan(&codex_paths(&codex_home, &home, &vendor_files), 40_000).unwrap();
        assert!(plan.grants.contains(&Grant {
            path: vendor_files.clone(),
            access: Access::ReadWrite,
        }));
        let absent: Vec<PathBuf> = GIT_CONFIG_FILES
            .iter()
            .map(|name| home.join(name))
            .collect();
        assert_eq!(plan.absent_paths, absent);
        assert!(
            plan.grants
                .iter()
                .all(|grant| !grant.path.starts_with(&home)),
            "{:?}",
            plan.grants
        );
        assert_eq!(plan.proxy_port, 40_000);
        assert_eq!(plan.core_ports, core_ports(CorePorts::PRODUCTION));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A git file the home has is granted to read and drops out of the absences.
    #[test]
    fn a_present_git_file_is_granted_to_read_and_is_no_absence() {
        let dir = scratch("present");
        let (home, vendor_files) = (dir.join("home"), dir.join("vendor"));
        let codex_home = dir.join("codex-home");
        std::fs::write(home.join(".gitconfig"), "[user]\n").unwrap();
        let plan = session_plan(&codex_paths(&codex_home, &home, &vendor_files), 40_000).unwrap();
        assert!(plan.grants.contains(&Grant {
            path: home.join(".gitconfig"),
            access: Access::Read,
        }));
        assert!(!plan.absent_paths.contains(&home.join(".gitconfig")));
        assert_eq!(plan.absent_paths.len(), GIT_CONFIG_FILES.len() - 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A Codex session gets its Codex home to read and write and nothing of Claude's: no
    /// `~/.claude`, cache, state file or inbox socket directory, and none of them is made.
    #[test]
    fn a_codex_plan_grants_its_codex_home_and_nothing_of_claude_s() {
        let dir = scratch("codex");
        let (home, vendor_files) = (dir.join("home"), dir.join("vendor"));
        let codex_home = dir.join("codex-home");
        let plan = session_plan(&codex_paths(&codex_home, &home, &vendor_files), 40_000).unwrap();
        assert_eq!(
            plan.grants,
            [
                Grant {
                    path: vendor_files.clone(),
                    access: Access::ReadWrite,
                },
                Grant {
                    path: codex_home.clone(),
                    access: Access::ReadWrite,
                },
            ]
        );
        assert!(plan.state_files.is_empty() && plan.socket_dirs.is_empty());
        for name in [CLAUDE_CONFIG_DIR_NAME, CLAUDE_CACHE_DIR, CLAUDE_STATE_FILE] {
            assert!(
                !home.join(name).exists(),
                "{name} was made for a Codex session"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_home_without_its_cache_levels_gets_each_made_and_a_link_among_them_is_refused() {
        let home = std::env::temp_dir().join(format!("tycho-state-{}", std::process::id()));
        if home.exists() {
            std::fs::remove_dir_all(&home).unwrap();
        }
        std::fs::create_dir_all(&home).unwrap();
        let cache =
            ensure_state_path(&home, "Library/Caches/claude-cli-nodejs", current_uid()).unwrap();
        assert!(cache.is_dir());
        assert_eq!(cache, home.join("Library/Caches/claude-cli-nodejs"));
        std::os::unix::fs::symlink(&home, home.join("linked")).unwrap();
        assert!(matches!(
            ensure_state_path(&home, "linked/claude", current_uid()),
            Err(PrepareError::State(..))
        ));
        std::fs::remove_dir_all(&home).unwrap();
    }
}

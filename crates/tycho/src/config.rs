//! Ports, paths, names and bounds of the core; the policy numbers of the spine live in the
//! CUE configuration under `config/` and reach the services through `config_store`.

use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use nix::unistd::{Uid, User};
use tycho_types::session::{SessionName, SOCKET_PATH_MAX_BYTES};

use crate::command::{self, CommandError};
use crate::config_store::CONFIG_DIR_ENV;

pub const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
pub const RESTATE_ADMIN_PORT: u16 = 19070;
pub const RESTATE_INGRESS_PORT: u16 = 18080;
pub const RESTATE_NODE_PORT: u16 = 15122;
pub const ENDPOINT_PORT: u16 = 19080;
/// A fixed node name, so a restarted server finds its own metadata on disk.
pub const RESTATE_NODE_NAME: &str = "tycho";

pub const HOME_ENV: &str = "TYCHO_HOME";
pub const ZMX_ENV: &str = "TYCHO_ZMX";
pub const RESTATE_SERVER_ENV: &str = "TYCHO_RESTATE_SERVER";
pub const HOME_DEFAULT_DIR: &str = ".tycho";
/// Under the private home, never a shared directory: zmx does not check who connects to a
/// socket, and the agents' directory is group-shared.
pub const CORE_SOCKET_DIR: &str = "zmx";
pub const RESTATE_DATA_DIR: &str = "restate";
pub const LOG_DIR: &str = "logs";
pub const STOP_FILE: &str = "watchdog.stop";
pub const OPERATOR_SECRET_FILE: &str = "operator.secret";

pub const LAUNCHD_LABEL: &str = "dev.tycho.watchdog";
pub const LAUNCHD_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// The whole environment of a core process besides `HOME` and its own settings, so the
/// login shell zmx types into cannot leak configuration.
pub const CORE_PROCESS_PATH: &str = "/usr/bin:/bin";

pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
pub const COMMAND_OUTPUT_MAX_BYTES: usize = 64 * 1024;
pub const HTTP_BODY_MAX_BYTES: usize = 64 * 1024;
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);
pub const SESSION_WAIT_POLLS_MAX: u32 = 40;
pub const HEALTH_WAIT_POLLS_MAX: u32 = 120;
/// An unhealthy session younger than this is still booting and is left alone.
pub const STARTUP_GRACE_SECONDS: u64 = 30;
pub const WATCHDOG_INTERVAL: Duration = Duration::from_secs(5);
/// One `watchdog run` lasts at most this many ticks, then exits for launchd to restart it.
pub const WATCHDOG_ITERATIONS_MAX: u32 = 120;
pub const LIST_SESSIONS_MAX: usize = 256;

pub const AGENT_DIR_ENV: &str = "TYCHO_AGENT_DIR";
pub const AGENT_USER_ENV: &str = "TYCHO_AGENT_USER";
/// The dedicated macOS user agents run as.
pub const AGENT_USER_DEFAULT: &str = "tycho-agent";
/// Shared with the developer's group so Ghostty can attach to agent sessions.
pub const AGENT_SOCKET_DIR_DEFAULT: &str = "/Users/Shared/tycho-agent-zmx";
/// The agent user and the developer share the group; others get nothing.
pub const AGENT_DIR_MODE: u32 = 0o770;
pub const LEASE_DIR: &str = "leases";
pub const SPOOL_DIR: &str = "spool";
pub const SPEC_DIR: &str = "specs";
pub const SCROLLBACK_DIR: &str = "scrollback";

pub const ENTIRE_GRAPH_ENV: &str = "TYCHO_ENTIRE_GRAPH";
pub const GRAPH_INDEX_DIR: &str = "graph";
/// The graph plugin version the adapter accepts; its command names changed between releases.
pub const ENTIRE_GRAPH_PINNED_VERSION: &str = "v0.4.0";
/// A cold build of a 1,573-file repository took 42 seconds when the plugin was probed.
pub const GRAPH_BUILD_TIMEOUT: Duration = Duration::from_secs(900);
/// Covers a query that finds no cached index and builds one first.
pub const GRAPH_QUERY_TIMEOUT: Duration = Duration::from_secs(300);
pub const GRAPH_DIFF_BUDGET_SECONDS: u64 = 120;
pub const GRAPH_OUTPUT_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Input and loop bounds of the spine services; the timers, slots and caps are configuration.
pub mod spine {
    pub const RECONCILER_SESSIONS_MAX_PER_TICK: usize = 32;
    pub const RECONCILER_EXPECTED_MAX_SESSIONS: usize = 256;
    pub const EPIC_UNITS_MAX: usize = 64;
    pub const EPIC_RESERVATIONS_MAX: usize = 64;
    pub const SPAWN_ARGV_MAX_ITEMS: usize = 64;
    /// Full-slot answers a run accepts before it gives up; with the slot delay, about an hour.
    pub const RESERVE_ROUNDS_MAX: u32 = 360;
    /// Timer wakes one attempt watches through before it treats the session as stalled.
    pub const WATCH_ROUNDS_MAX: u32 = 10_000;
    /// Tasks one work unit's dispatch plan may name.
    pub const PLAN_TASKS_MAX: usize = 16;
    /// Attempts and rulings one unit run goes through before it is abandoned.
    pub const UNIT_ROUNDS_MAX: u32 = 16;
    /// Ledger limits `tycho epic start` gives a new epic: seat tokens and metered micro-dollars.
    pub const EPIC_SEAT_LIMIT_DEFAULT: u64 = 50_000_000;
    pub const EPIC_METERED_LIMIT_DEFAULT: u64 = 0;
}

/// Core session names are `core.<role>`, used only in the core socket directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreRole {
    Restate,
    Endpoint,
}

impl CoreRole {
    pub const ALL: [Self; 2] = [Self::Restate, Self::Endpoint];

    #[must_use]
    pub const fn session_name(self) -> &'static str {
        match self {
            Self::Restate => "core.restate",
            Self::Endpoint => "core.endpoint",
        }
    }
}

impl fmt::Display for CoreRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.session_name())
    }
}

#[must_use]
pub const fn loopback(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(LOOPBACK, port))
}

#[must_use]
pub fn admin_url(path: &str) -> String {
    format!("http://{}{path}", loopback(RESTATE_ADMIN_PORT))
}

#[must_use]
pub fn ingress_url(path: &str) -> String {
    format!("http://{}{path}", loopback(RESTATE_INGRESS_PORT))
}

#[must_use]
pub fn endpoint_url(path: &str) -> String {
    format!("http://{}{path}", loopback(ENDPOINT_PORT))
}

/// The agent socket directory and the lease and spool directories under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDirs {
    pub socket_dir: PathBuf,
}

impl AgentDirs {
    /// `TYCHO_AGENT_DIR` when set and absolute, else the shared default.
    pub fn from_environment() -> Result<Self, ConfigError> {
        let socket_dir = env::var_os(AGENT_DIR_ENV)
            .map_or_else(|| PathBuf::from(AGENT_SOCKET_DIR_DEFAULT), PathBuf::from);
        Self::new(socket_dir)
    }

    pub fn new(socket_dir: PathBuf) -> Result<Self, ConfigError> {
        if !socket_dir.is_absolute() {
            return Err(ConfigError::RelativePath(AGENT_DIR_ENV, socket_dir));
        }
        Ok(Self { socket_dir })
    }

    #[must_use]
    pub fn lease_dir(&self) -> PathBuf {
        self.socket_dir.join(LEASE_DIR)
    }

    #[must_use]
    pub fn spool_root(&self) -> PathBuf {
        self.socket_dir.join(SPOOL_DIR)
    }

    #[must_use]
    pub fn lease_path(&self, session: &SessionName) -> PathBuf {
        self.lease_dir().join(format!("{session}.lease"))
    }

    /// The heartbeat sequence counter, beside the lease so a restarted launcher continues it.
    #[must_use]
    pub fn sequence_path(&self, session: &SessionName) -> PathBuf {
        self.lease_dir().join(format!("{session}.seq"))
    }

    #[must_use]
    pub fn spec_dir(&self) -> PathBuf {
        self.socket_dir.join(SPEC_DIR)
    }

    /// Where the core leaves the launch spec; the launcher removes it once read.
    #[must_use]
    pub fn spec_path(&self, session: &SessionName) -> PathBuf {
        self.spec_dir().join(format!("{session}.json"))
    }

    #[must_use]
    pub fn spool_dir(&self, session: &SessionName) -> PathBuf {
        self.spool_root().join(session.to_string())
    }
}

/// The agent user's uid: `TYCHO_AGENT_USER` when set, else the default name.
pub fn agent_uid() -> Result<u32, ConfigError> {
    let name = env::var(AGENT_USER_ENV).unwrap_or_else(|_| AGENT_USER_DEFAULT.to_string());
    User::from_name(&name)
        .map_err(|error| ConfigError::UserLookup(error.to_string()))?
        .map(|user| user.uid.as_raw())
        .ok_or(ConfigError::NoAgentUser(name))
}

#[derive(Debug)]
pub enum ConfigError {
    NoAgentUser(String),
    NoHome,
    UserLookup(String),
    HomeOutsideUserHome(PathBuf),
    SymlinkInHome(PathBuf),
    Inspect(PathBuf, io::Error),
    Resolve(&'static str, CommandError),
    NotFound(PathBuf),
    UnsafePath(PathBuf),
    SocketPathTooLong(usize),
    CurrentExe(std::io::Error),
    RelativePath(&'static str, PathBuf),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHome => formatter.write_str("the current uid has no home directory"),
            Self::NoAgentUser(name) => {
                write!(formatter, "no user named {name} for {AGENT_USER_ENV}")
            }
            Self::UserLookup(error) => {
                write!(formatter, "cannot look up the current user: {error}")
            }
            Self::SymlinkInHome(path) => {
                write!(
                    formatter,
                    "{} is a symlink; refusing it in the core home",
                    path.display()
                )
            }
            Self::Inspect(path, error) => {
                write!(formatter, "cannot inspect {}: {error}", path.display())
            }
            Self::HomeOutsideUserHome(path) => write!(
                formatter,
                "{HOME_ENV}={} is not a directory under the user's home",
                path.display()
            ),
            Self::Resolve(tool, error) => write!(formatter, "cannot resolve {tool}: {error}"),
            Self::NotFound(path) => write!(formatter, "{} does not exist", path.display()),
            Self::UnsafePath(path) => write!(
                formatter,
                "{} contains whitespace or shell metacharacters",
                path.display()
            ),
            Self::SocketPathTooLong(length) => write!(
                formatter,
                "core socket path is {length} bytes; limit is {SOCKET_PATH_MAX_BYTES}"
            ),
            Self::CurrentExe(error) => write!(formatter, "cannot locate the tycho binary: {error}"),
            Self::RelativePath(variable, path) => {
                write!(formatter, "{variable}={} is not absolute", path.display())
            }
        }
    }
}

/// Absolute paths of the core's home and of every program it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    pub home: PathBuf,
    pub zmx: PathBuf,
    pub restate_server: PathBuf,
    pub tycho: PathBuf,
    /// `TYCHO_CONFIG_DIR`, forwarded to the endpoint's session when set.
    pub config_dir: Option<PathBuf>,
}

impl CoreConfig {
    /// The home is `.tycho` under the current uid's home from the user database, or
    /// `TYCHO_HOME` when that names a directory under it; tools come from `mise which`.
    pub fn from_environment() -> Result<Self, ConfigError> {
        let home = core_home()?;
        let zmx = tool_path(ZMX_ENV, "zmx")?;
        let restate_server = tool_path(RESTATE_SERVER_ENV, "restate-server")?;
        let tycho = env::current_exe().map_err(ConfigError::CurrentExe)?;
        Self::new(home, zmx, restate_server, tycho)?
            .with_config_dir(env::var_os(CONFIG_DIR_ENV).map(PathBuf::from))
    }

    /// The directory is typed into the endpoint's session, so it must be absolute and shell-safe.
    pub fn with_config_dir(mut self, dir: Option<PathBuf>) -> Result<Self, ConfigError> {
        if let Some(dir) = &dir {
            if !dir.is_absolute() {
                return Err(ConfigError::RelativePath(CONFIG_DIR_ENV, dir.clone()));
            }
            if !is_shell_safe(dir) {
                return Err(ConfigError::UnsafePath(dir.clone()));
            }
        }
        self.config_dir = dir;
        Ok(self)
    }

    /// Every path is typed into a shell by zmx, so each must be shell-safe text.
    pub fn new(
        home: PathBuf,
        zmx: PathBuf,
        restate_server: PathBuf,
        tycho: PathBuf,
    ) -> Result<Self, ConfigError> {
        for path in [&home, &zmx, &restate_server, &tycho] {
            if !is_shell_safe(path) {
                return Err(ConfigError::UnsafePath(path.clone()));
            }
        }
        let config = Self {
            home,
            zmx,
            restate_server,
            tycho,
            config_dir: None,
        };
        let longest = CoreRole::ALL
            .iter()
            .map(|role| {
                config
                    .socket_dir()
                    .join(role.session_name())
                    .as_os_str()
                    .len()
            })
            .max()
            .unwrap_or(0);
        if longest > SOCKET_PATH_MAX_BYTES {
            return Err(ConfigError::SocketPathTooLong(longest));
        }
        Ok(config)
    }

    #[must_use]
    pub fn socket_dir(&self) -> PathBuf {
        self.home.join(CORE_SOCKET_DIR)
    }

    /// Every directory the core writes, parents first.
    #[must_use]
    pub fn dirs(&self) -> [PathBuf; 4] {
        [
            self.home.clone(),
            self.socket_dir(),
            self.restate_data_dir(),
            self.log_dir(),
        ]
    }

    #[must_use]
    pub fn restate_data_dir(&self) -> PathBuf {
        self.home.join(RESTATE_DATA_DIR)
    }

    #[must_use]
    pub fn log_dir(&self) -> PathBuf {
        self.home.join(LOG_DIR)
    }

    #[must_use]
    pub fn stop_file(&self) -> PathBuf {
        self.home.join(STOP_FILE)
    }

    #[must_use]
    pub fn operator_secret_file(&self) -> PathBuf {
        self.home.join(OPERATOR_SECRET_FILE)
    }

    /// The command line typed into the role's zmx session; `exec` makes the session end
    /// with the program and makes the listed pid the program's pid.
    #[must_use]
    pub fn session_command(&self, role: CoreRole) -> String {
        match role {
            CoreRole::Restate => format!(
                "exec /usr/bin/env -i HOME={home} PATH={CORE_PROCESS_PATH} \
                 RESTATE_ADMIN__BIND_ADDRESS={admin} \
                 RESTATE_INGRESS__BIND_ADDRESS={ingress} RESTATE_BIND_ADDRESS={node} \
                 RESTATE_LISTEN_MODE=tcp RESTATE_NODE_NAME={RESTATE_NODE_NAME} \
                 RESTATE_DISABLE_TELEMETRY=true {server} --base-dir {data}",
                home = self.home.display(),
                admin = loopback(RESTATE_ADMIN_PORT),
                ingress = loopback(RESTATE_INGRESS_PORT),
                node = loopback(RESTATE_NODE_PORT),
                server = self.restate_server.display(),
                data = self.restate_data_dir().display(),
            ),
            CoreRole::Endpoint => format!(
                "exec /usr/bin/env -i HOME={home} PATH={CORE_PROCESS_PATH} {HOME_ENV}={home} {config_dir}{} endpoint",
                self.tycho.display(),
                home = self.home.display(),
                config_dir = self
                    .config_dir
                    .as_ref()
                    .map(|dir| format!("{CONFIG_DIR_ENV}={} ", dir.display()))
                    .unwrap_or_default(),
            ),
        }
    }
}

/// `.tycho` under the current uid's home, or `TYCHO_HOME` when that names a directory under it.
pub fn core_home() -> Result<PathBuf, ConfigError> {
    let user_home = user_home()?;
    let Some(home) = env::var_os(HOME_ENV) else {
        return Ok(user_home.join(HOME_DEFAULT_DIR));
    };
    checked_home_override(&user_home, PathBuf::from(home))
}

/// The graph plugin binary: `TYCHO_ENTIRE_GRAPH`, else entire's managed plugin directory.
pub fn entire_graph_path() -> Result<PathBuf, ConfigError> {
    resolve_entire_graph(&PluginDirs {
        binary: env::var_os(ENTIRE_GRAPH_ENV).map(PathBuf::from),
        plugin_dir: env::var_os("ENTIRE_PLUGIN_DIR").map(PathBuf::from),
        data_home: env::var_os("XDG_DATA_HOME").map(PathBuf::from),
        user_home: user_home()?,
    })
}

/// The inputs to the plugin path, in the precedence `entire plugin --help` lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginDirs {
    pub binary: Option<PathBuf>,
    pub plugin_dir: Option<PathBuf>,
    pub data_home: Option<PathBuf>,
    pub user_home: PathBuf,
}

pub fn resolve_entire_graph(dirs: &PluginDirs) -> Result<PathBuf, ConfigError> {
    let path = match (&dirs.binary, &dirs.plugin_dir, &dirs.data_home) {
        (Some(binary), _, _) => binary.clone(),
        (None, Some(dir), _) => absolute("ENTIRE_PLUGIN_DIR", dir)?.join("bin/entire-graph"),
        (None, None, Some(data_home)) => {
            absolute("XDG_DATA_HOME", data_home)?.join("entire/plugins/bin/entire-graph")
        }
        (None, None, None) => dirs
            .user_home
            .join(".local/share/entire/plugins/bin/entire-graph"),
    };
    if !path.is_absolute() || !path.exists() {
        return Err(ConfigError::NotFound(path));
    }
    Ok(path)
}

fn absolute<'a>(variable: &'static str, path: &'a Path) -> Result<&'a Path, ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError::RelativePath(variable, path.to_path_buf()));
    }
    Ok(path)
}

fn user_home() -> Result<PathBuf, ConfigError> {
    User::from_uid(Uid::current())
        .map_err(|error| ConfigError::UserLookup(error.to_string()))?
        .map(|user| user.dir)
        .ok_or(ConfigError::NoHome)
}

fn checked_home_override(user_home: &Path, home: PathBuf) -> Result<PathBuf, ConfigError> {
    let inside = home.is_absolute()
        && home != user_home
        && home.starts_with(user_home)
        && home
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    if !inside {
        return Err(ConfigError::HomeOutsideUserHome(home));
    }
    refuse_symlinks_below(user_home, &home)?;
    Ok(home)
}

/// A symlinked component would let the home resolve outside the user's home; a missing
/// component ends the walk, since `private_dir` creates the rest without following links.
fn refuse_symlinks_below(user_home: &Path, home: &Path) -> Result<(), ConfigError> {
    let mut path = user_home.to_path_buf();
    let below = home.strip_prefix(user_home).unwrap_or(home);
    for component in below.components() {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ConfigError::SymlinkInHome(path));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(ConfigError::Inspect(path, error)),
        }
    }
    Ok(())
}

/// The environment for any mise call: resolving a tool never installs one.
pub const MISE_NO_INSTALL: [(&str, &str); 2] = [
    ("MISE_EXEC_AUTO_INSTALL", "false"),
    ("MISE_NOT_FOUND_AUTO_INSTALL", "false"),
];

fn tool_path(variable: &str, tool: &'static str) -> Result<PathBuf, ConfigError> {
    let path = if let Some(path) = env::var_os(variable) {
        PathBuf::from(path)
    } else {
        let output = command::run_captured(
            Path::new("mise"),
            &["which", tool],
            &MISE_NO_INSTALL,
            COMMAND_TIMEOUT,
        )
        .map_err(|error| ConfigError::Resolve(tool, error))?;
        PathBuf::from(output.stdout.trim())
    };
    if !path.is_absolute() || !path.exists() {
        return Err(ConfigError::NotFound(path));
    }
    Ok(path)
}

#[must_use]
pub fn is_shell_safe(path: &Path) -> bool {
    path.to_str().is_some_and(|text| {
        !text.is_empty()
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "/._-+@".contains(c))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(home: &str) -> Result<CoreConfig, ConfigError> {
        CoreConfig::new(
            PathBuf::from(home),
            PathBuf::from("/opt/zmx"),
            PathBuf::from("/opt/restate-server"),
            PathBuf::from("/opt/tycho"),
        )
    }

    #[test]
    fn puts_the_socket_dir_under_the_home() {
        let config = config("/Users/someone/.tycho").unwrap();
        assert_eq!(
            config.socket_dir(),
            PathBuf::from("/Users/someone/.tycho/zmx")
        );
    }

    #[test]
    fn accepts_a_home_override_under_the_user_home() {
        let user_home = Path::new("/Users/someone");
        let home = PathBuf::from("/Users/someone/.tycho-test");
        assert_eq!(
            checked_home_override(user_home, home.clone()).unwrap(),
            home
        );
    }

    #[test]
    fn rejects_a_home_override_outside_the_user_home() {
        let user_home = Path::new("/Users/someone");
        for home in [
            "/tmp/tycho",
            "/Users/Shared/tycho",
            "/Users/someone",
            "/Users/someone/../other",
            ".tycho",
        ] {
            assert!(matches!(
                checked_home_override(user_home, PathBuf::from(home)),
                Err(ConfigError::HomeOutsideUserHome(_))
            ));
        }
    }

    #[test]
    fn rejects_a_home_with_a_space() {
        assert!(matches!(
            config("/Users/some one/.tycho"),
            Err(ConfigError::UnsafePath(_))
        ));
    }

    #[test]
    fn rejects_a_home_past_the_socket_bound() {
        let home = format!("/{}", "a".repeat(90));
        assert!(matches!(
            config(&home),
            Err(ConfigError::SocketPathTooLong(_))
        ));
    }

    #[test]
    fn endpoint_command_execs_the_binary() {
        let config = config("/h").unwrap();
        assert_eq!(
            config.session_command(CoreRole::Endpoint),
            "exec /usr/bin/env -i HOME=/h PATH=/usr/bin:/bin TYCHO_HOME=/h /opt/tycho endpoint"
        );
    }

    #[test]
    fn endpoint_command_forwards_a_config_dir_and_refuses_a_relative_one() {
        let config = config("/h")
            .unwrap()
            .with_config_dir(Some(PathBuf::from("/h/config")))
            .unwrap();
        assert_eq!(
            config.session_command(CoreRole::Endpoint),
            "exec /usr/bin/env -i HOME=/h PATH=/usr/bin:/bin TYCHO_HOME=/h \
             TYCHO_CONFIG_DIR=/h/config /opt/tycho endpoint"
        );
        assert!(matches!(
            config.with_config_dir(Some(PathBuf::from("config"))),
            Err(ConfigError::RelativePath(CONFIG_DIR_ENV, _))
        ));
    }

    #[test]
    fn restate_command_clears_the_environment() {
        let config = config("/h").unwrap();
        assert_eq!(
            config.session_command(CoreRole::Restate),
            "exec /usr/bin/env -i HOME=/h PATH=/usr/bin:/bin \
             RESTATE_ADMIN__BIND_ADDRESS=127.0.0.1:19070 \
             RESTATE_INGRESS__BIND_ADDRESS=127.0.0.1:18080 RESTATE_BIND_ADDRESS=127.0.0.1:15122 \
             RESTATE_LISTEN_MODE=tcp RESTATE_NODE_NAME=tycho RESTATE_DISABLE_TELEMETRY=true \
             /opt/restate-server --base-dir /h/restate"
        );
    }

    fn plugin_dirs(
        binary: Option<&str>,
        plugin_dir: Option<&str>,
        data_home: Option<&str>,
    ) -> PluginDirs {
        PluginDirs {
            binary: binary.map(PathBuf::from),
            plugin_dir: plugin_dir.map(PathBuf::from),
            data_home: data_home.map(PathBuf::from),
            user_home: PathBuf::from("/nonexistent-home"),
        }
    }

    #[test]
    fn refuses_a_relative_plugin_dir() {
        assert!(matches!(
            resolve_entire_graph(&plugin_dirs(None, Some("plugins"), None)),
            Err(ConfigError::RelativePath("ENTIRE_PLUGIN_DIR", _))
        ));
    }

    #[test]
    fn refuses_a_relative_data_home() {
        assert!(matches!(
            resolve_entire_graph(&plugin_dirs(None, None, Some("share"))),
            Err(ConfigError::RelativePath("XDG_DATA_HOME", _))
        ));
    }

    #[test]
    fn refuses_a_plugin_binary_that_is_relative_or_missing() {
        assert!(matches!(
            resolve_entire_graph(&plugin_dirs(Some("entire-graph"), None, None)),
            Err(ConfigError::NotFound(_))
        ));
        assert!(matches!(
            resolve_entire_graph(&plugin_dirs(None, Some("/nonexistent"), None)),
            Err(ConfigError::NotFound(_))
        ));
        assert!(matches!(
            resolve_entire_graph(&plugin_dirs(None, None, None)),
            Err(ConfigError::NotFound(_))
        ));
    }

    #[test]
    fn accepts_an_existing_absolute_plugin_binary() {
        assert_eq!(
            resolve_entire_graph(&plugin_dirs(Some("/bin/sh"), Some("relative"), None)).unwrap(),
            PathBuf::from("/bin/sh")
        );
    }

    #[test]
    fn rejects_a_home_override_through_a_symlink() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("config-symlink-{}", std::process::id()));
        fs::create_dir_all(base.join("outside")).unwrap();
        let user_home = base.canonicalize().unwrap();
        let outside = user_home.join("outside");
        std::os::unix::fs::symlink(&outside, user_home.join("link")).unwrap();
        let through_link = checked_home_override(&user_home, user_home.join("link/.tycho"));
        let direct = checked_home_override(&user_home, user_home.join("real/.tycho"));
        fs::remove_dir_all(&user_home).unwrap();
        assert!(matches!(through_link, Err(ConfigError::SymlinkInHome(_))));
        assert!(direct.is_ok());
    }
}

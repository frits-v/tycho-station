//! Ports, paths, names and bounds of the core, in one place; issue 37 moves them to CUE
//! configuration.

use std::env;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tycho_types::session::SOCKET_PATH_MAX_BYTES;

use crate::command::{self, CommandError};

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
/// Developer-owned, mode 0700, apart from the agents' group-shared directory, because zmx
/// does not check who connects to a socket.
pub const CORE_SOCKET_DIR: &str = "/Users/Shared/tycho-core-zmx";
pub const CORE_SOCKET_DIR_MODE: u32 = 0o700;
pub const RESTATE_DATA_DIR: &str = "restate";
pub const LOG_DIR: &str = "logs";
pub const STOP_FILE: &str = "watchdog.stop";

pub const LAUNCHD_LABEL: &str = "dev.tycho.watchdog";
pub const LAUNCHD_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

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
pub fn endpoint_url(path: &str) -> String {
    format!("http://{}{path}", loopback(ENDPOINT_PORT))
}

#[derive(Debug)]
pub enum ConfigError {
    NoHome,
    Resolve(&'static str, CommandError),
    NotFound(PathBuf),
    UnsafePath(PathBuf),
    SocketPathTooLong(usize),
    CurrentExe(std::io::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHome => write!(formatter, "neither {HOME_ENV} nor HOME is set"),
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
        }
    }
}

/// Absolute paths of the core's home and of every program it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    pub home: PathBuf,
    pub socket_dir: PathBuf,
    pub zmx: PathBuf,
    pub restate_server: PathBuf,
    pub tycho: PathBuf,
}

impl CoreConfig {
    /// Reads the environment, falling back to `$HOME/.tycho` and `mise which` for tools.
    pub fn from_environment() -> Result<Self, ConfigError> {
        let home = match env::var_os(HOME_ENV) {
            Some(home) => PathBuf::from(home),
            None => PathBuf::from(env::var_os("HOME").ok_or(ConfigError::NoHome)?)
                .join(HOME_DEFAULT_DIR),
        };
        let zmx = tool_path(ZMX_ENV, "zmx")?;
        let restate_server = tool_path(RESTATE_SERVER_ENV, "restate-server")?;
        let tycho = env::current_exe().map_err(ConfigError::CurrentExe)?;
        Self::new(
            home,
            PathBuf::from(CORE_SOCKET_DIR),
            zmx,
            restate_server,
            tycho,
        )
    }

    /// Every path is typed into a shell by zmx, so each must be shell-safe text.
    pub fn new(
        home: PathBuf,
        socket_dir: PathBuf,
        zmx: PathBuf,
        restate_server: PathBuf,
        tycho: PathBuf,
    ) -> Result<Self, ConfigError> {
        for path in [&home, &socket_dir, &zmx, &restate_server, &tycho] {
            if !is_shell_safe(path) {
                return Err(ConfigError::UnsafePath(path.clone()));
            }
        }
        let config = Self {
            home,
            socket_dir,
            zmx,
            restate_server,
            tycho,
        };
        let longest = CoreRole::ALL
            .iter()
            .map(|role| {
                config
                    .socket_dir
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

    /// The command line typed into the role's zmx session; `exec` makes the session end
    /// with the program and makes the listed pid the program's pid.
    #[must_use]
    pub fn session_command(&self, role: CoreRole) -> String {
        match role {
            CoreRole::Restate => format!(
                "exec env RESTATE_ADMIN__BIND_ADDRESS={admin} \
                 RESTATE_INGRESS__BIND_ADDRESS={ingress} RESTATE_BIND_ADDRESS={node} \
                 RESTATE_LISTEN_MODE=tcp RESTATE_NODE_NAME={RESTATE_NODE_NAME} \
                 RESTATE_DISABLE_TELEMETRY=true {server} --base-dir {data}",
                admin = loopback(RESTATE_ADMIN_PORT),
                ingress = loopback(RESTATE_INGRESS_PORT),
                node = loopback(RESTATE_NODE_PORT),
                server = self.restate_server.display(),
                data = self.restate_data_dir().display(),
            ),
            CoreRole::Endpoint => format!("exec {} endpoint", self.tycho.display()),
        }
    }
}

fn tool_path(variable: &str, tool: &'static str) -> Result<PathBuf, ConfigError> {
    let path = if let Some(path) = env::var_os(variable) {
        PathBuf::from(path)
    } else {
        let output =
            command::run_captured(Path::new("mise"), &["which", tool], &[], COMMAND_TIMEOUT)
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
        with_socket_dir(home, CORE_SOCKET_DIR)
    }

    fn with_socket_dir(home: &str, socket_dir: &str) -> Result<CoreConfig, ConfigError> {
        CoreConfig::new(
            PathBuf::from(home),
            PathBuf::from(socket_dir),
            PathBuf::from("/opt/zmx"),
            PathBuf::from("/opt/restate-server"),
            PathBuf::from("/opt/tycho"),
        )
    }

    #[test]
    fn accepts_the_shared_core_socket_dir() {
        let config = config("/Users/someone/.tycho").unwrap();
        assert_eq!(
            config.socket_dir,
            PathBuf::from("/Users/Shared/tycho-core-zmx")
        );
    }

    #[test]
    fn rejects_a_home_with_a_space() {
        assert!(matches!(
            config("/Users/some one/.tycho"),
            Err(ConfigError::UnsafePath(_))
        ));
    }

    #[test]
    fn rejects_a_socket_dir_past_the_socket_bound() {
        let socket_dir = format!("/{}", "a".repeat(90));
        assert!(matches!(
            with_socket_dir("/h", &socket_dir),
            Err(ConfigError::SocketPathTooLong(_))
        ));
    }

    #[test]
    fn endpoint_command_execs_the_binary() {
        let config = config("/h").unwrap();
        assert_eq!(
            config.session_command(CoreRole::Endpoint),
            "exec /opt/tycho endpoint"
        );
    }
}

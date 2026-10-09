//! The launchd user agent that runs `tycho watchdog run`: plist rendering, install,
//! uninstall, and the decoder of `launchctl print`.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::OFlag;
use nix::unistd::{Uid, User};

use crate::command::{self, CommandError};
use crate::config::{
    CoreConfig, COMMAND_TIMEOUT, HOME_ENV, LAUNCHD_LABEL, LAUNCHD_PATH, RESTATE_SERVER_ENV, ZMX_ENV,
};
use crate::private_dir::{self, DirError};

const LAUNCHCTL: &str = "/bin/launchctl";
/// launchd waits this long before restarting an agent that exited.
pub const THROTTLE_SECONDS: u32 = 10;
const PLIST_MODE: u32 = 0o644;

#[must_use]
pub fn render_plist(config: &CoreConfig, label: &str) -> String {
    let log = config.log_dir().join("watchdog.log");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{tycho}</string>
    <string>watchdog</string>
    <string>run</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>{LAUNCHD_PATH}</string>
    <key>{HOME_ENV}</key>
    <string>{home}</string>
    <key>{ZMX_ENV}</key>
    <string>{zmx}</string>
    <key>{RESTATE_SERVER_ENV}</key>
    <string>{restate_server}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>{THROTTLE_SECONDS}</integer>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#,
        tycho = config.tycho.display(),
        home = config.home.display(),
        zmx = config.zmx.display(),
        restate_server = config.restate_server.display(),
        log = log.display(),
    )
}

/// What `launchctl print gui/<uid>/<label>` says about the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    Running {
        pid: u32,
    },
    LoadedNotRunning,
    NotLoaded,
    Unrecognised {
        code: Option<i32>,
        stderr_head: String,
    },
}

/// launchctl exits 113 for a service missing from a domain that exists.
pub const LAUNCHCTL_SERVICE_NOT_FOUND: i32 = 113;
const STDERR_HEAD_MAX_CHARS: usize = 200;

/// Reads only the service's own top-level fields, which carry exactly one tab of indent.
#[must_use]
pub fn decode_print(code: Option<i32>, stdout: &str, stderr: &str) -> AgentState {
    let unrecognised = || AgentState::Unrecognised {
        code,
        stderr_head: stderr.chars().take(STDERR_HEAD_MAX_CHARS).collect(),
    };
    match code {
        Some(0) => {}
        Some(LAUNCHCTL_SERVICE_NOT_FOUND) => return AgentState::NotLoaded,
        _ => return unrecognised(),
    }
    let field = |key: &str| {
        stdout.lines().find_map(|line| {
            line.strip_prefix('\t')
                .filter(|rest| !rest.starts_with('\t'))
                .and_then(|rest| rest.strip_prefix(key))
                .and_then(|rest| rest.strip_prefix(" = "))
        })
    };
    match (field("state"), field("pid")) {
        (Some("running"), Some(pid)) => pid
            .parse::<u32>()
            .map_or_else(|_| unrecognised(), |pid| AgentState::Running { pid }),
        (Some("not running" | "spawn scheduled"), None) => AgentState::LoadedNotRunning,
        _ => unrecognised(),
    }
}

#[derive(Debug)]
pub enum LaunchdError {
    Command(CommandError),
    AlreadyLoaded(String),
    Unrecognised(String, AgentState),
    PlistNotOwned(PathBuf),
    Io(PathBuf, std::io::Error),
    NoHome,
    UserLookup(String),
    Dir(DirError),
}

impl fmt::Display for LaunchdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command(error) => write!(formatter, "{error}"),
            Self::AlreadyLoaded(target) => write!(formatter, "{target} is already loaded"),
            Self::Unrecognised(target, state) => {
                write!(
                    formatter,
                    "{target}: launchctl print is unrecognised: {state:?}; not acting"
                )
            }
            Self::PlistNotOwned(path) => write!(
                formatter,
                "{} exists and is not a regular file owned by the current user",
                path.display()
            ),
            Self::Io(path, error) => write!(formatter, "{}: {error}", path.display()),
            Self::NoHome => formatter.write_str("the current uid has no home directory"),
            Self::UserLookup(error) => {
                write!(formatter, "cannot look up the current user: {error}")
            }
            Self::Dir(error) => write!(formatter, "{error}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Agent {
    pub label: String,
    pub plist_path: PathBuf,
    pub domain: String,
}

impl Agent {
    /// The agent under `~/Library/LaunchAgents` in the `gui/<uid>` domain.
    pub fn for_user(label: &str) -> Result<Self, LaunchdError> {
        let uid = Uid::current();
        let home = User::from_uid(uid)
            .map_err(|error| LaunchdError::UserLookup(error.to_string()))?
            .ok_or(LaunchdError::NoHome)?
            .dir;
        Ok(Self {
            label: label.to_string(),
            plist_path: home
                .join("Library/LaunchAgents")
                .join(format!("{label}.plist")),
            domain: format!("gui/{uid}"),
        })
    }

    pub fn for_default_label() -> Result<Self, LaunchdError> {
        Self::for_user(LAUNCHD_LABEL)
    }

    #[must_use]
    pub fn target(&self) -> String {
        format!("{}/{}", self.domain, self.label)
    }

    pub fn state(&self) -> Result<AgentState, LaunchdError> {
        let target = self.target();
        let captured = command::run_status(
            Path::new(LAUNCHCTL),
            &["print", &target],
            &[],
            COMMAND_TIMEOUT,
        )
        .map_err(LaunchdError::Command)?;
        Ok(decode_print(
            captured.status.code(),
            &captured.stdout,
            &captured.stderr,
        ))
    }

    /// The state, refusing an unrecognised one so nothing acts on a guess.
    fn known_state(&self) -> Result<AgentState, LaunchdError> {
        match self.state()? {
            state @ AgentState::Unrecognised { .. } => {
                Err(LaunchdError::Unrecognised(self.target(), state))
            }
            state => Ok(state),
        }
    }

    /// Refuses when the label is loaded, so it never replaces an agent it did not load.
    pub fn install(&self, config: &CoreConfig) -> Result<String, LaunchdError> {
        if self.known_state()? != AgentState::NotLoaded {
            return Err(LaunchdError::AlreadyLoaded(self.target()));
        }
        private_dir::ensure(&config.dirs()).map_err(LaunchdError::Dir)?;
        remove_owned_file(&config.stop_file())?;
        if let Some(parent) = self.plist_path.parent() {
            private_dir::ensure_owned(parent).map_err(LaunchdError::Dir)?;
        }
        remove_owned_file(&self.plist_path)?;
        write_new_file(
            &self.plist_path,
            render_plist(config, &self.label).as_bytes(),
        )?;
        let plist = self.plist_path.display().to_string();
        let bootstrapped = command::run_captured(
            Path::new(LAUNCHCTL),
            &["bootstrap", &self.domain, &plist],
            &[],
            COMMAND_TIMEOUT,
        );
        if let Err(error) = bootstrapped {
            remove_owned_file(&self.plist_path)?;
            return Err(LaunchdError::Command(error));
        }
        Ok(format!("bootstrapped {} from {plist}", self.target()))
    }

    /// Boots the agent out if loaded and removes its plist if present.
    pub fn uninstall(&self) -> Result<String, LaunchdError> {
        let target = self.target();
        let was_loaded = self.known_state()? != AgentState::NotLoaded;
        if was_loaded {
            command::run_captured(
                Path::new(LAUNCHCTL),
                &["bootout", &target],
                &[],
                COMMAND_TIMEOUT,
            )
            .map_err(LaunchdError::Command)?;
        }
        let had_file = remove_owned_file(&self.plist_path)?;
        Ok(format!(
            "{target}: booted out {was_loaded}, plist removed {had_file}"
        ))
    }
}

/// Removes a regular file the current user owns; refuses a symlink or a foreign file.
fn remove_owned_file(path: &Path) -> Result<bool, LaunchdError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(LaunchdError::Io(path.to_path_buf(), error)),
    };
    if !metadata.file_type().is_file() || metadata.uid() != Uid::current().as_raw() {
        return Err(LaunchdError::PlistNotOwned(path.to_path_buf()));
    }
    fs::remove_file(path).map_err(|error| LaunchdError::Io(path.to_path_buf(), error))?;
    Ok(true)
}

/// Creates the file only if nothing is there, never through a symlink.
fn write_new_file(path: &Path, contents: &[u8]) -> Result<(), LaunchdError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PLIST_MODE)
        .custom_flags(OFlag::O_NOFOLLOW.bits())
        .open(path)
        .map_err(|error| LaunchdError::Io(path.to_path_buf(), error))?;
    file.write_all(contents)
        .map_err(|error| LaunchdError::Io(path.to_path_buf(), error))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.tycho.watchdog</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/bin/tycho</string>
    <string>watchdog</string>
    <string>run</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>TYCHO_HOME</key>
    <string>/Users/someone/.tycho</string>
    <key>TYCHO_ZMX</key>
    <string>/opt/zmx/0.8.1/zmx</string>
    <key>TYCHO_RESTATE_SERVER</key>
    <string>/opt/restate-server/1.7.13/restate-server</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>StandardOutPath</key>
  <string>/Users/someone/.tycho/logs/watchdog.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/someone/.tycho/logs/watchdog.log</string>
</dict>
</plist>
"#;

    #[test]
    fn renders_the_plist() {
        let config = CoreConfig::new(
            PathBuf::from("/Users/someone/.tycho"),
            PathBuf::from("/opt/zmx/0.8.1/zmx"),
            PathBuf::from("/opt/restate-server/1.7.13/restate-server"),
            PathBuf::from("/opt/bin/tycho"),
        )
        .unwrap();
        assert_eq!(render_plist(&config, LAUNCHD_LABEL), EXPECTED);
    }

    const RUNNING: &str = include_str!("fixtures/launchctl-print-running.txt");
    const SCHEDULED: &str = include_str!("fixtures/launchctl-print-scheduled.txt");
    const NOT_FOUND: &str = include_str!("fixtures/launchctl-print-113.txt");
    const NO_DOMAIN: &str = include_str!("fixtures/launchctl-print-112.txt");

    #[test]
    fn decodes_a_running_agent() {
        assert_eq!(
            decode_print(Some(0), RUNNING, ""),
            AgentState::Running { pid: 94267 }
        );
    }

    #[test]
    fn decodes_a_loaded_agent_waiting_to_respawn() {
        assert_eq!(
            decode_print(Some(0), SCHEDULED, ""),
            AgentState::LoadedNotRunning
        );
    }

    #[test]
    fn decodes_exit_113_as_not_loaded() {
        assert_eq!(
            decode_print(Some(113), "", NOT_FOUND),
            AgentState::NotLoaded
        );
    }

    #[test]
    fn decodes_a_missing_domain_as_unrecognised() {
        assert_eq!(
            decode_print(Some(112), "", NO_DOMAIN),
            AgentState::Unrecognised {
                code: Some(112),
                stderr_head: NO_DOMAIN.to_string()
            }
        );
    }

    #[test]
    fn decodes_unexpected_output_as_unrecognised() {
        for stdout in [
            "\tstate = sleeping\n",
            "\tstate = running\n\tpid = minus one\n",
            "\t\tstate = running\n\t\tpid = 3\n",
        ] {
            assert!(matches!(
                decode_print(Some(0), stdout, ""),
                AgentState::Unrecognised { code: Some(0), .. }
            ));
        }
        assert!(matches!(
            decode_print(None, "", ""),
            AgentState::Unrecognised { code: None, .. }
        ));
    }
}

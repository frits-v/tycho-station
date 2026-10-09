//! The launchd user agent that runs `tycho watchdog run`: plist rendering, install,
//! uninstall, and the decoder of `launchctl print`.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::command::{self, CommandError};
use crate::config::{
    CoreConfig, COMMAND_TIMEOUT, HOME_ENV, LAUNCHD_LABEL, LAUNCHD_PATH, RESTATE_SERVER_ENV, ZMX_ENV,
};

const LAUNCHCTL: &str = "/bin/launchctl";
const ID: &str = "/usr/bin/id";
/// launchd waits this long before restarting an agent that exited.
pub const THROTTLE_SECONDS: u32 = 10;

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
  <true/>
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    Running { pid: u32 },
    LoadedNotRunning,
    NotLoaded,
    Unrecognised,
}

/// launchctl exits non-zero for an unknown service; a loaded one prints `state = ...`.
#[must_use]
pub fn decode_print(exit_success: bool, stdout: &str) -> AgentState {
    if !exit_success {
        return AgentState::NotLoaded;
    }
    let field = |key: &str| {
        stdout.lines().find_map(|line| {
            line.trim()
                .strip_prefix(key)
                .and_then(|rest| rest.trim_start().strip_prefix('='))
                .map(str::trim)
        })
    };
    match (field("state"), field("pid")) {
        (Some("running"), Some(pid)) => pid
            .parse::<u32>()
            .map_or(AgentState::Unrecognised, |pid| AgentState::Running { pid }),
        (Some("not running" | "spawn scheduled" | "exited"), None) => AgentState::LoadedNotRunning,
        _ => AgentState::Unrecognised,
    }
}

#[derive(Debug)]
pub enum LaunchdError {
    Command(CommandError),
    AlreadyLoaded(String),
    Io(PathBuf, std::io::Error),
    NoHome,
    BadUid(String),
}

impl fmt::Display for LaunchdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command(error) => write!(formatter, "{error}"),
            Self::AlreadyLoaded(target) => write!(formatter, "{target} is already loaded"),
            Self::Io(path, error) => write!(formatter, "{}: {error}", path.display()),
            Self::NoHome => formatter.write_str("HOME is not set"),
            Self::BadUid(text) => write!(formatter, "id -u printed {text:?}"),
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
        let home = std::env::var_os("HOME").ok_or(LaunchdError::NoHome)?;
        let uid_text = command::run_captured(Path::new(ID), &["-u"], &[], COMMAND_TIMEOUT)
            .map_err(LaunchdError::Command)?
            .stdout;
        let uid: u32 = uid_text
            .trim()
            .parse()
            .map_err(|_| LaunchdError::BadUid(uid_text.clone()))?;
        Ok(Self {
            label: label.to_string(),
            plist_path: PathBuf::from(home)
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
        Ok(decode_print(captured.status.success(), &captured.stdout))
    }

    /// Refuses when the label is already loaded, so it never replaces an agent it did not load.
    pub fn install(&self, config: &CoreConfig) -> Result<String, LaunchdError> {
        if self.state()? != AgentState::NotLoaded {
            return Err(LaunchdError::AlreadyLoaded(self.target()));
        }
        let log_dir = config.log_dir();
        fs::create_dir_all(&log_dir).map_err(|error| LaunchdError::Io(log_dir, error))?;
        if let Some(parent) = self.plist_path.parent() {
            fs::create_dir_all(parent).map_err(|error| LaunchdError::Io(parent.into(), error))?;
        }
        fs::write(&self.plist_path, render_plist(config, &self.label))
            .map_err(|error| LaunchdError::Io(self.plist_path.clone(), error))?;
        let plist = self.plist_path.display().to_string();
        command::run_captured(
            Path::new(LAUNCHCTL),
            &["bootstrap", &self.domain, &plist],
            &[],
            COMMAND_TIMEOUT,
        )
        .map_err(LaunchdError::Command)?;
        Ok(format!("bootstrapped {} from {plist}", self.target()))
    }

    /// Boots the agent out if loaded and removes its plist if present.
    pub fn uninstall(&self) -> Result<String, LaunchdError> {
        let target = self.target();
        let was_loaded = self.state()? != AgentState::NotLoaded;
        if was_loaded {
            command::run_captured(
                Path::new(LAUNCHCTL),
                &["bootout", &target],
                &[],
                COMMAND_TIMEOUT,
            )
            .map_err(LaunchdError::Command)?;
        }
        let had_file = self.plist_path.exists();
        if had_file {
            fs::remove_file(&self.plist_path)
                .map_err(|error| LaunchdError::Io(self.plist_path.clone(), error))?;
        }
        Ok(format!(
            "{target}: booted out {was_loaded}, plist removed {had_file}"
        ))
    }
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
  <true/>
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

    #[test]
    fn decodes_a_running_agent() {
        let stdout = "gui/501/dev.tycho.watchdog = {\n\tactive count = 1\n\tstate = running\n\tpid = 4242\n}";
        assert_eq!(
            decode_print(true, stdout),
            AgentState::Running { pid: 4242 }
        );
    }

    #[test]
    fn decodes_a_loaded_agent_waiting_to_respawn() {
        let stdout = "gui/501/dev.tycho.watchdog = {\n\tstate = spawn scheduled\n}";
        assert_eq!(decode_print(true, stdout), AgentState::LoadedNotRunning);
    }

    #[test]
    fn decodes_an_unknown_service_as_not_loaded() {
        assert_eq!(decode_print(false, ""), AgentState::NotLoaded);
    }

    #[test]
    fn decodes_unexpected_output_as_unrecognised() {
        assert_eq!(
            decode_print(true, "state = sleeping"),
            AgentState::Unrecognised
        );
        assert_eq!(
            decode_print(true, "state = running\npid = minus one"),
            AgentState::Unrecognised
        );
    }
}

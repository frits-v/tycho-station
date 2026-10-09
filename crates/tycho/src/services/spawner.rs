//! The port through which services start and stop agent sessions under zmx; the launcher
//! side implements it, and `doubles` holds the test implementation.

use std::fmt;

use tycho_types::envelope::ShortText;
use tycho_types::launcher::LauncherEnv;
use tycho_types::lease::Lease;
use tycho_types::session::SessionName;
use tycho_types::task_packet::AbsolutePath;

/// Whether the vendor writes bounded files or owns the session's pty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnTerminal {
    #[default]
    Files,
    /// An interactive control session.
    Inherit,
}

/// One detached zmx session: name, launcher argv and environment, and how the vendor runs.
#[derive(Debug, Clone)]
pub struct SpawnSpec {
    pub session: SessionName,
    pub argv: Vec<ShortText>,
    pub environment: LauncherEnv,
    pub terminal: SpawnTerminal,
    pub working_dir: Option<AbsolutePath>,
}

/// What became of a lease read; an unreadable file is a failure, never an absent lease.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LeaseRead {
    Absent,
    Present { lease: Lease },
    Unreadable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnerError {
    /// Worth retrying: zmx or the file system did not answer.
    Transient(String),
    /// Never worth retrying: the request itself is refused.
    Refused(String),
}

impl fmt::Display for SpawnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient(reason) => write!(formatter, "spawner (transient): {reason}"),
            Self::Refused(reason) => write!(formatter, "spawner refused: {reason}"),
        }
    }
}

impl std::error::Error for SpawnerError {}

/// Blocking calls; services run them off the async runtime inside journaled steps.
pub trait Spawner: Send + Sync + 'static {
    /// A short label for diagnostics.
    fn describe(&self) -> String;
    /// Starts the session detached and returns the launcher's pid.
    fn spawn(&self, spec: &SpawnSpec) -> Result<u32, SpawnerError>;
    /// Kills by the recorded pid, never by session name alone.
    fn kill(&self, session: &SessionName, pid: u32) -> Result<(), SpawnerError>;
    /// Kills a lost session by its zmx name; a lost session's pid is never trusted.
    fn kill_by_name(&self, session: &SessionName) -> Result<(), SpawnerError>;
    /// Saves the session's scrollback as evidence and returns where it went.
    fn save_scrollback(&self, session: &SessionName) -> Result<ShortText, SpawnerError>;
    /// Types one line into the session's stdin and submits it, for a nudge.
    fn send(&self, session: &SessionName, text: &ShortText) -> Result<(), SpawnerError>;
    /// Reads the lease file the launcher keeps for this session name.
    fn read_lease(&self, session: &SessionName) -> LeaseRead;
}

/// The production stand-in until a launcher is installed: every call is refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoLauncher;

const NO_LAUNCHER: &str = "no launcher is installed in this endpoint";

impl Spawner for NoLauncher {
    fn describe(&self) -> String {
        "no launcher".to_string()
    }

    fn spawn(&self, _spec: &SpawnSpec) -> Result<u32, SpawnerError> {
        Err(SpawnerError::Refused(NO_LAUNCHER.to_string()))
    }

    fn kill(&self, _session: &SessionName, _pid: u32) -> Result<(), SpawnerError> {
        Err(SpawnerError::Refused(NO_LAUNCHER.to_string()))
    }

    fn kill_by_name(&self, _session: &SessionName) -> Result<(), SpawnerError> {
        Err(SpawnerError::Refused(NO_LAUNCHER.to_string()))
    }

    fn save_scrollback(&self, _session: &SessionName) -> Result<ShortText, SpawnerError> {
        Err(SpawnerError::Refused(NO_LAUNCHER.to_string()))
    }

    fn send(&self, _session: &SessionName, _text: &ShortText) -> Result<(), SpawnerError> {
        Err(SpawnerError::Refused(NO_LAUNCHER.to_string()))
    }

    fn read_lease(&self, _session: &SessionName) -> LeaseRead {
        LeaseRead::Unreadable {
            reason: NO_LAUNCHER.to_string(),
        }
    }
}

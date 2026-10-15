//! The core's zmx sessions: the `zmx list` decoder, and run, kill and list in the core
//! socket directory.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use nix::fcntl::OFlag;
use nix::unistd::Uid;

use tycho_types::agent_switch::{SUDO, SWITCHED_HOME};
use tycho_types::lease::PID_MAX;

use nix::sys::signal::Signal;

use crate::command::{self, Captured, CommandError};
use crate::config::{COMMAND_OUTPUT_MAX_BYTES, COMMAND_TIMEOUT, LIST_SESSIONS_MAX};
use crate::process::{self, ProcessFacts};

/// Set inside a zmx session: zmx refuses to attach from inside one, and nothing zmx runs for
/// the core inherits the caller's session.
pub const SESSION_ENV: &str = "ZMX_SESSION";

/// The core directory is private: zmx does not check who connects to a socket.
const CORE_DIR_MODE: &str = "0700";
/// Matches `AGENT_DIR_MODE`: the agent user and the developer share the group.
const AGENT_ZMX_DIR_MODE: &str = "0770";
/// The log zmx appends to stays writable by the other side of the shared group.
const AGENT_ZMX_LOG_MODE: &str = "0660";
/// zmx masks the socket, directory and log modes with the process umask, so every zmx run in
/// the shared directory, the developer's clients included, runs under 007.
const SHELL: &str = "/bin/sh";
const UMASK_EXEC: &str = "umask 007; exec \"$0\" \"$@\"";
/// `zmx run` starts `bash` through `PATH`; the shared directory's sessions get the system's.
const AGENT_PATH: &str = "/usr/bin:/bin";

/// One line of `zmx list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListEntry {
    Running {
        name: String,
        pid: u32,
        created_unix_seconds: u64,
    },
    Ended {
        name: String,
        pid: u32,
        exit_code: i32,
    },
    Unrecognised(String),
}

/// Where one session name stands in a decoded list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Running {
        pid: u32,
        created_unix_seconds: u64,
    },
    Ended {
        pid: u32,
    },
    Absent,
    /// The list held a line the decoder could not read, so absence cannot be trusted.
    Unrecognised,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ListError {
    TooManySessions(usize),
}

pub fn decode_list(stdout: &str) -> Result<Vec<ListEntry>, ListError> {
    let lines: Vec<&str> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.len() > LIST_SESSIONS_MAX {
        return Err(ListError::TooManySessions(lines.len()));
    }
    Ok(lines.into_iter().map(decode_line).collect())
}

fn decode_line(line: &str) -> ListEntry {
    let mut name = None;
    let mut pid = None;
    let mut created = None;
    let mut ended = false;
    let mut exit_code = None;
    for field in line.trim_start_matches([' ', '*']).split('\t') {
        match field.split_once('=') {
            Some(("name", value)) if !value.is_empty() => name = Some(value.to_string()),
            Some(("pid", value)) => {
                pid = value
                    .parse::<u32>()
                    .ok()
                    .filter(|pid| (1..=PID_MAX).contains(pid));
            }
            Some(("created", value)) => created = value.parse::<u64>().ok(),
            Some(("ended", _)) => ended = true,
            Some(("exit_code", value)) => exit_code = value.parse::<i32>().ok(),
            Some(("clients" | "cwd", _)) => {}
            _ => return ListEntry::Unrecognised(line.to_string()),
        }
    }
    match (name, pid, created, ended, exit_code) {
        (Some(name), Some(pid), Some(created_unix_seconds), false, None) => ListEntry::Running {
            name,
            pid,
            created_unix_seconds,
        },
        (Some(name), Some(pid), Some(_), true, Some(exit_code)) => ListEntry::Ended {
            name,
            pid,
            exit_code,
        },
        _ => ListEntry::Unrecognised(line.to_string()),
    }
}

#[must_use]
pub fn presence(entries: &[ListEntry], name: &str) -> Presence {
    if entries
        .iter()
        .any(|entry| matches!(entry, ListEntry::Unrecognised(_)))
    {
        return Presence::Unrecognised;
    }
    let mut found = Presence::Absent;
    let mut count = 0_usize;
    for entry in entries {
        match entry {
            ListEntry::Running {
                name: listed,
                pid,
                created_unix_seconds,
            } if listed == name => {
                count = count.saturating_add(1);
                found = Presence::Running {
                    pid: *pid,
                    created_unix_seconds: *created_unix_seconds,
                };
            }
            ListEntry::Ended {
                name: listed, pid, ..
            } if listed == name => {
                count = count.saturating_add(1);
                found = Presence::Ended { pid: *pid };
            }
            _ => {}
        }
    }
    if count > 1 {
        return Presence::Unrecognised;
    }
    found
}

/// Counts the entries carrying a name, for the no-duplicate assertion.
#[must_use]
pub fn count_named(entries: &[ListEntry], name: &str) -> usize {
    entries
        .iter()
        .filter(|entry| match entry {
            ListEntry::Running { name: listed, .. } | ListEntry::Ended { name: listed, .. } => {
                listed == name
            }
            ListEntry::Unrecognised(_) => false,
        })
        .count()
}

/// The directory and file zmx 0.8.1 logs to under `ZMX_DIR`.
///
/// zmx appends to `logs/zmx.log` by path, following a link, opens it before any subcommand and
/// exits if it cannot, and truncates it by path past 2 MiB. It reads no variable that moves the
/// log. In the shared directory the log directory is therefore the developer's, closed to group
/// writes, and the log a regular file of the developer's the shared group can append to: the
/// agent can neither replace the log nor rename the directory, which the sticky bit on the
/// shared directory protects.
pub const LOG_DIR: &str = "logs";
pub const LOG_FILE: &str = "zmx.log";
const LOG_DIR_MODE: u32 = 0o750;
const LOG_FILE_MODE: u32 = 0o660;
const GROUP_WRITE: u32 = 0o020;
const STICKY: u32 = 0o1000;
const SHARED_DIR_MODE: u32 = 0o1770;
/// Modes a log directory and file are created with before the exact mode is set on the
/// descriptor.
const CREATE_DIR_MODE: u32 = 0o700;
const CREATE_FILE_MODE: u32 = 0o600;

/// Why the shared directory's log is not one the developer may append to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogRefusal {
    /// The shared directory lets its group rename entries: no sticky bit.
    NotSticky {
        dir: PathBuf,
        mode: u32,
    },
    NotDirectory(PathBuf),
    Foreign {
        path: PathBuf,
        uid: u32,
    },
    /// A link, a FIFO, a directory or anything else that is not a regular file.
    NotRegular(PathBuf),
    HardLinked {
        path: PathBuf,
        links: u64,
    },
    Io {
        path: PathBuf,
        error: String,
    },
}

impl std::fmt::Display for LogRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSticky { dir, mode } => write!(
                formatter,
                "{} has mode {mode:04o}: group-writable without the sticky bit, so the agent \
                 could rename the core's entries; `xtask provision-agent` sets 3770",
                dir.display()
            ),
            Self::NotDirectory(path) => write!(formatter, "{} is not a directory", path.display()),
            Self::Foreign { path, uid } => write!(
                formatter,
                "{} belongs to uid {uid}, not the core; remove it as its owner",
                path.display()
            ),
            Self::NotRegular(path) => write!(
                formatter,
                "{} is not a regular file; zmx would follow or block on it",
                path.display()
            ),
            Self::HardLinked { path, links } => write!(
                formatter,
                "{} has {links} links; zmx would append to every one",
                path.display()
            ),
            Self::Io { path, error } => write!(formatter, "{}: {error}", path.display()),
        }
    }
}

fn io_refusal(path: &Path) -> impl Fn(io::Error) -> LogRefusal + '_ {
    move |error| LogRefusal::Io {
        path: path.to_path_buf(),
        error: error.to_string(),
    }
}

/// The shared directory itself: a directory whose group cannot rename entries it does not own.
pub fn check_shared_dir(kind_is_dir: bool, mode: u32, dir: &Path) -> Result<(), LogRefusal> {
    if !kind_is_dir {
        return Err(LogRefusal::NotDirectory(dir.to_path_buf()));
    }
    if mode & GROUP_WRITE != 0 && mode & STICKY == 0 {
        return Err(LogRefusal::NotSticky {
            dir: dir.to_path_buf(),
            mode: mode & 0o7777,
        });
    }
    Ok(())
}

/// The opened log directory: a directory of the core's; its mode is then set exactly.
pub fn check_log_dir(
    kind_is_dir: bool,
    uid: u32,
    core_uid: u32,
    path: &Path,
) -> Result<(), LogRefusal> {
    if !kind_is_dir {
        return Err(LogRefusal::NotDirectory(path.to_path_buf()));
    }
    if uid != core_uid {
        return Err(LogRefusal::Foreign {
            path: path.to_path_buf(),
            uid,
        });
    }
    Ok(())
}

/// The opened log: a regular file of the core's with one link; its mode is then set exactly.
pub fn check_log_file(
    kind_is_file: bool,
    uid: u32,
    links: u64,
    core_uid: u32,
    path: &Path,
) -> Result<(), LogRefusal> {
    if !kind_is_file {
        return Err(LogRefusal::NotRegular(path.to_path_buf()));
    }
    if uid != core_uid {
        return Err(LogRefusal::Foreign {
            path: path.to_path_buf(),
            uid,
        });
    }
    if links != 1 {
        return Err(LogRefusal::HardLinked {
            path: path.to_path_buf(),
            links,
        });
    }
    Ok(())
}

fn set_exact_mode(file: &File, mode: u32, path: &Path) -> Result<(), LogRefusal> {
    let found = file.metadata().map_err(io_refusal(path))?.mode() & 0o7777;
    if found != mode {
        file.set_permissions(Permissions::from_mode(mode))
            .map_err(io_refusal(path))?;
    }
    Ok(())
}

/// Makes a missing shared directory as zmx would, group-shared, and sticky; a provisioned one
/// already exists with the shared group.
fn create_shared_dir(path: &Path) -> Result<(), LogRefusal> {
    DirBuilder::new()
        .mode(CREATE_DIR_MODE)
        .create(path)
        .map_err(io_refusal(path))?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY | OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(io_refusal(path))?;
    set_exact_mode(&dir, SHARED_DIR_MODE, path)
}

/// Opens an existing log directory without following a link, or creates it new.
fn open_log_dir(path: &Path) -> Result<File, LogRefusal> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => DirBuilder::new()
            .mode(CREATE_DIR_MODE)
            .create(path)
            .map_err(io_refusal(path))?,
        Err(error) => return Err(io_refusal(path)(error)),
    }
    OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY | OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(code) if code == libc_eloop() || code == libc_enotdir() => {
                LogRefusal::NotDirectory(path.to_path_buf())
            }
            _ => io_refusal(path)(error),
        })
}

/// Opens an existing log without following a link or blocking on a FIFO.
fn open_existing_log(path: &Path) -> Result<Option<File>, LogRefusal> {
    let opened = OpenOptions::new()
        .read(true)
        .append(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path);
    match opened {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) if error.raw_os_error() == Some(libc_eloop()) => {
            Err(LogRefusal::NotRegular(path.to_path_buf()))
        }
        Err(error) => Err(io_refusal(path)(error)),
    }
}

fn create_log(path: &Path) -> Result<File, LogRefusal> {
    OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .mode(CREATE_FILE_MODE)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(io_refusal(path))
}

fn checked_log(file: File, core_uid: u32, path: &Path) -> Result<File, LogRefusal> {
    let facts = file.metadata().map_err(io_refusal(path))?;
    check_log_file(
        facts.file_type().is_file(),
        facts.uid(),
        facts.nlink(),
        core_uid,
        path,
    )?;
    Ok(file)
}

/// The log, created new when absent or when the name holds a link, a FIFO, another user's file
/// or a file with a second link: the core owns the log directory, so it unlinks the name, which
/// follows nothing, and a link the agent made elsewhere keeps only the old inode.
fn core_log(path: &Path, core_uid: u32) -> Result<File, LogRefusal> {
    let existing = open_existing_log(path).and_then(|file| {
        file.map(|file| checked_log(file, core_uid, path))
            .transpose()
    });
    match existing {
        Ok(Some(file)) => return Ok(file),
        Ok(None) => {}
        Err(
            LogRefusal::NotRegular(_) | LogRefusal::HardLinked { .. } | LogRefusal::Foreign { .. },
        ) => fs::remove_file(path).map_err(io_refusal(path))?,
        Err(other) => return Err(other),
    }
    checked_log(create_log(path)?, core_uid, path)
}

const fn libc_eloop() -> i32 {
    nix::errno::Errno::ELOOP as i32
}

const fn libc_enotdir() -> i32 {
    nix::errno::Errno::ENOTDIR as i32
}

/// Makes the shared directory's zmx log safe for the core to append to.
///
/// Runs before any zmx command the core runs there. The directory must be the core's, and
/// sticky when its group can write it; it is made so when missing, as zmx would otherwise make
/// it without the sticky bit. `logs` must be the core's and is set to 0750, and `zmx.log` is
/// kept a regular file of the core's with one link at 0660.
pub fn prepare_shared_log(socket_dir: &Path) -> Result<(), LogRefusal> {
    let core_uid = Uid::current().as_raw();
    let shared = match fs::symlink_metadata(socket_dir) {
        Ok(facts) => facts,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_shared_dir(socket_dir)?;
            fs::symlink_metadata(socket_dir).map_err(io_refusal(socket_dir))?
        }
        Err(error) => return Err(io_refusal(socket_dir)(error)),
    };
    check_shared_dir(shared.file_type().is_dir(), shared.mode(), socket_dir)?;
    if shared.uid() != core_uid {
        return Err(LogRefusal::Foreign {
            path: socket_dir.to_path_buf(),
            uid: shared.uid(),
        });
    }
    let dir_path = socket_dir.join(LOG_DIR);
    let dir = open_log_dir(&dir_path)?;
    let facts = dir.metadata().map_err(io_refusal(&dir_path))?;
    check_log_dir(facts.file_type().is_dir(), facts.uid(), core_uid, &dir_path)?;
    set_exact_mode(&dir, LOG_DIR_MODE, &dir_path)?;
    let file_path = dir_path.join(LOG_FILE);
    let file = core_log(&file_path, core_uid)?;
    set_exact_mode(&file, LOG_FILE_MODE, &file_path)
}

/// The agent's side of the same log, before the launcher's own zmx command.
///
/// The shared directory must be sticky when its group can write it, `logs` a real directory, and `zmx.log` a
/// regular file. The agent creates and repairs nothing there; the core owns both.
pub fn check_shared_log_as_agent(socket_dir: &Path) -> Result<(), LogRefusal> {
    let shared = fs::symlink_metadata(socket_dir).map_err(io_refusal(socket_dir))?;
    check_shared_dir(shared.file_type().is_dir(), shared.mode(), socket_dir)?;
    let dir_path = socket_dir.join(LOG_DIR);
    let dir = fs::symlink_metadata(&dir_path).map_err(io_refusal(&dir_path))?;
    if !dir.file_type().is_dir() {
        return Err(LogRefusal::NotDirectory(dir_path));
    }
    let file_path = dir_path.join(LOG_FILE);
    match open_existing_log(&file_path)? {
        Some(file) => {
            let facts = file.metadata().map_err(io_refusal(&file_path))?;
            if facts.file_type().is_file() {
                Ok(())
            } else {
                Err(LogRefusal::NotRegular(file_path))
            }
        }
        None => Err(LogRefusal::Io {
            path: file_path,
            error: "absent; the core makes it before any session starts".to_string(),
        }),
    }
}

#[derive(Debug)]
pub enum ZmxError {
    Log(LogRefusal),
    Command(CommandError),
    List(ListError),
    RunFailed(ExitStatus),
    /// `zmx run` through sudo as the agent failed; sudo's refusal is not captured, since the
    /// session daemon would inherit a capture pipe.
    SwitchedRunFailed {
        agent: String,
        status: ExitStatus,
    },
}

impl std::fmt::Display for ZmxError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Log(refusal) => write!(formatter, "{refusal}"),
            Self::Command(error) => write!(formatter, "{error}"),
            Self::List(ListError::TooManySessions(count)) => write!(
                formatter,
                "zmx list has {count} sessions; limit is {LIST_SESSIONS_MAX}"
            ),
            Self::RunFailed(status) => write!(formatter, "zmx run exited with {status}"),
            Self::SwitchedRunFailed { agent, status } => write!(
                formatter,
                "sudo -n -u {agent} zmx run exited with {status}; `xtask setup` reads the \
                 sudoers rule back and `xtask provision-agent` installs it"
            ),
        }
    }
}

/// Which socket directory a `Zmx` drives, and as whom it starts sessions there.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Directory {
    /// The core's private directory, as the caller.
    Core,
    /// The directory the developer's group shares with the agent, as the core, which owns it.
    /// With an agent user, `run` goes through the sudoers rule as that user; every other
    /// subcommand is the core's, over the socket the shared group can connect to.
    Shared { agent: Option<String> },
    /// The same directory as the agent, for a launcher's command on its own session.
    SharedFromAgent,
}

/// zmx bound to one socket directory.
#[derive(Debug, Clone)]
pub struct Zmx {
    binary: PathBuf,
    socket_dir: String,
    directory: Directory,
}

impl Zmx {
    #[must_use]
    pub fn new(binary: &Path, socket_dir: &Path) -> Self {
        Self {
            binary: binary.to_path_buf(),
            socket_dir: socket_dir.display().to_string(),
            directory: Directory::Core,
        }
    }

    /// zmx bound to the agent socket directory, which the developer's group shares; sessions
    /// start as the caller.
    #[must_use]
    pub fn agent(binary: &Path, socket_dir: &Path) -> Self {
        Self {
            binary: binary.to_path_buf(),
            socket_dir: socket_dir.display().to_string(),
            directory: Directory::Shared { agent: None },
        }
    }

    /// zmx in the agent socket directory as the agent itself, for a launcher ending its own
    /// session; it checks the core's log and changes nothing there.
    #[must_use]
    pub fn from_agent(binary: &Path, socket_dir: &Path) -> Self {
        Self {
            binary: binary.to_path_buf(),
            socket_dir: socket_dir.display().to_string(),
            directory: Directory::SharedFromAgent,
        }
    }

    /// zmx bound to the agent socket directory, starting each session as `agent` through
    /// `sudo -n`, which the sudoers rule lets the developer run with no password.
    #[must_use]
    pub fn agent_as(binary: &Path, socket_dir: &Path, agent: &str) -> Self {
        Self {
            binary: binary.to_path_buf(),
            socket_dir: socket_dir.display().to_string(),
            directory: Directory::Shared {
                agent: Some(agent.to_string()),
            },
        }
    }

    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    #[must_use]
    pub fn socket_dir(&self) -> &str {
        &self.socket_dir
    }

    /// The user `run` starts sessions as, when it is not the caller.
    #[must_use]
    pub fn switched_to(&self) -> Option<&str> {
        match &self.directory {
            Directory::Shared { agent: Some(agent) } => Some(agent),
            Directory::Shared { agent: None } | Directory::SharedFromAgent | Directory::Core => {
                None
            }
        }
    }

    fn environment(&self) -> Vec<(&str, &str)> {
        match self.directory {
            Directory::Core => vec![
                ("ZMX_DIR", self.socket_dir.as_str()),
                ("ZMX_DIR_MODE", CORE_DIR_MODE),
            ],
            Directory::Shared { agent: None } | Directory::SharedFromAgent => vec![
                ("ZMX_DIR", self.socket_dir.as_str()),
                ("ZMX_DIR_MODE", AGENT_ZMX_DIR_MODE),
                ("ZMX_LOG_MODE", AGENT_ZMX_LOG_MODE),
                ("PATH", AGENT_PATH),
            ],
            Directory::Shared { agent: Some(_) } => vec![
                ("ZMX_DIR", self.socket_dir.as_str()),
                ("ZMX_DIR_MODE", AGENT_ZMX_DIR_MODE),
                ("ZMX_LOG_MODE", AGENT_ZMX_LOG_MODE),
                ("PATH", AGENT_PATH),
                ("HOME", SWITCHED_HOME),
            ],
        }
    }

    /// A switched run starts from `/`: zmx hands its working directory to the session, and the
    /// agent cannot enter the developer's home, where a core or a suite may be running.
    fn working_dir(&self, arguments: &[&str]) -> Option<&'static Path> {
        (self.switched_to().is_some() && arguments.first() == Some(&"run")).then(|| Path::new("/"))
    }

    /// The program and arguments that run zmx with `arguments`: directly in the core
    /// directory; under umask 007 in the shared one, and through sudo as the agent for a
    /// switched `run`.
    #[must_use]
    pub fn invocation(&self, arguments: &[&str]) -> (PathBuf, Vec<String>) {
        let zmx = self.binary.display().to_string();
        let words = |prefix: &[&str]| -> Vec<String> {
            prefix
                .iter()
                .copied()
                .chain(arguments.iter().copied())
                .map(str::to_string)
                .collect()
        };
        match &self.directory {
            Directory::Core => (self.binary.clone(), words(&[])),
            Directory::Shared { agent: Some(agent) } if arguments.first() == Some(&"run") => (
                PathBuf::from(SHELL),
                words(&["-c", UMASK_EXEC, SUDO, "-n", "-u", agent, "--", &zmx]),
            ),
            Directory::Shared { .. } | Directory::SharedFromAgent => {
                (PathBuf::from(SHELL), words(&["-c", UMASK_EXEC, &zmx]))
            }
        }
    }

    /// zmx with this directory's environment and no inherited session, once the shared log is
    /// checked, for a caller that drives a subcommand this type does not wrap, such as a
    /// viewer's attach.
    pub fn command(&self, arguments: &[&str]) -> Result<std::process::Command, ZmxError> {
        self.prepare()?;
        let (program, words) = self.invocation(arguments);
        let mut command = std::process::Command::new(program);
        command
            .args(words)
            .envs(self.environment())
            .env_remove(SESSION_ENV);
        if let Some(dir) = self.working_dir(arguments) {
            command.current_dir(dir);
        }
        Ok(command)
    }

    /// Every command in the shared directory first checks the log zmx will append to.
    fn prepare(&self) -> Result<(), ZmxError> {
        let dir = Path::new(&self.socket_dir);
        match self.directory {
            Directory::Core => Ok(()),
            Directory::Shared { .. } => prepare_shared_log(dir).map_err(ZmxError::Log),
            Directory::SharedFromAgent => check_shared_log_as_agent(dir).map_err(ZmxError::Log),
        }
    }

    fn status(&self, arguments: &[&str], max_bytes: usize) -> Result<Captured, ZmxError> {
        self.prepare()?;
        let (program, words) = self.invocation(arguments);
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        command::run_status_capped(
            &program,
            &words,
            &self.environment(),
            &[OsString::from(SESSION_ENV)],
            COMMAND_TIMEOUT,
            max_bytes,
        )
        .map_err(ZmxError::Command)
    }

    fn succeeded(&self, arguments: &[&str]) -> Result<Captured, ZmxError> {
        let captured = self.status(arguments, COMMAND_OUTPUT_MAX_BYTES)?;
        if !captured.status.success() {
            return Err(ZmxError::Command(CommandError::Failed(
                self.binary.display().to_string(),
                captured.status,
                captured.stderr,
            )));
        }
        Ok(captured)
    }

    fn detached(&self, arguments: &[&str]) -> Result<(), ZmxError> {
        self.prepare()?;
        let (program, words) = self.invocation(arguments);
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        let status = command::run_detached_from(
            &program,
            &words,
            &self.environment(),
            &[OsString::from(SESSION_ENV)],
            self.working_dir(arguments),
            COMMAND_TIMEOUT,
        )
        .map_err(ZmxError::Command)?;
        if !status.success() {
            return Err(self
                .switched_to()
                .map_or(ZmxError::RunFailed(status), |agent| {
                    ZmxError::SwitchedRunFailed {
                        agent: agent.to_string(),
                        status,
                    }
                }));
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<ListEntry>, ZmxError> {
        let captured = self.succeeded(&["list"])?;
        decode_list(&captured.stdout).map_err(ZmxError::List)
    }

    /// Spawns detached; never a bare attach, which would hijack the calling terminal.
    pub fn run_detached(&self, name: &str, command_line: &str) -> Result<(), ZmxError> {
        let mut arguments = vec!["run", name, "-d"];
        arguments.extend(command_line.split(' ').filter(|word| !word.is_empty()));
        self.detached(&arguments)
    }

    /// Spawns detached with each word as one argument; zmx quotes every word for the shell.
    pub fn run_words(&self, name: &str, words: &[String]) -> Result<(), ZmxError> {
        let mut arguments = vec!["run", name, "-d"];
        arguments.extend(words.iter().map(String::as_str));
        self.detached(&arguments)
    }

    /// The session's scrollback; more than `max_bytes` is an error, never a truncation.
    pub fn history(&self, name: &str, max_bytes: usize) -> Result<String, ZmxError> {
        let captured = self.status(&["history", name], max_bytes)?;
        if !captured.status.success() {
            return Err(ZmxError::RunFailed(captured.status));
        }
        Ok(captured.stdout)
    }

    /// Writes text to the session's pty input, as a nudge.
    pub fn send(&self, name: &str, text: &str) -> Result<(), ZmxError> {
        self.succeeded(&["send", name, text]).map(|_| ())
    }

    /// Ends a session by name; a missing session is not an error here.
    pub fn kill(&self, name: &str) -> Result<(), ZmxError> {
        self.status(&["kill", name, "--force"], COMMAND_OUTPUT_MAX_BYTES)
            .map(|_| ())
    }

    /// Ends every listed session by name. A running entry's pid is killed first, and only when
    /// `ps` shows it running a command that starts with one of `programs`; an ended entry's
    /// pid may belong to another process by now and is never signalled.
    pub fn clear(&self, programs: &[String]) -> Result<ClearReport, ZmxError> {
        let mut lines = Vec::new();
        for entry in self.list()? {
            let line = match clear_action(&entry, &process::process_facts, programs) {
                ClearAction::SignalThenRemove { name, pid } => format!(
                    "{name} running as pid {pid}, signal: {:?}; zmx kill: {:?}",
                    process::send(pid, false, Signal::SIGKILL),
                    self.kill(&name)
                ),
                ClearAction::RemoveByName { name, why } => {
                    format!("{name} {why}; zmx kill: {:?}", self.kill(&name))
                }
                ClearAction::Leave(text) => format!("unrecognised entry {text:?}"),
            };
            lines.push(line);
        }
        let remaining = self.list()?.len();
        Ok(ClearReport { lines, remaining })
    }
}

/// What `Zmx::clear` does with one listed entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearAction {
    /// A running session whose pid `ps` shows running an expected program.
    SignalThenRemove { name: String, pid: u32 },
    /// Removed by name only, with the reason its pid is not signalled.
    RemoveByName { name: String, why: String },
    /// An entry the decoder did not recognise is left and counts as remaining.
    Leave(String),
}

/// An ended entry's pid may belong to another process by now, so `ps` is not even asked.
pub fn clear_action(
    entry: &ListEntry,
    facts: &dyn Fn(u32) -> ProcessFacts,
    programs: &[String],
) -> ClearAction {
    match entry {
        ListEntry::Running { name, pid, .. } => match expected_program(&facts(*pid), programs) {
            Ok(()) => ClearAction::SignalThenRemove {
                name: name.clone(),
                pid: *pid,
            },
            Err(reason) => ClearAction::RemoveByName {
                name: name.clone(),
                why: format!("running as pid {pid}, not signalled: {reason}"),
            },
        },
        ListEntry::Ended { name, pid, .. } => ClearAction::RemoveByName {
            name: name.clone(),
            why: format!("ended (pid {pid} not signalled)"),
        },
        ListEntry::Unrecognised(text) => ClearAction::Leave(text.clone()),
    }
}

/// What `Zmx::clear` did with each listed entry, and how many entries are still listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearReport {
    pub lines: Vec<String>,
    pub remaining: usize,
}

const COMMAND_ECHO_MAX_CHARS: usize = 120;

/// Whether `ps`'s answer for a listed pid shows a command starting with one of `programs`.
pub fn expected_program(facts: &ProcessFacts, programs: &[String]) -> Result<(), String> {
    match facts {
        ProcessFacts::Running(facts)
            if programs
                .iter()
                .any(|program| facts.command.starts_with(program.as_str())) =>
        {
            Ok(())
        }
        ProcessFacts::Running(facts) => Err(format!(
            "it runs {:?}",
            facts
                .command
                .chars()
                .take(COMMAND_ECHO_MAX_CHARS)
                .collect::<String>()
        )),
        ProcessFacts::Gone => Err("it is gone".to_string()),
        ProcessFacts::Unrecognised(text) => Err(format!("ps answered {text:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Facts;

    fn running(command: &str) -> ProcessFacts {
        ProcessFacts::Running(Facts {
            uid: 501,
            pgid: 42,
            started_unix_seconds: 0,
            command: command.to_string(),
        })
    }

    #[test]
    fn an_ended_entry_is_removed_by_name_without_asking_ps_or_signalling() {
        let programs = vec!["/opt/restate-server".to_string()];
        let asked = std::cell::Cell::new(0_u32);
        let facts = |_pid: u32| {
            asked.set(asked.get().saturating_add(1));
            running("/opt/restate-server --base-dir /h")
        };
        let ended = ListEntry::Ended {
            name: "core.restate".to_string(),
            pid: 60267,
            exit_code: 137,
        };
        assert_eq!(
            clear_action(&ended, &facts, &programs),
            ClearAction::RemoveByName {
                name: "core.restate".to_string(),
                why: "ended (pid 60267 not signalled)".to_string(),
            }
        );
        assert_eq!(asked.get(), 0);
    }

    #[test]
    fn a_running_entry_is_signalled_only_while_it_runs_an_expected_program() {
        let programs = vec!["/opt/restate-server".to_string()];
        let entry = ListEntry::Running {
            name: "core.restate".to_string(),
            pid: 60889,
            created_unix_seconds: 0,
        };
        assert_eq!(
            clear_action(
                &entry,
                &|_| running("/opt/restate-server --base-dir /h"),
                &programs
            ),
            ClearAction::SignalThenRemove {
                name: "core.restate".to_string(),
                pid: 60889,
            }
        );
        assert!(matches!(
            clear_action(&entry, &|_| running("/bin/zsh -l"), &programs),
            ClearAction::RemoveByName { .. }
        ));
        assert!(matches!(
            clear_action(&entry, &|_| ProcessFacts::Gone, &programs),
            ClearAction::RemoveByName { .. }
        ));
        assert_eq!(
            clear_action(
                &ListEntry::Unrecognised("x".to_string()),
                &|_| ProcessFacts::Gone,
                &programs
            ),
            ClearAction::Leave("x".to_string())
        );
    }

    #[test]
    fn only_a_pid_running_an_expected_program_is_signalled() {
        let programs = vec![
            "/opt/restate-server".to_string(),
            "/opt/tycho endpoint".to_string(),
        ];
        assert_eq!(
            expected_program(&running("/opt/restate-server --base-dir /h"), &programs),
            Ok(())
        );
        assert_eq!(
            expected_program(&running("/opt/tycho endpoint"), &programs),
            Ok(())
        );
        for other in [
            running("/bin/zsh -l"),
            running("/opt/tycho launch --spec x"),
            ProcessFacts::Gone,
            ProcessFacts::Unrecognised("?".to_string()),
        ] {
            assert!(expected_program(&other, &programs).is_err(), "{other:?}");
        }
    }

    const RUNNING: &str = "  name=core.restate\tpid=60889\tclients=0\tcreated=1791528126\tcwd=file://host/Users/someone\n";
    const ENDED: &str = "  name=core.endpoint\tpid=60267\tclients=0\tcreated=1791528101\tcwd=file://host/Users/someone\tended=1791528114\texit_code=137\n";

    #[test]
    fn decodes_a_running_session() {
        assert_eq!(
            decode_list(RUNNING).unwrap(),
            vec![ListEntry::Running {
                name: "core.restate".to_string(),
                pid: 60889,
                created_unix_seconds: 1_791_528_126,
            }]
        );
    }

    #[test]
    fn decodes_an_ended_session() {
        assert_eq!(
            decode_list(ENDED).unwrap(),
            vec![ListEntry::Ended {
                name: "core.endpoint".to_string(),
                pid: 60267,
                exit_code: 137,
            }]
        );
    }

    #[test]
    fn decodes_empty_output_as_no_sessions() {
        assert_eq!(decode_list("").unwrap(), vec![]);
        assert_eq!(presence(&[], "core.restate"), Presence::Absent);
    }

    #[test]
    fn marks_an_unknown_field_unrecognised() {
        let line = "  name=core.restate\tpid=1\tcreated=2\tcolour=blue";
        assert_eq!(
            decode_list(line).unwrap(),
            vec![ListEntry::Unrecognised(line.to_string())]
        );
    }

    #[test]
    fn marks_a_line_without_a_pid_unrecognised() {
        let entries = decode_list("  name=core.restate\tcreated=2").unwrap();
        assert!(matches!(entries.as_slice(), [ListEntry::Unrecognised(_)]));
    }

    #[test]
    fn marks_a_pid_out_of_range_unrecognised() {
        for pid in ["0", "2147483648"] {
            let line = format!("  name=core.restate\tpid={pid}\tcreated=2");
            let entries = decode_list(&line).unwrap();
            assert!(matches!(entries.as_slice(), [ListEntry::Unrecognised(_)]));
        }
    }

    #[test]
    fn an_unrecognised_line_hides_absence() {
        let entries = decode_list("garbage").unwrap();
        assert_eq!(presence(&entries, "core.restate"), Presence::Unrecognised);
    }

    #[test]
    fn finds_presence_by_name() {
        let entries = decode_list(&format!("{RUNNING}{ENDED}")).unwrap();
        assert_eq!(
            presence(&entries, "core.restate"),
            Presence::Running {
                pid: 60889,
                created_unix_seconds: 1_791_528_126
            }
        );
        assert_eq!(
            presence(&entries, "core.endpoint"),
            Presence::Ended { pid: 60267 }
        );
        assert_eq!(presence(&entries, "core.other"), Presence::Absent);
    }

    #[test]
    fn a_duplicate_name_is_unrecognised() {
        let entries = decode_list(&format!("{RUNNING}{RUNNING}")).unwrap();
        assert_eq!(count_named(&entries, "core.restate"), 2);
        assert_eq!(presence(&entries, "core.restate"), Presence::Unrecognised);
    }

    #[test]
    fn only_a_switched_run_goes_through_sudo_and_every_shared_command_sets_the_umask() {
        let zmx = Path::new("/p/zmx");
        let dir = Path::new("/Users/Shared/tycho-agent-zmx");
        let switched = Zmx::agent_as(zmx, dir, "tycho-agent");
        let run = ["run", "s", "-d", "exec", "/usr/bin/env"];
        assert_eq!(
            switched.invocation(&run),
            (
                PathBuf::from("/bin/sh"),
                [
                    "-c",
                    UMASK_EXEC,
                    "/usr/bin/sudo",
                    "-n",
                    "-u",
                    "tycho-agent",
                    "--",
                    "/p/zmx",
                    "run",
                    "s",
                    "-d",
                    "exec",
                    "/usr/bin/env"
                ]
                .map(str::to_string)
                .to_vec()
            )
        );
        for arguments in [
            &["list"][..],
            &["kill", "s", "--force"],
            &["history", "s"],
            &["send", "s", "x"],
            &["attach", "s"],
        ] {
            let (program, words) = switched.invocation(arguments);
            assert_eq!(program, PathBuf::from("/bin/sh"));
            assert_eq!(&words[..3], ["-c", UMASK_EXEC, "/p/zmx"], "{arguments:?}");
            assert!(!words.iter().any(|word| word == "/usr/bin/sudo"));
        }
        let unswitched = Zmx::agent(zmx, dir);
        assert_eq!(unswitched.switched_to(), None);
        assert_eq!(switched.switched_to(), Some("tycho-agent"));
        let (_, words) = unswitched.invocation(&run);
        assert_eq!(&words[..3], ["-c", UMASK_EXEC, "/p/zmx"]);
        let core = Zmx::new(zmx, Path::new("/h/.tycho/zmx"));
        assert_eq!(
            core.invocation(&["list"]),
            (PathBuf::from("/p/zmx"), vec!["list".to_string()])
        );
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the stand-in lives in a scratch directory no other user can write"
    )]
    fn a_shared_directory_command_runs_with_umask_007_and_the_shared_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("tycho-zmx-umask-{}", std::process::id()));
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap();
        }
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("zmx-stand-in");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf '%s %s %s %s %s\\n' \"$(umask)\" \"$ZMX_DIR_MODE\" \"$ZMX_LOG_MODE\" \"$PATH\" \"${ZMX_SESSION-unset}\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let shared = Zmx::agent(&script, &dir);
        let seen = shared.history("s", COMMAND_OUTPUT_MAX_BYTES).unwrap();
        assert_eq!(seen.trim(), "0007 0770 0660 /usr/bin:/bin unset");
        let core = Zmx::new(&script, &dir);
        let seen = core.history("s", COMMAND_OUTPUT_MAX_BYTES).unwrap();
        assert!(seen.contains(" 0700 "), "{seen}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the fixture lives in a scratch directory no other user can write"
    )]
    fn shared_scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tzl-{test}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        fs::set_permissions(&dir, Permissions::from_mode(0o1770)).unwrap();
        dir
    }

    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the fixture lives in a scratch directory no other user can write"
    )]
    fn a_fresh_shared_directory_gets_the_core_s_log_at_its_modes_and_keeps_its_content() {
        let dir = shared_scratch("fresh");
        prepare_shared_log(&dir).unwrap();
        let logs = dir.join(LOG_DIR);
        let log = logs.join(LOG_FILE);
        assert_eq!(mode_of(&logs), LOG_DIR_MODE);
        assert_eq!(mode_of(&log), LOG_FILE_MODE);
        fs::write(&log, "kept\n").unwrap();
        fs::set_permissions(&logs, Permissions::from_mode(0o770)).unwrap();
        prepare_shared_log(&dir).unwrap();
        assert_eq!(
            mode_of(&logs),
            LOG_DIR_MODE,
            "a group-writable log directory is narrowed"
        );
        assert_eq!(fs::read_to_string(&log).unwrap(), "kept\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the fixture lives in a scratch directory no other user can write"
    )]
    fn a_link_at_the_log_is_replaced_and_the_developer_s_zmx_appends_only_to_its_own_log() {
        let dir = shared_scratch("link");
        prepare_shared_log(&dir).unwrap();
        let target = dir.join("developer-file");
        fs::write(&target, "keep\n").unwrap();
        let log = dir.join(LOG_DIR).join(LOG_FILE);
        fs::remove_file(&log).unwrap();
        std::os::unix::fs::symlink(&target, &log).unwrap();
        let script = dir.join("zmx-stand-in");
        fs::write(
            &script,
            "#!/bin/sh\necho appended >> \"$ZMX_DIR/logs/zmx.log\"\n",
        )
        .unwrap();
        fs::set_permissions(&script, Permissions::from_mode(0o700)).unwrap();
        let zmx = Zmx::agent(&script, &dir);
        assert!(zmx.list().is_ok());
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep\n");
        let facts = fs::symlink_metadata(&log).unwrap();
        assert!(facts.file_type().is_file(), "the link was not replaced");
        assert_eq!(fs::read_to_string(&log).unwrap(), "appended\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The agent can link the core's log from anywhere on the volume, which would refuse every
    /// command of the core's for good; the core owns the log directory and replaces the log.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the fixture lives in a scratch directory no other user can write"
    )]
    fn a_hard_linked_or_fifo_log_is_replaced_and_a_linked_log_directory_is_refused() {
        let dir = shared_scratch("links");
        prepare_shared_log(&dir).unwrap();
        let log = dir.join(LOG_DIR).join(LOG_FILE);
        fs::write(&log, "old\n").unwrap();
        let other = dir.join("other-name");
        fs::hard_link(&log, &other).unwrap();
        prepare_shared_log(&dir).unwrap();
        assert_eq!(fs::symlink_metadata(&log).unwrap().nlink(), 1);
        assert_eq!(fs::read_to_string(&log).unwrap(), "");
        assert_eq!(fs::read_to_string(&other).unwrap(), "old\n");
        assert_eq!(mode_of(&log), LOG_FILE_MODE);
        fs::remove_file(&log).unwrap();
        nix::unistd::mkfifo(&log, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        prepare_shared_log(&dir).unwrap();
        assert!(fs::symlink_metadata(&log).unwrap().file_type().is_file());
        fs::remove_dir_all(dir.join(LOG_DIR)).unwrap();
        let elsewhere = dir.join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join(LOG_DIR)).unwrap();
        assert!(matches!(
            prepare_shared_log(&dir),
            Err(LogRefusal::NotDirectory(_))
        ));
        assert!(!elsewhere.join(LOG_FILE).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the fixture lives in a scratch directory no other user can write"
    )]
    fn the_agent_side_checks_the_core_s_log_and_changes_nothing() {
        let dir = shared_scratch("agent-side");
        let script = dir.join("zmx-stand-in");
        fs::write(&script, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&script, Permissions::from_mode(0o700)).unwrap();
        let from_agent = Zmx::from_agent(&script, &dir);
        assert!(matches!(from_agent.list(), Err(ZmxError::Log(_))));
        assert!(
            !dir.join(LOG_DIR).exists(),
            "the agent side made the log directory"
        );
        prepare_shared_log(&dir).unwrap();
        assert!(from_agent.list().is_ok());
        let log = dir.join(LOG_DIR).join(LOG_FILE);
        fs::remove_file(&log).unwrap();
        std::os::unix::fs::symlink("/dev/null", &log).unwrap();
        assert!(matches!(
            from_agent.list(),
            Err(ZmxError::Log(LogRefusal::NotRegular(_)))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_shared_directory_of_another_user_is_refused_on_the_core_s_side() {
        assert!(matches!(
            prepare_shared_log(Path::new("/")),
            Err(LogRefusal::Foreign { uid: 0, .. })
        ));
        let zmx = Zmx::agent(Path::new("/usr/bin/true"), Path::new("/"));
        assert!(matches!(
            zmx.list(),
            Err(ZmxError::Log(LogRefusal::Foreign { .. }))
        ));
        assert!(matches!(
            zmx.command(&["attach", "s"]),
            Err(ZmxError::Log(_))
        ));
    }

    #[test]
    fn a_switched_run_starts_from_the_root_with_an_empty_home_and_nothing_else_moves() {
        let switched = Zmx::agent_as(Path::new("/p/zmx"), Path::new("/d"), "tycho-agent");
        assert_eq!(switched.working_dir(&["run", "s"]), Some(Path::new("/")));
        assert_eq!(switched.working_dir(&["list"]), None);
        assert!(switched
            .environment()
            .contains(&("HOME", tycho_types::agent_switch::SWITCHED_HOME)));
        let caller = Zmx::agent(Path::new("/p/zmx"), Path::new("/d"));
        assert_eq!(caller.working_dir(&["run", "s"]), None);
        assert!(!caller.environment().iter().any(|(name, _)| *name == "HOME"));
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the fixture lives in a scratch directory no other user can write"
    )]
    fn a_missing_shared_directory_is_made_sticky_before_zmx_can_make_it() {
        let parent = shared_scratch("missing");
        let dir = parent.join("agent");
        let zmx = Zmx::agent(Path::new("/usr/bin/true"), &dir);
        assert!(zmx.list().is_ok());
        assert_eq!(mode_of(&dir), SHARED_DIR_MODE);
        assert_eq!(mode_of(&dir.join(LOG_DIR)), LOG_DIR_MODE);
        fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the fixture lives in a scratch directory no other user can write"
    )]
    fn a_group_writable_shared_directory_needs_the_sticky_bit() {
        let dir = shared_scratch("sticky");
        fs::set_permissions(&dir, Permissions::from_mode(0o2770)).unwrap();
        assert!(matches!(
            prepare_shared_log(&dir),
            Err(LogRefusal::NotSticky { .. })
        ));
        assert!(!dir.join(LOG_DIR).exists());
        fs::set_permissions(&dir, Permissions::from_mode(0o3770)).unwrap();
        prepare_shared_log(&dir).unwrap();
        fs::set_permissions(&dir, Permissions::from_mode(0o750)).unwrap();
        prepare_shared_log(&dir).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_log_or_log_directory_of_another_user_is_refused() {
        let path = Path::new("/shared/logs");
        assert_eq!(check_log_dir(true, 501, 501, path), Ok(()));
        assert!(matches!(
            check_log_dir(true, 503, 501, path),
            Err(LogRefusal::Foreign { uid: 503, .. })
        ));
        assert!(matches!(
            check_log_dir(false, 501, 501, path),
            Err(LogRefusal::NotDirectory(_))
        ));
        assert_eq!(check_log_file(true, 501, 1, 501, path), Ok(()));
        assert!(matches!(
            check_log_file(true, 503, 1, 501, path),
            Err(LogRefusal::Foreign { uid: 503, .. })
        ));
        assert!(matches!(
            check_log_file(false, 501, 1, 501, path),
            Err(LogRefusal::NotRegular(_))
        ));
        assert!(matches!(
            check_shared_dir(true, 0o40770, path),
            Err(LogRefusal::NotSticky { mode: 0o770, .. })
        ));
        assert_eq!(check_shared_dir(true, 0o43770, path), Ok(()));
    }

    #[test]
    fn refuses_a_list_over_the_bound() {
        let many = RUNNING.repeat(LIST_SESSIONS_MAX + 1);
        assert_eq!(
            decode_list(&many),
            Err(ListError::TooManySessions(LIST_SESSIONS_MAX + 1))
        );
    }
}

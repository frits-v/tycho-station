//! The Claude Code adapter for interactive control sessions (design section 6).
//!
//! A session is found by its pre-assigned id in the vendor's session registry,
//! `<config>/sessions/<pid>.json`, every time: the inbox socket is named by pid, so a resumed
//! session has a new one. An instruction is one JSON line on that socket; the vendor never
//! answers on it, so delivery is confirmed only by observing the session.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::signal;
use nix::unistd::Pid;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tycho_types::envelope::{ShortText, TEXT_MAX_BYTES};
use tycho_types::lease::PID_MAX;
use tycho_types::session::{SessionName, Vendor};
use tycho_types::task_packet::Effort;

use crate::agent_files::{current_uid, read_checked};
use crate::config::AgentDirs;
use crate::launch_spec::VendorTerminal;
use crate::relay::{remove_relay_dir, write_instruction};
use crate::vendors::control::{
    bounded, AddressTarget, ContextReport, ControlCommand, ControlLaunch, Delivery, Observation,
    PermissionMode, SessionVendor, VendorError, VendorSessionId, WaitingFor, MODEL_NAME_MAX_BYTES,
};

/// One `ShortText`, far below the inbox's documented 1,048,576-character message limit.
pub const INSTRUCTION_MAX_BYTES: usize = TEXT_MAX_BYTES;
/// The largest auto-compact window the vendor accepts; it caps it at the model's window.
pub const AUTO_COMPACT_WINDOW_MAX: u64 = 1_000_000;
pub const REGISTRY_FILES_MAX: usize = 1024;
pub const REGISTRY_FILE_MAX_BYTES: usize = 16 * 1024;
/// The shared inbox socket directory; the vendor defines it and the fallbacks, not the adapter.
pub const SOCKETS_DIR: &str = "/tmp/cc-socks";
/// The vendor's socket directory under `$XDG_RUNTIME_DIR` when that is set.
pub const SOCKETS_DIR_NAME: &str = "cc-socks";
pub const XDG_RUNTIME_DIR_ENV: &str = "XDG_RUNTIME_DIR";
pub const REPLY_MAX_BYTES: usize = 4096;
/// The transcript window read for the last turn's usage.
pub const TRANSCRIPT_TAIL_MAX_BYTES: u64 = 512 * 1024;
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);
const STATUS_PERMISSION_PROMPT: &str = "permission prompt";

/// When the adapter hands an instruction to the session's launcher instead of the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMode {
    /// Only when the socket or the registry refuses the core as another user.
    OnRefusal,
    /// Always: the core and the session run as different users.
    Always,
}

/// The adapter for one vendor user's Claude Code: binary, configuration and relay directory.
#[derive(Debug, Clone)]
pub struct ClaudeControl {
    pub binary: PathBuf,
    /// The vendor user's `~/.claude` (or `CLAUDE_CONFIG_DIR`).
    pub config_dir: PathBuf,
    pub relay_dirs: Option<AgentDirs>,
    pub relay_mode: RelayMode,
    /// Where the vendor may bind inbox sockets; a registry path elsewhere is refused.
    pub sockets_dirs: Vec<PathBuf>,
    /// The uid that must own the inbox socket and the transcript.
    pub agent_uid: u32,
}

/// One registry file; only pid and session id are required, as other versions share the files.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryEntry {
    pub pid: u32,
    pub session_id: String,
    pub cwd: Option<String>,
    pub kind: Option<String>,
    pub status: Option<String>,
    pub waiting_for: Option<String>,
    pub messaging_socket_path: Option<String>,
}

/// The file type `symlink_metadata` or `fstat` reports, never through a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Socket,
    Symlink,
    Regular,
    Directory,
    Other,
}

/// The type and owner the socket and transcript checks read from a path's metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathFacts {
    pub kind: PathKind,
    pub uid: u32,
}

impl PathFacts {
    #[must_use]
    pub fn of(metadata: &fs::Metadata) -> Self {
        let file_type = metadata.file_type();
        let kind = if file_type.is_symlink() {
            PathKind::Symlink
        } else if file_type.is_socket() {
            PathKind::Socket
        } else if file_type.is_file() {
            PathKind::Regular
        } else if file_type.is_dir() {
            PathKind::Directory
        } else {
            PathKind::Other
        };
        Self {
            kind,
            uid: metadata.uid(),
        }
    }
}

/// Where a session id stands in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Located {
    Found(RegistryEntry),
    Absent,
    Unreadable(String),
    /// The registry belongs to another user.
    Denied(String),
    /// More than one live process claims the id.
    Ambiguous(usize),
}

/// The `--effort` word; the CLI has no level below `low`.
pub const fn effort_word(effort: Effort) -> Result<&'static str, VendorError> {
    match effort {
        Effort::Minimal => Err(VendorError::Unsupported(
            "claude has no effort below low; route the control session at low or above",
        )),
        Effort::Low => Ok("low"),
        Effort::Medium => Ok("medium"),
        Effort::High => Ok("high"),
        Effort::Max => Ok("max"),
    }
}

#[must_use]
pub const fn permission_word(mode: PermissionMode) -> &'static str {
    match mode {
        PermissionMode::Manual => "manual",
        PermissionMode::AcceptEdits => "acceptEdits",
        PermissionMode::DontAsk => "dontAsk",
        PermissionMode::Plan => "plan",
    }
}

/// The one `--settings` object: sandbox, inbound accepted, widest auto-compact window.
pub fn settings_json(sandbox_settings: &str) -> Result<String, VendorError> {
    // Passed on every start and resume: the vendor does not keep it with the session.
    let mut settings: Map<String, Value> = serde_json::from_str(sandbox_settings)
        .map_err(|error| VendorError::Argument(format!("sandbox settings: {error}")))?;
    if !settings.get("sandbox").is_some_and(Value::is_object) {
        return Err(VendorError::Argument(
            "sandbox settings carry no sandbox object".to_string(),
        ));
    }
    settings.insert("crossSessionInbound".to_string(), json!("accept"));
    settings.insert(
        "autoCompactWindow".to_string(),
        json!(AUTO_COMPACT_WINDOW_MAX),
    );
    let text = Value::Object(settings).to_string();
    if text.len() > TEXT_MAX_BYTES {
        return Err(VendorError::Argument(format!(
            "settings of {} bytes exceed {TEXT_MAX_BYTES}",
            text.len()
        )));
    }
    Ok(text)
}

fn check_model(model: &str) -> Result<(), VendorError> {
    let allowed =
        |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte);
    let first_ok = model
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if !first_ok || model.len() > MODEL_NAME_MAX_BYTES || !model.bytes().all(allowed) {
        return Err(VendorError::Argument(format!(
            "model {:?} is not 1..={MODEL_NAME_MAX_BYTES} bytes of [a-z0-9.-]",
            bounded(model)
        )));
    }
    Ok(())
}

/// The transcript directory name for a working directory: non-alphanumerics become `-`.
#[must_use]
pub fn project_slug(cwd: &str) -> String {
    cwd.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect()
}

/// Decodes one registry file; a file that is not a session record is never usable.
pub fn decode_registry(bytes: &[u8]) -> Result<RegistryEntry, String> {
    let entry: RegistryEntry =
        serde_json::from_slice(bytes).map_err(|error| bounded(&error.to_string()))?;
    if entry.pid == 0 || entry.pid > PID_MAX {
        return Err(format!("pid {} is out of range", entry.pid));
    }
    Ok(entry)
}

/// The observation a registry entry decodes to.
#[must_use]
pub fn observation_of(entry: &RegistryEntry) -> Observation {
    let pid = entry.pid;
    let Some(status) = entry.status.as_deref() else {
        return Observation::Unrecognised {
            reason: "the registry entry carries no status".to_string(),
        };
    };
    match (status, entry.waiting_for.as_deref()) {
        ("idle", _) => Observation::Idle { pid },
        ("busy", _) => Observation::Busy { pid },
        ("waiting", Some(STATUS_PERMISSION_PROMPT)) => Observation::Waiting {
            pid,
            waiting_for: WaitingFor::PermissionPrompt,
        },
        ("waiting", other) => Observation::Waiting {
            pid,
            waiting_for: WaitingFor::Unrecognised(bounded(other.unwrap_or_default())),
        },
        (status, _) => Observation::Unrecognised {
            reason: format!("status {:?}", bounded(status)),
        },
    }
}

/// Input plus cache tokens of the last assistant turn in a transcript tail.
#[must_use]
pub fn context_of(tail: &str) -> ContextReport {
    // The first line of a tail window may be cut; a line that is not JSON is skipped.
    let Some(usage) = tail.lines().rev().find_map(|line| {
        let entry = serde_json::from_str::<Value>(line).ok()?;
        (entry.get("type").and_then(Value::as_str) == Some("assistant"))
            .then(|| entry.pointer("/message/usage").cloned())
            .flatten()
    }) else {
        return ContextReport::NoTurnYet;
    };
    let field = |name: &str| usage.get(name).and_then(Value::as_u64);
    match (
        field("input_tokens"),
        field("cache_creation_input_tokens"),
        field("cache_read_input_tokens"),
    ) {
        (Some(input), Some(created), Some(read)) => ContextReport::Tokens {
            tokens: input.saturating_add(created).saturating_add(read),
        },
        _ => ContextReport::Unrecognised {
            reason: "the last assistant usage lacks a token count".to_string(),
        },
    }
}

/// Maps a connect or write error to its delivery state; nothing was written in any of them.
#[must_use]
pub fn connect_failure(socket: &Path, error: &io::Error) -> Delivery {
    let socket = socket.display().to_string();
    match error.kind() {
        io::ErrorKind::NotFound => Delivery::NoSocket { socket },
        io::ErrorKind::ConnectionRefused => Delivery::Refused { socket },
        io::ErrorKind::PermissionDenied => Delivery::Denied { socket },
        _ => Delivery::Unrecognised {
            reason: bounded(&format!("{socket}: {error}")),
        },
    }
}

/// The JSON line the inbox reads: the shape the vendor's own debug log prints.
#[must_use]
pub fn instruction_line(instruction: &ShortText) -> String {
    let line = json!({
        "type": "user",
        "message": {"role": "user", "content": instruction.as_str()},
    });
    format!("{line}\n")
}

/// The three operations a post makes on a connection, so a test can fail each one.
pub trait Channel {
    fn write_some(&mut self, bytes: &[u8]) -> io::Result<usize>;
    fn half_close(&mut self) -> io::Result<()>;
    fn read_reply(&mut self, reply: &mut Vec<u8>) -> io::Result<()>;
}

impl Channel for UnixStream {
    fn write_some(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write(bytes)
    }

    fn half_close(&mut self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }

    fn read_reply(&mut self, reply: &mut Vec<u8>) -> io::Result<()> {
        let limit = u64::try_from(REPLY_MAX_BYTES).unwrap_or(u64::MAX);
        self.take(limit).read_to_end(reply).map(drop)
    }
}

/// Writes the line counting bytes; once one byte is out the instruction counts as written.
fn write_counted(channel: &mut impl Channel, line: &[u8]) -> (usize, io::Result<()>) {
    let mut sent = 0_usize;
    for _ in 0..=line.len() {
        let Some(rest) = line.get(sent..).filter(|rest| !rest.is_empty()) else {
            return (sent, Ok(()));
        };
        match channel.write_some(rest) {
            Ok(0) => return (sent, Err(io::Error::from(io::ErrorKind::WriteZero))),
            Ok(count) => sent = sent.saturating_add(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return (sent, Err(error)),
        }
    }
    (sent, Ok(()))
}

/// Writes the line, half-closes, and decodes what comes back.
pub fn post_on(channel: &mut impl Channel, label: String, line: &str) -> Delivery {
    let (sent, written) = write_counted(channel, line.as_bytes());
    let written = written.and_then(|()| channel.half_close());
    match written {
        Err(error) if sent == 0 => {
            return Delivery::WriteFailed {
                socket: label,
                reason: bounded(&error.to_string()),
            }
        }
        Err(error) => {
            return Delivery::WriteInterrupted {
                socket: label,
                sent,
                reason: bounded(&error.to_string()),
            }
        }
        Ok(()) => {}
    }
    let mut reply = Vec::new();
    match channel.read_reply(&mut reply) {
        Ok(()) if reply.is_empty() => Delivery::Posted { socket: label },
        Ok(()) => Delivery::Replied {
            socket: label,
            reply: bounded(&String::from_utf8_lossy(&reply)),
        },
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) && reply.is_empty() =>
        {
            Delivery::PostedUnclosed { socket: label }
        }
        Err(error) => Delivery::Replied {
            socket: label,
            reply: bounded(&format!("read failed: {error}")),
        },
    }
}

/// The effective uid of the process that bound the connected socket.
#[cfg(target_os = "macos")]
pub(crate) fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    nix::unistd::getpeereid(stream)
        .map(|(uid, _)| uid.as_raw())
        .map_err(io::Error::from)
}

/// The effective uid of the process that bound the connected socket.
#[cfg(target_os = "linux")]
pub(crate) fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map(|credentials| credentials.uid())
        .map_err(io::Error::from)
}

/// Connects, checks the listener runs as `listener_uid`, and posts the line within the timeouts.
#[must_use]
pub fn post(socket: &Path, line: &str, listener_uid: u32) -> Delivery {
    let mut stream = match UnixStream::connect(socket) {
        Ok(stream) => stream,
        Err(error) => return connect_failure(socket, &error),
    };
    let label = socket.display().to_string();
    match peer_uid(&stream) {
        Ok(uid) if uid == listener_uid => {}
        Ok(uid) => {
            return Delivery::Untrusted {
                reason: format!(
                    "{label}: the listener runs as uid {uid}, expected uid {listener_uid}"
                ),
            }
        }
        Err(error) => {
            return Delivery::Untrusted {
                reason: bounded(&format!("{label}: peer credentials: {error}")),
            }
        }
    }
    let timeouts = stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_read_timeout(Some(IO_TIMEOUT)));
    if let Err(error) = timeouts {
        return Delivery::WriteFailed {
            socket: label,
            reason: bounded(&error.to_string()),
        };
    }
    post_on(&mut stream, label, line)
}

/// The vendor's socket directories for `uid`: under `$XDG_RUNTIME_DIR`, shared, per-user.
#[must_use]
pub fn sockets_dirs(xdg_runtime_dir: Option<&Path>, uid: u32) -> Vec<PathBuf> {
    xdg_runtime_dir
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(SOCKETS_DIR_NAME))
        .into_iter()
        .chain([
            PathBuf::from(SOCKETS_DIR),
            PathBuf::from(format!("{SOCKETS_DIR}-{uid}")),
        ])
        .collect()
}

/// `sockets_dirs` for this process's environment and `uid`.
#[must_use]
pub fn sockets_dirs_from_environment(uid: u32) -> Vec<PathBuf> {
    let xdg = std::env::var_os(XDG_RUNTIME_DIR_ENV).map(PathBuf::from);
    sockets_dirs(xdg.as_deref(), uid)
}

/// The registry's socket when it is absolute, without `..`, and `<dir>/<pid>.sock` in the set.
pub fn socket_shape(raw: &str, pid: u32, sockets_dirs: &[PathBuf]) -> Result<PathBuf, String> {
    let path = PathBuf::from(raw);
    let shown = bounded(raw);
    if !path.is_absolute() {
        return Err(format!("socket {shown:?} is not absolute"));
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(format!("socket {shown:?} holds a parent component"));
    }
    if !path
        .parent()
        .is_some_and(|parent| sockets_dirs.iter().any(|dir| dir.as_path() == parent))
    {
        return Err(format!(
            "socket {shown:?} is not in one of the vendor's socket directories"
        ));
    }
    let expected = format!("{pid}.sock");
    if path.file_name().and_then(|name| name.to_str()) != Some(expected.as_str()) {
        return Err(format!("socket {shown:?} is not named {expected}"));
    }
    Ok(path)
}

/// A socket, not a link or a regular file, owned by the agent user.
pub fn check_socket_facts(facts: PathFacts, agent_uid: u32) -> Result<(), String> {
    if facts.kind != PathKind::Socket {
        return Err(format!("a {:?}, not a socket", facts.kind));
    }
    if facts.uid != agent_uid {
        return Err(format!(
            "owned by uid {}, expected uid {agent_uid}",
            facts.uid
        ));
    }
    Ok(())
}

/// Where a directory on a vendor path stands.
#[derive(Debug)]
pub enum DirState {
    Real,
    Missing,
    /// Present but a link, not a directory, or another user's.
    Refused(String),
    Unreadable(io::Error),
}

/// Whether `dir` is a real directory of `agent_uid`, never through a link.
#[must_use]
pub fn real_dir(dir: &Path, agent_uid: u32) -> DirState {
    let metadata = match fs::symlink_metadata(dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return DirState::Missing,
        Err(error) => return DirState::Unreadable(error),
    };
    let facts = PathFacts::of(&metadata);
    if facts.kind == PathKind::Directory && facts.uid == agent_uid {
        return DirState::Real;
    }
    DirState::Refused(bounded(&format!(
        "{}: a {:?} of uid {}, expected a directory of uid {agent_uid}",
        dir.display(),
        facts.kind,
        facts.uid
    )))
}

/// A shaped socket's directory, type and owner; a stat error decodes as a connect error would.
pub fn check_socket(path: &Path, agent_uid: u32) -> Result<(), Delivery> {
    let parent = path.parent().unwrap_or(path);
    match real_dir(parent, agent_uid) {
        DirState::Real => {}
        DirState::Missing => {
            return Err(Delivery::NoSocket {
                socket: path.display().to_string(),
            })
        }
        DirState::Refused(reason) => return Err(Delivery::Untrusted { reason }),
        DirState::Unreadable(error) => return Err(connect_failure(path, &error)),
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| connect_failure(path, &error))?;
    check_socket_facts(PathFacts::of(&metadata), agent_uid).map_err(|reason| Delivery::Untrusted {
        reason: bounded(&format!("{}: {reason}", path.display())),
    })
}

/// The registry's socket once its shape, directory, type and owner pass.
pub fn trusted_socket(
    raw: &str,
    pid: u32,
    sockets_dirs: &[PathBuf],
    agent_uid: u32,
) -> Result<PathBuf, Delivery> {
    let path =
        socket_shape(raw, pid, sockets_dirs).map_err(|reason| Delivery::Untrusted { reason })?;
    check_socket(&path, agent_uid)?;
    Ok(path)
}

/// The launcher's checked socket for its vendor `pid`, against its own environment and uid.
pub fn socket_of_pid(config_dir: &Path, pid: u32) -> Result<Option<PathBuf>, String> {
    let uid = current_uid();
    socket_in_registry(config_dir, pid, &sockets_dirs_from_environment(uid), uid)
}

/// The checked socket the registry file of `pid` names; a socket not bound yet is handed on.
pub fn socket_in_registry(
    config_dir: &Path,
    pid: u32,
    sockets_dirs: &[PathBuf],
    agent_uid: u32,
) -> Result<Option<PathBuf>, String> {
    let path = config_dir.join("sessions").join(format!("{pid}.json"));
    let bytes = read_checked(&path, REGISTRY_FILE_MAX_BYTES, None)
        .map_err(|error| bounded(&error.to_string()))?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let entry = decode_registry(&bytes)?;
    if entry.pid != pid {
        return Err(format!("{} names pid {}", path.display(), entry.pid));
    }
    let Some(raw) = entry.messaging_socket_path else {
        return Ok(None);
    };
    let socket = socket_shape(&raw, pid, sockets_dirs)?;
    match check_socket(&socket, agent_uid) {
        // Not bound yet: the post finds no socket and marks the instruction failed.
        Ok(()) | Err(Delivery::NoSocket { .. }) => Ok(Some(socket)),
        Err(refusal) => Err(bounded(&format!("{refusal:?}"))),
    }
}

fn unreadable_at(path: &Path, error: &io::Error) -> ContextReport {
    ContextReport::Unreadable {
        reason: bounded(&format!("{}: {error}", path.display())),
    }
}

/// The transcript's last bytes from a regular file of `agent_uid`; missing is `None`.
fn read_tail(path: &Path, agent_uid: u32) -> Result<Option<String>, ContextReport> {
    // O_NONBLOCK keeps a planted FIFO from blocking the open; the descriptor check refuses it.
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path);
    let mut file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(Errno::ELOOP as i32) => {
            return Err(ContextReport::Unrecognised {
                reason: bounded(&format!("{}: a link, not a transcript", path.display())),
            })
        }
        Err(error) => return Err(unreadable_at(path, &error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| unreadable_at(path, &error))?;
    let facts = PathFacts::of(&metadata);
    if facts.kind != PathKind::Regular || facts.uid != agent_uid {
        return Err(ContextReport::Unrecognised {
            reason: bounded(&format!(
                "{}: a {:?} of uid {}, expected a regular file of uid {agent_uid}",
                path.display(),
                facts.kind,
                facts.uid
            )),
        });
    }
    let start = metadata.len().saturating_sub(TRANSCRIPT_TAIL_MAX_BYTES);
    file.seek(SeekFrom::Start(start))
        .map_err(|error| unreadable_at(path, &error))?;
    let mut tail = Vec::new();
    file.take(TRANSCRIPT_TAIL_MAX_BYTES)
        .read_to_end(&mut tail)
        .map_err(|error| unreadable_at(path, &error))?;
    Ok(Some(String::from_utf8_lossy(&tail).into_owned()))
}

/// Whether a pid names a live process; another user's process counts as live.
fn alive(pid: u32) -> bool {
    i32::try_from(pid).is_ok_and(|raw| {
        matches!(
            signal::kill(Pid::from_raw(raw), None),
            Ok(()) | Err(Errno::EPERM)
        )
    })
}

impl ClaudeControl {
    /// The socket directories come from this process's environment for `agent_uid`.
    #[must_use]
    pub fn new(binary: PathBuf, config_dir: PathBuf, agent_uid: u32) -> Self {
        Self {
            binary,
            config_dir,
            relay_dirs: None,
            relay_mode: RelayMode::OnRefusal,
            sockets_dirs: sockets_dirs_from_environment(agent_uid),
            agent_uid,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn with_sockets_dirs(mut self, sockets_dirs: Vec<PathBuf>) -> Self {
        self.sockets_dirs = sockets_dirs;
        self
    }

    #[cfg(test)]
    #[must_use]
    pub const fn with_agent_uid(mut self, agent_uid: u32) -> Self {
        self.agent_uid = agent_uid;
        self
    }

    #[must_use]
    pub fn with_relay(mut self, dirs: AgentDirs, mode: RelayMode) -> Self {
        self.relay_dirs = Some(dirs);
        self.relay_mode = mode;
        self
    }

    fn relay(&self, target: &AddressTarget, key: &ShortText, line: &str) -> Delivery {
        let Some(dirs) = &self.relay_dirs else {
            return Delivery::RelayFailed {
                reason: "no relay directory is configured".to_string(),
            };
        };
        match write_instruction(dirs, &target.session, key, line) {
            Ok(file) => Delivery::Relayed { file },
            Err(reason) => Delivery::RelayFailed {
                reason: bounded(&reason),
            },
        }
    }

    /// Scans the registry for live processes holding the id; over the bound is an error. A file
    /// that cannot be read or decoded makes the lookup unreadable only when nothing matched.
    #[must_use]
    pub fn locate(&self, session: &VendorSessionId) -> Located {
        let dir = self.config_dir.join("sessions");
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Located::Absent,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Located::Denied(bounded(&format!("{}: {error}", dir.display())))
            }
            Err(error) => {
                return Located::Unreadable(bounded(&format!("{}: {error}", dir.display())))
            }
        };
        let mut found = Vec::new();
        let mut failed: Option<String> = None;
        for (count, entry) in entries.enumerate() {
            if count >= REGISTRY_FILES_MAX {
                return Located::Unreadable(format!(
                    "{} holds more than {REGISTRY_FILES_MAX} entries",
                    dir.display()
                ));
            }
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(error) => return Located::Unreadable(bounded(&error.to_string())),
            };
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            match Self::read_entry(&path, session) {
                Ok(Some(record)) => found.push(record),
                Ok(None) => {}
                Err(reason) => failed = failed.or(Some(reason)),
            }
        }
        match (found.len(), failed) {
            (0, Some(reason)) => Located::Unreadable(reason),
            (0, None) => Located::Absent,
            (1, _) => found.pop().map_or(Located::Absent, Located::Found),
            (many, _) => Located::Ambiguous(many),
        }
    }

    /// The entry for this id with a live process; an unreadable or undecodable file is an error.
    fn read_entry(path: &Path, session: &VendorSessionId) -> Result<Option<RegistryEntry>, String> {
        let bytes = match read_checked(path, REGISTRY_FILE_MAX_BYTES, None) {
            Ok(Some(bytes)) => bytes,
            // Removed between the listing and the read: the process ended.
            Ok(None) => return Ok(None),
            Err(error) => return Err(bounded(&format!("{}: {error}", path.display()))),
        };
        let entry =
            decode_registry(&bytes).map_err(|reason| format!("{}: {reason}", path.display()))?;
        Ok((entry.session_id == session.as_str() && alive(entry.pid)).then_some(entry))
    }

    /// The transcript path once `projects` and the project under it are real directories.
    fn transcript_path(&self, entry: &RegistryEntry) -> Result<Option<PathBuf>, ContextReport> {
        let cwd = entry
            .cwd
            .as_deref()
            .ok_or_else(|| ContextReport::Unreadable {
                reason: "the registry entry names no working directory".to_string(),
            })?;
        let slug = project_slug(cwd);
        if slug.is_empty() {
            return Err(ContextReport::Unrecognised {
                reason: "the registry entry's working directory is empty".to_string(),
            });
        }
        let projects = self.config_dir.join("projects");
        let project = projects.join(slug);
        // The slug holds only alphanumerics and `-`, so it cannot leave the projects directory.
        for dir in [&projects, &project] {
            match real_dir(dir, self.agent_uid) {
                DirState::Real => {}
                DirState::Missing => return Ok(None),
                DirState::Refused(reason) => return Err(ContextReport::Unrecognised { reason }),
                DirState::Unreadable(error) => return Err(unreadable_at(dir, &error)),
            }
        }
        Ok(Some(project.join(format!("{}.jsonl", entry.session_id))))
    }

    fn transcript_tail(&self, entry: &RegistryEntry) -> Result<Option<String>, ContextReport> {
        self.transcript_path(entry)?
            .map_or(Ok(None), |path| read_tail(&path, self.agent_uid))
    }

    /// Posts to the entry's checked socket; a socket refusing the core goes to the relay.
    fn deliver(
        &self,
        target: &AddressTarget,
        key: &ShortText,
        entry: &RegistryEntry,
        line: &str,
    ) -> Delivery {
        let Some(raw) = entry.messaging_socket_path.as_deref() else {
            return Delivery::Unrecognised {
                reason: "the registry entry names no inbox socket".to_string(),
            };
        };
        let delivery = match trusted_socket(raw, entry.pid, &self.sockets_dirs, self.agent_uid) {
            // Between the check and the connect a socket can be swapped; the peer uid is checked
            // before any byte, so what remains is a connect to a socket of the agent uid, or a
            // foreign listener seeing a connection that closes with no payload.
            Ok(socket) => post(&socket, line, self.agent_uid),
            Err(refusal) => refusal,
        };
        match delivery {
            Delivery::Denied { .. } => self.relay(target, key, line),
            delivery => delivery,
        }
    }
}

impl SessionVendor for ClaudeControl {
    fn describe(&self) -> String {
        format!("claude control at {}", self.binary.display())
    }

    fn serves(&self, vendor: Vendor) -> bool {
        vendor == Vendor::Claude
    }

    fn control_command(&self, launch: &ControlLaunch) -> Result<ControlCommand, VendorError> {
        check_model(&launch.model)?;
        let id_flag = if launch.resume {
            "--resume"
        } else {
            "--session-id"
        };
        let argv = [
            self.binary.display().to_string().as_str(),
            "--model",
            &launch.model,
            "--effort",
            effort_word(launch.effort)?,
            "--permission-mode",
            permission_word(launch.permission),
            "--name",
            &launch.session.to_string(),
            id_flag,
            launch.vendor_session.as_str(),
            "--settings",
            &settings_json(&launch.sandbox_settings)?,
        ]
        .map(str::to_string)
        .to_vec();
        Ok(ControlCommand {
            argv,
            terminal: VendorTerminal::Inherit,
            working_dir: PathBuf::from(launch.working_dir.as_str()),
        })
    }

    fn address(
        &self,
        target: &AddressTarget,
        key: &ShortText,
        instruction: &ShortText,
    ) -> Delivery {
        let line = instruction_line(instruction);
        if self.relay_mode == RelayMode::Always {
            return self.relay(target, key, &line);
        }
        match self.locate(&target.vendor_session) {
            Located::Found(entry) => self.deliver(target, key, &entry, &line),
            Located::Denied(_) => self.relay(target, key, &line),
            Located::Absent => Delivery::NoSession,
            Located::Unreadable(reason) => Delivery::Unreadable { reason },
            Located::Ambiguous(count) => Delivery::Unrecognised {
                reason: format!("{count} live processes hold the session id"),
            },
        }
    }

    fn observe(&self, session: &VendorSessionId) -> Observation {
        match self.locate(session) {
            Located::Found(entry) => observation_of(&entry),
            Located::Absent => Observation::Absent,
            Located::Unreadable(reason) | Located::Denied(reason) => {
                Observation::Unreadable { reason }
            }
            Located::Ambiguous(count) => Observation::Unrecognised {
                reason: format!("{count} live processes hold the session id"),
            },
        }
    }

    fn resume_handle(&self, session: &VendorSessionId) -> Result<ShortText, VendorError> {
        ShortText::parse(session.as_str()).map_err(|error| VendorError::Argument(error.to_string()))
    }

    fn context_size(&self, session: &VendorSessionId) -> ContextReport {
        let entry = match self.locate(session) {
            Located::Found(entry) => entry,
            Located::Absent => return ContextReport::Absent,
            Located::Unreadable(reason) | Located::Denied(reason) => {
                return ContextReport::Unreadable { reason }
            }
            Located::Ambiguous(count) => {
                return ContextReport::Unrecognised {
                    reason: format!("{count} live processes hold the session id"),
                }
            }
        };
        match self.transcript_tail(&entry) {
            Ok(Some(tail)) => context_of(&tail),
            Ok(None) => ContextReport::NoTurnYet,
            Err(report) => report,
        }
    }

    fn release(&self, session: &SessionName) -> Result<(), String> {
        self.relay_dirs
            .as_ref()
            .map_or(Ok(()), |dirs| remove_relay_dir(dirs, session))
    }
}

#[cfg(test)]
mod tests;

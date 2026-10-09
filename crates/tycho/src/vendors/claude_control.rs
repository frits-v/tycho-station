//! The Claude Code adapter for interactive control sessions (design section 6).
//!
//! A session is found by its pre-assigned id in the vendor's session registry,
//! `<config>/sessions/<pid>.json`, every time: the inbox socket is named by pid, so a resumed
//! session has a new one. An instruction is one JSON line on that socket; the vendor never
//! answers on it, so delivery is confirmed only by observing the session.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal;
use nix::unistd::Pid;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tycho_types::envelope::{ShortText, TEXT_MAX_BYTES};
use tycho_types::lease::PID_MAX;
use tycho_types::task_packet::Effort;

use crate::agent_files::read_checked;
use crate::launch_spec::VendorTerminal;
use crate::vendors::control::{
    bounded, ContextReport, ControlCommand, ControlLaunch, Delivery, Observation, PermissionMode,
    SessionVendor, VendorError, VendorSessionId, WaitingFor, MODEL_NAME_MAX_BYTES,
};

/// The inbox socket's documented line limit is 1,048,576 characters; an instruction is a
/// `ShortText`, far below it, which also keeps it inside one typed line for the fallback.
pub const INSTRUCTION_MAX_BYTES: usize = TEXT_MAX_BYTES;
/// The largest auto-compact window the vendor accepts; it is capped at the model's window,
/// so compaction runs only at the vendor's default fraction of the full window.
pub const AUTO_COMPACT_WINDOW_MAX: u64 = 1_000_000;
pub const REGISTRY_FILES_MAX: usize = 1024;
pub const REGISTRY_FILE_MAX_BYTES: usize = 16 * 1024;
pub const REPLY_MAX_BYTES: usize = 4096;
/// The transcript window read for the last turn's usage.
pub const TRANSCRIPT_TAIL_MAX_BYTES: u64 = 512 * 1024;
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);
const STATUS_PERMISSION_PROMPT: &str = "permission prompt";

/// The adapter for one vendor user's Claude Code: its binary and its configuration directory.
#[derive(Debug, Clone)]
pub struct ClaudeControl {
    pub binary: PathBuf,
    /// The vendor user's `~/.claude` (or `CLAUDE_CONFIG_DIR`).
    pub config_dir: PathBuf,
}

/// One registry file, decoded; fields the adapter does not use are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryEntry {
    pub pid: u32,
    pub session_id: String,
    pub cwd: String,
    pub kind: String,
    pub status: String,
    pub waiting_for: Option<String>,
    pub messaging_socket_path: Option<String>,
}

/// Where a session id stands in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Located {
    Found(RegistryEntry),
    Absent,
    Unreadable(String),
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

/// The one `--settings` object: the spec's sandbox, inbound messages accepted, and the
/// widest auto-compact window. Re-passed on every resume: the vendor does not keep it.
pub fn settings_json(sandbox_settings: &str) -> Result<String, VendorError> {
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

/// The registry's directory name for a working directory: every byte outside `[A-Za-z0-9]`
/// becomes `-`, as observed for `/Users/frits/.tw12/work` and `-Users-frits--tw12-work`.
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
    match (entry.status.as_str(), entry.waiting_for.as_deref()) {
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

/// Context held after the last assistant turn in a transcript tail: input, cache creation
/// and cache read tokens of its usage.
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

/// Writes the line, half-closes, and reads what comes back within the bound.
#[must_use]
pub fn post(socket: &Path, line: &str) -> Delivery {
    let mut stream = match UnixStream::connect(socket) {
        Ok(stream) => stream,
        Err(error) => return connect_failure(socket, &error),
    };
    let label = socket.display().to_string();
    let written = stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_read_timeout(Some(IO_TIMEOUT)))
        .and_then(|()| stream.write_all(line.as_bytes()))
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write));
    if let Err(error) = written {
        return Delivery::WriteFailed {
            socket: label,
            reason: bounded(&error.to_string()),
        };
    }
    let mut reply = Vec::new();
    let limit = u64::try_from(REPLY_MAX_BYTES).unwrap_or(u64::MAX);
    match (&mut stream).take(limit).read_to_end(&mut reply) {
        Ok(_) if reply.is_empty() => Delivery::Posted { socket: label },
        Ok(_) => Delivery::Replied {
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
    #[must_use]
    pub const fn new(binary: PathBuf, config_dir: PathBuf) -> Self {
        Self { binary, config_dir }
    }

    /// Scans the registry for live processes holding the id; more files than the bound is an
    /// error, never a partial scan.
    #[must_use]
    pub fn locate(&self, session: &VendorSessionId) -> Located {
        let dir = self.config_dir.join("sessions");
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Located::Absent,
            Err(error) => {
                return Located::Unreadable(bounded(&format!("{}: {error}", dir.display())))
            }
        };
        let mut found = Vec::new();
        for (count, entry) in entries.enumerate() {
            if count >= REGISTRY_FILES_MAX {
                return Located::Unreadable(format!(
                    "{} holds more than {REGISTRY_FILES_MAX} entries",
                    dir.display()
                ));
            }
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            if let Some(record) = Self::read_entry(&path, session) {
                found.push(record);
            }
        }
        match found.len() {
            0 => Located::Absent,
            1 => found.pop().map_or(Located::Absent, Located::Found),
            many => Located::Ambiguous(many),
        }
    }

    /// A registry file for this id whose process is alive; anything else is skipped.
    fn read_entry(path: &Path, session: &VendorSessionId) -> Option<RegistryEntry> {
        let bytes = read_checked(path, REGISTRY_FILE_MAX_BYTES, None).ok()??;
        let entry = decode_registry(&bytes).ok()?;
        (entry.session_id == session.as_str() && alive(entry.pid)).then_some(entry)
    }

    fn transcript_tail(&self, entry: &RegistryEntry) -> Result<Option<String>, String> {
        let path = self
            .config_dir
            .join("projects")
            .join(project_slug(&entry.cwd))
            .join(format!("{}.jsonl", entry.session_id));
        let mut file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(bounded(&format!("{}: {error}", path.display()))),
        };
        let length = file.metadata().map_err(|error| error.to_string())?.len();
        let start = length.saturating_sub(TRANSCRIPT_TAIL_MAX_BYTES);
        file.seek(SeekFrom::Start(start))
            .map_err(|error| error.to_string())?;
        let mut tail = Vec::new();
        file.take(TRANSCRIPT_TAIL_MAX_BYTES)
            .read_to_end(&mut tail)
            .map_err(|error| error.to_string())?;
        Ok(Some(String::from_utf8_lossy(&tail).into_owned()))
    }
}

impl SessionVendor for ClaudeControl {
    fn describe(&self) -> String {
        format!("claude control at {}", self.binary.display())
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

    fn address(&self, session: &VendorSessionId, instruction: &ShortText) -> Delivery {
        match self.locate(session) {
            Located::Found(entry) => entry.messaging_socket_path.map_or_else(
                || Delivery::Unrecognised {
                    reason: "the registry entry names no inbox socket".to_string(),
                },
                |socket| post(Path::new(&socket), &instruction_line(instruction)),
            ),
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
            Located::Unreadable(reason) => Observation::Unreadable { reason },
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
            Located::Unreadable(reason) => return ContextReport::Unreadable { reason },
            Located::Ambiguous(count) => {
                return ContextReport::Unrecognised {
                    reason: format!("{count} live processes hold the session id"),
                }
            }
        };
        match self.transcript_tail(&entry) {
            Ok(Some(tail)) => context_of(&tail),
            Ok(None) => ContextReport::NoTurnYet,
            Err(reason) => ContextReport::Unreadable { reason },
        }
    }
}

#[cfg(test)]
mod tests;

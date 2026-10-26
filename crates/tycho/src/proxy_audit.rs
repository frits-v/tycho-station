//! The session proxy's decisions as a file beside the spool, and the core's decoding of it
//! into the firings and examinations of mandate article 15.
//!
//! The launcher writes the file once, when the vendor ends, as the agent; the core reads it
//! as a file of the agent's in a directory the agent can write, so it is read without
//! following a link, within its bound, and every line it cannot place counts as
//! unrecognised, never as a decision.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use nono::undo::{NetworkAuditDecision, NetworkAuditEvent};
use serde::{Deserialize, Serialize};
use tycho_types::session::SessionName;

use crate::agent_files::{read_checked, write_durable_mode};
use crate::config::AgentDirs;
use crate::session_proxy::AUDIT_EVENTS_MAX;

/// Beside the session's spool directory, in the spool root the core's group can read.
pub const AUDIT_FILE_SUFFIX: &str = "proxy-audit.jsonl";
/// The core reads the agent's file through the shared group.
pub const AUDIT_FILE_MODE: u32 = 0o640;
/// The bounds of the text fields as JSON writes them, escapes included: a `"` or `\` the
/// vendor puts in a host name takes two bytes, so a bound on the raw text would not bound the
/// line.
pub const TARGET_MAX_BYTES: usize = 253;
pub const REASON_MAX_BYTES: usize = 256;
pub const PATH_MAX_BYTES: usize = 32;
/// Ends a field that was cut to its bound.
pub const CUT_MARKER: char = '\u{2026}';
/// One line at its longest: the three text fields at their escaped bounds and the fixed
/// fields at their widest come to under 700 bytes.
pub const AUDIT_LINE_MAX_BYTES: usize = 1024;
/// The proxy's cap of events plus the one line that says it was reached.
pub const AUDIT_LINES_MAX: usize = AUDIT_EVENTS_MAX + 1;
pub const AUDIT_FILE_MAX_BYTES: usize = AUDIT_LINES_MAX * AUDIT_LINE_MAX_BYTES;
/// The mechanism a refusal at the proxy is a firing of.
pub const MECHANISM: &str = "session_proxy";
/// Firings a session's record names; `firing_count` counts every one.
pub const FIRINGS_KEPT_MAX: usize = 32;

/// The audit file of one session.
#[must_use]
pub fn audit_path(dirs: &AgentDirs, session: &SessionName) -> PathBuf {
    dirs.spool_root()
        .join(format!("{session}.{AUDIT_FILE_SUFFIX}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineDecision {
    Allow,
    Deny,
    /// An approval decision, which the station's proxy configuration never asks for.
    Other,
    /// The proxy held its cap of events and dropped every later one.
    CapReached,
}

/// One line of the file: the station's own shape, so a nono release that changes its event
/// type changes the writer, not what the core reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLine {
    pub unix_ms: u64,
    pub decision: LineDecision,
    /// The path the request took: `connect`, `connect_intercept`, `reverse` or `external`.
    pub path: String,
    pub target: String,
    pub port: Option<u16>,
    pub reason: Option<String>,
}

/// The bytes JSON writes for a character the cut keeps; control characters are dropped.
const fn escaped_len(character: char) -> usize {
    if matches!(character, '"' | '\\') {
        2
    } else {
        character.len_utf8()
    }
}

/// The text without control characters, within `max` bytes as JSON writes it; a text that
/// does not fit is cut and ends with `CUT_MARKER`.
fn cut(text: &str, max: usize) -> String {
    let kept: Vec<char> = text
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    let whole: usize = kept.iter().map(|character| escaped_len(*character)).sum();
    if whole <= max {
        return kept.into_iter().collect();
    }
    let budget = max.saturating_sub(escaped_len(CUT_MARKER));
    let mut used = 0_usize;
    let mut cut = String::new();
    for character in kept {
        used = used.saturating_add(escaped_len(character));
        if used > budget {
            break;
        }
        cut.push(character);
    }
    cut.push(CUT_MARKER);
    cut
}

impl AuditLine {
    #[must_use]
    pub fn of(event: &NetworkAuditEvent) -> Self {
        let decision = match event.decision {
            NetworkAuditDecision::Allow => LineDecision::Allow,
            NetworkAuditDecision::Deny => LineDecision::Deny,
            _ => LineDecision::Other,
        };
        let path = serde_json::to_value(&event.mode)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(|| "unrecognised".to_string());
        Self {
            unix_ms: event.timestamp_unix_ms,
            decision,
            path: cut(&path, PATH_MAX_BYTES),
            target: cut(&event.target, TARGET_MAX_BYTES),
            port: event.port,
            reason: event
                .reason
                .as_deref()
                .map(|reason| cut(reason, REASON_MAX_BYTES)),
        }
    }
}

/// The file's bytes: one line per event, at most the proxy's cap, then the cap line when the
/// proxy reached it.
pub fn encode(events: &[NetworkAuditEvent]) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = Vec::new();
    for event in events.iter().take(AUDIT_EVENTS_MAX) {
        serde_json::to_writer(&mut bytes, &AuditLine::of(event))?;
        bytes.push(b'\n');
    }
    if events.len() >= AUDIT_EVENTS_MAX {
        let cap = AuditLine {
            unix_ms: events.last().map_or(0, |event| event.timestamp_unix_ms),
            decision: LineDecision::CapReached,
            path: String::new(),
            target: String::new(),
            port: None,
            reason: Some(format!("the proxy kept {AUDIT_EVENTS_MAX} events")),
        };
        serde_json::to_writer(&mut bytes, &cap)?;
        bytes.push(b'\n');
    }
    Ok(bytes)
}

/// Writes the file under a staging name and renames it into place, so the core reads the
/// whole file or none; a file already there is an error, and nothing is written through a
/// link.
pub fn write(path: &Path, events: &[NetworkAuditEvent]) -> io::Result<usize> {
    let bytes = encode(events).map_err(io::Error::other)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} already exists", path.display()),
            ));
        }
        Err(error) => return Err(error),
    }
    write_durable_mode(path, &bytes, AUDIT_FILE_MODE)?;
    Ok(events.len().min(AUDIT_EVENTS_MAX))
}

/// A refusal at the proxy: a firing of the session proxy under article 15.5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Firing {
    pub mechanism: String,
    pub session: SessionName,
    /// The refused destination, `host:port`.
    pub subject: String,
    pub unix_ms: u64,
    pub reason: Option<String>,
}

/// What one session's file says, as the ledger counts it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAudit {
    /// Admitted requests: runs of the mechanism that found nothing to refuse.
    pub examinations: usize,
    /// Every refusal in the file.
    pub firing_count: usize,
    /// The first `FIRINGS_KEPT_MAX` refusals.
    pub firings: Vec<Firing>,
    /// Lines that are not a decision the decoder knows; never counted as either.
    pub unrecognised: usize,
    /// The proxy dropped events past its cap, so the counts are a lower bound.
    pub at_cap: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AuditRead {
    /// No file: the launcher wrote none, or has not yet.
    Absent,
    Read(SessionAudit),
    /// The file could not be read as the agent's regular file within its bound.
    Unreadable {
        reason: String,
    },
}

impl fmt::Display for SessionAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let subjects: Vec<&str> = self
            .firings
            .iter()
            .map(|firing| firing.subject.as_str())
            .collect();
        write!(
            formatter,
            "{} examinations, {} firings [{}], {} unrecognised{}",
            self.examinations,
            self.firing_count,
            subjects.join(", "),
            self.unrecognised,
            if self.at_cap {
                ", at the proxy's cap"
            } else {
                ""
            }
        )
    }
}

/// Decodes the file's bytes; a line over its bound, a line past the most the launcher writes,
/// or one that does not decode, is unrecognised.
#[must_use]
pub fn decode(session: &SessionName, bytes: &[u8]) -> SessionAudit {
    let mut audit = SessionAudit {
        examinations: 0,
        firing_count: 0,
        firings: Vec::new(),
        unrecognised: 0,
        at_cap: false,
    };
    let lines = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty());
    for (index, line) in lines.enumerate() {
        let decoded = (index < AUDIT_LINES_MAX && line.len() <= AUDIT_LINE_MAX_BYTES)
            .then(|| serde_json::from_slice::<AuditLine>(line).ok())
            .flatten();
        match decoded.map(|line| (line.decision, line)) {
            Some((LineDecision::Allow, _)) => {
                audit.examinations = audit.examinations.saturating_add(1);
            }
            Some((LineDecision::Deny, line)) => {
                audit.firing_count = audit.firing_count.saturating_add(1);
                if audit.firings.len() < FIRINGS_KEPT_MAX {
                    audit.firings.push(Firing {
                        mechanism: MECHANISM.to_string(),
                        session: session.clone(),
                        subject: format!("{}:{}", line.target, line.port.unwrap_or_default()),
                        unix_ms: line.unix_ms,
                        reason: line.reason,
                    });
                }
            }
            Some((LineDecision::CapReached, _)) => audit.at_cap = true,
            Some((LineDecision::Other, _)) | None => {
                audit.unrecognised = audit.unrecognised.saturating_add(1);
            }
        }
    }
    audit
}

/// The core's read of one session's file, as a file of `agent_uid` within its bound.
#[must_use]
pub fn read(dirs: &AgentDirs, session: &SessionName, agent_uid: u32) -> AuditRead {
    let path = audit_path(dirs, session);
    match read_checked(&path, AUDIT_FILE_MAX_BYTES, Some(agent_uid)) {
        Ok(None) => AuditRead::Absent,
        Ok(Some(bytes)) => AuditRead::Read(decode(session, &bytes)),
        Err(error) => AuditRead::Unreadable {
            reason: format!("{}: {error}", path.display()),
        },
    }
}

#[cfg(test)]
mod tests;

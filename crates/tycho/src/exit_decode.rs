//! The files a vendor adapter writes for the launcher, the progress file and the result
//! file, and the table that turns how a vendor ended into an `ExitState`.

use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus;

use serde::Deserialize;
use tycho_types::envelope::{
    CommitSha, ProgressMarker, ShortText, StatusPayload, Usage, ENVELOPE_MAX_BYTES,
};
use tycho_types::exit::ExitState;
use tycho_types::session::SessionName;

use crate::agent_files::{current_uid, read_checked};
use crate::spool::{check_result_envelope, escalation_rejection};

pub const PROGRESS_FILE_MAX_BYTES: usize = 4096;
pub const RESULT_FILE_MAX_BYTES: usize = ENVELOPE_MAX_BYTES + 1024;
const SUMMARY_RUNNING: &str = "running";
const SUMMARY_PROGRESS_INVALID: &str = "progress file unreadable";
/// Wire text of the unrecognised states this table produces.
pub const RAW_RESULT_FILE_INVALID: &str = "result_file_invalid";
pub const RAW_COMPLETED_WITHOUT_RESULT: &str = "completed_without_valid_result";
pub const RAW_EXIT_STATUS_UNKNOWN: &str = "exit_status_unknown";

/// What the vendor's hooks last wrote; every field is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressFile {
    pub head_sha: Option<CommitSha>,
    #[serde(default)]
    pub tests_passing: u32,
    pub summary: Option<ShortText>,
    pub context_tokens: Option<u64>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_micro_dollars: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    Absent,
    Read {
        file: ProgressFile,
        modified_unix_ms: u64,
    },
    Invalid(String),
}

#[must_use]
pub fn read_progress(path: &Path) -> Progress {
    let bytes = match read_checked(path, PROGRESS_FILE_MAX_BYTES, Some(current_uid())) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Progress::Absent,
        Err(error) => return Progress::Invalid(error.to_string()),
    };
    let modified_unix_ms = std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        });
    match serde_json::from_slice::<ProgressFile>(&bytes) {
        Ok(file) => Progress::Read {
            file,
            modified_unix_ms,
        },
        Err(error) => Progress::Invalid(error.to_string()),
    }
}

/// The heartbeat's status and context size: the progress marker, or an empty one with a note
/// when the file is unreadable.
pub fn status_payload(
    progress: &Progress,
    started_unix_ms: u64,
) -> Result<(StatusPayload, u64), String> {
    let summary = |text: &str| ShortText::parse(text).map_err(|error| error.to_string());
    let (file, last_progress_unix_ms, fallback) = match progress {
        Progress::Absent => (ProgressFile::default(), started_unix_ms, SUMMARY_RUNNING),
        Progress::Read {
            file,
            modified_unix_ms,
        } => (file.clone(), *modified_unix_ms, SUMMARY_RUNNING),
        Progress::Invalid(_) => (
            ProgressFile::default(),
            started_unix_ms,
            SUMMARY_PROGRESS_INVALID,
        ),
    };
    let context_tokens = file.context_tokens.unwrap_or(0);
    let status = StatusPayload {
        state: None,
        summary: file.summary.map_or_else(|| summary(fallback), Ok)?,
        last_progress_unix_ms,
        progress: ProgressMarker {
            head_sha: file.head_sha,
            tests_passing: file.tests_passing,
        },
        active_workers: 0,
        usage: Usage {
            input_tokens: file.input_tokens.unwrap_or(0),
            output_tokens: file.output_tokens.unwrap_or(0),
            // A seat-billed vendor reports no cost, so an absent field is zero spend.
            cost_micro_dollars: file.cost_micro_dollars.unwrap_or(0),
        },
        blockers: Vec::new(),
    };
    Ok((status, context_tokens))
}

/// The result file: a state word, and with `completed` the result envelope.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultReport {
    pub state: String,
    pub envelope: Option<serde_json::Value>,
    /// Why the vendor adapter chose this state, for the launcher's log; never decoded.
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultFile {
    Absent,
    Report(ResultReport),
    Invalid(String),
}

#[must_use]
pub fn read_result_file(path: &Path) -> ResultFile {
    match read_checked(path, RESULT_FILE_MAX_BYTES, Some(current_uid())) {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).map_or_else(
            |error| ResultFile::Invalid(error.to_string()),
            ResultFile::Report,
        ),
        Ok(None) => ResultFile::Absent,
        Err(error) => ResultFile::Invalid(error.to_string()),
    }
}

/// How the vendor process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildEnd {
    Exited(i32),
    Signalled(i32),
    NotStarted,
    Unknown,
}

impl From<ExitStatus> for ChildEnd {
    fn from(status: ExitStatus) -> Self {
        match (status.code(), status.signal()) {
            (Some(code), _) => Self::Exited(code),
            (None, Some(signal)) => Self::Signalled(signal),
            (None, None) => Self::Unknown,
        }
    }
}

/// Why the launcher ended the vendor itself, if it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    None,
    /// SIGTERM or SIGHUP to the launcher.
    Cancelled,
    WallClock,
    OutputTooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub state: ExitState,
    pub envelope: Option<serde_json::Value>,
}

impl Decoded {
    const fn failure(state: ExitState) -> Self {
        Self {
            state,
            envelope: None,
        }
    }
}

/// The exit decoding table; a stop by the launcher wins over anything the vendor wrote.
#[must_use]
pub fn decode_exit(
    stop: Stop,
    end: ChildEnd,
    result: ResultFile,
    session: &SessionName,
) -> Decoded {
    match stop {
        Stop::Cancelled => return Decoded::failure(ExitState::Cancelled),
        Stop::WallClock => return Decoded::failure(ExitState::BudgetExceeded),
        Stop::OutputTooLarge => return Decoded::failure(ExitState::Failed),
        Stop::None => {}
    }
    match result {
        ResultFile::Invalid(_) => Decoded::failure(ExitState::from_wire(RAW_RESULT_FILE_INVALID)),
        ResultFile::Report(report) => decode_report(report, end, session),
        ResultFile::Absent => Decoded::failure(match end {
            ChildEnd::Exited(_) | ChildEnd::NotStarted => ExitState::Failed,
            ChildEnd::Signalled(_) => ExitState::Killed,
            ChildEnd::Unknown => ExitState::from_wire(RAW_EXIT_STATUS_UNKNOWN),
        }),
    }
}

fn decode_report(report: ResultReport, end: ChildEnd, session: &SessionName) -> Decoded {
    match ExitState::from_wire(&report.state) {
        ExitState::Completed => match (end, report.envelope) {
            (ChildEnd::Exited(0), Some(envelope))
                if check_result_envelope(&envelope, session).is_ok() =>
            {
                Decoded {
                    state: ExitState::Completed,
                    envelope: Some(envelope),
                }
            }
            _ => Decoded::failure(ExitState::from_wire(RAW_COMPLETED_WITHOUT_RESULT)),
        },
        ExitState::Escalated => match report.envelope {
            Some(envelope) if escalation_rejection(&envelope, session).is_ok() => Decoded {
                state: ExitState::Escalated,
                envelope: Some(envelope),
            },
            _ => Decoded::failure(ExitState::Escalated),
        },
        other => Decoded::failure(other),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use tycho_types::exit::Disposition;

    pub const SESSION: &str = "cf7a.wu03.wrk.claude.a1f3";
    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[must_use]
    pub fn envelope(from: &str) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "id": "01J9Z3K7Q8R2W5X6Y7Z8A9B0C1",
            "type": "result",
            "work_unit_id": "wu03",
            "from": from,
            "to": "cf7a.wu03.ctl.codex",
            "causation_id": null,
            "correlation_id": "cf7a",
            "created_at_unix_ms": 1,
            "expires_at_unix_ms": null,
            "payload": {
                "outcome": "done",
                "branch": "wu03/a1",
                "head_sha": SHA,
                "criteria": [],
                "usage": {"input_tokens": 1, "output_tokens": 2}
            }
        })
    }

    fn session() -> SessionName {
        SessionName::parse(SESSION).unwrap()
    }

    fn report(state: &str, envelope: Option<serde_json::Value>) -> ResultFile {
        ResultFile::Report(ResultReport {
            state: state.to_string(),
            envelope,
            detail: None,
        })
    }

    fn decode(stop: Stop, end: ChildEnd, result: ResultFile) -> ExitState {
        decode_exit(stop, end, result, &session()).state
    }

    fn unrecognised(raw: &str) -> ExitState {
        ExitState::from_wire(raw)
    }

    #[test]
    fn launcher_stops_win_over_the_vendor() {
        let done = || report("completed", Some(envelope(SESSION)));
        let ok = ChildEnd::Exited(0);
        assert_eq!(decode(Stop::Cancelled, ok, done()), ExitState::Cancelled);
        assert_eq!(
            decode(Stop::WallClock, ok, done()),
            ExitState::BudgetExceeded
        );
        assert_eq!(decode(Stop::OutputTooLarge, ok, done()), ExitState::Failed);
    }

    #[test]
    fn completed_needs_exit_zero_and_a_result_from_this_session() {
        let decoded = decode_exit(
            Stop::None,
            ChildEnd::Exited(0),
            report("completed", Some(envelope(SESSION))),
            &session(),
        );
        assert_eq!(decoded.state, ExitState::Completed);
        assert_eq!(decoded.envelope, Some(envelope(SESSION)));
        let bad = unrecognised(RAW_COMPLETED_WITHOUT_RESULT);
        for (end, result) in [
            (
                ChildEnd::Exited(1),
                report("completed", Some(envelope(SESSION))),
            ),
            (
                ChildEnd::Signalled(9),
                report("completed", Some(envelope(SESSION))),
            ),
            (ChildEnd::Exited(0), report("completed", None)),
            (
                ChildEnd::Exited(0),
                report("completed", Some(envelope("cf7a.wu03.wrk.claude.other"))),
            ),
            (
                ChildEnd::Exited(0),
                report("completed", Some(serde_json::json!({}))),
            ),
        ] {
            assert_eq!(decode(Stop::None, end, result), bad);
        }
        assert_eq!(bad.disposition(), Disposition::Inbox);
    }

    #[test]
    fn a_reported_failure_state_passes_through() {
        for state in [
            ExitState::Escalated,
            ExitState::TooLarge,
            ExitState::Stalled,
            ExitState::Cancelled,
            ExitState::Killed,
            ExitState::BudgetExceeded,
            ExitState::RateLimited,
            ExitState::Failed,
        ] {
            let result = report(state.as_wire(), None);
            assert_eq!(decode(Stop::None, ChildEnd::Exited(3), result), state);
        }
        let unknown = decode(
            Stop::None,
            ChildEnd::Exited(0),
            report("error_max_turns", None),
        );
        assert_eq!(unknown, unrecognised("error_max_turns"));
        assert_eq!(unknown.disposition(), Disposition::Inbox);
    }

    #[test]
    fn without_a_result_file_the_exit_status_decides() {
        let absent = || ResultFile::Absent;
        assert_eq!(
            decode(Stop::None, ChildEnd::Exited(0), absent()),
            ExitState::Failed
        );
        assert_eq!(
            decode(Stop::None, ChildEnd::Exited(2), absent()),
            ExitState::Failed
        );
        assert_eq!(
            decode(Stop::None, ChildEnd::NotStarted, absent()),
            ExitState::Failed
        );
        assert_eq!(
            decode(Stop::None, ChildEnd::Signalled(9), absent()),
            ExitState::Killed
        );
        assert_eq!(
            decode(Stop::None, ChildEnd::Unknown, absent()),
            unrecognised(RAW_EXIT_STATUS_UNKNOWN)
        );
        assert_eq!(
            decode(
                Stop::None,
                ChildEnd::Exited(0),
                ResultFile::Invalid("x".into())
            ),
            unrecognised(RAW_RESULT_FILE_INVALID)
        );
    }

    #[test]
    fn result_and_progress_files_are_bounded_and_strict() {
        let dir = std::env::temp_dir().join(format!("tycho-exit-decode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let result = dir.join("result.json");
        assert_eq!(read_result_file(&result), ResultFile::Absent);
        std::fs::write(&result, "x".repeat(RESULT_FILE_MAX_BYTES + 1)).unwrap();
        assert!(matches!(read_result_file(&result), ResultFile::Invalid(_)));
        std::fs::write(&result, r#"{"state":"failed","extra":1}"#).unwrap();
        assert!(matches!(read_result_file(&result), ResultFile::Invalid(_)));
        std::fs::write(&result, r#"{"state":"failed","envelope":null}"#).unwrap();
        assert!(matches!(read_result_file(&result), ResultFile::Report(_)));
        let progress = dir.join("progress.json");
        assert_eq!(read_progress(&progress), Progress::Absent);
        std::fs::write(&progress, r#"{"head_sha":"nothex"}"#).unwrap();
        let invalid = read_progress(&progress);
        assert!(matches!(invalid, Progress::Invalid(_)));
        let (status, _) = status_payload(&invalid, 7).unwrap();
        assert_eq!(status.summary.as_str(), SUMMARY_PROGRESS_INVALID);
        std::fs::write(
            &progress,
            format!(r#"{{"head_sha":"{SHA}","tests_passing":4,"context_tokens":900}}"#),
        )
        .unwrap();
        let (status, context_tokens) = status_payload(&read_progress(&progress), 7).unwrap();
        assert_eq!(status.progress.tests_passing, 4);
        assert_eq!(context_tokens, 900);
        assert_eq!(status.summary.as_str(), SUMMARY_RUNNING);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

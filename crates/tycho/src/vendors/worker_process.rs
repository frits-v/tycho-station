//! `tycho worker`, the vendor command the launcher runs for a headless worker.
//!
//! It checks the vendor's version banner, runs the headless command in the worktree with the
//! brief on stdin, folds the event stream into the progress file as it goes, and writes the
//! result file the launcher decodes when the vendor exits.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use nix::sys::signal::Signal;
use nix::unistd::{Uid, User};
use serde_json::{json, Value};
use tycho_types::envelope::{CommitSha, Envelope, Payload, RecordId, ResultPayload};
use tycho_types::launcher::ENV_SESSION_NAME;
use tycho_types::session::{SessionName, Vendor};

use crate::agent_files::write_durable;
use crate::command::run_captured;
use crate::config::COMMAND_TIMEOUT;
use crate::exit_decode::ChildEnd;
use crate::launch_spec::{
    AGENT_TELEMETRY_ENV, PROGRESS_FILE_ENV, RESULT_FILE_ENV, VENDOR_SANDBOX_SETTINGS_ENV,
};
use crate::process::{now_unix_ms, send};
use crate::vendors::claude_worker::ClaudeWorker;
use crate::vendors::codex_worker::{CodexWorker, CODEX_OUTPUT_SCHEMA};
use crate::vendors::worker::{
    outcome, state_word, CommandRefusal, Refusal, Stream, VersionState, WorkerArgs, WorkerError,
    WorkerTask, WorkerVendor, EVENT_LINE_MAX_BYTES, WORD_VERSION_MISMATCH,
};

/// Event lines one run may produce; the launcher's output cap usually ends it first.
pub const EVENT_LINES_MAX: u64 = 1_000_000;
pub const OUTPUT_SCHEMA_FILE: &str = "output-schema.json";
pub const EXIT_COMPLETED: i32 = 0;
pub const EXIT_NOT_COMPLETED: i32 = 1;
pub const EXIT_REFUSED: i32 = 2;

/// What the launcher hands the worker in its environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerEnvironment {
    pub result: PathBuf,
    pub progress: PathBuf,
    pub session: SessionName,
    pub settings: String,
    pub inherited: Vec<(String, String)>,
}

fn required(environment: &BTreeMap<String, String>, name: &str) -> Result<String, WorkerError> {
    environment
        .get(name)
        .cloned()
        .ok_or_else(|| WorkerError::Argument(format!("{name} is not set")))
}

impl WorkerEnvironment {
    pub fn from_map(environment: &BTreeMap<String, String>) -> Result<Self, WorkerError> {
        let session = SessionName::parse(&required(environment, ENV_SESSION_NAME)?)
            .map_err(|error| WorkerError::Argument(error.to_string()))?;
        let inherited_names = ["HOME", "PATH"]
            .into_iter()
            .chain(AGENT_TELEMETRY_ENV.iter().map(|(name, _)| *name));
        let inherited = inherited_names
            .filter_map(|name| {
                environment
                    .get(name)
                    .map(|value| (name.to_string(), value.clone()))
            })
            .collect();
        Ok(Self {
            result: PathBuf::from(required(environment, RESULT_FILE_ENV)?),
            progress: PathBuf::from(required(environment, PROGRESS_FILE_ENV)?),
            session,
            settings: required(environment, VENDOR_SANDBOX_SETTINGS_ENV)?,
            inherited,
        })
    }
}

/// HOME, PATH and telemetry off from the launcher, and USER from the uid: the pinned Claude
/// CLI finds its subscription login in the keychain under USER and fails without it.
#[must_use]
pub fn vendor_environment(environment: &WorkerEnvironment, user: &str) -> Vec<(String, String)> {
    let mut pairs = environment.inherited.clone();
    pairs.push(("USER".to_string(), user.to_string()));
    pairs
}

fn current_user() -> Result<String, WorkerError> {
    User::from_uid(Uid::current())
        .ok()
        .flatten()
        .map(|user| user.name)
        .ok_or_else(|| WorkerError::Argument("the current uid has no user name".to_string()))
}

#[must_use]
pub fn adapter(vendor: Vendor) -> Option<Box<dyn WorkerVendor>> {
    match vendor {
        Vendor::Claude => Some(Box::new(ClaudeWorker)),
        Vendor::Codex => Some(Box::new(CodexWorker)),
        Vendor::Antigravity | Vendor::Amp | Vendor::OpenCode => None,
    }
}

/// The progress file the launcher's heartbeat reads.
#[must_use]
pub fn progress_json(stream: &Stream) -> Value {
    json!({
        "context_tokens": stream.context_tokens,
        "input_tokens": stream.usage.input_tokens,
        "output_tokens": stream.usage.output_tokens,
        "cost_micro_dollars": stream.usage.cost_micro_dollars,
    })
}

/// What a completed result needs besides the stream.
#[derive(Debug, Clone)]
pub struct Claim<'a> {
    pub args: &'a WorkerArgs,
    pub session: &'a SessionName,
    pub head: CommitSha,
    pub created_at_unix_ms: u64,
}

/// The result envelope: from this worker to its control session, a claim of done or not.
pub fn result_envelope(claim: &Claim<'_>, stream: &Stream) -> Result<Value, String> {
    let work_unit = claim
        .session
        .work_unit()
        .cloned()
        .ok_or_else(|| format!("{} names no work unit", claim.session))?;
    let envelope = Envelope {
        id: RecordId::parse(claim.args.session_id.as_str()).map_err(|error| error.to_string())?,
        work_unit_id: work_unit,
        from: claim.session.clone(),
        to: claim.args.to.clone(),
        causation_id: None,
        correlation_id: claim.session.epic().clone(),
        created_at_unix_ms: claim.created_at_unix_ms,
        expires_at_unix_ms: None,
        payload: Payload::Result(ResultPayload {
            outcome: outcome(&claim.args.base, &claim.head, stream.reported_outcome),
            branch: claim.args.branch.clone(),
            head_sha: claim.head.clone(),
            criteria: Vec::new(),
            usage: stream.usage,
        }),
    };
    let bytes = envelope.to_bytes().map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    write_durable(path, &bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn write_result(path: &Path, state: &str, envelope: Option<&Value>) -> Result<(), String> {
    write_json(path, &json!({"state": state, "envelope": envelope}))
}

/// The worktree's HEAD, read by the worker after the vendor exits.
pub fn head_commit(worktree: &Path) -> Result<CommitSha, String> {
    let worktree = worktree.display().to_string();
    let captured = run_captured(
        Path::new("git"),
        &["-C", &worktree, "rev-parse", "--verify", "HEAD"],
        &[("GIT_CONFIG_NOSYSTEM", "1")],
        COMMAND_TIMEOUT,
    )
    .map_err(|error| error.to_string())?;
    CommitSha::parse(captured.stdout.trim()).map_err(|error| error.to_string())
}

/// Reads at most one bounded line; a longer line is returned cut and counts as unrecognised.
fn next_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> std::io::Result<usize> {
    line.clear();
    let limit = u64::try_from(EVENT_LINE_MAX_BYTES).unwrap_or(u64::MAX);
    reader.by_ref().take(limit).read_until(b'\n', line)
}

/// Feeds every line to the adapter, copies it to `events`, and stops the vendor on a refusal.
pub fn fold_stream(
    vendor: &dyn WorkerVendor,
    source: impl Read,
    events: &mut dyn Write,
    progress: &mut dyn FnMut(&Stream),
) -> Stream {
    let mut stream = Stream::default();
    let mut reader = BufReader::new(source);
    let mut line = Vec::new();
    let mut copying = true;
    for _ in 0..EVENT_LINES_MAX {
        match next_line(&mut reader, &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        copying = copying && events.write_all(&line).is_ok();
        vendor.observe(line.trim_ascii_end(), &mut stream);
        if stream.refusal.is_some() {
            break;
        }
        if stream.reportable() {
            progress(&stream);
        }
    }
    stream
}

fn spawn_vendor(
    command: &[String],
    args: &WorkerArgs,
    environment: &[(String, String)],
) -> Result<Child, String> {
    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| "empty vendor command".to_string())?;
    let brief =
        File::open(&args.brief).map_err(|error| format!("{}: {error}", args.brief.display()))?;
    Command::new(program)
        .args(arguments)
        .current_dir(&args.worktree)
        .env_clear()
        .envs(environment.iter().map(|(name, value)| (name, value)))
        .stdin(brief)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("{program}: {error}"))
}

/// Runs the vendor to its end; a refused stream kills it before it spends more.
fn run_vendor(
    vendor: &dyn WorkerVendor,
    command: &[String],
    run: &Prepared<'_>,
    events: &mut dyn Write,
) -> Result<(Stream, ChildEnd), String> {
    let mut child = spawn_vendor(command, run.args, &run.vendor_environment)?;
    let mut write_progress = |stream: &Stream| {
        drop(write_json(
            &run.environment.progress,
            &progress_json(stream),
        ));
    };
    let stream = child.stdout.take().map_or_else(Stream::default, |stdout| {
        fold_stream(vendor, stdout, events, &mut write_progress)
    });
    if stream.refusal.is_some() {
        drop(send(child.id(), false, Signal::SIGKILL));
    }
    let end = child.wait().map_or(ChildEnd::Unknown, ChildEnd::from);
    write_progress(&stream);
    Ok((stream, end))
}

/// Everything checked before the vendor runs.
struct Prepared<'a> {
    args: &'a WorkerArgs,
    environment: &'a WorkerEnvironment,
    vendor_environment: Vec<(String, String)>,
}

fn check_version(vendor: &dyn WorkerVendor, run: &Prepared<'_>) -> Result<(), Refusal> {
    let pairs: Vec<(&str, &str)> = run
        .vendor_environment
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let banner = run_captured(&run.args.binary, &["--version"], &pairs, COMMAND_TIMEOUT)
        .map(|captured| captured.stdout)
        .unwrap_or_default();
    match vendor.version(&banner) {
        VersionState::Pinned => Ok(()),
        VersionState::Other(found) | VersionState::Unrecognised(found) => {
            Err(Refusal::VersionMismatch(found))
        }
    }
}

/// The state word and the envelope a completed run carries.
fn conclude(run: &Prepared<'_>, stream: &Stream, end: ChildEnd) -> (String, Option<Value>) {
    let word = state_word(stream, end);
    if word != "completed" {
        return (word, None);
    }
    let claim = head_commit(&run.args.worktree).and_then(|head| {
        result_envelope(
            &Claim {
                args: run.args,
                session: &run.environment.session,
                head,
                created_at_unix_ms: now_unix_ms(),
            },
            stream,
        )
    });
    claim.map_or_else(
        |_| ("failed".to_string(), None),
        |envelope| (word, Some(envelope)),
    )
}

/// The whole worker run; returns the exit code and, on a refusal to start, the reason.
pub fn run(
    words: &[String],
    environment: &BTreeMap<String, String>,
    events: &mut dyn Write,
) -> Result<i32, String> {
    let environment =
        WorkerEnvironment::from_map(environment).map_err(|error| error.to_string())?;
    let parsed = WorkerArgs::parse(words).and_then(|args| {
        adapter(args.vendor)
            .map(|vendor| (args, vendor))
            .ok_or(WorkerError::Unsupported(CommandRefusal::NoAdapter))
    });
    let (args, vendor) = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            write_result(&environment.result, "failed", None)?;
            return Err(error.to_string());
        }
    };
    let prepared = Prepared {
        args: &args,
        environment: &environment,
        vendor_environment: vendor_environment(
            &environment,
            &current_user().map_err(|error| error.to_string())?,
        ),
    };
    if check_version(vendor.as_ref(), &prepared).is_err() {
        write_result(&environment.result, WORD_VERSION_MISMATCH, None)?;
        return Ok(EXIT_NOT_COMPLETED);
    }
    let command = prepare_command(vendor.as_ref(), &prepared)?;
    let (stream, end) = match run_vendor(vendor.as_ref(), &command, &prepared, events) {
        Ok(ended) => ended,
        Err(error) => {
            write_result(&environment.result, "failed", None)?;
            return Err(error);
        }
    };
    let (word, envelope) = conclude(&prepared, &stream, end);
    let completed = envelope.is_some();
    write_result(&environment.result, &word, envelope.as_ref())?;
    Ok(if completed {
        EXIT_COMPLETED
    } else {
        EXIT_NOT_COMPLETED
    })
}

/// Writes the output schema beside the result file and builds the vendor's command.
fn prepare_command(vendor: &dyn WorkerVendor, run: &Prepared<'_>) -> Result<Vec<String>, String> {
    let schema = run.environment.result.parent().map_or_else(
        || PathBuf::from(OUTPUT_SCHEMA_FILE),
        |dir| dir.join(OUTPUT_SCHEMA_FILE),
    );
    write_durable(&schema, CODEX_OUTPUT_SCHEMA.as_bytes())
        .map_err(|error| format!("{}: {error}", schema.display()))?;
    let task = WorkerTask {
        worktree: run.args.worktree.clone(),
        model: run.args.model.clone(),
        effort: run.args.effort,
        max_turns: run.args.max_turns,
        // The result is the branch head, so every headless task commits.
        requires_commit: true,
        session_id: run.args.session_id.clone(),
        settings: run.environment.settings.clone(),
        output_schema: schema,
    };
    match vendor.command(&run.args.binary, &task) {
        Ok(command) => Ok(command),
        Err(error) => {
            write_result(&run.environment.result, "failed", None)?;
            Err(error.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendors::worker::{ModelName, VendorEnd, VendorSessionId};
    use std::num::NonZeroU16;
    use tycho_types::envelope::{BranchName, Outcome, Usage};
    use tycho_types::task_packet::Effort;

    const SUCCESS: &str = include_str!("../fixtures/claude-worker-success.jsonl");
    const BARE: &str = include_str!("../fixtures/claude-worker-bare.jsonl");
    const SESSION: &str = "cf7a.wu03.wrk.claude.a1f3";
    const BASE: &str = "0123456789abcdef0123456789abcdef01234567";
    const HEAD: &str = "1123456789abcdef0123456789abcdef01234567";

    fn launcher_environment() -> BTreeMap<String, String> {
        let mut environment = BTreeMap::from([
            (ENV_SESSION_NAME.to_string(), SESSION.to_string()),
            (
                RESULT_FILE_ENV.to_string(),
                "/spool/result.json".to_string(),
            ),
            (
                PROGRESS_FILE_ENV.to_string(),
                "/spool/progress.json".to_string(),
            ),
            (VENDOR_SANDBOX_SETTINGS_ENV.to_string(), "{}".to_string()),
            ("HOME".to_string(), "/Users/agent".to_string()),
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("TYCHO_TIER".to_string(), "light".to_string()),
        ]);
        for (name, value) in AGENT_TELEMETRY_ENV {
            environment.insert(name.to_string(), value.to_string());
        }
        environment
    }

    #[test]
    fn the_vendor_environment_carries_user_and_nothing_of_tycho() {
        let environment = WorkerEnvironment::from_map(&launcher_environment()).unwrap();
        let pairs = vendor_environment(&environment, "agent");
        let names: Vec<&str> = pairs.iter().map(|(name, _)| name.as_str()).collect();
        assert!(pairs.contains(&("USER".to_string(), "agent".to_string())));
        assert!(names.contains(&"HOME") && names.contains(&"PATH"));
        assert!(names.contains(&"DISABLE_TELEMETRY"));
        assert!(
            !names.iter().any(|name| name.starts_with("TYCHO_")),
            "{names:?}"
        );
        assert_eq!(names.len(), 3 + AGENT_TELEMETRY_ENV.len());
    }

    #[test]
    fn the_worker_environment_is_required() {
        for name in [
            ENV_SESSION_NAME,
            RESULT_FILE_ENV,
            PROGRESS_FILE_ENV,
            VENDOR_SANDBOX_SETTINGS_ENV,
        ] {
            let mut environment = launcher_environment();
            environment.remove(name);
            assert!(WorkerEnvironment::from_map(&environment).is_err(), "{name}");
        }
    }

    #[test]
    fn a_stream_is_copied_and_folded_with_progress_on_each_usage() {
        let mut copied = Vec::new();
        let mut reports = 0_u32;
        let stream = fold_stream(&ClaudeWorker, SUCCESS.as_bytes(), &mut copied, &mut |_| {
            reports += 1;
        });
        assert_eq!(copied, SUCCESS.as_bytes());
        assert_eq!(stream.end, Some(VendorEnd::Completed));
        assert!(reports >= 1);
    }

    #[test]
    fn a_refused_stream_stops_at_the_init_event() {
        let mut copied = Vec::new();
        let stream = fold_stream(&ClaudeWorker, BARE.as_bytes(), &mut copied, &mut |_| {});
        assert_eq!(stream.refusal, Some(Refusal::BareMode));
        assert_eq!(stream.end, None);
        assert_eq!(stream.events, 2);
    }

    #[test]
    fn an_overlong_line_is_cut_and_unrecognised() {
        let long = format!(
            "{}\n{{\"type\":\"user\"}}\n",
            "x".repeat(EVENT_LINE_MAX_BYTES + 10)
        );
        let mut sink = std::io::sink();
        let stream = fold_stream(&ClaudeWorker, long.as_bytes(), &mut sink, &mut |_| {});
        assert_eq!((stream.events, stream.unrecognised), (3, 2));
    }

    fn args() -> WorkerArgs {
        WorkerArgs {
            vendor: Vendor::Claude,
            binary: PathBuf::from("/c"),
            brief: PathBuf::from("/b.md"),
            worktree: PathBuf::from("/w"),
            model: ModelName::parse("haiku").unwrap(),
            effort: Effort::Low,
            max_turns: NonZeroU16::new(4),
            session_id: VendorSessionId::parse("3f0c6c1e-6b1a-4a51-9a0e-2a8c5d0c1a10").unwrap(),
            to: SessionName::parse("cf7a.wu03.ctl.claude").unwrap(),
            branch: BranchName::parse("wu03/a1").unwrap(),
            base: CommitSha::parse(BASE).unwrap(),
        }
    }

    #[test]
    fn a_completed_result_is_an_envelope_the_launcher_accepts() {
        let session = SessionName::parse(SESSION).unwrap();
        let args = args();
        let stream = Stream {
            usage: Usage {
                input_tokens: 5,
                output_tokens: 7,
                cost_micro_dollars: 9,
            },
            ..Stream::default()
        };
        let claim = Claim {
            args: &args,
            session: &session,
            head: CommitSha::parse(HEAD).unwrap(),
            created_at_unix_ms: 1,
        };
        let envelope = result_envelope(&claim, &stream).unwrap();
        assert!(crate::spool::check_result_envelope(&envelope, &session).is_ok());
        assert_eq!(envelope["payload"]["outcome"], json!("done"));
        assert_eq!(envelope["payload"]["usage"]["output_tokens"], json!(7));
        let unmoved = Claim {
            head: CommitSha::parse(BASE).unwrap(),
            ..claim
        };
        let envelope = result_envelope(&unmoved, &stream).unwrap();
        let payload: ResultPayload = serde_json::from_value(envelope["payload"].clone()).unwrap();
        assert_eq!(payload.outcome, Outcome::NotDone);
    }

    #[test]
    fn the_progress_file_matches_what_the_launcher_reads() {
        let stream = Stream {
            context_tokens: Some(33_390),
            ..Stream::default()
        };
        let bytes = serde_json::to_vec(&progress_json(&stream)).unwrap();
        let file: crate::exit_decode::ProgressFile = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(file.context_tokens, Some(33_390));
    }
}

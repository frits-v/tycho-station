//! The `WorkerVendor` port: the headless command for one task, the decoder of the vendor's
//! event stream, and the state a decoded stream and the vendor's exit come to.

use std::fmt;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tycho_types::envelope::{BranchName, CommitSha, Outcome, Usage};
use tycho_types::session::{SessionName, Vendor};
use tycho_types::task_packet::Effort;

use crate::exit_decode::{ChildEnd, RAW_EXIT_STATUS_UNKNOWN};

pub const MODEL_NAME_MAX_BYTES: usize = 64;
pub const WORKER_PATH_MAX_BYTES: usize = 1024;
/// Turns one worker may take; a task that needs more is re-planned smaller.
pub const WORKER_TURNS_MAX: u16 = 500;
/// The longest event line a decoder reads; a longer line is unrecognised.
pub const EVENT_LINE_MAX_BYTES: usize = 1024 * 1024;
/// Vendor text kept in a decoded state, such as a result subtype or an error code.
pub const VENDOR_WORD_MAX_BYTES: usize = 48;
const SESSION_ID_GROUPS: [usize; 5] = [8, 4, 4, 4, 12];

/// Result-file words for the states no `ExitState` names; each decodes as unrecognised and
/// blocks in the inbox rather than re-queueing.
pub const WORD_BARE_MODE: &str = "vendor_bare_mode";
pub const WORD_VERSION_MISMATCH: &str = "vendor_version_mismatch";
pub const WORD_LOGIN_REQUIRED: &str = "vendor_login_required";
pub const WORD_NO_RESULT: &str = "vendor_no_result";
pub const WORD_RESULT_PREFIX: &str = "vendor_result_";

/// Why an adapter will not build a command for a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandRefusal {
    /// `codex exec` has no turn cap; a capped task would run uncapped.
    NoTurnCap,
    /// No probe has shown a Codex worker commit in its worktree under the station's sandbox,
    /// with Codex's own sandbox off; the factory does not commit on its behalf.
    CannotCommit,
    /// No headless adapter exists for the vendor.
    NoAdapter,
}

impl fmt::Display for CommandRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NoTurnCap => "codex exec has no turn cap",
            Self::CannotCommit => "a codex exec commit under the station sandbox is not yet probed",
            Self::NoAdapter => "no headless adapter for this vendor",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerError {
    Argument(String),
    Unsupported(CommandRefusal),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argument(reason) => write!(formatter, "worker argument: {reason}"),
            Self::Unsupported(reason) => write!(formatter, "not supported: {reason}"),
        }
    }
}

impl std::error::Error for WorkerError {}

/// A vendor session id assigned before the spawn: a lowercase UUID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct VendorSessionId(String);

impl VendorSessionId {
    pub fn parse(text: &str) -> Result<Self, WorkerError> {
        let groups: Vec<&str> = text.split('-').collect();
        let shaped = groups.len() == SESSION_ID_GROUPS.len()
            && groups.iter().zip(SESSION_ID_GROUPS).all(|(group, length)| {
                group.len() == length
                    && group
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
        if !shaped {
            return Err(WorkerError::Argument(format!(
                "session id {text:?} is not a lowercase UUID"
            )));
        }
        Ok(Self(text.to_string()))
    }

    /// A version 4 UUID from 32 random hex digits, such as a session secret's first half.
    pub fn from_hex(hex: &str) -> Result<Self, WorkerError> {
        let digits: Vec<char> = hex.chars().take(32).collect();
        if digits.len() != 32 {
            return Err(WorkerError::Argument(
                "fewer than 32 hex digits".to_string(),
            ));
        }
        let mut text = String::with_capacity(36);
        for (index, digit) in digits.iter().enumerate() {
            if matches!(index, 8 | 12 | 16 | 20) {
                text.push('-');
            }
            text.push(match index {
                12 => '4',
                16 => '8',
                _ => *digit,
            });
        }
        Self::parse(&text)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for VendorSessionId {
    type Error = WorkerError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<VendorSessionId> for String {
    fn from(value: VendorSessionId) -> Self {
        value.0
    }
}

/// A model name or alias as the vendor CLI takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ModelName(String);

impl ModelName {
    pub fn parse(text: &str) -> Result<Self, WorkerError> {
        let allowed = |byte: u8| byte.is_ascii_alphanumeric() || b"._-[]".contains(&byte);
        if text.is_empty()
            || text.len() > MODEL_NAME_MAX_BYTES
            || text.starts_with('-')
            || !text.bytes().all(allowed)
        {
            return Err(WorkerError::Argument(format!("model {text:?}")));
        }
        Ok(Self(text.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ModelName {
    type Error = WorkerError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ModelName> for String {
    fn from(value: ModelName) -> Self {
        value.0
    }
}

/// An absolute path without `..`, short enough to pass as one argument.
pub fn check_path(what: &str, path: &Path) -> Result<(), WorkerError> {
    let text = path
        .to_str()
        .ok_or_else(|| WorkerError::Argument(format!("{what} is not UTF-8")))?;
    let parent = path
        .components()
        .any(|part| part == std::path::Component::ParentDir);
    if !path.is_absolute() || parent || text.len() > WORKER_PATH_MAX_BYTES {
        return Err(WorkerError::Argument(format!(
            "{what} {text:?} is not a bounded absolute path"
        )));
    }
    Ok(())
}

/// What one headless run needs; the brief file reaches the vendor on stdin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerTask {
    pub worktree: PathBuf,
    pub model: ModelName,
    pub effort: Effort,
    pub max_turns: Option<NonZeroU16>,
    /// Whether the task's result is a commit on the worktree's branch.
    pub requires_commit: bool,
    pub session_id: VendorSessionId,
    /// The sandbox settings JSON the launcher hands the vendor.
    pub settings: String,
    /// Where a vendor that takes a response schema reads it.
    pub output_schema: PathBuf,
}

/// What the `--version` banner says about the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionState {
    Pinned,
    Other(String),
    Unrecognised(String),
}

/// Why the adapter stopped a vendor it had started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    BareMode,
    VersionMismatch(String),
}

/// How the vendor's own stream says the run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VendorEnd {
    Completed,
    TurnCap,
    BudgetCap,
    RateLimited,
    LoginRequired,
    Failed,
    Unrecognised(String),
}

/// The fold of every decoded event of one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stream {
    pub events: u64,
    pub unrecognised: u64,
    pub started: bool,
    pub usage: Usage,
    pub context_tokens: Option<u64>,
    pub resume_handle: Option<String>,
    /// The last error code or message the vendor reported, kept short.
    pub vendor_error: Option<String>,
    pub rate_limit_rejected: bool,
    pub reported_outcome: Option<Outcome>,
    pub refusal: Option<Refusal>,
    pub end: Option<VendorEnd>,
}

impl Stream {
    /// Whether this event changed what the progress file reports.
    #[must_use]
    pub const fn reportable(&self) -> bool {
        self.context_tokens.is_some() || self.end.is_some()
    }
}

/// Keeps vendor text short and visible ASCII, so a state word built from it round-trips.
#[must_use]
pub fn vendor_word(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_graphic)
        .take(VENDOR_WORD_MAX_BYTES)
        .collect()
}

/// One headless vendor: its command line, its version banner and its event decoder.
pub trait WorkerVendor {
    fn vendor(&self) -> Vendor;
    fn pinned_version(&self) -> &'static str;
    /// The headless command, program first; the working directory is the worktree.
    fn command(&self, binary: &Path, task: &WorkerTask) -> Result<Vec<String>, WorkerError>;
    fn version(&self, banner: &str) -> VersionState;
    /// Decodes one event line into the fold; a line it cannot read counts as unrecognised.
    fn observe(&self, line: &[u8], stream: &mut Stream);
}

/// The result-file state word: a refusal first, then the vendor's end, then the exit.
#[must_use]
pub fn state_word(stream: &Stream, end: ChildEnd) -> String {
    match &stream.refusal {
        Some(Refusal::BareMode) => return WORD_BARE_MODE.to_string(),
        Some(Refusal::VersionMismatch(_)) => return WORD_VERSION_MISMATCH.to_string(),
        None => {}
    }
    match (&stream.end, end) {
        (Some(VendorEnd::Completed), ChildEnd::Exited(0)) => "completed".to_string(),
        (None, ChildEnd::Exited(0)) => WORD_NO_RESULT.to_string(),
        (Some(VendorEnd::Completed | VendorEnd::Failed), _)
        | (None, ChildEnd::Exited(_) | ChildEnd::NotStarted) => "failed".to_string(),
        (Some(VendorEnd::TurnCap), _) => "too_large".to_string(),
        (Some(VendorEnd::BudgetCap), _) => "budget_exceeded".to_string(),
        (Some(VendorEnd::RateLimited), _) => "rate_limited".to_string(),
        (Some(VendorEnd::LoginRequired), _) => WORD_LOGIN_REQUIRED.to_string(),
        (Some(VendorEnd::Unrecognised(raw)), _) => format!("{WORD_RESULT_PREFIX}{raw}"),
        (None, ChildEnd::Signalled(_)) => "killed".to_string(),
        (None, ChildEnd::Unknown) => RAW_EXIT_STATUS_UNKNOWN.to_string(),
    }
}

/// Done only when the worker moved the branch and did not itself report not done.
#[must_use]
pub fn outcome(base: &CommitSha, head: &CommitSha, reported: Option<Outcome>) -> Outcome {
    if head != base && reported != Some(Outcome::NotDone) {
        Outcome::Done
    } else {
        Outcome::NotDone
    }
}

/// The `tycho worker` arguments the core puts in the launch spec's vendor command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerArgs {
    pub vendor: Vendor,
    pub binary: PathBuf,
    pub brief: PathBuf,
    pub worktree: PathBuf,
    pub model: ModelName,
    pub effort: Effort,
    pub max_turns: Option<NonZeroU16>,
    pub session_id: VendorSessionId,
    pub to: SessionName,
    pub branch: BranchName,
    pub base: CommitSha,
}

pub const WORKER_COMMAND: &str = "worker";

const fn effort_word(effort: Effort) -> &'static str {
    match effort {
        Effort::Minimal => "minimal",
        Effort::Low => "low",
        Effort::Medium => "medium",
        Effort::High => "high",
        Effort::Max => "max",
    }
}

fn wire<T: for<'de> Deserialize<'de>>(what: &str, text: &str) -> Result<T, WorkerError> {
    serde_json::from_value(serde_json::Value::String(text.to_string()))
        .map_err(|error| WorkerError::Argument(format!("{what} {text:?}: {error}")))
}

impl WorkerArgs {
    /// `<tycho> worker --vendor .. --binary .. ..`, every flag once, `--max-turns` optional.
    #[must_use]
    pub fn to_argv(&self, tycho: &Path) -> Vec<String> {
        let mut words = vec![
            tycho.display().to_string(),
            WORKER_COMMAND.to_string(),
            "--vendor".to_string(),
            self.vendor.as_str().to_string(),
        ];
        let pairs = [
            ("--binary", self.binary.display().to_string()),
            ("--brief", self.brief.display().to_string()),
            ("--worktree", self.worktree.display().to_string()),
            ("--model", self.model.as_str().to_string()),
            ("--effort", effort_word(self.effort).to_string()),
            ("--session-id", self.session_id.as_str().to_string()),
            ("--to", self.to.to_string()),
            ("--branch", self.branch.to_string()),
            ("--base", self.base.to_string()),
        ];
        for (flag, value) in pairs {
            words.push(flag.to_string());
            words.push(value);
        }
        if let Some(turns) = self.max_turns {
            words.push("--max-turns".to_string());
            words.push(turns.to_string());
        }
        words
    }

    /// Parses the words after `worker`; an unknown, repeated or missing flag is refused.
    pub fn parse(words: &[String]) -> Result<Self, WorkerError> {
        let flags = flag_map(words)?;
        let take = |flag: &str| {
            flags
                .get(flag)
                .cloned()
                .ok_or_else(|| WorkerError::Argument(format!("{flag} is missing")))
        };
        let path = |flag: &str| -> Result<PathBuf, WorkerError> {
            let path = PathBuf::from(take(flag)?);
            check_path(flag, &path)?;
            Ok(path)
        };
        let max_turns = flags
            .get("--max-turns")
            .map(|text| parse_turns(text))
            .transpose()?;
        Ok(Self {
            vendor: wire("vendor", &take("--vendor")?)?,
            binary: path("--binary")?,
            brief: path("--brief")?,
            worktree: path("--worktree")?,
            model: ModelName::parse(&take("--model")?)?,
            effort: wire("effort", &take("--effort")?)?,
            max_turns,
            session_id: VendorSessionId::parse(&take("--session-id")?)?,
            to: wire("control session", &take("--to")?)?,
            branch: wire("branch", &take("--branch")?)?,
            base: wire("base commit", &take("--base")?)?,
        })
    }
}

const WORKER_FLAGS: [&str; 11] = [
    "--vendor",
    "--binary",
    "--brief",
    "--worktree",
    "--model",
    "--effort",
    "--max-turns",
    "--session-id",
    "--to",
    "--branch",
    "--base",
];

fn flag_map(words: &[String]) -> Result<std::collections::BTreeMap<String, String>, WorkerError> {
    let mut flags = std::collections::BTreeMap::new();
    let mut pairs = words.chunks(2);
    for pair in pairs.by_ref().take(WORKER_FLAGS.len()) {
        let [flag, value] = pair else {
            return Err(WorkerError::Argument("a flag without a value".to_string()));
        };
        if !WORKER_FLAGS.contains(&flag.as_str()) {
            return Err(WorkerError::Argument(format!("unknown flag {flag:?}")));
        }
        if flags.insert(flag.clone(), value.clone()).is_some() {
            return Err(WorkerError::Argument(format!("{flag} given twice")));
        }
    }
    if pairs.next().is_some() {
        return Err(WorkerError::Argument("too many arguments".to_string()));
    }
    Ok(flags)
}

fn parse_turns(text: &str) -> Result<NonZeroU16, WorkerError> {
    text.parse::<NonZeroU16>()
        .ok()
        .filter(|turns| turns.get() <= WORKER_TURNS_MAX)
        .ok_or_else(|| WorkerError::Argument(format!("--max-turns {text:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const OTHER: &str = "1123456789abcdef0123456789abcdef01234567";

    pub fn args() -> WorkerArgs {
        WorkerArgs {
            vendor: Vendor::Claude,
            binary: PathBuf::from("/opt/claude/2.1.295/claude"),
            brief: PathBuf::from("/agent/worktrees/briefs/cf7a.wu03.wrk.claude.a1f3.md"),
            worktree: PathBuf::from("/agent/worktrees/cf7a/wu03/a1"),
            model: ModelName::parse("haiku").unwrap(),
            effort: Effort::Low,
            max_turns: NonZeroU16::new(6),
            session_id: VendorSessionId::parse("3f0c6c1e-6b1a-4a51-9a0e-2a8c5d0c1a10").unwrap(),
            to: SessionName::parse("cf7a.wu03.ctl.claude").unwrap(),
            branch: BranchName::parse("wu03/a1").unwrap(),
            base: CommitSha::parse(SHA).unwrap(),
        }
    }

    #[test]
    fn worker_arguments_have_exact_text_and_round_trip() {
        let argv = args().to_argv(Path::new("/opt/tycho/bin/tycho"));
        assert_eq!(
            argv.join(" "),
            "/opt/tycho/bin/tycho worker --vendor claude --binary /opt/claude/2.1.295/claude \
             --brief /agent/worktrees/briefs/cf7a.wu03.wrk.claude.a1f3.md \
             --worktree /agent/worktrees/cf7a/wu03/a1 --model haiku --effort low \
             --session-id 3f0c6c1e-6b1a-4a51-9a0e-2a8c5d0c1a10 --to cf7a.wu03.ctl.claude \
             --branch wu03/a1 --base 0123456789abcdef0123456789abcdef01234567 --max-turns 6"
        );
        assert_eq!(WorkerArgs::parse(&argv[2..]).unwrap(), args());
    }

    #[test]
    fn worker_arguments_refuse_what_they_do_not_know() {
        let argv = args().to_argv(Path::new("/t"));
        let words = |edit: &dyn Fn(&mut Vec<String>)| {
            let mut words = argv[2..].to_vec();
            edit(&mut words);
            WorkerArgs::parse(&words)
        };
        assert!(words(&|w| w.truncate(w.len() - 1)).is_err());
        assert!(words(&|w| w.extend(["--model".into(), "opus".into()])).is_err());
        assert!(words(&|w| w.extend(["--resume".into(), "x".into()])).is_err());
        assert!(words(&|w| w.drain(0..2).for_each(drop)).is_err());
        assert!(words(&|w| *w.last_mut().unwrap() = "0".into()).is_err());
        assert!(words(&|w| *w.last_mut().unwrap() = "501".into()).is_err());
        assert!(words(&|w| w[5] = "relative/brief.md".into()).is_err());
        assert!(words(&|w| w[5] = "/a/../brief.md".into()).is_err());
        let mut no_cap = argv[2..argv.len() - 2].to_vec();
        assert_eq!(WorkerArgs::parse(&no_cap).unwrap().max_turns, None);
        no_cap.push("--max-turns".into());
        assert!(WorkerArgs::parse(&no_cap).is_err());
    }

    #[test]
    fn session_ids_are_lowercase_uuids() {
        let id = VendorSessionId::from_hex("0123456789abcdef0123456789abcdef4444").unwrap();
        assert_eq!(id.as_str(), "01234567-89ab-4def-8123-456789abcdef");
        for bad in [
            "",
            "3F0C6C1E-6B1A-4A51-9A0E-2A8C5D0C1A10",
            "3f0c6c1e6b1a4a519a0e2a8c5d0c1a10",
            "3f0c6c1e-6b1a-4a51-9a0e-2a8c5d0c1a1",
            "3f0c6c1e-6b1a-4a51-9a0e-2a8c5d0c1a1g",
        ] {
            assert!(VendorSessionId::parse(bad).is_err(), "{bad}");
        }
        assert!(VendorSessionId::from_hex("abc").is_err());
    }

    #[test]
    fn model_names_are_bounded_words() {
        assert!(ModelName::parse("claude-opus-4-7[1m]").is_ok());
        assert!(ModelName::parse("gpt-5-codex-mini").is_ok());
        for bad in [
            "",
            "-p",
            "a b",
            "a;b",
            &"m".repeat(MODEL_NAME_MAX_BYTES + 1),
        ] {
            assert!(ModelName::parse(bad).is_err(), "{bad}");
        }
    }

    fn stream(end: Option<VendorEnd>) -> Stream {
        Stream {
            end,
            ..Stream::default()
        }
    }

    #[test]
    fn every_end_and_exit_has_a_state_word() {
        let ok = ChildEnd::Exited(0);
        let failed = ChildEnd::Exited(1);
        let cases = [
            (stream(Some(VendorEnd::Completed)), ok, "completed"),
            (stream(Some(VendorEnd::Completed)), failed, "failed"),
            (stream(Some(VendorEnd::Failed)), failed, "failed"),
            (stream(Some(VendorEnd::TurnCap)), failed, "too_large"),
            (
                stream(Some(VendorEnd::BudgetCap)),
                failed,
                "budget_exceeded",
            ),
            (stream(Some(VendorEnd::RateLimited)), failed, "rate_limited"),
            (
                stream(Some(VendorEnd::LoginRequired)),
                failed,
                WORD_LOGIN_REQUIRED,
            ),
            (
                stream(Some(VendorEnd::Unrecognised("error_new".into()))),
                failed,
                "vendor_result_error_new",
            ),
            (stream(None), ChildEnd::Signalled(9), "killed"),
            (stream(None), ok, WORD_NO_RESULT),
            (stream(None), failed, "failed"),
            (stream(None), ChildEnd::NotStarted, "failed"),
            (stream(None), ChildEnd::Unknown, RAW_EXIT_STATUS_UNKNOWN),
        ];
        for (stream, end, word) in cases {
            assert_eq!(state_word(&stream, end), word, "{stream:?} {end:?}");
        }
        let refused = Stream {
            refusal: Some(Refusal::BareMode),
            ..stream(Some(VendorEnd::Completed))
        };
        assert_eq!(state_word(&refused, ok), WORD_BARE_MODE);
        let mismatch = Stream {
            refusal: Some(Refusal::VersionMismatch("2.2.0".into())),
            ..stream(None)
        };
        assert_eq!(state_word(&mismatch, ok), WORD_VERSION_MISMATCH);
    }

    #[test]
    fn inbox_words_stay_unrecognised_and_keep_their_text() {
        use tycho_types::exit::{Disposition, ExitState};
        for word in [
            WORD_BARE_MODE,
            WORD_VERSION_MISMATCH,
            WORD_LOGIN_REQUIRED,
            WORD_NO_RESULT,
        ] {
            let state = ExitState::from_wire(word);
            assert_eq!(state.disposition(), Disposition::Inbox, "{word}");
            assert_eq!(
                String::from(state),
                format!("unrecognised:{}:{word}", word.len())
            );
        }
        let long = format!("{WORD_RESULT_PREFIX}{}", vendor_word(&"x".repeat(200)));
        assert!(matches!(
            ExitState::from_wire(&long),
            ExitState::Unrecognised { raw: Some(_), .. }
        ));
    }

    #[test]
    fn done_needs_a_moved_branch() {
        let base = CommitSha::parse(SHA).unwrap();
        let head = CommitSha::parse(OTHER).unwrap();
        assert_eq!(outcome(&base, &head, None), Outcome::Done);
        assert_eq!(outcome(&base, &head, Some(Outcome::Done)), Outcome::Done);
        assert_eq!(
            outcome(&base, &head, Some(Outcome::NotDone)),
            Outcome::NotDone
        );
        assert_eq!(outcome(&base, &base, None), Outcome::NotDone);
    }
}

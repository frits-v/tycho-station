//! Operator precondition checks for running the factory on this machine (docs/slices.md,
//! "Operator prerequisites"). `run` never creates anything; a human with sudo or an
//! account login does that. It only reports what it finds, and a probe that cannot run
//! is `Unreachable`, never guessed as `Missing` or `Present`.
//!
//! Each check belongs to one side. Run as the developer, the command checks the
//! developer side and defers the agent side; run as `tycho-agent`, the reverse. The
//! machine is prepared when both runs exit 0.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tycho_types::session::{SESSION_NAME_MAX_BYTES, SOCKET_PATH_MAX_BYTES};

use crate::tool_prefix;

pub const AGENT_USER_NAME: &str = "tycho-agent";
pub const AGENT_GROUP_NAME: &str = "tycho-agent";
/// `staff`, the default primary group, whose members can traverse a 0750 home.
const STAFF_GID: u32 = 20;
pub const SHARED_GROUP_NAME: &str = "tycho-zmx";
pub const AGENT_SOCKET_DIR: &str = "/Users/Shared/tycho-agent-zmx";
const CORE_SOCKET_DIR_RELATIVE: &str = ".tycho/zmx";
pub const AGENT_SOCKET_DIR_MODE: u32 = 0o2770;
pub const CORE_SOCKET_DIR_MODE: u32 = 0o0700;
/// What a socket path leaves for the directory once the name and separator are in it.
const SOCKET_DIR_MAX_BYTES: usize = SOCKET_PATH_MAX_BYTES
    .saturating_sub(1)
    .saturating_sub(SESSION_NAME_MAX_BYTES);
const _: () = assert!(AGENT_SOCKET_DIR.len() <= SOCKET_DIR_MAX_BYTES);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_OUTPUT_MAX_BYTES: usize = 1 << 17;
/// `security find-*-password` exit code when no item matches.
const SECURITY_ITEM_NOT_FOUND_EXIT: i32 = 44;
/// `dsmemberutil checkmembership` exit code when the user or group does not exist.
const DSMEMBERUTIL_NOT_FOUND_EXIT: i32 = 7;
/// The core home tycho resolves when `TYCHO_HOME` is unset, under the developer's home.
const CORE_HOME_RELATIVE: &str = ".tycho";
/// The variable that moves the core home, as `tycho::config::core_home` reads it.
const CORE_HOME_ENV: &str = "TYCHO_HOME";
/// The vendor credential store under the core home.
const CREDENTIALS_DIR: &str = "credentials";
const CREDENTIAL_STORE_MODE: u32 = 0o700;
const CREDENTIAL_FILE_MODE: u32 = 0o600;
/// `git config --get-all` exit code when the key is not set.
const GIT_CONFIG_KEY_UNSET_EXIT: i32 = 1;

pub fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
}

/// Who a check can be performed as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Developer,
    Agent,
}

impl Side {
    const fn other(self) -> Self {
        match self {
            Self::Developer => Self::Agent,
            Self::Agent => Self::Developer,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Developer => "developer",
            Self::Agent => "agent",
        }
    }

    const fn run_as(self) -> &'static str {
        match self {
            Self::Developer => "the developer",
            Self::Agent => AGENT_USER_NAME,
        }
    }

    /// The agent runs the prefix's xtask, which needs neither mise nor a checkout.
    const fn setup_command(self) -> &'static str {
        match self {
            Self::Developer => "mise run setup",
            Self::Agent => "/Users/Shared/tycho/bin/xtask setup",
        }
    }
}

fn mode_for(username: &str) -> Side {
    if username == AGENT_USER_NAME {
        Side::Agent
    } else {
        Side::Developer
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    AgentGroupExists,
    AgentUserExists,
    AgentHomeDirectory,
    SharedGroupExists,
    DeveloperInSharedGroup,
    DeveloperHomeClosedToAgent,
    AgentDirExists,
    AgentDirIsDirectory,
    AgentDirOwnerUid,
    AgentDirOwnerGid,
    AgentDirMode,
    CoreDirFitsBudget,
    CoreDirExists,
    CoreDirIsDirectory,
    CoreDirOwnerUid,
    CoreDirMode,
    PinZmx,
    PinRestate,
    PinRestateServer,
    PinClaude,
    PinCodex,
    PinEntire,
    PinCue,
    EntireLogin,
    PrefixDirectory,
    PrefixTree,
    PrefixMise,
    PrefixClaude,
    PrefixCodex,
    PrefixZmx,
    PrefixStationXtask,
    PrefixStationTycho,
    AgentInSharedGroup,
    AgentPrimaryGroup,
    CredentialSsh,
    CredentialGh,
    CredentialAws,
    CredentialNetrc,
    CredentialGitconfig,
    KeychainGithub,
    KeychainGitlab,
    KeychainAws,
    KeychainSsh,
    KeychainGhCli,
    ClaudeCredential,
    CodexCredential,
    AgentCredentialStoreClosed,
    AgentPrefixWritable,
    AgentPrefixMise,
    AgentPrefixClaude,
    AgentPrefixCodex,
    AgentPrefixZmx,
}

#[derive(Debug)]
struct CheckSpec {
    check: Check,
    name: &'static str,
    side: Side,
}

const fn spec(check: Check, name: &'static str, side: Side) -> CheckSpec {
    CheckSpec { check, name, side }
}

/// Every check, in print order; each one runs on exactly one side.
const CATALOGUE: [CheckSpec; 52] = [
    spec(
        Check::AgentGroupExists,
        "agent group exists",
        Side::Developer,
    ),
    spec(Check::AgentUserExists, "agent user exists", Side::Developer),
    spec(
        Check::AgentHomeDirectory,
        "agent home directory",
        Side::Developer,
    ),
    spec(
        Check::SharedGroupExists,
        "shared group exists",
        Side::Developer,
    ),
    spec(
        Check::DeveloperInSharedGroup,
        "developer is a member of the shared group",
        Side::Developer,
    ),
    spec(
        Check::DeveloperHomeClosedToAgent,
        "agent user cannot search the developer's home",
        Side::Developer,
    ),
    spec(
        Check::AgentDirExists,
        "agent socket directory: exists",
        Side::Developer,
    ),
    spec(
        Check::AgentDirIsDirectory,
        "agent socket directory: is a directory",
        Side::Developer,
    ),
    spec(
        Check::AgentDirOwnerUid,
        "agent socket directory: owner uid",
        Side::Developer,
    ),
    spec(
        Check::AgentDirOwnerGid,
        "agent socket directory: owner gid",
        Side::Developer,
    ),
    spec(
        Check::AgentDirMode,
        "agent socket directory: mode",
        Side::Developer,
    ),
    spec(
        Check::CoreDirFitsBudget,
        "core socket directory: path fits the socket budget",
        Side::Developer,
    ),
    spec(
        Check::CoreDirExists,
        "core socket directory: exists",
        Side::Developer,
    ),
    spec(
        Check::CoreDirIsDirectory,
        "core socket directory: is a directory",
        Side::Developer,
    ),
    spec(
        Check::CoreDirOwnerUid,
        "core socket directory: owner uid",
        Side::Developer,
    ),
    spec(
        Check::CoreDirMode,
        "core socket directory: mode",
        Side::Developer,
    ),
    spec(
        Check::PinZmx,
        "zmx resolves through mise at the pinned version",
        Side::Developer,
    ),
    spec(
        Check::PinRestate,
        "restate resolves through mise at the pinned version",
        Side::Developer,
    ),
    spec(
        Check::PinRestateServer,
        "restate-server resolves through mise at the pinned version",
        Side::Developer,
    ),
    spec(
        Check::PinClaude,
        "claude resolves through mise at the pinned version",
        Side::Developer,
    ),
    spec(
        Check::PinCodex,
        "codex resolves through mise at the pinned version",
        Side::Developer,
    ),
    spec(
        Check::PinEntire,
        "entire resolves through mise at the pinned version",
        Side::Developer,
    ),
    spec(
        Check::PinCue,
        "cue resolves through mise at the pinned version",
        Side::Developer,
    ),
    spec(
        Check::EntireLogin,
        "entire logged in as the developer",
        Side::Developer,
    ),
    spec(
        Check::ClaudeCredential,
        "vendor credential: claude token in the core's store, the developer's, mode 0600",
        Side::Developer,
    ),
    spec(
        Check::CodexCredential,
        "vendor credential: codex auth.json in the core's store, the developer's, mode 0600",
        Side::Developer,
    ),
    spec(
        Check::PrefixDirectory,
        "tool prefix: a real directory the developer owns, mode 0755",
        Side::Developer,
    ),
    spec(
        Check::PrefixTree,
        "tool prefix: every entry the developer's, closed to group and other writes, links inside",
        Side::Developer,
    ),
    spec(
        Check::PrefixMise,
        "tool prefix: mise is the pinned version",
        Side::Developer,
    ),
    spec(
        Check::PrefixClaude,
        "tool prefix: claude is the pinned install, run by path, at its recorded digest",
        Side::Developer,
    ),
    spec(
        Check::PrefixCodex,
        "tool prefix: codex is the pinned install, run by path, at its recorded digest",
        Side::Developer,
    ),
    spec(
        Check::PrefixZmx,
        "tool prefix: zmx is the pinned install, run by path, at its recorded digest",
        Side::Developer,
    ),
    spec(
        Check::PrefixStationXtask,
        "tool prefix: xtask is the recorded build of this checkout's commit",
        Side::Developer,
    ),
    spec(
        Check::PrefixStationTycho,
        "tool prefix: tycho is the recorded build of this checkout's commit",
        Side::Developer,
    ),
    spec(
        Check::AgentInSharedGroup,
        "agent user is a member of the shared group",
        Side::Agent,
    ),
    spec(
        Check::AgentPrimaryGroup,
        "agent user's primary group is tycho-agent",
        Side::Agent,
    ),
    spec(
        Check::CredentialSsh,
        "agent credential: ~/.ssh",
        Side::Agent,
    ),
    spec(
        Check::CredentialGh,
        "agent credential: ~/.config/gh",
        Side::Agent,
    ),
    spec(
        Check::CredentialAws,
        "agent credential: ~/.aws",
        Side::Agent,
    ),
    spec(
        Check::CredentialNetrc,
        "agent credential: ~/.netrc",
        Side::Agent,
    ),
    spec(
        Check::CredentialGitconfig,
        "agent credential: gitconfig credential helper",
        Side::Agent,
    ),
    spec(
        Check::KeychainGithub,
        "agent keychain: no item for github.com",
        Side::Agent,
    ),
    spec(
        Check::KeychainGitlab,
        "agent keychain: no item for gitlab.com",
        Side::Agent,
    ),
    spec(
        Check::KeychainAws,
        "agent keychain: no item for aws",
        Side::Agent,
    ),
    spec(
        Check::KeychainSsh,
        "agent keychain: no item for ssh",
        Side::Agent,
    ),
    spec(
        Check::KeychainGhCli,
        "agent keychain: no item for gh:github.com",
        Side::Agent,
    ),
    spec(
        Check::AgentCredentialStoreClosed,
        "as the agent: the core's credential store cannot be reached",
        Side::Agent,
    ),
    spec(
        Check::AgentPrefixWritable,
        "as the agent: nothing in the tool prefix is writable",
        Side::Agent,
    ),
    spec(
        Check::AgentPrefixMise,
        "as the agent: mise in the tool prefix is the pinned version",
        Side::Agent,
    ),
    spec(
        Check::AgentPrefixClaude,
        "as the agent: claude runs by path at its pin and recorded digest",
        Side::Agent,
    ),
    spec(
        Check::AgentPrefixCodex,
        "as the agent: codex runs by path at its pin and recorded digest",
        Side::Agent,
    ),
    spec(
        Check::AgentPrefixZmx,
        "as the agent: zmx runs by path at its pin and recorded digest",
        Side::Agent,
    ),
];

pub fn check_name(check: Check) -> &'static str {
    CATALOGUE
        .iter()
        .find(|entry| entry.check == check)
        .map_or("check missing from the catalogue", |entry| entry.name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Present,
    Missing,
    Wrong { found: String, wanted: String },
    Unreachable { why: String },
    Deferred { to: Side },
}

impl Status {
    pub const fn is_pass(&self) -> bool {
        matches!(self, Self::Present)
    }

    const fn is_deferred(&self) -> bool {
        matches!(self, Self::Deferred { .. })
    }
}

impl fmt::Display for Status {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Present => write!(formatter, "present"),
            Self::Missing => write!(formatter, "missing"),
            Self::Wrong { found, wanted } => {
                write!(formatter, "wrong (found {found}, wanted {wanted})")
            }
            Self::Unreachable { why } => write!(formatter, "unreachable ({why})"),
            Self::Deferred { to } => write!(formatter, "deferred to the {} run", to.label()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub check: Check,
    pub status: Status,
    pub hint: Option<String>,
}

impl Finding {
    pub const fn new(check: Check, status: Status) -> Self {
        Self {
            check,
            status,
            hint: None,
        }
    }

    pub fn with_hint(check: Check, status: Status, hint: impl Into<String>) -> Self {
        Self {
            check,
            status,
            hint: Some(hint.into()),
        }
    }

    pub fn unreachable(check: Check, why: impl Into<String>) -> Self {
        Self::new(check, Status::Unreachable { why: why.into() })
    }
}

/// What running an external probe produced; every decoder reads this, never the raw `Output`.
#[derive(Debug)]
pub enum Capture {
    Ran {
        success: bool,
        /// `None` when a signal ended the process.
        code: Option<i32>,
        stdout: String,
        stderr: String,
    },
    ExecutableNotFound,
    Unreachable(String),
}

pub fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or_default().trim()
}

pub fn plain_command(program: &str, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    command
}

/// Disables auto-install and the network, so a pinned-but-absent tool reports `Missing`.
fn mise_command(args: &[&str]) -> Command {
    let mut command = Command::new("mise");
    command
        .args(args)
        .current_dir(workspace_root())
        .env("MISE_EXEC_AUTO_INSTALL", "false")
        .env("MISE_NOT_FOUND_AUTO_INSTALL", "false")
        .env("MISE_OFFLINE", "1");
    command
}

/// Reads up to `PROBE_OUTPUT_MAX_BYTES`; the second element is true on overflow.
fn read_capped(mut reader: impl Read) -> (Vec<u8>, bool) {
    let mut buffer = Vec::new();
    let cap = u64::try_from(PROBE_OUTPUT_MAX_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut limited = (&mut reader).take(cap);
    drop(limited.read_to_end(&mut buffer));
    let overflow = buffer.len() > PROBE_OUTPUT_MAX_BYTES;
    (buffer, overflow)
}

fn spawn_reader(pipe: Option<impl Read + Send + 'static>) -> mpsc::Receiver<(Vec<u8>, bool)> {
    let (sender, receiver) = mpsc::channel();
    match pipe {
        Some(pipe) => {
            thread::spawn(move || drop(sender.send(read_capped(pipe))));
        }
        None => drop(sender.send((Vec::new(), false))),
    }
    receiver
}

fn recv_by<T>(receiver: &mpsc::Receiver<T>, deadline: Instant) -> Option<T> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    receiver.recv_timeout(remaining).ok()
}

fn run_bounded(command: Command) -> Capture {
    run_bounded_within(command, PROBE_TIMEOUT)
}

/// Runs `command` bounded: stdout/stderr read on separate threads, timeout kills by pid.
pub fn run_bounded_within(mut command: Command, timeout: Duration) -> Capture {
    let program = command.get_program().to_string_lossy().into_owned();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Capture::ExecutableNotFound
        }
        Err(error) => return Capture::Unreachable(format!("failed to start {program}: {error}")),
    };
    let pid = child.id();
    let stdout_receiver = spawn_reader(child.stdout.take());
    let stderr_receiver = spawn_reader(child.stderr.take());
    let (wait_sender, wait_receiver) = mpsc::channel();
    thread::spawn(move || drop(wait_sender.send(child.wait())));

    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let stdout = recv_by(&stdout_receiver, deadline);
    let stderr = recv_by(&stderr_receiver, deadline);
    let status = recv_by(&wait_receiver, deadline);
    let (
        Some((stdout_bytes, stdout_overflow)),
        Some((stderr_bytes, stderr_overflow)),
        Some(status),
    ) = (stdout, stderr, status)
    else {
        drop(Command::new("kill").args(["-9", &pid.to_string()]).status());
        return Capture::Unreachable(format!("{program} did not finish within {timeout:?}"));
    };
    if stdout_overflow || stderr_overflow {
        return Capture::Unreachable(format!(
            "{program} output exceeded {PROBE_OUTPUT_MAX_BYTES} bytes"
        ));
    }
    match status {
        Ok(status) => Capture::Ran {
            success: status.success(),
            code: status.code(),
            stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
            stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        },
        Err(error) => Capture::Unreachable(format!("{program} wait failed: {error}")),
    }
}

pub fn decode_zmx_version(stdout: &str) -> Option<String> {
    let mut tokens = stdout.lines().next().unwrap_or_default().split_whitespace();
    if tokens.next()? != "zmx" {
        return None;
    }
    tokens.next().map(str::to_string)
}

fn decode_restate_cli_version(stdout: &str) -> Option<String> {
    let mut tokens = stdout.lines().next().unwrap_or_default().split_whitespace();
    if tokens.next()? != "restate-cli" {
        return None;
    }
    tokens.next().map(str::to_string)
}

fn decode_restate_server_version(stdout: &str) -> Option<String> {
    let mut tokens = stdout.lines().next().unwrap_or_default().split_whitespace();
    if tokens.next()? != "restate-server" {
        return None;
    }
    tokens.next().map(str::to_string)
}

fn decode_cue_version(stdout: &str) -> Option<String> {
    let mut tokens = stdout.lines().next().unwrap_or_default().split_whitespace();
    if tokens.next()? != "cue" || tokens.next()? != "version" {
        return None;
    }
    tokens.next()?.strip_prefix('v').map(str::to_string)
}

fn decode_entire_version(stdout: &str) -> Option<String> {
    let mut tokens = stdout.lines().next().unwrap_or_default().split_whitespace();
    if tokens.next()? != "Entire" || tokens.next()? != "CLI" {
        return None;
    }
    tokens.next().map(str::to_string)
}

pub fn decode_claude_version(stdout: &str) -> Option<String> {
    let mut tokens = stdout.lines().next().unwrap_or_default().split_whitespace();
    let version = tokens.next()?;
    if tokens.next()? != "(Claude" || tokens.next()? != "Code)" {
        return None;
    }
    Some(version.to_string())
}

pub fn decode_codex_version(stdout: &str) -> Option<String> {
    let mut tokens = stdout.lines().next().unwrap_or_default().split_whitespace();
    if tokens.next()? != "codex-cli" {
        return None;
    }
    tokens.next().map(str::to_string)
}

fn classify_version(found: Option<String>, tool: &str, raw: &str, wanted: &str) -> Status {
    let Some(found) = found else {
        return Status::Unreachable {
            why: format!("unrecognised {tool} version output: {raw:?}"),
        };
    };
    if found == wanted {
        Status::Present
    } else {
        Status::Wrong {
            found,
            wanted: wanted.to_string(),
        }
    }
}

/// `mise exec`'s failure text: the tool has no installed version, or something else failed.
#[derive(Debug, PartialEq, Eq)]
enum MiseFailure {
    ToolNotInstalled,
    Other(String),
}

fn decode_mise_exec_failure(stderr: &str) -> MiseFailure {
    let first = stderr.lines().next().unwrap_or_default();
    if first.contains("couldn't exec process") && first.contains("No such file or directory") {
        MiseFailure::ToolNotInstalled
    } else {
        MiseFailure::Other(first.to_string())
    }
}

/// A defence against drift once `mise_pin` has already confirmed the tool is installed.
fn mise_pinned_version(
    tool: &str,
    version_args: &[&str],
    decode: fn(&str) -> Option<String>,
    wanted: &str,
) -> Status {
    let mut args = vec!["exec", "--", tool];
    args.extend_from_slice(version_args);
    match run_bounded(mise_command(&args)) {
        Capture::ExecutableNotFound => Status::Unreachable {
            why: "mise is not on PATH".to_string(),
        },
        Capture::Unreachable(why) => Status::Unreachable { why },
        Capture::Ran {
            success: false,
            stderr,
            ..
        } => match decode_mise_exec_failure(&stderr) {
            MiseFailure::ToolNotInstalled => Status::Missing,
            MiseFailure::Other(why) => Status::Unreachable { why },
        },
        Capture::Ran {
            success: true,
            stdout,
            ..
        } => classify_version(decode(&stdout), tool, &stdout, wanted),
    }
}

/// Whether a tool is pinned and installed, from one `mise ls --current --json` per run.
#[derive(Debug, PartialEq, Eq)]
enum MisePin {
    Installed(String),
    NotInstalled(String),
    NotPinned,
}

fn decode_mise_pin(ls_json: &str, tool: &str) -> Option<MisePin> {
    let value: serde_json::Value = serde_json::from_str(ls_json).ok()?;
    let Some(raw) = value.get(tool) else {
        return Some(MisePin::NotPinned);
    };
    let entries = raw.as_array()?;
    let active = entries
        .iter()
        .find(|entry| entry.get("active").and_then(serde_json::Value::as_bool) == Some(true));
    let entry = active.or_else(|| entries.first())?;
    let version = entry.get("version")?.as_str()?.to_string();
    let installed = entry.get("installed")?.as_bool()?;
    Some(if installed {
        MisePin::Installed(version)
    } else {
        MisePin::NotInstalled(version)
    })
}

#[derive(Debug)]
enum MiseLs {
    Json(String),
    Unreachable(String),
}

fn mise_ls() -> MiseLs {
    match run_bounded(mise_command(&["ls", "--current", "--json"])) {
        Capture::ExecutableNotFound => MiseLs::Unreachable("mise is not on PATH".to_string()),
        Capture::Unreachable(why) => MiseLs::Unreachable(why),
        Capture::Ran {
            success: false,
            stderr,
            ..
        } => MiseLs::Unreachable(
            stderr
                .lines()
                .next()
                .unwrap_or("mise ls failed")
                .to_string(),
        ),
        Capture::Ran {
            success: true,
            stdout,
            ..
        } => MiseLs::Json(stdout),
    }
}

fn mise_pin(ls: &MiseLs, tool: &str) -> Result<MisePin, String> {
    match ls {
        MiseLs::Unreachable(why) => Err(why.clone()),
        MiseLs::Json(text) => decode_mise_pin(text, tool)
            .ok_or_else(|| format!("unrecognised mise ls output for {tool}")),
    }
}

fn mise_pinned_finding(
    check: Check,
    tool: &str,
    ls: &MiseLs,
    version_args: &[&str],
    decode: fn(&str) -> Option<String>,
) -> Finding {
    match mise_pin(ls, tool) {
        Err(why) => Finding::unreachable(check, why),
        Ok(MisePin::NotPinned) => Finding::with_hint(
            check,
            Status::Missing,
            format!("not pinned; pin it in mise.toml as `{tool}`"),
        ),
        Ok(MisePin::NotInstalled(version)) => Finding::with_hint(
            check,
            Status::Missing,
            format!("pinned at {version} but not installed; run: mise install"),
        ),
        Ok(MisePin::Installed(version)) => Finding::new(
            check,
            mise_pinned_version(tool, version_args, decode, &version),
        ),
    }
}

fn vendor_findings(ls: &MiseLs) -> Vec<Finding> {
    vec![
        mise_pinned_finding(Check::PinZmx, "zmx", ls, &["--version"], decode_zmx_version),
        mise_pinned_finding(
            Check::PinRestate,
            "restate",
            ls,
            &["--version"],
            decode_restate_cli_version,
        ),
        mise_pinned_finding(
            Check::PinRestateServer,
            "restate-server",
            ls,
            &["--version"],
            decode_restate_server_version,
        ),
        mise_pinned_finding(
            Check::PinClaude,
            "claude",
            ls,
            &["--version"],
            decode_claude_version,
        ),
        mise_pinned_finding(
            Check::PinCodex,
            "codex",
            ls,
            &["--version"],
            decode_codex_version,
        ),
        mise_pinned_finding(
            Check::PinEntire,
            "entire",
            ls,
            &["--version"],
            decode_entire_version,
        ),
        mise_pinned_finding(Check::PinCue, "cue", ls, &["version"], decode_cue_version),
    ]
}

/// A login probe runs the tool, so it runs only once `mise ls` reports it installed.
fn installed_gate(check: Check, tool: &str, ls: &MiseLs) -> Option<Finding> {
    match mise_pin(ls, tool) {
        Ok(MisePin::Installed(_)) => None,
        Err(why) => Some(Finding::unreachable(check, why)),
        Ok(MisePin::NotPinned) => Some(Finding::unreachable(
            check,
            format!("{tool} is not pinned in mise.toml, so its login cannot be checked"),
        )),
        Ok(MisePin::NotInstalled(version)) => Some(Finding::unreachable(
            check,
            format!("{tool} {version} is pinned but not installed; run: mise install"),
        )),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AuthStatus {
    LoggedIn,
    LoggedOut,
    Unrecognised,
}

fn json_bool(text: &str, field: &str) -> Option<bool> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value.get(field)?.as_bool()
}

/// `entire auth status --json` exits 0 logged in or out; a non-zero exit is a failure to look.
fn decode_entire_auth_status(code: Option<i32>, stdout: &str, _stderr: &str) -> AuthStatus {
    match (code, json_bool(stdout, "logged_in")) {
        (Some(0), Some(true)) => AuthStatus::LoggedIn,
        (Some(0), Some(false)) => AuthStatus::LoggedOut,
        _ => AuthStatus::Unrecognised,
    }
}

struct LoginProbe {
    check: Check,
    tool: &'static str,
    args: &'static [&'static str],
    decode: fn(Option<i32>, &str, &str) -> AuthStatus,
    login_hint: &'static str,
}

const ENTIRE_LOGIN: LoginProbe = LoginProbe {
    check: Check::EntireLogin,
    tool: "entire",
    args: &["auth", "status", "--json"],
    decode: decode_entire_auth_status,
    login_hint: "log in once from a terminal: entire auth login",
};

/// A tool may answer on stdout or stderr, so both first lines are shown.
fn unrecognised_login(probe: &LoginProbe, code: Option<i32>, stdout: &str, stderr: &str) -> String {
    format!(
        "unrecognised {} {} result (exit {code:?}): stdout {:?}, stderr {:?}",
        probe.tool,
        probe.args.join(" "),
        first_line(stdout),
        first_line(stderr)
    )
}

fn login_finding(probe: &LoginProbe, ls: &MiseLs) -> Finding {
    if let Some(gated) = installed_gate(probe.check, probe.tool, ls) {
        return gated;
    }
    let mut args = vec!["exec", "--", probe.tool];
    args.extend_from_slice(probe.args);
    match run_bounded(mise_command(&args)) {
        Capture::ExecutableNotFound => Finding::unreachable(probe.check, "mise is not on PATH"),
        capture => decoded_login(probe, capture),
    }
}

fn decoded_login(probe: &LoginProbe, capture: Capture) -> Finding {
    match capture {
        Capture::ExecutableNotFound => {
            Finding::unreachable(probe.check, format!("{} is not installed", probe.tool))
        }
        Capture::Unreachable(why) => Finding::unreachable(probe.check, why),
        Capture::Ran {
            code,
            stdout,
            stderr,
            ..
        } => match (probe.decode)(code, &stdout, &stderr) {
            AuthStatus::LoggedIn => Finding::new(probe.check, Status::Present),
            AuthStatus::LoggedOut => {
                Finding::with_hint(probe.check, Status::Missing, probe.login_hint)
            }
            AuthStatus::Unrecognised => Finding::unreachable(
                probe.check,
                unrecognised_login(probe, code, &stdout, &stderr),
            ),
        },
    }
}

/// Services whose keychain items would be a git host, cloud or SSH credential.
const FORBIDDEN_KEYCHAIN_SERVICES: [(Check, &str); 5] = [
    (Check::KeychainGithub, "github.com"),
    (Check::KeychainGitlab, "gitlab.com"),
    (Check::KeychainAws, "aws"),
    (Check::KeychainSsh, "ssh"),
    (Check::KeychainGhCli, "gh:github.com"),
];
const KEYCHAIN_LOOKUPS: [&str; 2] = ["find-generic-password", "find-internet-password"];

#[derive(Debug, PartialEq, Eq)]
enum KeychainItem {
    Absent,
    /// The keychain file the item was found in.
    Present(String),
    Unrecognised,
}

/// Without `-w` or `-g`, `security` prints attributes only and never the secret.
fn decode_keychain_item(code: Option<i32>, stdout: &str, stderr: &str) -> KeychainItem {
    match code {
        Some(SECURITY_ITEM_NOT_FOUND_EXIT) if stderr.contains("could not be found") => {
            KeychainItem::Absent
        }
        Some(0) => first_line(stdout)
            .strip_prefix("keychain: \"")
            .and_then(|rest| rest.strip_suffix('"'))
            .map_or(KeychainItem::Unrecognised, |path| {
                KeychainItem::Present(path.to_string())
            }),
        _ => KeychainItem::Unrecognised,
    }
}

fn keychain_lookup_status(lookup: &str, service: &str) -> Status {
    match run_bounded(plain_command("security", &[lookup, "-s", service])) {
        Capture::ExecutableNotFound => Status::Unreachable {
            why: "security is not on PATH".to_string(),
        },
        Capture::Unreachable(why) => Status::Unreachable { why },
        Capture::Ran {
            code,
            stdout,
            stderr,
            ..
        } => match decode_keychain_item(code, &stdout, &stderr) {
            KeychainItem::Absent => Status::Present,
            KeychainItem::Present(keychain) => Status::Wrong {
                found: format!("a {lookup} item in {keychain}"),
                wanted: format!("no item for {service}"),
            },
            KeychainItem::Unrecognised => Status::Unreachable {
                why: format!(
                    "unrecognised security {lookup} result (exit {code:?}): {:?}",
                    first_line(&stderr)
                ),
            },
        },
    }
}

fn keychain_findings() -> Vec<Finding> {
    FORBIDDEN_KEYCHAIN_SERVICES
        .iter()
        .map(|&(check, service)| {
            let status = KEYCHAIN_LOOKUPS
                .iter()
                .map(|lookup| keychain_lookup_status(lookup, service))
                .find(|status| !status.is_pass())
                .unwrap_or(Status::Present);
            Finding::new(check, status)
        })
        .collect()
}

/// From `id -u`/`id -un`, never `$HOME`/`$USER`, so this is whoever is actually running.
#[derive(Debug, Clone)]
pub struct Identity {
    pub uid: u32,
    pub username: String,
}

fn decode_id_output(stdout: &str) -> Option<String> {
    let first = stdout.lines().next()?.trim();
    if first.is_empty() {
        None
    } else {
        Some(first.to_string())
    }
}

fn id_output(args: &[&str]) -> Result<String, String> {
    match run_bounded(plain_command("id", args)) {
        Capture::ExecutableNotFound => Err("id is not on PATH".to_string()),
        Capture::Unreachable(why) => Err(why),
        Capture::Ran {
            success: false,
            stderr,
            ..
        } => Err(stderr.lines().next().unwrap_or("id failed").to_string()),
        Capture::Ran {
            success: true,
            stdout,
            ..
        } => decode_id_output(&stdout).ok_or_else(|| format!("unrecognised id output: {stdout:?}")),
    }
}

pub fn current_identity() -> Result<Identity, String> {
    let uid_text = id_output(&["-u"])?;
    let uid: u32 = uid_text
        .parse()
        .map_err(|_| format!("unrecognised id -u output: {uid_text:?}"))?;
    let username = id_output(&["-un"])?;
    Ok(Identity { uid, username })
}

#[derive(Debug)]
enum DsclLookup {
    Found(String),
    NotFound,
    Unreachable(String),
}

/// `dscl`'s failure text: the record does not exist, or something else went wrong.
#[derive(Debug, PartialEq, Eq)]
enum DsclFailure {
    RecordNotFound,
    Other(String),
}

fn decode_dscl_failure(stderr: &str) -> DsclFailure {
    if stderr.contains("eDSRecordNotFound") {
        DsclFailure::RecordNotFound
    } else {
        DsclFailure::Other(stderr.lines().next().unwrap_or("dscl failed").to_string())
    }
}

fn dscl_read(path: &str, key: Option<&str>) -> DsclLookup {
    dscl_read_keys(path, key.as_slice())
}

fn dscl_read_keys(path: &str, keys: &[&str]) -> DsclLookup {
    let mut args = vec![".", "-read", path];
    args.extend_from_slice(keys);
    match run_bounded(plain_command("dscl", &args)) {
        Capture::ExecutableNotFound => DsclLookup::Unreachable("dscl is not on PATH".to_string()),
        Capture::Unreachable(why) => DsclLookup::Unreachable(why),
        Capture::Ran {
            success: true,
            stdout,
            ..
        } => DsclLookup::Found(stdout),
        Capture::Ran {
            success: false,
            stderr,
            ..
        } => match decode_dscl_failure(&stderr) {
            DsclFailure::RecordNotFound => DsclLookup::NotFound,
            DsclFailure::Other(why) => DsclLookup::Unreachable(why),
        },
    }
}

/// A line that looks like a different `Key:` record, where a continuation value stops.
fn looks_like_new_attribute(line: &str) -> bool {
    if line.starts_with(' ') || line.starts_with('\t') {
        return false;
    }
    line.contains(": ") || line.ends_with(':')
}

/// Reads one `dscl -read` attribute: usually `Key: value`, sometimes a bare `Key:` header with the value spread over the lines that follow.
fn dscl_value(stdout: &str, key: &str) -> Option<String> {
    let inline_prefix = format!("{key}: ");
    let header = format!("{key}:");
    let mut lines = stdout.lines();
    while let Some(line) = lines.next() {
        if let Some(value) = line.strip_prefix(inline_prefix.as_str()) {
            return Some(value.trim().to_string());
        }
        if line == header {
            let mut collected = Vec::new();
            for continuation in lines.by_ref() {
                if looks_like_new_attribute(continuation) {
                    break;
                }
                collected.push(continuation.strip_prefix(' ').unwrap_or(continuation));
            }
            return Some(collected.join("\n").trim().to_string());
        }
    }
    None
}

fn lookup_status(lookup: &DsclLookup) -> Status {
    match lookup {
        DsclLookup::Found(_) => Status::Present,
        DsclLookup::NotFound => Status::Missing,
        DsclLookup::Unreachable(why) => Status::Unreachable { why: why.clone() },
    }
}

fn group_gid(lookup: &DsclLookup) -> Result<u32, String> {
    match lookup {
        DsclLookup::Found(stdout) => {
            let Some(value) = dscl_value(stdout, "PrimaryGroupID") else {
                return Err("PrimaryGroupID missing from the group record".to_string());
            };
            value
                .parse()
                .map_err(|_| format!("unrecognised PrimaryGroupID {value:?} in the group record"))
        }
        DsclLookup::NotFound => Err(format!("group {SHARED_GROUP_NAME} does not exist")),
        DsclLookup::Unreachable(why) => Err(why.clone()),
    }
}

pub fn resolve_home(username: &str) -> Result<String, String> {
    match dscl_read(&format!("/Users/{username}"), Some("NFSHomeDirectory")) {
        DsclLookup::Found(stdout) => dscl_value(&stdout, "NFSHomeDirectory")
            .ok_or_else(|| "NFSHomeDirectory missing from the user record".to_string()),
        DsclLookup::NotFound => Err(format!("user {username} does not exist")),
        DsclLookup::Unreachable(why) => Err(why),
    }
}

/// `dsmemberutil`'s own membership check, rather than parsing `dscl`'s member list by hand.
#[derive(Debug, PartialEq, Eq)]
enum MembershipOutcome {
    Member,
    NotMember,
    GroupNotFound,
    UserNotFound,
    Unrecognised,
}

fn decode_membership(code: Option<i32>, stdout: &str) -> MembershipOutcome {
    match (code, first_line(stdout)) {
        (Some(0), "user is a member of the group") => MembershipOutcome::Member,
        (Some(0), "user is not a member of the group") => MembershipOutcome::NotMember,
        (Some(DSMEMBERUTIL_NOT_FOUND_EXIT), "Group not found") => MembershipOutcome::GroupNotFound,
        (Some(DSMEMBERUTIL_NOT_FOUND_EXIT), "User not found") => MembershipOutcome::UserNotFound,
        _ => MembershipOutcome::Unrecognised,
    }
}

fn membership_status(user: &str, group: &str) -> Status {
    match run_bounded(plain_command(
        "dsmemberutil",
        &["checkmembership", "-U", user, "-G", group],
    )) {
        Capture::ExecutableNotFound => Status::Unreachable {
            why: "dsmemberutil is not on PATH".to_string(),
        },
        Capture::Unreachable(why) => Status::Unreachable { why },
        Capture::Ran { code, stdout, .. } => match decode_membership(code, &stdout) {
            MembershipOutcome::Member => Status::Present,
            MembershipOutcome::NotMember
            | MembershipOutcome::GroupNotFound
            | MembershipOutcome::UserNotFound => Status::Missing,
            MembershipOutcome::Unrecognised => Status::Unreachable {
                why: format!("unrecognised dsmemberutil result (exit {code:?}): {stdout:?}"),
            },
        },
    }
}

/// The entry in the developer's home ACL that keeps the agent out, as `chmod +a` takes it.
/// The agent's own primary group does not: macOS makes every local account a member of
/// `staff` through `localaccounts`, and a home is commonly `staff` at 0750.
pub const HOME_DENY_ENTRY: &str = "user:tycho-agent deny search,list,readattr,readextattr";
const HOME_DENY_PRINCIPAL: &str = "user:tycho-agent";
/// The most entries macOS keeps in one ACL (`KAUTH_ACL_MAX_ENTRIES`).
const ACL_ENTRIES_MAX: usize = 128;
const HOME_CLOSED_HINT: &str = "as the developer: chmod +a \"user:tycho-agent deny search,list,readattr,readextattr\" ~ (mise run provision-agent runs it)";

/// One ACL entry as `ls -le` prints it: `<n>: <principal> [inherited] <allow|deny> <perms>`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AclEntry {
    principal: String,
    allows: bool,
    permissions: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum AclListing {
    Entries(Vec<AclEntry>),
    Unrecognised(String),
}

fn decode_acl_entry(line: &str) -> Option<AclEntry> {
    let (index, rest) = line.trim_start().split_once(": ")?;
    if index.is_empty() || !index.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    let mut tokens = rest.split_whitespace();
    let principal = tokens.next().filter(|principal| principal.contains(':'))?;
    let mut kind = tokens.next()?;
    if kind == "inherited" {
        kind = tokens.next()?;
    }
    let allows = match kind {
        "allow" => true,
        "deny" => false,
        _ => return None,
    };
    let permissions = tokens.next()?.split(',').map(str::to_string).collect();
    if tokens.next().is_some() {
        return None;
    }
    Some(AclEntry {
        principal: principal.to_string(),
        allows,
        permissions,
    })
}

/// `ls -lde <dir>` prints the directory's long line, then one line per ACL entry.
fn decode_acl_listing(stdout: &str) -> AclListing {
    let mut lines = stdout.lines();
    let Some(head) = lines.next() else {
        return AclListing::Unrecognised("no output".to_string());
    };
    if !head.starts_with('d') {
        return AclListing::Unrecognised(head.to_string());
    }
    let mut entries = Vec::new();
    for line in lines {
        if entries.len() >= ACL_ENTRIES_MAX {
            return AclListing::Unrecognised(format!("more than {ACL_ENTRIES_MAX} ACL entries"));
        }
        match decode_acl_entry(line) {
            Some(entry) => entries.push(entry),
            None => return AclListing::Unrecognised(line.to_string()),
        }
    }
    AclListing::Entries(entries)
}

/// Whether the agent belongs to the group a home is owned by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentInGroup {
    Member,
    NotMember,
    NoAgent,
}

/// The ACL is read in order and its first entry about search decides; only then do the mode
/// bits count. An allow entry for anyone but the developer is taken as reaching the agent. An
/// `only_inherit` entry applies to what is created inside the home, not to the home itself.
fn home_search_status(
    entries: &[AclEntry],
    mode: u32,
    developer: &str,
    agent: AgentInGroup,
) -> Status {
    let developer_principal = format!("user:{developer}");
    for entry in entries {
        let names = |wanted: &str| {
            entry
                .permissions
                .iter()
                .any(|permission| permission == wanted)
        };
        if !names("search") || names("only_inherit") {
            continue;
        }
        if !entry.allows && entry.principal == HOME_DENY_PRINCIPAL {
            return Status::Present;
        }
        if entry.allows && entry.principal != developer_principal {
            return Status::Wrong {
                found: format!("an ACL entry allowing search to {} first", entry.principal),
                wanted: format!("{HOME_DENY_PRINCIPAL} denied search first"),
            };
        }
    }
    let wanted = format!("{HOME_DENY_PRINCIPAL} denied search");
    match agent {
        AgentInGroup::NoAgent => Status::Missing,
        _ if mode & 0o001 != 0 => Status::Wrong {
            found: format!("mode {mode:04o}, which lets every user search it"),
            wanted,
        },
        AgentInGroup::Member if mode & 0o010 != 0 => Status::Wrong {
            found: format!("mode {mode:04o}, and {AGENT_USER_NAME} is in the home's group"),
            wanted,
        },
        AgentInGroup::Member | AgentInGroup::NotMember => Status::Present,
    }
}

/// The home's ACL listing; `Err` when `ls` could not run or failed.
fn home_acl(home: &str) -> Result<AclListing, String> {
    let mut command = plain_command("/bin/ls", &["-lde", home]);
    command.env_remove("CLICOLOR").env_remove("CLICOLOR_FORCE");
    match run_bounded(command) {
        Capture::ExecutableNotFound => Err("/bin/ls is not present".to_string()),
        Capture::Unreachable(why) => Err(why),
        Capture::Ran {
            success: false,
            stderr,
            ..
        } => Err(format!("ls -lde {home}: {}", first_line(&stderr))),
        Capture::Ran {
            success: true,
            stdout,
            ..
        } => Ok(decode_acl_listing(&stdout)),
    }
}

/// `dsmemberutil` answers "not a member" for a user's own primary group, so that is compared
/// first from the user record.
fn agent_in_group(gid: u32) -> Result<AgentInGroup, String> {
    let record = dscl_read(&format!("/Users/{AGENT_USER_NAME}"), Some("PrimaryGroupID"));
    match primary_gid(&record, "agent user") {
        Ok(primary) if primary == gid => return Ok(AgentInGroup::Member),
        Ok(_) => {}
        Err(Status::Missing) => return Ok(AgentInGroup::NoAgent),
        Err(status) => return Err(status.to_string()),
    }
    let gid_text = gid.to_string();
    match run_bounded(plain_command(
        "dsmemberutil",
        &["checkmembership", "-U", AGENT_USER_NAME, "-g", &gid_text],
    )) {
        Capture::ExecutableNotFound => Err("dsmemberutil is not on PATH".to_string()),
        Capture::Unreachable(why) => Err(why),
        Capture::Ran { code, stdout, .. } => match decode_membership(code, &stdout) {
            MembershipOutcome::Member => Ok(AgentInGroup::Member),
            MembershipOutcome::NotMember | MembershipOutcome::GroupNotFound => {
                Ok(AgentInGroup::NotMember)
            }
            MembershipOutcome::UserNotFound => Ok(AgentInGroup::NoAgent),
            MembershipOutcome::Unrecognised => Err(format!(
                "unrecognised dsmemberutil result (exit {code:?}): {stdout:?}"
            )),
        },
    }
}

fn home_closed_status(username: &str) -> Status {
    let unreachable = |why: String| Status::Unreachable { why };
    let home = match resolve_home(username) {
        Ok(home) => home,
        Err(why) => return unreachable(why),
    };
    let metadata = match fs::symlink_metadata(&home) {
        Ok(metadata) if metadata.is_dir() => metadata,
        Ok(metadata) => return unreachable(format!("{home} is a {}", file_kind(&metadata))),
        Err(error) => return unreachable(format!("{home}: {error}")),
    };
    let entries = match home_acl(&home) {
        Ok(AclListing::Entries(entries)) => entries,
        Ok(AclListing::Unrecognised(line)) => {
            return unreachable(format!("unrecognised ls -lde line: {line:?}"))
        }
        Err(why) => return unreachable(why),
    };
    match agent_in_group(metadata.gid()) {
        Ok(agent) => home_search_status(
            &entries,
            metadata.permissions().mode() & 0o7777,
            username,
            agent,
        ),
        Err(why) => unreachable(why),
    }
}

fn home_closed_finding(identity: &Identity) -> Finding {
    let status = home_closed_status(&identity.username);
    if status.is_pass() {
        Finding::new(Check::DeveloperHomeClosedToAgent, status)
    } else {
        Finding::with_hint(Check::DeveloperHomeClosedToAgent, status, HOME_CLOSED_HINT)
    }
}

const AGENT_GROUP_HINT: &str = "create the group, then make it the agent's primary group: sudo dseditgroup -o create -r \"Tycho Agent\" tycho-agent; sudo dscl . -create /Users/tycho-agent PrimaryGroupID <gid of tycho-agent>";

fn primary_gid(lookup: &DsclLookup, record: &str) -> Result<u32, Status> {
    match lookup {
        DsclLookup::Found(stdout) => {
            let Some(value) = dscl_value(stdout, "PrimaryGroupID") else {
                return Err(Status::Unreachable {
                    why: format!("PrimaryGroupID missing from the {record} record"),
                });
            };
            value.parse().map_err(|_| Status::Unreachable {
                why: format!("unrecognised PrimaryGroupID {value:?} in the {record} record"),
            })
        }
        DsclLookup::NotFound => Err(Status::Missing),
        DsclLookup::Unreachable(why) => Err(Status::Unreachable { why: why.clone() }),
    }
}

/// Present only when the user record's gid is the `tycho-agent` group's and is not `staff`.
fn primary_group_status(user: &DsclLookup, group: &DsclLookup) -> Status {
    let user_gid = match primary_gid(user, "agent user") {
        Ok(gid) => gid,
        Err(status) => return status,
    };
    if user_gid == STAFF_GID {
        return Status::Wrong {
            found: format!("gid {STAFF_GID} (staff)"),
            wanted: format!("the gid of group {AGENT_GROUP_NAME}"),
        };
    }
    let group_gid = match primary_gid(group, AGENT_GROUP_NAME) {
        Ok(gid) => gid,
        Err(status) => return status,
    };
    if user_gid == group_gid {
        Status::Present
    } else {
        Status::Wrong {
            found: format!("gid {user_gid}"),
            wanted: format!("gid {group_gid} ({AGENT_GROUP_NAME})"),
        }
    }
}

fn primary_group_finding(username: &str) -> Finding {
    let user = dscl_read(&format!("/Users/{username}"), Some("PrimaryGroupID"));
    let group = dscl_read(
        &format!("/Groups/{AGENT_GROUP_NAME}"),
        Some("PrimaryGroupID"),
    );
    let status = primary_group_status(&user, &group);
    if status.is_pass() {
        Finding::new(Check::AgentPrimaryGroup, status)
    } else {
        Finding::with_hint(Check::AgentPrimaryGroup, status, AGENT_GROUP_HINT)
    }
}

/// The home `sysadminctl -addUser -home` records for the agent. The record alone creates no
/// directory; macOS makes one at a first login through the login window.
pub const AGENT_HOME: &str = "/Users/tycho-agent";
/// Nobody but the agent searches or lists its home.
pub const AGENT_HOME_MODE: u32 = 0o700;
const AGENT_HOME_KEYS: [&str; 3] = ["NFSHomeDirectory", "UniqueID", "PrimaryGroupID"];
const AGENT_HOME_CREATE_HINT: &str = "sudo /usr/sbin/createhomedir -c -u tycho-agent, then sudo /bin/chmod 0700 /Users/tycho-agent if its mode is wider (mise run provision-agent runs both)";

/// The facts in the agent's user record that its home is measured against.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AgentRecord {
    home: String,
    uid: u32,
    gid: u32,
}

/// One attribute of the home that differs from the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Differs {
    pub found: u32,
    pub wanted: u32,
}

/// Each attribute of the home that differs from the record; `None` matches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HomeMismatch {
    /// What sits at the path when it is not a directory.
    pub kind: Option<&'static str>,
    pub owner: Option<Differs>,
    pub group: Option<Differs>,
    pub mode: Option<Differs>,
    /// The first ACL entry that allows anything, as `chmod -a` takes it.
    pub acl_allow: Option<String>,
}

impl HomeMismatch {
    /// Only the mode differs, and it grants a bit beyond the agent's own.
    pub fn is_only_a_wider_mode(&self) -> bool {
        self.kind.is_none()
            && self.owner.is_none()
            && self.group.is_none()
            && self.acl_allow.is_none()
            && self
                .mode
                .is_some_and(|mode| mode.found & !AGENT_HOME_MODE != 0)
    }
}

/// What the agent home probe found; an unrecognised record is never taken as usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentHomeState {
    Ok,
    Missing,
    Wrong(HomeMismatch),
    Unreachable(String),
    Unrecognised(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentHome {
    /// The record's `NFSHomeDirectory`, once the record is read and recognised.
    pub path: Option<String>,
    pub state: AgentHomeState,
}

impl AgentHome {
    /// The record names `AGENT_HOME`, or is not read yet, so it is the one the user step
    /// creates there: the only path the home steps act on.
    pub fn is_at_agent_home(&self) -> bool {
        self.path.as_deref().is_none_or(|path| path == AGENT_HOME)
    }
}

fn record_number(stdout: &str, key: &str) -> Result<u32, AgentHomeState> {
    let value = dscl_value(stdout, key)
        .ok_or_else(|| AgentHomeState::Unrecognised(format!("agent user record without {key}")))?;
    value.parse().map_err(|_| {
        AgentHomeState::Unrecognised(format!("{key} {value:?} in the agent user record"))
    })
}

/// A record that does not exist has no home either, so it reads missing.
fn decode_agent_record(lookup: &DsclLookup) -> Result<AgentRecord, AgentHomeState> {
    let stdout = match lookup {
        DsclLookup::Found(stdout) => stdout,
        DsclLookup::NotFound => return Err(AgentHomeState::Missing),
        DsclLookup::Unreachable(why) => return Err(AgentHomeState::Unreachable(why.clone())),
    };
    let home = dscl_value(stdout, "NFSHomeDirectory").ok_or_else(|| {
        AgentHomeState::Unrecognised("agent user record without NFSHomeDirectory".to_string())
    })?;
    if !home.starts_with('/') || home.contains('\n') {
        return Err(AgentHomeState::Unrecognised(format!(
            "NFSHomeDirectory {home:?} in the agent user record"
        )));
    }
    Ok(AgentRecord {
        uid: record_number(stdout, "UniqueID")?,
        gid: record_number(stdout, "PrimaryGroupID")?,
        home,
    })
}

fn differs(found: u32, wanted: u32) -> Option<Differs> {
    (found != wanted).then_some(Differs { found, wanted })
}

/// A deny entry, such as the `group:everyone deny delete` a created home carries, only takes
/// access away; an allow entry grants what the 0700 mode withholds.
fn first_allow(entries: &[AclEntry]) -> Option<String> {
    entries
        .iter()
        .find(|entry| entry.allows)
        .map(|entry| format!("{} allow {}", entry.principal, entry.permissions.join(",")))
}

/// The ACL of a home that is a directory, as `ls -lde` lists it without opening the directory.
fn home_acl_allow(listing: Result<AclListing, String>) -> Result<Option<String>, AgentHomeState> {
    match listing {
        Ok(AclListing::Entries(entries)) => Ok(first_allow(&entries)),
        Ok(AclListing::Unrecognised(line)) => Err(AgentHomeState::Unrecognised(format!(
            "ls -lde line {line:?} for the agent home"
        ))),
        Err(why) => Err(AgentHomeState::Unreachable(why)),
    }
}

/// Reads the entry without following a link rather than opening it: the developer cannot open
/// another user's 0700 directory, so an open would fail on the home in its wanted state.
/// `read_acl` is `home_acl` outside tests; `ls -e` and ACLs are macOS's own.
fn measure_agent_home(
    record: &AgentRecord,
    read_acl: impl Fn(&str) -> Result<AclListing, String>,
) -> AgentHomeState {
    let metadata = match fs::symlink_metadata(&record.home) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return AgentHomeState::Missing,
        Err(error) => return AgentHomeState::Unreachable(format!("{}: {error}", record.home)),
    };
    let acl_allow = if metadata.is_dir() {
        match home_acl_allow(read_acl(&record.home)) {
            Ok(allow) => allow,
            Err(state) => return state,
        }
    } else {
        None
    };
    let mismatch = HomeMismatch {
        kind: (!metadata.is_dir()).then(|| file_kind(&metadata)),
        owner: differs(metadata.uid(), record.uid),
        group: differs(metadata.gid(), record.gid),
        mode: differs(metadata.permissions().mode() & 0o7777, AGENT_HOME_MODE),
        acl_allow,
    };
    if mismatch == HomeMismatch::default() {
        AgentHomeState::Ok
    } else {
        AgentHomeState::Wrong(mismatch)
    }
}

pub fn agent_home() -> AgentHome {
    let lookup = dscl_read_keys(&format!("/Users/{AGENT_USER_NAME}"), &AGENT_HOME_KEYS);
    match decode_agent_record(&lookup) {
        Ok(record) => AgentHome {
            state: measure_agent_home(&record, home_acl),
            path: Some(record.home),
        },
        Err(state) => AgentHome { path: None, state },
    }
}

fn mismatch_status(mismatch: &HomeMismatch) -> Status {
    let mut found = Vec::new();
    let mut wanted = Vec::new();
    if let Some(kind) = mismatch.kind {
        found.push(format!("a {kind}"));
        wanted.push("a directory".to_string());
    }
    if let Some(owner) = mismatch.owner {
        found.push(format!("owner uid {}", owner.found));
        wanted.push(format!("owner uid {} ({AGENT_USER_NAME})", owner.wanted));
    }
    if let Some(group) = mismatch.group {
        found.push(format!("group gid {}", group.found));
        wanted.push(format!("group gid {}", group.wanted));
    }
    if let Some(mode) = mismatch.mode {
        found.push(format!("mode {:04o}", mode.found));
        wanted.push(format!("mode {:04o}", mode.wanted));
    }
    if let Some(entry) = &mismatch.acl_allow {
        found.push(format!("ACL entry {entry}"));
        wanted.push("no ACL allow entry".to_string());
    }
    Status::Wrong {
        found: found.join(", "),
        wanted: wanted.join(", "),
    }
}

const NARROWS_NOTE: &str = "mise run provision-agent narrows it";

/// A home that is not the agent's own is left to the operator: root does not change its owner
/// by path. A group, mode or ACL entry on the agent's own home the agent can set itself.
/// The note that the task narrows the mode appears only where `provision-agent` would.
fn mismatch_hint(mismatch: &HomeMismatch, home: &AgentHome) -> String {
    let path = home.path.as_deref().unwrap_or(AGENT_HOME);
    if mismatch.kind.is_some() || mismatch.owner.is_some() {
        return format!("{path} is not a directory the agent owns; inspect it and move it aside by hand, then run mise run provision-agent again");
    }
    let mut steps = Vec::new();
    if let Some(group) = mismatch.group {
        steps.push(format!(
            "sudo -u {AGENT_USER_NAME} /usr/bin/chgrp {} {path}",
            group.wanted
        ));
    }
    if let Some(entry) = &mismatch.acl_allow {
        steps.push(format!(
            "sudo -u {AGENT_USER_NAME} /bin/chmod -a \"{entry}\" {path}"
        ));
    }
    if mismatch.mode.is_some() {
        let chmod = format!("sudo -u {AGENT_USER_NAME} /bin/chmod {AGENT_HOME_MODE:04o} {path}");
        if home.is_at_agent_home() && mismatch.is_only_a_wider_mode() {
            steps.push(format!("{chmod} ({NARROWS_NOTE})"));
        } else {
            steps.push(chmod);
        }
    }
    steps.join("; ")
}

/// The home steps act only on `AGENT_HOME`; a record naming another path is the operator's.
fn missing_home_hint(home: &AgentHome) -> String {
    match home.path.as_deref() {
        Some(path) if !home.is_at_agent_home() => format!(
            "the agent user record names {path}, not {AGENT_HOME}, and the task creates only {AGENT_HOME}; point NFSHomeDirectory at {AGENT_HOME} (sudo dscl . -create /Users/{AGENT_USER_NAME} NFSHomeDirectory {AGENT_HOME}) and run mise run provision-agent again"
        ),
        _ => AGENT_HOME_CREATE_HINT.to_string(),
    }
}

pub fn agent_home_finding(home: &AgentHome) -> Finding {
    let check = Check::AgentHomeDirectory;
    match &home.state {
        AgentHomeState::Ok => Finding::new(check, Status::Present),
        AgentHomeState::Missing => {
            Finding::with_hint(check, Status::Missing, missing_home_hint(home))
        }
        AgentHomeState::Wrong(mismatch) => Finding::with_hint(
            check,
            mismatch_status(mismatch),
            mismatch_hint(mismatch, home),
        ),
        AgentHomeState::Unreachable(why) => Finding::unreachable(check, why.clone()),
        AgentHomeState::Unrecognised(what) => {
            Finding::unreachable(check, format!("unrecognised {what}"))
        }
    }
}

fn credential_absence_finding(
    check: Check,
    home: &Result<String, String>,
    relative: &str,
) -> Finding {
    let home = match home {
        Ok(home) => home,
        Err(why) => return Finding::unreachable(check, format!("agent home unknown: {why}")),
    };
    let path = Path::new(home).join(relative);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Finding::new(check, Status::Present)
        }
        Err(error) => Finding::unreachable(check, format!("{}: {error}", path.display())),
        Ok(_) => Finding::new(
            check,
            Status::Wrong {
                found: format!("{} exists", path.display()),
                wanted: "absent".to_string(),
            },
        ),
    }
}

/// An empty value clears every helper set before it, Apple's `osxkeychain` included.
const CLEAR_CREDENTIAL_HELPERS_HINT: &str =
    "as the agent, clear every credential helper: git config --global credential.helper \"\"";

#[derive(Debug, PartialEq, Eq)]
enum CredentialHelpers {
    Unset,
    /// Each helper with the scope it came from, comma-separated.
    Configured(String),
    Unrecognised,
}

/// `git config --show-scope --get-all` exits 1 with no output when no file sets the key, and otherwise prints `<scope>\t<value>` per value in the order git applies them; an empty value clears the helpers before it.
fn decode_credential_helpers(code: Option<i32>, stdout: &str, stderr: &str) -> CredentialHelpers {
    let lines: Vec<&str> = stdout.lines().filter(|line| !line.is_empty()).collect();
    match code {
        Some(GIT_CONFIG_KEY_UNSET_EXIT) if lines.is_empty() && stderr.trim().is_empty() => {
            CredentialHelpers::Unset
        }
        Some(0) if !lines.is_empty() => {
            let mut helpers = Vec::new();
            for line in lines {
                match line.split_once('\t') {
                    Some((scope, helper)) if !scope.is_empty() => {
                        if helper.trim().is_empty() {
                            helpers.clear();
                        } else {
                            helpers.push(format!("{} (scope {scope})", helper.trim()));
                        }
                    }
                    _ => return CredentialHelpers::Unrecognised,
                }
            }
            if helpers.is_empty() {
                CredentialHelpers::Unset
            } else {
                CredentialHelpers::Configured(helpers.join(", "))
            }
        }
        _ => CredentialHelpers::Unrecognised,
    }
}

/// Runs from `/` with only `PATH` and the given `HOME`, so no repository config or inherited `GIT_*` variable changes what git reads.
fn scope_to_home(command: &mut Command, home: &str) {
    command.current_dir("/").env_clear().env("HOME", home);
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
}

/// Every file git reads for the agent: the home files, the system file, includes, and the gitconfig that ships with Apple's git, which `--system` does not read.
fn credential_helper_command(home: &str) -> Command {
    let mut command = plain_command(
        "git",
        &["config", "--show-scope", "--get-all", "credential.helper"],
    );
    scope_to_home(&mut command, home);
    command
}

fn credential_gitconfig_finding(home: &Result<String, String>) -> Finding {
    let check = Check::CredentialGitconfig;
    let home = match home {
        Ok(home) => home,
        Err(why) => return Finding::unreachable(check, format!("agent home unknown: {why}")),
    };
    let status = match run_bounded(credential_helper_command(home)) {
        Capture::ExecutableNotFound => Status::Unreachable {
            why: "git is not on PATH".to_string(),
        },
        Capture::Unreachable(why) => Status::Unreachable { why },
        Capture::Ran {
            code,
            stdout,
            stderr,
            ..
        } => match decode_credential_helpers(code, &stdout, &stderr) {
            CredentialHelpers::Unset => Status::Present,
            CredentialHelpers::Configured(helpers) => {
                return Finding::with_hint(
                    check,
                    Status::Wrong {
                        found: format!("credential helper {helpers}"),
                        wanted: "no credential helper".to_string(),
                    },
                    CLEAR_CREDENTIAL_HELPERS_HINT,
                )
            }
            CredentialHelpers::Unrecognised => Status::Unreachable {
                why: format!(
                    "unrecognised git config result (exit {code:?}): {:?} {:?}",
                    first_line(&stdout),
                    first_line(&stderr)
                ),
            },
        },
    };
    Finding::new(check, status)
}

fn credential_findings(home: &Result<String, String>) -> Vec<Finding> {
    vec![
        credential_absence_finding(Check::CredentialSsh, home, ".ssh"),
        credential_absence_finding(Check::CredentialGh, home, ".config/gh"),
        credential_absence_finding(Check::CredentialAws, home, ".aws"),
        credential_absence_finding(Check::CredentialNetrc, home, ".netrc"),
        credential_gitconfig_finding(home),
    ]
}

fn owner_status(found: u32, wanted: Result<u32, String>) -> Status {
    match wanted {
        Ok(wanted) if found == wanted => Status::Present,
        Ok(wanted) => Status::Wrong {
            found: found.to_string(),
            wanted: wanted.to_string(),
        },
        Err(why) => Status::Unreachable { why },
    }
}

fn owner_uid_status(found: u32, candidates: &[u32]) -> Status {
    if candidates.contains(&found) {
        return Status::Present;
    }
    Status::Wrong {
        found: found.to_string(),
        wanted: candidates
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(" or "),
    }
}

fn mode_status(found: u32, wanted: u32) -> Status {
    if found == wanted {
        Status::Present
    } else {
        Status::Wrong {
            found: format!("{found:04o}"),
            wanted: format!("{wanted:04o}"),
        }
    }
}

fn file_kind(metadata: &fs::Metadata) -> &'static str {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_file() {
        "file"
    } else {
        "other"
    }
}

fn directory_kind_status(metadata: &fs::Metadata) -> Status {
    if metadata.is_dir() {
        return Status::Present;
    }
    Status::Wrong {
        found: file_kind(metadata).to_string(),
        wanted: "directory".to_string(),
    }
}

/// For the core directory only; `AGENT_SOCKET_DIR` is checked at compile time instead.
fn path_length_status(path: &str) -> Status {
    let length = path.len();
    if length <= SOCKET_DIR_MAX_BYTES {
        Status::Present
    } else {
        Status::Wrong {
            found: format!("{length} bytes"),
            wanted: format!("<= {SOCKET_DIR_MAX_BYTES} bytes"),
        }
    }
}

/// The checks that follow `exists` for one socket directory, in catalogue order.
const AGENT_DIR_DEPENDENT: [Check; 4] = [
    Check::AgentDirIsDirectory,
    Check::AgentDirOwnerUid,
    Check::AgentDirOwnerGid,
    Check::AgentDirMode,
];
const CORE_DIR_DEPENDENT: [Check; 3] = [
    Check::CoreDirIsDirectory,
    Check::CoreDirOwnerUid,
    Check::CoreDirMode,
];

fn directory_error_findings(exists: Check, dependent: &[Check], error: &io::Error) -> Vec<Finding> {
    let (exists_status, why) = if error.kind() == io::ErrorKind::NotFound {
        (Status::Missing, "directory does not exist".to_string())
    } else {
        (
            Status::Unreachable {
                why: error.to_string(),
            },
            error.to_string(),
        )
    };
    let mut findings = vec![Finding::new(exists, exists_status)];
    findings.extend(
        dependent
            .iter()
            .map(|&check| Finding::unreachable(check, why.clone())),
    );
    findings
}

fn agent_socket_dir_findings(group_gid: Result<u32, String>, developer_uid: u32) -> Vec<Finding> {
    let metadata = match fs::symlink_metadata(AGENT_SOCKET_DIR) {
        Ok(metadata) => metadata,
        Err(error) => {
            return directory_error_findings(Check::AgentDirExists, &AGENT_DIR_DEPENDENT, &error)
        }
    };
    vec![
        Finding::new(Check::AgentDirExists, Status::Present),
        Finding::new(Check::AgentDirIsDirectory, directory_kind_status(&metadata)),
        Finding::new(
            Check::AgentDirOwnerUid,
            owner_uid_status(metadata.uid(), &[developer_uid, 0]),
        ),
        Finding::new(
            Check::AgentDirOwnerGid,
            owner_status(metadata.gid(), group_gid),
        ),
        Finding::new(
            Check::AgentDirMode,
            mode_status(
                metadata.permissions().mode() & 0o7777,
                AGENT_SOCKET_DIR_MODE,
            ),
        ),
    ]
}

pub fn core_socket_dir_path(home: &str) -> String {
    format!("{home}/{CORE_SOCKET_DIR_RELATIVE}")
}

fn stat_core_socket_dir(path: &str, developer_uid: u32) -> Vec<Finding> {
    let mut findings = vec![Finding::new(
        Check::CoreDirFitsBudget,
        path_length_status(path),
    )];
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            findings.extend(directory_error_findings(
                Check::CoreDirExists,
                &CORE_DIR_DEPENDENT,
                &error,
            ));
            return findings;
        }
    };
    findings.push(Finding::new(Check::CoreDirExists, Status::Present));
    findings.push(Finding::new(
        Check::CoreDirIsDirectory,
        directory_kind_status(&metadata),
    ));
    findings.push(Finding::new(
        Check::CoreDirOwnerUid,
        owner_status(metadata.uid(), Ok(developer_uid)),
    ));
    findings.push(Finding::new(
        Check::CoreDirMode,
        mode_status(metadata.permissions().mode() & 0o7777, CORE_SOCKET_DIR_MODE),
    ));
    findings
}

fn core_socket_findings(identity: &Identity) -> Vec<Finding> {
    match resolve_home(&identity.username) {
        Ok(home) => stat_core_socket_dir(&core_socket_dir_path(&home), identity.uid),
        Err(why) => [Check::CoreDirFitsBudget, Check::CoreDirExists]
            .iter()
            .chain(CORE_DIR_DEPENDENT.iter())
            .map(|&check| Finding::unreachable(check, why.clone()))
            .collect(),
    }
}

/// Runs only checks the developer can perform: nothing here reads the agent's home or keychain.
pub fn developer_findings(identity: &Identity) -> Vec<Finding> {
    let mut findings = record_findings(identity);
    let ls = mise_ls();
    findings.extend(vendor_findings(&ls));
    findings.push(login_finding(&ENTIRE_LOGIN, &ls));
    findings.extend(stored_credential_findings(identity));
    findings
        .extend(tool_prefix::Probe::read(&tool_prefix::Prefix::production(), identity).findings());
    findings
}

/// A vendor's stored credential as setup reports it: the check, the file name in the store,
/// and how the operator stores it.
struct StoredCredential {
    check: Check,
    vendor: &'static str,
    hint: &'static str,
}

const STORED_CREDENTIALS: [StoredCredential; 2] = [
    StoredCredential {
        check: Check::ClaudeCredential,
        vendor: "claude",
        hint: "as the subscription's owner run claude setup-token, then /Users/Shared/tycho/bin/tycho credentials set claude and paste the token (docs/process.md, Vendor credentials)",
    },
    StoredCredential {
        check: Check::CodexCredential,
        vendor: "codex",
        hint: "as the plan's owner run codex login, then /Users/Shared/tycho/bin/tycho credentials set codex < ~/.codex/auth.json (docs/process.md, Vendor credentials)",
    },
];

/// The core home the way `tycho` resolves it: `TYCHO_HOME` when it names a directory strictly
/// inside the user's home with no link on the way, else `.tycho` under the user's home.
fn core_home(user_home: &Path, moved: Option<&std::ffi::OsStr>) -> Result<PathBuf, String> {
    let Some(moved) = moved else {
        return Ok(user_home.join(CORE_HOME_RELATIVE));
    };
    let home = PathBuf::from(moved);
    let inside = home.is_absolute()
        && home != user_home
        && home.starts_with(user_home)
        && home.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        });
    if !inside {
        return Err(format!(
            "{CORE_HOME_ENV}={} is not a directory inside {}",
            home.display(),
            user_home.display()
        ));
    }
    let mut walked = user_home.to_path_buf();
    for component in home.strip_prefix(user_home).unwrap_or(&home).components() {
        walked.push(component);
        if fs::symlink_metadata(&walked).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(format!("{} is a symbolic link", walked.display()));
        }
    }
    Ok(home)
}

fn stored_credential_findings(identity: &Identity) -> Vec<Finding> {
    let moved = std::env::var_os(CORE_HOME_ENV);
    let store = resolve_home(&identity.username)
        .and_then(|home| core_home(Path::new(&home), moved.as_deref()))
        .map(|home| home.join(CREDENTIALS_DIR));
    STORED_CREDENTIALS
        .iter()
        .map(|stored| {
            let status = store.as_ref().map_or_else(
                |why| Status::Unreachable { why: why.clone() },
                |store| stored_credential_status(store, stored.vendor, identity.uid),
            );
            if status.is_pass() {
                Finding::new(stored.check, status)
            } else {
                Finding::with_hint(stored.check, status, stored.hint)
            }
        })
        .collect()
}

/// An entry of the store as lstat sees it: never through a link, contents never read.
fn store_entry_status(path: &Path, directory: bool, uid: u32, mode: u32) -> Status {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Status::Missing,
        Err(error) => {
            return Status::Unreachable {
                why: format!("{}: {error}", path.display()),
            }
        }
    };
    let kind_ok = if directory {
        metadata.file_type().is_dir()
    } else {
        metadata.file_type().is_file()
    };
    if !kind_ok {
        return Status::Wrong {
            found: format!("{} at {}", file_kind(&metadata), path.display()),
            wanted: if directory {
                "directory"
            } else {
                "regular file"
            }
            .to_string(),
        };
    }
    if metadata.uid() != uid {
        return Status::Wrong {
            found: format!("{} owned by uid {}", path.display(), metadata.uid()),
            wanted: format!("uid {uid}"),
        };
    }
    match mode_status(metadata.permissions().mode() & 0o7777, mode) {
        Status::Wrong { found, wanted } => Status::Wrong {
            found: format!("{} at mode {found}", path.display()),
            wanted,
        },
        other => other,
    }
}

/// The store is a 0700 directory of the developer and the vendor's file a 0600 regular file
/// of the developer: nothing in the group or other bits, no link.
fn stored_credential_status(store: &Path, vendor: &str, developer_uid: u32) -> Status {
    match store_entry_status(store, true, developer_uid, CREDENTIAL_STORE_MODE) {
        Status::Present => store_entry_status(
            &store.join(vendor),
            false,
            developer_uid,
            CREDENTIAL_FILE_MODE,
        ),
        other => other,
    }
}

/// Where the agent looks for the core's store: the default core home of the user who owns the
/// tool prefix, the developer, read from the password database rather than any environment.
/// The agent cannot see a core home the developer moved with `TYCHO_HOME`, so a moved home is
/// checked on the developer's side only.
fn developer_store() -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(tool_prefix::PREFIX_ROOT)
        .map_err(|error| format!("{}: {error}", tool_prefix::PREFIX_ROOT))?;
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(metadata.uid()))
        .map_err(|error| format!("uid {}: {error}", metadata.uid()))?
        .ok_or_else(|| {
            format!(
                "no user has uid {}, the tool prefix's owner",
                metadata.uid()
            )
        })?;
    Ok(user.dir.join(CORE_HOME_RELATIVE).join(CREDENTIALS_DIR))
}

/// Run as the agent: a denial at any step of the walk passes; reaching the store, listing it
/// or opening a vendor file is the boundary answering.
fn agent_store_status(store: &Path) -> Status {
    let denied = |error: &io::Error| error.kind() == io::ErrorKind::PermissionDenied;
    match fs::metadata(store) {
        Err(error) if denied(&error) => return Status::Present,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Status::Unreachable {
                why: format!(
                    "{} does not exist and every directory above it let the agent search, so the store's own mode is untested",
                    store.display()
                ),
            }
        }
        Err(error) => {
            return Status::Unreachable {
                why: format!("{}: {error}", store.display()),
            }
        }
        Ok(_) => {}
    }
    if fs::read_dir(store).is_ok() {
        return Status::Wrong {
            found: format!("the agent lists {}", store.display()),
            wanted: "permission denied".to_string(),
        };
    }
    for stored in &STORED_CREDENTIALS {
        let path = store.join(stored.vendor);
        match fs::File::open(&path) {
            Ok(_) => {
                return Status::Wrong {
                    found: format!("the agent opens {}", path.display()),
                    wanted: "permission denied".to_string(),
                }
            }
            Err(error) if denied(&error) => {}
            Err(error) => {
                return Status::Unreachable {
                    why: format!("{}: {error}", path.display()),
                }
            }
        }
    }
    Status::Present
}

/// The developer-side checks of directory records and socket directories, which read no
/// tool and no network.
pub fn record_findings(identity: &Identity) -> Vec<Finding> {
    record_probe(identity).0
}

/// The record findings with the agent home they were measured from, so a remedy decides on
/// the same probe the finding reports.
pub fn record_probe(identity: &Identity) -> (Vec<Finding>, AgentHome) {
    let agent_group_lookup = dscl_read(&format!("/Groups/{AGENT_GROUP_NAME}"), None);
    let agent_lookup = dscl_read(&format!("/Users/{AGENT_USER_NAME}"), Some("RecordName"));
    let group_lookup = dscl_read(&format!("/Groups/{SHARED_GROUP_NAME}"), None);
    let home = agent_home();
    let mut findings = vec![
        Finding::new(Check::AgentGroupExists, lookup_status(&agent_group_lookup)),
        Finding::new(Check::AgentUserExists, lookup_status(&agent_lookup)),
        agent_home_finding(&home),
        Finding::new(Check::SharedGroupExists, lookup_status(&group_lookup)),
        Finding::new(
            Check::DeveloperInSharedGroup,
            membership_status(&identity.username, SHARED_GROUP_NAME),
        ),
        home_closed_finding(identity),
    ];
    findings.extend(agent_socket_dir_findings(
        group_gid(&group_lookup),
        identity.uid,
    ));
    findings.extend(core_socket_findings(identity));
    (findings, home)
}

/// The agent's membership and primary group, read from directory services by name, which the
/// developer can do as well as the agent.
pub fn agent_record_findings() -> Vec<Finding> {
    vec![
        Finding::new(
            Check::AgentInSharedGroup,
            membership_status(AGENT_USER_NAME, SHARED_GROUP_NAME),
        ),
        primary_group_finding(AGENT_USER_NAME),
    ]
}

/// A group's gid; `Ok(None)` when the group does not exist.
pub fn group_id(group: &str) -> Result<Option<u32>, String> {
    let lookup = dscl_read(&format!("/Groups/{group}"), Some("PrimaryGroupID"));
    match primary_gid(&lookup, group) {
        Ok(gid) => Ok(Some(gid)),
        Err(Status::Missing) => Ok(None),
        Err(status) => Err(status.to_string()),
    }
}

/// Runs only checks the agent can perform on itself: nothing here resolves the developer's home, the core directory or the developer's logins.
fn agent_findings(identity: &Identity) -> Vec<Finding> {
    let home = resolve_home(&identity.username);
    let mut findings = vec![Finding::new(
        Check::AgentInSharedGroup,
        membership_status(&identity.username, SHARED_GROUP_NAME),
    )];
    findings.push(primary_group_finding(&identity.username));
    findings.extend(credential_findings(&home));
    findings.extend(keychain_findings());
    let prefix = tool_prefix::agent_findings(identity);
    findings.push(Finding::new(
        Check::AgentCredentialStoreClosed,
        developer_store().map_or_else(
            |why| Status::Unreachable { why },
            |store| agent_store_status(&store),
        ),
    ));
    findings.extend(prefix);
    findings
}

/// One finding per catalogue entry: the produced result, `Deferred` for the other side, `Unreachable` for a gap.
pub fn assemble(mode: Side, produced: &[Finding]) -> Vec<Finding> {
    let mut findings: Vec<Finding> = CATALOGUE
        .iter()
        .map(|entry| {
            if entry.side != mode {
                return Finding::new(entry.check, Status::Deferred { to: entry.side });
            }
            produced
                .iter()
                .find(|finding| finding.check == entry.check)
                .cloned()
                .unwrap_or_else(|| {
                    Finding::unreachable(entry.check, "no probe produced this finding")
                })
        })
        .collect();
    let stray = produced.iter().filter(|finding| {
        !CATALOGUE
            .iter()
            .any(|entry| entry.check == finding.check && entry.side == mode)
    });
    findings.extend(stray.map(|finding| {
        Finding::unreachable(
            finding.check,
            "produced by a probe outside this side's catalogue",
        )
    }));
    findings
}

fn unknown_mode_findings(why: &str) -> Vec<Finding> {
    CATALOGUE
        .iter()
        .map(|entry| {
            Finding::unreachable(
                entry.check,
                format!("cannot tell who is running, so no side can run: {why}"),
            )
        })
        .collect()
}

pub fn print_findings(findings: &[Finding]) {
    for finding in findings {
        let label = if finding.status.is_pass() {
            "ok"
        } else if finding.status.is_deferred() {
            "DEFERRED"
        } else {
            "FAIL"
        };
        println!("xtask setup: {label} {}", check_name(finding.check));
        if !finding.status.is_pass() {
            println!("  {}", finding.status);
        }
        if let Some(hint) = &finding.hint {
            println!("  hint: {hint}");
        }
    }
}

/// Exit 0 when every check on this run's side passed; deferred checks count on their own line only.
pub fn summarize(mode: Option<Side>, findings: &[Finding]) -> i32 {
    let examined = findings
        .iter()
        .filter(|finding| !finding.status.is_deferred())
        .count();
    let deferred = findings.len().saturating_sub(examined);
    let failed = findings
        .iter()
        .filter(|finding| !finding.status.is_pass() && !finding.status.is_deferred())
        .count();
    let mode_label = mode.map_or("unknown", Side::label);
    if examined == 0 {
        eprintln!("xtask setup: {mode_label} mode examined 0 preconditions; a check over nothing is a failure");
        return 1;
    }
    println!(
        "xtask setup: {mode_label} mode: examined {examined} preconditions, {failed} not present"
    );
    match mode {
        Some(mode) => println!(
            "xtask setup: {deferred} deferred to the {} run (run `{}` as {})",
            mode.other().label(),
            mode.other().setup_command(),
            mode.other().run_as()
        ),
        None => println!("xtask setup: {deferred} deferred; no side could run"),
    }
    i32::from(failed > 0)
}

pub fn run() -> i32 {
    match current_identity() {
        Ok(identity) => {
            let mode = mode_for(&identity.username);
            let produced = match mode {
                Side::Developer => developer_findings(&identity),
                Side::Agent => agent_findings(&identity),
            };
            let findings = assemble(mode, &produced);
            print_findings(&findings);
            summarize(Some(mode), &findings)
        }
        Err(why) => {
            let findings = unknown_mode_findings(&why);
            print_findings(&findings);
            summarize(None, &findings)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_SIDES: [(&str, Side); 52] = [
        ("agent group exists", Side::Developer),
        ("agent user exists", Side::Developer),
        ("agent home directory", Side::Developer),
        ("shared group exists", Side::Developer),
        ("developer is a member of the shared group", Side::Developer),
        (
            "agent user cannot search the developer's home",
            Side::Developer,
        ),
        ("agent socket directory: exists", Side::Developer),
        ("agent socket directory: is a directory", Side::Developer),
        ("agent socket directory: owner uid", Side::Developer),
        ("agent socket directory: owner gid", Side::Developer),
        ("agent socket directory: mode", Side::Developer),
        (
            "core socket directory: path fits the socket budget",
            Side::Developer,
        ),
        ("core socket directory: exists", Side::Developer),
        ("core socket directory: is a directory", Side::Developer),
        ("core socket directory: owner uid", Side::Developer),
        ("core socket directory: mode", Side::Developer),
        (
            "zmx resolves through mise at the pinned version",
            Side::Developer,
        ),
        (
            "restate resolves through mise at the pinned version",
            Side::Developer,
        ),
        (
            "restate-server resolves through mise at the pinned version",
            Side::Developer,
        ),
        (
            "claude resolves through mise at the pinned version",
            Side::Developer,
        ),
        (
            "codex resolves through mise at the pinned version",
            Side::Developer,
        ),
        (
            "entire resolves through mise at the pinned version",
            Side::Developer,
        ),
        (
            "cue resolves through mise at the pinned version",
            Side::Developer,
        ),
        ("entire logged in as the developer", Side::Developer),
        (
            "vendor credential: claude token in the core's store, the developer's, mode 0600",
            Side::Developer,
        ),
        (
            "vendor credential: codex auth.json in the core's store, the developer's, mode 0600",
            Side::Developer,
        ),
        (
            "tool prefix: a real directory the developer owns, mode 0755",
            Side::Developer,
        ),
        (
            "tool prefix: every entry the developer's, closed to group and other writes, links inside",
            Side::Developer,
        ),
        ("tool prefix: mise is the pinned version", Side::Developer),
        (
            "tool prefix: claude is the pinned install, run by path, at its recorded digest",
            Side::Developer,
        ),
        (
            "tool prefix: codex is the pinned install, run by path, at its recorded digest",
            Side::Developer,
        ),
        (
            "tool prefix: zmx is the pinned install, run by path, at its recorded digest",
            Side::Developer,
        ),
        (
            "tool prefix: xtask is the recorded build of this checkout's commit",
            Side::Developer,
        ),
        (
            "tool prefix: tycho is the recorded build of this checkout's commit",
            Side::Developer,
        ),
        ("agent user is a member of the shared group", Side::Agent),
        ("agent user's primary group is tycho-agent", Side::Agent),
        ("agent credential: ~/.ssh", Side::Agent),
        ("agent credential: ~/.config/gh", Side::Agent),
        ("agent credential: ~/.aws", Side::Agent),
        ("agent credential: ~/.netrc", Side::Agent),
        ("agent credential: gitconfig credential helper", Side::Agent),
        ("agent keychain: no item for github.com", Side::Agent),
        ("agent keychain: no item for gitlab.com", Side::Agent),
        ("agent keychain: no item for aws", Side::Agent),
        ("agent keychain: no item for ssh", Side::Agent),
        ("agent keychain: no item for gh:github.com", Side::Agent),
        ("as the agent: the core's credential store cannot be reached", Side::Agent),
        (
            "as the agent: nothing in the tool prefix is writable",
            Side::Agent,
        ),
        (
            "as the agent: mise in the tool prefix is the pinned version",
            Side::Agent,
        ),
        (
            "as the agent: claude runs by path at its pin and recorded digest",
            Side::Agent,
        ),
        (
            "as the agent: codex runs by path at its pin and recorded digest",
            Side::Agent,
        ),
        (
            "as the agent: zmx runs by path at its pin and recorded digest",
            Side::Agent,
        ),
    ];

    fn checks_run(findings: &[Finding]) -> Vec<Check> {
        findings
            .iter()
            .filter(|finding| !finding.status.is_deferred())
            .map(|finding| finding.check)
            .collect()
    }

    #[test]
    fn mode_runs_partition_the_catalogue() {
        let table: Vec<(&str, Side)> = CATALOGUE
            .iter()
            .map(|entry| (entry.name, entry.side))
            .collect();
        assert_eq!(table, EXPECTED_SIDES.to_vec());
        for (index, entry) in CATALOGUE.iter().enumerate() {
            let later = CATALOGUE.iter().skip(index.saturating_add(1));
            assert!(later.clone().all(|other| other.check != entry.check));
            assert!(later.clone().all(|other| other.name != entry.name));
        }

        let developer_run = assemble(Side::Developer, &[]);
        let agent_run = assemble(Side::Agent, &[]);
        for (mode, run) in [(Side::Developer, &developer_run), (Side::Agent, &agent_run)] {
            let checks: Vec<Check> = run.iter().map(|finding| finding.check).collect();
            let catalogue: Vec<Check> = CATALOGUE.iter().map(|entry| entry.check).collect();
            assert_eq!(
                checks, catalogue,
                "every check exactly once in {mode:?} mode"
            );
            for (finding, entry) in run.iter().zip(CATALOGUE.iter()) {
                if entry.side == mode {
                    assert!(!finding.status.is_deferred());
                } else {
                    assert_eq!(finding.status, Status::Deferred { to: mode.other() });
                }
            }
        }

        let developer_checks = checks_run(&developer_run);
        let agent_checks = checks_run(&agent_run);
        assert!(developer_checks
            .iter()
            .all(|check| !agent_checks.contains(check)));
        assert_eq!(
            developer_checks.len().saturating_add(agent_checks.len()),
            CATALOGUE.len()
        );
        assert_eq!(developer_checks.len(), 34);
        assert_eq!(agent_checks.len(), 18);
    }

    /// `ls -lde` on this machine's home and on a directory carrying the deny entry and an
    /// inherited allow.
    const HOME_LISTING: &str = "drwxr-x---+ 93 frits  staff  2976 Oct  9 21:13 /Users/frits\n 0: group:everyone deny delete\n";
    const DENIED_LISTING: &str = "drwxr-xr-x@ 3 frits  wheel  96 Oct  9 21:16 acltest\n 0: user:tycho-agent deny list,search,readattr,readextattr\n 1: group:staff inherited allow list,search,directory_inherit\n";

    fn entries(listing: &str) -> Vec<AclEntry> {
        match decode_acl_listing(listing) {
            AclListing::Entries(entries) => entries,
            AclListing::Unrecognised(line) => panic!("unrecognised {line}"),
        }
    }

    #[test]
    fn decodes_acl_listings_and_rejects_the_unrecognised() {
        assert_eq!(
            entries(HOME_LISTING),
            vec![AclEntry {
                principal: "group:everyone".to_string(),
                allows: false,
                permissions: vec!["delete".to_string()],
            }]
        );
        let denied = entries(DENIED_LISTING);
        assert_eq!(denied.len(), 2);
        assert!(denied.get(1).is_some_and(|entry| entry.allows));
        assert_eq!(
            entries("drwx------  3 frits  staff  96 Oct  9 21:16 /Users/frits\n"),
            Vec::new()
        );
        for unrecognised in [
            "",
            "-rw-r--r--  1 frits  staff  0 Oct  9 21:16 file\n",
            "drwx------  3 frits  staff  96 Oct  9 21:16 d\n 0: user:tycho-agent maybe search\n",
            "drwx------  3 frits  staff  96 Oct  9 21:16 d\nsomething else\n",
        ] {
            assert!(matches!(
                decode_acl_listing(unrecognised),
                AclListing::Unrecognised(_)
            ));
        }
        let lines = (0..=ACL_ENTRIES_MAX)
            .map(|index| format!(" {index}: group:staff deny delete"))
            .collect::<Vec<_>>()
            .join("\n");
        let long = format!("drwx------  3 frits  staff  96 Oct  9 21:16 d\n{lines}");
        assert!(matches!(
            decode_acl_listing(&long),
            AclListing::Unrecognised(_)
        ));
    }

    #[test]
    fn the_agent_is_kept_out_of_the_home_by_the_deny_entry_not_its_primary_group() {
        let staff_home = entries(HOME_LISTING);
        assert!(matches!(
            home_search_status(&staff_home, 0o750, "frits", AgentInGroup::Member),
            Status::Wrong { .. }
        ));
        assert!(matches!(
            home_search_status(&staff_home, 0o755, "frits", AgentInGroup::NotMember),
            Status::Wrong { .. }
        ));
        assert_eq!(
            home_search_status(&staff_home, 0o750, "frits", AgentInGroup::NotMember),
            Status::Present
        );
        assert_eq!(
            home_search_status(&staff_home, 0o700, "frits", AgentInGroup::Member),
            Status::Present
        );
        assert_eq!(
            home_search_status(&staff_home, 0o750, "frits", AgentInGroup::NoAgent),
            Status::Missing
        );
        assert_eq!(
            home_search_status(
                &entries(DENIED_LISTING),
                0o755,
                "frits",
                AgentInGroup::Member
            ),
            Status::Present
        );
        let allow_first = "drwxr-x---+ 3 frits  staff  96 Oct  9 21:16 d\n 0: group:staff allow list,search\n 1: user:tycho-agent deny list,search,readattr,readextattr\n";
        assert!(matches!(
            home_search_status(&entries(allow_first), 0o700, "frits", AgentInGroup::Member),
            Status::Wrong { .. }
        ));
        let inherit_only = "drwxr-x---+ 3 frits  staff  96 Oct  9 21:16 d\n 0: user:tycho-agent deny list,search,readattr,readextattr,directory_inherit,only_inherit\n";
        assert!(matches!(
            home_search_status(&entries(inherit_only), 0o750, "frits", AgentInGroup::Member),
            Status::Wrong { .. }
        ));
        let owner_allow = "drwxr-x---+ 3 frits  staff  96 Oct  9 21:16 d\n 0: user:frits allow list,search\n 1: user:tycho-agent deny list,search,readattr,readextattr\n";
        assert_eq!(
            home_search_status(&entries(owner_allow), 0o750, "frits", AgentInGroup::Member),
            Status::Present
        );
    }

    #[test]
    fn mode_is_agent_only_for_the_agent_user() {
        assert_eq!(mode_for("tycho-agent"), Side::Agent);
        assert_eq!(mode_for("frits"), Side::Developer);
        assert_eq!(mode_for("tycho-agent2"), Side::Developer);
        assert_eq!(mode_for(""), Side::Developer);
    }

    #[test]
    fn assemble_keeps_produced_results_and_fails_closed_on_gaps() {
        let produced = [Finding::new(Check::AgentUserExists, Status::Present)];
        let findings = assemble(Side::Developer, &produced);
        let agent_user = findings
            .iter()
            .find(|finding| finding.check == Check::AgentUserExists)
            .map(|finding| &finding.status);
        assert_eq!(agent_user, Some(&Status::Present));
        let shared_group = findings
            .iter()
            .find(|finding| finding.check == Check::SharedGroupExists)
            .map(|finding| finding.status.clone());
        assert_eq!(
            shared_group,
            Some(Status::Unreachable {
                why: "no probe produced this finding".to_string()
            })
        );

        let stray = [Finding::new(
            Check::AgentCredentialStoreClosed,
            Status::Present,
        )];
        let findings = assemble(Side::Developer, &stray);
        assert_eq!(findings.len(), CATALOGUE.len().saturating_add(1));
        assert!(findings
            .last()
            .is_some_and(|finding| matches!(finding.status, Status::Unreachable { .. })));
    }

    #[test]
    fn unknown_identity_makes_every_check_unreachable() {
        let findings = unknown_mode_findings("id is not on PATH");
        assert_eq!(findings.len(), CATALOGUE.len());
        assert!(findings
            .iter()
            .all(|finding| matches!(finding.status, Status::Unreachable { .. })));
        assert_eq!(summarize(None, &findings), 1);
    }

    #[test]
    fn summarize_exits_on_its_own_side_and_ignores_deferred() {
        assert_eq!(summarize(Some(Side::Developer), &[]), 1);
        let own_side_green = [
            Finding::new(Check::AgentUserExists, Status::Present),
            Finding::new(Check::KeychainSsh, Status::Deferred { to: Side::Agent }),
        ];
        assert_eq!(summarize(Some(Side::Developer), &own_side_green), 0);
        let own_side_red = [
            Finding::new(Check::AgentUserExists, Status::Missing),
            Finding::new(Check::KeychainSsh, Status::Deferred { to: Side::Agent }),
        ];
        assert_eq!(summarize(Some(Side::Developer), &own_side_red), 1);
        let only_deferred = [Finding::new(
            Check::KeychainSsh,
            Status::Deferred { to: Side::Agent },
        )];
        assert_eq!(summarize(Some(Side::Developer), &only_deferred), 1);
    }

    #[test]
    fn deferred_is_never_a_pass() {
        let status = Status::Deferred { to: Side::Agent };
        assert!(!status.is_pass());
        assert!(status.is_deferred());
        assert_eq!(status.to_string(), "deferred to the agent run");
        assert_eq!(
            Status::Deferred {
                to: Side::Developer
            }
            .to_string(),
            "deferred to the developer run"
        );
    }

    #[test]
    fn decodes_keychain_item_lookup_states() {
        let not_found = "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n";
        assert_eq!(
            decode_keychain_item(Some(44), "", not_found),
            KeychainItem::Absent
        );
        let found = "keychain: \"/Users/frits/Library/Keychains/login.keychain-db\"\nversion: 512\nclass: \"genp\"\nattributes:\n    \"svce\"<blob>=\"tycho-probe-test\"\n";
        assert_eq!(
            decode_keychain_item(Some(0), found, ""),
            KeychainItem::Present("/Users/frits/Library/Keychains/login.keychain-db".to_string())
        );
        let found_internet = "keychain: \"/Users/frits/Library/Keychains/login.keychain-db\"\nversion: 512\nclass: \"inet\"\n";
        assert!(matches!(
            decode_keychain_item(Some(0), found_internet, ""),
            KeychainItem::Present(_)
        ));
        assert_eq!(
            decode_keychain_item(Some(44), "", "some other error\n"),
            KeychainItem::Unrecognised
        );
        assert_eq!(
            decode_keychain_item(Some(0), "unexpected\n", ""),
            KeychainItem::Unrecognised
        );
        assert_eq!(
            decode_keychain_item(Some(51), "", "User interaction is not allowed.\n"),
            KeychainItem::Unrecognised
        );
        assert_eq!(
            decode_keychain_item(None, "", ""),
            KeychainItem::Unrecognised
        );
    }

    #[test]
    fn decodes_entire_auth_status_with_its_exit_code() {
        let entire_logged_in = r#"{"logged_in": true, "token_source": "macOS Keychain"}"#;
        let entire_logged_out = "{\n  \"logged_in\": false,\n  \"available_contexts\": 0\n}\n";
        assert_eq!(
            decode_entire_auth_status(Some(0), entire_logged_in, ""),
            AuthStatus::LoggedIn
        );
        assert_eq!(
            decode_entire_auth_status(Some(0), entire_logged_out, ""),
            AuthStatus::LoggedOut
        );
        assert_eq!(
            decode_entire_auth_status(Some(1), "", ""),
            AuthStatus::Unrecognised
        );
        assert_eq!(
            decode_entire_auth_status(Some(0), "not json", ""),
            AuthStatus::Unrecognised
        );
    }

    #[test]
    fn an_unrecognised_login_names_both_first_lines() {
        let message = unrecognised_login(
            &ENTIRE_LOGIN,
            Some(2),
            "{\"error\": true}\nmore\n",
            "warning\n",
        );
        assert_eq!(
            message,
            "unrecognised entire auth status --json result (exit Some(2)): stdout \"{\\\"error\\\": true}\", stderr \"warning\""
        );
    }

    #[test]
    fn login_hints_name_each_tools_own_login_command() {
        assert!(ENTIRE_LOGIN.login_hint.ends_with("entire auth login"));
        let [claude, codex] = &STORED_CREDENTIALS;
        assert!(
            claude.hint.contains("claude setup-token")
                && claude.hint.contains("credentials set claude")
        );
        assert!(
            codex.hint.contains("codex login")
                && codex
                    .hint
                    .contains("credentials set codex < ~/.codex/auth.json")
        );
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the scratch directory is this test's own, under the temporary directory"
    )]
    fn remove_scratch(dir: &Path) {
        drop(fs::remove_dir_all(dir));
    }

    fn credential_scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("xtask-store-{test}-{}", std::process::id()));
        remove_scratch(&dir);
        fs::create_dir(&dir).unwrap();
        dir
    }

    fn uid_of(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().uid()
    }

    #[test]
    fn a_credential_store_must_be_a_private_directory_of_the_developer() {
        let root = credential_scratch("store");
        let store = root.join("credentials");
        let me = uid_of(&root);
        assert_eq!(
            stored_credential_status(&store, "claude", me),
            Status::Missing
        );
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            stored_credential_status(&store, "claude", me),
            Status::Wrong { wanted, .. } if wanted == "0700"
        ));
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            stored_credential_status(&store, "claude", me),
            Status::Missing
        );
        assert!(matches!(
            stored_credential_status(&store, "claude", me.wrapping_add(1)),
            Status::Wrong { wanted, .. } if wanted.starts_with("uid ")
        ));
        remove_scratch(&root);
    }

    #[test]
    fn a_stored_credential_must_be_a_private_file_of_the_developer() {
        let root = credential_scratch("file");
        let store = root.join("credentials");
        let me = uid_of(&root);
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let file = store.join("claude");
        fs::write(&file, "sk-ant-oat01-x").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        let wrong = stored_credential_status(&store, "claude", me);
        assert!(
            matches!(&wrong, Status::Wrong { found, wanted } if found.ends_with("mode 0640") && wanted == "0600"),
            "{wrong}"
        );
        assert!(!wrong.to_string().contains("sk-ant-oat01-x"));
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            stored_credential_status(&store, "claude", me),
            Status::Present
        );
        fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink(root.join("elsewhere"), &file).unwrap();
        assert!(matches!(
            stored_credential_status(&store, "claude", me),
            Status::Wrong { wanted, .. } if wanted == "regular file"
        ));
        remove_scratch(&root);
    }

    #[test]
    fn the_store_follows_the_core_home_tycho_resolves() {
        let root = credential_scratch("home");
        assert_eq!(core_home(&root, None).unwrap(), root.join(".tycho"));
        let moved = root.join("test-core");
        assert_eq!(core_home(&root, Some(moved.as_os_str())).unwrap(), moved);
        for refused in [
            PathBuf::from("relative"),
            root.clone(),
            PathBuf::from("/elsewhere/core"),
            root.join("a/../b"),
        ] {
            assert!(
                core_home(&root, Some(refused.as_os_str())).is_err(),
                "{}",
                refused.display()
            );
        }
        std::os::unix::fs::symlink("/tmp", root.join("linked")).unwrap();
        assert!(core_home(&root, Some(root.join("linked/core").as_os_str())).is_err());
        remove_scratch(&root);
    }

    #[test]
    fn the_agents_store_probe_passes_only_on_a_denial() {
        let root = credential_scratch("agent");
        let store = root.join("credentials");
        assert!(matches!(
            agent_store_status(&store),
            Status::Unreachable { .. }
        ));
        fs::create_dir(&store).unwrap();
        fs::write(store.join("claude"), "x").unwrap();
        assert!(matches!(
            agent_store_status(&store),
            Status::Wrong { found, .. } if found.starts_with("the agent lists")
        ));
        fs::set_permissions(&store, fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(agent_store_status(&store), Status::Present);
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(agent_store_status(&store), Status::Present);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        remove_scratch(&root);
    }

    #[test]
    fn an_empty_credential_helper_clears_the_helpers_before_it() {
        assert_eq!(
            decode_credential_helpers(Some(0), "unknown\tosxkeychain\nglobal\t\n", ""),
            CredentialHelpers::Unset
        );
        assert_eq!(
            decode_credential_helpers(
                Some(0),
                "unknown\tosxkeychain\nglobal\t\nlocal\tstore\n",
                ""
            ),
            CredentialHelpers::Configured("store (scope local)".to_string())
        );
        assert_eq!(
            decode_credential_helpers(
                Some(0),
                "unknown\t\nglobal\tstore\nglobal\tosxkeychain\n",
                ""
            ),
            CredentialHelpers::Configured(
                "store (scope global), osxkeychain (scope global)".to_string()
            )
        );
    }

    #[test]
    fn decodes_credential_helper_states_and_rejects_the_unrecognised() {
        assert_eq!(
            decode_credential_helpers(Some(1), "", ""),
            CredentialHelpers::Unset
        );
        assert_eq!(
            decode_credential_helpers(Some(0), "\tosxkeychain\n", ""),
            CredentialHelpers::Unrecognised
        );
        assert_eq!(
            decode_credential_helpers(Some(0), "unknown\tosxkeychain\n", ""),
            CredentialHelpers::Configured("osxkeychain (scope unknown)".to_string())
        );
        assert_eq!(
            decode_credential_helpers(Some(0), "unknown\tosxkeychain\nglobal\tstore\n", ""),
            CredentialHelpers::Configured(
                "osxkeychain (scope unknown), store (scope global)".to_string()
            )
        );
        assert_eq!(
            decode_credential_helpers(Some(1), "", "xcrun: error: invalid active developer path\n"),
            CredentialHelpers::Unrecognised
        );
        assert_eq!(
            decode_credential_helpers(Some(0), "osxkeychain\n", ""),
            CredentialHelpers::Unrecognised
        );
        assert_eq!(
            decode_credential_helpers(Some(0), "", ""),
            CredentialHelpers::Unrecognised
        );
        assert_eq!(
            decode_credential_helpers(Some(1), "unknown\tosxkeychain\n", ""),
            CredentialHelpers::Unrecognised
        );
        assert_eq!(
            decode_credential_helpers(Some(3), "", ""),
            CredentialHelpers::Unrecognised
        );
        assert_eq!(
            decode_credential_helpers(None, "", ""),
            CredentialHelpers::Unrecognised
        );
    }

    #[test]
    fn credential_helper_command_runs_from_root_with_only_home_and_path() {
        let command = credential_helper_command("/Users/tycho-agent");
        assert_eq!(command.get_current_dir(), Some(Path::new("/")));
        assert!(command.get_args().all(|arg| arg != "--system"));

        let mut env_command = plain_command("env", &[]);
        scope_to_home(&mut env_command, "/Users/tycho-agent");
        let capture = run_bounded(env_command);
        let Capture::Ran {
            success: true,
            stdout,
            ..
        } = capture
        else {
            panic!("env did not run to a successful exit");
        };
        let lines: Vec<&str> = stdout.lines().collect();
        let mut names: Vec<&str> = lines
            .iter()
            .map(|line| line.split('=').next().unwrap_or_default())
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["HOME", "PATH"],
            "env printed the variables {names:?}"
        );
        assert!(lines.contains(&"HOME=/Users/tycho-agent"));
    }

    #[test]
    fn login_probes_stop_before_exec_unless_the_tool_is_installed() {
        let ls = MiseLs::Json(
            r#"{
                "claude": [{"version": "2.1.280", "installed": false, "active": true}],
                "entire": [{"version": "0.11.4", "installed": true, "active": true}]
            }"#
            .to_string(),
        );
        assert!(matches!(
            installed_gate(Check::EntireLogin, "claude", &ls),
            Some(Finding {
                status: Status::Unreachable { .. },
                ..
            })
        ));
        assert!(matches!(
            installed_gate(Check::EntireLogin, "codex", &ls),
            Some(Finding {
                status: Status::Unreachable { .. },
                ..
            })
        ));
        assert!(installed_gate(Check::EntireLogin, "entire", &ls).is_none());
        let unreachable = MiseLs::Unreachable("mise is not on PATH".to_string());
        assert!(installed_gate(Check::EntireLogin, "entire", &unreachable).is_some());
    }

    #[test]
    fn primary_group_passes_when_the_user_gid_is_the_agent_groups() {
        let user = DsclLookup::Found("PrimaryGroupID: 601\n".to_string());
        let group = DsclLookup::Found("PrimaryGroupID: 601\n".to_string());
        assert_eq!(primary_group_status(&user, &group), Status::Present);
    }

    #[test]
    fn primary_group_fails_for_staff_a_missing_group_or_a_mismatch() {
        let agent_group = DsclLookup::Found("PrimaryGroupID: 601\n".to_string());
        let staff_user = DsclLookup::Found("PrimaryGroupID: 20\n".to_string());
        assert_eq!(
            primary_group_status(&staff_user, &agent_group),
            Status::Wrong {
                found: "gid 20 (staff)".to_string(),
                wanted: "the gid of group tycho-agent".to_string()
            }
        );
        let staff_group = DsclLookup::Found("PrimaryGroupID: 20\n".to_string());
        assert!(matches!(
            primary_group_status(&staff_user, &staff_group),
            Status::Wrong { .. }
        ));
        let other_user = DsclLookup::Found("PrimaryGroupID: 700\n".to_string());
        assert_eq!(
            primary_group_status(&other_user, &agent_group),
            Status::Wrong {
                found: "gid 700".to_string(),
                wanted: "gid 601 (tycho-agent)".to_string()
            }
        );
        assert_eq!(
            primary_group_status(&other_user, &DsclLookup::NotFound),
            Status::Missing
        );
        assert_eq!(
            primary_group_status(&DsclLookup::NotFound, &agent_group),
            Status::Missing
        );
        let no_attribute = DsclLookup::Found("RecordName: tycho-agent\n".to_string());
        assert!(matches!(
            primary_group_status(&no_attribute, &agent_group),
            Status::Unreachable { .. }
        ));
        let unreachable = DsclLookup::Unreachable("dscl is not on PATH".to_string());
        assert!(matches!(
            primary_group_status(&other_user, &unreachable),
            Status::Unreachable { .. }
        ));
        assert!(matches!(
            primary_group_status(&unreachable, &agent_group),
            Status::Unreachable { .. }
        ));
        assert_eq!(
            primary_group_status(&other_user, &no_attribute),
            Status::Unreachable {
                why: "PrimaryGroupID missing from the tycho-agent record".to_string()
            }
        );
        let not_numeric = DsclLookup::Found("PrimaryGroupID: staff\n".to_string());
        assert_eq!(
            primary_group_status(&not_numeric, &agent_group),
            Status::Unreachable {
                why: "unrecognised PrimaryGroupID \"staff\" in the agent user record".to_string()
            }
        );
    }

    #[test]
    fn decodes_membership_states_with_exit_code_and_rejects_the_unrecognised() {
        assert_eq!(
            decode_membership(Some(0), "user is a member of the group\n"),
            MembershipOutcome::Member
        );
        assert_eq!(
            decode_membership(Some(0), "user is not a member of the group\n"),
            MembershipOutcome::NotMember
        );
        assert_eq!(
            decode_membership(Some(7), "Group not found\n"),
            MembershipOutcome::GroupNotFound
        );
        assert_eq!(
            decode_membership(Some(7), "User not found\n"),
            MembershipOutcome::UserNotFound
        );
        assert_eq!(
            decode_membership(Some(1), "user is a member of the group\n"),
            MembershipOutcome::Unrecognised
        );
        assert_eq!(
            decode_membership(Some(0), "Group not found\n"),
            MembershipOutcome::Unrecognised
        );
        assert_eq!(
            decode_membership(Some(0), "garbage\n"),
            MembershipOutcome::Unrecognised
        );
        assert_eq!(
            decode_membership(None, "user is a member of the group\n"),
            MembershipOutcome::Unrecognised
        );
    }

    #[test]
    fn missing_agent_home_makes_every_home_probe_unreachable() {
        let home = Err("user tycho-agent does not exist".to_string());
        for finding in credential_findings(&home) {
            assert!(matches!(finding.status, Status::Unreachable { .. }));
        }
    }

    #[test]
    fn directory_error_names_every_dependent_check() {
        let error = io::Error::from(io::ErrorKind::NotFound);
        let findings =
            directory_error_findings(Check::AgentDirExists, &AGENT_DIR_DEPENDENT, &error);
        let checks: Vec<Check> = findings.iter().map(|finding| finding.check).collect();
        assert_eq!(
            checks,
            vec![
                Check::AgentDirExists,
                Check::AgentDirIsDirectory,
                Check::AgentDirOwnerUid,
                Check::AgentDirOwnerGid,
                Check::AgentDirMode
            ]
        );
        assert_eq!(
            findings.first().map(|finding| &finding.status),
            Some(&Status::Missing)
        );
    }

    #[test]
    fn decodes_each_version_output_and_rejects_the_unrecognised() {
        assert_eq!(
            decode_zmx_version(
                "zmx\t\t0.8.1\nghostty_vt\tghostty-1.3.2\nsocket_dir\t/Users/frits/.zmx\n"
            ),
            Some("0.8.1".to_string())
        );
        assert_eq!(decode_zmx_version("not zmx output\n"), None);

        assert_eq!(
            decode_restate_cli_version(
                "restate-cli 1.7.13 (5ab87a6 aarch64-apple-darwin 2026-10-01)\n"
            ),
            Some("1.7.13".to_string())
        );
        assert_eq!(decode_restate_cli_version("restate-server 1.7.13\n"), None);

        assert_eq!(
            decode_restate_server_version("restate-server 1.7.13\n"),
            Some("1.7.13".to_string())
        );
        assert_eq!(decode_restate_server_version("restate-cli 1.7.13\n"), None);

        assert_eq!(
            decode_cue_version("cue version v0.17.1\n\nCUE language version v0.17.1\n"),
            Some("0.17.1".to_string())
        );
        assert_eq!(decode_cue_version("cue v0.17.1\n"), None);

        assert_eq!(
            decode_entire_version(
                "Entire CLI 0.11.4\nGo version: go1.27.1\nOS/Arch: darwin/arm64\n"
            ),
            Some("0.11.4".to_string())
        );
        assert_eq!(decode_entire_version("entire 0.11.4\n"), None);

        assert_eq!(
            decode_claude_version("2.1.280 (Claude Code)\n"),
            Some("2.1.280".to_string())
        );
        assert_eq!(decode_claude_version("2.1.280\n"), None);

        assert_eq!(
            decode_codex_version("codex-cli 0.160.1\n"),
            Some("0.160.1".to_string())
        );
        assert_eq!(decode_codex_version("codex 0.5.0\n"), None);
    }
    #[test]
    fn classifies_a_version_against_its_pin() {
        // A real zmx --version sample at a version older than a pin.
        let found = decode_zmx_version(
            "zmx\t\t0.4.2\nghostty_vt\tghostty-1.3.0\nsocket_dir\t/Users/frits/.zmx\n",
        );
        assert_eq!(
            classify_version(found, "zmx", "zmx 0.4.2", "0.8.1"),
            Status::Wrong {
                found: "0.4.2".to_string(),
                wanted: "0.8.1".to_string()
            }
        );
        assert_eq!(
            classify_version(None, "zmx", "garbage", "0.8.1"),
            Status::Unreachable {
                why: "unrecognised zmx version output: \"garbage\"".to_string()
            }
        );
    }
    #[test]
    fn decodes_mise_exec_failure_states() {
        let not_installed = "mise ERROR \"codex\" couldn't exec process: No such file or directory\nmise ERROR Version: 2026.9.0 macos-arm64 (2026-09-01)\nmise ERROR Run with --verbose or MISE_VERBOSE=1 for more information\n";
        assert_eq!(
            decode_mise_exec_failure(not_installed),
            MiseFailure::ToolNotInstalled
        );
        assert_eq!(
            decode_mise_exec_failure("mise ERROR some other failure\n"),
            MiseFailure::Other("mise ERROR some other failure".to_string())
        );
    }
    #[test]
    fn decodes_dscl_failure_states() {
        let not_found = "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n";
        assert_eq!(decode_dscl_failure(not_found), DsclFailure::RecordNotFound);
        assert_eq!(
            decode_dscl_failure("<dscl_cmd> DS Error: -14009 (eDSPermissionError)\n"),
            DsclFailure::Other("<dscl_cmd> DS Error: -14009 (eDSPermissionError)".to_string())
        );
    }
    #[test]
    fn decodes_mise_pin_states_and_rejects_the_unrecognised() {
        let json = r#"{
            "zmx": [{"version": "0.8.1", "installed": true, "active": true}],
            "entire": [{"version": "0.11.4", "installed": false, "active": true}]
        }"#;
        assert_eq!(
            decode_mise_pin(json, "zmx"),
            Some(MisePin::Installed("0.8.1".to_string()))
        );
        assert_eq!(
            decode_mise_pin(json, "entire"),
            Some(MisePin::NotInstalled("0.11.4".to_string()))
        );
        assert_eq!(decode_mise_pin(json, "codex"), Some(MisePin::NotPinned));
        assert_eq!(decode_mise_pin("not json", "zmx"), None);
        assert_eq!(decode_mise_pin(r#"{"zmx": "not an array"}"#, "zmx"), None);
    }
    #[test]
    fn decodes_id_output_and_rejects_the_empty_line() {
        assert_eq!(decode_id_output("501\n"), Some("501".to_string()));
        assert_eq!(decode_id_output("frits\n"), Some("frits".to_string()));
        assert_eq!(decode_id_output("\n"), None);
    }
    #[test]
    fn parses_dscl_attribute_lines_and_rejects_the_absent_key() {
        assert_eq!(
            dscl_value("NFSHomeDirectory: /Users/frits\n", "NFSHomeDirectory"),
            Some("/Users/frits".to_string())
        );
        assert_eq!(
            dscl_value(
                "GroupMembership: root frits _mbsetupuser\n",
                "GroupMembership"
            ),
            Some("root frits _mbsetupuser".to_string())
        );
        assert_eq!(
            dscl_value("NFSHomeDirectory: /Users/frits\n", "PrimaryGroupID"),
            None
        );
    }
    #[test]
    fn dscl_value_handles_the_continuation_line_form() {
        let sample = "dsAttrTypeNative:accountPolicyData:\n <?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>failedLoginCount</key>\n\t<integer>0</integer>\n</dict>\n</plist>\n\ndsAttrTypeNative:AvatarRepresentation: \n";
        let value = dscl_value(sample, "dsAttrTypeNative:accountPolicyData").unwrap_or_default();
        assert!(value.starts_with("<?xml"));
        assert!(value.contains("<key>failedLoginCount</key>"));
        assert!(!value.contains("AvatarRepresentation"));
    }
    #[test]
    fn owner_and_mode_status_pass_only_on_an_exact_match() {
        assert_eq!(owner_status(501, Ok(501)), Status::Present);
        assert_eq!(
            owner_status(501, Ok(502)),
            Status::Wrong {
                found: "501".to_string(),
                wanted: "502".to_string()
            }
        );
        assert_eq!(
            owner_status(501, Err("group unknown".to_string())),
            Status::Unreachable {
                why: "group unknown".to_string()
            }
        );
        assert_eq!(mode_status(0o2770, 0o2770), Status::Present);
        assert_eq!(
            mode_status(0o0770, 0o2770),
            Status::Wrong {
                found: "0770".to_string(),
                wanted: "2770".to_string()
            }
        );
    }
    #[test]
    fn socket_dir_budget_is_computed_from_tycho_types_constants() {
        assert_eq!(SOCKET_DIR_MAX_BYTES, 38);
        assert_eq!(path_length_status(AGENT_SOCKET_DIR), Status::Present);
        let long = "/".to_string() + &"d".repeat(SOCKET_DIR_MAX_BYTES.saturating_add(1));
        assert!(matches!(path_length_status(&long), Status::Wrong { .. }));
    }
    #[test]
    fn agent_and_core_socket_dirs_cannot_collide_for_a_real_home() {
        let core = core_socket_dir_path("/Users/example-developer");
        assert_ne!(core, AGENT_SOCKET_DIR);
    }
    #[test]
    fn mise_command_disables_auto_install_and_the_network() {
        let command = mise_command(&["exec", "--", "zmx", "--version"]);
        let envs: Vec<_> = command.get_envs().collect();
        assert!(envs.contains(&(
            std::ffi::OsStr::new("MISE_EXEC_AUTO_INSTALL"),
            Some(std::ffi::OsStr::new("false"))
        )));
        assert!(envs.contains(&(
            std::ffi::OsStr::new("MISE_NOT_FOUND_AUTO_INSTALL"),
            Some(std::ffi::OsStr::new("false"))
        )));
        assert!(envs.contains(&(
            std::ffi::OsStr::new("MISE_OFFLINE"),
            Some(std::ffi::OsStr::new("1"))
        )));
    }

    #[test]
    fn group_gid_tells_a_missing_attribute_from_an_unparsable_one() {
        let found = DsclLookup::Found("PrimaryGroupID: 701\n".to_string());
        assert_eq!(group_gid(&found), Ok(701));
        let absent = DsclLookup::Found("RecordName: tycho-zmx\n".to_string());
        assert_eq!(
            group_gid(&absent),
            Err("PrimaryGroupID missing from the group record".to_string())
        );
        let not_numeric = DsclLookup::Found("PrimaryGroupID: zmx\n".to_string());
        assert_eq!(
            group_gid(&not_numeric),
            Err("unrecognised PrimaryGroupID \"zmx\" in the group record".to_string())
        );
        assert_eq!(
            group_gid(&DsclLookup::NotFound),
            Err("group tycho-zmx does not exist".to_string())
        );
    }

    #[test]
    fn owner_uid_status_accepts_any_candidate() {
        assert_eq!(owner_uid_status(501, &[501, 0]), Status::Present);
        assert_eq!(owner_uid_status(0, &[501, 0]), Status::Present);
        assert_eq!(
            owner_uid_status(777, &[501, 0]),
            Status::Wrong {
                found: "777".to_string(),
                wanted: "501 or 0".to_string()
            }
        );
    }

    fn home_scratch(name: &str) -> std::path::PathBuf {
        let base =
            std::env::temp_dir().join(format!("xtask-setup-home-{}-{name}", std::process::id()));
        fs::create_dir(&base).expect("create the scratch directory");
        base
    }

    /// A record naming `path`, owned as `path`'s parent is, so only what a test changes differs.
    fn record_for(path: &Path) -> AgentRecord {
        let parent = fs::metadata(path.parent().expect("a parent")).expect("stat the parent");
        AgentRecord {
            home: path.display().to_string(),
            uid: parent.uid(),
            gid: parent.gid(),
        }
    }

    fn home_dir(base: &Path, mode: u32) -> std::path::PathBuf {
        let home = base.join("home");
        fs::create_dir(&home).expect("create the home");
        fs::set_permissions(&home, fs::Permissions::from_mode(mode)).expect("set the mode");
        home
    }

    #[test]
    fn an_agent_home_at_the_records_owner_group_and_0700_is_ok() {
        let base = home_scratch("ok");
        let home = home_dir(&base, 0o700);
        let record = record_for(&home);
        assert_eq!(measure(&record), AgentHomeState::Ok);
        let finding = agent_home_finding(&AgentHome {
            path: Some(record.home),
            state: AgentHomeState::Ok,
        });
        assert_eq!(finding.status, Status::Present);
        assert!(finding.hint.is_none());
        fs::remove_dir(&home).expect("remove the home");
        fs::remove_dir(&base).expect("remove the base");
    }

    #[test]
    fn an_agent_home_the_record_names_but_nobody_created_is_missing() {
        let base = home_scratch("missing");
        let record = record_for(&base.join("never-created"));
        assert_eq!(measure(&record), AgentHomeState::Missing);
        assert_eq!(
            decode_agent_record(&DsclLookup::NotFound),
            Err(AgentHomeState::Missing)
        );
        let elsewhere = agent_home_finding(&AgentHome {
            path: Some(record.home),
            state: AgentHomeState::Missing,
        });
        assert_eq!(elsewhere.status, Status::Missing);
        assert!(elsewhere.hint.is_some_and(|hint| hint
            .contains("point NFSHomeDirectory at /Users/tycho-agent")
            && !hint.contains("createhomedir")));
        for path in [Some(AGENT_HOME.to_string()), None] {
            let at_agent_home = agent_home_finding(&AgentHome {
                path,
                state: AgentHomeState::Missing,
            });
            assert_eq!(at_agent_home.hint.as_deref(), Some(AGENT_HOME_CREATE_HINT));
        }
        fs::remove_dir(&base).expect("remove the base");
    }

    /// Measures with an empty ACL, so the stat checks run where `ls -e` does not exist.
    fn measure(record: &AgentRecord) -> AgentHomeState {
        measure_agent_home(record, |_: &str| Ok(AclListing::Entries(Vec::new())))
    }

    /// A created home's listing, with an allow entry after its deny entry.
    const HOME_WITH_ALLOW: &str = "drwx------+ 11 tycho-agent  tycho-agent  352 Oct 12 09:39 /Users/tycho-agent\n 0: group:everyone deny delete\n 1: group:staff allow list,search\n";

    #[test]
    fn an_acl_allow_entry_on_the_agent_home_is_wrong_and_a_deny_entry_passes() {
        let base = home_scratch("acl");
        let home = home_dir(&base, 0o700);
        let record = record_for(&home);
        let listing = |text: &'static str| move |_: &str| Ok(decode_acl_listing(text));
        assert_eq!(
            measure_agent_home(&record, listing(HOME_LISTING)),
            AgentHomeState::Ok
        );
        let AgentHomeState::Wrong(mismatch) = measure_agent_home(&record, listing(HOME_WITH_ALLOW))
        else {
            panic!("an allow entry is wrong");
        };
        assert_eq!(
            mismatch,
            HomeMismatch {
                acl_allow: Some("group:staff allow list,search".to_string()),
                ..HomeMismatch::default()
            }
        );
        assert!(!mismatch.is_only_a_wider_mode());
        let finding = agent_home_finding(&AgentHome {
            path: Some(record.home.clone()),
            state: AgentHomeState::Wrong(mismatch),
        });
        assert!(matches!(
            &finding.status,
            Status::Wrong { found, .. } if found == "ACL entry group:staff allow list,search"
        ));
        assert!(finding
            .hint
            .is_some_and(|hint| hint.contains("chmod -a \"group:staff allow list,search\"")));
        assert!(matches!(
            measure_agent_home(&record, listing("total 0\n")),
            AgentHomeState::Unrecognised(_)
        ));
        assert!(matches!(
            measure_agent_home(&record, |_: &str| Err("/bin/ls is not present".to_string())),
            AgentHomeState::Unreachable(why) if why == "/bin/ls is not present"
        ));
        fs::remove_dir(&home).expect("remove the home");
        fs::remove_dir(&base).expect("remove the base");
    }

    /// The deny-delete entry would keep the scratch directory from being removed.
    #[cfg(target_os = "macos")]
    fn chmod_clear_acl(path: &Path) {
        let status = Command::new("/bin/chmod")
            .arg("-N")
            .arg(path)
            .status()
            .expect("run chmod -N");
        assert!(status.success(), "chmod -N");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_acl_of_a_real_home_is_read_and_only_an_allow_entry_fails() {
        let base = home_scratch("real-acl");
        let home = home_dir(&base, 0o700);
        let record = record_for(&home);
        let chmod = |entry: &str| {
            let status = Command::new("/bin/chmod")
                .args(["+a", entry])
                .arg(&home)
                .status()
                .expect("run chmod");
            assert!(status.success(), "chmod +a {entry}");
        };
        chmod("group:everyone deny delete");
        assert_eq!(measure_agent_home(&record, home_acl), AgentHomeState::Ok);
        chmod("group:staff allow list,search");
        assert_eq!(
            measure_agent_home(&record, home_acl),
            AgentHomeState::Wrong(HomeMismatch {
                acl_allow: Some("group:staff allow list,search".to_string()),
                ..HomeMismatch::default()
            })
        );
        let entries = vec![
            AclEntry {
                principal: "group:everyone".to_string(),
                allows: false,
                permissions: vec!["delete".to_string()],
            },
            AclEntry {
                principal: "user:frits".to_string(),
                allows: true,
                permissions: vec!["search".to_string(), "list".to_string()],
            },
        ];
        assert_eq!(
            first_allow(&entries),
            Some("user:frits allow search,list".to_string())
        );
        assert_eq!(first_allow(entries.get(..1).unwrap_or_default()), None);
        chmod_clear_acl(&home);
        fs::remove_dir(&home).expect("remove the home");
        fs::remove_dir(&base).expect("remove the base");
    }

    #[test]
    fn an_agent_home_with_another_owner_group_or_mode_is_wrong_and_names_each() {
        let base = home_scratch("wrong");
        let home = home_dir(&base, 0o755);
        let mut record = record_for(&home);
        let (uid, gid) = (record.uid, record.gid);
        assert_eq!(
            measure(&record),
            AgentHomeState::Wrong(HomeMismatch {
                mode: Some(Differs {
                    found: 0o755,
                    wanted: 0o700
                }),
                ..HomeMismatch::default()
            })
        );
        record.uid = uid.wrapping_add(1);
        record.gid = gid.wrapping_add(1);
        let AgentHomeState::Wrong(mismatch) = measure(&record) else {
            panic!("a home owned by another uid and gid is wrong");
        };
        assert_eq!(
            mismatch.owner,
            Some(Differs {
                found: uid,
                wanted: uid.wrapping_add(1)
            })
        );
        assert_eq!(
            mismatch.group,
            Some(Differs {
                found: gid,
                wanted: gid.wrapping_add(1)
            })
        );
        assert!(!mismatch.is_only_a_wider_mode());
        let finding = agent_home_finding(&AgentHome {
            path: Some(record.home),
            state: AgentHomeState::Wrong(mismatch),
        });
        let Status::Wrong { found, wanted } = &finding.status else {
            panic!("the finding is wrong");
        };
        assert_eq!(
            found,
            &format!("owner uid {uid}, group gid {gid}, mode 0755")
        );
        assert!(wanted.contains("mode 0700"));
        assert!(finding
            .hint
            .is_some_and(|hint| hint.contains("move it aside by hand")));
        fs::remove_dir(&home).expect("remove the home");
        fs::remove_dir(&base).expect("remove the base");
    }

    #[test]
    fn a_symlink_at_the_agent_home_is_wrong_and_its_target_is_not_measured() {
        let base = home_scratch("symlink");
        let target = home_dir(&base, 0o700);
        let link = base.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("plant the link");
        let AgentHomeState::Wrong(mismatch) = measure(&record_for(&link)) else {
            panic!("a symlink is not a home");
        };
        assert_eq!(mismatch.kind, Some("symlink"));
        fs::remove_file(&link).expect("remove the link");
        fs::remove_dir(&target).expect("remove the target");
        fs::remove_dir(&base).expect("remove the base");
    }

    #[test]
    fn only_a_mode_beyond_the_agents_own_bits_is_wider() {
        let mode = |found| HomeMismatch {
            mode: Some(Differs {
                found,
                wanted: AGENT_HOME_MODE,
            }),
            ..HomeMismatch::default()
        };
        assert!(mode(0o750).is_only_a_wider_mode());
        assert!(mode(0o1700).is_only_a_wider_mode());
        assert!(!mode(0o500).is_only_a_wider_mode());
        let mut owned_elsewhere = mode(0o755);
        owned_elsewhere.owner = Some(Differs {
            found: 0,
            wanted: 503,
        });
        assert!(!owned_elsewhere.is_only_a_wider_mode());
    }

    #[test]
    fn an_agent_home_that_cannot_be_read_is_unreachable() {
        let base = home_scratch("unreachable");
        let file = base.join("file");
        fs::write(&file, b"").expect("create the file");
        assert!(matches!(
            measure(&record_for(&file.join("home"))),
            AgentHomeState::Unreachable(why) if why.contains("Not a directory")
        ));
        let failed = DsclLookup::Unreachable("dscl is not on PATH".to_string());
        assert_eq!(
            decode_agent_record(&failed),
            Err(AgentHomeState::Unreachable(
                "dscl is not on PATH".to_string()
            ))
        );
        let finding = agent_home_finding(&AgentHome {
            path: None,
            state: AgentHomeState::Unreachable("dscl is not on PATH".to_string()),
        });
        assert!(matches!(finding.status, Status::Unreachable { .. }));
        fs::remove_file(&file).expect("remove the file");
        fs::remove_dir(&base).expect("remove the base");
    }

    #[test]
    fn decodes_the_agent_record_and_rejects_the_unrecognised() {
        let found = |stdout: &str| decode_agent_record(&DsclLookup::Found(stdout.to_string()));
        assert_eq!(
            found("NFSHomeDirectory: /Users/tycho-agent\nPrimaryGroupID: 502\nUniqueID: 503\n"),
            Ok(AgentRecord {
                home: "/Users/tycho-agent".to_string(),
                uid: 503,
                gid: 502,
            })
        );
        for unrecognised in [
            "PrimaryGroupID: 502\nUniqueID: 503\n",
            "NFSHomeDirectory: tycho-agent\nPrimaryGroupID: 502\nUniqueID: 503\n",
            "NFSHomeDirectory:\n /Users/a\n /Users/b\nPrimaryGroupID: 502\nUniqueID: 503\n",
            "NFSHomeDirectory: /Users/tycho-agent\nPrimaryGroupID: 502\n",
            "NFSHomeDirectory: /Users/tycho-agent\nPrimaryGroupID: staff\nUniqueID: 503\n",
        ] {
            assert!(
                matches!(found(unrecognised), Err(AgentHomeState::Unrecognised(_))),
                "{unrecognised:?}"
            );
        }
        let finding = agent_home_finding(&AgentHome {
            path: None,
            state: AgentHomeState::Unrecognised("agent user record without UniqueID".to_string()),
        });
        assert!(matches!(
            finding.status,
            Status::Unreachable { ref why } if why.starts_with("unrecognised")
        ));
    }
}

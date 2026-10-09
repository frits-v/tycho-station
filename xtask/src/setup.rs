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
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tycho_types::session::{SESSION_NAME_MAX_BYTES, SOCKET_PATH_MAX_BYTES};

pub const AGENT_USER_NAME: &str = "tycho-agent";
pub const SHARED_GROUP_NAME: &str = "tycho-zmx";
pub const AGENT_SOCKET_DIR: &str = "/Users/Shared/tycho-agent-zmx";
const CORE_SOCKET_DIR_RELATIVE: &str = ".tycho/zmx";
const AGENT_SOCKET_DIR_MODE: u32 = 0o2770;
const CORE_SOCKET_DIR_MODE: u32 = 0o0700;
/// What a socket path leaves for the directory once the name and separator are in it.
const SOCKET_DIR_MAX_BYTES: usize = SOCKET_PATH_MAX_BYTES
    .saturating_sub(1)
    .saturating_sub(SESSION_NAME_MAX_BYTES);
const _: () = assert!(AGENT_SOCKET_DIR.len() <= SOCKET_DIR_MAX_BYTES);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_OUTPUT_MAX_BYTES: usize = 1 << 17;
const CREDENTIAL_FILE_MAX_BYTES: u64 = 1 << 16;
/// `security find-*-password` exit code when no item matches.
const SECURITY_ITEM_NOT_FOUND_EXIT: i32 = 44;
/// `dsmemberutil checkmembership` exit code when the user or group does not exist.
const DSMEMBERUTIL_NOT_FOUND_EXIT: i32 = 7;
/// `claude auth status` exit code when no login is stored.
const CLAUDE_LOGGED_OUT_EXIT: i32 = 1;

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
}

/// Who a check can be performed as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
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
}

fn mode_for(username: &str) -> Side {
    if username == AGENT_USER_NAME {
        Side::Agent
    } else {
        Side::Developer
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    AgentUserExists,
    SharedGroupExists,
    DeveloperInSharedGroup,
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
    AgentInSharedGroup,
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
    ClaudeLogin,
    CodexLogin,
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
const CATALOGUE: [CheckSpec; 34] = [
    spec(Check::AgentUserExists, "agent user exists", Side::Developer),
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
        Check::AgentInSharedGroup,
        "agent user is a member of the shared group",
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
        Check::ClaudeLogin,
        "claude logged in as the agent",
        Side::Agent,
    ),
    spec(
        Check::CodexLogin,
        "codex logged in as the agent",
        Side::Agent,
    ),
];

fn check_name(check: Check) -> &'static str {
    CATALOGUE
        .iter()
        .find(|entry| entry.check == check)
        .map_or("check missing from the catalogue", |entry| entry.name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    Present,
    Missing,
    Wrong { found: String, wanted: String },
    Unreachable { why: String },
    Deferred { to: Side },
}

impl Status {
    const fn is_pass(&self) -> bool {
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
struct Finding {
    check: Check,
    status: Status,
    hint: Option<String>,
}

impl Finding {
    const fn new(check: Check, status: Status) -> Self {
        Self {
            check,
            status,
            hint: None,
        }
    }

    fn with_hint(check: Check, status: Status, hint: impl Into<String>) -> Self {
        Self {
            check,
            status,
            hint: Some(hint.into()),
        }
    }

    fn unreachable(check: Check, why: impl Into<String>) -> Self {
        Self::new(check, Status::Unreachable { why: why.into() })
    }
}

/// What running an external probe produced; every decoder reads this, never the raw `Output`.
#[derive(Debug)]
enum Capture {
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

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or_default().trim()
}

fn plain_command(program: &str, args: &[&str]) -> Command {
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

/// Runs `command` bounded: stdout/stderr read on separate threads, timeout kills by pid.
fn run_bounded(mut command: Command) -> Capture {
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
    let stdout_rx = spawn_reader(child.stdout.take());
    let stderr_rx = spawn_reader(child.stderr.take());
    let (wait_sender, wait_rx) = mpsc::channel();
    thread::spawn(move || drop(wait_sender.send(child.wait())));

    let deadline = Instant::now()
        .checked_add(PROBE_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let stdout = recv_by(&stdout_rx, deadline);
    let stderr = recv_by(&stderr_rx, deadline);
    let status = recv_by(&wait_rx, deadline);
    let (
        Some((stdout_bytes, stdout_overflow)),
        Some((stderr_bytes, stderr_overflow)),
        Some(status),
    ) = (stdout, stderr, status)
    else {
        drop(Command::new("kill").args(["-9", &pid.to_string()]).status());
        return Capture::Unreachable(format!("{program} did not finish within {PROBE_TIMEOUT:?}"));
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

fn decode_zmx_version(stdout: &str) -> Option<String> {
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

fn decode_claude_version(stdout: &str) -> Option<String> {
    let mut tokens = stdout.lines().next().unwrap_or_default().split_whitespace();
    let version = tokens.next()?;
    if tokens.next()? != "(Claude" || tokens.next()? != "Code)" {
        return None;
    }
    Some(version.to_string())
}

/// Documented shape (`codex-cli <semver>`); no codex binary exists here to sample from.
fn decode_codex_version(stdout: &str) -> Option<String> {
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

/// `claude auth status --json` prints `loggedIn` either way and exits 1 when logged out.
fn decode_claude_auth_status(code: Option<i32>, stdout: &str) -> AuthStatus {
    match (code, json_bool(stdout, "loggedIn")) {
        (Some(0), Some(true)) => AuthStatus::LoggedIn,
        (Some(CLAUDE_LOGGED_OUT_EXIT), Some(false)) => AuthStatus::LoggedOut,
        _ => AuthStatus::Unrecognised,
    }
}

/// `entire auth status --json` exits 0 logged in or out; a non-zero exit is a failure to look.
fn decode_entire_auth_status(code: Option<i32>, stdout: &str) -> AuthStatus {
    match (code, json_bool(stdout, "logged_in")) {
        (Some(0), Some(true)) => AuthStatus::LoggedIn,
        (Some(0), Some(false)) => AuthStatus::LoggedOut,
        _ => AuthStatus::Unrecognised,
    }
}

/// No codex binary has been available to capture a `login status` sample from.
const fn decode_codex_login_status(_code: Option<i32>, _stdout: &str) -> AuthStatus {
    AuthStatus::Unrecognised
}

struct LoginProbe {
    check: Check,
    tool: &'static str,
    args: &'static [&'static str],
    decode: fn(Option<i32>, &str) -> AuthStatus,
}

const ENTIRE_LOGIN: LoginProbe = LoginProbe {
    check: Check::EntireLogin,
    tool: "entire",
    args: &["auth", "status", "--json"],
    decode: decode_entire_auth_status,
};
const CLAUDE_LOGIN: LoginProbe = LoginProbe {
    check: Check::ClaudeLogin,
    tool: "claude",
    args: &["auth", "status", "--json"],
    decode: decode_claude_auth_status,
};
const CODEX_LOGIN: LoginProbe = LoginProbe {
    check: Check::CodexLogin,
    tool: "codex",
    args: &["login", "status"],
    decode: decode_codex_login_status,
};

fn login_finding(probe: &LoginProbe, ls: &MiseLs) -> Finding {
    if let Some(gated) = installed_gate(probe.check, probe.tool, ls) {
        return gated;
    }
    let mut args = vec!["exec", "--", probe.tool];
    args.extend_from_slice(probe.args);
    match run_bounded(mise_command(&args)) {
        Capture::ExecutableNotFound => Finding::unreachable(probe.check, "mise is not on PATH"),
        Capture::Unreachable(why) => Finding::unreachable(probe.check, why),
        Capture::Ran {
            code,
            stdout,
            stderr,
            ..
        } => match (probe.decode)(code, &stdout) {
            AuthStatus::LoggedIn => Finding::new(probe.check, Status::Present),
            AuthStatus::LoggedOut => Finding::with_hint(
                probe.check,
                Status::Missing,
                format!("log in once from a terminal: {} auth login", probe.tool),
            ),
            AuthStatus::Unrecognised => Finding::unreachable(
                probe.check,
                format!(
                    "unrecognised {} {} result (exit {code:?}): {:?}",
                    probe.tool,
                    probe.args.join(" "),
                    first_line(&stderr)
                ),
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
struct Identity {
    uid: u32,
    username: String,
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

fn current_identity() -> Result<Identity, String> {
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
    let mut args = vec![".", "-read", path];
    if let Some(key) = key {
        args.push(key);
    }
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
        DsclLookup::Found(stdout) => dscl_value(stdout, "PrimaryGroupID")
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| "PrimaryGroupID missing from the group record".to_string()),
        DsclLookup::NotFound => Err(format!("group {SHARED_GROUP_NAME} does not exist")),
        DsclLookup::Unreachable(why) => Err(why.clone()),
    }
}

fn resolve_home(username: &str) -> Result<String, String> {
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

/// Opens without blocking and checks the handle, so a FIFO or device fails instead of hanging; reads bounded, erroring over `CREDENTIAL_FILE_MAX_BYTES` rather than truncating.
fn read_bounded_file(path: &Path) -> io::Result<String> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    let cap = CREDENTIAL_FILE_MAX_BYTES.saturating_add(1);
    file.by_ref().take(cap).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > CREDENTIAL_FILE_MAX_BYTES {
        return Err(io::Error::other(format!(
            "{} exceeds {CREDENTIAL_FILE_MAX_BYTES} bytes",
            path.display()
        )));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn gitconfig_has_credential_helper(path: &Path) -> Result<bool, Status> {
    match read_bounded_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Status::Unreachable {
            why: format!("{}: {error}", path.display()),
        }),
        Ok(text) => Ok(text.contains("[credential")),
    }
}

/// Checks `~/.gitconfig` and `~/.config/git/config`; the hint names the system gitconfig, which this does not read.
fn credential_gitconfig_finding(home: &Result<String, String>) -> Finding {
    let check = Check::CredentialGitconfig;
    let hint = "also check the system gitconfig: git config --system --get-all credential.helper";
    let home = match home {
        Ok(home) => home,
        Err(why) => {
            return Finding::with_hint(
                check,
                Status::Unreachable {
                    why: format!("agent home unknown: {why}"),
                },
                hint,
            )
        }
    };
    for relative in [".gitconfig", ".config/git/config"] {
        match gitconfig_has_credential_helper(&Path::new(home).join(relative)) {
            Err(status) => return Finding::with_hint(check, status, hint),
            Ok(true) => {
                return Finding::with_hint(
                    check,
                    Status::Wrong {
                        found: format!("credential helper configured in {relative}"),
                        wanted: "no credential helper".to_string(),
                    },
                    hint,
                )
            }
            Ok(false) => {}
        }
    }
    Finding::with_hint(check, Status::Present, hint)
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

fn core_socket_dir_path(home: &str) -> String {
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
fn developer_findings(identity: &Identity) -> Vec<Finding> {
    let agent_lookup = dscl_read(&format!("/Users/{AGENT_USER_NAME}"), Some("RecordName"));
    let group_lookup = dscl_read(&format!("/Groups/{SHARED_GROUP_NAME}"), None);
    let mut findings = vec![
        Finding::new(Check::AgentUserExists, lookup_status(&agent_lookup)),
        Finding::new(Check::SharedGroupExists, lookup_status(&group_lookup)),
        Finding::new(
            Check::DeveloperInSharedGroup,
            membership_status(&identity.username, SHARED_GROUP_NAME),
        ),
    ];
    findings.extend(agent_socket_dir_findings(
        group_gid(&group_lookup),
        identity.uid,
    ));
    findings.extend(core_socket_findings(identity));
    let ls = mise_ls();
    findings.extend(vendor_findings(&ls));
    findings.push(login_finding(&ENTIRE_LOGIN, &ls));
    findings
}

/// Runs only checks the agent can perform on itself: nothing here resolves the developer's home, the core directory or the developer's logins.
fn agent_findings(identity: &Identity) -> Vec<Finding> {
    let home = resolve_home(&identity.username);
    let mut findings = vec![Finding::new(
        Check::AgentInSharedGroup,
        membership_status(&identity.username, SHARED_GROUP_NAME),
    )];
    findings.extend(credential_findings(&home));
    findings.extend(keychain_findings());
    let ls = mise_ls();
    findings.push(login_finding(&CLAUDE_LOGIN, &ls));
    findings.push(login_finding(&CODEX_LOGIN, &ls));
    findings
}

/// One finding per catalogue entry: the produced result, `Deferred` for the other side, `Unreachable` for a gap.
fn assemble(mode: Side, produced: &[Finding]) -> Vec<Finding> {
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

fn print_findings(findings: &[Finding]) {
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
fn summarize(mode: Option<Side>, findings: &[Finding]) -> i32 {
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
            "xtask setup: {deferred} deferred to the {} run (run `mise run setup` as {})",
            mode.other().label(),
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

    const EXPECTED_SIDES: [(&str, Side); 34] = [
        ("agent user exists", Side::Developer),
        ("shared group exists", Side::Developer),
        ("developer is a member of the shared group", Side::Developer),
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
        ("agent user is a member of the shared group", Side::Agent),
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
        ("claude logged in as the agent", Side::Agent),
        ("codex logged in as the agent", Side::Agent),
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
        assert_eq!(developer_checks.len(), 21);
        assert_eq!(agent_checks.len(), 13);
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
        assert_eq!(
            findings.first().map(|finding| &finding.status),
            Some(&Status::Present)
        );
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

        let stray = [Finding::new(Check::ClaudeLogin, Status::Present)];
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
            Finding::new(Check::ClaudeLogin, Status::Deferred { to: Side::Agent }),
        ];
        assert_eq!(summarize(Some(Side::Developer), &own_side_green), 0);
        let own_side_red = [
            Finding::new(Check::AgentUserExists, Status::Missing),
            Finding::new(Check::ClaudeLogin, Status::Deferred { to: Side::Agent }),
        ];
        assert_eq!(summarize(Some(Side::Developer), &own_side_red), 1);
        let only_deferred = [Finding::new(
            Check::ClaudeLogin,
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
    fn decodes_auth_status_with_exit_code_per_tool() {
        let claude_logged_in = r#"{"loggedIn": true, "authMethod": "claude.ai"}"#;
        let claude_logged_out = "{\n  \"loggedIn\": false,\n  \"authMethod\": \"none\",\n  \"apiProvider\": \"firstParty\"\n}\n";
        assert_eq!(
            decode_claude_auth_status(Some(0), claude_logged_in),
            AuthStatus::LoggedIn
        );
        assert_eq!(
            decode_claude_auth_status(Some(1), claude_logged_out),
            AuthStatus::LoggedOut
        );
        assert_eq!(
            decode_claude_auth_status(Some(0), claude_logged_out),
            AuthStatus::Unrecognised
        );
        assert_eq!(
            decode_claude_auth_status(Some(1), claude_logged_in),
            AuthStatus::Unrecognised
        );
        assert_eq!(
            decode_claude_auth_status(Some(1), "not json"),
            AuthStatus::Unrecognised
        );

        let entire_logged_in = r#"{"logged_in": true, "token_source": "macOS Keychain"}"#;
        let entire_logged_out = "{\n  \"logged_in\": false,\n  \"available_contexts\": 0\n}\n";
        assert_eq!(
            decode_entire_auth_status(Some(0), entire_logged_in),
            AuthStatus::LoggedIn
        );
        assert_eq!(
            decode_entire_auth_status(Some(0), entire_logged_out),
            AuthStatus::LoggedOut
        );
        assert_eq!(
            decode_entire_auth_status(Some(1), ""),
            AuthStatus::Unrecognised
        );
        assert_eq!(
            decode_entire_auth_status(Some(0), "not json"),
            AuthStatus::Unrecognised
        );

        assert_eq!(
            decode_codex_login_status(Some(0), "Logged in"),
            AuthStatus::Unrecognised
        );
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
            installed_gate(Check::ClaudeLogin, "claude", &ls),
            Some(Finding {
                status: Status::Unreachable { .. },
                ..
            })
        ));
        assert!(matches!(
            installed_gate(Check::CodexLogin, "codex", &ls),
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
    fn read_bounded_file_rejects_a_fifo_without_blocking() {
        let directory =
            std::env::temp_dir().join(format!("xtask-setup-fifo-{}", std::process::id()));
        assert!(fs::create_dir(&directory).is_ok() || directory.is_dir());
        let fifo = directory.join("pipe");
        let made = Command::new("mkfifo").arg(&fifo).status();
        assert!(made.is_ok_and(|status| status.success()));

        let (sender, receiver) = mpsc::channel();
        let path = fifo.clone();
        thread::spawn(move || {
            drop(sender.send(read_bounded_file(&path).map_err(|error| error.to_string())));
        });
        let outcome = receiver.recv_timeout(Duration::from_secs(2));
        drop(fs::remove_file(&fifo));
        drop(fs::remove_dir(&directory));

        let Ok(result) = outcome else {
            panic!("read_bounded_file blocked on a FIFO");
        };
        assert!(result.is_err_and(|error| error.contains("is not a regular file")));
    }

    #[test]
    fn read_bounded_file_reads_a_regular_file_and_rejects_an_oversized_one() {
        let directory =
            std::env::temp_dir().join(format!("xtask-setup-file-{}", std::process::id()));
        assert!(fs::create_dir(&directory).is_ok() || directory.is_dir());
        let small = directory.join("small");
        let large = directory.join("large");
        assert!(fs::write(&small, "[user]\n").is_ok());
        let oversized = "x".repeat(
            usize::try_from(CREDENTIAL_FILE_MAX_BYTES)
                .unwrap_or(0)
                .saturating_add(1),
        );
        assert!(fs::write(&large, oversized).is_ok());
        let small_result = read_bounded_file(&small).ok();
        let large_result = read_bounded_file(&large);
        drop(fs::remove_file(&small));
        drop(fs::remove_file(&large));
        drop(fs::remove_dir(&directory));
        assert_eq!(small_result, Some("[user]\n".to_string()));
        assert!(large_result.is_err());
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
            decode_codex_version("codex-cli 0.5.0\n"),
            Some("0.5.0".to_string())
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
}

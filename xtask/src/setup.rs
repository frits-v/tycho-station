//! Operator precondition checks for running the factory on this machine (docs/slices.md,
//! "Operator prerequisites"). `run` never creates anything; a human with sudo or an
//! account login does that. It only reports what it finds, and a probe that cannot run
//! is `Unreachable`, never guessed as `Missing` or `Present`.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    Present,
    Missing,
    Wrong { found: String, wanted: String },
    Unreachable { why: String },
}

impl Status {
    const fn is_pass(&self) -> bool {
        matches!(self, Self::Present)
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
        }
    }
}

#[derive(Debug, Clone)]
struct Finding {
    name: String,
    status: Status,
    hint: Option<String>,
    /// True when this finding could only be checked by running as the agent user, and
    /// this run did not.
    deferred: bool,
}

impl Finding {
    fn new(name: impl Into<String>, status: Status) -> Self {
        Self {
            name: name.into(),
            status,
            hint: None,
            deferred: false,
        }
    }

    fn with_hint(name: impl Into<String>, status: Status, hint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status,
            hint: Some(hint.into()),
            deferred: false,
        }
    }

    /// A finding this run could not perform because it did not run as the agent user.
    fn deferred(name: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Unreachable {
                why: "deferred to agent mode".to_string(),
            },
            hint: Some(hint.into()),
            deferred: true,
        }
    }
}

/// What running an external probe produced; every decoder reads this, never the raw `Output`.
#[derive(Debug)]
enum Capture {
    Ran {
        success: bool,
        stdout: String,
        stderr: String,
    },
    ExecutableNotFound,
    Unreachable(String),
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
    name: &str,
    tool: &str,
    ls: &MiseLs,
    version_args: &[&str],
    decode: fn(&str) -> Option<String>,
    not_pinned_hint: &str,
) -> Finding {
    match mise_pin(ls, tool) {
        Err(why) => Finding::new(name, Status::Unreachable { why }),
        Ok(MisePin::NotPinned) => Finding::with_hint(name, Status::Missing, not_pinned_hint),
        Ok(MisePin::NotInstalled(version)) => Finding::with_hint(
            name,
            Status::Missing,
            format!("pinned at {version} but not installed; run: mise install"),
        ),
        Ok(MisePin::Installed(version)) => Finding::new(
            name,
            mise_pinned_version(tool, version_args, decode, &version),
        ),
    }
}

fn vendor_findings(ls: &MiseLs) -> Vec<Finding> {
    vec![
        mise_pinned_finding(
            "zmx resolves through mise at the pinned version",
            "zmx",
            ls,
            &["--version"],
            decode_zmx_version,
            "not pinned; pin it in mise.toml as `zmx`",
        ),
        mise_pinned_finding(
            "restate resolves through mise at the pinned version",
            "restate",
            ls,
            &["--version"],
            decode_restate_cli_version,
            "not pinned; pin it in mise.toml as `restate`",
        ),
        mise_pinned_finding(
            "restate-server resolves through mise at the pinned version",
            "restate-server",
            ls,
            &["--version"],
            decode_restate_server_version,
            "not pinned; pin it in mise.toml as `restate-server`",
        ),
        mise_pinned_finding(
            "claude resolves through mise at the pinned version",
            "claude",
            ls,
            &["--version"],
            decode_claude_version,
            "not pinned; pin it in mise.toml as `claude`",
        ),
        mise_pinned_finding(
            "codex resolves through mise at the pinned version",
            "codex",
            ls,
            &["--version"],
            decode_codex_version,
            "not pinned yet; pin it in mise.toml as `codex` or `npm:@openai/codex`",
        ),
        mise_pinned_finding(
            "entire resolves through mise at the pinned version",
            "entire",
            ls,
            &["--version"],
            decode_entire_version,
            "not pinned; pin it in mise.toml as `entire`",
        ),
        mise_pinned_finding(
            "cue resolves through mise at the pinned version",
            "cue",
            ls,
            &["version"],
            decode_cue_version,
            "not pinned; pin it in mise.toml as `cue`",
        ),
    ]
}

#[derive(Debug, PartialEq, Eq)]
enum AuthStatus {
    LoggedIn,
    LoggedOut,
}

fn auth_status_to_status(decoded: Option<&AuthStatus>) -> Status {
    match decoded {
        Some(AuthStatus::LoggedIn) => Status::Present,
        Some(AuthStatus::LoggedOut) => Status::Missing,
        None => Status::Unreachable {
            why: "unrecognised auth status output".to_string(),
        },
    }
}

fn decode_claude_auth_status(stdout: &str) -> Option<AuthStatus> {
    let value: serde_json::Value = serde_json::from_str(stdout).ok()?;
    let logged_in = value.get("loggedIn")?.as_bool()?;
    Some(if logged_in {
        AuthStatus::LoggedIn
    } else {
        AuthStatus::LoggedOut
    })
}

fn decode_entire_auth_status(stdout: &str) -> Option<AuthStatus> {
    let value: serde_json::Value = serde_json::from_str(stdout).ok()?;
    let logged_in = value.get("logged_in")?.as_bool()?;
    Some(if logged_in {
        AuthStatus::LoggedIn
    } else {
        AuthStatus::LoggedOut
    })
}

#[derive(Debug, PartialEq, Eq)]
enum KeychainListing {
    NoLoginKeychain,
    LoginKeychainPresent,
}

fn decode_keychain_listing(stdout: &str) -> Option<KeychainListing> {
    if stdout.trim().is_empty() {
        return None;
    }
    if stdout.contains("login.keychain") {
        Some(KeychainListing::LoginKeychainPresent)
    } else {
        Some(KeychainListing::NoLoginKeychain)
    }
}

/// Checked as whoever runs this (expected to be the developer), unlike `claude`/`codex` below.
fn entire_login_finding() -> Finding {
    let name = "entire logged in as the developer";
    match run_bounded(mise_command(&[
        "exec", "--", "entire", "auth", "status", "--json",
    ])) {
        Capture::ExecutableNotFound => Finding::new(
            name,
            Status::Unreachable {
                why: "mise is not on PATH".to_string(),
            },
        ),
        Capture::Unreachable(why) => Finding::new(name, Status::Unreachable { why }),
        Capture::Ran {
            success: false,
            stderr,
            ..
        } => Finding::new(
            name,
            Status::Unreachable {
                why: stderr
                    .lines()
                    .next()
                    .unwrap_or("entire auth status failed")
                    .to_string(),
            },
        ),
        Capture::Ran {
            success: true,
            stdout,
            ..
        } => Finding::new(
            name,
            auth_status_to_status(decode_entire_auth_status(&stdout).as_ref()),
        ),
    }
}

fn claude_login_finding(identity: &Identity) -> Finding {
    let name = "claude logged in";
    if identity.username != AGENT_USER_NAME {
        return Finding::deferred(
            name,
            format!("run as the operator, logged in as {AGENT_USER_NAME}: claude auth status"),
        );
    }
    match run_bounded(mise_command(&[
        "exec", "--", "claude", "auth", "status", "--json",
    ])) {
        Capture::ExecutableNotFound => Finding::new(
            name,
            Status::Unreachable {
                why: "mise is not on PATH".to_string(),
            },
        ),
        Capture::Unreachable(why) => Finding::new(name, Status::Unreachable { why }),
        Capture::Ran {
            success: false,
            stderr,
            ..
        } => Finding::new(
            name,
            Status::Unreachable {
                why: stderr
                    .lines()
                    .next()
                    .unwrap_or("claude auth status failed")
                    .to_string(),
            },
        ),
        Capture::Ran {
            success: true,
            stdout,
            ..
        } => Finding::new(
            name,
            auth_status_to_status(decode_claude_auth_status(&stdout).as_ref()),
        ),
    }
}

/// No codex binary exists to sample a real `login status` from, so this never classifies it.
fn codex_login_finding(identity: &Identity) -> Finding {
    let name = "codex logged in";
    if identity.username != AGENT_USER_NAME {
        return Finding::deferred(
            name,
            format!("run as the operator, logged in as {AGENT_USER_NAME}: codex login status"),
        );
    }
    match run_bounded(mise_command(&["exec", "--", "codex", "login", "status"])) {
        Capture::ExecutableNotFound => Finding::new(
            name,
            Status::Unreachable {
                why: "mise is not on PATH".to_string(),
            },
        ),
        Capture::Unreachable(why) => Finding::new(name, Status::Unreachable { why }),
        Capture::Ran {
            success: false,
            stderr,
            ..
        } => Finding::new(
            name,
            Status::Unreachable {
                why: stderr
                    .lines()
                    .next()
                    .unwrap_or("codex login status failed")
                    .to_string(),
            },
        ),
        Capture::Ran { success: true, .. } => Finding::new(
            name,
            Status::Unreachable {
                why: "no captured sample exists to decode codex login status output".to_string(),
            },
        ),
    }
}

fn keychain_listing_to_status(decoded: Option<&KeychainListing>) -> Status {
    match decoded {
        Some(KeychainListing::NoLoginKeychain) => Status::Present,
        Some(KeychainListing::LoginKeychainPresent) => Status::Wrong {
            found: "login keychain present".to_string(),
            wanted: "no login keychain".to_string(),
        },
        None => Status::Unreachable {
            why: "unrecognised security list-keychains output".to_string(),
        },
    }
}

fn keychain_finding(identity: &Identity) -> Finding {
    let name = "agent credential: login keychain";
    if identity.username != AGENT_USER_NAME {
        return Finding::deferred(
            name,
            format!("run as the operator, logged in as {AGENT_USER_NAME}: security list-keychains"),
        );
    }
    match run_bounded(plain_command("security", &["list-keychains"])) {
        Capture::ExecutableNotFound => Finding::new(
            name,
            Status::Unreachable {
                why: "security is not on PATH".to_string(),
            },
        ),
        Capture::Unreachable(why) => Finding::new(name, Status::Unreachable { why }),
        Capture::Ran {
            success: false,
            stderr,
            ..
        } => Finding::new(
            name,
            Status::Unreachable {
                why: stderr
                    .lines()
                    .next()
                    .unwrap_or("security list-keychains failed")
                    .to_string(),
            },
        ),
        Capture::Ran {
            success: true,
            stdout,
            ..
        } => Finding::new(
            name,
            keychain_listing_to_status(decode_keychain_listing(&stdout).as_ref()),
        ),
    }
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
}

fn decode_membership(stdout: &str) -> Option<MembershipOutcome> {
    match stdout.lines().next().unwrap_or_default().trim() {
        "user is a member of the group" => Some(MembershipOutcome::Member),
        "user is not a member of the group" => Some(MembershipOutcome::NotMember),
        "Group not found" => Some(MembershipOutcome::GroupNotFound),
        "User not found" => Some(MembershipOutcome::UserNotFound),
        _ => None,
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
        Capture::Ran { stdout, .. } => match decode_membership(&stdout) {
            Some(MembershipOutcome::Member) => Status::Present,
            Some(
                MembershipOutcome::NotMember
                | MembershipOutcome::GroupNotFound
                | MembershipOutcome::UserNotFound,
            ) => Status::Missing,
            None => Status::Unreachable {
                why: format!("unrecognised dsmemberutil output: {stdout:?}"),
            },
        },
    }
}

fn agent_home_unreachable(name: &str) -> Finding {
    Finding::new(
        name,
        Status::Unreachable {
            why: format!("agent user home directory unknown; run: dscl . -read /Users/{AGENT_USER_NAME} NFSHomeDirectory"),
        },
    )
}

fn credential_absence_finding(name: &str, home: Option<&str>, relative: &str) -> Finding {
    let Some(home) = home else {
        return agent_home_unreachable(name);
    };
    let path = Path::new(home).join(relative);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Finding::new(name, Status::Present)
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Finding::new(
            name,
            Status::Unreachable {
                why: format!(
                    "permission denied; run as the operator: ls -la {}",
                    path.display()
                ),
            },
        ),
        Err(error) => Finding::new(
            name,
            Status::Unreachable {
                why: error.to_string(),
            },
        ),
        Ok(_) => Finding::new(
            name,
            Status::Wrong {
                found: format!("{} exists", path.display()),
                wanted: "absent".to_string(),
            },
        ),
    }
}

/// Stats `path` first so a symlink to a FIFO cannot hang the open; reads bounded, erroring over `CREDENTIAL_FILE_MAX_BYTES` rather than truncating.
fn read_bounded_file(path: &Path) -> io::Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    let metadata = if metadata.file_type().is_symlink() {
        fs::metadata(path)?
    } else {
        metadata
    };
    if !metadata.is_file() {
        return Err(io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let mut file = fs::File::open(path)?;
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
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Err(Status::Unreachable {
            why: format!(
                "permission denied; run as the operator: cat {}",
                path.display()
            ),
        }),
        Err(error) => Err(Status::Unreachable {
            why: error.to_string(),
        }),
        Ok(text) => Ok(text.contains("[credential")),
    }
}

/// Checks `~/.gitconfig` and `~/.config/git/config`; the hint also names the system gitconfig, which this cannot inspect as the developer.
fn credential_gitconfig_finding(home: Option<&str>) -> Finding {
    let name = "agent credential: gitconfig credential helper";
    let hint = "also check the system gitconfig: git config --system --get-all credential.helper";
    let Some(home) = home else {
        return Finding::with_hint(name, agent_home_unreachable(name).status, hint);
    };
    for relative in [".gitconfig", ".config/git/config"] {
        match gitconfig_has_credential_helper(&Path::new(home).join(relative)) {
            Err(status) => return Finding::with_hint(name, status, hint),
            Ok(true) => {
                return Finding::with_hint(
                    name,
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
    Finding::with_hint(name, Status::Present, hint)
}

fn agent_user_findings() -> Vec<Finding> {
    let lookup = dscl_read(
        &format!("/Users/{AGENT_USER_NAME}"),
        Some("NFSHomeDirectory"),
    );
    let home = match &lookup {
        DsclLookup::Found(stdout) => dscl_value(stdout, "NFSHomeDirectory"),
        DsclLookup::NotFound | DsclLookup::Unreachable(_) => None,
    };
    let mut findings = vec![Finding::new("agent user exists", lookup_status(&lookup))];
    findings.push(credential_absence_finding(
        "agent credential: ~/.ssh",
        home.as_deref(),
        ".ssh",
    ));
    findings.push(credential_absence_finding(
        "agent credential: ~/.config/gh",
        home.as_deref(),
        ".config/gh",
    ));
    findings.push(credential_absence_finding(
        "agent credential: ~/.aws",
        home.as_deref(),
        ".aws",
    ));
    findings.push(credential_absence_finding(
        "agent credential: ~/.netrc",
        home.as_deref(),
        ".netrc",
    ));
    findings.push(credential_gitconfig_finding(home.as_deref()));
    findings
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

fn owner_uid_status(found: u32, wanted: Result<Vec<u32>, String>) -> Status {
    match wanted {
        Ok(candidates) if candidates.contains(&found) => Status::Present,
        Ok(candidates) => Status::Wrong {
            found: found.to_string(),
            wanted: candidates
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(" or "),
        },
        Err(why) => Status::Unreachable { why },
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

fn directory_kind_status(metadata: &fs::Metadata) -> Status {
    if metadata.is_dir() {
        return Status::Present;
    }
    let kind = if metadata.file_type().is_symlink() {
        "symlink"
    } else if metadata.is_file() {
        "file"
    } else {
        "other"
    };
    Status::Wrong {
        found: kind.to_string(),
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

fn directory_error_findings(label: &str, error: &io::Error, extra: &[&str]) -> Vec<Finding> {
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
    let mut findings = vec![Finding::new(format!("{label}: exists"), exists_status)];
    for name in extra {
        findings.push(Finding::new(
            format!("{label}: {name}"),
            Status::Unreachable { why: why.clone() },
        ));
    }
    findings
}

fn agent_socket_dir_findings(
    group_gid: Result<u32, String>,
    developer_uids: Result<Vec<u32>, String>,
) -> Vec<Finding> {
    let label = "agent socket directory";
    let metadata = match fs::symlink_metadata(AGENT_SOCKET_DIR) {
        Ok(metadata) => metadata,
        Err(error) => {
            return directory_error_findings(
                label,
                &error,
                &["is a directory", "owner uid", "owner gid", "mode"],
            )
        }
    };
    vec![
        Finding::new(format!("{label}: exists"), Status::Present),
        Finding::new(
            format!("{label}: is a directory"),
            directory_kind_status(&metadata),
        ),
        Finding::new(
            format!("{label}: owner uid"),
            owner_uid_status(metadata.uid(), developer_uids),
        ),
        Finding::new(
            format!("{label}: owner gid"),
            owner_status(metadata.gid(), group_gid),
        ),
        Finding::new(
            format!("{label}: mode"),
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

fn stat_core_socket_dir(path: &str, developer_uid: Result<u32, String>) -> Vec<Finding> {
    let label = "core socket directory";
    let mut findings = vec![Finding::new(
        format!("{label}: path fits the socket budget"),
        path_length_status(path),
    )];
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            findings.extend(directory_error_findings(
                label,
                &error,
                &["is a directory", "owner uid", "mode"],
            ));
            return findings;
        }
    };
    findings.push(Finding::new(format!("{label}: exists"), Status::Present));
    findings.push(Finding::new(
        format!("{label}: is a directory"),
        directory_kind_status(&metadata),
    ));
    findings.push(Finding::new(
        format!("{label}: owner uid"),
        owner_status(metadata.uid(), developer_uid),
    ));
    findings.push(Finding::new(
        format!("{label}: mode"),
        mode_status(metadata.permissions().mode() & 0o7777, CORE_SOCKET_DIR_MODE),
    ));
    findings
}

fn core_socket_dir_unreachable_findings(why: &str) -> Vec<Finding> {
    [
        "path fits the socket budget",
        "exists",
        "is a directory",
        "owner uid",
        "mode",
    ]
    .iter()
    .map(|suffix| {
        Finding::new(
            format!("core socket directory: {suffix}"),
            Status::Unreachable {
                why: why.to_string(),
            },
        )
    })
    .collect()
}

fn core_socket_findings(identity: &Result<Identity, String>) -> Vec<Finding> {
    let identity = match identity {
        Ok(identity) => identity,
        Err(why) => return core_socket_dir_unreachable_findings(why),
    };
    match resolve_home(&identity.username) {
        Ok(home) => stat_core_socket_dir(&core_socket_dir_path(&home), Ok(identity.uid)),
        Err(why) => core_socket_dir_unreachable_findings(&why),
    }
}

fn developer_uid_candidates(identity: &Identity) -> Result<Vec<u32>, String> {
    if identity.username == AGENT_USER_NAME {
        return Err(
            "cannot determine the developer's uid while running as the agent user".to_string(),
        );
    }
    Ok(vec![identity.uid, 0])
}

fn shared_group_findings(identity: &Result<Identity, String>) -> Vec<Finding> {
    let lookup = dscl_read(&format!("/Groups/{SHARED_GROUP_NAME}"), None);
    let mut findings = vec![Finding::new("shared group exists", lookup_status(&lookup))];
    findings.push(match identity {
        Ok(identity) => Finding::new(
            "developer is a member of the shared group",
            membership_status(&identity.username, SHARED_GROUP_NAME),
        ),
        Err(why) => Finding::new(
            "developer is a member of the shared group",
            Status::Unreachable { why: why.clone() },
        ),
    });
    findings.push(Finding::new(
        "agent user is a member of the shared group",
        membership_status(AGENT_USER_NAME, SHARED_GROUP_NAME),
    ));
    let developer_uids = match identity {
        Ok(identity) => developer_uid_candidates(identity),
        Err(why) => Err(why.clone()),
    };
    findings.extend(agent_socket_dir_findings(
        group_gid(&lookup),
        developer_uids,
    ));
    findings
}

fn all_findings() -> Vec<Finding> {
    let identity = current_identity();
    let mut findings = agent_user_findings();
    findings.extend(shared_group_findings(&identity));
    findings.extend(core_socket_findings(&identity));
    let ls = mise_ls();
    findings.extend(vendor_findings(&ls));
    findings.push(entire_login_finding());
    match &identity {
        Ok(identity) => {
            findings.push(claude_login_finding(identity));
            findings.push(codex_login_finding(identity));
            findings.push(keychain_finding(identity));
        }
        Err(why) => {
            findings.push(Finding::new(
                "claude logged in",
                Status::Unreachable { why: why.clone() },
            ));
            findings.push(Finding::new(
                "codex logged in",
                Status::Unreachable { why: why.clone() },
            ));
            findings.push(Finding::new(
                "agent credential: login keychain",
                Status::Unreachable { why: why.clone() },
            ));
        }
    }
    findings
}

fn print_findings(findings: &[Finding]) {
    for finding in findings {
        println!(
            "xtask setup: {} {}",
            if finding.status.is_pass() {
                "ok"
            } else {
                "FAIL"
            },
            finding.name
        );
        if !finding.status.is_pass() {
            println!("  {}", finding.status);
        }
        if let Some(hint) = &finding.hint {
            println!("  hint: {hint}");
        }
    }
}

/// The finish-style count and exit code; pure over `findings`, so testable without a probe.
fn summarize(findings: &[Finding]) -> i32 {
    let examined = findings.len();
    if examined == 0 {
        eprintln!("xtask setup: examined 0 preconditions; a check over nothing is a failure");
        return 1;
    }
    let failed = findings
        .iter()
        .filter(|finding| !finding.status.is_pass())
        .count();
    let deferred = findings.iter().filter(|finding| finding.deferred).count();
    println!("xtask setup: examined {examined} preconditions, {failed} not present");
    println!("xtask setup: {deferred} findings require the agent-side run (run `mise run setup` as {AGENT_USER_NAME})");
    i32::from(failed > 0)
}

pub fn run() -> i32 {
    let findings = all_findings();
    print_findings(&findings);
    summarize(&findings)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn decodes_membership_states_and_rejects_the_unrecognised() {
        assert_eq!(
            decode_membership("user is a member of the group\n"),
            Some(MembershipOutcome::Member)
        );
        assert_eq!(
            decode_membership("user is not a member of the group\n"),
            Some(MembershipOutcome::NotMember)
        );
        assert_eq!(
            decode_membership("Group not found\n"),
            Some(MembershipOutcome::GroupNotFound)
        );
        assert_eq!(
            decode_membership("User not found\n"),
            Some(MembershipOutcome::UserNotFound)
        );
        assert_eq!(decode_membership("garbage\n"), None);
    }

    #[test]
    fn decodes_id_output_and_rejects_the_empty_line() {
        assert_eq!(decode_id_output("501\n"), Some("501".to_string()));
        assert_eq!(decode_id_output("frits\n"), Some("frits".to_string()));
        assert_eq!(decode_id_output("\n"), None);
    }

    #[test]
    fn decodes_auth_status_json_per_tool() {
        let logged_in = r#"{"loggedIn": true, "email": "user@example.com"}"#;
        let logged_out = r#"{"loggedIn": false}"#;
        assert_eq!(
            decode_claude_auth_status(logged_in),
            Some(AuthStatus::LoggedIn)
        );
        assert_eq!(
            decode_claude_auth_status(logged_out),
            Some(AuthStatus::LoggedOut)
        );
        assert_eq!(decode_claude_auth_status("not json"), None);

        let entire_logged_in = r#"{"logged_in": true, "user": "github:example"}"#;
        let entire_logged_out = r#"{"logged_in": false}"#;
        assert_eq!(
            decode_entire_auth_status(entire_logged_in),
            Some(AuthStatus::LoggedIn)
        );
        assert_eq!(
            decode_entire_auth_status(entire_logged_out),
            Some(AuthStatus::LoggedOut)
        );
        assert_eq!(decode_entire_auth_status("not json"), None);
    }

    #[test]
    fn decodes_keychain_listing_and_rejects_empty_output() {
        let sample = "    \"/Users/frits/Library/Keychains/login.keychain-db\"\n    \"/Library/Keychains/System.keychain\"\n";
        assert_eq!(
            decode_keychain_listing(sample),
            Some(KeychainListing::LoginKeychainPresent)
        );
        let no_login = "    \"/Library/Keychains/System.keychain\"\n";
        assert_eq!(
            decode_keychain_listing(no_login),
            Some(KeychainListing::NoLoginKeychain)
        );
        assert_eq!(decode_keychain_listing(""), None);
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
    fn owner_uid_status_accepts_any_candidate() {
        assert_eq!(owner_uid_status(501, Ok(vec![501, 0])), Status::Present);
        assert_eq!(owner_uid_status(0, Ok(vec![501, 0])), Status::Present);
        assert_eq!(
            owner_uid_status(777, Ok(vec![501, 0])),
            Status::Wrong {
                found: "777".to_string(),
                wanted: "501 or 0".to_string()
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
    fn missing_agent_home_makes_every_credential_probe_unreachable() {
        let finding = credential_absence_finding("x", None, ".ssh");
        assert!(matches!(finding.status, Status::Unreachable { .. }));
        let finding = credential_gitconfig_finding(None);
        assert!(matches!(finding.status, Status::Unreachable { .. }));
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
    fn summarize_fails_on_zero_examined_and_on_any_non_present() {
        assert_eq!(summarize(&[]), 1);
        let all_present = [
            Finding::new("a", Status::Present),
            Finding::new("b", Status::Present),
        ];
        assert_eq!(summarize(&all_present), 0);
        let one_missing = [
            Finding::new("a", Status::Present),
            Finding::new("b", Status::Missing),
        ];
        assert_eq!(summarize(&one_missing), 1);
    }

    #[test]
    fn deferred_finding_is_a_failure_and_counted_as_deferred() {
        let finding = Finding::deferred("x", "run as the operator: codex login status");
        assert!(!finding.status.is_pass());
        assert!(finding.deferred);
    }
}

//! Operator precondition checks for running the factory on this machine (docs/slices.md,
//! "Operator prerequisites"). `run` never creates anything; a human with sudo or an
//! account login does that. It only reports what it finds, and a probe that cannot run
//! is `Unreachable`, never guessed as `Missing` or `Present`.

use std::env;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tycho_types::session::{SESSION_NAME_MAX_BYTES, SOCKET_PATH_MAX_BYTES};

pub const AGENT_USER_NAME: &str = "tycho-agent";
pub const SHARED_GROUP_NAME: &str = "tycho-zmx";
pub const AGENT_SOCKET_DIR: &str = "/Users/Shared/tycho-agent-zmx";
pub const CORE_SOCKET_DIR: &str = "/Users/Shared/tycho-core-zmx";
const AGENT_SOCKET_DIR_MODE: u32 = 0o2770;
const CORE_SOCKET_DIR_MODE: u32 = 0o0700;
/// What a socket path leaves for the directory once the longest session name and the
/// path separator are in it; derived from `tycho_types`, never assumed.
const SOCKET_DIR_MAX_BYTES: usize = SOCKET_PATH_MAX_BYTES
    .saturating_sub(1)
    .saturating_sub(SESSION_NAME_MAX_BYTES);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_OUTPUT_MAX_BYTES: usize = 1 << 16;
const CREDENTIAL_FILE_MAX_BYTES: u64 = 1 << 16;

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
}

impl Finding {
    fn new(name: impl Into<String>, status: Status) -> Self {
        Self {
            name: name.into(),
            status,
            hint: None,
        }
    }

    fn with_hint(name: impl Into<String>, status: Status, hint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status,
            hint: Some(hint.into()),
        }
    }
}

/// What running an external probe produced; every probe's own decoder reads this, never
/// the raw `Output`, so each decoder has one place that enumerates the tool's states.
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

/// Converts captured bytes to text, or `None` when they exceed `PROBE_OUTPUT_MAX_BYTES`;
/// exceeding the maximum is an error the caller reports, never a silent truncation.
fn bounded_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() > PROBE_OUTPUT_MAX_BYTES {
        None
    } else {
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

/// Runs `program` with a deadline; on timeout it kills the child by pid and reports
/// `Unreachable` rather than blocking forever.
fn run_bounded(program: &str, args: &[&str]) -> Capture {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Capture::ExecutableNotFound
        }
        Err(error) => return Capture::Unreachable(format!("failed to start {program}: {error}")),
    };
    let pid = child.id();
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let outcome = child.wait_with_output();
        drop(sender.send(outcome));
    });
    match receiver.recv_timeout(PROBE_TIMEOUT) {
        Ok(Ok(output)) => {
            let (Some(stdout), Some(stderr)) =
                (bounded_text(&output.stdout), bounded_text(&output.stderr))
            else {
                return Capture::Unreachable(format!(
                    "{program} output exceeded {PROBE_OUTPUT_MAX_BYTES} bytes"
                ));
            };
            Capture::Ran {
                success: output.status.success(),
                stdout,
                stderr,
            }
        }
        Ok(Err(error)) => Capture::Unreachable(format!("{program} wait failed: {error}")),
        Err(_) => {
            drop(Command::new("kill").args(["-9", &pid.to_string()]).status());
            Capture::Unreachable(format!("{program} did not finish within {PROBE_TIMEOUT:?}"))
        }
    }
}

// --- version decoders: one function per tool's `--version` output shape ---

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
    stdout
        .lines()
        .next()?
        .split_whitespace()
        .next()
        .map(str::to_string)
}

/// `mise exec`'s own failure text has exactly two states worth telling apart: the tool
/// has no installed version to resolve, or something else went wrong.
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

/// Classifies a decoded version string against an optional pin; `None` means the
/// decoder did not recognise the output's shape.
fn classify_version(
    found: Option<String>,
    tool: &str,
    raw: &str,
    wanted: Option<&str>,
) -> (Status, Option<String>) {
    let Some(found) = found else {
        return (
            Status::Unreachable {
                why: format!("unrecognised {tool} version output: {raw:?}"),
            },
            None,
        );
    };
    match wanted {
        Some(wanted) if found == wanted => (Status::Present, Some(found)),
        Some(wanted) => (
            Status::Wrong {
                found: found.clone(),
                wanted: wanted.to_string(),
            },
            Some(found),
        ),
        None => (Status::Present, Some(found)),
    }
}

/// Probes `mise exec -- <tool> <version_args>` and classifies it against an optional
/// pin. Returns the status plus the version string found, when one could be read.
/// `version_args` varies by tool: most take `--version`, `cue` takes the `version`
/// subcommand instead.
fn mise_pinned_version(
    tool: &str,
    version_args: &[&str],
    decode: fn(&str) -> Option<String>,
    wanted: Option<&str>,
) -> (Status, Option<String>) {
    let mut args = vec!["exec", "--", tool];
    args.extend_from_slice(version_args);
    match run_bounded("mise", &args) {
        Capture::ExecutableNotFound => (
            Status::Unreachable {
                why: "mise is not on PATH".to_string(),
            },
            None,
        ),
        Capture::Unreachable(why) => (Status::Unreachable { why }, None),
        Capture::Ran {
            success: false,
            stderr,
            ..
        } => match decode_mise_exec_failure(&stderr) {
            MiseFailure::ToolNotInstalled => (Status::Missing, None),
            MiseFailure::Other(why) => (Status::Unreachable { why }, None),
        },
        Capture::Ran {
            success: true,
            stdout,
            ..
        } => classify_version(decode(&stdout), tool, &stdout, wanted),
    }
}

fn mise_pinned_finding(
    name: &str,
    tool: &str,
    version_args: &[&str],
    decode: fn(&str) -> Option<String>,
    wanted: &str,
) -> Finding {
    let (status, _found) = mise_pinned_version(tool, version_args, decode, Some(wanted));
    Finding::new(name, status)
}

// --- dscl: the directory service the agent user, the shared group and their
// membership live in ---

#[derive(Debug)]
enum DsclLookup {
    Found(String),
    NotFound,
    Unreachable(String),
}

/// `dscl`'s own failure text has exactly two states worth telling apart: the record
/// does not exist, or something else went wrong.
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
    match run_bounded("dscl", &args) {
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

fn dscl_value(stdout: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}: ");
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .map(|value| value.trim().to_string())
}

fn lookup_status(lookup: &DsclLookup) -> Status {
    match lookup {
        DsclLookup::Found(_) => Status::Present,
        DsclLookup::NotFound => Status::Missing,
        DsclLookup::Unreachable(why) => Status::Unreachable { why: why.clone() },
    }
}

fn group_members(lookup: &DsclLookup) -> Vec<String> {
    match lookup {
        DsclLookup::Found(stdout) => dscl_value(stdout, "GroupMembership")
            .map(|value| value.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default(),
        DsclLookup::NotFound | DsclLookup::Unreachable(_) => Vec::new(),
    }
}

fn membership_finding(
    name: &str,
    lookup: &DsclLookup,
    members: &[String],
    username: &str,
) -> Finding {
    let status = match lookup {
        DsclLookup::Unreachable(why) => Status::Unreachable { why: why.clone() },
        _ if members.iter().any(|member| member == username) => Status::Present,
        DsclLookup::NotFound | DsclLookup::Found(_) => Status::Missing,
    };
    Finding::new(name, status)
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

// --- credentials: the agent user must hold none, and most of this is unreadable as
// the developer by design, which is reported as `Unreachable`, not guessed clean ---

fn agent_home_unreachable(name: &str) -> Finding {
    Finding::new(
        name,
        Status::Unreachable {
            why: format!(
                "agent user home directory unknown; run: dscl . -read /Users/{AGENT_USER_NAME} NFSHomeDirectory"
            ),
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

/// Reads `path` up to `CREDENTIAL_FILE_MAX_BYTES`; a file over that maximum is an error,
/// never a silent truncation, since a truncated read could miss a `[credential]` block.
fn read_bounded_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(CREDENTIAL_FILE_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > CREDENTIAL_FILE_MAX_BYTES {
        return Err(io::Error::other(format!(
            "{} exceeds {CREDENTIAL_FILE_MAX_BYTES} bytes",
            path.display()
        )));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn credential_gitconfig_finding(home: Option<&str>) -> Finding {
    let name = "agent credential: ~/.gitconfig credential helper";
    let Some(home) = home else {
        return agent_home_unreachable(name);
    };
    let path = Path::new(home).join(".gitconfig");
    let text = match read_bounded_file(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Finding::new(name, Status::Present)
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return Finding::new(
                name,
                Status::Unreachable {
                    why: format!(
                        "permission denied; run as the operator: cat {}",
                        path.display()
                    ),
                },
            )
        }
        Err(error) => {
            return Finding::new(
                name,
                Status::Unreachable {
                    why: error.to_string(),
                },
            )
        }
        Ok(text) => text,
    };
    if text.contains("[credential") {
        Finding::new(
            name,
            Status::Wrong {
                found: "credential helper configured".to_string(),
                wanted: "no credential helper".to_string(),
            },
        )
    } else {
        Finding::new(name, Status::Present)
    }
}

fn credential_keychain_finding() -> Finding {
    Finding::new(
        "agent credential: login keychain",
        Status::Unreachable {
            why: format!(
                "keychain access is scoped to a logged-in session; run as the operator, logged in as {AGENT_USER_NAME}: security list-keychains"
            ),
        },
    )
}

// --- socket directories: existence, ownership and mode, plus the length budget the
// longest session name leaves ---

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

/// `owner` compares against `gid` when `by_group` is true, otherwise against `uid`.
fn socket_dir_findings(
    label: &str,
    path: &str,
    wanted_mode: u32,
    by_group: bool,
    wanted: Result<u32, String>,
) -> Vec<Finding> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            let why = if error.kind() == io::ErrorKind::NotFound {
                "directory does not exist".to_string()
            } else {
                error.to_string()
            };
            let exists = if error.kind() == io::ErrorKind::NotFound {
                Status::Missing
            } else {
                Status::Unreachable { why: why.clone() }
            };
            return vec![
                Finding::new(format!("{label}: exists"), exists),
                Finding::new(
                    format!("{label}: owner"),
                    Status::Unreachable { why: why.clone() },
                ),
                Finding::new(format!("{label}: mode"), Status::Unreachable { why }),
            ];
        }
    };
    let found_owner = if by_group {
        metadata.gid()
    } else {
        metadata.uid()
    };
    vec![
        Finding::new(format!("{label}: exists"), Status::Present),
        Finding::new(format!("{label}: owner"), owner_status(found_owner, wanted)),
        Finding::new(
            format!("{label}: mode"),
            mode_status(metadata.permissions().mode() & 0o7777, wanted_mode),
        ),
    ]
}

fn socket_dir_length_finding(label: &str, path: &str) -> Finding {
    let length = path.len();
    let status = if length <= SOCKET_DIR_MAX_BYTES {
        Status::Present
    } else {
        Status::Wrong {
            found: format!("{length} bytes"),
            wanted: format!("<= {SOCKET_DIR_MAX_BYTES} bytes"),
        }
    };
    Finding::new(format!("{label}: path fits the socket budget"), status)
}

fn developer_username() -> Result<String, String> {
    env::var("USER").map_err(|_| "USER environment variable is not set".to_string())
}

fn developer_uid() -> Result<u32, String> {
    let home = env::var("HOME").map_err(|_| "HOME environment variable is not set".to_string())?;
    fs::metadata(&home)
        .map(|metadata| metadata.uid())
        .map_err(|error| format!("cannot stat {home}: {error}"))
}

// --- assembling every precondition ---

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
    findings.push(credential_keychain_finding());
    findings
}

fn shared_group_findings() -> Vec<Finding> {
    let lookup = dscl_read(&format!("/Groups/{SHARED_GROUP_NAME}"), None);
    let members = group_members(&lookup);
    let developer = developer_username();
    let mut findings = vec![Finding::new("shared group exists", lookup_status(&lookup))];
    findings.push(match &developer {
        Ok(username) => membership_finding(
            "developer is a member of the shared group",
            &lookup,
            &members,
            username,
        ),
        Err(why) => Finding::new(
            "developer is a member of the shared group",
            Status::Unreachable { why: why.clone() },
        ),
    });
    findings.push(membership_finding(
        "agent user is a member of the shared group",
        &lookup,
        &members,
        AGENT_USER_NAME,
    ));
    findings.push(socket_dir_length_finding(
        "agent socket directory",
        AGENT_SOCKET_DIR,
    ));
    findings.extend(socket_dir_findings(
        "agent socket directory",
        AGENT_SOCKET_DIR,
        AGENT_SOCKET_DIR_MODE,
        true,
        group_gid(&lookup),
    ));
    findings
}

fn core_socket_dir_findings() -> Vec<Finding> {
    let mut findings = socket_dir_findings(
        "core socket directory",
        CORE_SOCKET_DIR,
        CORE_SOCKET_DIR_MODE,
        false,
        developer_uid(),
    );
    let distinct = if AGENT_SOCKET_DIR == CORE_SOCKET_DIR {
        Status::Wrong {
            found: CORE_SOCKET_DIR.to_string(),
            wanted: "different from the agent socket directory".to_string(),
        }
    } else {
        Status::Present
    };
    findings.push(Finding::new(
        "core and agent socket directories are distinct",
        distinct,
    ));
    findings
}

fn claude_and_codex_findings() -> Vec<Finding> {
    let (claude_status, claude_found) =
        mise_pinned_version("claude", &["--version"], decode_claude_version, None);
    let claude = match claude_found {
        Some(found) => Finding::with_hint(
            "claude resolves through mise",
            claude_status,
            format!("found {found}"),
        ),
        None => Finding::new("claude resolves through mise", claude_status),
    };
    let (codex_status, _found) =
        mise_pinned_version("codex", &["--version"], decode_claude_version, None);
    let codex = if codex_status == Status::Missing {
        Finding::with_hint(
            "codex resolves through mise",
            codex_status,
            "not pinned yet; pin it in mise.toml as `codex` or `npm:@openai/codex`",
        )
    } else {
        Finding::new("codex resolves through mise", codex_status)
    };
    let login_state = Finding::with_hint(
        "agent user vendor login state",
        Status::Unreachable {
            why: "logged-in state is per account and cannot be checked as the developer".to_string(),
        },
        format!("run as the operator, logged in as {AGENT_USER_NAME}: claude /status; codex login status"),
    );
    vec![claude, codex, login_state]
}

fn vendor_findings() -> Vec<Finding> {
    let mut findings = vec![
        mise_pinned_finding(
            "zmx resolves through mise at the pinned version",
            "zmx",
            &["--version"],
            decode_zmx_version,
            "0.8.1",
        ),
        mise_pinned_finding(
            "restate resolves through mise at the pinned version",
            "restate",
            &["--version"],
            decode_restate_cli_version,
            "1.7.13",
        ),
        mise_pinned_finding(
            "restate-server resolves through mise at the pinned version",
            "restate-server",
            &["--version"],
            decode_restate_server_version,
            "1.7.13",
        ),
    ];
    findings.extend(claude_and_codex_findings());
    findings.push(mise_pinned_finding(
        "entire resolves through mise at the pinned version",
        "entire",
        &["--version"],
        decode_entire_version,
        "0.11.4",
    ));
    findings.push(mise_pinned_finding(
        "cue resolves through mise at the pinned version",
        "cue",
        &["version"],
        decode_cue_version,
        "0.17.1",
    ));
    findings
}

fn all_findings() -> Vec<Finding> {
    let mut findings = agent_user_findings();
    findings.extend(shared_group_findings());
    findings.extend(core_socket_dir_findings());
    findings.extend(vendor_findings());
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

/// The finish-style count and exit code; pure over `findings` so it is testable without
/// running any probe.
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
    println!("xtask setup: examined {examined} preconditions, {failed} not present");
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
        assert_eq!(decode_claude_version(""), None);
    }

    #[test]
    fn classifies_a_version_against_its_pin() {
        // The real global zmx on this machine (outside mise) resolves to 0.4.2.
        let found = decode_zmx_version(
            "zmx\t\t0.4.2\nghostty_vt\tghostty-1.3.0\nsocket_dir\t/Users/frits/.zmx\n",
        );
        assert_eq!(
            classify_version(found, "zmx", "zmx 0.4.2", Some("0.8.1")),
            (
                Status::Wrong {
                    found: "0.4.2".to_string(),
                    wanted: "0.8.1".to_string()
                },
                Some("0.4.2".to_string())
            )
        );
        assert_eq!(
            classify_version(None, "zmx", "garbage", Some("0.8.1")),
            (
                Status::Unreachable {
                    why: "unrecognised zmx version output: \"garbage\"".to_string()
                },
                None
            )
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
        assert!(AGENT_SOCKET_DIR.len() <= SOCKET_DIR_MAX_BYTES);
        assert!(CORE_SOCKET_DIR.len() <= SOCKET_DIR_MAX_BYTES);
        assert_eq!(
            socket_dir_length_finding("x", AGENT_SOCKET_DIR).status,
            Status::Present
        );
        let long = "/".to_string() + &"d".repeat(SOCKET_DIR_MAX_BYTES.saturating_add(1));
        assert!(matches!(
            socket_dir_length_finding("x", &long).status,
            Status::Wrong { .. }
        ));
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
    fn missing_agent_home_makes_every_credential_probe_unreachable() {
        let finding = credential_absence_finding("x", None, ".ssh");
        assert!(matches!(finding.status, Status::Unreachable { .. }));
        let finding = credential_gitconfig_finding(None);
        assert!(matches!(finding.status, Status::Unreachable { .. }));
    }
}

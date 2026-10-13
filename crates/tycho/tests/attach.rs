//! Attach tests for slice zero step 6. The agent user creates zmx sessions in the shared
//! socket directory; the developer attaches to one through a pty from `script` and types a
//! line, then has Ghostty open a tab running the attach through `osascript`, once from inside
//! a zmx session and once from a launchd agent. Each path is decoded into an enumerated
//! outcome, and an Automation consent prompt is a named state that could not look. macOS only,
//! run by `mise run attach-tests` from a terminal, where sudo asks for the developer's password.
#![allow(
    clippy::disallowed_methods,
    reason = "fixtures live in throwaway directories the developer created"
)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the evidence lines are the test's report for the pull request"
)]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers fail the test by panicking"
)]

use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nix::unistd::{access, AccessFlags, Group, User};
use tycho::agent_files::current_uid;
use tycho::command::{self, CommandError};
use tycho::config::{
    ToolPrefix, AGENT_SOCKET_DIR_DEFAULT, AGENT_USER_DEFAULT, TOOL_PREFIX_DEFAULT,
};
use tycho::zmx::{self, Presence, Zmx, SESSION_ENV};

const SUDO: &str = "/usr/bin/sudo";
const SCRIPT: &str = "/usr/bin/script";
const OSASCRIPT: &str = "/usr/bin/osascript";
const LAUNCHCTL: &str = "/bin/launchctl";
const GHOSTTY_APP: &str = "/Applications/Ghostty.app";
/// The group the developer and the agent share for the agent socket directory.
const SHARED_GROUP: &str = "tycho-zmx";
/// zmx 0.8.1 sets the log directory's mode from this and each log file's from the next; every
/// client appends to `logs/zmx.log` and the session's log, so both users need them writable.
const ZMX_DIR_MODE: &str = "0770";
const ZMX_LOG_MODE: &str = "0660";
const AGENT_PATH: &str = "PATH=/usr/bin:/bin";
/// Covers the operator typing the password at the first prompt.
const SUDO_TIMEOUT: Duration = Duration::from_secs(120);
const OUTPUT_MAX_BYTES: usize = 65_536;
const OUTPUT_FILE_MAX_BYTES: u64 = 65_536;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// An Automation consent dialog holds osascript until it is answered; past this the path
/// reads as unanswered.
const ANSWER_WAIT_MAX: Duration = Duration::from_secs(180);
const MARKER_WAIT_MAX: Duration = Duration::from_secs(30);
/// Lets `zmx attach` connect and set its terminal mode before the line is typed.
const ATTACH_SETTLE: Duration = Duration::from_secs(2);
const DETACH_WAIT_MAX: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const MARKER_MAX_BYTES: u64 = 4096;
const SHARED_ENTRIES_MAX: usize = 64;
const EVIDENCE_MAX_CHARS: usize = 400;
/// The agent-side shell's last line: who it ran as and what the script exited with.
const RUN_MARKER: &str = "tycho-attach";
const OPENED_PREFIX: &str = "opened terminal ";
/// Ctrl-\, zmx's detach key.
const DETACH_KEY: u8 = 0x1c;

/// The program of each agent-owned session: it reads one typed line, writes it to the marker
/// path, then sleeps, so a session the teardown never reaches ends on its own.
const READ_ONE_LINE: &str =
    "IFS= read -r line && printf \"%s\\n\" \"$line\" > \"$1\"; exec /bin/sleep 600";
/// Creates each named session as the agent in the shared directory. sudo leaves the umask at
/// 022, under which zmx creates the socket 0755 and the developer cannot connect.
const SPAWN_SESSIONS: &str = "umask 007; zmx=$1; export ZMX_DIR=\"$2\" ZMX_DIR_MODE=\"$3\" \
     ZMX_LOG_MODE=\"$4\"; program=$5; shift 5; status=0; \
     while [ $# -ge 2 ]; do \"$zmx\" run \"$1\" -d exec /bin/sh -c \"$program\" sh \"$2\" \
     < /dev/null || status=$?; shift 2; done; exit $status";
/// Ends each named session by name, never by pid, and removes its log.
const KILL_SESSIONS: &str = "zmx=$1; dir=$2; export ZMX_DIR=\"$2\"; shift 2; status=0; \
     for name in \"$@\"; do \"$zmx\" kill \"$name\" --force < /dev/null || status=$?; \
     /bin/rm -f \"$dir/logs/$name.log\"; done; exit $status";
/// Runs inside the developer's zmx session: osascript's output and exit status land in files.
const OSASCRIPT_IN_SESSION: &str =
    "/usr/bin/osascript \"$1\" \"$2\" \"$3\" > \"$4\" 2> \"$5\"; echo $? > \"$6\"";

/// Opens a Ghostty tab running the attach command, types the line into it, and prints the
/// tab's terminal id. A Ghostty that is not running is reported as -600, never launched.
const OPEN_TAB_SCRIPT: &str = r#"on run argv
	set attachCommand to item 1 of argv
	set typedLine to item 2 of argv
	if application id "com.mitchellh.ghostty" is not running then error "Ghostty is not running." number -600
	tell application id "com.mitchellh.ghostty"
		set surface to new surface configuration
		set command of surface to attachCommand
		if (count of windows) is 0 then
			set opened to selected tab of (new window with configuration surface)
		else
			set opened to new tab in front window with configuration surface
		end if
		set attached to focused terminal of opened
		delay 2
		input text typedLine to attached
		send key "enter" to attached
		return "opened terminal " & (id of attached)
	end tell
end run
"#;

fn deadline_after(wait: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(wait).unwrap_or(now)
}

fn cut(text: &str) -> String {
    text.chars().take(EVIDENCE_MAX_CHARS).collect()
}

/// Why the suite refuses to start, if it does.
const fn terminal_refusal(stdin_is_terminal: bool) -> Option<&'static str> {
    if stdin_is_terminal {
        None
    } else {
        Some(
            "attach: stdin is not a terminal. The agent's sessions are created through sudo, \
             which asks for the developer's password on the terminal, and the Ghostty paths \
             may raise Automation consent dialogs; run `mise run attach-tests` from Ghostty.",
        )
    }
}

/// How an agent-side run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AgentRun {
    Ran { exit: i32, stderr: String },
    CouldNotRun(String),
    Unrecognised(String),
}

fn wrap(script: &str) -> String {
    format!(
        "(\n{script}\n)\nrc=$?\nprintf '\\n{RUN_MARKER} uid=%s exit=%s\\n' \"$(/usr/bin/id -u)\" \"$rc\""
    )
}

/// Reads the marker line, which counts only as the last non-empty line.
fn read_run_marker(stdout: &str) -> Option<(u32, i32)> {
    let last = stdout.lines().rev().find(|line| !line.trim().is_empty())?;
    let rest = last.strip_prefix(RUN_MARKER)?.trim();
    let mut words = rest.split(' ');
    let uid = words.next()?.strip_prefix("uid=")?.parse().ok()?;
    let exit = words.next()?.strip_prefix("exit=")?.parse().ok()?;
    words.next().is_none().then_some((uid, exit))
}

fn decode_agent_run(stdout: &str, stderr: &str, agent_uid: u32) -> AgentRun {
    match read_run_marker(stdout) {
        Some((uid, exit)) if uid == agent_uid => AgentRun::Ran {
            exit,
            stderr: cut(stderr.trim()),
        },
        Some((uid, _)) => AgentRun::Unrecognised(format!("ran as uid {uid}, not the agent's")),
        None => stderr
            .lines()
            .find(|line| line.starts_with("sudo:"))
            .map_or_else(
                || AgentRun::Unrecognised(format!("no run report; stderr {}", cut(stderr.trim()))),
                |line| AgentRun::CouldNotRun(line.to_string()),
            ),
    }
}

#[derive(Debug, Clone)]
struct Agent {
    uid: u32,
    home: PathBuf,
}

/// Runs `script` with `arguments` as `$1`.. in a shell of the agent user, with an empty
/// environment, from `/`. The one place the identity switch is made: today through sudo,
/// which prompts on the terminal.
fn run_as_agent(agent: &Agent, script: &str, arguments: &[&str]) -> AgentRun {
    let home = format!("HOME={}", agent.home.display());
    let wrapped = wrap(script);
    let mut words = vec![
        "-u",
        AGENT_USER_DEFAULT,
        "-H",
        "--",
        "/usr/bin/env",
        "-i",
        home.as_str(),
        AGENT_PATH,
        "/bin/sh",
        "-c",
        wrapped.as_str(),
        RUN_MARKER,
    ];
    words.extend_from_slice(arguments);
    match command::run_status_from(
        Path::new(SUDO),
        &words,
        Path::new("/"),
        SUDO_TIMEOUT,
        OUTPUT_MAX_BYTES,
    ) {
        Ok(captured) => decode_agent_run(&captured.stdout, &captured.stderr, agent.uid),
        Err(error @ (CommandError::OutputTooLarge(..) | CommandError::NotUtf8(_))) => {
            AgentRun::Unrecognised(error.to_string())
        }
        Err(error) => AgentRun::CouldNotRun(error.to_string()),
    }
}

/// What `sudo -n` answered after `sudo -k` dropped any cached credential.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SudoProbe {
    PasswordRequired,
    NoPasswordRule,
    Refused(String),
    Unrecognised(String),
}

fn decode_sudo_probe(success: bool, stderr: &str) -> SudoProbe {
    if success {
        return SudoProbe::NoPasswordRule;
    }
    let first = stderr.lines().next().unwrap_or("").to_string();
    if first == "sudo: a password is required" {
        SudoProbe::PasswordRequired
    } else if first.starts_with("sudo:") {
        SudoProbe::Refused(first)
    } else {
        SudoProbe::Unrecognised(cut(stderr.trim()))
    }
}

/// Drops sudo's cached credential when the run ends, passed or failed.
struct ForgetSudo;

impl Drop for ForgetSudo {
    fn drop(&mut self) {
        match Command::new(SUDO).arg("-k").status() {
            Ok(status) if status.success() => println!("attach: sudo -k at the end of the run"),
            Ok(status) => eprintln!("attach: sudo -k at the end exited {status}"),
            Err(error) => eprintln!("attach: sudo -k at the end could not run: {error}"),
        }
    }
}

/// What the developer's `zmx list` of the shared directory says about one session.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Listed {
    Running {
        pid: u32,
    },
    Ended,
    Absent,
    /// zmx could not write a log file in the shared directory.
    AccessDenied(String),
    Unrecognised(String),
}

fn decode_listing(exit: Option<i32>, stdout: &str, stderr: &str, name: &str) -> Listed {
    match exit {
        Some(0) => {}
        Some(_) if stderr.contains("AccessDenied") => {
            return Listed::AccessDenied(cut(stderr.trim()));
        }
        _ => return Listed::Unrecognised(format!("exit {exit:?}: {}", cut(stderr.trim()))),
    }
    match zmx::decode_list(stdout) {
        Ok(entries) => match zmx::presence(&entries, name) {
            Presence::Running { pid, .. } => Listed::Running { pid },
            Presence::Ended { .. } => Listed::Ended,
            Presence::Absent => Listed::Absent,
            Presence::Unrecognised => Listed::Unrecognised(cut(stdout.trim())),
        },
        Err(error) => Listed::Unrecognised(format!("{error:?}")),
    }
}

/// zmx bound to the shared directory as the developer runs it.
#[derive(Debug, Clone)]
struct SharedZmx {
    binary: PathBuf,
    dir: String,
}

impl SharedZmx {
    const fn environment(&self) -> [(&str, &str); 3] {
        [
            ("ZMX_DIR", self.dir.as_str()),
            ("ZMX_DIR_MODE", ZMX_DIR_MODE),
            ("ZMX_LOG_MODE", ZMX_LOG_MODE),
        ]
    }

    fn listed(&self, name: &str) -> Listed {
        match command::run_status_capped(
            &self.binary,
            &["list"],
            &self.environment(),
            &[OsString::from(SESSION_ENV)],
            COMMAND_TIMEOUT,
            OUTPUT_MAX_BYTES,
        ) {
            Ok(captured) => decode_listing(
                captured.status.code(),
                &captured.stdout,
                &captured.stderr,
                name,
            ),
            Err(error) => Listed::Unrecognised(error.to_string()),
        }
    }

    /// The command a Ghostty tab runs: no inherited session, and no detach key on the outer
    /// client, as design section 12 names it.
    fn attach_command(&self, name: &str) -> String {
        format!(
            "/usr/bin/env -u {SESSION_ENV} ZMX_DIR={} ZMX_DIR_MODE={ZMX_DIR_MODE} \
             ZMX_LOG_MODE={ZMX_LOG_MODE} ZMX_NO_DETACH_KEY=1 {} attach {name}",
            self.dir,
            self.binary.display()
        )
    }
}

/// What a marker file says about a typed line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Marker {
    Absent,
    /// The agent's session wrote the line; terminal replies may precede it.
    Arrived(String),
    WrittenByAnother {
        uid: u32,
    },
    Garbled(String),
}

fn judge_marker(found: Option<(&str, u32)>, typed: &str, agent_uid: u32) -> Marker {
    match found {
        None => Marker::Absent,
        Some((_, uid)) if uid != agent_uid => Marker::WrittenByAnother { uid },
        Some((content, _)) if content.trim_end().ends_with(typed) => {
            Marker::Arrived(cut(content.trim_end()))
        }
        Some((content, _)) => Marker::Garbled(cut(content)),
    }
}

fn read_marker(path: &Path, typed: &str, agent_uid: u32) -> Marker {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Marker::Absent;
    };
    if !metadata.is_file() || metadata.len() > MARKER_MAX_BYTES {
        return Marker::Garbled(format!(
            "{:?}, {} bytes",
            metadata.file_type(),
            metadata.len()
        ));
    }
    let content = fs::read_to_string(path).unwrap_or_default();
    judge_marker(Some((&content, metadata.uid())), typed, agent_uid)
}

/// Waits for the marker within the bound; an absent marker after it stays absent.
fn wait_for_marker(path: &Path, typed: &str, agent_uid: u32) -> Marker {
    let deadline = deadline_after(MARKER_WAIT_MAX);
    while Instant::now() < deadline {
        match read_marker(path, typed, agent_uid) {
            Marker::Absent => std::thread::sleep(POLL_INTERVAL),
            other => return other,
        }
    }
    read_marker(path, typed, agent_uid)
}

/// The osascript's answer, decoded from its exit status and output.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    Opened {
        terminal: String,
    },
    /// -1743 not authorised, -1744 consent would be required.
    ConsentRequired {
        code: i32,
        line: String,
    },
    /// -600 not running, -1728 when the script cannot compile against an absent Ghostty,
    /// -10814 not installed.
    GhosttyUnavailable {
        code: i32,
        line: String,
    },
    /// -1712 Apple event timed out, or no answer within the suite's bound.
    Unanswered(String),
    Unrecognised(String),
}

/// The trailing `(-NNNN)` of an osascript error line.
fn error_code(line: &str) -> Option<i32> {
    let inner = line.trim_end().strip_suffix(')')?;
    let (_, number) = inner.rsplit_once('(')?;
    number.parse().ok()
}

fn decode_osascript(exit: Option<i32>, stdout: &str, stderr: &str) -> Answer {
    match exit {
        Some(0) => {
            let terminal = stdout.trim().strip_prefix(OPENED_PREFIX).unwrap_or("");
            if terminal.is_empty() || !stderr.trim().is_empty() {
                Answer::Unrecognised(format!("exit 0: {}", cut(stdout.trim())))
            } else {
                Answer::Opened {
                    terminal: terminal.to_string(),
                }
            }
        }
        Some(exit) => {
            let error = stderr
                .lines()
                .rev()
                .find(|line| line.contains(" error: "))
                .and_then(|line| error_code(line).map(|code| (code, line.trim().to_string())));
            match error {
                Some((code @ (-1743 | -1744), line)) => Answer::ConsentRequired { code, line },
                Some((-1728, line)) if !line.contains("syntax error: Can") => {
                    Answer::Unrecognised(format!("exit {exit}: {line}"))
                }
                Some((code @ (-600 | -1728 | -10814), line)) => {
                    Answer::GhosttyUnavailable { code, line }
                }
                Some((-1712, line)) => Answer::Unanswered(line),
                _ => Answer::Unrecognised(format!("exit {exit}: {}", cut(stderr.trim()))),
            }
        }
        None => Answer::Unrecognised(format!("no exit status; stderr {}", cut(stderr.trim()))),
    }
}

/// Where one attach path ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PathOutcome {
    /// The typed line reached the agent's session through the attached client.
    Attached(String),
    /// The path ran and did not reach the agent's session.
    Failed(String),
    /// Automation consent stands between the requester and Ghostty.
    ConsentRequired {
        requester: String,
        evidence: String,
    },
    GhosttyUnavailable(String),
    NoAnswer(String),
    CouldNotRun(String),
    Unrecognised(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Passed,
    Failed,
    CouldNotLook,
    Unrecognised,
}

const fn disposition(outcome: &PathOutcome) -> Disposition {
    match outcome {
        PathOutcome::Attached(_) => Disposition::Passed,
        PathOutcome::Failed(_) => Disposition::Failed,
        PathOutcome::ConsentRequired { .. }
        | PathOutcome::GhosttyUnavailable(_)
        | PathOutcome::NoAnswer(_)
        | PathOutcome::CouldNotRun(_) => Disposition::CouldNotLook,
        PathOutcome::Unrecognised(_) => Disposition::Unrecognised,
    }
}

const fn state_name(outcome: &PathOutcome) -> &'static str {
    match outcome {
        PathOutcome::Attached(_) => "attached",
        PathOutcome::Failed(_) => "failed",
        PathOutcome::ConsentRequired { .. } => "consent required",
        PathOutcome::GhosttyUnavailable(_) => "ghostty unavailable",
        PathOutcome::NoAnswer(_) => "no answer",
        PathOutcome::CouldNotRun(_) => "could not run",
        PathOutcome::Unrecognised(_) => "unrecognised",
    }
}

/// A tab path's outcome from the osascript's answer and, once a tab opened, the marker.
fn tab_outcome(answer: Answer, requester: &str, marker: impl FnOnce() -> Marker) -> PathOutcome {
    match answer {
        Answer::Opened { terminal } => match marker() {
            Marker::Arrived(content) => PathOutcome::Attached(format!(
                "Ghostty terminal {terminal}; the agent's session wrote {content:?}"
            )),
            other => PathOutcome::Failed(format!("Ghostty terminal {terminal} opened; {other:?}")),
        },
        Answer::ConsentRequired { line, .. } => PathOutcome::ConsentRequired {
            requester: requester.to_string(),
            evidence: line,
        },
        Answer::GhosttyUnavailable { line, .. } => PathOutcome::GhosttyUnavailable(line),
        Answer::Unanswered(line) => PathOutcome::NoAnswer(line),
        Answer::Unrecognised(text) => PathOutcome::Unrecognised(text),
    }
}

/// One line per path, the consent instructions, and the tally; returns the lines and the
/// number of failures, where examining nothing is one.
fn report_lines(results: &[(String, PathOutcome)]) -> (Vec<String>, usize) {
    if results.is_empty() {
        return (
            vec!["attach: examined 0 attach paths, which is a failure".to_string()],
            1,
        );
    }
    let mut lines = Vec::new();
    let mut failures = 0_usize;
    for (path, outcome) in results {
        lines.push(format!("attach: {path}: {outcome:?}"));
        if let PathOutcome::ConsentRequired { requester, .. } = outcome {
            lines.push(format!(
                "attach: {path}: consent required; open System Settings, Privacy & Security, \
                 Automation, turn on Ghostty under {requester}, then run \
                 `mise run attach-tests` again"
            ));
        }
        if disposition(outcome) != Disposition::Passed {
            failures = failures.saturating_add(1);
        }
    }
    let states: Vec<String> = results
        .iter()
        .map(|(path, outcome)| format!("{path} {}", state_name(outcome)))
        .collect();
    lines.push(format!(
        "attach: examined {} attach paths: {}; {failures} did not pass",
        results.len(),
        states.join(", ")
    ));
    (lines, failures)
}

/// The launchd user agent that runs the osascript once.
fn render_plist(label: &str, arguments: &[&str], stdout: &Path, stderr: &Path) -> String {
    let strings = arguments
        .iter()
        .map(|argument| format!("    <string>{}</string>", xml_escape(argument)))
        .collect::<Vec<String>>()
        .join("\n");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{strings}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{stdout}</string>
  <key>StandardErrorPath</key>
  <string>{stderr}</string>
</dict>
</plist>
"#,
        label = xml_escape(label),
        stdout = xml_escape(&stdout.display().to_string()),
        stderr = xml_escape(&stderr.display().to_string()),
    )
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// What `launchctl print gui/<uid>/<label>` says about the one-shot job.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Job {
    Running,
    /// Loaded and not yet run, or waiting to be spawned.
    Waiting,
    Exited(i32),
    NotLoaded,
    Unrecognised(String),
}

/// launchctl exits 113 for a service missing from a domain that exists.
const LAUNCHCTL_SERVICE_NOT_FOUND: i32 = 113;

/// Reads only the service's own top-level fields, which carry exactly one tab of indent.
fn decode_job(exit: Option<i32>, stdout: &str, stderr: &str) -> Job {
    match exit {
        Some(0) => {}
        Some(LAUNCHCTL_SERVICE_NOT_FOUND) => return Job::NotLoaded,
        _ => return Job::Unrecognised(format!("exit {exit:?}: {}", cut(stderr.trim()))),
    }
    let field = |key: &str| {
        stdout.lines().find_map(|line| {
            line.strip_prefix('\t')
                .filter(|rest| !rest.starts_with('\t'))
                .and_then(|rest| rest.strip_prefix(key))
                .and_then(|rest| rest.strip_prefix(" = "))
        })
    };
    match (field("state"), field("last exit code")) {
        (Some("running"), _) => Job::Running,
        (Some("spawn scheduled"), _) | (Some("not running"), None | Some("(never exited)")) => {
            Job::Waiting
        }
        (Some("not running"), Some(code)) => code.parse().map_or_else(
            |_| Job::Unrecognised(format!("last exit code = {code}")),
            Job::Exited,
        ),
        (state, code) => Job::Unrecognised(format!("state {state:?}, last exit code {code:?}")),
    }
}

/// What `launchctl bootout` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BootOut {
    Done,
    NotLoaded,
    Unrecognised(String),
}

fn decode_bootout(exit: Option<i32>, stderr: &str) -> BootOut {
    match exit {
        Some(0) => BootOut::Done,
        Some(3) if stderr.contains("No such process") => BootOut::NotLoaded,
        _ => BootOut::Unrecognised(format!("exit {exit:?}: {}", cut(stderr.trim()))),
    }
}

/// Who owns an entry of the shared directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    Agent,
    Developer,
    Other,
}

fn owner_of(uid: u32, agent_uid: u32) -> Owner {
    if uid == agent_uid {
        Owner::Agent
    } else if uid == current_uid() {
        Owner::Developer
    } else {
        Owner::Other
    }
}

/// One entry of the shared directory as the developer sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    path: String,
    owner: Owner,
    mode: u32,
    socket: bool,
    developer_writable: bool,
}

/// A socket the developer reaches through the group: connecting needs write on it.
const fn group_can_connect(mode: u32) -> bool {
    mode & 0o060 == 0o060
}

/// The entries the developer can write beyond the sockets, each named.
fn writable_beyond_sockets(entries: &[Entry]) -> Vec<String> {
    entries
        .iter()
        .filter(|entry| entry.developer_writable && !entry.socket)
        .map(|entry| entry.path.clone())
        .collect()
}

/// Every entry of the directory and of its subdirectories, one level down; more than
/// `SHARED_ENTRIES_MAX` entries is an error.
fn shared_entries(dir: &Path, agent_uid: u32) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        let listing =
            fs::read_dir(&next).map_err(|error| format!("{}: {error}", next.display()))?;
        for item in listing {
            let path = item
                .map_err(|error| format!("{}: {error}", next.display()))?
                .path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if metadata.is_dir() && next == dir {
                pending.push(path.clone());
            }
            entries.push(Entry {
                path: path
                    .strip_prefix(dir)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
                owner: owner_of(metadata.uid(), agent_uid),
                mode: metadata.permissions().mode() & 0o7777,
                socket: metadata.file_type().is_socket(),
                developer_writable: access(&path, AccessFlags::W_OK).is_ok(),
            });
            if entries.len() > SHARED_ENTRIES_MAX {
                return Err(format!(
                    "{} holds more than {SHARED_ENTRIES_MAX} entries",
                    dir.display()
                ));
            }
        }
    }
    Ok(entries)
}

/// The developer's throwaway directories and the agent's sessions, ended when the test ends.
struct Scratch {
    agent: Agent,
    shared: SharedZmx,
    /// The developer's own files and socket directory, mode 0700.
    private: PathBuf,
    /// Where the agent's sessions write their markers: the developer's, group-shared.
    drop: PathBuf,
    agent_sessions: Vec<String>,
    developer_sessions: Vec<(Zmx, String)>,
    launchd: Option<LaunchdJob>,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Some(job) = self.launchd.take() {
            job.remove();
        }
        for (zmx, name) in &self.developer_sessions {
            println!("teardown: developer session {name}: {:?}", zmx.kill(name));
        }
        if !self.agent_sessions.is_empty() {
            let mut arguments = vec![
                self.shared.binary.to_str().unwrap_or(""),
                self.shared.dir.as_str(),
            ];
            arguments.extend(self.agent_sessions.iter().map(String::as_str));
            let killed = run_as_agent(&self.agent, KILL_SESSIONS, &arguments);
            println!("teardown: killed the agent's sessions by name: {killed:?}");
        }
        for dir in [&self.private, &self.drop] {
            if let Err(error) = fs::remove_dir_all(dir) {
                eprintln!("teardown: cannot remove {}: {error}", dir.display());
            }
        }
    }
}

/// The throwaway launchd agent; booted out and its plist removed on teardown.
struct LaunchdJob {
    target: String,
    plist: PathBuf,
}

impl LaunchdJob {
    fn remove(&self) {
        let answer = Command::new(LAUNCHCTL)
            .args(["bootout", &self.target])
            .output()
            .map(|output| {
                decode_bootout(
                    output.status.code(),
                    &String::from_utf8_lossy(&output.stderr),
                )
            });
        println!("teardown: launchctl bootout {}: {answer:?}", self.target);
        if let Err(error) = fs::remove_file(&self.plist) {
            eprintln!("teardown: cannot remove {}: {error}", self.plist.display());
        }
    }
}

/// Refuses to start without a terminal, the agent user, the prefix's zmx, or the shared
/// directory, or with a sudo answer the station does not expect; prints what it saw.
fn preflight() -> (Agent, SharedZmx) {
    if let Some(refusal) = terminal_refusal(std::io::stdin().is_terminal()) {
        panic!("{refusal}");
    }
    let agent = User::from_name(AGENT_USER_DEFAULT)
        .unwrap_or_else(|error| panic!("attach: cannot look up {AGENT_USER_DEFAULT}: {error}"))
        .unwrap_or_else(|| {
            panic!("attach: no user {AGENT_USER_DEFAULT}; run `mise run provision-agent`")
        });
    let agent = Agent {
        uid: agent.uid.as_raw(),
        home: agent.dir,
    };
    let prefix = ToolPrefix::load(PathBuf::from(TOOL_PREFIX_DEFAULT))
        .unwrap_or_else(|error| panic!("attach: the shared tool prefix: {error}"));
    let binary = prefix
        .tool("zmx")
        .unwrap_or_else(|| panic!("attach: station.json records no zmx"))
        .to_path_buf();
    let dir = Path::new(AGENT_SOCKET_DIR_DEFAULT);
    let metadata = fs::symlink_metadata(dir).unwrap_or_else(|error| {
        panic!(
            "attach: {}: {error}; run `mise run provision-agent`",
            dir.display()
        )
    });
    let shared_gid = Group::from_name(SHARED_GROUP)
        .ok()
        .flatten()
        .map(|group| group.gid.as_raw());
    println!(
        "attach: zmx {}; {} owned by the developer {}, in group {SHARED_GROUP} {}, mode {:o}; {GHOSTTY_APP} {}",
        binary.display(),
        dir.display(),
        metadata.uid() == current_uid(),
        Some(metadata.gid()) == shared_gid,
        metadata.permissions().mode() & 0o7777,
        if Path::new(GHOSTTY_APP).exists() { "present" } else { "absent" }
    );
    match shared_entries(dir, agent.uid) {
        Ok(entries) => {
            for entry in entries {
                println!("attach: before the run, the shared directory holds {entry:?}");
            }
        }
        Err(error) => println!("attach: before the run, the shared directory: {error}"),
    }
    probe_sudo();
    (
        agent,
        SharedZmx {
            binary,
            dir: AGENT_SOCKET_DIR_DEFAULT.to_string(),
        },
    )
}

fn probe_sudo() {
    let forget = Command::new(SUDO).arg("-k").status().unwrap();
    assert!(forget.success(), "attach: sudo -k exited {forget}");
    let probe = Command::new(SUDO)
        .args(["-n", "-u", AGENT_USER_DEFAULT, "--", "/usr/bin/true"])
        .current_dir("/")
        .output()
        .unwrap();
    let seen = decode_sudo_probe(
        probe.status.success(),
        &String::from_utf8_lossy(&probe.stderr),
    );
    println!("attach: sudo -n -u {AGENT_USER_DEFAULT} after sudo -k: {seen:?}");
    match seen {
        SudoProbe::PasswordRequired => {
            println!("attach: sudo asks for the developer's password once, on this terminal");
        }
        SudoProbe::NoPasswordRule => panic!(
            "attach: a sudoers rule runs commands as {AGENT_USER_DEFAULT} with no password; \
             the station installs none while the identity switch is undecided"
        ),
        SudoProbe::Refused(line) => panic!("attach: could not look: {line}"),
        SudoProbe::Unrecognised(text) => panic!("attach: sudo -n answered {text}"),
    }
}

/// Creates a directory that must not exist yet, with `mode`, optionally in `group`.
fn fresh_dir(path: &Path, mode: u32, group: Option<&str>) {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .unwrap_or_else(|error| panic!("attach: cannot create {}: {error}", path.display()));
    if let Some(group) = group {
        let gid = Group::from_name(group)
            .unwrap()
            .unwrap_or_else(|| panic!("attach: no group {group}"))
            .gid;
        nix::unistd::chown(path, None, Some(gid)).unwrap();
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn scratch(agent: Agent, shared: SharedZmx) -> Scratch {
    let pid = std::process::id();
    let private = PathBuf::from(format!("/private/tmp/tycho-attach-{pid}"));
    let drop = PathBuf::from(format!("/private/tmp/tycho-attach-drop-{pid}"));
    fresh_dir(&private, 0o700, None);
    fresh_dir(&drop, 0o770, Some(SHARED_GROUP));
    fresh_dir(&private.join("zmx"), 0o700, None);
    fs::write(private.join("open-tab.applescript"), OPEN_TAB_SCRIPT).unwrap();
    Scratch {
        agent,
        shared,
        private,
        drop,
        agent_sessions: Vec::new(),
        developer_sessions: Vec::new(),
        launchd: None,
    }
}

/// The agent-owned session each path attaches to, and the line typed into it.
#[derive(Debug, Clone)]
struct Target {
    path: &'static str,
    session: String,
    marker: PathBuf,
    typed: String,
}

fn targets(drop: &Path) -> Vec<Target> {
    let pid = std::process::id();
    [
        ("developer pty", "p"),
        ("ghostty tab under zmx", "z"),
        ("ghostty tab under launchd", "l"),
    ]
    .into_iter()
    .map(|(path, suffix)| Target {
        path,
        session: format!("ta{pid}{suffix}"),
        marker: drop.join(suffix),
        typed: format!("typed-{pid}-{suffix}"),
    })
    .collect()
}

/// Creates every target session as the agent in one sudo call, so sudo asks once.
fn spawn_agent_sessions(scratch: &mut Scratch, targets: &[Target]) -> Result<(), String> {
    let binary = scratch.shared.binary.display().to_string();
    let markers: Vec<String> = targets
        .iter()
        .map(|target| target.marker.display().to_string())
        .collect();
    let mut arguments = vec![
        binary.as_str(),
        scratch.shared.dir.as_str(),
        ZMX_DIR_MODE,
        ZMX_LOG_MODE,
        READ_ONE_LINE,
    ];
    for (target, marker) in targets.iter().zip(&markers) {
        arguments.push(target.session.as_str());
        arguments.push(marker.as_str());
        scratch.agent_sessions.push(target.session.clone());
    }
    match run_as_agent(&scratch.agent, SPAWN_SESSIONS, &arguments) {
        AgentRun::Ran { exit: 0, .. } => Ok(()),
        AgentRun::Ran { exit, stderr } if stderr.contains("AccessDenied") => Err(format!(
            "could not run: the agent's zmx exited {exit} with {stderr}; a log file in \
             {}/logs belongs to another user or is not group-writable",
            scratch.shared.dir
        )),
        other => Err(format!("the agent's spawn: {other:?}")),
    }
}

/// Attaches as the developer through a pty from `script`, types the line, detaches, and
/// checks the session still runs.
fn attach_by_pty(shared: &SharedZmx, owner_uid: u32, target: &Target) -> PathOutcome {
    match shared.listed(&target.session) {
        Listed::Running { .. } => {}
        Listed::AccessDenied(text) => return PathOutcome::CouldNotRun(format!("zmx list: {text}")),
        other => return PathOutcome::Unrecognised(format!("before attach: {other:?}")),
    }
    let mut client = match Command::new(SCRIPT)
        .args(["-q", "/dev/null"])
        .arg(&shared.binary)
        .args(["attach", &target.session])
        .env_remove(SESSION_ENV)
        .envs(shared.environment())
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return PathOutcome::CouldNotRun(format!("{SCRIPT}: {error}")),
    };
    std::thread::sleep(ATTACH_SETTLE);
    let typed = type_into(&mut client, format!("{}\r", target.typed).as_bytes());
    let marker = wait_for_marker(&target.marker, &target.typed, owner_uid);
    let detached = type_into(&mut client, &[DETACH_KEY]).and_then(|()| wait_bounded(&mut client));
    let after = shared.listed(&target.session);
    match (typed, marker, detached, after) {
        (Ok(()), Marker::Arrived(content), Ok(status), Listed::Running { pid }) => {
            PathOutcome::Attached(format!(
                "the agent's session wrote {content:?}; the client detached with {status}; \
                 the session still runs as pid {pid}"
            ))
        }
        (typed, marker, detached, after) => PathOutcome::Failed(format!(
            "typed {typed:?}, marker {marker:?}, detach {detached:?}, then {after:?}"
        )),
    }
}

fn type_into(client: &mut Child, bytes: &[u8]) -> Result<(), String> {
    let stdin = client.stdin.as_mut().ok_or("no stdin")?;
    stdin
        .write_all(bytes)
        .and_then(|()| stdin.flush())
        .map_err(|error| error.to_string())
}

fn wait_bounded(client: &mut Child) -> Result<String, String> {
    let deadline = deadline_after(DETACH_WAIT_MAX);
    while Instant::now() < deadline {
        match client.try_wait() {
            Ok(Some(status)) => return Ok(status.to_string()),
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
            Err(error) => return Err(error.to_string()),
        }
    }
    drop(client.kill());
    drop(client.wait());
    Err(format!(
        "the client was still attached after {DETACH_WAIT_MAX:?}; killed"
    ))
}

/// Polls `answered` until it yields or the bound passes.
fn poll_for<T>(mut answered: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = deadline_after(ANSWER_WAIT_MAX);
    while Instant::now() < deadline {
        if let Some(value) = answered() {
            return Some(value);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    None
}

/// The terminal application a consent prompt under zmx names: the one running the suite.
fn requester_under_zmx() -> String {
    env::var("TERM_PROGRAM").map_or_else(
        |_| "the terminal application running the suite".to_string(),
        |name| format!("the terminal application running the suite ({name})"),
    )
}

/// Runs the osascript inside a developer zmx session and decodes what it answered.
fn tab_under_zmx(scratch: &mut Scratch, target: &Target) -> PathOutcome {
    let zmx = Zmx::new(&scratch.shared.binary, &scratch.private.join("zmx"));
    let name = format!("{}d", target.session);
    let files = ["zmx.out", "zmx.err", "zmx.status"].map(|file| scratch.private.join(file));
    let words: Vec<String> = [
        "exec".to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        OSASCRIPT_IN_SESSION.to_string(),
        "sh".to_string(),
        scratch
            .private
            .join("open-tab.applescript")
            .display()
            .to_string(),
        scratch.shared.attach_command(&target.session),
        target.typed.clone(),
    ]
    .into_iter()
    .chain(files.iter().map(|file| file.display().to_string()))
    .collect();
    if let Err(error) = zmx.run_words(&name, &words) {
        return PathOutcome::CouldNotRun(format!("zmx run {name}: {error}"));
    }
    scratch.developer_sessions.push((zmx, name));
    let Some(status) = poll_for(|| {
        fs::read_to_string(&files[2])
            .ok()
            .and_then(|text| text.trim().parse::<i32>().ok())
    }) else {
        return PathOutcome::NoAnswer(format!(
            "osascript gave no answer in {ANSWER_WAIT_MAX:?}; a consent dialog may be open"
        ));
    };
    let answer = answer_from_files(status, &files[0], &files[1]);
    println!("attach: under zmx, osascript answered {answer:?}");
    tab_outcome(answer, &requester_under_zmx(), || {
        wait_for_marker(&target.marker, &target.typed, scratch.agent.uid)
    })
}

/// Writes the job's plist, new and never through a link, and bootstraps it in the GUI
/// domain; the job is booted out and the plist removed on teardown.
fn install_job(
    scratch: &mut Scratch,
    target: &Target,
    outputs: &[PathBuf; 2],
) -> Result<String, PathOutcome> {
    let label = format!("tycho-attach-test-{}", std::process::id());
    let home = PathBuf::from(env::var_os("HOME").unwrap());
    let plist = home
        .join("Library/LaunchAgents")
        .join(format!("{label}.plist"));
    let script = scratch
        .private
        .join("open-tab.applescript")
        .display()
        .to_string();
    let attach = scratch.shared.attach_command(&target.session);
    let arguments = [
        OSASCRIPT,
        script.as_str(),
        attach.as_str(),
        target.typed.as_str(),
    ];
    let rendered = render_plist(&label, &arguments, &outputs[0], &outputs[1]);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&plist)
        .and_then(|mut file| file.write_all(rendered.as_bytes()))
        .map_err(|error| PathOutcome::CouldNotRun(format!("{}: {error}", plist.display())))?;
    let domain = format!("gui/{}", current_uid());
    let job = format!("{domain}/{label}");
    scratch.launchd = Some(LaunchdJob {
        target: job.clone(),
        plist: plist.clone(),
    });
    let plist_text = plist.display().to_string();
    match command::run_status(
        Path::new(LAUNCHCTL),
        &["bootstrap", &domain, &plist_text],
        &[],
        COMMAND_TIMEOUT,
    ) {
        Ok(captured) if captured.status.success() => Ok(job),
        Ok(captured) => Err(PathOutcome::CouldNotRun(format!(
            "launchctl bootstrap: {}",
            cut(captured.stderr.trim())
        ))),
        Err(error) => Err(PathOutcome::CouldNotRun(format!(
            "launchctl bootstrap: {error}"
        ))),
    }
}

/// Waits for the one-shot job to exit and returns its exit code.
fn wait_for_job(job: &str) -> Result<i32, PathOutcome> {
    let answered = poll_for(|| match job_state(job) {
        Job::Exited(code) => Some(Ok(code)),
        Job::Running | Job::Waiting => None,
        other => Some(Err(other)),
    });
    match answered {
        Some(Ok(code)) => Ok(code),
        Some(Err(other)) => Err(PathOutcome::Unrecognised(format!(
            "launchctl print: {other:?}"
        ))),
        None => Err(PathOutcome::NoAnswer(format!(
            "the launchd agent's osascript gave no answer in {ANSWER_WAIT_MAX:?}; a consent \
             dialog may be open"
        ))),
    }
}

/// The osascript's answer from its exit status and its output files; an output file over
/// `OUTPUT_FILE_MAX_BYTES` is unrecognised, never cut.
fn answer_from_files(exit: i32, stdout: &Path, stderr: &Path) -> Answer {
    let read = |path: &Path| match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.len() > OUTPUT_FILE_MAX_BYTES => Err(format!(
            "{} is over {OUTPUT_MAX_BYTES} bytes",
            path.display()
        )),
        Ok(_) => fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(format!("{}: {error}", path.display())),
    };
    match (read(stdout), read(stderr)) {
        (Ok(out), Ok(err)) => decode_osascript(Some(exit), &out, &err),
        (Err(error), _) | (_, Err(error)) => Answer::Unrecognised(error),
    }
}

/// Runs the osascript as a one-shot launchd user agent and decodes what it answered.
fn tab_under_launchd(scratch: &mut Scratch, target: &Target) -> PathOutcome {
    let outputs = ["launchd.out", "launchd.err"].map(|file| scratch.private.join(file));
    let exit = match install_job(scratch, target, &outputs).and_then(|job| wait_for_job(&job)) {
        Ok(exit) => exit,
        Err(outcome) => return outcome,
    };
    let answer = answer_from_files(exit, &outputs[0], &outputs[1]);
    println!("attach: under launchd, osascript answered {answer:?}");
    tab_outcome(answer, "osascript (the launchd agent's program)", || {
        wait_for_marker(&target.marker, &target.typed, scratch.agent.uid)
    })
}

fn job_state(target: &str) -> Job {
    match command::run_status(
        Path::new(LAUNCHCTL),
        &["print", target],
        &[],
        COMMAND_TIMEOUT,
    ) {
        Ok(captured) => decode_job(captured.status.code(), &captured.stdout, &captured.stderr),
        Err(error) => Job::Unrecognised(error.to_string()),
    }
}

/// Prints every entry of the shared directory with the agent's sessions in it.
fn record_shared_modes(scratch: &Scratch) {
    let entries = match shared_entries(Path::new(&scratch.shared.dir), scratch.agent.uid) {
        Ok(entries) => entries,
        Err(error) => {
            println!("attach: the shared directory with the sessions in it: {error}");
            return;
        }
    };
    for entry in &entries {
        println!(
            "attach: shared entry {} owner {:?} mode {:o} socket {} developer-writable {}",
            entry.path, entry.owner, entry.mode, entry.socket, entry.developer_writable
        );
        if entry.socket && !group_can_connect(entry.mode) {
            println!("attach:   the group cannot connect to {}", entry.path);
        }
    }
    println!(
        "attach: measured: beyond the sockets the developer can write {:?}; zmx 0.8.1 appends \
         to logs/zmx.log and the session's log on every list and attach",
        writable_beyond_sockets(&entries)
    );
}

#[test]
#[ignore = "creates sessions as the agent user through sudo and drives Ghostty; run with mise run attach-tests from a Ghostty terminal"]
fn a_developer_tab_attaches_to_an_agent_owned_session() {
    let (agent, shared) = preflight();
    let _forget = ForgetSudo;
    let mut scratch = scratch(agent, shared);
    let targets = targets(&scratch.drop);
    let mut results: Vec<(String, PathOutcome)> = Vec::new();
    match spawn_agent_sessions(&mut scratch, &targets) {
        Ok(()) => {
            record_shared_modes(&scratch);
            for target in &targets {
                let outcome = match target.path {
                    "developer pty" => attach_by_pty(&scratch.shared, scratch.agent.uid, target),
                    "ghostty tab under zmx" => tab_under_zmx(&mut scratch, target),
                    _ => tab_under_launchd(&mut scratch, target),
                };
                results.push((target.path.to_string(), outcome));
            }
        }
        Err(reason) => {
            for target in &targets {
                results.push((
                    target.path.to_string(),
                    PathOutcome::CouldNotRun(reason.clone()),
                ));
            }
        }
    }
    let (lines, failures) = report_lines(&results);
    for line in &lines {
        println!("{line}");
    }
    drop(scratch);
    assert_eq!(
        failures, 0,
        "{failures} attach paths did not attach; see the lines above"
    );
}

/// The pty path and the spawn script against sessions the developer owns, in a private
/// socket directory: no sudo and no Ghostty, so the mechanics are checked apart from the
/// identity switch.
#[test]
#[ignore = "runs zmx and script; run with mise run attach-tests"]
fn a_client_through_a_pty_reaches_a_developer_session_and_detaches() {
    let pid = std::process::id();
    let root = PathBuf::from(format!("/private/tmp/tycho-attach-self-{pid}"));
    fresh_dir(&root, 0o700, None);
    let socket_dir = root.join("zmx");
    fresh_dir(&socket_dir, 0o700, None);
    let binary = mise_zmx();
    let shared = SharedZmx {
        binary: binary.clone(),
        dir: socket_dir.display().to_string(),
    };
    let target = Target {
        path: "developer pty",
        session: format!("ts{pid}p"),
        marker: root.join("p"),
        typed: format!("typed-{pid}-p"),
    };
    let spawn_arguments = [
        binary.to_str().unwrap(),
        shared.dir.as_str(),
        ZMX_DIR_MODE,
        ZMX_LOG_MODE,
        READ_ONE_LINE,
        target.session.as_str(),
        target.marker.to_str().unwrap(),
    ];
    let spawned = Command::new("/bin/sh")
        .args(["-c", SPAWN_SESSIONS, RUN_MARKER])
        .args(spawn_arguments)
        .env_remove(SESSION_ENV)
        .current_dir("/")
        .status()
        .unwrap();
    let outcome = attach_by_pty(&shared, current_uid(), &target);
    let socket = fs::symlink_metadata(socket_dir.join(&target.session))
        .map(|metadata| format!("{:o}", metadata.permissions().mode() & 0o777));
    let killed = Command::new("/bin/sh")
        .args([
            "-c",
            KILL_SESSIONS,
            RUN_MARKER,
            binary.to_str().unwrap(),
            &shared.dir,
            &target.session,
        ])
        .env_remove(SESSION_ENV)
        .status()
        .unwrap();
    let left = shared.listed(&target.session);
    fs::remove_dir_all(&root).unwrap();
    println!("attach: self-check: spawn {spawned}, socket mode {socket:?}, {outcome:?}, kill {killed}, then {left:?}");
    assert!(spawned.success());
    assert_eq!(
        socket.unwrap(),
        "770",
        "umask 007 makes the socket group-connectable"
    );
    assert!(matches!(outcome, PathOutcome::Attached(_)), "{outcome:?}");
    assert!(killed.success());
    assert_eq!(left, Listed::Absent, "the kill by name ended the session");
}

/// The developer's pinned zmx, which is the version the prefix holds.
fn mise_zmx() -> PathBuf {
    let output = Command::new("mise")
        .args(["which", "zmx"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mise which zmx: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

#[cfg(test)]
mod decoders {
    //! Samples captured on macOS 26 with osascript, launchctl and zmx 0.8.1 as the developer;
    //! the -1743 and -1744 lines are the documented form, since a refusal cannot be produced
    //! without answering a consent dialog.
    use super::*;

    const AGENT: u32 = 503;

    #[test]
    fn the_suite_refuses_to_start_without_a_terminal() {
        let refusal = terminal_refusal(false).unwrap();
        assert!(refusal.contains("not a terminal"), "{refusal}");
        assert!(refusal.contains("mise run attach-tests"), "{refusal}");
        assert_eq!(terminal_refusal(true), None);
    }

    #[test]
    fn an_opened_tab_is_read_from_stdout() {
        assert_eq!(
            decode_osascript(Some(0), "opened terminal 6F1C-22\n", ""),
            Answer::Opened {
                terminal: "6F1C-22".to_string()
            }
        );
        for (stdout, stderr) in [
            ("", ""),
            ("something else\n", ""),
            ("opened terminal 1\n", "warning\n"),
        ] {
            assert!(
                matches!(
                    decode_osascript(Some(0), stdout, stderr),
                    Answer::Unrecognised(_)
                ),
                "{stdout:?} {stderr:?}"
            );
        }
    }

    #[test]
    fn each_error_code_maps_to_its_state() {
        let samples = [
            (
                "/tmp/open-tab.applescript:18:67: execution error: Not authorized to send Apple events to Ghostty. (-1743)\n",
                "consent",
            ),
            ("execution error: Ghostty got an error: Consent would be required. (-1744)\n", "consent"),
            ("6:31: execution error: Ghostty is not running. (-600)\n", "unavailable"),
            ("5:42: syntax error: Can\u{2019}t get application id \"dev.tycho.absent-app\". (-1728)\n", "unavailable"),
            ("execution error: Ghostty got an error: AppleEvent timed out. (-1712)\n", "no answer"),
            (
                "/tmp/open-tab.applescript:15:43: execution error: Ghostty got an error: Can\u{2019}t get terminal id \"6F1C\". (-1728)\n",
                "unrecognised",
            ),
            ("6:9: execution error: x (-2753)\n", "unrecognised"),
            ("osascript: something without a code\n", "unrecognised"),
        ];
        let mut examined = 0_usize;
        for (stderr, expected) in samples {
            let state = match decode_osascript(Some(1), "", stderr) {
                Answer::ConsentRequired { .. } => "consent",
                Answer::GhosttyUnavailable { .. } => "unavailable",
                Answer::Unanswered(_) => "no answer",
                Answer::Unrecognised(_) => "unrecognised",
                Answer::Opened { .. } => "opened",
            };
            assert_eq!(state, expected, "{stderr}");
            examined = examined.saturating_add(1);
        }
        assert_eq!(examined, 8);
        assert!(matches!(
            decode_osascript(None, "", ""),
            Answer::Unrecognised(_)
        ));
    }

    #[test]
    fn a_tab_passes_only_when_the_agents_session_wrote_the_typed_line() {
        let opened = || Answer::Opened {
            terminal: "T".to_string(),
        };
        let arrived = tab_outcome(opened(), "x", || Marker::Arrived("typed-1-z".to_string()));
        assert_eq!(disposition(&arrived), Disposition::Passed);
        for marker in [
            Marker::Absent,
            Marker::WrittenByAnother { uid: 501 },
            Marker::Garbled("?".to_string()),
        ] {
            let outcome = tab_outcome(opened(), "x", || marker.clone());
            assert_eq!(disposition(&outcome), Disposition::Failed, "{marker:?}");
        }
        let consent = tab_outcome(
            Answer::ConsentRequired {
                code: -1743,
                line: "Not authorized".to_string(),
            },
            "osascript",
            || panic!("no marker is read without a tab"),
        );
        assert_eq!(disposition(&consent), Disposition::CouldNotLook);
    }

    #[test]
    fn the_marker_must_be_the_agents_and_end_with_the_typed_line() {
        assert_eq!(judge_marker(None, "typed-1-p", AGENT), Marker::Absent);
        assert_eq!(
            judge_marker(Some(("typed-1-p\n", AGENT)), "typed-1-p", AGENT),
            Marker::Arrived("typed-1-p".to_string())
        );
        assert_eq!(
            judge_marker(Some(("\u{1b}[?1;2ctyped-1-p\n", AGENT)), "typed-1-p", AGENT),
            Marker::Arrived("\u{1b}[?1;2ctyped-1-p".to_string())
        );
        assert_eq!(
            judge_marker(Some(("typed-1-p\n", 501)), "typed-1-p", AGENT),
            Marker::WrittenByAnother { uid: 501 }
        );
        assert!(matches!(
            judge_marker(Some(("typed-1-\n", AGENT)), "typed-1-p", AGENT),
            Marker::Garbled(_)
        ));
    }

    #[test]
    fn the_agent_run_must_report_the_agents_uid() {
        let ran = format!("\n{RUN_MARKER} uid={AGENT} exit=0\n");
        assert_eq!(
            decode_agent_run(&ran, "", AGENT),
            AgentRun::Ran {
                exit: 0,
                stderr: String::new()
            }
        );
        assert!(matches!(
            decode_agent_run(&format!("{RUN_MARKER} uid=501 exit=0\n"), "", AGENT),
            AgentRun::Unrecognised(_)
        ));
        assert!(matches!(
            decode_agent_run("", "sudo: a password is required\n", AGENT),
            AgentRun::CouldNotRun(_)
        ));
        assert!(matches!(
            decode_agent_run("partial", "", AGENT),
            AgentRun::Unrecognised(_)
        ));
        let output = Command::new("/bin/sh")
            .args(["-c", &wrap("exit 3"), RUN_MARKER])
            .output()
            .unwrap();
        assert_eq!(
            read_run_marker(&String::from_utf8(output.stdout).unwrap()),
            Some((current_uid(), 3))
        );
    }

    const LISTED: &str =
        "  name=ta123p\tpid=70267\tclients=0\tcreated=1791862732\tcwd=file://host/\n";

    #[test]
    fn the_listing_reuses_the_zmx_decoder_and_names_access_denied() {
        assert_eq!(
            decode_listing(Some(0), LISTED, "", "ta123p"),
            Listed::Running { pid: 70267 }
        );
        assert_eq!(
            decode_listing(Some(0), LISTED, "", "ta123z"),
            Listed::Absent
        );
        assert!(matches!(
            decode_listing(Some(0), &format!("{LISTED}garbage\n"), "", "ta123p"),
            Listed::Unrecognised(_)
        ));
        assert!(matches!(
            decode_listing(
                Some(1),
                "",
                "\u{1b}[31merror\u{1b}[0m: AccessDenied\n",
                "ta123p"
            ),
            Listed::AccessDenied(_)
        ));
        assert!(matches!(
            decode_listing(Some(1), "", "error: other\n", "ta123p"),
            Listed::Unrecognised(_)
        ));
        assert!(matches!(
            decode_listing(None, "", "", "ta123p"),
            Listed::Unrecognised(_)
        ));
    }

    const EXITED: &str = include_str!("attach/launchctl-print-exited.txt");
    const RUNNING: &str = include_str!("../src/fixtures/launchctl-print-running.txt");
    const SCHEDULED: &str = include_str!("../src/fixtures/launchctl-print-scheduled.txt");
    const NOT_FOUND: &str = include_str!("../src/fixtures/launchctl-print-113.txt");

    #[test]
    fn the_job_state_is_read_from_launchctl_print() {
        assert_eq!(decode_job(Some(0), EXITED, ""), Job::Exited(3));
        assert_eq!(decode_job(Some(0), RUNNING, ""), Job::Running);
        assert_eq!(decode_job(Some(0), SCHEDULED, ""), Job::Waiting);
        assert_eq!(decode_job(Some(113), "", NOT_FOUND), Job::NotLoaded);
        let never = EXITED.replace("\tlast exit code = 3", "\tlast exit code = (never exited)");
        assert_eq!(decode_job(Some(0), &never, ""), Job::Waiting);
        let odd = EXITED.replace("\tlast exit code = 3", "\tlast exit code = three");
        assert!(matches!(
            decode_job(Some(0), &odd, ""),
            Job::Unrecognised(_)
        ));
        assert!(matches!(
            decode_job(Some(112), "", "Bad request.\n"),
            Job::Unrecognised(_)
        ));
        assert!(matches!(decode_job(Some(0), "", ""), Job::Unrecognised(_)));
    }

    #[test]
    fn bootout_tells_a_gone_job_from_a_refusal() {
        assert_eq!(decode_bootout(Some(0), ""), BootOut::Done);
        assert_eq!(
            decode_bootout(Some(3), "Boot-out failed: 3: No such process\n"),
            BootOut::NotLoaded
        );
        assert!(matches!(
            decode_bootout(Some(5), "Bootstrap failed: 5: Input/output error\n"),
            BootOut::Unrecognised(_)
        ));
    }

    #[test]
    fn the_plist_runs_the_program_once_with_escaped_arguments() {
        let rendered = render_plist(
            "tycho-attach-test-1",
            &[
                OSASCRIPT,
                "/tmp/a.applescript",
                "env A=1 zmx attach x",
                "a<b&c",
            ],
            Path::new("/tmp/o"),
            Path::new("/tmp/e"),
        );
        assert!(rendered.contains("<string>tycho-attach-test-1</string>"));
        assert!(rendered.contains(
            "<array>\n    <string>/usr/bin/osascript</string>\n    <string>/tmp/a.applescript</string>\n    <string>env A=1 zmx attach x</string>\n    <string>a&lt;b&amp;c</string>\n  </array>"
        ));
        assert!(rendered.contains("<key>RunAtLoad</key>\n  <true/>"));
        assert!(!rendered.contains("KeepAlive"), "the job runs once");
        assert!(rendered.contains("<key>StandardErrorPath</key>\n  <string>/tmp/e</string>"));
    }

    #[test]
    fn a_report_counts_what_it_examined_and_names_the_consent_path() {
        let results = vec![
            (
                "developer pty".to_string(),
                PathOutcome::Attached("wrote".to_string()),
            ),
            (
                "ghostty tab under launchd".to_string(),
                PathOutcome::ConsentRequired {
                    requester: "osascript".to_string(),
                    evidence: "(-1743)".to_string(),
                },
            ),
            (
                "ghostty tab under zmx".to_string(),
                PathOutcome::Failed("no marker".to_string()),
            ),
        ];
        let (lines, failures) = report_lines(&results);
        assert_eq!(failures, 2);
        assert!(lines.iter().any(|line| line.contains(
            "System Settings, Privacy & Security, Automation, turn on Ghostty under osascript"
        )));
        assert_eq!(
            lines.last().unwrap(),
            "attach: examined 3 attach paths: developer pty attached, ghostty tab under launchd \
             consent required, ghostty tab under zmx failed; 2 did not pass"
        );
        let (lines, failures) = report_lines(&[]);
        assert_eq!(failures, 1, "examining nothing fails");
        assert!(lines[0].contains("examined 0"));
    }

    #[test]
    fn only_an_attached_path_passes() {
        let outcomes = [
            PathOutcome::Failed(String::new()),
            PathOutcome::ConsentRequired {
                requester: String::new(),
                evidence: String::new(),
            },
            PathOutcome::GhosttyUnavailable(String::new()),
            PathOutcome::NoAnswer(String::new()),
            PathOutcome::CouldNotRun(String::new()),
            PathOutcome::Unrecognised(String::new()),
        ];
        for outcome in &outcomes {
            assert_ne!(disposition(outcome), Disposition::Passed, "{outcome:?}");
        }
        assert_eq!(
            disposition(&PathOutcome::Attached(String::new())),
            Disposition::Passed
        );
    }

    #[test]
    fn a_socket_needs_group_read_and_write_and_the_rest_is_measured() {
        assert!(group_can_connect(0o770));
        assert!(
            !group_can_connect(0o755),
            "the mode zmx gives a socket under umask 022"
        );
        let entries = [
            Entry {
                path: "ta1p".to_string(),
                owner: Owner::Agent,
                mode: 0o770,
                socket: true,
                developer_writable: true,
            },
            Entry {
                path: "logs/zmx.log".to_string(),
                owner: Owner::Agent,
                mode: 0o660,
                socket: false,
                developer_writable: true,
            },
            Entry {
                path: "logs".to_string(),
                owner: Owner::Agent,
                mode: 0o770,
                socket: false,
                developer_writable: false,
            },
        ];
        assert_eq!(writable_beyond_sockets(&entries), ["logs/zmx.log"]);
    }

    #[test]
    fn the_tab_script_never_launches_ghostty_and_returns_the_terminal_id() {
        assert!(OPEN_TAB_SCRIPT.contains("is not running then error"));
        assert!(OPEN_TAB_SCRIPT.contains("number -600"));
        assert!(OPEN_TAB_SCRIPT.contains(&format!("return \"{OPENED_PREFIX}\"")));
        let shared = SharedZmx {
            binary: PathBuf::from("/Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx"),
            dir: AGENT_SOCKET_DIR_DEFAULT.to_string(),
        };
        assert_eq!(
            shared.attach_command("ta1z"),
            "/usr/bin/env -u ZMX_SESSION ZMX_DIR=/Users/Shared/tycho-agent-zmx ZMX_DIR_MODE=0770 \
             ZMX_LOG_MODE=0660 ZMX_NO_DETACH_KEY=1 /Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx \
             attach ta1z"
        );
    }

    #[test]
    fn the_session_program_reads_one_line_into_the_marker() {
        let dir = env::temp_dir().join(format!("tycho-attach-program-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let marker = dir.join("m");
        let mut child = Command::new("/bin/sh")
            .args([
                "-c",
                &READ_ONE_LINE.replace("exec /bin/sleep 600", "exit 0"),
                "sh",
            ])
            .arg(&marker)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"typed-1-p\n")
            .unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(
            read_marker(&marker, "typed-1-p", current_uid()),
            Marker::Arrived("typed-1-p".to_string())
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}

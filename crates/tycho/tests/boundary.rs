//! Boundary tests for slice zero step 5. As the agent user, every probe into the developer's
//! home and credentials, the agent's own settings file, the Restate admin port of a test core
//! and that core's canonical repository is decoded into an enumerated outcome; then, as the
//! core, a worker's commit is fetched, verified on a fresh checkout with pinned criteria,
//! fast-forwarded and synced to a throwaway remote. The sudoers rule is read back and must be
//! exactly the narrow one; a session started through it must run as the agent; and the agent
//! must not be able to point the developer's zmx log elsewhere. macOS only, run by
//! `mise run boundary-tests` from a terminal, where sudo asks for the developer's password.
#![allow(
    clippy::disallowed_methods,
    reason = "fixtures live in throwaway directories no other user can write"
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

#[path = "chaos/support.rs"]
#[allow(
    dead_code,
    reason = "the suite takes the throwaway core and leaves the chaos cases' helpers"
)]
mod support;

use std::env;
use std::fs;
use std::io::IsTerminal;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use tycho::agent_files::current_uid;
use tycho::command::{self, CommandError};
use tycho::config::{
    AGENT_SOCKET_DIR_DEFAULT, AGENT_USER_DEFAULT, TOOL_PREFIX_DEFAULT, ToolPrefix,
};
use tycho::config::{AgentDirs, CorePorts};
use tycho::credentials::{Credential, CredentialVendor};
use tycho::launch_spec::{HeartbeatTarget, VendorTerminal};
use tycho::process::{ProcessFacts, process_facts};
use tycho::proxy_audit::{self, AuditRead};
use tycho::repositories::{ProjectName, Repositories, pin_ref, unit_branch};
use tycho::spawn::{SpawnOutcome, SpawnRequest, spawn_session};
use tycho::zmx::{LOG_DIR, LOG_FILE, Presence, Zmx, prepare_shared_log, presence};
use tycho_harness::content::content_ref;
use tycho_harness::verify::{VerifyOptions, run_criteria_with, unit_passed};
use tycho_harness::work_units::{PassCondition, load_default};
use tycho_types::agent_switch::{
    Expected, Listing, WiderProbe, decode_listing, decode_wider, listing_arguments,
    wider_probe_arguments,
};
use tycho_types::envelope::{BranchName, CommitSha};
use tycho_types::git_environment::{git_command, hook_environment_refusal};
use tycho_types::launcher::{ENV_AWAITABLE_ID, ENV_SESSION_NAME, ENV_SESSION_SECRET, LauncherEnv};
use tycho_types::service::{Attempt, WorkUnitId};
use tycho_types::session::SessionName;

const SUDO: &str = "/usr/bin/sudo";
/// Covers the operator typing the password at the first probe's prompt.
const PROBE_TIMEOUT: Duration = Duration::from_mins(2);
const PROBE_OUTPUT_MAX_BYTES: usize = 65_536;
/// The agent-side shell's last line: who it ran as and what the probe exited with.
const MARKER: &str = "tycho-probe";
const AGENT_PATH: &str = "PATH=/usr/bin:/bin:/usr/sbin:/sbin";
/// How long a session started through the rule gets to appear in, and leave, `zmx list`.
const SESSION_WAIT: Duration = Duration::from_secs(10);
const SESSION_POLL: Duration = Duration::from_millis(250);
/// Reached text printed for an open boundary is cut to this many characters.
const EVIDENCE_MAX_CHARS: usize = 400;
const PROJECT: &str = "widget";
const DEFAULT_BRANCH: &str = "main";
/// The content reference of the trivial unit's done criteria as JSON, pinned when this suite
/// was written; a fixture edit that changes them fails the positive path until it is re-pinned.
const TRIVIAL_CRITERIA_PIN: &str =
    "sha256:79e763fdcc81e0d4e65669692d96aa786ddb725bcd7ea2dfcaf5b8355758dc49";
const CRITERION_TIMEOUT_MS: u64 = 300_000;

/// What refused the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// EACCES, from the file system or from git reporting it.
    PermissionDenied,
    /// EPERM.
    NotPermitted,
    /// git could not write the object database.
    GitWriteRefused,
    /// Nothing accepted the connection.
    ConnectionRefused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Denied(Refusal, String),
    /// The boundary is open; what the agent reached.
    Succeeded(String),
    /// The probe could not look: sudo refused, the user is missing, a timeout, an absent target.
    CouldNotRun(String),
    Unrecognised(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expectation {
    Refused,
    /// A boundary the design lists as open; its outcome is recorded, not passed.
    Measured {
        gap: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Refused,
    MeasuredOpen,
    /// A measured boundary that refused: its gap row can go.
    MeasuredRefused,
    Open,
    CouldNotLook,
    Unrecognised,
}

impl Disposition {
    const fn fails(self) -> bool {
        match self {
            Self::Refused | Self::MeasuredOpen | Self::MeasuredRefused => false,
            Self::Open | Self::CouldNotLook | Self::Unrecognised => true,
        }
    }
}

const fn disposition(expectation: Expectation, outcome: &Outcome) -> Disposition {
    match (expectation, outcome) {
        (Expectation::Refused, Outcome::Denied(..)) => Disposition::Refused,
        (Expectation::Refused, Outcome::Succeeded(_)) => Disposition::Open,
        (Expectation::Measured { .. }, Outcome::Denied(..)) => Disposition::MeasuredRefused,
        (Expectation::Measured { .. }, Outcome::Succeeded(_)) => Disposition::MeasuredOpen,
        (_, Outcome::CouldNotRun(_)) => Disposition::CouldNotLook,
        (_, Outcome::Unrecognised(_)) => Disposition::Unrecognised,
    }
}

fn cut(text: &str) -> String {
    text.chars().take(EVIDENCE_MAX_CHARS).collect()
}

/// Wraps a probe so the agent-side shell reports its uid and the probe's exit status on a
/// line of its own: a run without that line never reached the agent. The probe runs in a
/// subshell, so its own `exit` ends only the probe.
fn wrap(script: &str) -> String {
    format!(
        "(\n{script}\n)\nrc=$?\nprintf '\\n{MARKER} uid=%s exit=%s\\n' \"$(/usr/bin/id -u)\" \"$rc\""
    )
}

/// Reads the marker, which counts only as the last non-empty line: the uid and exit status,
/// or why they cannot be read.
fn read_marker(stdout: &str) -> Option<Result<(u32, i32), String>> {
    let last = stdout.lines().rev().find(|line| !line.trim().is_empty());
    let line = match last.and_then(|line| line.strip_prefix(MARKER)) {
        Some(line) => line.trim(),
        None if stdout.lines().any(|line| line.starts_with(MARKER)) => {
            return Some(Err("output follows the marker line".to_string()));
        }
        None => return None,
    };
    let mut words = line.split(' ');
    let uid = words.next().and_then(|word| word.strip_prefix("uid="));
    let exit = words.next().and_then(|word| word.strip_prefix("exit="));
    Some(match (uid, exit, words.next()) {
        (Some(uid), Some(exit), None) => uid
            .parse()
            .ok()
            .zip(exit.parse().ok())
            .ok_or_else(|| format!("marker {line:?}")),
        _ => Err(format!("marker {line:?}")),
    })
}

/// The refusal a failed probe's stderr names; an absent target is a probe that could not look.
fn classify_failure(exit: i32, stderr: &str) -> Outcome {
    for line in stderr.lines() {
        let refusal = if line.contains("Permission denied") {
            Some(Refusal::PermissionDenied)
        } else if line.contains("Operation not permitted") {
            Some(Refusal::NotPermitted)
        } else if line.contains("insufficient permission")
            || line.contains("unable to create temporary object directory")
        {
            Some(Refusal::GitWriteRefused)
        } else if line.contains("Couldn't connect to server") || line.contains("Connection refused")
        {
            Some(Refusal::ConnectionRefused)
        } else {
            None
        };
        if let Some(refusal) = refusal {
            return Outcome::Denied(refusal, line.to_string());
        }
    }
    if let Some(line) = stderr
        .lines()
        .find(|line| line.contains("No such file or directory"))
    {
        return Outcome::CouldNotRun(format!("the target is absent as the agent sees it: {line}"));
    }
    Outcome::Unrecognised(format!("exit {exit}: {}", cut(stderr.trim())))
}

/// Decodes one agent-side run from its output; the agent's uid must be the one that ran.
fn decode(stdout: &str, stderr: &str, agent_uid: u32) -> Outcome {
    let Some(marker) = read_marker(stdout) else {
        if let Some(line) = stderr.lines().find(|line| line.starts_with("sudo:")) {
            return Outcome::CouldNotRun(line.to_string());
        }
        return Outcome::Unrecognised(format!("no probe report; stderr {}", cut(stderr.trim())));
    };
    let (uid, exit) = match marker {
        Ok(read) => read,
        Err(reason) => return Outcome::Unrecognised(reason),
    };
    if uid != agent_uid {
        return Outcome::Unrecognised("ran under a uid other than the agent's".to_string());
    }
    if exit == 0 {
        let reached = stdout
            .rsplit_once(MARKER)
            .map_or(stdout, |(before, _)| before)
            .trim();
        return Outcome::Succeeded(cut(reached));
    }
    classify_failure(exit, stderr)
}

/// The agent user as the suite sees it.
#[derive(Debug, Clone)]
struct Agent {
    uid: u32,
    home: PathBuf,
}

/// Runs `script` with `arguments` as `$1`.. in a shell of the agent user, with an empty
/// environment, from `/`. The one place the identity switch is made: today through sudo,
/// which prompts on the terminal.
fn run_as_agent(agent: &Agent, script: &str, arguments: &[&str]) -> Outcome {
    let home = format!("HOME={}", agent.home.display());
    let wrapped = wrap(script);
    let mut words = vec![
        "-u",
        AGENT_USER_DEFAULT,
        "--",
        "/usr/bin/env",
        "-i",
        home.as_str(),
        AGENT_PATH,
        "/bin/sh",
        "-c",
        wrapped.as_str(),
        MARKER,
    ];
    words.extend_from_slice(arguments);
    match command::run_status_from(
        Path::new(SUDO),
        &words,
        Path::new("/"),
        PROBE_TIMEOUT,
        PROBE_OUTPUT_MAX_BYTES,
    ) {
        Ok(captured) => decode(&captured.stdout, &captured.stderr, agent.uid),
        Err(error @ (CommandError::OutputTooLarge(..) | CommandError::NotUtf8(_))) => {
            Outcome::Unrecognised(error.to_string())
        }
        Err(error) => Outcome::CouldNotRun(error.to_string()),
    }
}

/// Drops sudo's cached credential when the run ends, passed or failed, so the developer's
/// ticket does not outlive the suite.
struct ForgetSudo;

impl Drop for ForgetSudo {
    fn drop(&mut self) {
        match Command::new(SUDO).arg("-k").status() {
            Ok(status) if status.success() => println!("boundary: sudo -k at the end of the run"),
            Ok(status) => eprintln!("boundary: sudo -k at the end exited {status}"),
            Err(error) => eprintln!("boundary: sudo -k at the end could not run: {error}"),
        }
    }
}

/// The prefix's zmx, which the sudoers rule names.
fn prefix_zmx() -> PathBuf {
    ToolPrefix::load(PathBuf::from(TOOL_PREFIX_DEFAULT))
        .unwrap_or_else(|error| panic!("boundary: the shared tool prefix: {error}"))
        .tool("zmx")
        .unwrap_or_else(|| panic!("boundary: station.json records no zmx"))
        .to_path_buf()
}

fn sudo_answer(arguments: &[String]) -> (Option<i32>, String, String) {
    let output = Command::new(SUDO)
        .args(arguments)
        .current_dir("/")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("boundary: sudo could not run: {error}"));
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Requires exactly the narrow rule, with the probes setup makes: `zmx list` as the agent is
/// listed with no password, and a command outside the rule still needs one. Neither probe uses
/// or drops a cached ticket.
fn require_the_narrow_rule() {
    let zmx = prefix_zmx();
    let zmx = zmx.to_str().unwrap();
    let installs = Path::new(zmx)
        .parent()
        .and_then(Path::parent)
        .map(|dir| format!("{}/", dir.display()))
        .unwrap();
    let expected = Expected {
        agent: AGENT_USER_DEFAULT,
        zmx,
        zmx_installs: &installs,
    };
    let (exit, stdout, stderr) = sudo_answer(&listing_arguments());
    let listing = decode_listing(exit, &stdout, &stderr, &expected);
    println!("boundary: sudo -n -k -l: {listing:?}");
    let (exit, stdout, stderr) = sudo_answer(&wider_probe_arguments(AGENT_USER_DEFAULT));
    let wider = decode_wider(exit, &stdout, &stderr);
    println!("boundary: sudo -n -k -u {AGENT_USER_DEFAULT} -- /usr/bin/true: {wider:?}");
    assert!(
        matches!(&listing, Listing::Listed(reading) if reading.is_exact()),
        "boundary: the sudoers listing is not exactly the rule for the prefix's zmx; run \
         `mise run setup`, then `mise run provision-agent`"
    );
    assert_eq!(
        wider,
        WiderProbe::PasswordRequired,
        "boundary: a sudoers rule runs commands outside the prefix's zmx as \
         {AGENT_USER_DEFAULT} with no password"
    );
}

/// Refuses to start without a terminal, without the agent user, or without exactly the narrow
/// sudoers rule; prints what it saw.
fn preflight() -> Agent {
    assert!(
        std::io::stdin().is_terminal(),
        "boundary: stdin is not a terminal. The agent-side probes run through sudo, which asks \
         for the developer's password on the terminal; run `mise run boundary-tests` from one."
    );
    let agent = nix::unistd::User::from_name(AGENT_USER_DEFAULT)
        .unwrap_or_else(|error| panic!("boundary: cannot look up {AGENT_USER_DEFAULT}: {error}"))
        .unwrap_or_else(|| {
            panic!("boundary: no user {AGENT_USER_DEFAULT}; run `mise run provision-agent`")
        });
    let agent = Agent {
        uid: agent.uid.as_raw(),
        home: agent.dir,
    };
    println!(
        "boundary: agent {AGENT_USER_DEFAULT} home {}",
        agent.home.display()
    );
    let forget = Command::new(SUDO).arg("-k").status().unwrap();
    assert!(forget.success(), "boundary: sudo -k exited {forget}");
    require_the_narrow_rule();
    println!("boundary: sudo asks for the developer's password once, on this terminal");
    agent
}

struct Boundary {
    name: String,
    expectation: Expectation,
    script: &'static str,
    arguments: Vec<String>,
}

const LIST: &str = "/bin/ls -1A \"$1\"";
/// Opens the settings file for append and writes nothing, or creates and removes it, so the
/// agent's settings are left as they were.
const WRITE_SETTINGS: &str = "if [ -e \"$1\" ]; then : >> \"$1\" && echo \"opened $1 for writing\"; \
     else : > \"$1\" && /bin/rm -f \"$1\" && echo \"created and removed $1\"; fi";
const ADMIN_HEALTH: &str =
    "/usr/bin/curl -sS -m 5 -o /dev/null -w 'admin answered %{http_code}' \"http://$1/health\"";
/// Puts a link at the developer's zmx log, so the developer's next zmx command would append
/// to `$2`; the log directory is the developer's and closed to group writes.
const PLANT_LOG_LINK: &str =
    "/bin/ln -sf \"$2\" \"$1/logs/zmx.log\" && echo \"linked $1/logs/zmx.log to $2\"";
/// Moves the developer's log directory aside, so the agent could make its own in its place;
/// the shared directory is sticky.
const RENAME_LOG_DIR: &str = "/bin/mv \"$1/logs\" \"$1/logs.agent\" && echo \"renamed $1/logs\"";
const WRITE_OBJECTS: &str = ": > \"$1/objects/tycho-boundary-probe\" && echo \"wrote $1/objects\"";
const WRITE_HOOK: &str = "/bin/mkdir -p \"$1/hooks\" && printf '#!/bin/sh\\nexit 0\\n' > \
     \"$1/hooks/pre-receive\" && echo \"wrote $1/hooks/pre-receive\"";
/// Names the first directory on the way to `$1` that the agent cannot search, with `ls`'s own
/// line, so a refusal of the canonical repository says which layer gave it and whether that
/// layer refused or was absent. Globbing is off and `$1` is split by parameter expansion,
/// never by word splitting; each pass consumes one component.
const LAYER_WALK: &str = "set -f; rest=${1#/}; walked=''; \
     while [ -n \"$rest\" ]; do part=${rest%%/*}; \
     case \"$rest\" in */*) rest=${rest#*/} ;; *) rest='' ;; esac; \
     [ -z \"$part\" ] && continue; walked=\"$walked/$part\"; \
     if ! line=$(/bin/ls -d \"$walked/.\" 2>&1 > /dev/null); then \
     echo \"stopped at $walked: $line\"; exit 0; fi; done; echo 'every layer searchable'";
/// git reports an unreadable repository as one that does not exist, so a failed push is
/// followed by a look at the path, whose refusal names the cause. A step before the push that
/// fails says so in a line that decodes as unrecognised, never as a refusal.
const PUSH_DEFAULT: &str = "/usr/bin/git --version > /dev/null 2>&1 || \
     { echo 'probe: git cannot run as this user' >&2; exit 125; }; \
     d=$(/usr/bin/mktemp -d 2> /dev/null) || { echo 'probe: no temporary directory' >&2; exit 125; }; \
     g() { GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 /usr/bin/git -C \"$d\" -c user.name=agent -c user.email=agent@tycho.invalid \"$@\"; }; \
     { g init -q && g commit -q --allow-empty -m escape; } > /dev/null 2>&1 || \
     { /bin/rm -rf \"$d\"; echo 'probe: could not prepare a commit' >&2; exit 125; }; \
     g push -q --force \"$1\" HEAD:refs/heads/\"$2\" && echo \"pushed a commit to $2 of $1\"; \
     rc=$?; /bin/rm -rf \"$d\"; [ $rc -eq 0 ] || /bin/ls -d \"$1/.\" > /dev/null; exit $rc";

fn developer_home() -> PathBuf {
    PathBuf::from(env::var_os("HOME").unwrap())
}

/// The developer's side of each target, printed so a refusal is read against what exists.
fn present(path: &Path) -> &'static str {
    if fs::symlink_metadata(path).is_ok() {
        "present to the developer"
    } else {
        "absent to the developer"
    }
}

fn boundaries(agent: &Agent, admin: &str, canonical: &Path) -> Vec<Boundary> {
    let home = developer_home();
    let mut list: Vec<Boundary> = [
        home.clone(),
        home.join("Library/Keychains"),
        home.join(".config/gh"),
        home.join(".ssh"),
        home.join(".aws"),
    ]
    .into_iter()
    .map(|path| Boundary {
        name: format!("read {} ({})", path.display(), present(&path)),
        expectation: Expectation::Refused,
        script: LIST,
        arguments: vec![path.display().to_string()],
    })
    .collect();
    let settings = agent.home.join(".claude/settings.json");
    let canonical = canonical.display().to_string();
    list.extend([
        Boundary {
            name: format!("write {}", settings.display()),
            expectation: Expectation::Measured {
                gap: "the agent can write its Claude settings file, which no station session reads (--setting-sources=, section 6)",
            },
            script: WRITE_SETTINGS,
            arguments: vec![settings.display().to_string()],
        },
        Boundary {
            name: format!("reach the Restate admin port {admin}"),
            expectation: Expectation::Refused,
            script: ADMIN_HEALTH,
            arguments: vec![admin.to_string()],
        },
        Boundary {
            name: "write to the canonical repository's objects".to_string(),
            expectation: Expectation::Refused,
            script: WRITE_OBJECTS,
            arguments: vec![canonical.clone()],
        },
        Boundary {
            name: "edit the canonical repository's hooks directory".to_string(),
            expectation: Expectation::Refused,
            script: WRITE_HOOK,
            arguments: vec![canonical.clone()],
        },
        Boundary {
            name: format!("push to the canonical repository's {DEFAULT_BRANCH}"),
            expectation: Expectation::Refused,
            script: PUSH_DEFAULT,
            arguments: vec![canonical, DEFAULT_BRANCH.to_string()],
        },
    ]);
    list
}

/// Prints one line per boundary and the count examined; returns the failures, where
/// examining nothing is one.
fn report(results: &[(String, Expectation, Outcome)]) -> usize {
    if results.is_empty() {
        println!("boundary: examined 0 boundaries, which is a failure");
        return 1;
    }
    let mut failures = 0_usize;
    let mut counts = [
        (Disposition::Refused, 0_usize),
        (Disposition::MeasuredOpen, 0),
        (Disposition::MeasuredRefused, 0),
        (Disposition::Open, 0),
        (Disposition::CouldNotLook, 0),
        (Disposition::Unrecognised, 0),
    ];
    for (name, expectation, outcome) in results {
        let disposition = disposition(*expectation, outcome);
        println!("boundary: {disposition:?}: {name}: {outcome:?}");
        for (counted, count) in &mut counts {
            if *counted == disposition {
                *count = count.saturating_add(1);
            }
        }
        if let (Disposition::MeasuredOpen, Expectation::Measured { gap }) =
            (disposition, expectation)
        {
            println!("boundary:   measured, not passed: {gap}");
        }
        if disposition.fails() {
            failures = failures.saturating_add(1);
        }
    }
    let tally: Vec<String> = counts
        .iter()
        .map(|(disposition, count)| format!("{count} {disposition:?}"))
        .collect();
    println!(
        "boundary: examined {} boundaries: {}; {failures} failed",
        results.len(),
        tally.join(", ")
    );
    failures
}

fn test_home(test: &str) -> PathBuf {
    developer_home().join(format!(".tycho-boundary-{test}-{}", std::process::id()))
}

/// The synthetic epic as the project's canonical repository under the core's home.
fn canonical_repository(core_home: &Path, worktree_root: PathBuf) -> (Repositories, ProjectName) {
    let repositories = Repositories::new(
        PathBuf::from("git"),
        core_home.to_path_buf(),
        worktree_root,
        current_uid(),
    )
    .unwrap();
    let source = core_home.join("source");
    fs::create_dir_all(&source).unwrap();
    let built = tycho_harness::repository::build(&source).unwrap();
    let project = ProjectName::parse(PROJECT).unwrap();
    let head = repositories.create_canonical(&project, &source).unwrap();
    assert_eq!(head, built.head_sha);
    println!(
        "evidence: canonical repository {} at {head}",
        repositories.canonical(&project).display()
    );
    (repositories, project)
}

#[test]
#[ignore = "probes as the agent user through sudo; run with mise run boundary-tests from a terminal"]
fn the_agent_user_is_refused_at_every_boundary() {
    let agent = preflight();
    let _forget = ForgetSudo;
    let claim = support::claim_ports(&test_home("agent"));
    let core = support::Core::new(claim);
    support::start_once(&core, |core| {
        core.tycho(&["core", "start"])
            .status
            .success()
            .then_some(())
    });
    let (repositories, project) =
        canonical_repository(&core.config.home, core.config.home.join("worktrees"));
    let canonical = repositories.canonical(&project);
    assert!(
        canonical.join("objects").is_dir(),
        "the core sees its repository"
    );
    let admin = core.config.ports.admin().to_string();
    let answered = support::client()
        .get(core.config.ports.admin_url("/health"))
        .send()
        .unwrap()
        .status();
    println!("evidence: the admin port {admin} answers the developer with {answered}");
    assert!(answered.is_success(), "the probe needs a live admin port");
    let shared = Path::new(AGENT_SOCKET_DIR_DEFAULT);
    prepare_shared_log(shared)
        .unwrap_or_else(|refusal| panic!("boundary: the shared zmx log: {refusal}"));
    let target = core.config.home.join("developer-file");
    fs::write(&target, "kept\n").unwrap();
    let mut list = boundaries(&agent, &admin, &canonical);
    list.extend(log_boundaries(shared, &target));
    let results: Vec<(String, Expectation, Outcome)> = list
        .into_iter()
        .map(|boundary| {
            let arguments: Vec<&str> = boundary.arguments.iter().map(String::as_str).collect();
            let outcome = run_as_agent(&agent, boundary.script, &arguments);
            (boundary.name, boundary.expectation, outcome)
        })
        .collect();
    let layer = run_as_agent(&agent, LAYER_WALK, &[canonical.to_str().unwrap()]);
    println!("evidence: the agent's walk to the canonical repository: {layer:?}");
    developer_log_is_intact(shared, &target);
    let failures = report(&results);
    assert_eq!(
        failures, 0,
        "{failures} boundaries are open or could not be examined"
    );
}

/// The agent's attempts on the developer's zmx log, both refused when the shared directory is
/// sticky and the log directory the developer's.
fn log_boundaries(shared: &Path, target: &Path) -> [Boundary; 2] {
    let shared = shared.display().to_string();
    [
        Boundary {
            name: format!("put a link at {shared}/logs/zmx.log"),
            expectation: Expectation::Refused,
            script: PLANT_LOG_LINK,
            arguments: vec![shared.clone(), target.display().to_string()],
        },
        Boundary {
            name: format!("rename {shared}/logs"),
            expectation: Expectation::Refused,
            script: RENAME_LOG_DIR,
            arguments: vec![shared],
        },
    ]
}

/// After the agent's attempts, the developer's zmx appends to its own log and nowhere else.
fn developer_log_is_intact(shared: &Path, target: &Path) {
    let listed = Zmx::agent(&prefix_zmx(), shared).list();
    let kept = fs::read_to_string(target).unwrap();
    println!(
        "evidence: after the agent's attempts the developer's zmx list answered {:?} and the \
         link target holds {kept:?}",
        listed.as_ref().map(Vec::len)
    );
    assert!(listed.is_ok(), "the developer's zmx refused its own log");
    assert_eq!(
        kept, "kept\n",
        "the developer's zmx appended through the agent's link"
    );
    let log = shared.join(LOG_DIR).join(LOG_FILE);
    let log_facts = fs::symlink_metadata(&log).unwrap();
    assert!(
        log_facts.file_type().is_file() && log_facts.uid() == current_uid(),
        "{} is no longer the developer's regular file",
        log.display()
    );
}

/// What `ps` says of the pid zmx lists for `name`, once it runs the typed program or the wait
/// ends.
fn listed_program(zmx: &Zmx, name: &str) -> ProcessFacts {
    let mut seen = Presence::Absent;
    let started = std::time::Instant::now();
    while started.elapsed() < SESSION_WAIT {
        seen = presence(&zmx.list().unwrap(), name);
        if let Presence::Running { pid, .. } = seen
            && let ProcessFacts::Running(facts) = process_facts(pid)
            && facts.command.starts_with("/bin/sleep")
        {
            break;
        }
        std::thread::sleep(SESSION_POLL);
    }
    match seen {
        Presence::Running { pid, .. } => process_facts(pid),
        other => panic!("boundary: {name} is {other:?} in zmx list"),
    }
}

/// Whether `name` left `zmx list` within the wait.
fn gone_within(zmx: &Zmx, name: &str) -> bool {
    let started = std::time::Instant::now();
    while started.elapsed() < SESSION_WAIT {
        if presence(&zmx.list().unwrap(), name) == Presence::Absent {
            return true;
        }
        std::thread::sleep(SESSION_POLL);
    }
    false
}

/// What a session started through the rule shows, as comparisons: the uids themselves are
/// never printed.
struct SessionEvidence {
    listed_is_agent: bool,
    command: String,
    socket_is_agent: bool,
    socket_mode: u32,
}

impl SessionEvidence {
    fn read(zmx: &Zmx, shared: &Path, name: &str, agent_uid: u32) -> Self {
        let (listed_is_agent, command) = match listed_program(zmx, name) {
            ProcessFacts::Running(facts) => (facts.uid == agent_uid, facts.command),
            ProcessFacts::Gone => (false, "gone".to_string()),
            ProcessFacts::Unrecognised(text) => (false, format!("ps answered {text}")),
        };
        let socket = fs::symlink_metadata(shared.join(name)).unwrap();
        Self {
            listed_is_agent,
            command,
            socket_is_agent: socket.uid() == agent_uid,
            socket_mode: socket.mode() & 0o777,
        }
    }
}

/// A session started through the sudoers rule, as the spawner starts a launcher: zmx must list a
/// pid of the agent's running the typed program, and the session's socket must be the agent's.
#[test]
#[ignore = "starts a session as the agent through the sudoers rule; run with mise run boundary-tests"]
fn a_session_started_through_the_rule_runs_as_the_agent() {
    require_the_narrow_rule();
    let agent_uid = nix::unistd::User::from_name(AGENT_USER_DEFAULT)
        .unwrap()
        .unwrap_or_else(|| panic!("boundary: no user {AGENT_USER_DEFAULT}"))
        .uid
        .as_raw();
    let shared = Path::new(AGENT_SOCKET_DIR_DEFAULT);
    let zmx = Zmx::agent_as(&prefix_zmx(), shared, AGENT_USER_DEFAULT);
    let name = format!("tycho-boundary-{}", std::process::id());
    let program = ["exec", "/bin/sleep", "120"].map(str::to_string);
    zmx.run_words(&name, &program)
        .unwrap_or_else(|error| panic!("boundary: {error}"));
    let seen = SessionEvidence::read(&zmx, shared, &name, agent_uid);
    println!(
        "evidence: {name}: the listed pid is the agent's {}, runs {:?}; the socket is the \
         agent's {}, mode {:o}",
        seen.listed_is_agent, seen.command, seen.socket_is_agent, seen.socket_mode
    );
    let killed = zmx.kill(&name);
    let gone = gone_within(&zmx, &name);
    println!("evidence: zmx kill {name} by name as the developer: {killed:?}; gone {gone}");
    assert!(seen.listed_is_agent, "the listed pid is not the agent's");
    assert!(
        seen.command.starts_with("/bin/sleep 120"),
        "{}",
        seen.command
    );
    assert!(
        seen.socket_is_agent,
        "the session socket is not the agent's"
    );
    assert_eq!(
        seen.socket_mode, 0o770,
        "the developer's group cannot connect"
    );
    assert!(
        gone,
        "the developer's kill by name did not end the agent's session"
    );
}

/// Starts `tycho session-leader -- /bin/sleep <seconds>` as a background child of a shell,
/// sandboxed by the plan in `$2` as a vendor is, and prints the child's pid, as `$!` names it.
/// The shell zmx starts is the leader of the pty's session already, and `setsid` refuses a
/// session leader, so a program typed with `exec` in place of the shell cannot lead a session
/// of its own; a child can.
const GROUP_LEADER_SCRIPT: &str = "TYCHO_SANDBOX_PLAN=\"$2\" \"$0\" session-leader -- /bin/sleep \"$1\" & printf 'reap-leader %s\\n' \"$!\"; wait";
const LEADER_MARKER: &str = "reap-leader ";

/// The smallest plan the trampoline accepts: the system paths and a proxy port nothing
/// listens on, which `sleep` never uses.
fn minimal_plan() -> String {
    tycho::sandbox::SandboxPlan {
        proxy_port: 40_000,
        core_ports: tycho::sandbox::core_ports(tycho::config::CorePorts::PRODUCTION),
        grants: Vec::new(),
        socket_dirs: Vec::new(),
        absent_paths: Vec::new(),
        state_files: Vec::new(),
    }
    .to_json()
    .unwrap()
}

fn group_leader_words(tycho: &str, seconds: &str) -> Vec<String> {
    [
        "/bin/sh",
        "-c",
        GROUP_LEADER_SCRIPT,
        tycho,
        seconds,
        &minimal_plan(),
    ]
    .map(str::to_string)
    .to_vec()
}

/// The pid a line of output names as the group leader; the echoed command line, whose marker
/// is followed by the format, never matches.
fn leader_pid(output: &str) -> Option<u32> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix(LEADER_MARKER)
            .filter(|digits| !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()))
            .and_then(|digits| digits.parse().ok())
    })
}

/// What `ps` says of `pid` once it leads its own group, or at the end of the session wait:
/// `$!` names the child before its `setsid` has run.
fn once_leading(pid: u32) -> ProcessFacts {
    let started = std::time::Instant::now();
    loop {
        let facts = process_facts(pid);
        let leads = matches!(&facts, ProcessFacts::Running(running) if running.pgid == pid);
        if leads || started.elapsed() >= SESSION_WAIT {
            return facts;
        }
        std::thread::sleep(SESSION_POLL);
    }
}

/// The group leader's pid from the session's scrollback, within the session wait.
fn leader_from_history(zmx: &Zmx, name: &str) -> Option<u32> {
    let started = std::time::Instant::now();
    while started.elapsed() < SESSION_WAIT {
        if let Some(pid) = zmx
            .history(name, PROBE_OUTPUT_MAX_BYTES)
            .ok()
            .as_deref()
            .and_then(leader_pid)
        {
            return Some(pid);
        }
        std::thread::sleep(SESSION_POLL);
    }
    None
}

/// The kill path's delivery through the rule: a group leader running as the agent, as a vendor
/// runs under `tycho session-leader`, is killed by a throwaway session the core starts as the
/// agent and then removes.
#[test]
#[ignore = "kills a process group of the agent through the sudoers rule; run with mise run boundary-tests"]
fn a_group_of_the_agent_is_killed_through_the_rule() {
    require_the_narrow_rule();
    let agent_uid = nix::unistd::User::from_name(AGENT_USER_DEFAULT)
        .unwrap()
        .unwrap_or_else(|| panic!("boundary: no user {AGENT_USER_DEFAULT}"))
        .uid
        .as_raw();
    let shared = Path::new(AGENT_SOCKET_DIR_DEFAULT);
    let zmx = Zmx::agent_as(&prefix_zmx(), shared, AGENT_USER_DEFAULT);
    let tycho = ToolPrefix::load(PathBuf::from(TOOL_PREFIX_DEFAULT))
        .unwrap()
        .tycho()
        .display()
        .to_string();
    let name = format!("tycho-boundary-reap-{}", std::process::id());
    let mut program = vec!["exec".to_string()];
    program.extend(group_leader_words(&tycho, "600"));
    zmx.run_words(&name, &program)
        .unwrap_or_else(|error| panic!("boundary: {error}"));
    let leader = leader_from_history(&zmx, &name);
    let (leader_is_agent, leads_its_group, command) = match leader.map(once_leading) {
        Some(ProcessFacts::Running(facts)) => (
            facts.uid == agent_uid,
            Some(facts.pgid) == leader,
            facts.command,
        ),
        other => (false, false, format!("{other:?}")),
    };
    let verdict = leader.map(|pid| tycho::kill::deliver_through(&zmx, pid, true, &process_facts));
    let removed = zmx.kill(&name);
    println!(
        "evidence: the group leader is the agent's {leader_is_agent}, leads its group \
         {leads_its_group}, runs {command:?}; the kill through the rule: {verdict:?}; {name} \
         removed: {removed:?}"
    );
    assert!(leader_is_agent, "the group leader is not the agent's");
    assert!(leads_its_group, "the child does not lead its own group");
    assert_eq!(
        verdict,
        Some(tycho::kill::KillVerdict::SignalledThroughRule)
    );
}

/// The fake vendor of a session launched as the agent: from inside the session sandbox it
/// probes the core's admin port, a host off the allowlist through the proxy and the model
/// endpoint through the route, dumps its environment, and marks the end.
const SESSION_VENDOR_SCRIPT: &str = r#"#!/bin/sh
# $1 marker prefix, $2 the core's admin port
/bin/bash -c 'if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then echo open; else echo refused; fi' admin "$2" > "$1.admin"
/usr/bin/env > "$1.env"
/usr/bin/curl -s -o /dev/null -w '%{http_connect}' --max-time 10 https://github.com/ > "$1.github" 2>/dev/null
/usr/bin/curl -s -o "$1.model-body" -w '%{http_code}' --max-time 20 -H "Authorization: Bearer $CLAUDE_CODE_OAUTH_TOKEN" -H 'anthropic-version: 2023-06-01' "$ANTHROPIC_BASE_URL/v1/models" > "$1.model" 2>/dev/null
echo done > "$1.done"
"#;
/// The shape of a long-lived Claude token; Anthropic refuses it, which shows the route
/// reached Anthropic with the token the proxy holds.
const SESSION_TEST_TOKEN: &str = "sk-ant-oat01-boundary-suite-test-credential-0123456789";
const SHARED_GROUP: &str = "tycho-zmx";

/// The fake vendor's directory: the developer's, in the shared group at 2770, so the agent
/// reads the script and writes its markers and the developer reads them back.
struct SessionFixture {
    dir: PathBuf,
}

impl SessionFixture {
    fn new() -> Self {
        let dir = PathBuf::from(format!(
            "/Users/Shared/tycho-boundary-session-{}",
            std::process::id()
        ));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let group = nix::unistd::Group::from_name(SHARED_GROUP)
            .unwrap()
            .unwrap_or_else(|| panic!("boundary: no group {SHARED_GROUP}"));
        nix::unistd::chown(&dir, None, Some(group.gid)).unwrap();
        fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o2770)).unwrap();
        fs::write(dir.join("vendor.sh"), SESSION_VENDOR_SCRIPT).unwrap();
        Self { dir }
    }

    fn marker(&self, suffix: &str) -> PathBuf {
        self.dir.join(format!("marker{suffix}"))
    }

    fn read(&self, suffix: &str) -> String {
        fs::read_to_string(self.marker(suffix)).unwrap_or_default()
    }
}

impl Drop for SessionFixture {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.dir));
    }
}

/// A session launched as the agent, as the spawner launches a vendor, is held at its
/// boundaries from inside: the core's admin port refused while it answers the developer, a host
/// off the allowlist refused at the proxy and recorded as a firing in the session's audit, the
/// model endpoint reached through the route, and the handed token in no variable of the
/// vendor's. The bare probes of `the_agent_user_is_refused_at_every_boundary` run outside any
/// session sandbox and stay measurements of the agent user alone.
#[test]
#[ignore = "launches a session as the agent through the sudoers rule against a test core; run with mise run boundary-tests"]
fn a_session_launched_as_the_agent_is_held_at_its_boundaries() {
    require_the_narrow_rule();
    let agent = nix::unistd::User::from_name(AGENT_USER_DEFAULT)
        .unwrap()
        .unwrap_or_else(|| panic!("boundary: no user {AGENT_USER_DEFAULT}"));
    let agent_uid = agent.uid.as_raw();
    let claim = support::claim_ports(&test_home("session"));
    let core = support::Core::new(claim);
    support::start_once(&core, |core| {
        core.tycho(&["core", "start"])
            .status
            .success()
            .then_some(())
    });
    let ports = core.config.ports;
    let answered = support::client()
        .get(ports.admin_url("/health"))
        .send()
        .unwrap()
        .status();
    println!("evidence: the admin port answers the developer with {answered}");
    assert!(answered.is_success(), "the probe needs a live admin port");
    let shared = Path::new(AGENT_SOCKET_DIR_DEFAULT);
    let dirs = AgentDirs::new(shared.to_path_buf()).unwrap();
    let zmx = Zmx::agent_as(&prefix_zmx(), shared, AGENT_USER_DEFAULT);
    let prefix = ToolPrefix::load(PathBuf::from(TOOL_PREFIX_DEFAULT)).unwrap();
    let fixture = SessionFixture::new();
    let name = SessionName::parse(&format!("b{}.wu01.wrk.claude.bs", std::process::id())).unwrap();
    let outcome = launch_as_agent(&Launch {
        zmx: &zmx,
        dirs: &dirs,
        prefix: &prefix,
        fixture: &fixture,
        name: &name,
        agent: &agent,
        ports,
    });
    println!("evidence: spawn_session({name}) as the agent -> {outcome:?}");
    let ended = within_the_launched_wait(|| fixture.marker(".done").exists());
    let audit =
        first_within_the_launched_wait(|| match proxy_audit::read(&dirs, &name, agent_uid) {
            AuditRead::Absent => None,
            read => Some(read),
        });
    drop(zmx.kill(&name.to_string()));
    assert!(
        matches!(outcome, Ok(SpawnOutcome::Spawned { .. })),
        "{outcome:?}"
    );
    assert_held_from_inside(&fixture, ended, audit);
}

/// What a launch as the agent needs: the agent's zmx and directories, the prefix it starts
/// from, the fake vendor and the test core's ports.
struct Launch<'a> {
    zmx: &'a Zmx,
    dirs: &'a AgentDirs,
    prefix: &'a ToolPrefix,
    fixture: &'a SessionFixture,
    name: &'a SessionName,
    agent: &'a nix::unistd::User,
    ports: CorePorts,
}

/// Spawns the fake vendor as the spawner spawns one, through the rule as the agent, with a test
/// token the hand-off delivers.
fn launch_as_agent(
    launch: &Launch<'_>,
) -> Result<SpawnOutcome, tycho::services::spawner::SpawnerError> {
    let (fixture, name, ports) = (launch.fixture, launch.name, launch.ports);
    let env = LauncherEnv::from_map(&std::collections::BTreeMap::from([
        (
            ENV_AWAITABLE_ID.to_string(),
            format!("boundary-awaitable-{}", std::process::id()),
        ),
        (ENV_SESSION_SECRET.to_string(), "s".repeat(40)),
        (ENV_SESSION_NAME.to_string(), name.to_string()),
    ]))
    .unwrap();
    let vendor = [
        "/bin/sh".to_string(),
        fixture.dir.join("vendor.sh").display().to_string(),
        fixture.marker("").display().to_string(),
        ports.admin().port().to_string(),
    ];
    let credential =
        Credential::parse(CredentialVendor::Claude, SESSION_TEST_TOKEN.as_bytes()).unwrap();
    let outcome = spawn_session(&SpawnRequest {
        zmx: launch.zmx,
        dirs: launch.dirs,
        tycho: &launch.prefix.tycho(),
        home: &launch.agent.dir,
        env: &env,
        heartbeat: HeartbeatTarget::LaunchProbe,
        vendor: &vendor,
        agent_uid: launch.agent.uid.as_raw(),
        tier: None,
        terminal: VendorTerminal::Files,
        vendor_dir: Some(&fixture.dir),
        ports,
        tool_prefix: launch.prefix,
        credential: Some(&credential),
    });
    println!("evidence: spawn_session({name}) as the agent -> {outcome:?}");
    outcome
}

/// From inside the session: the admin port refused, github.com refused at the proxy and in
/// the audit, the model endpoint answered by Anthropic, and only the phantom in the vendor's
/// environment.
fn assert_held_from_inside(fixture: &SessionFixture, ended: bool, audit: Option<AuditRead>) {
    let environment = fixture.read(".env");
    let names: Vec<&str> = environment
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name))
        .collect();
    let value = |wanted: &str| {
        environment
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{wanted}=")))
    };
    let body: String = fixture
        .read(".model-body")
        .chars()
        .take(EVIDENCE_MAX_CHARS)
        .collect();
    println!(
        "evidence: from inside the agent's session: vendor ended {ended}; admin port {}; \
         github.com through the proxy {}; the model endpoint through the route {} {body}; the \
         vendor's environment names {names:?}; the proxy audit {audit:?}",
        fixture.read(".admin").trim(),
        fixture.read(".github").trim(),
        fixture.read(".model").trim(),
    );
    assert!(ended, "the vendor did not finish its probes");
    assert_eq!(
        fixture.read(".admin").trim(),
        "refused",
        "the vendor reached the admin port"
    );
    assert_eq!(
        fixture.read(".github").trim(),
        "403",
        "the proxy did not refuse github.com"
    );
    assert_eq!(fixture.read(".model").trim(), "401", "{body}");
    assert!(
        body.contains("\"authentication_error\""),
        "the route did not reach Anthropic: {body}"
    );
    assert!(
        !environment.contains(SESSION_TEST_TOKEN),
        "the vendor's environment holds the handed token"
    );
    assert!(
        value("CLAUDE_CODE_OAUTH_TOKEN").is_some()
            && value("CLAUDE_CODE_OAUTH_TOKEN") == value("NONO_PROXY_TOKEN"),
        "the vendor's token is not the phantom"
    );
    let Some(AuditRead::Read(audit)) = audit else {
        panic!("the session's proxy audit did not read: {audit:?}");
    };
    assert!(
        audit
            .firings
            .iter()
            .any(|firing| firing.subject == "github.com:443"),
        "{audit}"
    );
}

/// Polls a condition for the session wait of a launched session, twice the wait of a bare one,
/// since the vendor's model probe goes to the network.
fn within_the_launched_wait(mut condition: impl FnMut() -> bool) -> bool {
    first_within_the_launched_wait(|| condition().then_some(())).is_some()
}

fn first_within_the_launched_wait<T>(mut condition: impl FnMut() -> Option<T>) -> Option<T> {
    let started = std::time::Instant::now();
    while started.elapsed() < LAUNCHED_SESSION_WAIT {
        if let Some(value) = condition() {
            return Some(value);
        }
        std::thread::sleep(SESSION_POLL);
    }
    None
}

const LAUNCHED_SESSION_WAIT: Duration = Duration::from_mins(1);

/// The gate's throwaway directories, removed when the test ends.
struct GateScratch {
    core_home: PathBuf,
    scratch: PathBuf,
}

impl GateScratch {
    fn new() -> Self {
        // Under the developer's home like the production core home `~/.tycho`, which is
        // where the agent's refusal starts; the remote and worktrees stay in a temporary
        // directory.
        let core_home = test_home("gate");
        let scratch = env::temp_dir().join(format!("tycho-boundary-gate-{}", std::process::id()));
        for dir in [&core_home, &scratch] {
            if dir.exists() {
                fs::remove_dir_all(dir).unwrap();
            }
        }
        fs::create_dir_all(&scratch).unwrap();
        let scratch = fs::canonicalize(&scratch).unwrap();
        // The core's home is private before anything is put in it, as the core keeps it.
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&core_home)
            .unwrap();
        Self { core_home, scratch }
    }
}

impl Drop for GateScratch {
    fn drop(&mut self) {
        for dir in [&self.core_home, &self.scratch] {
            if let Err(error) = fs::remove_dir_all(dir) {
                eprintln!("teardown: cannot remove {}: {error}", dir.display());
            }
        }
    }
}

fn git(directory: &Path, arguments: &[&str]) -> String {
    if let Some(refusal) = hook_environment_refusal() {
        panic!("{refusal}");
    }
    let output = git_command()
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// The trivial unit's done criteria, checked against the pin before they run.
fn pinned_criteria() -> Vec<tycho_types::task_packet::DoneCriterion> {
    let unit = load_default()
        .unwrap()
        .into_iter()
        .find(|unit| unit.key == "trivial")
        .unwrap();
    assert_eq!(unit.pass_condition, PassCondition::CriteriaPass);
    let criteria = unit.packet.done_criteria;
    let pin = content_ref(&serde_json::to_vec(&criteria).unwrap()).unwrap();
    println!(
        "evidence: the trivial unit's criteria hash to {}",
        pin.as_str()
    );
    assert_eq!(
        pin.as_str(),
        TRIVIAL_CRITERIA_PIN,
        "the criteria moved from their pin"
    );
    criteria
}

/// A worker's commit of the trivial unit's reference change, in a worktree of the canonical
/// repository, fetched and pinned by the core.
fn pinned_worker_commit(
    repositories: &Repositories,
    project: &ProjectName,
    worktree_root: &Path,
) -> (CommitSha, String) {
    let unit = WorkUnitId::parse("wu01").unwrap();
    let branch = unit_branch(&unit, Attempt::FIRST).unwrap();
    let path = worktree_root.join("cf7a/wu01/a1");
    let worktree = repositories
        .clone_worktree(project, &path, &branch)
        .unwrap();
    tycho_harness::repository::apply_patch(
        &worktree.path,
        tycho_harness::repository::PATCH_TRIVIAL,
    )
    .unwrap();
    git(
        &worktree.path,
        &["commit", "-q", "-a", "-m", "fix: the answer is 42"],
    );
    let head = CommitSha::parse(&git(&worktree.path, &["rev-parse", "HEAD"])).unwrap();
    let pin = pin_ref(&unit, 1);
    repositories.pin(project, &worktree, &head, &pin).unwrap();
    println!("evidence: fetched {head} from the worktree and pinned it at {pin}");
    (head, pin)
}

/// Runs the pinned criteria on a fresh checkout of `head`; the checkout is gone afterwards.
fn verify_on_a_fresh_checkout(
    repositories: &Repositories,
    project: &ProjectName,
    head: &CommitSha,
    log_dir: PathBuf,
) -> bool {
    let checkout = repositories.fresh_checkout(project, head).unwrap();
    let options = VerifyOptions::new(CRITERION_TIMEOUT_MS, Some(log_dir)).unwrap();
    let reports = run_criteria_with(&checkout.path(), &pinned_criteria(), &options);
    for report in &reports {
        println!(
            "evidence: criterion {} {:?} on {}: {}",
            report.index,
            report.status,
            checkout.path().display(),
            report.detail
        );
    }
    unit_passed(PassCondition::CriteriaPass, &reports)
}

#[test]
#[ignore = "builds and verifies the synthetic repository; run with mise run boundary-tests"]
fn the_core_verifies_a_worker_commit_fast_forwards_and_syncs_it() {
    let dirs = GateScratch::new();
    let worktree_root = dirs.scratch.join("worktrees");
    let (repositories, project) = canonical_repository(&dirs.core_home, worktree_root.clone());
    let remote = dirs.scratch.join("remote.git");
    let remote_text = remote.to_str().unwrap();
    git(&dirs.scratch, &["init", "-q", "--bare", remote_text]);
    let source = dirs.core_home.join("source");
    git(&source, &["push", "-q", remote_text, DEFAULT_BRANCH]);
    let base = git(&remote, &["rev-parse", DEFAULT_BRANCH]);
    let (head, pin) = pinned_worker_commit(&repositories, &project, &worktree_root);
    assert!(
        verify_on_a_fresh_checkout(
            &repositories,
            &project,
            &head,
            dirs.scratch.join("criterion-logs")
        ),
        "the pinned criteria failed on the worker's commit"
    );
    let default = BranchName::parse(DEFAULT_BRANCH).unwrap();
    repositories
        .fast_forward(&project, &default, &head)
        .unwrap();
    let default_ref = format!("refs/heads/{DEFAULT_BRANCH}");
    assert_eq!(repositories.resolve(&project, &default_ref).unwrap(), head);
    repositories.sync(&project, remote_text, &default).unwrap();
    println!("evidence: {DEFAULT_BRANCH} moved from {base} to {head} and synced to {remote_text}");
    assert_eq!(git(&remote, &["rev-parse", DEFAULT_BRANCH]), head.as_str());
    assert_eq!(
        repositories.resolve(&project, &pin).unwrap(),
        head,
        "the pin ref holds the commit"
    );
    assert_eq!(
        git(&remote, &["for-each-ref", "--format=%(refname)"]),
        default_ref,
        "only the default branch reaches the remote"
    );
}

#[cfg(test)]
mod probes {
    //! Each probe script run as the test's own user: it reaches a target that user owns and
    //! is refused by one root owns, decoded by the same decoder the agent's runs go through.
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn run_as_self(script: &str, arguments: &[&str]) -> Outcome {
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(wrap(script))
            .arg(MARKER)
            .args(arguments)
            .current_dir("/")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        decode(
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
            current_uid(),
        )
    }

    fn root_home() -> &'static str {
        if Path::new("/var/root").exists() {
            "/var/root"
        } else {
            "/root"
        }
    }

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.0));
        }
    }

    fn scratch(test: &str) -> Scratch {
        let dir = env::temp_dir().join(format!("tycho-boundary-{test}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        fs::create_dir_all(&dir).unwrap();
        Scratch(fs::canonicalize(&dir).unwrap())
    }

    #[test]
    fn each_probe_reaches_what_its_user_owns_and_is_refused_by_what_root_owns() {
        assert_ne!(
            current_uid(),
            0,
            "root owns both targets; run as another user"
        );
        let owned = scratch("probes");
        let repository = owned.0.join("canonical.git");
        git(
            &owned.0,
            &["init", "-q", "--bare", repository.to_str().unwrap()],
        );
        let repository = repository.to_str().unwrap();
        let settings = owned.0.join("settings.json");
        let settings = settings.to_str().unwrap();
        let refused = format!("{}/canonical.git", root_home());
        let refused_settings = format!("{}/settings.json", root_home());
        let cases: [(&str, Vec<&str>, Vec<&str>); 5] = [
            (LIST, vec![repository], vec![root_home()]),
            (WRITE_SETTINGS, vec![settings], vec![&refused_settings]),
            (WRITE_OBJECTS, vec![repository], vec![&refused]),
            (WRITE_HOOK, vec![repository], vec![&refused]),
            (
                PUSH_DEFAULT,
                vec![repository, DEFAULT_BRANCH],
                vec![&refused, DEFAULT_BRANCH],
            ),
        ];
        for (script, reach, refuse) in &cases {
            let reached = run_as_self(script, reach);
            assert!(
                matches!(reached, Outcome::Succeeded(_)),
                "{script}: {reached:?}"
            );
            let denied = run_as_self(script, refuse);
            assert!(
                matches!(denied, Outcome::Denied(Refusal::PermissionDenied, _)),
                "{script}: {denied:?}"
            );
        }
        assert!(
            fs::symlink_metadata(owned.0.join("settings.json")).is_err(),
            "the settings probe leaves no file it created"
        );
        assert_eq!(
            git(
                Path::new(repository),
                &["for-each-ref", "--format=%(refname)"]
            ),
            format!("refs/heads/{DEFAULT_BRANCH}"),
            "the push probe reached the default branch"
        );
    }

    /// The walk's line for a path, which the walk reports as a reached outcome.
    fn walk(path: &str) -> String {
        match run_as_self(LAYER_WALK, &[path]) {
            Outcome::Succeeded(line) => line,
            other => panic!("the walk to {path} did not report: {other:?}"),
        }
    }

    #[test]
    fn the_layer_walk_tells_a_refused_layer_from_an_absent_one() {
        let owned = scratch("walk");
        fs::create_dir_all(owned.0.join("a/b")).unwrap();
        assert_eq!(
            walk(owned.0.join("a/b").to_str().unwrap()),
            "every layer searchable"
        );
        let resolved_root = fs::canonicalize(root_home()).unwrap();
        let refused = walk(
            resolved_root
                .join("repositories/widget.git")
                .to_str()
                .unwrap(),
        );
        assert!(
            refused.starts_with(&format!("stopped at {}: ", resolved_root.display()))
                && refused.contains("Permission denied"),
            "{refused}"
        );
        let missing = owned.0.join("absent");
        let absent = walk(missing.join("widget.git").to_str().unwrap());
        assert!(
            absent.starts_with(&format!("stopped at {}: ", missing.display()))
                && absent.contains("No such file or directory"),
            "{absent}"
        );
    }

    #[test]
    fn the_layer_walk_takes_a_glob_character_literally() {
        let owned = scratch("walk-glob");
        fs::create_dir_all(owned.0.join("a/c")).unwrap();
        let star = owned.0.join("*");
        let line = walk(star.join("c").to_str().unwrap());
        assert!(
            line.starts_with(&format!("stopped at {}: ", star.display()))
                && line.contains("No such file or directory"),
            "the walk expanded {}: {line}",
            star.display()
        );
        let spaced = owned.0.join("a b");
        fs::create_dir_all(&spaced).unwrap();
        assert_eq!(walk(spaced.to_str().unwrap()), "every layer searchable");
    }

    #[test]
    fn the_settings_probe_leaves_an_existing_file_as_it_was() {
        let owned = scratch("settings");
        let settings = owned.0.join("settings.json");
        fs::write(&settings, "{\"model\":\"x\"}").unwrap();
        let reached = run_as_self(WRITE_SETTINGS, &[settings.to_str().unwrap()]);
        assert!(matches!(reached, Outcome::Succeeded(_)), "{reached:?}");
        assert_eq!(fs::read_to_string(&settings).unwrap(), "{\"model\":\"x\"}");
    }

    #[test]
    fn the_admin_probe_reaches_a_listener_and_is_refused_by_a_closed_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let read = stream.read(&mut request).unwrap();
            assert!(read > 0, "curl sent no request");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .unwrap();
        });
        let reached = run_as_self(ADMIN_HEALTH, &[&address]);
        server.join().unwrap();
        assert_eq!(
            reached,
            Outcome::Succeeded("admin answered 200".to_string())
        );
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = closed.local_addr().unwrap().to_string();
        drop(closed);
        let refused = run_as_self(ADMIN_HEALTH, &[&address]);
        assert!(
            matches!(refused, Outcome::Denied(Refusal::ConnectionRefused, _)),
            "{refused:?}"
        );
    }
}

#[cfg(test)]
mod group_leader {
    //! The reap test's program run as the test's own user, under a session leader as zmx runs
    //! its shell.
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    const TYCHO: &str = env!("CARGO_BIN_EXE_tycho");

    /// Runs the words under a fresh pseudo-terminal through `script`, whose shell leads the
    /// pty's session the way the shell zmx starts does.
    fn under_a_terminal(words: &[String]) -> Command {
        if cfg!(target_os = "macos") {
            let mut command = Command::new("script");
            command.args(["-q", "/dev/null"]).args(words);
            command
        } else {
            let line = words
                .iter()
                .map(|word| format!("'{}'", word.replace('\'', r"'\''")))
                .collect::<Vec<_>>()
                .join(" ");
            let mut command = Command::new("script");
            command.args(["-qec", &line, "/dev/null"]);
            command
        }
    }

    #[test]
    fn a_program_typed_with_exec_in_a_session_leader_cannot_lead_a_session() {
        let words = [
            "/bin/sh",
            "-c",
            "TYCHO_SANDBOX_PLAN=\"$1\" exec \"$0\" session-leader -- /bin/sleep 1",
            TYCHO,
            &minimal_plan(),
        ]
        .map(str::to_string);
        let output = under_a_terminal(&words)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let shown = String::from_utf8_lossy(&output.stdout);
        assert!(
            shown.contains("setsid"),
            "the trampoline did not fail at setsid: {output:?}"
        );
    }

    #[test]
    fn a_child_of_a_session_leader_leads_its_own_group_and_names_its_pid() {
        let mut shell = under_a_terminal(&group_leader_words(TYCHO, "30"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(shell.stdout.take().unwrap());
        let mut leader = None;
        for _ in 0..LEADER_LINES_MAX {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            // `script` echoes the end of its input as `^D` and two backspaces first.
            leader = line
                .find(LEADER_MARKER)
                .and_then(|at| leader_pid(&line[at..]));
            if leader.is_some() {
                break;
            }
        }
        let leader = leader.unwrap_or_else(|| panic!("no leader line"));
        let facts = once_leading(leader);
        let killed = tycho::process::send(leader, true, nix::sys::signal::Signal::SIGKILL);
        let ended = shell.wait();
        match facts {
            ProcessFacts::Running(facts) => {
                assert_eq!(facts.pgid, leader, "the child is not its group's leader");
                assert!(facts.command.contains("sleep 30"), "{}", facts.command);
            }
            other => panic!("ps answered {other:?}"),
        }
        assert!(killed.is_ok(), "{killed:?}");
        assert!(ended.is_ok());
    }

    /// The reap program, the plan included, fits the line zmx types for it as the agent.
    #[test]
    fn the_reap_program_with_its_plan_fits_the_typed_line() {
        let tycho = "/Users/Shared/tycho/bin/tycho";
        let mut words = vec!["exec".to_string()];
        words.extend(group_leader_words(tycho, "600"));
        let typed: usize = words.iter().map(|word| word.len() + 3).sum::<usize>()
            + "; echo ZMX_TASK_COMPLETED:0000:$?".len();
        assert!(
            typed < tycho::spawn::TYPED_LINE_MAX_BYTES,
            "the reap line is {typed} bytes"
        );
        assert!(tycho::sandbox::SandboxPlan::from_json(words.last().unwrap()).is_ok());
    }

    /// Lines `script` may print before the shell's own, its echo of the command included.
    const LEADER_LINES_MAX: usize = 16;

    #[test]
    fn only_a_marker_followed_by_digits_names_the_leader() {
        assert_eq!(leader_pid("reap-leader 4242\r\n"), Some(4242));
        assert_eq!(
            leader_pid("$ /bin/sh -c '\"$0\" ... printf '\\''reap-leader %s\\n'"),
            None
        );
        assert_eq!(
            leader_pid("reap-leader %s\\n' \"$!\"; wait\nreap-leader 7\n"),
            Some(7)
        );
        assert_eq!(leader_pid("reap-leader \n"), None);
    }
}

#[cfg(test)]
mod decoders {
    //! Samples captured on macOS by running each probe as the developer against a directory
    //! the developer owns and one owned by root, and from sudo itself.
    use super::*;

    const AGENT: u32 = 503;

    fn ran(reached: &str, uid: u32, exit: i32) -> String {
        format!("{reached}\n{MARKER} uid={uid} exit={exit}\n")
    }

    #[test]
    fn a_refusal_is_decoded_and_named() {
        let samples = [
            (
                "ls: /var/root: Permission denied\n",
                Refusal::PermissionDenied,
            ),
            (
                "sh: /var/root/probe: Permission denied\n",
                Refusal::PermissionDenied,
            ),
            (
                "fatal: cannot change to '/var/root/x.git': Permission denied\n",
                Refusal::PermissionDenied,
            ),
            (
                "fatal: '/var/root/x.git' does not appear to be a git repository\nfatal: Could not read from remote repository.\n\nPlease make sure you have the correct access rights\nand the repository exists.\nls: /var/root/x.git/.: Permission denied\n",
                Refusal::PermissionDenied,
            ),
            (
                "error: insufficient permission for adding an object to repository database canon.git/objects\nfatal: Unable to add (null) to database\n",
                Refusal::GitWriteRefused,
            ),
            (
                "error: remote unpack failed: unable to create temporary object directory\n",
                Refusal::GitWriteRefused,
            ),
            (
                "touch: /etc/x: Operation not permitted\n",
                Refusal::NotPermitted,
            ),
            (
                "curl: (7) Failed to connect to 127.0.0.1 port 20126 after 0 ms: Couldn't connect to server\n",
                Refusal::ConnectionRefused,
            ),
        ];
        let mut examined = 0_usize;
        for (stderr, refusal) in samples {
            let outcome = decode(&ran("", AGENT, 1), stderr, AGENT);
            assert!(
                matches!(outcome, Outcome::Denied(named, _) if named == refusal),
                "{stderr}"
            );
            examined = examined.saturating_add(1);
        }
        assert_eq!(examined, 8);
    }

    #[test]
    fn a_probe_that_ran_and_exited_zero_is_an_open_boundary_with_what_it_reached() {
        assert_eq!(
            decode(&ran("hosts.yml\nconfig.yml", AGENT, 0), "", AGENT),
            Outcome::Succeeded("hosts.yml\nconfig.yml".to_string())
        );
        assert_eq!(
            decode(&ran("admin answered 200", AGENT, 0), "", AGENT),
            Outcome::Succeeded("admin answered 200".to_string())
        );
    }

    #[test]
    fn a_probe_that_never_reached_the_agent_could_not_look() {
        for stderr in [
            "sudo: a password is required\n",
            "sudo: unknown user tycho-agent\nsudo: error initializing audit plugin sudoers_audit\n",
            "sudo: 3 incorrect password attempts\n",
        ] {
            assert!(
                matches!(decode("", stderr, AGENT), Outcome::CouldNotRun(_)),
                "{stderr}"
            );
        }
        assert!(matches!(
            decode(
                &ran("", AGENT, 1),
                "sh: /Users/tycho-agent/.claude/settings.json: No such file or directory\n",
                AGENT
            ),
            Outcome::CouldNotRun(_)
        ));
    }

    #[test]
    fn anything_else_is_unrecognised_and_never_passes() {
        let unreadable_alone = "fatal: '/var/root/x.git' does not appear to be a git repository\n";
        let cases = [
            decode(&ran("", AGENT, 128), unreadable_alone, AGENT),
            decode(
                &ran("", 501, 1),
                "ls: /var/root: Permission denied\n",
                AGENT,
            ),
            decode("listing without a marker", "", AGENT),
            decode(&format!("{MARKER} uid=503\n"), "", AGENT),
            decode(&format!("{MARKER} uid=x exit=0\n"), "", AGENT),
            decode(
                &ran("", AGENT, 125),
                "probe: git cannot run as this user\n",
                AGENT,
            ),
            decode(
                &ran("", AGENT, 28),
                "curl: (28) Connection timed out after 5001 milliseconds\n",
                AGENT,
            ),
        ];
        for outcome in &cases {
            assert!(matches!(outcome, Outcome::Unrecognised(_)), "{outcome:?}");
            assert!(disposition(Expectation::Refused, outcome).fails());
        }
        assert_eq!(cases.len(), 7);
    }

    #[test]
    fn a_marker_followed_by_more_output_is_not_read() {
        let trailing = format!("{MARKER} uid={AGENT} exit=1\nls: x: Permission denied\n");
        assert_eq!(
            read_marker(&trailing),
            Some(Err("output follows the marker line".to_string()))
        );
        assert!(matches!(
            decode(&trailing, "", AGENT),
            Outcome::Unrecognised(_)
        ));
        assert_eq!(
            read_marker(&format!("{MARKER} uid={AGENT} exit=1\n\n  \n")),
            Some(Ok((AGENT, 1)))
        );
        assert_eq!(
            decode(&ran("", 501, 1), "ls: x: Permission denied\n", AGENT),
            Outcome::Unrecognised("ran under a uid other than the agent's".to_string())
        );
    }

    #[test]
    fn the_wrapper_reports_the_uid_and_exit_on_its_own_line() {
        let output = Command::new("/bin/sh")
            .args(["-c", &wrap("printf partial; exit 3"), MARKER])
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(read_marker(&stdout), Some(Ok((current_uid(), 3))));
        assert!(stdout.starts_with("partial\n"));
    }

    #[test]
    fn only_a_refusal_passes_a_refused_boundary_and_a_measurement_never_fails_on_open() {
        let denied = Outcome::Denied(Refusal::PermissionDenied, String::new());
        let open = Outcome::Succeeded(String::new());
        let blind = Outcome::CouldNotRun(String::new());
        let measured = Expectation::Measured { gap: "listed" };
        assert_eq!(
            disposition(Expectation::Refused, &denied),
            Disposition::Refused
        );
        assert_eq!(disposition(Expectation::Refused, &open), Disposition::Open);
        assert_eq!(disposition(measured, &open), Disposition::MeasuredOpen);
        assert_eq!(disposition(measured, &denied), Disposition::MeasuredRefused);
        assert_eq!(disposition(measured, &blind), Disposition::CouldNotLook);
        assert!(Disposition::Open.fails());
        assert!(Disposition::CouldNotLook.fails());
        assert!(!Disposition::MeasuredOpen.fails());
    }

    #[test]
    fn a_report_counts_what_it_examined_and_each_failure() {
        let results = vec![
            (
                "read".to_string(),
                Expectation::Refused,
                Outcome::Denied(Refusal::PermissionDenied, String::new()),
            ),
            (
                "admin".to_string(),
                Expectation::Refused,
                Outcome::Succeeded("admin answered 200".to_string()),
            ),
            (
                "settings".to_string(),
                Expectation::Measured { gap: "listed" },
                Outcome::Succeeded(String::new()),
            ),
            (
                "push".to_string(),
                Expectation::Refused,
                Outcome::CouldNotRun("sudo: a password is required".to_string()),
            ),
        ];
        assert_eq!(report(&results), 2);
        assert_eq!(report(&[]), 1, "examining nothing fails");
    }
}

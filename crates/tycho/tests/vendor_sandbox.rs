//! Probes of the pinned Claude Code under the station's session sandbox, through the same
//! proxy, plan and trampoline the launcher uses: which settings layer decides Claude's own
//! sandbox, and whether Claude can save its configuration. macOS only; each probe spends a
//! short `claude -p` turn on the core's stored Claude token, so the suite uses the vendor
//! seat and never runs beside the worker or control suites (`mise run vendor-sandbox-tests`).
#![allow(
    clippy::disallowed_methods,
    reason = "fixtures live in throwaway directories no other user can write"
)]
#![allow(
    clippy::print_stdout,
    reason = "the evidence lines are the test's report for the pull request"
)]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers fail the test by panicking"
)]

use std::fs;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tycho::agent_files::current_uid;
use tycho::config::{self, CorePorts, MISE_NO_INSTALL};
use tycho::credentials::{self, CLAUDE_TOKEN_ENV, CredentialVendor};
use tycho::launch_spec::AGENT_TELEMETRY_ENV;
use tycho::sandbox::{Access, Grant, PLAN_ENV, SandboxVendor};
use tycho::session_sandbox::{self, SessionPaths};
use tycho::spawn::CLAUDE_SANDBOX_OFF;
use tycho::vendors::claude_worker::ClaudeWorker;
use tycho::vendors::worker::{ModelName, VendorSessionId, WorkerTask, WorkerVendor};
use tycho_types::git_environment::{git_command, hook_environment_refusal};
use tycho_types::task_packet::Effort;

const TYCHO: &str = env!("CARGO_BIN_EXE_tycho");
const RUN_LIMIT: Duration = Duration::from_mins(3);
const PROBE_COMMAND: &str = "echo probe-$((6*7))";
const PROBE_OUTPUT: &str = "probe-42";
/// Claude's own sandbox as the station passed it before the station's sandbox existed.
const VENDOR_SANDBOX_ON: &str =
    r#"{"sandbox":{"enabled":true,"failIfUnavailable":true,"allowUnsandboxedCommands":false}}"#;

fn mise_which(tool: &str) -> PathBuf {
    let output = Command::new("mise")
        .args(["which", tool])
        .envs(MISE_NO_INSTALL)
        .output()
        .unwrap();
    assert!(output.status.success(), "mise which {tool} failed");
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

/// A scratch home, worktree and session directory under the developer's home, which no
/// grant of the system list covers.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(test: &str) -> Self {
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let root = home.join(format!(".tvs-{test}-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        for dir in ["home/Library/Caches", "worktree", "vendor"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        if let Some(refusal) = hook_environment_refusal() {
            panic!("{refusal}");
        }
        let git = git_command()
            .args(["init", "-q"])
            .current_dir(root.join("worktree"))
            .status()
            .unwrap();
        assert!(git.success());
        Self { root }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn worktree(&self) -> PathBuf {
        self.root.join("worktree")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.root));
    }
}

/// What one run's stream shows of the probe command's Bash call.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BashOutcome {
    /// The command ran and printed its output.
    Ran,
    /// Claude's own sandbox could not start inside the station's, which refuses the socket
    /// it listens on and the profile it applies, so the call was refused.
    VendorSandboxFailed,
    /// No Bash call came back.
    NoToolResult,
    Unrecognised(String),
}

fn tool_results(stream: &str) -> Vec<String> {
    stream
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["type"] == "user")
        .filter_map(|event| event["message"]["content"].as_array().cloned())
        .flatten()
        .filter(|item| item["type"] == "tool_result")
        .map(|item| item["content"].to_string())
        .collect()
}

fn decode_bash(stream: &str) -> BashOutcome {
    let results = tool_results(stream);
    let failed = |text: &String| {
        text.contains("sandbox_apply")
            || text.contains("Sandbox is required but failed to initialize")
    };
    if results.iter().any(failed) {
        return BashOutcome::VendorSandboxFailed;
    }
    if results.iter().any(|text| text.contains(PROBE_OUTPUT)) {
        return BashOutcome::Ran;
    }
    results.first().map_or(BashOutcome::NoToolResult, |text| {
        BashOutcome::Unrecognised(text.chars().take(300).collect())
    })
}

struct Run {
    stream: String,
    stderr: String,
    proxy: String,
}

/// One `claude -p` turn as a worker runs it, through the station's proxy, plan and
/// trampoline, with `settings` passed by `--settings`.
fn run_claude(scratch: &Scratch, settings: &str, prompt: &str) -> Run {
    run_claude_as(scratch, settings, prompt, Mode::Sandboxed)
}

/// Whether a run goes through the trampoline, or straight to the vendor as the positive
/// control of a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Sandboxed,
    Unsandboxed,
}

/// The grants the core would put in the spec: the worktree, and the vendor's install and
/// the directory its link points into.
fn spec_grants(scratch: &Scratch, claude: &Path) -> Vec<Grant> {
    let mut grants = vec![
        Grant {
            path: scratch.worktree(),
            access: Access::ReadWrite,
        },
        Grant {
            path: claude.parent().unwrap().to_path_buf(),
            access: Access::Read,
        },
    ];
    if let Ok(target) = fs::read_link(claude) {
        grants.push(Grant {
            path: target.parent().unwrap().to_path_buf(),
            access: Access::Read,
        });
    }
    grants
}

/// The worker's command line for `claude`, with Bash available to the probe's prompt.
fn worker_words(claude: &Path, scratch: &Scratch, settings: &str) -> Vec<String> {
    let task = WorkerTask {
        worktree: scratch.worktree(),
        model: ModelName::parse("haiku").unwrap(),
        effort: Effort::Low,
        max_turns: NonZeroU16::new(4),
        requires_commit: false,
        session_id: VendorSessionId::parse(&uuid_like()).unwrap(),
        settings: settings.to_string(),
        output_schema: scratch.root.join("vendor/schema.json"),
    };
    let mut words = ClaudeWorker.command(claude, &task).unwrap();
    words.extend(["--allowedTools".to_string(), "Bash".to_string()]);
    words
}

fn run_claude_as(scratch: &Scratch, settings: &str, prompt: &str, mode: Mode) -> Run {
    let claude = mise_which("claude");
    let spec_grants = spec_grants(scratch, &claude);
    let home = scratch.home();
    let vendor_files = scratch.root.join("vendor");
    let paths = SessionPaths {
        vendor: SandboxVendor::Claude,
        home: &home,
        vendor_files: &vendor_files,
        codex_home: None,
        spec_grants: &spec_grants,
        ports: CorePorts::PRODUCTION,
        uid: current_uid(),
    };
    let prepared = session_sandbox::prepare(&paths).unwrap();
    let words = worker_words(&claude, scratch, settings);
    let token = credentials::load(&config::core_home().unwrap(), CredentialVendor::Claude)
        .unwrap_or_else(|error| panic!("no Claude token in the core's store: {error}"));
    let user = tycho::launch_spec::current_user_name().unwrap();
    let path = format!("{}:/usr/bin:/bin", claude.parent().unwrap().display());
    let mut command = match mode {
        Mode::Sandboxed => {
            let mut command = Command::new(TYCHO);
            command.arg("session-leader").arg("--").args(&words);
            command
        }
        Mode::Unsandboxed => {
            let mut command = Command::new(&words[0]);
            command.args(&words[1..]);
            command
        }
    };
    command
        .env_clear()
        .env("HOME", &home)
        .env("PATH", path)
        .env("USER", &user)
        .env("LOGNAME", &user)
        .env(CLAUDE_TOKEN_ENV, token.expose())
        .envs(AGENT_TELEMETRY_ENV)
        .envs(prepared.proxy.child_environment())
        .current_dir(scratch.worktree());
    if mode == Mode::Sandboxed {
        command.env(PLAN_ENV, &prepared.plan);
    }
    let output = run_with_prompt(command, prompt);
    let record = prepared.proxy.stop();
    Run {
        stream: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        proxy: record.to_string(),
    }
}

/// Runs the command with the prompt on stdin, as the worker hands the brief.
fn run_with_prompt(mut command: Command, prompt: &str) -> std::process::Output {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    std::io::Write::write_all(&mut stdin, prompt.as_bytes()).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        started.elapsed() < RUN_LIMIT,
        "the probe outlasted {RUN_LIMIT:?}"
    );
    output
}

fn uuid_like() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let hex = format!("{nanos:032x}");
    format!(
        "{}-{}-4{}-a{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[13..16],
        &hex[17..20],
        &hex[20..32]
    )
}

fn bash_prompt() -> String {
    format!("Use the Bash tool to run exactly `{PROBE_COMMAND}`, then reply with only its output.")
}

/// A worktree's `.claude/settings.json` that turns Claude's sandbox on does not win over the
/// settings the launcher passes. The third cell is the observable that tells the two apart:
/// with Claude's sandbox on, it cannot start inside the station's and refuses the call.
#[test]
#[ignore = "spends three claude turns; run with mise run vendor-sandbox-tests"]
fn a_worktree_cannot_turn_claude_s_sandbox_back_on_under_the_launcher_s_settings() {
    let scratch = Scratch::new("settings");
    let baseline = run_claude(&scratch, CLAUDE_SANDBOX_OFF, &bash_prompt());
    let worktree_settings = scratch.worktree().join(".claude");
    fs::create_dir_all(&worktree_settings).unwrap();
    fs::write(worktree_settings.join("settings.json"), VENDOR_SANDBOX_ON).unwrap();
    let worktree_on = run_claude(&scratch, CLAUDE_SANDBOX_OFF, &bash_prompt());
    fs::remove_file(worktree_settings.join("settings.json")).unwrap();
    let launcher_on = run_claude(&scratch, VENDOR_SANDBOX_ON, &bash_prompt());
    let cells = [
        ("launcher off, no worktree setting", &baseline),
        ("launcher off, worktree on", &worktree_on),
        ("launcher on", &launcher_on),
    ];
    let outcomes: Vec<BashOutcome> = cells
        .iter()
        .map(|(name, run)| {
            let outcome = decode_bash(&run.stream);
            println!("evidence: {name}: {outcome:?}; proxy: {}", run.proxy);
            if !matches!(outcome, BashOutcome::Ran | BashOutcome::VendorSandboxFailed) {
                println!(
                    "stderr: {}",
                    run.stderr.chars().take(2000).collect::<String>()
                );
            }
            outcome
        })
        .collect();
    assert_eq!(
        outcomes,
        [
            BashOutcome::Ran,
            BashOutcome::Ran,
            BashOutcome::VendorSandboxFailed
        ]
    );
}

/// The keys of Claude's global configuration in the scratch home and their values.
fn saved_state(home: &Path) -> Value {
    fs::read_to_string(home.join(".claude.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null)
}

/// Claude Code saves `~/.claude.json` by writing a temporary file beside it and renaming it
/// over the file; the sandbox grants the file and `~/.claude`, so whether a save lands is a
/// question for the run. The unsandboxed run is the positive control: it shows what a save
/// looks like, so an unchanged file under the sandbox is a refused save, not a run that
/// saved nothing.
#[test]
#[ignore = "spends two claude turns; run with mise run vendor-sandbox-tests"]
fn claude_saves_its_configuration_under_the_sandbox() {
    let seed = "{\"numStartups\":0}\n";
    let control = Scratch::new("save-control");
    fs::write(control.home().join(".claude.json"), seed).unwrap();
    let unsandboxed = run_claude_as(
        &control,
        CLAUDE_SANDBOX_OFF,
        "Reply with the word ready.",
        Mode::Unsandboxed,
    );
    let control_state = saved_state(&control.home());
    let scratch = Scratch::new("save");
    fs::write(scratch.home().join(".claude.json"), seed).unwrap();
    let sandboxed = run_claude(&scratch, CLAUDE_SANDBOX_OFF, "Reply with the word ready.");
    let state = saved_state(&scratch.home());
    let listing = |home: &Path| -> Vec<String> {
        fs::read_dir(home)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    };
    let keys = |value: &Value| -> Vec<String> {
        value
            .as_object()
            .map(|object| object.keys().cloned().collect())
            .unwrap_or_default()
    };
    println!(
        "evidence: unsandboxed save wrote keys {:?}, home {:?}; sandboxed save wrote keys {:?}, home {:?}; proxy {}",
        keys(&control_state),
        listing(&control.home()),
        keys(&state),
        listing(&scratch.home()),
        sandboxed.proxy
    );
    println!(
        "stderr: {}",
        sandboxed.stderr.chars().take(2000).collect::<String>()
    );
    drop(unsandboxed);
    assert_ne!(
        control_state,
        serde_json::from_str::<Value>(seed).unwrap(),
        "the positive control saved nothing, so this probe cannot tell a refused save"
    );
    assert_eq!(
        keys(&state),
        keys(&control_state),
        "Claude's save under the sandbox did not land as it does without it"
    );
}

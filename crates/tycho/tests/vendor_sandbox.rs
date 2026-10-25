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
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tycho::agent_files::current_uid;
use tycho::config::{self, CorePorts, MISE_NO_INSTALL};
use tycho::credentials::{self, CredentialVendor};
use tycho::launch_spec::AGENT_TELEMETRY_ENV;
use tycho::sandbox::{Access, Grant, PLAN_ENV, SandboxVendor};
use tycho::session_proxy::{HandedToken, ProxyRecord};
use tycho::session_sandbox::{self, SessionPaths};
use tycho::spawn::CLAUDE_SANDBOX_OFF;
use tycho::vendors::claude_worker::{ClaudeWorker, SETTING_SOURCES_NONE};
use tycho::vendors::codex_worker::CodexWorker;
use tycho::vendors::worker::{ModelName, VendorSessionId, WorkerTask, WorkerVendor};
use tycho::vendors::worker_process::worker_settings;
use tycho_types::git_environment::{git_command, hook_environment_refusal};
use tycho_types::task_packet::Effort;

const TYCHO: &str = env!("CARGO_BIN_EXE_tycho");
const RUN_LIMIT: Duration = Duration::from_mins(3);
/// A model in the pinned Codex's bundled catalog that a `ChatGPT` login may use; the routing
/// table's `gpt-5-codex` and `gpt-5-codex-mini` are refused with `model_not_found`.
const CODEX_PROBE_MODEL: &str = "gpt-6-luna";
const PROBE_COMMAND: &str = "echo probe-$((6*7))";
const PROBE_OUTPUT: &str = "probe-42";
/// Claude's own sandbox as the station passed it before the station's sandbox existed.
const VENDOR_SANDBOX_ON: &str =
    r#"{"sandbox":{"enabled":true,"failIfUnavailable":true,"allowUnsandboxedCommands":false}}"#;
/// A settings file that turns Claude's sandbox on and denies Bash. A deny rule from any layer
/// that is read wins over the launcher's allow rule, so a Bash call that runs shows the file
/// was not read at all, not only outranked.
const FILE_SANDBOX_ON_BASH_DENIED: &str = r#"{"sandbox":{"enabled":true,"failIfUnavailable":true,"allowUnsandboxedCommands":false},"permissions":{"deny":["Bash"]}}"#;

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
    /// A permission rule refused the call, or took Bash out of the session.
    Denied,
    /// No Bash call came back; a tool a deny rule names is not offered to the model.
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
    // A deny rule naming the whole tool takes it out of the session; the model's call then
    // gets the vendor's "no such tool" error.
    let denied = |text: &String| {
        text.contains("No such tool available: Bash")
            || (text.contains("Permission to use Bash") && text.contains("denied"))
    };
    if results.iter().any(denied) {
        return BashOutcome::Denied;
    }
    results.first().map_or(BashOutcome::NoToolResult, |text| {
        BashOutcome::Unrecognised(text.chars().take(300).collect())
    })
}

struct Run {
    stream: String,
    stderr: String,
    proxy: ProxyRecord,
}

/// Claude's model traffic takes the route: requests to the base URL, which the proxy answers
/// with the handed token, and never a tunnel to `api.anthropic.com`, which the proxy refuses
/// and could only intercept with a CA of its own. The proxy's record counts the paths.
fn assert_model_traffic_took_the_route(run: &Run) {
    let reverse = run.proxy.modes.get("reverse").copied().unwrap_or(0);
    assert!(reverse >= 1, "no request took the route: {}", run.proxy);
    assert!(
        !run.proxy.modes.contains_key("connect_intercept"),
        "{}",
        run.proxy
    );
    assert!(
        run.proxy
            .denied_targets
            .iter()
            .all(|target| !target.starts_with("api.anthropic.com")),
        "a tunnel to the model API was tried: {}",
        run.proxy
    );
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
    /// Sandboxed, with the worker's words less `--setting-sources=`: the positive control
    /// that a planted settings file is read when the flag is absent.
    SandboxedReadingSettingFiles,
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

/// The worker's command line for `claude`, with the settings the worker derives from the
/// launcher's: the escalation directory and the Bash allow rule added.
fn worker_words(claude: &Path, scratch: &Scratch, settings: &str) -> Vec<String> {
    let settings = worker_settings(settings, &scratch.root.join("vendor/escalation")).unwrap();
    let task = WorkerTask {
        worktree: scratch.worktree(),
        model: ModelName::parse("haiku").unwrap(),
        effort: Effort::Low,
        max_turns: NonZeroU16::new(4),
        requires_commit: false,
        session_id: VendorSessionId::parse(&uuid_like()).unwrap(),
        settings,
        output_schema: scratch.root.join("vendor/schema.json"),
    };
    ClaudeWorker.command(claude, &task).unwrap()
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
    let token = credentials::load(&config::core_home().unwrap(), CredentialVendor::Claude)
        .unwrap_or_else(|error| panic!("no Claude token in the core's store: {error}"));
    let prepared = session_sandbox::prepare(&paths, HandedToken::of(&token), true).unwrap();
    println!("evidence: claude binary {}", claude.display());
    let mut words = worker_words(&claude, scratch, settings);
    if mode == Mode::SandboxedReadingSettingFiles {
        let flags = words
            .iter()
            .filter(|word| *word == SETTING_SOURCES_NONE)
            .count();
        assert_eq!(flags, 1, "the worker passes the flag once");
        words.retain(|word| word != SETTING_SOURCES_NONE);
    }
    let user = tycho::launch_spec::current_user_name().unwrap();
    let path = format!("{}:/usr/bin:/bin", claude.parent().unwrap().display());
    let mut command = match mode {
        Mode::Sandboxed | Mode::SandboxedReadingSettingFiles => {
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
        .envs(AGENT_TELEMETRY_ENV)
        .envs(prepared.proxy.child_environment())
        .current_dir(scratch.worktree());
    if mode != Mode::Unsandboxed {
        command.env(PLAN_ENV, prepared.plan.as_deref().unwrap());
    }
    let output = run_with_prompt(command, prompt);
    let record = prepared.proxy.stop();
    Run {
        stream: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        proxy: record,
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

/// Only the launcher's settings decide Claude's sandbox: the worker starts Claude with
/// `--setting-sources=`, so the worktree's and the user's settings files are not read. The
/// third cell is the observable that tells the layers apart: with Claude's sandbox on, it
/// cannot start inside the station's and refuses the call.
#[test]
#[ignore = "spends four claude turns; run with mise run vendor-sandbox-tests"]
fn a_worktree_cannot_turn_claude_s_sandbox_back_on_under_the_launcher_s_settings() {
    let scratch = Scratch::new("settings");
    let baseline = run_claude(&scratch, CLAUDE_SANDBOX_OFF, &bash_prompt());
    let worktree_settings = scratch.worktree().join(".claude");
    let user_settings = scratch.home().join(".claude");
    let planted = [
        worktree_settings.join("settings.json"),
        worktree_settings.join("settings.local.json"),
        user_settings.join("settings.json"),
    ];
    for file in &planted {
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, FILE_SANDBOX_ON_BASH_DENIED).unwrap();
    }
    let files_on = run_claude(&scratch, CLAUDE_SANDBOX_OFF, &bash_prompt());
    let files_read = run_claude_as(
        &scratch,
        CLAUDE_SANDBOX_OFF,
        &bash_prompt(),
        Mode::SandboxedReadingSettingFiles,
    );
    for file in &planted {
        fs::remove_file(file).unwrap();
    }
    let launcher_on = run_claude(&scratch, VENDOR_SANDBOX_ON, &bash_prompt());
    let cells = [
        ("launcher off, no settings file", &baseline),
        (
            "launcher off, worktree and user files on with Bash denied",
            &files_on,
        ),
        ("the same files, read without the flag", &files_read),
        ("launcher on", &launcher_on),
    ];
    assert_settings_cells(&cells);
}

/// Every cell reached its init and its result; the outcomes and the offered tools match the
/// layer each cell's settings came from.
fn assert_settings_cells(cells: &[(&str, &Run); 4]) {
    let outcomes: Vec<BashOutcome> = cells
        .iter()
        .map(|(name, run)| {
            let outcome = decode_bash(&run.stream);
            let tools = init_tools(&run.stream);
            println!(
                "evidence: {name}: {outcome:?}; Bash offered: {:?}; result event: {}; proxy: {}",
                tools
                    .as_ref()
                    .map(|tools| tools.iter().any(|tool| tool == "Bash")),
                has_result(&run.stream),
                run.proxy
            );
            // A run that never reached its init or its result shows nothing about settings.
            assert!(
                tools.is_some() && has_result(&run.stream),
                "{name}: the run did not complete"
            );
            assert_model_traffic_took_the_route(run);
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
        [&outcomes[0], &outcomes[1], &outcomes[3]],
        [
            &BashOutcome::Ran,
            &BashOutcome::Ran,
            &BashOutcome::VendorSandboxFailed
        ]
    );
    // The flagless cell is told apart by the session's own tool list: the files' deny rule
    // takes Bash out of it, which a run that never started cannot show.
    let offered: Vec<bool> = cells
        .iter()
        .map(|(_, run)| {
            init_tools(&run.stream)
                .unwrap_or_default()
                .iter()
                .any(|tool| tool == "Bash")
        })
        .collect();
    assert_eq!(
        offered,
        [true, true, false, true],
        "the planted files were not read without the flag, so the second cell shows nothing"
    );
    assert!(
        matches!(outcomes[2], BashOutcome::Denied | BashOutcome::NoToolResult),
        "{:?}",
        outcomes[2]
    );
    // The launcher's object turns auto memory off in every cell, so `system/init` names no
    // memory directory, which with auto memory on lies in the agent-writable home.
    for (name, run) in cells {
        assert!(!init_names_memory(&run.stream), "{name}: auto memory is on");
    }
}

/// Whether `system/init` names a memory directory.
fn init_names_memory(stream: &str) -> bool {
    stream
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .any(|event| {
            event["subtype"] == "init"
                && event["memory_paths"]
                    .as_object()
                    .is_some_and(|paths| !paths.is_empty())
        })
}

/// The tools `system/init` offers the session; `None` when the stream has no init event.
fn init_tools(stream: &str) -> Option<Vec<String>> {
    stream
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| event["type"] == "system" && event["subtype"] == "init")
        .map(|event| {
            event["tools"]
                .as_array()
                .map(|tools| {
                    tools
                        .iter()
                        .filter_map(|tool| tool.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        })
}

/// Whether the stream ends its turn with a `result` event.
fn has_result(stream: &str) -> bool {
    stream
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .any(|event| event["type"] == "result")
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
    assert_model_traffic_took_the_route(&sandboxed);
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

/// What one `codex exec` turn showed: whether it completed, the proxy's record, and the start
/// of its stream and standard error.
struct CodexRun {
    completed: bool,
    proxy: ProxyRecord,
    output: String,
}

const CODEX_PROBE_SCHEMA: &str = r#"{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"],"additionalProperties":false}"#;

/// The session's Codex home, 0700, holding the core's `auth.json` at 0600 as the launcher
/// leaves it.
fn codex_home_with_auth(scratch: &Scratch) -> PathBuf {
    let codex_home = scratch.root.join("vendor-codex-home");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&codex_home)
        .unwrap();
    let auth = credentials::load(&config::core_home().unwrap(), CredentialVendor::Codex)
        .unwrap_or_else(|error| panic!("no Codex credential in the core's store: {error}"));
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(codex_home.join(tycho::credentials::CODEX_AUTH_FILE))
        .and_then(|mut file| std::io::Write::write_all(&mut file, auth.expose().as_bytes()))
        .unwrap();
    codex_home
}

/// Whether a `codex exec --json` stream completed its turn.
fn turn_completed(stream: &str) -> bool {
    stream
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .any(|event| event["type"] == "turn.completed")
}

/// One `codex exec` turn as a worker runs it, through the station's proxy, with its Codex home
/// in the session's directory holding the core's `auth.json`; under the trampoline when
/// `mode` says so.
/// The proxy and plan for a Codex session: the worktree and Codex's install in the spec, and
/// the Codex home the launcher adds.
fn codex_prepared(scratch: &Scratch, codex: &Path, codex_home: &Path) -> session_sandbox::Prepared {
    let install = codex.parent().and_then(Path::parent).unwrap().to_path_buf();
    let spec_grants = [
        Grant {
            path: scratch.worktree(),
            access: Access::ReadWrite,
        },
        Grant {
            path: install,
            access: Access::Read,
        },
    ];
    let home = scratch.home();
    let vendor_files = scratch.root.join("vendor");
    let paths = SessionPaths {
        vendor: SandboxVendor::Codex,
        home: &home,
        vendor_files: &vendor_files,
        codex_home: Some(codex_home),
        spec_grants: &spec_grants,
        ports: CorePorts::PRODUCTION,
        uid: current_uid(),
    };
    session_sandbox::prepare(&paths, None, true).unwrap()
}

/// The worker's command line for `codex exec`, with a model a `ChatGPT` login may use.
fn codex_words(scratch: &Scratch, codex: &Path, schema: PathBuf) -> Vec<String> {
    let task = WorkerTask {
        worktree: scratch.worktree(),
        model: ModelName::parse(CODEX_PROBE_MODEL).unwrap(),
        effort: Effort::Low,
        max_turns: None,
        requires_commit: false,
        session_id: VendorSessionId::parse(&uuid_like()).unwrap(),
        settings: String::new(),
        output_schema: schema,
    };
    CodexWorker.command(codex, &task).unwrap()
}

fn run_codex(scratch: &Scratch, mode: Mode) -> CodexRun {
    let codex = mise_which("codex");
    let codex_home = codex_home_with_auth(scratch);
    let schema = scratch.root.join("vendor/schema.json");
    fs::write(&schema, CODEX_PROBE_SCHEMA).unwrap();
    let home = scratch.home();
    let prepared = codex_prepared(scratch, &codex, &codex_home);
    let words = codex_words(scratch, &codex, schema);
    let user = tycho::launch_spec::current_user_name().unwrap();
    let mut command = if mode == Mode::Sandboxed {
        let mut command = Command::new(TYCHO);
        command.arg("session-leader").arg("--").args(&words);
        command
    } else {
        let mut command = Command::new(&words[0]);
        command.args(&words[1..]);
        command
    };
    command
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("USER", &user)
        .env("LOGNAME", &user)
        .env(tycho::credentials::CODEX_HOME_ENV, &codex_home)
        .envs(session_sandbox::trust_environment(SandboxVendor::Codex))
        .envs(AGENT_TELEMETRY_ENV)
        .envs(prepared.proxy.child_environment())
        .current_dir(scratch.worktree());
    if mode == Mode::Sandboxed {
        command.env(PLAN_ENV, prepared.plan.as_deref().unwrap());
    }
    let output = run_with_prompt(command, "Answer with the word ready in the answer field.");
    let proxy = prepared.proxy.stop();
    let stream = String::from_utf8_lossy(&output.stdout).into_owned();
    let completed = turn_completed(&stream);
    assert!(
        codex_home
            .join(tycho::credentials::CODEX_AUTH_FILE)
            .is_file(),
        "the Codex credential is a file in the session's Codex home"
    );
    CodexRun {
        completed,
        proxy,
        output: format!(
            "{}\n{}",
            stream.chars().take(1000).collect::<String>(),
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(6000)
                .collect::<String>()
        ),
    }
}

/// A `codex exec` turn completes under the station's sandbox with its Codex home in the
/// session's directory. The core's `auth.json` stays a file in the sandbox's reach: Codex's
/// bearer has no route. No name resolves inside the sandbox, so the turn shows Codex works
/// through the proxy alone. The unsandboxed run through the same proxy is the positive
/// control: a turn it cannot complete says nothing about the sandbox.
#[test]
#[ignore = "spends two codex turns; run with mise run vendor-sandbox-tests"]
fn codex_runs_a_turn_under_the_sandbox_with_its_home_in_the_session() {
    let control = run_codex(&Scratch::new("codex-control"), Mode::Unsandboxed);
    println!(
        "evidence: codex through the proxy, unsandboxed: turn completed {}; proxy {}",
        control.completed, control.proxy
    );
    assert!(
        control.completed,
        "the positive control failed: {}",
        control.output
    );
    let sandboxed = run_codex(&Scratch::new("codex"), Mode::Sandboxed);
    println!(
        "evidence: codex under the sandbox: turn completed {}; proxy {}",
        sandboxed.completed, sandboxed.proxy
    );
    assert!(sandboxed.completed, "{}", sandboxed.output);
    assert!(sandboxed.proxy.allowed >= 1, "{}", sandboxed.proxy);
}

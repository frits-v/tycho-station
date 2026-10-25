//! The session sandbox as the trampoline applies it, on this host's kernel: Seatbelt on
//! macOS, Landlock on the Linux ci runner. A kernel that cannot apply it fails these tests;
//! a sandbox that could not be applied is never a pass.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods,
    reason = "test helpers fail the test by panicking; fixtures live in scratch directories"
)]

use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tycho::sandbox::{Access, EXIT_SANDBOX_REFUSED, Grant, PLAN_ENV, SandboxPlan};

const TYCHO: &str = env!("CARGO_BIN_EXE_tycho");
const BASH: &str = "/bin/bash";

/// What the sandboxed shell tries, one line per probe: the core's port, the proxy's port, a
/// write in the granted directory, a write outside every grant, and the plan's variable.
const PROBES: &str = r#"
if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then echo core=open; else echo core=refused; fi
if (exec 3<>"/dev/tcp/127.0.0.1/$2") 2>/dev/null; then echo proxy=open; else echo proxy=refused; fi
if (echo x > "$3/granted") 2>/dev/null; then echo granted=written; else echo granted=refused; fi
if (echo x > "$4/outside") 2>/dev/null; then echo outside=written; else echo outside=refused; fi
if env | grep -q "^TYCHO_SANDBOX_PLAN="; then echo plan=present; else echo plan=absent; fi
"#;

struct Scratch {
    granted: PathBuf,
    outside: PathBuf,
}

impl Scratch {
    /// The granted directory under the system temporary directory; the other one under
    /// `HOME`, which no grant covers.
    fn new(test: &str) -> Self {
        let tag = format!("tycho-sandbox-{test}-{}", std::process::id());
        let granted = std::env::temp_dir().join(&tag);
        let outside = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(".{tag}"));
        for dir in [&granted, &outside] {
            if dir.exists() {
                fs::remove_dir_all(dir).unwrap();
            }
            fs::create_dir_all(dir).unwrap();
        }
        Self { granted, outside }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.granted));
        drop(fs::remove_dir_all(&self.outside));
    }
}

fn plan(proxy_port: u16, core_port: u16, granted: &Path) -> SandboxPlan {
    SandboxPlan {
        proxy_port,
        core_ports: vec![core_port],
        grants: vec![Grant {
            path: granted.to_path_buf(),
            access: Access::ReadWrite,
        }],
        socket_dirs: Vec::new(),
        absent_paths: Vec::new(),
        state_files: Vec::new(),
    }
}

fn run(plan: Option<&SandboxPlan>, words: &[&str]) -> Output {
    run_through("session-leader", plan, words)
}

/// Runs the words through one of the two trampolines the launcher uses.
fn run_through(trampoline: &str, plan: Option<&SandboxPlan>, words: &[&str]) -> Output {
    let mut command = Command::new(TYCHO);
    command.arg(trampoline).arg("--").args(words);
    command.env_remove(PLAN_ENV);
    if let Some(plan) = plan {
        command.env(PLAN_ENV, plan.to_json().unwrap());
    }
    command.output().unwrap()
}

#[test]
fn the_sandboxed_vendor_reaches_only_the_proxy_and_its_grants() {
    for trampoline in ["session-leader", "group-leader"] {
        probe_through(trampoline);
    }
}

fn probe_through(trampoline: &str) {
    let scratch = Scratch::new(trampoline);
    let core = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let core_port = core.local_addr().unwrap().port();
    let proxy_port = proxy.local_addr().unwrap().port();
    let output = run_through(
        trampoline,
        Some(&plan(proxy_port, core_port, &scratch.granted)),
        &[
            BASH,
            "-c",
            PROBES,
            "probes",
            &core_port.to_string(),
            &proxy_port.to_string(),
            &scratch.granted.display().to_string(),
            &scratch.outside.display().to_string(),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{:?}: {stdout}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        [
            "core=refused",
            "proxy=open",
            "granted=written",
            "outside=refused",
            "plan=absent"
        ],
        "{trampoline}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!scratch.outside.join("outside").exists());
}

/// What a refusal case hands the trampoline in `TYCHO_SANDBOX_PLAN`.
enum PlanInput {
    Absent,
    Text(String),
}

fn run_with_input(trampoline: &str, input: &PlanInput, words: &[&str]) -> Output {
    let mut command = Command::new(TYCHO);
    command.arg(trampoline).arg("--").args(words);
    command.env_remove(PLAN_ENV);
    if let PlanInput::Text(text) = input {
        command.env(PLAN_ENV, text);
    }
    command.output().unwrap()
}

/// No plan, a plan that does not decode, one with a field the plan does not have, one whose
/// proxy port is one of the core's, or one with a grant that does not exist: either
/// trampoline refuses with its own exit code and runs nothing.
#[test]
fn a_missing_or_unsound_plan_runs_nothing() {
    let scratch = Scratch::new("refusals");
    let marker = scratch.granted.join("ran");
    let marker_text = marker.display().to_string();
    let words = [BASH, "-c", "echo ran > \"$1\"", "refusal", &marker_text];
    let mut on_core = plan(19_070, 19_070, &scratch.granted);
    on_core.core_ports.push(18_080);
    let mut missing = plan(40_000, 19_070, &scratch.granted);
    missing.grants.push(Grant {
        path: scratch.granted.join("never-made"),
        access: Access::Read,
    });
    let sound = plan(40_000, 19_070, &scratch.granted).to_json().unwrap();
    // A plan built by hand: `to_json` refuses the unsound ones before they leave the launcher.
    let encode = |plan: &SandboxPlan| serde_json::to_string(plan).unwrap();
    let cases = [
        ("none", PlanInput::Absent),
        (
            "not json",
            PlanInput::Text("{\"proxy_port\":40000,".to_string()),
        ),
        (
            "unknown field",
            PlanInput::Text(sound.replacen('{', "{\"extra\":true,", 1)),
        ),
        ("core port", PlanInput::Text(encode(&on_core))),
        ("missing grant", PlanInput::Text(encode(&missing))),
    ];
    let mut examined = 0_usize;
    for trampoline in ["session-leader", "group-leader"] {
        for (name, input) in &cases {
            let output = run_with_input(trampoline, input, &words);
            assert_eq!(
                output.status.code(),
                Some(EXIT_SANDBOX_REFUSED),
                "{trampoline}, {name}: {output:?}"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("sandbox refused"),
                "{trampoline}, {name}: {output:?}"
            );
            assert!(!marker.exists(), "{trampoline}, {name}: the program ran");
            examined += 1;
        }
    }
    assert_eq!(examined, 10);
}

/// A state file is writable with its `<file>.<suffix>` siblings, and nothing else beside it
/// or below a sibling; what the kernel refuses, not what the rule's text says.
#[cfg(target_os = "macos")]
#[test]
fn a_state_file_and_its_siblings_are_writable_and_nothing_else_beside_them() {
    let scratch = Scratch::new("state");
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut state = plan(proxy.local_addr().unwrap().port(), 19_070, &scratch.granted);
    let file = scratch.outside.join(".claude.json");
    fs::create_dir(scratch.outside.join(".claude.json.d")).unwrap();
    state.state_files = vec![file.clone()];
    let script = r#"
cd "$1" || exit 9
w() { if (echo x > "$1") 2>/dev/null; then echo "$1=written"; else echo "$1=refused"; fi; }
w .claude.json.saving
if mv .claude.json.saving .claude.json 2>/dev/null; then echo rename=done; else echo rename=refused; fi
w .claude.jsonx
w .claude.json.d/inner
w other.json
"#;
    let outside = scratch.outside.display().to_string();
    let output = run(Some(&state), &[BASH, "-c", script, "state", &outside]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        [
            ".claude.json.saving=written",
            "rename=done",
            ".claude.jsonx=refused",
            ".claude.json.d/inner=refused",
            "other.json=refused"
        ],
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), "x\n");
}

/// No name resolves through the system resolver inside the sandbox; the same lookup outside
/// it, the positive control, resolves, so a refusal is the sandbox's and not a host without
/// a network.
#[cfg(target_os = "macos")]
#[test]
fn no_name_resolves_inside_the_sandbox() {
    let scratch = Scratch::new("dns");
    let lookup = "dscacheutil -q host -a name api.anthropic.com";
    let resolved = |output: &Output| {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.starts_with("ip_address:") || line.starts_with("ipv6_address:"))
    };
    let outside = Command::new(BASH).args(["-c", lookup]).output().unwrap();
    assert!(
        resolved(&outside),
        "the positive control resolved nothing, so this host cannot tell a refusal"
    );
    let inside = run(
        Some(&plan(40_000, 19_070, &scratch.granted)),
        &[BASH, "-c", lookup],
    );
    assert!(
        !resolved(&inside),
        "a name resolved inside the sandbox: {}",
        String::from_utf8_lossy(&inside.stdout)
    );
}

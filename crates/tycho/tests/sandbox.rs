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
    let mut command = Command::new(TYCHO);
    command.arg("session-leader").arg("--").args(words);
    command.env_remove(PLAN_ENV);
    if let Some(plan) = plan {
        command.env(PLAN_ENV, plan.to_json().unwrap());
    }
    command.output().unwrap()
}

#[test]
fn the_sandboxed_vendor_reaches_only_the_proxy_and_its_grants() {
    let scratch = Scratch::new("probes");
    let core = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let core_port = core.local_addr().unwrap().port();
    let proxy_port = proxy.local_addr().unwrap().port();
    let output = run(
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
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!scratch.outside.join("outside").exists());
}

/// No plan, a plan whose proxy port is one of the core's, or a grant that does not exist:
/// the trampoline refuses with its own exit code and runs nothing.
#[test]
fn a_missing_or_unsound_plan_runs_nothing() {
    let scratch = Scratch::new("refusals");
    let marker = scratch.granted.join("ran");
    let words = [BASH, "-c", "echo ran > \"$1\"", "refusal", ""];
    let mut on_core = plan(19_070, 19_070, &scratch.granted);
    on_core.core_ports.push(18_080);
    let mut missing = plan(40_000, 19_070, &scratch.granted);
    missing.grants.push(Grant {
        path: scratch.granted.join("never-made"),
        access: Access::Read,
    });
    for (name, plan) in [
        ("none", None),
        ("core port", Some(&on_core)),
        ("missing", Some(&missing)),
    ] {
        let marker_text = marker.display().to_string();
        let mut words = words;
        words[4] = &marker_text;
        let output = run(plan, &words);
        assert_eq!(
            output.status.code(),
            Some(EXIT_SANDBOX_REFUSED),
            "{name}: {output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("sandbox refused"),
            "{name}: {output:?}"
        );
        assert!(!marker.exists(), "{name}: the program ran");
    }
}

//! The session trampoline the launcher runs every vendor through: under a pseudo-terminal,
//! a program started through `tycho session-leader` has no controlling terminal, so a tool
//! that touches the terminal cannot stop the vendor's process group.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers fail the test by panicking"
)]

use std::process::Command;

use tycho::sandbox::{PLAN_ENV, SandboxPlan};

const TYCHO: &str = env!("CARGO_BIN_EXE_tycho");

/// The smallest plan the trampoline accepts: the system paths and a proxy port nothing
/// listens on, which no probe here uses.
fn plan() -> String {
    SandboxPlan {
        proxy_port: 40_000,
        core_ports: vec![19_070],
        grants: Vec::new(),
        socket_dirs: Vec::new(),
        absent_paths: Vec::new(),
    }
    .to_json()
    .unwrap()
}
const PROBE: &str = "if (: < /dev/tty) 2>/dev/null; then echo attached; else echo detached; fi";

/// Runs the words under a fresh pseudo-terminal through `script`, which gives them a
/// controlling terminal the way a zmx session does.
fn under_a_terminal(words: &[&str]) -> String {
    let output = if cfg!(target_os = "macos") {
        Command::new("script")
            .args(["-q", "/dev/null"])
            .args(words)
            .env(PLAN_ENV, plan())
            .output()
    } else {
        let line = words
            .iter()
            .map(|word| format!("'{}'", word.replace('\'', r"'\''")))
            .collect::<Vec<_>>()
            .join(" ");
        Command::new("script")
            .args(["-qec", &line, "/dev/null"])
            .env(PLAN_ENV, plan())
            .output()
    }
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    // `script` echoes the end of its input as `^D` and backspaces before the program's output.
    String::from_utf8(output.stdout)
        .unwrap()
        .rsplit(|letter: char| !letter.is_ascii_alphabetic())
        .find(|word| !word.is_empty())
        .unwrap_or_default()
        .to_string()
}

/// The probe runs as a child of a shell that is the terminal's session leader, as the vendor
/// is a child of the worker; the trailing `:` keeps the shell from exec-ing the last command.
fn probe(prefix: &str) -> String {
    let line = format!("{prefix} /bin/sh -c '{PROBE}'; :");
    under_a_terminal(&["/bin/sh", "-c", &line])
}

#[test]
fn a_program_under_the_trampoline_has_no_controlling_terminal() {
    assert_eq!(probe(""), "attached");
    assert_eq!(probe(&format!("{TYCHO} session-leader --")), "detached");
}

#[test]
fn the_trampoline_refuses_a_command_without_its_separator() {
    let output = Command::new(TYCHO)
        .args(["session-leader", "/bin/true"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected --"));
}

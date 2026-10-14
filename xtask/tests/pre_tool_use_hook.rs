#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test by panicking"
)]

use std::io::Write;
use std::process::{Command, Stdio};

/// The hook's standard output and exit code for one hook input.
fn run_hook(input: &str) -> (String, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["hook", "pre-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    (
        String::from_utf8(output.stdout).unwrap(),
        output.status.code().unwrap(),
    )
}

fn bash(command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string()
}

fn denial(stdout: &str) -> String {
    let output: serde_json::Value = serde_json::from_str(stdout).unwrap();
    let field = |name: &str| {
        output
            .pointer(&format!("/hookSpecificOutput/{name}"))
            .and_then(serde_json::Value::as_str)
            .unwrap()
            .to_string()
    };
    assert_eq!(field("hookEventName"), "PreToolUse");
    assert_eq!(field("permissionDecision"), "deny");
    field("permissionDecisionReason")
}

#[test]
fn a_ready_pull_request_is_denied_and_a_draft_with_a_good_title_passes() {
    let (stdout, code) = run_hook(&bash("gh pr create --title 'fix: a b' --body x"));
    assert_eq!(code, 0);
    assert!(denial(&stdout).contains("--draft"), "{stdout}");

    let (stdout, code) = run_hook(&bash("gh pr create --draft --title 'Fix: a b' --body x"));
    assert_eq!(code, 0);
    assert!(
        denial(&stdout).contains("fails the commit subject check"),
        "{stdout}"
    );

    let (stdout, code) = run_hook(&bash("gh pr create --draft --title 'fix: a b' --body x"));
    assert_eq!((stdout.as_str(), code), ("", 0));
}

#[test]
fn input_that_is_not_a_hook_event_is_denied_and_another_tool_passes() {
    let (stdout, code) = run_hook("not json");
    assert_eq!(code, 0);
    assert!(denial(&stdout).contains("not JSON"), "{stdout}");

    let other_tool = serde_json::json!({ "tool_name": "Read", "tool_input": {} }).to_string();
    assert_eq!(run_hook(&other_tool), (String::new(), 0));
}

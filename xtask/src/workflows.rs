//! `xtask workflows`: the CUE workflow policy, then zizmor and jactionlint over the workflow
//! files at pedantic, with their online audits, or without them under `--offline`. zizmor and
//! jactionlint write SARIF under `target/sarif`, and their findings are read from it.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use crate::config::CueOutcome;
use crate::process::{run_bounded, run_bounded_capturing_stderr, Captured, Exit};
use crate::sarif::{self, Finding, Results};

const WORKFLOW_DIR: &str = ".github/workflows";
const POLICY: &str = ".github/workflow-policy.cue";
const POLICY_TIMEOUT: Duration = Duration::from_secs(60);
const WORKFLOW_FILES_MAX: usize = 64;
const AUDIT_TIMEOUT: Duration = Duration::from_secs(300);
const REPORTED_FINDINGS_MAX: usize = 40;
const TOKEN_VARIABLES: [&str; 2] = ["GH_TOKEN", "GITHUB_TOKEN"];

/// Whether the audits that look actions up on GitHub run. ci runs them; the pre-push hook
/// runs offline, so it needs no token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Online,
    Offline,
}

/// How a SARIF-writing audit ended.
#[derive(Debug, PartialEq, Eq)]
pub enum AuditOutcome {
    Clean,
    Findings(Vec<Finding>),
    Unrecognised(String),
}

/// What jactionlint's `--verbose` log says about the run.
#[derive(Debug, PartialEq, Eq)]
pub enum LintLog {
    Examined(usize),
    /// jactionlint drops its shellcheck rule and still passes when it cannot run shellcheck.
    ShellcheckMissing,
    Unrecognised,
}

/// zizmor exits 0 with `--format sarif` whether or not it found anything, so its results
/// decide the outcome.
pub fn decode_zizmor(exit: &Exit, output: &str) -> AuditOutcome {
    if *exit != Exit::Code(0) {
        return AuditOutcome::Unrecognised(format!("zizmor ended {exit:?}"));
    }
    findings_from(output)
}

/// jactionlint with `--strict-exit` exits 1 exactly when it reports a finding at any level.
pub fn decode_jactionlint(exit: &Exit, output: &str) -> AuditOutcome {
    match (exit, findings_from(output)) {
        (_, AuditOutcome::Unrecognised(reason)) => AuditOutcome::Unrecognised(reason),
        (Exit::Code(0), AuditOutcome::Clean) => AuditOutcome::Clean,
        (Exit::Code(1), AuditOutcome::Findings(findings)) => AuditOutcome::Findings(findings),
        (exit, outcome) => {
            AuditOutcome::Unrecognised(format!("jactionlint ended {exit:?} with {outcome:?}"))
        }
    }
}

fn findings_from(output: &str) -> AuditOutcome {
    let document: Value = match serde_json::from_str(output) {
        Ok(document) => document,
        Err(error) => return AuditOutcome::Unrecognised(format!("no SARIF: {error}")),
    };
    match sarif::results(&document) {
        Results::Findings(findings) if findings.is_empty() => AuditOutcome::Clean,
        Results::Findings(findings) => AuditOutcome::Findings(findings),
        Results::Unrecognised(reason) => AuditOutcome::Unrecognised(reason),
    }
}

pub fn decode_lint_log(log: &str) -> LintLog {
    if log
        .lines()
        .any(|line| line.starts_with("verbose: Rule \"shellcheck\" was disabled"))
    {
        return LintLog::ShellcheckMissing;
    }
    for line in log.lines() {
        let Some(rest) = line.strip_prefix("verbose: Found ") else {
            continue;
        };
        let words: Vec<&str> = rest.split_whitespace().collect();
        if let [_, "error" | "errors", "in", files, "file" | "files"] = words.as_slice() {
            return files
                .parse()
                .map_or(LintLog::Unrecognised, LintLog::Examined);
        }
    }
    LintLog::Unrecognised
}

/// The online audits need a GitHub token in the environment; without one they cannot run,
/// which is a failure rather than a pass. The token itself is never read here.
fn token_present() -> bool {
    TOKEN_VARIABLES
        .iter()
        .any(|name| env::var(name).is_ok_and(|value| !value.is_empty()))
}

fn workflow_files() -> Result<Vec<PathBuf>, String> {
    let entries = fs::read_dir(WORKFLOW_DIR)
        .map_err(|error| format!("cannot read {WORKFLOW_DIR}: {error}"))?;
    let mut files = Vec::new();
    for (index, entry) in entries
        .enumerate()
        .take(WORKFLOW_FILES_MAX.saturating_add(1))
    {
        if index >= WORKFLOW_FILES_MAX {
            return Err(format!(
                "more than {WORKFLOW_FILES_MAX} entries under {WORKFLOW_DIR}"
            ));
        }
        let path = entry
            .map_err(|error| format!("cannot read {WORKFLOW_DIR}: {error}"))?
            .path();
        let extension = path.extension().and_then(|extension| extension.to_str());
        if matches!(extension, Some("yml" | "yaml")) {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// Keeps the tool's SARIF for upload unless the decoder did not recognise it, then reports.
fn report(tool: &str, output: &str, outcome: AuditOutcome) -> Result<(), String> {
    if !matches!(outcome, AuditOutcome::Unrecognised(_)) {
        sarif::write_text(tool, output)?;
    }
    match outcome {
        AuditOutcome::Clean => Ok(()),
        AuditOutcome::Findings(findings) => {
            for finding in findings.iter().take(REPORTED_FINDINGS_MAX) {
                eprintln!("  {finding}");
            }
            Err(format!("{tool}: {} findings", findings.len()))
        }
        AuditOutcome::Unrecognised(reason) => Err(format!("{tool}: {reason}")),
    }
}

/// `cue vet -c` of one workflow file against the policy; cue prints a refusal's reasons.
fn policy_outcome(policy: &Path, file: &Path) -> CueOutcome {
    let captured = run_bounded(
        Command::new("cue")
            .args(["vet", "-c"])
            .arg(policy)
            .arg(file),
        POLICY_TIMEOUT,
    );
    crate::config::decode(&captured.exit, captured.stdout)
}

/// Every workflow file against `.github/workflow-policy.cue`; returns how many it examined.
fn policy(files: &[PathBuf]) -> Result<usize, String> {
    let refused: Vec<String> = files
        .iter()
        .filter_map(|file| match policy_outcome(Path::new(POLICY), file) {
            CueOutcome::Clean(_) => None,
            CueOutcome::Rejected => Some(format!("{} breaks the policy", file.display())),
            other => Some(format!("{}: cue {other:?}", file.display())),
        })
        .collect();
    if refused.is_empty() {
        Ok(files.len())
    } else {
        Err(format!("{POLICY}: {}", refused.join("; ")))
    }
}

fn zizmor_arguments(network: Network) -> Vec<&'static str> {
    let mut arguments = vec!["--persona=pedantic", "--format", "sarif", "--no-progress"];
    if network == Network::Offline {
        arguments.push("--no-online-audits");
    }
    arguments
}

const fn jactionlint_arguments(network: Network) -> [&'static str; 5] {
    let online = match network {
        Network::Online => "--online=strict",
        Network::Offline => "--no-online",
    };
    ["--format", "sarif", "--strict-exit", online, "--verbose"]
}

fn zizmor(files: &[PathBuf], network: Network) -> Result<(), String> {
    let captured = run_bounded(
        Command::new("zizmor")
            .args(zizmor_arguments(network))
            .args(files),
        AUDIT_TIMEOUT,
    );
    let outcome = decode_zizmor(&captured.exit, &captured.stdout);
    report("zizmor", &captured.stdout, outcome)
}

/// The profile and the action allow list live in `.github/jactionlint.yaml`.
fn jactionlint(network: Network) -> Result<usize, String> {
    let captured: Captured = run_bounded_capturing_stderr(
        Command::new("jactionlint").args(jactionlint_arguments(network)),
        AUDIT_TIMEOUT,
    );
    for line in captured
        .stderr
        .lines()
        .filter(|line| !line.starts_with("verbose: "))
    {
        eprintln!("{line}");
    }
    let files = match decode_lint_log(&captured.stderr) {
        LintLog::Examined(0) => return Err("jactionlint examined 0 files".to_string()),
        LintLog::Examined(files) => files,
        LintLog::ShellcheckMissing => {
            return Err("jactionlint could not run shellcheck over the run: scripts".to_string())
        }
        LintLog::Unrecognised => {
            return Err("jactionlint printed no `Found N errors in M files` summary".to_string())
        }
    };
    let outcome = decode_jactionlint(&captured.exit, &captured.stdout);
    report("jactionlint", &captured.stdout, outcome)?;
    Ok(files)
}

fn audits(network: Network) -> Result<String, String> {
    if network == Network::Online && !token_present() {
        return Err(format!(
            "no GitHub token in {}; the online audits need one",
            TOKEN_VARIABLES.join(" or ")
        ));
    }
    let files = workflow_files()?;
    if files.is_empty() {
        return Err(format!("no workflow files under {WORKFLOW_DIR}"));
    }
    let vetted = policy(&files)?;
    let zizmor_result = zizmor(&files, network);
    let linted = jactionlint(network)?;
    zizmor_result?;
    let mode = match network {
        Network::Online => "",
        Network::Offline => " offline",
    };
    Ok(format!(
        "the policy examined {vetted} files, zizmor {}{mode}, jactionlint {linted}, no findings",
        files.len()
    ))
}

/// `xtask workflows [--offline]`.
pub fn command(argument: Option<&str>) -> i32 {
    match argument {
        None => workflows(Network::Online),
        Some("--offline") => workflows(Network::Offline),
        Some(other) => {
            eprintln!("usage: xtask workflows [--offline]; got {other}");
            2
        }
    }
}

pub fn workflows(network: Network) -> i32 {
    match audits(network) {
        Ok(summary) => {
            println!("xtask workflows: {summary}");
            0
        }
        Err(reason) => {
            eprintln!("xtask workflows: {reason}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each fixture under `xtask/fixtures/workflow-policy` is named for what the policy does
    /// with it; the cases are a privileged workflow checking out a ref or a repository, one
    /// with workflow-level concurrency, a privileged base checkout, and an unprivileged ref.
    #[test]
    fn the_policy_refuses_a_privileged_checkout_of_the_author_s_code_and_nothing_else() {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let policy_file = crate_dir.join("..").join(POLICY);
        let fixtures = crate_dir.join("fixtures/workflow-policy");
        let mut names: Vec<PathBuf> = fs::read_dir(&fixtures)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        names.sort();
        assert_eq!(names.len(), 5, "{names:?}");
        for fixture in names {
            let name = fixture.file_name().unwrap().to_string_lossy().into_owned();
            let outcome = policy_outcome(&policy_file, &fixture);
            if name.starts_with("refused-") {
                assert_eq!(outcome, CueOutcome::Rejected, "{name}");
            } else {
                assert!(
                    matches!(outcome, CueOutcome::Clean(_)),
                    "{name}: {outcome:?}"
                );
            }
        }
    }

    const CLEAN: &str =
        r#"{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "z"}}, "results": []}]}"#;
    const ONE: &str = r#"{"version": "2.1.0", "runs": [{"results": [{
        "ruleId": "missing-timeout", "message": {"text": "no timeout"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".github/workflows/ci.yml"},
        "region": {"startLine": 12, "startColumn": 3}}}]}]}]}"#;

    #[test]
    fn offline_audits_turn_off_each_tools_network_and_online_ones_are_strict() {
        assert!(zizmor_arguments(Network::Offline).contains(&"--no-online-audits"));
        assert!(!zizmor_arguments(Network::Online).contains(&"--no-online-audits"));
        assert!(jactionlint_arguments(Network::Offline).contains(&"--no-online"));
        assert!(jactionlint_arguments(Network::Online).contains(&"--online=strict"));
    }

    #[test]
    fn zizmor_is_judged_by_its_results() {
        assert_eq!(decode_zizmor(&Exit::Code(0), CLEAN), AuditOutcome::Clean);
        assert!(matches!(
            decode_zizmor(&Exit::Code(0), ONE),
            AuditOutcome::Findings(findings) if findings.len() == 1
        ));
        assert!(matches!(
            decode_zizmor(&Exit::Code(1), CLEAN),
            AuditOutcome::Unrecognised(_)
        ));
        assert!(matches!(
            decode_zizmor(&Exit::Code(0), "not json"),
            AuditOutcome::Unrecognised(_)
        ));
    }

    #[test]
    fn jactionlint_exit_and_results_must_agree() {
        assert_eq!(
            decode_jactionlint(&Exit::Code(0), CLEAN),
            AuditOutcome::Clean
        );
        assert!(matches!(
            decode_jactionlint(&Exit::Code(1), ONE),
            AuditOutcome::Findings(_)
        ));
        assert!(matches!(
            decode_jactionlint(&Exit::Code(0), ONE),
            AuditOutcome::Unrecognised(_)
        ));
        assert!(matches!(
            decode_jactionlint(&Exit::Code(1), CLEAN),
            AuditOutcome::Unrecognised(_)
        ));
        assert!(matches!(
            decode_jactionlint(&Exit::TimedOut, CLEAN),
            AuditOutcome::Unrecognised(_)
        ));
    }

    #[test]
    fn the_lint_log_gives_the_file_count() {
        let log = "verbose: Found 0 parse errors in 2 ms for .github/workflows/ci.yml\n\
                   verbose: Found 15 errors in 2 files\n";
        assert_eq!(decode_lint_log(log), LintLog::Examined(2));
        assert_eq!(
            decode_lint_log("verbose: Found 1 error in 1 file\n"),
            LintLog::Examined(1)
        );
    }

    #[test]
    fn a_lint_log_without_shellcheck_or_a_summary_fails() {
        let log = "verbose: Rule \"shellcheck\" was disabled: exec: \"shellcheck\": executable file not found in $PATH\n\
                   verbose: Found 0 errors in 3 files\n";
        assert_eq!(decode_lint_log(log), LintLog::ShellcheckMissing);
        assert_eq!(
            decode_lint_log("verbose: Linting 3 files\n"),
            LintLog::Unrecognised
        );
    }
}

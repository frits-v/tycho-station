//! `xtask opengrep`: every rule in `opengrep/rust.yml` against its fixture lines in
//! `opengrep/rust.rs`, then the rules over the Rust sources. The scan's SARIF goes to
//! `target/sarif/opengrep.sarif`.

use std::collections::BTreeSet;
use std::fs;
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use crate::process::{run_bounded, Exit};
use crate::sarif::{self, Finding};

const RULES_FILE: &str = "opengrep/rust.yml";
const FIXTURE_DIR: &str = "opengrep";
const SCANNED_DIRS: [&str; 2] = ["crates", "xtask"];
const EXCLUDED: [&str; 2] = ["target", ".worktrees"];
const OPENGREP_TIMEOUT: Duration = Duration::from_secs(300);
const RULES_MAX: usize = 256;
const REPORTED_FINDINGS_MAX: usize = 40;

/// How one rule fared against its fixture lines.
#[derive(Debug, PartialEq, Eq)]
pub enum FixtureVerdict {
    Passed {
        lines: usize,
    },
    /// The rule has no `ruleid:` fixture line, or opengrep did not test it at all.
    NoFixtureLines,
    /// A `ruleid:` line the rule did not report.
    Missed(Vec<u64>),
    /// A reported line no `ruleid:` marks: a fixture false positive.
    FalsePositive(Vec<u64>),
    /// opengrep's `passed` disagrees with the lines it reported, or the entry has another shape.
    Unrecognised(String),
}

/// What `opengrep test --json` reported.
#[derive(Debug, PartialEq, Eq)]
pub enum TestReport {
    Rules(Vec<(String, FixtureVerdict)>),
    /// A rule file opengrep could not load or found no fixture for.
    BrokenConfig(String),
    Unrecognised(String),
}

/// What `opengrep scan --json --error` reported.
#[derive(Debug, PartialEq, Eq)]
pub enum ScanReport {
    Clean {
        files: usize,
    },
    Findings {
        files: usize,
        findings: Vec<Finding>,
    },
    /// The scan ran over no file.
    Empty,
    /// opengrep listed errors or skipped rules.
    ToolErrors(String),
    Unrecognised(String),
}

/// The rule ids of an opengrep rule file, sorted; more than the bound is an error.
pub fn rule_ids(rules: &str) -> Result<Vec<String>, String> {
    let mut ids: Vec<String> = rules
        .lines()
        .filter_map(|line| line.strip_prefix("  - id: "))
        .map(|id| id.trim().to_string())
        .take(RULES_MAX.saturating_add(1))
        .collect();
    if ids.len() > RULES_MAX {
        return Err(format!("{RULES_FILE} defines more than {RULES_MAX} rules"));
    }
    ids.sort();
    Ok(ids)
}

fn line_numbers(value: Option<&Value>) -> Option<BTreeSet<u64>> {
    value?.as_array()?.iter().map(Value::as_u64).collect()
}

/// The expected and reported lines of one rule, over all its fixture files.
fn rule_lines(check: &Value) -> Option<(BTreeSet<u64>, BTreeSet<u64>)> {
    let mut expected = BTreeSet::new();
    let mut reported = BTreeSet::new();
    for file in check.get("matches")?.as_object()?.values() {
        expected.extend(line_numbers(file.get("expected_lines"))?);
        reported.extend(line_numbers(file.get("reported_lines"))?);
    }
    Some((expected, reported))
}

pub fn fixture_verdict(check: &Value) -> FixtureVerdict {
    let Some(passed) = check.get("passed").and_then(Value::as_bool) else {
        return FixtureVerdict::Unrecognised("no boolean `passed`".to_string());
    };
    let Some((expected, reported)) = rule_lines(check) else {
        return FixtureVerdict::Unrecognised("`matches` is not a map of line lists".to_string());
    };
    if expected.is_empty() {
        return FixtureVerdict::NoFixtureLines;
    }
    let missed: Vec<u64> = expected.difference(&reported).copied().collect();
    let extra: Vec<u64> = reported.difference(&expected).copied().collect();
    let verdict = if !missed.is_empty() {
        FixtureVerdict::Missed(missed)
    } else if !extra.is_empty() {
        FixtureVerdict::FalsePositive(extra)
    } else {
        FixtureVerdict::Passed {
            lines: expected.len(),
        }
    };
    if matches!(verdict, FixtureVerdict::Passed { .. }) == passed {
        verdict
    } else {
        FixtureVerdict::Unrecognised(format!(
            "`passed` is {passed} but the lines say {verdict:?}"
        ))
    }
}

pub fn decode_test(report: &Value) -> TestReport {
    for name in ["config_with_errors", "config_missing_tests"] {
        match report.get(name).and_then(Value::as_array) {
            Some(entries) if entries.is_empty() => {}
            Some(entries) => return TestReport::BrokenConfig(format!("{name}: {entries:?}")),
            None => return TestReport::Unrecognised(format!("no `{name}` array")),
        }
    }
    let Some(configs) = report.get("results").and_then(Value::as_object) else {
        return TestReport::Unrecognised("no `results` map".to_string());
    };
    let mut rules = Vec::new();
    for config in configs.values() {
        let Some(checks) = config.get("checks").and_then(Value::as_object) else {
            return TestReport::Unrecognised("a config without a `checks` map".to_string());
        };
        if checks.len().saturating_add(rules.len()) > RULES_MAX {
            return TestReport::Unrecognised(format!("more than {RULES_MAX} tested rules"));
        }
        for (rule, check) in checks {
            let id = rule.rsplit('.').next().unwrap_or(rule).to_string();
            rules.push((id, fixture_verdict(check)));
        }
    }
    rules.sort_by(|left, right| left.0.cmp(&right.0));
    TestReport::Rules(rules)
}

/// Every rule in the rule file passed its fixtures; a rule opengrep did not test counts as
/// having no fixture lines. Returns the number of rules.
pub fn fixtures_pass(rule_ids: &[String], report: TestReport) -> Result<usize, String> {
    let rules = match report {
        TestReport::Rules(rules) => rules,
        TestReport::BrokenConfig(reason) => return Err(format!("broken rule file: {reason}")),
        TestReport::Unrecognised(reason) => {
            return Err(format!("unrecognised test report: {reason}"))
        }
    };
    let mut failures = Vec::new();
    for id in rule_ids {
        match rules.iter().find(|(tested, _)| tested == id) {
            Some((_, FixtureVerdict::Passed { .. })) => {}
            Some((_, verdict)) => failures.push(format!("{id}: {verdict:?}")),
            None => failures.push(format!("{id}: {:?}", FixtureVerdict::NoFixtureLines)),
        }
    }
    for (tested, _) in &rules {
        if !rule_ids.contains(tested) {
            failures.push(format!("{tested}: tested but not in {RULES_FILE}"));
        }
    }
    if rule_ids.is_empty() {
        failures.push(format!("{RULES_FILE} defines no rules"));
    }
    if failures.is_empty() {
        Ok(rule_ids.len())
    } else {
        Err(failures.join("; "))
    }
}

fn scan_finding(result: &Value) -> Option<Finding> {
    let check_id = result.get("check_id")?.as_str()?;
    let rule = check_id.rsplit('.').next().unwrap_or(check_id);
    let number = |field: &str| {
        result
            .pointer(&format!("/start/{field}"))
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
    };
    Some(Finding {
        path: result.get("path")?.as_str()?.to_string(),
        line: number("line")?,
        column: number("col")?,
        rule: rule.to_string(),
        message: result
            .pointer("/extra/message")?
            .as_str()?
            .trim()
            .to_string(),
    })
}

/// Decodes the scan's JSON together with its exit: `--error` makes opengrep exit 1 exactly
/// when it reports findings.
pub fn decode_scan(exit: &Exit, report: &Value) -> ScanReport {
    for name in ["errors", "skipped_rules"] {
        match report.get(name).and_then(Value::as_array) {
            Some(entries) if entries.is_empty() => {}
            Some(entries) => return ScanReport::ToolErrors(format!("{name}: {entries:?}")),
            None => return ScanReport::Unrecognised(format!("no `{name}` array")),
        }
    }
    let Some(files) = report.pointer("/paths/scanned").and_then(Value::as_array) else {
        return ScanReport::Unrecognised("no `paths.scanned` array".to_string());
    };
    let Some(results) = report.get("results").and_then(Value::as_array) else {
        return ScanReport::Unrecognised("no `results` array".to_string());
    };
    let Some(findings) = results.iter().map(scan_finding).collect::<Option<Vec<_>>>() else {
        return ScanReport::Unrecognised("a result without path, position or message".to_string());
    };
    match (exit, files.len(), findings.is_empty()) {
        (_, 0, _) => ScanReport::Empty,
        (Exit::Code(0), files, true) => ScanReport::Clean { files },
        (Exit::Code(1), files, false) => ScanReport::Findings { files, findings },
        (exit, files, _) => ScanReport::Unrecognised(format!(
            "exit {exit:?} with {} findings in {files} files",
            findings.len()
        )),
    }
}

fn run_json(command: &mut Command, allowed: &[i32]) -> Result<(Exit, Value), String> {
    let captured = run_bounded(command, OPENGREP_TIMEOUT);
    match &captured.exit {
        Exit::Code(code) if allowed.contains(code) => {}
        other => return Err(format!("opengrep ended {other:?}")),
    }
    let report = serde_json::from_str(&captured.stdout)
        .map_err(|error| format!("opengrep wrote no JSON report: {error}"))?;
    Ok((captured.exit, report))
}

fn test_fixtures(rule_ids: &[String]) -> Result<usize, String> {
    let (_, report) = run_json(
        Command::new("opengrep").args(["test", "--json", FIXTURE_DIR]),
        &[0, 1],
    )?;
    fixtures_pass(rule_ids, decode_test(&report))
}

fn scan() -> Result<ScanReport, String> {
    let sarif_path = sarif::path_for("opengrep");
    sarif::ensure_directory()?;
    let mut command = Command::new("opengrep");
    command.args([
        "scan",
        "--config",
        RULES_FILE,
        "--error",
        "--disable-version-check",
        "--quiet",
        "--json",
    ]);
    command.arg(format!("--sarif-output={}", sarif_path.display()));
    for excluded in EXCLUDED {
        command.args(["--exclude", excluded]);
    }
    command.args(SCANNED_DIRS);
    let (exit, report) = run_json(&mut command, &[0, 1])?;
    Ok(decode_scan(&exit, &report))
}

fn opengrep_steps() -> Result<String, String> {
    let rules = fs::read_to_string(RULES_FILE)
        .map_err(|error| format!("cannot read {RULES_FILE}: {error}"))?;
    let rule_ids = rule_ids(&rules)?;
    let rule_count = test_fixtures(&rule_ids)?;
    println!("xtask opengrep: {rule_count} rules pass their fixtures");
    match scan()? {
        ScanReport::Clean { files } => Ok(format!(
            "examined {rule_count} rules over {files} files, no findings"
        )),
        ScanReport::Findings { files, findings } => {
            for finding in findings.iter().take(REPORTED_FINDINGS_MAX) {
                eprintln!("  {finding}");
            }
            Err(format!(
                "examined {rule_count} rules over {files} files, {} findings",
                findings.len()
            ))
        }
        ScanReport::Empty => {
            Err("the scan examined 0 files; a check over nothing is a failure".into())
        }
        ScanReport::ToolErrors(reason) => Err(format!("opengrep reported errors: {reason}")),
        ScanReport::Unrecognised(reason) => Err(format!("unrecognised scan report: {reason}")),
    }
}

pub fn opengrep() -> i32 {
    match opengrep_steps() {
        Ok(summary) => {
            println!("xtask opengrep: {summary}");
            0
        }
        Err(reason) => {
            eprintln!("xtask opengrep: {reason}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn check(passed: bool, expected: &[u64], reported: &[u64]) -> Value {
        json!({"passed": passed, "matches": {"opengrep/rust.rs": {
            "expected_lines": expected, "reported_lines": reported
        }}, "errors": []})
    }

    fn test_report(checks: &Value) -> Value {
        json!({
            "results": {"opengrep/rust.yml": {"checks": checks}},
            "fixtest_results": {},
            "config_missing_tests": [],
            "config_missing_fixtests": [],
            "config_with_errors": []
        })
    }

    fn ids(names: &[&str]) -> Vec<String> {
        names.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn rule_ids_are_read_sorted_from_the_rule_file() {
        let rules = "rules:\n  - id: zeta\n    message: x\n  - id: alpha\n";
        assert_eq!(rule_ids(rules), Ok(ids(&["alpha", "zeta"])));
        let many = "  - id: rule\n".repeat(RULES_MAX.saturating_add(1));
        assert!(rule_ids(&many).is_err());
    }

    #[test]
    fn each_fixture_state_maps_to_its_verdict() {
        assert_eq!(
            fixture_verdict(&check(true, &[3, 5], &[3, 5])),
            FixtureVerdict::Passed { lines: 2 }
        );
        assert_eq!(
            fixture_verdict(&check(false, &[3, 5], &[3])),
            FixtureVerdict::Missed(vec![5])
        );
        assert_eq!(
            fixture_verdict(&check(false, &[3], &[3, 9])),
            FixtureVerdict::FalsePositive(vec![9])
        );
        assert_eq!(
            fixture_verdict(&check(true, &[], &[])),
            FixtureVerdict::NoFixtureLines
        );
        assert!(matches!(
            fixture_verdict(&check(true, &[3], &[])),
            FixtureVerdict::Unrecognised(_)
        ));
        assert!(matches!(
            fixture_verdict(&json!({"passed": true})),
            FixtureVerdict::Unrecognised(_)
        ));
    }

    #[test]
    fn a_passing_report_covers_every_rule() {
        let report = test_report(&json!({
            "opengrep.rust-a": check(true, &[3], &[3]),
            "opengrep.rust-b": check(true, &[7], &[7]),
        }));
        assert_eq!(
            fixtures_pass(&ids(&["rust-a", "rust-b"]), decode_test(&report)),
            Ok(2)
        );
    }

    #[test]
    fn an_untested_rule_a_fixture_miss_or_no_rules_fails() {
        let report = test_report(&json!({"rust-a": check(true, &[3], &[3])}));
        assert!(fixtures_pass(&ids(&["rust-a", "rust-b"]), decode_test(&report)).is_err());
        let missed = test_report(&json!({"rust-a": check(false, &[3], &[])}));
        assert!(fixtures_pass(&ids(&["rust-a"]), decode_test(&missed)).is_err());
        assert!(fixtures_pass(&[], decode_test(&test_report(&json!({})))).is_err());
    }

    #[test]
    fn a_broken_config_or_a_missing_field_is_not_a_pass() {
        let mut broken = test_report(&json!({}));
        broken["config_with_errors"] = json!(["opengrep/rust.yml"]);
        assert!(matches!(decode_test(&broken), TestReport::BrokenConfig(_)));
        let mut missing = test_report(&json!({}));
        if let Some(object) = missing.as_object_mut() {
            object.remove("config_missing_tests");
        }
        assert!(matches!(decode_test(&missing), TestReport::Unrecognised(_)));
    }

    fn scan_report(scanned: &[&str], results: &Value) -> Value {
        json!({"errors": [], "skipped_rules": [], "paths": {"scanned": scanned}, "results": results})
    }

    #[test]
    fn a_scan_maps_each_exit_and_result_shape_to_a_state() {
        let finding = json!([{
            "check_id": "opengrep.rust-todo-without-ticket",
            "path": "a.rs",
            "start": {"line": 7, "col": 5},
            "extra": {"message": "TODO without a ticket reference.\n"}
        }]);
        assert_eq!(
            decode_scan(&Exit::Code(0), &scan_report(&["a.rs", "b.rs"], &json!([]))),
            ScanReport::Clean { files: 2 }
        );
        let ScanReport::Findings { files, findings } =
            decode_scan(&Exit::Code(1), &scan_report(&["a.rs"], &finding))
        else {
            panic!("expected findings");
        };
        assert_eq!(files, 1);
        assert_eq!(
            findings.first().map(ToString::to_string).as_deref(),
            Some("a.rs:7:5: rust-todo-without-ticket: TODO without a ticket reference.")
        );
        assert_eq!(
            decode_scan(&Exit::Code(0), &scan_report(&[], &json!([]))),
            ScanReport::Empty
        );
        assert!(matches!(
            decode_scan(&Exit::Code(0), &scan_report(&["a.rs"], &finding)),
            ScanReport::Unrecognised(_)
        ));
        assert!(matches!(
            decode_scan(&Exit::Code(1), &scan_report(&["a.rs"], &json!([]))),
            ScanReport::Unrecognised(_)
        ));
        let mut errors = scan_report(&["a.rs"], &json!([]));
        errors["errors"] = json!([{"message": "parse error"}]);
        assert!(matches!(
            decode_scan(&Exit::Code(0), &errors),
            ScanReport::ToolErrors(_)
        ));
    }
}

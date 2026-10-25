//! `xtask codeql`: the `codeql` CLI's GitHub Actions security queries over the workflow files,
//! with the CLI pinned in `mise.toml` and the query pack pinned here. It runs before a push
//! that changes `.github`; code scanning runs the full analysis on every pull request. Its
//! SARIF goes to `target/codeql`, apart from `target/sarif`, since code scanning refuses such
//! results uploaded beside its default setup.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use crate::process::{Exit, run_bounded};
use crate::sarif::{self, Finding, Results};

const PACK: &str = "codeql/actions-queries@0.6.37";
const SUITE: &str = "codeql/actions-queries@0.6.37:codeql-suites/actions-security-extended.qls";
const OUTPUT_DIR: &str = "target/codeql";
const DATABASE: &str = "target/codeql/actions";
const RESULTS: &str = "target/codeql/actions.sarif";
const PACK_TIMEOUT: Duration = Duration::from_mins(5);
const CREATE_TIMEOUT: Duration = Duration::from_mins(5);
const ANALYZE_TIMEOUT: Duration = Duration::from_mins(10);
const BASELINE_MAX_BYTES: u64 = 4 << 20;
const RESULTS_MAX_BYTES: u64 = 32 << 20;
const REPORTED_FINDINGS_MAX: usize = 40;

/// What an analysis came to: the queries it ran and the files it extracted, with what they
/// found; anything else is unrecognised.
#[derive(Debug, PartialEq, Eq)]
pub enum Analysis {
    Clean { queries: usize, files: usize },
    Findings(Vec<Finding>),
    Unrecognised(String),
}

fn step(name: &str, command: &mut Command, timeout: Duration) -> Result<(), String> {
    match run_bounded(command, timeout).exit {
        Exit::Code(0) => Ok(()),
        other => Err(format!("{name} ended {other:?}")),
    }
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<String, String> {
    let size = fs::metadata(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?
        .len();
    if size > max_bytes {
        return Err(format!("{} is over {max_bytes} bytes", path.display()));
    }
    fs::read_to_string(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

/// The workflow files the extractor took in, from the database's baseline.
pub fn extracted_files(baseline: &str) -> Result<usize, String> {
    let value: Value =
        serde_json::from_str(baseline).map_err(|_| "the baseline is not JSON".to_string())?;
    value
        .pointer("/languages/actions/files")
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or_else(|| "the baseline names no GitHub Actions files".to_string())
}

/// Decodes the analysis's SARIF; an analysis that ran no query or read no file is
/// unrecognised, never clean.
pub fn decode(results: &str, files: usize) -> Analysis {
    let Ok(document) = serde_json::from_str::<Value>(results) else {
        return Analysis::Unrecognised("the results are not SARIF".to_string());
    };
    let queries = document
        .pointer("/runs/0/tool/driver/rules")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if queries == 0 || files == 0 {
        return Analysis::Unrecognised(format!("{queries} queries over {files} files"));
    }
    match sarif::results(&document) {
        Results::Findings(findings) if findings.is_empty() => Analysis::Clean { queries, files },
        Results::Findings(findings) => Analysis::Findings(findings),
        Results::Unrecognised(reason) => Analysis::Unrecognised(reason),
    }
}

fn analyse() -> Result<Analysis, String> {
    for directory in ["target", OUTPUT_DIR] {
        match fs::create_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("cannot create {directory}: {error}")),
        }
    }
    step(
        "codeql pack download",
        Command::new("codeql").args(["pack", "download", PACK]),
        PACK_TIMEOUT,
    )?;
    step(
        "codeql database create",
        Command::new("codeql").args([
            "database",
            "create",
            DATABASE,
            "--language=actions",
            "--source-root=.",
            "--overwrite",
        ]),
        CREATE_TIMEOUT,
    )?;
    let files = extracted_files(&read_bounded(
        &Path::new(DATABASE).join("baseline-info.json"),
        BASELINE_MAX_BYTES,
    )?)?;
    step(
        "codeql database analyze",
        Command::new("codeql").args([
            "database",
            "analyze",
            DATABASE,
            SUITE,
            "--format=sarif-latest",
            &format!("--output={RESULTS}"),
            "--threads=0",
        ]),
        ANALYZE_TIMEOUT,
    )?;
    Ok(decode(
        &read_bounded(Path::new(RESULTS), RESULTS_MAX_BYTES)?,
        files,
    ))
}

pub fn codeql() -> i32 {
    match analyse() {
        Ok(Analysis::Clean { queries, files }) => {
            println!(
                "xtask codeql: {queries} queries examined {files} workflow files, no findings"
            );
            0
        }
        Ok(Analysis::Findings(findings)) => {
            for finding in findings.iter().take(REPORTED_FINDINGS_MAX) {
                eprintln!("  {finding}");
            }
            eprintln!(
                "xtask codeql: {} findings; the SARIF is {RESULTS}",
                findings.len()
            );
            1
        }
        Ok(Analysis::Unrecognised(reason)) | Err(reason) => {
            eprintln!("xtask codeql: {reason}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn results(rules: usize, findings: &str) -> String {
        let rules: Vec<Value> = (0..rules)
            .map(|index| serde_json::json!({"id": format!("actions/rule-{index}")}))
            .collect();
        format!(
            r#"{{"version":"2.1.0","runs":[{{"tool":{{"driver":{{"name":"CodeQL","rules":{}}}}},"results":{findings}}}]}}"#,
            Value::Array(rules)
        )
    }

    #[test]
    fn the_baseline_counts_the_extracted_workflow_files() {
        let baseline = r#"{"languages":{"actions":{"files":[".github/workflows/ci.yml",
            ".github/workflows/review.yml"],"linesOfCode":90}}}"#;
        assert_eq!(extracted_files(baseline), Ok(2));
        assert!(extracted_files(r#"{"languages":{"rust":{"files":[]}}}"#).is_err());
        assert!(extracted_files("not json").is_err());
    }

    #[test]
    fn a_clean_analysis_reports_its_queries_and_files() {
        assert_eq!(
            decode(&results(23, "[]"), 4),
            Analysis::Clean {
                queries: 23,
                files: 4
            }
        );
    }

    #[test]
    fn an_analysis_over_nothing_or_with_no_queries_is_never_clean() {
        assert!(matches!(
            decode(&results(23, "[]"), 0),
            Analysis::Unrecognised(_)
        ));
        assert!(matches!(
            decode(&results(0, "[]"), 4),
            Analysis::Unrecognised(_)
        ));
        assert!(matches!(decode("not sarif", 4), Analysis::Unrecognised(_)));
    }

    #[test]
    fn a_result_is_a_finding_with_its_location() {
        let finding = r#"[{"ruleId":"actions/untrusted-checkout-toctou/critical",
            "message":{"text":"Insufficient protection"},
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":".github/workflows/review.yml"},
            "region":{"startLine":65,"startColumn":16}}}]}]"#;
        match decode(&results(23, finding), 4) {
            Analysis::Findings(findings) => {
                assert_eq!(findings.len(), 1);
                assert_eq!(findings.first().unwrap().line, 65);
            }
            other => panic!("{other:?}"),
        }
    }
}

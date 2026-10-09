//! SARIF 2.1.0 files under `target/sarif`: the runs the xtask's own checks write, and a
//! reader for the results other tools write there.

use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

pub const SARIF_DIR: &str = "target/sarif";
const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const RESULTS_MAX: usize = 10_000;
pub const SARIF_FILES_MAX: usize = 64;

/// One finding at a file, line and column, all one-based.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub rule: String,
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}: {}: {}",
            self.path, self.line, self.column, self.rule, self.message
        )
    }
}

impl Finding {
    pub fn at(path: &Path, line: usize, column: usize, rule: &str, message: String) -> Self {
        Self {
            path: path.display().to_string(),
            line: line.max(1),
            column: column.max(1),
            rule: rule.to_string(),
            message,
        }
    }
}

/// A rule a SARIF run names: its id and what it checks.
#[derive(Debug, Clone, Copy)]
pub struct Rule<'text> {
    pub id: &'text str,
    pub description: &'text str,
}

/// A SARIF document with one run of `tool`; `category` becomes the run's
/// `automationDetails.id`, which keeps one upload from replacing another's alerts.
pub fn document(tool: &str, category: &str, rules: &[Rule<'_>], findings: &[Finding]) -> Value {
    let rules: Vec<Value> = rules
        .iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "shortDescription": {"text": rule.description},
                "fullDescription": {"text": rule.description},
            })
        })
        .collect();
    let results: Vec<Value> = findings.iter().map(result).collect();
    json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": tool,
                "informationUri": "https://github.com/frits-v/tycho-station",
                "rules": rules,
            }},
            "automationDetails": {"id": format!("{category}/")},
            "results": results,
        }],
    })
}

fn result(finding: &Finding) -> Value {
    json!({
        "ruleId": finding.rule,
        "level": "error",
        "message": {"text": finding.message},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": finding.path},
            "region": {"startLine": finding.line, "startColumn": finding.column},
        }}],
    })
}

/// `target/sarif/<name>.sarif`.
pub fn path_for(name: &str) -> PathBuf {
    Path::new(SARIF_DIR).join(format!("{name}.sarif"))
}

pub fn ensure_directory() -> Result<(), String> {
    for directory in ["target", SARIF_DIR] {
        match fs::create_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("cannot create {directory}: {error}")),
        }
    }
    Ok(())
}

pub fn write_text(name: &str, text: &str) -> Result<PathBuf, String> {
    ensure_directory()?;
    let path = path_for(name);
    fs::write(&path, text).map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    Ok(path)
}

pub fn write(name: &str, document: &Value) -> Result<PathBuf, String> {
    write_text(name, &document.to_string())
}

/// Removes every `*.sarif` under `target/sarif`, so an upload never sends a file a
/// previous run left behind. Returns how many it removed.
pub fn clear() -> Result<usize, String> {
    let entries = match fs::read_dir(SARIF_DIR) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(format!("cannot read {SARIF_DIR}: {error}")),
    };
    let mut removed = 0_usize;
    for (index, entry) in entries.enumerate().take(SARIF_FILES_MAX.saturating_add(1)) {
        if index >= SARIF_FILES_MAX {
            return Err(format!(
                "more than {SARIF_FILES_MAX} entries under {SARIF_DIR}"
            ));
        }
        let path = entry
            .map_err(|error| format!("cannot read {SARIF_DIR}: {error}"))?
            .path();
        if path
            .extension()
            .is_some_and(|extension| extension == "sarif")
        {
            fs::remove_file(&path)
                .map_err(|error| format!("cannot remove {}: {error}", path.display()))?;
            removed = removed.saturating_add(1);
        }
    }
    Ok(removed)
}

/// What a SARIF document another tool wrote holds.
#[derive(Debug, PartialEq, Eq)]
pub enum Results {
    Findings(Vec<Finding>),
    /// Not a SARIF 2.1.0 document this reader knows: a missing field, a wrong type, or more
    /// results than the bound.
    Unrecognised(String),
}

/// Every result of every run, by rule, file, line and column.
pub fn results(document: &Value) -> Results {
    match read_results(document) {
        Ok(findings) => Results::Findings(findings),
        Err(reason) => Results::Unrecognised(reason),
    }
}

fn read_results(document: &Value) -> Result<Vec<Finding>, String> {
    if document.get("version").and_then(Value::as_str) != Some("2.1.0") {
        return Err("no `version` 2.1.0".to_string());
    }
    let runs = document
        .get("runs")
        .and_then(Value::as_array)
        .ok_or("no `runs` array")?;
    let mut findings = Vec::new();
    for run in runs {
        let entries = run
            .get("results")
            .and_then(Value::as_array)
            .ok_or("a run without a `results` array")?;
        for entry in entries {
            if findings.len() >= RESULTS_MAX {
                return Err(format!("more than {RESULTS_MAX} results"));
            }
            findings.push(read_result(entry)?);
        }
    }
    Ok(findings)
}

fn read_result(entry: &Value) -> Result<Finding, String> {
    let rule = entry
        .get("ruleId")
        .and_then(Value::as_str)
        .ok_or("a result without a `ruleId`")?;
    let message = entry
        .pointer("/message/text")
        .and_then(Value::as_str)
        .ok_or("a result without `message.text`")?;
    let location = entry
        .pointer("/locations/0/physicalLocation")
        .ok_or("a result without a physical location")?;
    let path = location
        .pointer("/artifactLocation/uri")
        .and_then(Value::as_str)
        .ok_or("a location without `artifactLocation.uri`")?;
    let number = |field: &str| {
        location
            .pointer(&format!("/region/{field}"))
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
    };
    let line = number("startLine").ok_or("a location without `region.startLine`")?;
    Ok(Finding {
        path: path.to_string(),
        line,
        column: number("startColumn").unwrap_or(1),
        rule: rule.to_string(),
        message: message.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: [Rule<'static>; 1] = [Rule {
        id: "check-names/abbreviation",
        description: "an abbreviated identifier",
    }];

    fn finding() -> Finding {
        Finding::at(
            Path::new("xtask/src/main.rs"),
            7,
            9,
            "check-names/abbreviation",
            "identifier `tmp`".to_string(),
        )
    }

    #[test]
    fn a_written_run_reads_back_with_its_rule_location_and_category() {
        let written = document("xtask", "xtask/check-names", &RULES, &[finding()]);
        assert_eq!(results(&written), Results::Findings(vec![finding()]));
        assert_eq!(
            written.pointer("/runs/0/automationDetails/id"),
            Some(&json!("xtask/check-names/"))
        );
        assert_eq!(
            written.pointer("/runs/0/tool/driver/rules/0/id"),
            Some(&json!("check-names/abbreviation"))
        );
    }

    #[test]
    fn a_clean_run_still_names_its_rules() {
        let written = document("xtask", "xtask/check-names", &RULES, &[]);
        assert_eq!(results(&written), Results::Findings(Vec::new()));
        assert!(written.pointer("/runs/0/tool/driver/rules/0").is_some());
    }

    #[test]
    fn a_document_without_a_version_results_or_a_line_is_unrecognised() {
        assert!(matches!(
            results(&json!({"runs": []})),
            Results::Unrecognised(_)
        ));
        assert!(matches!(
            results(&json!({"version": "2.1.0", "runs": [{}]})),
            Results::Unrecognised(_)
        ));
        let no_line = json!({"version": "2.1.0", "runs": [{"results": [{
            "ruleId": "r", "message": {"text": "m"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a"}, "region": {}}}]
        }]}]});
        assert!(matches!(results(&no_line), Results::Unrecognised(_)));
    }

    #[test]
    fn a_finding_never_reports_line_or_column_zero() {
        let at_zero = Finding::at(Path::new("a.rs"), 0, 0, "rule", String::new());
        assert_eq!((at_zero.line, at_zero.column), (1, 1));
    }
}

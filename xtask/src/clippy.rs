//! The ci clippy step: `mbx clippy` with JSON messages, each diagnostic printed as rustc
//! renders it and written to `target/sarif/clippy.sarif`.

use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use crate::process::{Exit, run_bounded};
use crate::sarif::{self, Finding, Rule};

const CLIPPY_TIMEOUT: Duration = Duration::from_hours(1);
const FINDINGS_MAX: usize = 2000;
const RENDERED_MAX: usize = 40;

/// One line of `cargo clippy --message-format json`.
#[derive(Debug, PartialEq, Eq)]
pub enum MessageLine {
    Artifact,
    BuildScript,
    Finished {
        success: bool,
    },
    /// An error or warning at a source location, with rustc's rendering.
    Diagnostic {
        finding: Finding,
        rendered: String,
    },
    /// A message without a primary span, such as "aborting due to 2 previous errors".
    Summary,
    Unrecognised(String),
}

/// How the clippy run ended.
#[derive(Debug, PartialEq, Eq)]
pub enum ClippyOutcome {
    Clean {
        artifacts: usize,
    },
    Findings {
        findings: Vec<Finding>,
        rendered: Vec<String>,
    },
    Unrecognised(String),
}

fn diagnostic(message: &Value) -> MessageLine {
    let level = message.get("level").and_then(Value::as_str);
    if !matches!(level, Some("error" | "warning")) {
        return MessageLine::Summary;
    }
    let primary = message
        .get("spans")
        .and_then(Value::as_array)
        .and_then(|spans| {
            spans
                .iter()
                .find(|span| span.get("is_primary").and_then(Value::as_bool) == Some(true))
        });
    let Some(span) = primary else {
        return MessageLine::Summary;
    };
    let number = |field: &str| {
        span.get(field)
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
    };
    let fields = (
        span.get("file_name").and_then(Value::as_str),
        number("line_start"),
        number("column_start"),
        message.get("message").and_then(Value::as_str),
    );
    let (Some(path), Some(line), Some(column), Some(text)) = fields else {
        return MessageLine::Unrecognised("a diagnostic span without file, line or column".into());
    };
    let rule = message
        .pointer("/code/code")
        .and_then(Value::as_str)
        .unwrap_or("rustc");
    MessageLine::Diagnostic {
        finding: Finding {
            path: path.to_string(),
            line,
            column,
            rule: rule.to_string(),
            message: text.to_string(),
        },
        rendered: message
            .get("rendered")
            .and_then(Value::as_str)
            .unwrap_or(text)
            .to_string(),
    }
}

pub fn decode_line(line: &str) -> MessageLine {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return MessageLine::Unrecognised(format!("not JSON: {line}"));
    };
    match value.get("reason").and_then(Value::as_str) {
        Some("compiler-artifact") => MessageLine::Artifact,
        Some("build-script-executed") => MessageLine::BuildScript,
        Some("build-finished") => value.get("success").and_then(Value::as_bool).map_or_else(
            || MessageLine::Unrecognised("build-finished without `success`".into()),
            |success| MessageLine::Finished { success },
        ),
        Some("compiler-message") => value.get("message").map_or_else(
            || MessageLine::Unrecognised("no `message`".into()),
            diagnostic,
        ),
        other => MessageLine::Unrecognised(format!("reason {other:?}")),
    }
}

/// Decodes every line with the exit: 0 with no diagnostic over at least one artifact is
/// clean, 0 or 101 with diagnostics is a finding, anything else (zero artifacts included)
/// is unrecognised. A diagnostic reported for more than one target is counted once.
pub fn decode(exit: &Exit, output: &str) -> ClippyOutcome {
    let mut artifacts = 0_usize;
    let mut finished = None;
    let mut findings: Vec<Finding> = Vec::new();
    let mut rendered = Vec::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        match decode_line(line) {
            MessageLine::Artifact => artifacts = artifacts.saturating_add(1),
            MessageLine::BuildScript | MessageLine::Summary => {}
            MessageLine::Finished { success } => finished = Some(success),
            MessageLine::Diagnostic {
                finding,
                rendered: text,
            } => {
                if findings.len() >= FINDINGS_MAX {
                    return ClippyOutcome::Unrecognised(format!(
                        "more than {FINDINGS_MAX} findings"
                    ));
                }
                if !findings.contains(&finding) {
                    findings.push(finding);
                    rendered.push(text);
                }
            }
            MessageLine::Unrecognised(reason) => return ClippyOutcome::Unrecognised(reason),
        }
    }
    match (exit, finished, findings.is_empty()) {
        (Exit::Code(0), Some(true), true) if artifacts > 0 => ClippyOutcome::Clean { artifacts },
        (Exit::Code(0 | 101), Some(_), false) => ClippyOutcome::Findings { findings, rendered },
        (exit, finished, _) => ClippyOutcome::Unrecognised(format!(
            "clippy ended {exit:?}, build finished {finished:?}, {} findings",
            findings.len()
        )),
    }
}

/// One rule per distinct lint, described by its first message.
fn rules_of(findings: &[Finding]) -> Vec<Rule<'_>> {
    let mut rules: Vec<Rule<'_>> = Vec::new();
    for finding in findings {
        if !rules.iter().any(|rule| rule.id == finding.rule) {
            rules.push(Rule {
                id: &finding.rule,
                description: &finding.message,
            });
        }
    }
    rules
}

pub fn clippy() -> Result<String, String> {
    let captured = run_bounded(
        Command::new("mbx").args([
            "clippy",
            "--workspace",
            "--all-targets",
            "--message-format",
            "json",
            "--",
            "-D",
            "warnings",
        ]),
        CLIPPY_TIMEOUT,
    );
    let outcome = decode(&captured.exit, &captured.stdout);
    let findings = match &outcome {
        ClippyOutcome::Clean { .. } => Vec::new(),
        ClippyOutcome::Findings { findings, .. } => findings.clone(),
        ClippyOutcome::Unrecognised(reason) => return Err(format!("clippy: {reason}")),
    };
    let document = sarif::document("clippy", "clippy", &rules_of(&findings), &findings);
    sarif::write("clippy", &document)?;
    match outcome {
        ClippyOutcome::Clean { artifacts } => Ok(format!(
            "clippy: checked {artifacts} artifacts, no findings"
        )),
        ClippyOutcome::Findings { findings, rendered } => {
            for text in rendered.iter().take(RENDERED_MAX) {
                eprint!("{text}");
            }
            Err(format!("clippy: {} findings", findings.len()))
        }
        ClippyOutcome::Unrecognised(reason) => Err(format!("clippy: {reason}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARTIFACT: &str = r#"{"reason":"compiler-artifact","package_id":"x"}"#;
    const FINISHED_OK: &str = r#"{"reason":"build-finished","success":true}"#;
    const FINISHED_FAILED: &str = r#"{"reason":"build-finished","success":false}"#;
    const LINT: &str = r#"{"reason":"compiler-message","message":{"level":"error","message":"used `unwrap()` on an `Option` value","code":{"code":"clippy::unwrap_used"},"rendered":"error: used `unwrap()`\n","spans":[{"file_name":"xtask/src/main.rs","line_start":12,"column_start":9,"is_primary":true}]}}"#;
    const ABORTING: &str = r#"{"reason":"compiler-message","message":{"level":"error","message":"aborting due to 1 previous error","code":null,"rendered":"error: aborting\n","spans":[]}}"#;

    fn lines(parts: &[&str]) -> String {
        parts.join("\n")
    }

    #[test]
    fn a_clean_run_counts_its_artifacts() {
        assert_eq!(
            decode(&Exit::Code(0), &lines(&[ARTIFACT, ARTIFACT, FINISHED_OK])),
            ClippyOutcome::Clean { artifacts: 2 }
        );
    }

    #[test]
    fn a_lint_becomes_one_finding_at_its_primary_span() {
        let output = lines(&[ARTIFACT, LINT, LINT, ABORTING, FINISHED_FAILED]);
        let ClippyOutcome::Findings { findings, rendered } = decode(&Exit::Code(101), &output)
        else {
            panic!("expected findings");
        };
        assert_eq!(rendered.len(), 1);
        assert_eq!(
            findings.first().map(ToString::to_string).as_deref(),
            Some(
                "xtask/src/main.rs:12:9: clippy::unwrap_used: used `unwrap()` on an `Option` value"
            )
        );
    }

    #[test]
    fn a_failure_without_a_diagnostic_or_an_unknown_line_is_unrecognised() {
        assert!(matches!(
            decode(&Exit::Code(101), &lines(&[ARTIFACT, FINISHED_FAILED])),
            ClippyOutcome::Unrecognised(_)
        ));
        assert!(matches!(
            decode(&Exit::Code(0), &lines(&[ARTIFACT])),
            ClippyOutcome::Unrecognised(_)
        ));
        assert!(matches!(
            decode(&Exit::Code(0), FINISHED_OK),
            ClippyOutcome::Unrecognised(_)
        ));
        assert!(matches!(
            decode(&Exit::Code(0), r#"{"reason":"something-new"}"#),
            ClippyOutcome::Unrecognised(_)
        ));
        assert!(matches!(
            decode(&Exit::TimedOut, FINISHED_OK),
            ClippyOutcome::Unrecognised(_)
        ));
    }

    #[test]
    fn each_lint_is_named_once_as_a_rule() {
        let finding = Finding::at(
            std::path::Path::new("a.rs"),
            1,
            1,
            "clippy::unwrap_used",
            "m".to_string(),
        );
        let findings = [finding.clone(), finding];
        let rules = rules_of(&findings);
        assert_eq!(rules.len(), 1);
    }
}

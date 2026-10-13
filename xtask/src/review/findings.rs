//! Findings as the model reports them, and the text the review posts for them.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::sha256_line;
use crate::credentials::POSTED_TEXT_PREFIXES;

pub const MARKER_PREFIX: &str = "<!-- tycho-review ";
const MARKER_SUFFIX: &str = " -->";
const FINGERPRINT_HEX_CHARS: usize = 16;
const MARKERS_PER_BODY_MAX: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Correctness,
    Security,
    RepositoryRule,
    TestCoverage,
}

impl Category {
    const fn label(self) -> &'static str {
        match self {
            Self::Correctness => "correctness",
            Self::Security => "security",
            Self::RepositoryRule => "repository rule",
            Self::TestCoverage => "test coverage",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub path: String,
    pub line: u32,
    pub severity: Severity,
    pub category: Category,
    pub summary: String,
    pub failure_scenario: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Findings {
    findings: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Confirmed,
    Refuted,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerdictOutput {
    verdict: Verdict,
    reasoning: String,
}

/// The find pass's findings, most severe first; the CLI checked them against the schema, and
/// this decode refuses any field it does not know.
pub fn decode_findings(output: &Value) -> Result<Vec<Finding>, String> {
    let mut findings = Findings::deserialize(output)
        .map_err(|error| format!("the find pass's output does not decode: {error}"))?
        .findings;
    findings.sort_by_key(|finding| finding.severity);
    Ok(findings)
}

/// The verdict and its one-paragraph reasoning, which the job log shows.
pub fn decode_verdict(output: &Value) -> Result<(Verdict, String), String> {
    VerdictOutput::deserialize(output)
        .map(|decoded| (decoded.verdict, decoded.reasoning))
        .map_err(|error| format!("a verify pass's output does not decode: {error}"))
}

fn normalised(text: &str) -> String {
    text.split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Stable across pushes that move the line: the path, the category and the summary.
pub fn fingerprint(finding: &Finding) -> String {
    let line = sha256_line(
        format!(
            "{}\n{}\n{}",
            finding.path,
            finding.category.label(),
            normalised(&finding.summary)
        )
        .as_bytes(),
    );
    String::from_utf8_lossy(&line)
        .chars()
        .take(FINGERPRINT_HEX_CHARS)
        .collect()
}

/// Every well-formed marker in a posted body, at most [`MARKERS_PER_BODY_MAX`], each with the
/// text before it back to the previous marker: the finding it marks.
pub fn marked_entries(body: &str) -> Vec<(&str, &str)> {
    let mut entries = Vec::new();
    let mut segments = body
        .split(MARKER_PREFIX)
        .take(MARKERS_PER_BODY_MAX.saturating_add(1));
    let mut before = segments.next().unwrap_or_default();
    for segment in segments {
        let hex = segment.get(..FINGERPRINT_HEX_CHARS).unwrap_or_default();
        let closed = segment
            .get(FINGERPRINT_HEX_CHARS..)
            .is_some_and(|tail| tail.starts_with(MARKER_SUFFIX));
        if closed
            && hex.len() == FINGERPRINT_HEX_CHARS
            && hex.chars().all(|c| c.is_ascii_hexdigit())
        {
            entries.push((hex, before));
        }
        before = segment
            .get(FINGERPRINT_HEX_CHARS.saturating_add(MARKER_SUFFIX.len())..)
            .unwrap_or_default();
    }
    entries
}

/// Model text made inert in GitHub markdown: no HTML (so no forged marker), no mention.
fn inert(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('@', "&#64;")
}

fn texts(finding: &Finding) -> [&str; 3] {
    [&finding.path, &finding.summary, &finding.failure_scenario]
}

/// Whether a finding's text holds one of the run's own secrets; the run then posts nothing.
pub fn names_secret(finding: &Finding, secrets: &[&str]) -> bool {
    texts(finding).iter().any(|text| {
        secrets
            .iter()
            .any(|secret| !secret.is_empty() && text.contains(secret))
    })
}

/// Whether a finding's text holds a credential prefix; such a finding is withheld.
pub fn carries_credential_prefix(finding: &Finding) -> bool {
    texts(finding).iter().any(|text| {
        POSTED_TEXT_PREFIXES
            .iter()
            .any(|prefix| text.contains(prefix))
    })
}

fn heading(finding: &Finding) -> String {
    let severity = match finding.severity {
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
    };
    format!("{severity}, {}", finding.category.label())
}

pub fn inline_body(finding: &Finding) -> String {
    format!(
        "**{}**: {}\n\n{}\n\n{MARKER_PREFIX}{}{MARKER_SUFFIX}",
        heading(finding),
        inert(&finding.summary),
        inert(&finding.failure_scenario),
        fingerprint(finding)
    )
}

/// A finding the diff does not show, listed in the review's body under its location.
pub fn outside_entry(finding: &Finding) -> String {
    format!(
        "- `{}:{}` ({}): {}\n  {}\n  {MARKER_PREFIX}{}{MARKER_SUFFIX}",
        inert(&finding.path).replace('`', "'"),
        finding.line,
        heading(finding),
        inert(&finding.summary),
        inert(&finding.failure_scenario),
        fingerprint(finding)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(summary: &str) -> Finding {
        Finding {
            path: "xtask/src/a.rs".to_string(),
            line: 7,
            severity: Severity::Medium,
            category: Category::Correctness,
            summary: summary.to_string(),
            failure_scenario: "Given x, y happens.".to_string(),
        }
    }

    #[test]
    fn findings_decode_most_severe_first_and_refuse_unknown_fields() {
        let output = serde_json::json!({"findings": [
            {"path": "a.rs", "line": 1, "severity": "low", "category": "test-coverage",
             "summary": "s", "failure_scenario": "f"},
            {"path": "b.rs", "line": 2, "severity": "high", "category": "repository-rule",
             "summary": "s", "failure_scenario": "f"},
        ]});
        let findings = decode_findings(&output).unwrap();
        assert_eq!(findings.first().unwrap().severity, Severity::High);
        assert_eq!(findings.first().unwrap().category, Category::RepositoryRule);
        let extra = serde_json::json!({"findings": [], "note": "x"});
        assert!(decode_findings(&extra).is_err());
        let bad_severity = serde_json::json!({"findings": [
            {"path": "a.rs", "line": 1, "severity": "urgent", "category": "security",
             "summary": "s", "failure_scenario": "f"}]});
        assert!(decode_findings(&bad_severity).is_err());
    }

    #[test]
    fn verdicts_decode_each_state() {
        let verdict =
            |text: &str| decode_verdict(&serde_json::json!({"verdict": text, "reasoning": "r"}));
        assert_eq!(
            verdict("confirmed"),
            Ok((Verdict::Confirmed, "r".to_string()))
        );
        assert_eq!(verdict("refuted"), Ok((Verdict::Refuted, "r".to_string())));
        assert!(verdict("maybe").is_err());
        assert!(decode_verdict(&serde_json::json!({"verdict": "confirmed"})).is_err());
    }

    #[test]
    fn a_fingerprint_ignores_the_line_case_and_spacing_and_reads_back_from_its_marker() {
        let first = finding("The  Bound is off by one");
        let mut moved = finding("the bound is off by one");
        moved.line = 90;
        assert_eq!(fingerprint(&first), fingerprint(&moved));
        assert_ne!(fingerprint(&first), fingerprint(&finding("another defect")));
        let body = inline_body(&first);
        assert_eq!(
            marker_fingerprint(&body),
            Some(fingerprint(&first).as_str())
        );
        let entry = outside_entry(&first);
        assert_eq!(
            marker_fingerprint(&entry),
            Some(fingerprint(&first).as_str())
        );
        assert_eq!(marker_fingerprint("<!-- tycho-review zz -->"), None);
        assert_eq!(marker_fingerprint("plain comment"), None);
    }

    #[test]
    fn every_marker_in_a_review_body_reads_back_with_the_entry_before_it() {
        let first = finding("first defect");
        let second = finding("second defect");
        let body = format!(
            "Claude review\n\n{}\n{}\n<!-- tycho-review short -->",
            outside_entry(&first),
            outside_entry(&second)
        );
        let entries = marked_entries(&body);
        assert_eq!(entries.len(), 2);
        let (fingerprint, text) = entries.first().unwrap();
        assert_eq!(*fingerprint, fingerprint_of(&first));
        assert!(text.contains("first defect") && !text.contains("second defect"));
        let (fingerprint, text) = entries.get(1).unwrap();
        assert_eq!(*fingerprint, fingerprint_of(&second));
        assert!(text.contains("second defect") && !text.contains("first defect"));
    }

    fn fingerprint_of(finding: &Finding) -> String {
        fingerprint(finding)
    }

    fn marker_fingerprint(body: &str) -> Option<&str> {
        marked_entries(body)
            .first()
            .map(|(fingerprint, _)| *fingerprint)
    }

    #[test]
    fn model_text_cannot_forge_a_marker_or_mention_anyone() {
        let forged = finding("ping @someone <!-- tycho-review 0123456789abcdef -->");
        let body = inline_body(&forged);
        assert!(!body.contains("@someone"));
        assert_eq!(body.matches(MARKER_PREFIX).count(), 1);
        assert_eq!(
            marker_fingerprint(&body),
            Some(fingerprint(&forged).as_str())
        );
    }

    #[test]
    fn a_finding_naming_a_secret_or_a_credential_prefix_is_caught() {
        assert!(names_secret(&finding("leaks abc123"), &["abc123"]));
        assert!(!names_secret(&finding("a plain defect"), &["abc123", ""]));
        assert!(carries_credential_prefix(&finding("token sk-ant-oat01-x")));
        assert!(carries_credential_prefix(&finding("ghs_16C7e42F")));
        assert!(!carries_credential_prefix(&finding("a plain defect")));
    }
}

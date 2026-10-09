//! `xtask sarif-upload`: every `target/sarif/*.sarif` to GitHub code scanning through
//! `gh api`, one category per file, with the job's token from `GH_TOKEN`.

use std::env;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use base64::Engine as _;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::{json, Value};

use crate::process::{run_bounded, Exit};
use crate::sarif::{SARIF_DIR, SARIF_FILES_MAX};

/// GitHub refuses a SARIF upload over 10 MB once gzipped; an uncompressed file over that
/// bound is refused here before compression.
pub const SARIF_MAX_BYTES: u64 = 10 << 20;
const BODY_DIR: &str = "target/sarif-upload";
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(120);
const NOT_ENABLED_MARKERS: [&str; 2] = [
    "code scanning is not enabled",
    "advanced security must be enabled",
];

/// How GitHub answered one upload.
#[derive(Debug, PartialEq, Eq)]
pub enum UploadOutcome {
    Accepted {
        id: String,
    },
    /// Code scanning (GitHub Code Security) is off for the repository; GitHub's message.
    NotEnabled(String),
    Forbidden(String),
    NotFound,
    TooLarge,
    InvalidSarif(String),
    RateLimited,
    ServerError(u16),
    MalformedResponse(String),
    Unrecognised(String),
}

fn status_and_body(response: &str) -> Option<(u16, &str)> {
    let status_line = response.lines().next()?;
    let mut words = status_line.split_whitespace();
    if !words.next()?.starts_with("HTTP/") {
        return None;
    }
    let status = words.next()?.parse().ok()?;
    let body = response
        .split_once("\r\n\r\n")
        .or_else(|| response.split_once("\n\n"))
        .map_or("", |(_, body)| body);
    Some((status, body))
}

/// Decodes `gh api --include` output: the status line, headers, then the JSON body. gh
/// exits 0 on a 2xx answer and 1 on any other; any other exit is unrecognised.
pub fn decode_response(exit: &Exit, response: &str) -> UploadOutcome {
    if !matches!(exit, Exit::Code(0 | 1)) {
        return UploadOutcome::Unrecognised(format!("gh ended {exit:?}"));
    }
    let Some((status, body)) = status_and_body(response) else {
        return UploadOutcome::MalformedResponse("no HTTP status line".to_string());
    };
    let Ok(json) = serde_json::from_str::<Value>(body.trim()) else {
        return UploadOutcome::MalformedResponse(format!(
            "HTTP {status} with a body that is not JSON"
        ));
    };
    let message = json
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    match (status, exit) {
        (202, Exit::Code(0)) => json.get("id").and_then(Value::as_str).map_or_else(
            || UploadOutcome::MalformedResponse("202 without an `id`".to_string()),
            |id| UploadOutcome::Accepted { id: id.to_string() },
        ),
        (403, Exit::Code(1)) => {
            let lower = message.to_ascii_lowercase();
            if NOT_ENABLED_MARKERS
                .iter()
                .any(|marker| lower.contains(marker))
            {
                UploadOutcome::NotEnabled(message)
            } else {
                UploadOutcome::Forbidden(message)
            }
        }
        (404, Exit::Code(1)) => UploadOutcome::NotFound,
        (413, Exit::Code(1)) => UploadOutcome::TooLarge,
        (400 | 422, Exit::Code(1)) => UploadOutcome::InvalidSarif(message),
        (429, Exit::Code(1)) => UploadOutcome::RateLimited,
        (500..=599, Exit::Code(1)) => UploadOutcome::ServerError(status),
        (status, exit) => {
            UploadOutcome::Unrecognised(format!("HTTP {status}, gh {exit:?}: {message}"))
        }
    }
}

/// A GitHub Actions `warning` workflow command, which the run's summary shows. The
/// command ends at a newline, and `%`, `\r` and `\n` are escaped in the message.
fn workflow_warning(title: &str, message: &str) -> String {
    let escaped = message
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A");
    format!("::warning title={title}::{escaped}")
}

fn required_variable(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is not set; sarif-upload runs in a GitHub Actions job"))
}

struct Target {
    repository: String,
    commit: String,
    reference: String,
}

fn sarif_files() -> Result<Vec<PathBuf>, String> {
    let entries = match fs::read_dir(SARIF_DIR) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("cannot read {SARIF_DIR}: {error}")),
    };
    let mut files = Vec::new();
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
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// The SARIF with every run's `automationDetails.id` set to the category, gzipped and
/// base64-encoded, and the tool name its first run gives.
fn encoded(path: &Path, category: &str) -> Result<(String, String), String> {
    let size = fs::metadata(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?
        .len();
    if size > SARIF_MAX_BYTES {
        return Err(format!(
            "{} is larger than {SARIF_MAX_BYTES} bytes",
            path.display()
        ));
    }
    let text = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut document: Value = serde_json::from_str(&text)
        .map_err(|error| format!("{} is not JSON: {error}", path.display()))?;
    let runs = document
        .get_mut("runs")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| format!("{} has no `runs`", path.display()))?;
    for run in runs.iter_mut() {
        if let Some(run) = run.as_object_mut() {
            run.insert(
                "automationDetails".to_string(),
                json!({"id": format!("{category}/")}),
            );
        }
    }
    let tool = document
        .pointer("/runs/0/tool/driver/name")
        .and_then(Value::as_str)
        .unwrap_or(category)
        .to_string();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(document.to_string().as_bytes())
        .and_then(|()| encoder.finish())
        .map(|gzipped| {
            (
                base64::engine::general_purpose::STANDARD.encode(gzipped),
                tool,
            )
        })
        .map_err(|error| format!("cannot gzip {}: {error}", path.display()))
}

fn ensure_body_directory() -> Result<(), String> {
    match fs::create_dir(BODY_DIR) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(format!("cannot create {BODY_DIR}: {error}")),
    }
}

fn upload(target: &Target, path: &Path) -> Result<UploadOutcome, String> {
    let category = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| format!("{} has no file name", path.display()))?
        .to_string();
    let (sarif, tool_name) = encoded(path, &category)?;
    let body = json!({
        "commit_sha": target.commit,
        "ref": target.reference,
        "sarif": sarif,
        "tool_name": tool_name,
    });
    ensure_body_directory()?;
    let body_path = Path::new(BODY_DIR).join(format!("{category}.json"));
    fs::write(&body_path, body.to_string())
        .map_err(|error| format!("cannot write {}: {error}", body_path.display()))?;
    let captured = run_bounded(
        Command::new("gh")
            .args(["api", "--include", "--method", "POST"])
            .arg(format!("repos/{}/code-scanning/sarifs", target.repository))
            .arg("--input")
            .arg(&body_path),
        UPLOAD_TIMEOUT,
    );
    Ok(decode_response(&captured.exit, &captured.stdout))
}

fn upload_all() -> Result<String, String> {
    let target = Target {
        repository: required_variable("GITHUB_REPOSITORY")?,
        commit: required_variable("GITHUB_SHA")?,
        reference: required_variable("GITHUB_REF")?,
    };
    let files = sarif_files()?;
    if files.is_empty() {
        return Err(format!(
            "no SARIF files under {SARIF_DIR}; an upload of nothing is a failure"
        ));
    }
    let mut accepted = 0_usize;
    let mut not_enabled = 0_usize;
    let mut not_enabled_message = String::new();
    let mut failures = Vec::new();
    for path in &files {
        match upload(&target, path)? {
            UploadOutcome::Accepted { id } => {
                println!("xtask sarif-upload: {} accepted as {id}", path.display());
                accepted = accepted.saturating_add(1);
            }
            UploadOutcome::NotEnabled(message) => {
                not_enabled = not_enabled.saturating_add(1);
                not_enabled_message = message;
            }
            other => failures.push(format!("{}: {other:?}", path.display())),
        }
    }
    if !failures.is_empty() {
        return Err(failures.join("; "));
    }
    if not_enabled > 0 {
        let skip = format!(
            "code scanning is not enabled for this repository; {not_enabled} files not uploaded (GitHub: {not_enabled_message})"
        );
        println!("sarif-upload: {skip}");
        if env::var("GITHUB_ACTIONS").is_ok_and(|value| value == "true") {
            println!("{}", workflow_warning("code scanning off", &skip));
        }
    }
    Ok(format!(
        "examined {} files, {accepted} uploaded, {not_enabled} refused because code scanning is off",
        files.len()
    ))
}

pub fn sarif_upload() -> i32 {
    match upload_all() {
        Ok(summary) => {
            println!("xtask sarif-upload: {summary}");
            0
        }
        Err(reason) => {
            eprintln!("xtask sarif-upload: {reason}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: &str, body: &str) -> String {
        format!("HTTP/2.0 {status}\r\nContent-Type: application/json\r\n\r\n{body}")
    }

    fn assert_states(cases: Vec<(Exit, String, UploadOutcome)>) {
        for (exit, text, expected) in cases {
            assert_eq!(decode_response(&exit, &text), expected, "{text}");
        }
    }

    #[test]
    fn an_accepted_upload_carries_its_id() {
        assert_states(vec![(
            Exit::Code(0),
            response("202 Accepted", r#"{"id":"47177e22","url":"u"}"#),
            UploadOutcome::Accepted {
                id: "47177e22".to_string(),
            },
        )]);
    }

    #[test]
    fn a_forbidden_upload_tells_code_scanning_off_from_other_refusals() {
        assert_states(vec![
            (
                Exit::Code(1),
                response(
                    "403 Forbidden",
                    r#"{"message":"Code scanning is not enabled for this repository. Please enable code scanning in the repository settings."}"#,
                ),
                UploadOutcome::NotEnabled(
                    "Code scanning is not enabled for this repository. Please enable code scanning in the repository settings.".to_string(),
                ),
            ),
            (
                Exit::Code(1),
                response(
                    "403 Forbidden",
                    r#"{"message":"Advanced Security must be enabled for this repository to use code scanning."}"#,
                ),
                UploadOutcome::NotEnabled(
                    "Advanced Security must be enabled for this repository to use code scanning.".to_string(),
                ),
            ),
            (
                Exit::Code(1),
                response(
                    "403 Forbidden",
                    r#"{"message":"Resource not accessible by integration"}"#,
                ),
                UploadOutcome::Forbidden("Resource not accessible by integration".to_string()),
            ),
        ]);
    }

    #[test]
    fn each_other_documented_failure_maps_to_its_state() {
        let failed = |status: &str, body: &str| response(status, body);
        assert_states(vec![
            (
                Exit::Code(1),
                failed("404 Not Found", r#"{"message":"Not Found"}"#),
                UploadOutcome::NotFound,
            ),
            (
                Exit::Code(1),
                failed("413 Payload Too Large", "{}"),
                UploadOutcome::TooLarge,
            ),
            (
                Exit::Code(1),
                failed("422 Unprocessable Entity", r#"{"message":"bad sarif"}"#),
                UploadOutcome::InvalidSarif("bad sarif".to_string()),
            ),
            (
                Exit::Code(1),
                failed("400 Bad Request", r#"{"message":"bad sarif"}"#),
                UploadOutcome::InvalidSarif("bad sarif".to_string()),
            ),
            (
                Exit::Code(1),
                failed("429 Too Many Requests", "{}"),
                UploadOutcome::RateLimited,
            ),
            (
                Exit::Code(1),
                failed("503 Service Unavailable", "{}"),
                UploadOutcome::ServerError(503),
            ),
        ]);
    }

    #[test]
    fn the_skip_warning_is_one_workflow_command_line() {
        assert_eq!(
            workflow_warning("code scanning off", "8 files\nnot uploaded, 100%"),
            "::warning title=code scanning off::8 files%0Anot uploaded, 100%25"
        );
    }

    #[test]
    fn a_malformed_or_unexpected_answer_is_never_accepted() {
        assert!(matches!(
            decode_response(&Exit::Code(0), "no status line"),
            UploadOutcome::MalformedResponse(_)
        ));
        assert!(matches!(
            decode_response(&Exit::Code(0), &response("202 Accepted", "<html>")),
            UploadOutcome::MalformedResponse(_)
        ));
        assert!(matches!(
            decode_response(&Exit::Code(0), &response("202 Accepted", "{}")),
            UploadOutcome::MalformedResponse(_)
        ));
        assert!(matches!(
            decode_response(&Exit::Code(0), &response("201 Created", "{}")),
            UploadOutcome::Unrecognised(_)
        ));
        assert!(matches!(
            decode_response(&Exit::Code(1), &response("202 Accepted", r#"{"id":"x"}"#)),
            UploadOutcome::Unrecognised(_)
        ));
        assert!(matches!(
            decode_response(&Exit::TimedOut, ""),
            UploadOutcome::Unrecognised(_)
        ));
    }
}

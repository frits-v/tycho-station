//! The Codex headless worker: `codex exec --json` with an output schema.
//!
//! The decoder follows the documented JSONL event shapes; the only captured sample is a run
//! without a login.

use std::path::Path;

use serde_json::Value;
use tycho_types::envelope::{Outcome, Usage};
use tycho_types::session::Vendor;
use tycho_types::task_packet::Effort;

use crate::vendors::worker::{
    vendor_word, Stream, VendorEnd, VersionState, WorkerError, WorkerTask, WorkerVendor,
};

pub const CODEX_PINNED_VERSION: &str = "0.160.1";
const CODEX_BANNER_PREFIX: &str = "codex-cli";
/// The response shape the worker's last message must take.
pub const CODEX_OUTPUT_SCHEMA: &str = r#"{"type":"object","properties":{"outcome":{"type":"string","enum":["done","not_done"]},"summary":{"type":"string"}},"required":["outcome","summary"],"additionalProperties":false}"#;
/// Item types of the documented `ThreadItemDetails`.
const ITEM_TYPES: [&str; 9] = [
    "agent_message",
    "reasoning",
    "command_execution",
    "file_change",
    "mcp_tool_call",
    "collab_tool_call",
    "web_search",
    "todo_list",
    "error",
];

#[derive(Debug, Clone, Copy, Default)]
pub struct CodexWorker;

/// One JSONL line of `codex exec --json` as the decoder reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexEvent {
    ThreadStarted { thread_id: Option<String> },
    TurnStarted,
    TurnCompleted { usage: Usage },
    TurnFailed { message: String },
    Item { reported: Option<Outcome> },
    Error { message: String },
    Unrecognised,
}

const fn effort_value(effort: Effort) -> &'static str {
    match effort {
        Effort::Minimal => "minimal",
        Effort::Low => "low",
        Effort::Medium => "medium",
        Effort::High => "high",
        Effort::Max => "xhigh",
    }
}

fn message(value: &Value) -> String {
    value
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// The outcome a final agent message reports under the output schema, if it parses.
fn reported_outcome(item: &Value) -> Option<Outcome> {
    let reply = item.get("text").and_then(Value::as_str)?;
    let reply: Value = serde_json::from_str(reply).ok()?;
    match reply.get("outcome").and_then(Value::as_str) {
        Some("done") => Some(Outcome::Done),
        Some("not_done") => Some(Outcome::NotDone),
        _ => None,
    }
}

fn decode_item(event: &Value) -> CodexEvent {
    let Some(item) = event.get("item") else {
        return CodexEvent::Unrecognised;
    };
    match item.get("type").and_then(Value::as_str) {
        Some("agent_message") => CodexEvent::Item {
            reported: reported_outcome(item),
        },
        Some(kind) if ITEM_TYPES.contains(&kind) => CodexEvent::Item { reported: None },
        _ => CodexEvent::Unrecognised,
    }
}

fn turn_usage(event: &Value) -> Usage {
    let usage = event.get("usage").cloned().unwrap_or(Value::Null);
    let count = |key: &str| usage.get(key).and_then(Value::as_u64).unwrap_or(0);
    Usage {
        input_tokens: count("input_tokens"),
        output_tokens: count("output_tokens"),
        cost_micro_dollars: 0,
    }
}

#[must_use]
pub fn decode_event(line: &[u8]) -> CodexEvent {
    let Ok(event) = serde_json::from_slice::<Value>(line) else {
        return CodexEvent::Unrecognised;
    };
    match event.get("type").and_then(Value::as_str) {
        Some("thread.started") => CodexEvent::ThreadStarted {
            thread_id: event
                .get("thread_id")
                .and_then(Value::as_str)
                .map(str::to_string),
        },
        Some("turn.started") => CodexEvent::TurnStarted,
        Some("turn.completed") => CodexEvent::TurnCompleted {
            usage: turn_usage(&event),
        },
        Some("turn.failed") => CodexEvent::TurnFailed {
            message: event.get("error").map(message).unwrap_or_default(),
        },
        Some("item.started" | "item.updated" | "item.completed") => decode_item(&event),
        Some("error") => CodexEvent::Error {
            message: message(&event),
        },
        _ => CodexEvent::Unrecognised,
    }
}

/// `turn.failed` carries only a message, so the table matches its documented texts.
#[must_use]
pub fn decode_failure(message: &str) -> VendorEnd {
    let lower = message.to_ascii_lowercase();
    if lower.contains("401 unauthorized") || lower.contains("not logged in") {
        VendorEnd::LoginRequired
    } else if lower.contains("429") || lower.contains("usage limit") || lower.contains("rate limit")
    {
        VendorEnd::RateLimited
    } else {
        VendorEnd::Failed
    }
}

impl WorkerVendor for CodexWorker {
    fn vendor(&self) -> Vendor {
        Vendor::Codex
    }

    fn pinned_version(&self) -> &'static str {
        CODEX_PINNED_VERSION
    }

    /// `codex exec` has no turn cap, so a task that names one is refused rather than run
    /// uncapped; the brief arrives on stdin through the `-` prompt.
    fn command(&self, binary: &Path, task: &WorkerTask) -> Result<Vec<String>, WorkerError> {
        if task.max_turns.is_some() {
            return Err(WorkerError::Unsupported("codex exec has no turn cap"));
        }
        let effort = format!("model_reasoning_effort=\"{}\"", effort_value(task.effort));
        Ok([
            binary.display().to_string().as_str(),
            "exec",
            "--json",
            "--output-schema",
            &task.output_schema.display().to_string(),
            "--sandbox",
            "workspace-write",
            "--cd",
            &task.worktree.display().to_string(),
            "--model",
            task.model.as_str(),
            "-c",
            &effort,
            "-",
        ]
        .iter()
        .map(ToString::to_string)
        .collect())
    }

    fn version(&self, banner: &str) -> VersionState {
        let words: Vec<&str> = banner.split_whitespace().collect();
        match words.as_slice() {
            [CODEX_BANNER_PREFIX, CODEX_PINNED_VERSION] => VersionState::Pinned,
            [CODEX_BANNER_PREFIX, found] => VersionState::Other(vendor_word(found)),
            _ => VersionState::Unrecognised(vendor_word(banner)),
        }
    }

    fn observe(&self, line: &[u8], stream: &mut Stream) {
        stream.events = stream.events.saturating_add(1);
        match decode_event(line) {
            CodexEvent::ThreadStarted { thread_id } => {
                stream.started = true;
                stream.resume_handle = thread_id;
            }
            CodexEvent::TurnStarted => {}
            CodexEvent::TurnCompleted { usage } => {
                stream.usage = usage;
                stream.end = Some(VendorEnd::Completed);
            }
            CodexEvent::TurnFailed { message } => {
                stream.vendor_error = Some(vendor_word(&message));
                stream.end = Some(decode_failure(&message));
            }
            CodexEvent::Item { reported } => {
                if reported.is_some() {
                    stream.reported_outcome = reported;
                }
            }
            CodexEvent::Error { message } => stream.vendor_error = Some(vendor_word(&message)),
            CodexEvent::Unrecognised => {
                stream.unrecognised = stream.unrecognised.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendors::worker::{ModelName, VendorSessionId};
    use std::num::NonZeroU16;
    use std::path::PathBuf;

    /// Written from the documented `exec_events.rs` shapes; no logged-in run was available.
    const DOCUMENTED_SUCCESS: &str =
        include_str!("../fixtures/codex-worker-documented-success.jsonl");
    const DOCUMENTED_FAILED: &str =
        include_str!("../fixtures/codex-worker-documented-failed.jsonl");
    /// Captured from the pinned CLI with an empty `CODEX_HOME`.
    const CAPTURED_NO_LOGIN: &str = include_str!("../fixtures/codex-worker-no-login.jsonl");

    fn fold(sample: &str) -> Stream {
        let mut stream = Stream::default();
        for line in sample.lines() {
            CodexWorker.observe(line.as_bytes(), &mut stream);
        }
        stream
    }

    fn task(max_turns: Option<u16>) -> WorkerTask {
        WorkerTask {
            worktree: PathBuf::from("/agent/worktrees/cf7a/wu03/a1"),
            model: ModelName::parse("gpt-5-codex-mini").unwrap(),
            effort: Effort::Max,
            max_turns: max_turns.and_then(NonZeroU16::new),
            session_id: VendorSessionId::parse("3f0c6c1e-6b1a-4a51-9a0e-2a8c5d0c1a10").unwrap(),
            settings: "{}".to_string(),
            output_schema: PathBuf::from("/spool/output-schema.json"),
        }
    }

    #[test]
    fn the_command_line_has_exact_text() {
        let words = CodexWorker
            .command(Path::new("/opt/codex/bin/codex"), &task(None))
            .unwrap();
        assert_eq!(
            words.join(" "),
            "/opt/codex/bin/codex exec --json --output-schema /spool/output-schema.json \
             --sandbox workspace-write --cd /agent/worktrees/cf7a/wu03/a1 \
             --model gpt-5-codex-mini -c model_reasoning_effort=\"xhigh\" -"
        );
    }

    #[test]
    fn a_turn_cap_is_refused_not_dropped() {
        assert_eq!(
            CodexWorker.command(Path::new("/c"), &task(Some(6))),
            Err(WorkerError::Unsupported("codex exec has no turn cap"))
        );
    }

    #[test]
    fn the_version_banner_is_checked_against_the_pin() {
        assert_eq!(
            CodexWorker.version("codex-cli 0.160.1\n"),
            VersionState::Pinned
        );
        assert_eq!(
            CodexWorker.version("codex-cli 0.161.0"),
            VersionState::Other("0.161.0".to_string())
        );
        assert!(matches!(
            CodexWorker.version("0.160.1"),
            VersionState::Unrecognised(_)
        ));
    }

    #[test]
    fn a_documented_success_completes_with_usage_and_the_reported_outcome() {
        let stream = fold(DOCUMENTED_SUCCESS);
        assert_eq!(stream.end, Some(VendorEnd::Completed));
        assert_eq!(stream.unrecognised, 0);
        assert_eq!(stream.usage.input_tokens, 24_763);
        assert_eq!(stream.usage.output_tokens, 122);
        assert_eq!(stream.reported_outcome, Some(Outcome::Done));
        assert_eq!(stream.context_tokens, None);
        assert_eq!(
            stream.resume_handle.as_deref(),
            Some("0199a213-81c0-7800-8aa1-bbab2a035a53")
        );
    }

    #[test]
    fn a_documented_failure_is_failed() {
        assert_eq!(fold(DOCUMENTED_FAILED).end, Some(VendorEnd::Failed));
    }

    #[test]
    fn a_captured_run_without_a_login_needs_the_operator() {
        let stream = fold(CAPTURED_NO_LOGIN);
        assert_eq!(stream.end, Some(VendorEnd::LoginRequired));
        assert_eq!(stream.unrecognised, 0);
        assert!(stream.started);
    }

    #[test]
    fn failure_messages_map_to_their_ends() {
        assert_eq!(
            decode_failure("You've hit your usage limit. Try again later."),
            VendorEnd::RateLimited
        );
        assert_eq!(
            decode_failure("unexpected status 429 Too Many Requests"),
            VendorEnd::RateLimited
        );
        assert_eq!(decode_failure("turn failed"), VendorEnd::Failed);
    }

    #[test]
    fn garbage_and_unknown_types_are_unrecognised() {
        for line in [
            "",
            "{",
            r#"{"type":"turn.paused"}"#,
            r#"{"type":"item.completed"}"#,
            r#"{"type":"item.completed","item":{"type":"hologram"}}"#,
        ] {
            assert_eq!(
                decode_event(line.as_bytes()),
                CodexEvent::Unrecognised,
                "{line}"
            );
        }
    }

    #[test]
    fn the_output_schema_is_json() {
        let schema: Value = serde_json::from_str(CODEX_OUTPUT_SCHEMA).unwrap();
        assert_eq!(
            schema["required"],
            serde_json::json!(["outcome", "summary"])
        );
    }
}

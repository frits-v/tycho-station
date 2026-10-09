//! The Claude headless worker: `claude -p` with stream-json, never bare, at the pinned version.

use std::path::Path;

use serde_json::Value;
use tycho_types::envelope::Usage;
use tycho_types::session::Vendor;
use tycho_types::task_packet::Effort;

use crate::vendors::worker::{
    vendor_word, Refusal, Stream, VendorEnd, VersionState, WorkerError, WorkerTask, WorkerVendor,
};

pub const CLAUDE_PINNED_VERSION: &str = "2.1.280";
const CLAUDE_BANNER_SUFFIX: &str = "(Claude Code)";
const HTTP_TOO_MANY_REQUESTS: u64 = 429;
const HTTP_UNAUTHORIZED: u64 = 401;
const HTTP_FORBIDDEN: u64 = 403;
/// System subtypes the pinned CLI emits that a worker does not act on.
const SYSTEM_OTHER: [&str; 9] = [
    "hook_started",
    "hook_progress",
    "hook_response",
    "thinking_tokens",
    "vcs_state_changed",
    "commands_changed",
    "status",
    "compact_boundary",
    "api_retry",
];

#[derive(Debug, Clone, Copy, Default)]
pub struct ClaudeWorker;

/// The fields of a `result` event the decoder reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeResult {
    pub subtype: String,
    pub is_error: bool,
    pub api_error_status: Option<u64>,
    pub usage: Usage,
    pub session_id: Option<String>,
}

/// One stream-json line as the decoder reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaudeEvent {
    Init {
        version: Option<String>,
        inbox_socket: bool,
        session_id: Option<String>,
    },
    Assistant {
        context_tokens: Option<u64>,
        error: Option<String>,
    },
    RateLimit {
        rejected: bool,
    },
    Result(ClaudeResult),
    /// A user event or a system event the worker does not act on.
    Other,
    Unrecognised,
}

const fn effort_flag(effort: Effort) -> &'static str {
    match effort {
        Effort::Minimal | Effort::Low => "low",
        Effort::Medium => "medium",
        Effort::High => "high",
        Effort::Max => "max",
    }
}

fn text(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn count(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// The largest cost a run may report, a million dollars; anything above is unrecognised.
const COST_MICRO_DOLLARS_MAX: f64 = 1e12;

/// `total_cost_usd`, exponent form included, rounded to micro-dollars; `None` when it is not
/// a finite non-negative number within the bound.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is finite, non-negative and below 1e12, so it fits a u64 exactly"
)]
pub fn micro_dollars(cost: &Value) -> Option<u64> {
    let micro = (cost.as_f64()? * 1e6).round();
    (micro.is_finite() && (0.0..=COST_MICRO_DOLLARS_MAX).contains(&micro)).then_some(micro as u64)
}

/// The prompt of the latest request: uncached, cache-read and cache-written input tokens.
fn context_tokens(message: &Value) -> Option<u64> {
    let usage = message.get("usage")?;
    let total = count(usage, "input_tokens")
        .saturating_add(count(usage, "cache_read_input_tokens"))
        .saturating_add(count(usage, "cache_creation_input_tokens"));
    (total > 0).then_some(total)
}

/// Cumulative usage of the run; input counts cache reads and writes as well. A cost that is
/// absent or does not parse makes the event unrecognised, never a zero spend.
fn run_usage(event: &Value) -> Option<Usage> {
    let usage = event.get("usage").cloned().unwrap_or(Value::Null);
    let cost = event.get("total_cost_usd").and_then(micro_dollars)?;
    Some(Usage {
        input_tokens: count(&usage, "input_tokens")
            .saturating_add(count(&usage, "cache_read_input_tokens"))
            .saturating_add(count(&usage, "cache_creation_input_tokens")),
        output_tokens: count(&usage, "output_tokens"),
        cost_micro_dollars: cost,
    })
}

fn decode_system(event: &Value) -> ClaudeEvent {
    match event.get("subtype").and_then(Value::as_str) {
        Some("init") => ClaudeEvent::Init {
            version: text(event, "claude_code_version"),
            inbox_socket: event
                .get("messaging_socket_path")
                .and_then(Value::as_str)
                .is_some_and(|path| !path.is_empty()),
            session_id: text(event, "session_id"),
        },
        Some(subtype) if SYSTEM_OTHER.contains(&subtype) => ClaudeEvent::Other,
        _ => ClaudeEvent::Unrecognised,
    }
}

fn decode_result_event(event: &Value) -> ClaudeEvent {
    let (Some(subtype), Some(usage)) = (text(event, "subtype"), run_usage(event)) else {
        return ClaudeEvent::Unrecognised;
    };
    ClaudeEvent::Result(ClaudeResult {
        subtype,
        is_error: event
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        api_error_status: event.get("api_error_status").and_then(Value::as_u64),
        usage,
        session_id: text(event, "session_id"),
    })
}

/// Decodes one line; anything that is not a JSON object of a known type is unrecognised.
#[must_use]
pub fn decode_event(line: &[u8]) -> ClaudeEvent {
    let Ok(event) = serde_json::from_slice::<Value>(line) else {
        return ClaudeEvent::Unrecognised;
    };
    match event.get("type").and_then(Value::as_str) {
        Some("system") => decode_system(&event),
        Some("assistant") => ClaudeEvent::Assistant {
            // A subagent's turn has its own context; the worker's is the main thread's.
            context_tokens: event
                .get("parent_tool_use_id")
                .is_none_or(Value::is_null)
                .then(|| event.get("message").and_then(context_tokens))
                .flatten(),
            error: text(&event, "error"),
        },
        Some("user") => ClaudeEvent::Other,
        Some("rate_limit_event") => ClaudeEvent::RateLimit {
            rejected: event
                .pointer("/rate_limit_info/status")
                .and_then(Value::as_str)
                == Some("rejected"),
        },
        Some("result") => decode_result_event(&event),
        _ => ClaudeEvent::Unrecognised,
    }
}

/// The result table; a failed final request reports `success` with `is_error` set.
#[must_use]
pub fn decode_result(result: &ClaudeResult, stream: &Stream) -> VendorEnd {
    let error = stream.vendor_error.as_deref();
    match result.subtype.as_str() {
        "success" if !result.is_error => VendorEnd::Completed,
        "success"
            if result.api_error_status == Some(HTTP_TOO_MANY_REQUESTS)
                || stream.rate_limit_rejected
                || error == Some("rate_limit") =>
        {
            VendorEnd::RateLimited
        }
        "success"
            if error == Some("authentication_failed")
                || matches!(
                    result.api_error_status,
                    Some(HTTP_UNAUTHORIZED | HTTP_FORBIDDEN)
                ) =>
        {
            VendorEnd::LoginRequired
        }
        "success" | "error_during_execution" | "error_max_structured_output_retries" => {
            VendorEnd::Failed
        }
        "error_max_turns" => VendorEnd::TurnCap,
        "error_max_budget_usd" => VendorEnd::BudgetCap,
        other => VendorEnd::Unrecognised(vendor_word(other)),
    }
}

/// The init event decides non-bare: the pinned version and a bound inbox socket.
fn observe_init(version: Option<String>, inbox_socket: bool, stream: &mut Stream) {
    match version {
        Some(found) if found == CLAUDE_PINNED_VERSION => {}
        found => {
            stream.refusal = Some(Refusal::VersionMismatch(vendor_word(
                found.as_deref().unwrap_or("absent"),
            )));
            return;
        }
    }
    if inbox_socket {
        stream.started = true;
    } else {
        stream.refusal = Some(Refusal::BareMode);
    }
}

impl WorkerVendor for ClaudeWorker {
    fn vendor(&self) -> Vendor {
        Vendor::Claude
    }

    fn pinned_version(&self) -> &'static str {
        CLAUDE_PINNED_VERSION
    }

    fn command(&self, binary: &Path, task: &WorkerTask) -> Result<Vec<String>, WorkerError> {
        let mut words: Vec<String> = [
            binary.display().to_string().as_str(),
            "-p",
            "--output-format",
            "stream-json",
            "--verbose",
            "--model",
            task.model.as_str(),
            "--effort",
            effort_flag(task.effort),
            "--permission-mode",
            "acceptEdits",
            "--permission-prompts",
            "none",
            "--session-id",
            task.session_id.as_str(),
            "--settings",
            task.settings.as_str(),
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        if let Some(turns) = task.max_turns {
            words.push("--max-turns".to_string());
            words.push(turns.to_string());
        }
        Ok(words)
    }

    fn version(&self, banner: &str) -> VersionState {
        let mut words = banner.split_whitespace();
        match (words.next(), words.collect::<Vec<_>>().join(" ").as_str()) {
            (Some(CLAUDE_PINNED_VERSION), CLAUDE_BANNER_SUFFIX) => VersionState::Pinned,
            (Some(found), CLAUDE_BANNER_SUFFIX) => VersionState::Other(vendor_word(found)),
            _ => VersionState::Unrecognised(vendor_word(banner)),
        }
    }

    fn observe(&self, line: &[u8], stream: &mut Stream) {
        stream.events = stream.events.saturating_add(1);
        match decode_event(line) {
            ClaudeEvent::Init {
                version,
                inbox_socket,
                session_id,
            } => {
                stream.resume_handle = session_id;
                observe_init(version, inbox_socket, stream);
            }
            ClaudeEvent::Assistant {
                context_tokens,
                error,
            } => {
                if context_tokens.is_some() {
                    stream.context_tokens = context_tokens;
                }
                if let Some(error) = error {
                    stream.vendor_error = Some(vendor_word(&error));
                }
            }
            ClaudeEvent::RateLimit { rejected } => {
                stream.rate_limit_rejected = stream.rate_limit_rejected || rejected;
            }
            ClaudeEvent::Result(result) => {
                stream.usage = result.usage;
                stream.end = Some(if stream.started {
                    decode_result(&result, stream)
                } else {
                    VendorEnd::Unrecognised("result_before_init".to_string())
                });
                if result.session_id.is_some() {
                    stream.resume_handle = result.session_id;
                }
            }
            ClaudeEvent::Other => {}
            ClaudeEvent::Unrecognised => {
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

    /// Captured from the pinned CLI under a subscription login; paths and lists trimmed.
    const SUCCESS: &str = include_str!("../fixtures/claude-worker-success.jsonl");
    const MAX_TURNS: &str = include_str!("../fixtures/claude-worker-max-turns.jsonl");
    const BARE: &str = include_str!("../fixtures/claude-worker-bare.jsonl");
    /// Captured with `USER` absent from the environment: the keychain lookup fails.
    const LOGIN: &str = include_str!("../fixtures/claude-worker-login.jsonl");

    fn fold(sample: &str) -> Stream {
        let mut stream = Stream::default();
        for line in sample.lines() {
            ClaudeWorker.observe(line.as_bytes(), &mut stream);
        }
        stream
    }

    fn task(max_turns: Option<u16>) -> WorkerTask {
        WorkerTask {
            worktree: PathBuf::from("/agent/worktrees/cf7a/wu03/a1"),
            model: ModelName::parse("haiku").unwrap(),
            effort: Effort::Minimal,
            max_turns: max_turns.and_then(NonZeroU16::new),
            requires_commit: true,
            session_id: VendorSessionId::parse("3f0c6c1e-6b1a-4a51-9a0e-2a8c5d0c1a10").unwrap(),
            settings: r#"{"sandbox":{"enabled":true}}"#.to_string(),
            output_schema: PathBuf::from("/spool/output-schema.json"),
        }
    }

    #[test]
    fn the_command_line_has_exact_text() {
        let words = ClaudeWorker
            .command(Path::new("/opt/claude/claude"), &task(Some(6)))
            .unwrap();
        assert_eq!(
            words.join(" "),
            "/opt/claude/claude -p --output-format stream-json --verbose --model haiku \
             --effort low --permission-mode acceptEdits --permission-prompts none \
             --session-id 3f0c6c1e-6b1a-4a51-9a0e-2a8c5d0c1a10 \
             --settings {\"sandbox\":{\"enabled\":true}} --max-turns 6"
        );
        assert!(!words.iter().any(|word| word == "--bare"));
        let uncapped = ClaudeWorker.command(Path::new("/c"), &task(None)).unwrap();
        assert!(!uncapped.iter().any(|word| word == "--max-turns"));
    }

    #[test]
    fn the_version_banner_is_checked_against_the_pin() {
        let worker = ClaudeWorker;
        assert_eq!(
            worker.version("2.1.280 (Claude Code)\n"),
            VersionState::Pinned
        );
        assert_eq!(
            worker.version("2.2.0 (Claude Code)"),
            VersionState::Other("2.2.0".to_string())
        );
        assert!(matches!(worker.version(""), VersionState::Unrecognised(_)));
        assert!(matches!(
            worker.version("2.1.280"),
            VersionState::Unrecognised(_)
        ));
    }

    #[test]
    fn a_captured_success_completes_with_usage_and_context_size() {
        let stream = fold(SUCCESS);
        assert_eq!(stream.end, Some(VendorEnd::Completed));
        assert!(stream.started);
        assert_eq!(stream.refusal, None);
        assert_eq!(stream.unrecognised, 0);
        assert_eq!(stream.events, 19);
        assert_eq!(stream.context_tokens, Some(8 + 33_089 + 293));
        assert_eq!(
            stream.usage,
            Usage {
                input_tokens: 26 + 33_382 + 65_799,
                output_tokens: 439,
                cost_micro_dollars: 75_565,
            }
        );
        assert_eq!(
            stream.resume_handle.as_deref(),
            Some("3f0c6c1e-6b1a-4a51-9a0e-2a8c5d0c1a10")
        );
    }

    #[test]
    fn a_captured_turn_cap_is_too_large() {
        let stream = fold(MAX_TURNS);
        assert_eq!(stream.end, Some(VendorEnd::TurnCap));
        assert!(stream.context_tokens.is_some());
    }

    #[test]
    fn a_captured_bare_run_is_refused() {
        let stream = fold(BARE);
        assert_eq!(stream.refusal, Some(Refusal::BareMode));
        assert!(!stream.started);
        assert_eq!(
            stream.end,
            Some(VendorEnd::Unrecognised("result_before_init".to_string()))
        );
    }

    #[test]
    fn a_captured_login_failure_needs_the_operator() {
        let stream = fold(LOGIN);
        assert_eq!(stream.end, Some(VendorEnd::LoginRequired));
        assert_eq!(
            stream.vendor_error.as_deref(),
            Some("authentication_failed")
        );
        assert_eq!(stream.context_tokens, None);
    }

    fn result(subtype: &str, is_error: bool, status: Option<u64>) -> ClaudeResult {
        ClaudeResult {
            subtype: subtype.to_string(),
            is_error,
            api_error_status: status,
            usage: Usage::default(),
            session_id: None,
        }
    }

    #[test]
    fn every_result_subtype_has_an_end() {
        let quiet = Stream::default();
        let cases = [
            (result("success", false, None), VendorEnd::Completed),
            (result("success", true, Some(429)), VendorEnd::RateLimited),
            (result("success", true, Some(500)), VendorEnd::Failed),
            (result("success", true, Some(401)), VendorEnd::LoginRequired),
            (result("success", true, Some(403)), VendorEnd::LoginRequired),
            (result("error_max_turns", true, None), VendorEnd::TurnCap),
            (
                result("error_max_budget_usd", true, None),
                VendorEnd::BudgetCap,
            ),
            (
                result("error_during_execution", true, None),
                VendorEnd::Failed,
            ),
            (
                result("error_max_structured_output_retries", true, None),
                VendorEnd::Failed,
            ),
            (
                result("error_something_new", true, None),
                VendorEnd::Unrecognised("error_something_new".to_string()),
            ),
        ];
        for (result, end) in cases {
            assert_eq!(decode_result(&result, &quiet), end, "{result:?}");
        }
        let limited = Stream {
            rate_limit_rejected: true,
            ..Stream::default()
        };
        assert_eq!(
            decode_result(&result("success", true, None), &limited),
            VendorEnd::RateLimited
        );
    }

    #[test]
    fn garbage_and_unknown_types_are_unrecognised() {
        for line in [
            "",
            "not json",
            "[1,2]",
            r#"{"no":"type"}"#,
            r#"{"type":"telemetry"}"#,
            r#"{"type":"system","subtype":"brand_new"}"#,
            r#"{"type":"result"}"#,
        ] {
            assert_eq!(
                decode_event(line.as_bytes()),
                ClaudeEvent::Unrecognised,
                "{line}"
            );
        }
        let stream = fold("garbage\n{\"type\":\"user\"}\n");
        assert_eq!(
            (stream.events, stream.unrecognised, stream.end),
            (2, 1, None)
        );
    }

    #[test]
    fn a_wrong_version_in_the_stream_is_refused() {
        let line = r#"{"type":"system","subtype":"init","claude_code_version":"2.2.0","messaging_socket_path":"/var/run/inbox.sock"}"#;
        let stream = fold(line);
        assert_eq!(
            stream.refusal,
            Some(Refusal::VersionMismatch("2.2.0".to_string()))
        );
    }

    #[test]
    fn costs_round_to_micro_dollars() {
        let parse = |text: &str| micro_dollars(&serde_json::from_str::<Value>(text).unwrap());
        assert_eq!(parse("0.0755649"), Some(75_565));
        assert_eq!(parse("1e-5"), Some(10));
        assert_eq!(parse("0"), Some(0));
        assert_eq!(parse("12.5"), Some(12_500_000));
        for bad in ["-1.0", "\"0.5\"", "null", "1e7"] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_result_without_a_readable_cost_is_unrecognised_not_free() {
        for cost in ["", r#","total_cost_usd":"0.5""#, r#","total_cost_usd":-1"#] {
            let line = format!(r#"{{"type":"result","subtype":"success","is_error":false{cost}}}"#);
            assert_eq!(
                decode_event(line.as_bytes()),
                ClaudeEvent::Unrecognised,
                "{line}"
            );
        }
    }

    #[test]
    fn a_subagents_turn_does_not_set_the_context_size() {
        let usage = r#""message":{"usage":{"input_tokens":5,"cache_read_input_tokens":90000}}"#;
        let main = format!(r#"{{"type":"assistant","parent_tool_use_id":null,{usage}}}"#);
        let sub = format!(r#"{{"type":"assistant","parent_tool_use_id":"toolu_1",{usage}}}"#);
        assert!(matches!(
            decode_event(main.as_bytes()),
            ClaudeEvent::Assistant {
                context_tokens: Some(90_005),
                ..
            }
        ));
        assert!(matches!(
            decode_event(sub.as_bytes()),
            ClaudeEvent::Assistant {
                context_tokens: None,
                ..
            }
        ));
    }
}

//! The envelope fixtures of the parent tests against the JSON Schema exported from
//! `schemas/*.cue`: what Rust accepts validates, what Rust refuses at the serde layer is
//! refused, and the parse-level checks the schema cannot carry are pinned as such.

use std::path::PathBuf;

use serde::Serialize;
use serde_json::Value;

use super::*;
use crate::exit::ExitState;
use crate::session::Vendor;
use crate::task_packet::Effort;

fn schema_value(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../config/export/schema")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn validator(name: &str) -> jsonschema::Validator {
    jsonschema::draft202012::new(&schema_value(name)).unwrap()
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn accepted() -> Vec<String> {
    vec![
        envelope("result", &result_payload()),
        envelope("status", &status_payload()),
        envelope("escalation", &escalation_payload(1)),
        envelope("escalation", &escalation_payload(2)),
        downward("task_packet", &task_packet_payload()),
        routed("cf7a.wu03.ctl.codex", "cf7a.root.claude", "wu03", "cf7a"),
        envelope(
            "status",
            r#"{"summary":"idle","last_progress_unix_ms":0,"progress":{"head_sha":null,"tests_passing":0},"active_workers":0,"usage":{"input_tokens":0,"output_tokens":0},"blockers":[]}"#,
        ),
    ]
}

#[test]
fn every_accepted_fixture_validates() {
    let schema = validator("envelope");
    for text in accepted() {
        assert!(Envelope::parse(text.as_bytes()).is_ok(), "{text}");
        let errors: Vec<String> = schema
            .iter_errors(&json(&text))
            .map(|error| error.to_string())
            .collect();
        assert!(errors.is_empty(), "{text}\n{errors:?}");
    }
}

#[test]
fn round_tripped_envelopes_validate() {
    let schema = validator("envelope");
    for text in accepted() {
        let bytes = Envelope::parse(text.as_bytes())
            .unwrap()
            .to_bytes()
            .unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(schema.is_valid(&value), "{value}");
    }
}

#[test]
fn the_task_packet_payload_validates_on_its_own() {
    let schema = validator("task_packet");
    assert!(schema.is_valid(&json(&task_packet_payload())));
    let missing = task_packet_payload().replace(r#","rationale":"touches the launcher""#, "");
    assert!(!schema.is_valid(&json(&missing)));
}

fn refused() -> Vec<String> {
    let base = envelope("result", &result_payload());
    let refs = vec![format!("\"{}\"", digest('d')); REFS_MAX_ITEMS.saturating_add(1)].join(",");
    vec![
        base.replace("\"id\"", "\"ack_required\":true,\"id\""),
        envelope(
            "result",
            &result_payload().replace("\"outcome\"", "\"merged\":true,\"outcome\""),
        ),
        base.replace("\"schema_version\":1", "\"schema_version\":2"),
        envelope("status", &result_payload()),
        envelope("verdict", &result_payload()),
        envelope(
            "escalation",
            &escalation_payload(OPTIONS_MAX_ITEMS.saturating_add(1)),
        ),
        downward(
            "task_packet",
            &task_packet_payload().replace(r#","rationale":"touches the launcher""#, ""),
        ),
        downward(
            "task_packet",
            &task_packet_payload().replace("touches the launcher", ""),
        ),
        downward(
            "task_packet",
            &task_packet_payload().replace(
                &format!(r#""inputs":["{}"]"#, digest('f')),
                &format!(r#""inputs":[{refs}]"#),
            ),
        ),
        downward(
            "task_packet",
            &task_packet_payload().replace(r#""tokens_max":200000"#, r#""tokens_max":0"#),
        ),
        envelope(
            "status",
            &status_payload().replace(
                "verifying",
                &"s".repeat(STATE_NAME_MAX_BYTES.saturating_add(1)),
            ),
        ),
        base.replace("wu03/task-7", "wu03/x.lock"),
        base.replace("cf7a.wu03.ctl.codex", "cf7a.root.ctl.codex"),
        base.replace("\"work_unit_id\":\"wu03\"", "\"work_unit_id\":\"root\""),
    ]
}

#[test]
fn every_refused_fixture_is_refused_by_the_schema() {
    let schema = validator("envelope");
    for text in refused() {
        assert!(Envelope::parse(text.as_bytes()).is_err(), "{text}");
        assert!(!schema.is_valid(&json(&text)), "{text}");
    }
}

/// The size cap, epic and unit agreement, direction and self-addressing live in `parse`.
#[test]
fn parse_level_checks_are_outside_the_schema() {
    let schema = validator("envelope");
    for text in [
        routed(
            "cf7a.wu03.wrk.claude.a1f3",
            "cf7a.wu03.ctl.codex",
            "wu03",
            "beef",
        ),
        routed(
            "cf7a.wu03.wrk.claude.a1f3",
            "cf7a.wu03.ctl.codex",
            "wu04",
            "cf7a",
        ),
        routed(
            "cf7a.wu03.wrk.claude.a1f3",
            "cf7a.wu03.wrk.claude.a1f3",
            "wu03",
            "cf7a",
        ),
        downward("result", &result_payload()),
    ] {
        assert!(Envelope::parse(text.as_bytes()).is_err(), "{text}");
        assert!(schema.is_valid(&json(&text)), "{text}");
    }
}

fn wire<T: Serialize>(values: &[T]) -> Vec<Value> {
    values
        .iter()
        .map(|value| serde_json::to_value(value).unwrap())
        .collect()
}

fn schema_enum(schema: &Value, pointer: &str) -> Vec<Value> {
    schema
        .pointer(pointer)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

#[test]
fn schema_enums_equal_the_rust_variants() {
    let schema = schema_value("envelope");
    let pairs = [
        (
            "/$defs/Effort/enum",
            wire(&[
                Effort::Minimal,
                Effort::Low,
                Effort::Medium,
                Effort::High,
                Effort::Max,
            ]),
        ),
        (
            "/$defs/Vendor/enum",
            wire(&[
                Vendor::Claude,
                Vendor::Codex,
                Vendor::Antigravity,
                Vendor::Amp,
                Vendor::OpenCode,
            ]),
        ),
        (
            "/$defs/Level/enum",
            wire(&[Level::Root, Level::Control, Level::Worker]),
        ),
        (
            "/$defs/ResultPayload/properties/outcome/enum",
            wire(&[Outcome::Done, Outcome::NotDone]),
        ),
        (
            "/$defs/EscalationPayload/properties/question_type/enum",
            wire(&[
                QuestionType::Empirical,
                QuestionType::Judgment,
                QuestionType::Authority,
            ]),
        ),
        (
            "/$defs/EscalationOption/properties/reversibility/enum",
            wire(&[
                Reversibility::TwoWay,
                Reversibility::Costly,
                Reversibility::OneWay,
            ]),
        ),
    ];
    for (pointer, variants) in pairs {
        assert_eq!(schema_enum(&schema, pointer), variants, "{pointer}");
    }
}

#[test]
fn envelope_branches_equal_the_message_types() {
    let schema = schema_value("envelope");
    let types: Vec<Value> = schema_enum(&schema, "/anyOf")
        .iter()
        .filter_map(|branch| branch.pointer("/properties/type/const").cloned())
        .collect();
    let expected = wire(&[
        MessageType::TaskPacket,
        MessageType::Result,
        MessageType::Status,
        MessageType::Escalation,
    ]);
    assert_eq!(types, expected);
}

#[test]
fn serialized_exit_states_validate() {
    let schema = validator("exit_state");
    let long = "x".repeat(crate::exit::EXIT_RAW_MAX_BYTES.saturating_add(1));
    for raw in [
        "completed",
        "escalated",
        "too_large",
        "stalled",
        "cancelled",
        "killed",
        "budget_exceeded",
        "rate_limited",
        "failed",
        "error_max_turns",
        "",
        "a b",
        long.as_str(),
        "unrecognised:9:completed",
    ] {
        let value = serde_json::to_value(ExitState::from_wire(raw)).unwrap();
        assert!(schema.is_valid(&value), "{raw:?} -> {value}");
    }
    for unwritten in ["Completed", "unrecognised", "unrecognised:x", "exploded"] {
        assert!(!schema.is_valid(&Value::from(unwritten)), "{unwritten}");
    }
}

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

/// One bound: a fixture at the maximum and one past it.
struct Bound {
    name: &'static str,
    at_max: String,
    over: String,
}

fn bound(name: &'static str, build: impl Fn(usize) -> String, max: usize) -> Bound {
    Bound {
        name,
        at_max: build(max),
        over: build(max.saturating_add(1)),
    }
}

fn packet_count_bounds() -> Vec<Bound> {
    vec![
        bound(
            "writable_paths",
            |n| task_packet_count("writable_paths", r#"["crates"]"#, r#""crates""#, n),
            PATHS_MAX_ITEMS,
        ),
        bound(
            "done_criteria",
            |n| {
                task_packet_count(
                    "done_criteria",
                    r#"[{"kind":"command","command":"cargo test","expected_exit":0},{"kind":"file_absent","path":"TODO.md"}]"#,
                    r#"{"kind":"file_absent","path":"TODO.md"}"#,
                    n,
                )
            },
            CRITERIA_MAX_ITEMS,
        ),
        bound(
            "forbidden_actions",
            |n| task_packet_count("forbidden_actions", r#"["push"]"#, r#""push""#, n),
            REFS_MAX_ITEMS,
        ),
        bound(
            "inputs",
            |n| {
                task_packet_count(
                    "inputs",
                    &format!(r#"["{}"]"#, digest('f')),
                    &format!(r#""{}""#, digest('d')),
                    n,
                )
            },
            REFS_MAX_ITEMS,
        ),
    ]
}

fn report_count_bounds() -> Vec<Bound> {
    let criterion = r#"{"criterion":0,"passed":true,"evidence":[]}"#;
    let one_criterion = format!(
        r#"[{{"criterion":0,"passed":true,"evidence":["{}"]}}]"#,
        digest('b')
    );
    vec![
        bound(
            "criteria",
            |n| {
                envelope(
                    "result",
                    &result_payload()
                        .replace(&one_criterion, &format!("[{}]", repeated(criterion, n))),
                )
            },
            CRITERIA_MAX_ITEMS,
        ),
        bound(
            "criteria.evidence",
            |n| {
                envelope(
                    "result",
                    &result_payload().replace(
                        &format!(r#"["{}"]"#, digest('b')),
                        &format!("[{}]", refs(n)),
                    ),
                )
            },
            REFS_MAX_ITEMS,
        ),
        bound(
            "blockers",
            |n| {
                envelope(
                    "status",
                    &status_payload()
                        .replace(r#""blockers":[]"#, &format!(r#""blockers":[{}]"#, refs(n))),
                )
            },
            REFS_MAX_ITEMS,
        ),
        bound(
            "options",
            |n| envelope("escalation", &escalation_payload(n)),
            OPTIONS_MAX_ITEMS,
        ),
    ]
}

fn escalation_count_bounds() -> Vec<Bound> {
    vec![
        bound(
            "evidence",
            |n| {
                envelope(
                    "escalation",
                    &escalation_payload(2)
                        .replace(r#""evidence":[]"#, &format!(r#""evidence":[{}]"#, refs(n))),
                )
            },
            REFS_MAX_ITEMS,
        ),
        bound(
            "cases_consulted",
            |n| {
                envelope(
                    "escalation",
                    &escalation_payload(2).replace(
                        r#""cases_consulted":["case-12"]"#,
                        &format!(r#""cases_consulted":[{}]"#, repeated(r#""case-12""#, n)),
                    ),
                )
            },
            REFS_MAX_ITEMS,
        ),
    ]
}

fn text_bounds() -> Vec<Bound> {
    let base = envelope("result", &result_payload());
    vec![
        bound(
            "id",
            |n| base.replace("01J9Z3K7Q8R2W5X6Y7Z8A9B0C1", &"a".repeat(n)),
            RECORD_ID_MAX_BYTES,
        ),
        bound(
            "summary",
            |n| {
                envelope(
                    "status",
                    &status_payload().replace("tests green", &"x".repeat(n)),
                )
            },
            TEXT_MAX_BYTES,
        ),
        bound(
            "branch",
            |n| base.replace("wu03/task-7", &"b".repeat(n)),
            BRANCH_MAX_BYTES,
        ),
    ]
}

fn path_and_state_bounds() -> Vec<Bound> {
    let packet = |payload: String| downward("task_packet", &payload);
    vec![
        bound(
            "state",
            |n| {
                envelope(
                    "status",
                    &status_payload().replace("verifying", &"s".repeat(n)),
                )
            },
            STATE_NAME_MAX_BYTES,
        ),
        bound(
            "worktree",
            |n| {
                packet(task_packet_payload().replace(
                    "/Users/agent/wt/cf7a-wu03",
                    &format!("/{}", "w".repeat(n.saturating_sub(1))),
                ))
            },
            crate::task_packet::PATH_MAX_BYTES,
        ),
        bound(
            "writable path",
            |n| {
                packet(task_packet_payload().replace(
                    r#""writable_paths":["crates"]"#,
                    &format!(r#""writable_paths":["{}"]"#, "p".repeat(n)),
                ))
            },
            crate::task_packet::PATH_MAX_BYTES,
        ),
    ]
}

fn name_bounds() -> Vec<Bound> {
    let packet = |payload: String| downward("task_packet", &payload);
    vec![
        bound(
            "class",
            |n| {
                packet(task_packet_payload().replace(
                    r#""class":"implement""#,
                    &format!(r#""class":"{}""#, "c".repeat(n)),
                ))
            },
            crate::task_packet::ROUTING_NAME_MAX_BYTES,
        ),
        bound(
            "epic",
            |n| {
                let epic = "e".repeat(n);
                routed(
                    &format!("{epic}.wu03.wrk.claude.a1f3"),
                    &format!("{epic}.wu03.ctl.codex"),
                    "wu03",
                    &epic,
                )
            },
            crate::service::ID_MAX_BYTES,
        ),
        bound(
            "unit",
            |n| {
                let unit = "u".repeat(n);
                routed(
                    &format!("cf7a.{unit}.wrk.claude.a1f3"),
                    &format!("cf7a.{unit}.ctl.codex"),
                    &unit,
                    "cf7a",
                )
            },
            crate::service::ID_MAX_BYTES,
        ),
    ]
}

fn suffix_and_budget_bounds() -> Vec<Bound> {
    vec![
        bound(
            "suffix",
            |n| {
                routed(
                    &format!("cf7a.wu03.wrk.claude.{}", "s".repeat(n)),
                    "cf7a.wu03.ctl.codex",
                    "wu03",
                    "cf7a",
                )
            },
            crate::session::SUFFIX_MAX_BYTES,
        ),
        bound(
            "wall_clock_max_ms",
            |n| with_budget(1, u64::try_from(n).unwrap()),
            usize::try_from(crate::task_packet::BUDGET_WALL_CLOCK_MAX_MS).unwrap(),
        ),
        bound(
            "tokens_max",
            |n| with_budget(u64::try_from(n).unwrap(), 1),
            usize::try_from(crate::task_packet::BUDGET_TOKENS_MAX_COUNT).unwrap(),
        ),
    ]
}

#[test]
fn every_bound_validates_at_its_maximum_and_is_refused_one_past() {
    let schema = validator("envelope");
    let groups = [
        packet_count_bounds(),
        report_count_bounds(),
        escalation_count_bounds(),
        text_bounds(),
        path_and_state_bounds(),
        name_bounds(),
        suffix_and_budget_bounds(),
    ];
    for case in groups.into_iter().flatten() {
        let name = case.name;
        assert!(
            Envelope::parse(case.at_max.as_bytes()).is_ok(),
            "{name} at max, Rust"
        );
        assert!(
            schema.is_valid(&json(&case.at_max)),
            "{name} at max, schema"
        );
        assert!(
            Envelope::parse(case.over.as_bytes()).is_err(),
            "{name} over, Rust"
        );
        assert!(!schema.is_valid(&json(&case.over)), "{name} over, schema");
    }
}

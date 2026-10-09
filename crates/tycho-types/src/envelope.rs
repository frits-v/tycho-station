//! The message envelope and its payloads: `task_packet` down; `result`, `status`, `escalation` up.
//! Payloads carry references into the content store, never content, so journal
//! entries stay small.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::service::{EpicId, WorkUnitId};
use crate::session::{Level, SessionName};
use crate::task_packet::{check_task_packet, TaskPacketPayload};
use crate::token::{
    check_hex, check_record_id, check_slug, check_text, checked_string, TokenError,
};

pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;
pub const ENVELOPE_MAX_BYTES: usize = 65_536;
pub const RECORD_ID_MAX_BYTES: usize = 64;
pub const TEXT_MAX_BYTES: usize = 512;
pub const BRANCH_MAX_BYTES: usize = 128;
pub const REFS_MAX_ITEMS: usize = 64;
pub const CRITERIA_MAX_ITEMS: usize = 64;
pub const OPTIONS_MAX_ITEMS: usize = 4;
pub const STATE_NAME_MAX_BYTES: usize = 32;
const CONTENT_REF_PREFIX: &str = "sha256:";

fn check_message_id(value: &str) -> Result<(), TokenError> {
    check_record_id(value, RECORD_ID_MAX_BYTES)
}

fn check_short_text(value: &str) -> Result<(), TokenError> {
    check_text(value, TEXT_MAX_BYTES)
}

fn check_commit_sha(value: &str) -> Result<(), TokenError> {
    check_hex(value, &[40, 64])
}

fn check_content_ref(value: &str) -> Result<(), TokenError> {
    let digest = value
        .strip_prefix(CONTENT_REF_PREFIX)
        .ok_or(TokenError::InvalidCharacter { position: 0 })?;
    check_hex(digest, &[64])
}

/// A git branch name in a portable subset of what `git check-ref-format` allows.
fn check_branch(value: &str) -> Result<(), TokenError> {
    check_text(value, BRANCH_MAX_BYTES)?;
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte);
    if let Some(position) = value.bytes().position(|byte| !allowed(byte)) {
        return Err(TokenError::InvalidCharacter { position });
    }
    if value.starts_with('-') || value.ends_with('.') || value.contains("..") {
        return Err(TokenError::InvalidCharacter { position: 0 });
    }
    let malformed_component = value.split('/').any(|component| {
        component.is_empty()
            || component.starts_with('.')
            || component
                .rsplit_once('.')
                .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("lock"))
    });
    if malformed_component {
        return Err(TokenError::InvalidCharacter { position: 0 });
    }
    Ok(())
}

fn check_state_name(value: &str) -> Result<(), TokenError> {
    check_slug(value, STATE_NAME_MAX_BYTES)
}

checked_string!(
    /// A message or case id, such as a ULID.
    RecordId,
    check_message_id
);
checked_string!(
    /// One line of human-readable text without control characters.
    ShortText,
    check_short_text
);
checked_string!(CommitSha, check_commit_sha);
checked_string!(
    /// `sha256:<hex>`, the address of an artifact in the content store.
    ContentRef,
    check_content_ref
);
checked_string!(BranchName, check_branch);
checked_string!(
    /// A reported state; a string so stored statuses survive new state names.
    StateName,
    check_state_name
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    TaskPacket,
    Result,
    Status,
    Escalation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Spend in micro-dollars for a metered vendor; zero under a seat.
    #[serde(default)]
    pub cost_micro_dollars: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Done,
    NotDone,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CriterionReport {
    /// Index into the task packet's done criteria.
    pub criterion: u16,
    pub passed: bool,
    pub evidence: Vec<ContentRef>,
}

/// A claim of done, never a claim of merged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultPayload {
    pub outcome: Outcome,
    pub branch: BranchName,
    pub head_sha: CommitSha,
    pub criteria: Vec<CriterionReport>,
    pub usage: Usage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressMarker {
    pub head_sha: Option<CommitSha>,
    pub tests_passing: u32,
}

/// Doubles as the heartbeat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusPayload {
    pub state: Option<StateName>,
    pub summary: ShortText,
    pub last_progress_unix_ms: u64,
    pub progress: ProgressMarker,
    pub active_workers: u16,
    pub usage: Usage,
    pub blockers: Vec<ContentRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionType {
    Empirical,
    Judgment,
    Authority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    TwoWay,
    Costly,
    OneWay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationOption {
    pub label: ShortText,
    pub reversibility: Reversibility,
    pub blast_radius: ShortText,
}

/// A certified question; a missing proposed ruling decodes, and the arbiter sends it back down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationPayload {
    pub level_reached: Level,
    pub give_up_reason: ShortText,
    pub question: ContentRef,
    pub question_type: QuestionType,
    pub options: Vec<EscalationOption>,
    pub proposed_ruling: Option<ContentRef>,
    pub evidence: Vec<ContentRef>,
    pub cases_consulted: Vec<RecordId>,
    pub blocking: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Payload {
    TaskPacket(TaskPacketPayload),
    Result(ResultPayload),
    Status(StatusPayload),
    Escalation(EscalationPayload),
}

impl Payload {
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::TaskPacket(_) => MessageType::TaskPacket,
            Self::Result(_) => MessageType::Result,
            Self::Status(_) => MessageType::Status,
            Self::Escalation(_) => MessageType::Escalation,
        }
    }
}

/// Level and vendor derive from `from` and `to`; `parse` and `to_bytes` check the epic and unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub id: RecordId,
    pub work_unit_id: WorkUnitId,
    pub from: SessionName,
    pub to: SessionName,
    pub causation_id: Option<RecordId>,
    pub correlation_id: EpicId,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: Option<u64>,
    pub payload: Payload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeIn {
    schema_version: u32,
    id: RecordId,
    #[serde(rename = "type")]
    message_type: MessageType,
    work_unit_id: WorkUnitId,
    from: SessionName,
    to: SessionName,
    causation_id: Option<RecordId>,
    correlation_id: EpicId,
    created_at_unix_ms: u64,
    expires_at_unix_ms: Option<u64>,
    payload: serde_json::Value,
}

#[derive(Serialize)]
struct EnvelopeOut<'a> {
    schema_version: u32,
    id: &'a RecordId,
    #[serde(rename = "type")]
    message_type: MessageType,
    work_unit_id: &'a WorkUnitId,
    from: &'a SessionName,
    to: &'a SessionName,
    causation_id: Option<&'a RecordId>,
    correlation_id: &'a EpicId,
    created_at_unix_ms: u64,
    expires_at_unix_ms: Option<u64>,
    payload: &'a Payload,
}

#[derive(Debug)]
pub enum EnvelopeError {
    TooLarge(usize),
    Json(serde_json::Error),
    SchemaVersion(u32),
    TooMany {
        field: &'static str,
        count: usize,
        max: usize,
    },
    OutOfRange {
        field: &'static str,
        value: u64,
        max: u64,
    },
    EpicMismatch,
    WorkUnitMismatch,
    SelfAddressed,
    Direction {
        message_type: MessageType,
        from: Level,
        to: Level,
    },
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(length) => write!(
                formatter,
                "envelope is {length} bytes; maximum is {ENVELOPE_MAX_BYTES}"
            ),
            Self::Json(error) => write!(formatter, "envelope: {error}"),
            Self::SchemaVersion(version) => write!(
                formatter,
                "envelope schema version {version}; expected {ENVELOPE_SCHEMA_VERSION}"
            ),
            Self::TooMany { field, count, max } => {
                write!(formatter, "{field} has {count} items; maximum is {max}")
            }
            Self::OutOfRange { field, value, max } => {
                write!(formatter, "{field} is {value}; expected 1..={max}")
            }
            Self::EpicMismatch => {
                write!(
                    formatter,
                    "correlation_id differs from the epic of from or to"
                )
            }
            Self::WorkUnitMismatch => write!(
                formatter,
                "work_unit_id differs from the unit of from or to, or neither carries one"
            ),
            Self::SelfAddressed => write!(formatter, "from and to are the same session"),
            Self::Direction {
                message_type,
                from,
                to,
            } => write!(
                formatter,
                "a {message_type:?} message cannot go from {from:?} to {to:?}"
            ),
        }
    }
}

impl std::error::Error for EnvelopeError {}

pub(crate) const fn check_count(
    field: &'static str,
    count: usize,
    max: usize,
) -> Result<(), EnvelopeError> {
    if count > max {
        return Err(EnvelopeError::TooMany { field, count, max });
    }
    Ok(())
}

fn check_result(payload: &ResultPayload) -> Result<(), EnvelopeError> {
    check_count("criteria", payload.criteria.len(), CRITERIA_MAX_ITEMS)?;
    for report in &payload.criteria {
        check_count("criteria.evidence", report.evidence.len(), REFS_MAX_ITEMS)?;
    }
    Ok(())
}

pub(crate) fn check_escalation(payload: &EscalationPayload) -> Result<(), EnvelopeError> {
    check_count("options", payload.options.len(), OPTIONS_MAX_ITEMS)?;
    check_count("evidence", payload.evidence.len(), REFS_MAX_ITEMS)?;
    check_count(
        "cases_consulted",
        payload.cases_consulted.len(),
        REFS_MAX_ITEMS,
    )
}

fn check_payload(payload: &Payload) -> Result<(), EnvelopeError> {
    match payload {
        Payload::TaskPacket(packet) => check_task_packet(packet),
        Payload::Result(result) => check_result(result),
        Payload::Status(status) => check_count("blockers", status.blockers.len(), REFS_MAX_ITEMS),
        Payload::Escalation(escalation) => check_escalation(escalation),
    }
}

/// Root is the top of the tree; a smaller rank is further up.
const fn level_rank(level: Level) -> u8 {
    match level {
        Level::Root => 0,
        Level::Control => 1,
        Level::Worker => 2,
    }
}

/// `task_packet` goes down the tree; `result`, `status` and `escalation` go up.
const fn check_direction(
    message_type: MessageType,
    from: Level,
    to: Level,
) -> Result<(), EnvelopeError> {
    let allowed = match message_type {
        MessageType::TaskPacket => level_rank(to) > level_rank(from),
        MessageType::Result | MessageType::Status | MessageType::Escalation => {
            level_rank(to) < level_rank(from)
        }
    };
    if !allowed {
        return Err(EnvelopeError::Direction {
            message_type,
            from,
            to,
        });
    }
    Ok(())
}

fn decode_payload(
    message_type: MessageType,
    value: serde_json::Value,
) -> Result<Payload, EnvelopeError> {
    let decoded = match message_type {
        MessageType::TaskPacket => serde_json::from_value(value).map(Payload::TaskPacket),
        MessageType::Result => serde_json::from_value(value).map(Payload::Result),
        MessageType::Status => serde_json::from_value(value).map(Payload::Status),
        MessageType::Escalation => serde_json::from_value(value).map(Payload::Escalation),
    };
    decoded.map_err(EnvelopeError::Json)
}

impl Envelope {
    pub fn parse(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() > ENVELOPE_MAX_BYTES {
            return Err(EnvelopeError::TooLarge(bytes.len()));
        }
        let wire: EnvelopeIn = serde_json::from_slice(bytes).map_err(EnvelopeError::Json)?;
        if wire.schema_version != ENVELOPE_SCHEMA_VERSION {
            return Err(EnvelopeError::SchemaVersion(wire.schema_version));
        }
        let envelope = Self {
            payload: decode_payload(wire.message_type, wire.payload)?,
            id: wire.id,
            work_unit_id: wire.work_unit_id,
            from: wire.from,
            to: wire.to,
            causation_id: wire.causation_id,
            correlation_id: wire.correlation_id,
            created_at_unix_ms: wire.created_at_unix_ms,
            expires_at_unix_ms: wire.expires_at_unix_ms,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Refuses to write what `parse` would reject, except for the overall size.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        self.validate()?;
        serde_json::to_vec(&EnvelopeOut {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            id: &self.id,
            message_type: self.payload.message_type(),
            work_unit_id: &self.work_unit_id,
            from: &self.from,
            to: &self.to,
            causation_id: self.causation_id.as_ref(),
            correlation_id: &self.correlation_id,
            created_at_unix_ms: self.created_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            payload: &self.payload,
        })
        .map_err(EnvelopeError::Json)
    }

    fn validate(&self) -> Result<(), EnvelopeError> {
        self.check_routing()?;
        check_direction(
            self.payload.message_type(),
            self.from.level(),
            self.to.level(),
        )?;
        check_payload(&self.payload)
    }

    fn check_routing(&self) -> Result<(), EnvelopeError> {
        if *self.from.epic() != self.correlation_id || *self.to.epic() != self.correlation_id {
            return Err(EnvelopeError::EpicMismatch);
        }
        let units = [self.from.work_unit(), self.to.work_unit()];
        let carried = units.iter().flatten().count();
        let agree = units
            .iter()
            .flatten()
            .all(|unit| **unit == self.work_unit_id);
        if carried == 0 || !agree {
            return Err(EnvelopeError::WorkUnitMismatch);
        }
        if self.from == self.to {
            return Err(EnvelopeError::SelfAddressed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_packet::{BUDGET_TOKENS_MAX_COUNT, BUDGET_WALL_CLOCK_MAX_MS, PATHS_MAX_ITEMS};

    mod schema;

    fn digest(fill: char) -> String {
        format!("sha256:{}", fill.to_string().repeat(64))
    }

    fn envelope(message_type: &str, payload: &str) -> String {
        format!(
            r#"{{"schema_version":1,"id":"01J9Z3K7Q8R2W5X6Y7Z8A9B0C1","type":"{message_type}","work_unit_id":"wu03","from":"cf7a.wu03.wrk.claude.a1f3","to":"cf7a.wu03.ctl.codex","causation_id":null,"correlation_id":"cf7a","created_at_unix_ms":1800000000000,"expires_at_unix_ms":null,"payload":{payload}}}"#
        )
    }

    /// The same envelope sent from the control session down to the worker.
    fn downward(message_type: &str, payload: &str) -> String {
        envelope(message_type, payload)
            .replace(
                "\"from\":\"cf7a.wu03.wrk.claude.a1f3\"",
                "\"from\":\"cf7a.wu03.ctl.codex\"",
            )
            .replace(
                "\"to\":\"cf7a.wu03.ctl.codex\"",
                "\"to\":\"cf7a.wu03.wrk.claude.a1f3\"",
            )
    }

    fn repeated(item: &str, count: usize) -> String {
        vec![item; count].join(",")
    }

    fn status_payload() -> String {
        r#"{"state":"verifying","summary":"tests green","last_progress_unix_ms":1800000000000,"progress":{"head_sha":null,"tests_passing":12},"active_workers":2,"usage":{"input_tokens":0,"output_tokens":0},"blockers":[]}"#.to_string()
    }

    fn result_payload() -> String {
        format!(
            r#"{{"outcome":"done","branch":"wu03/task-7","head_sha":"{}","criteria":[{{"criterion":0,"passed":true,"evidence":["{}"]}}],"usage":{{"input_tokens":1200,"output_tokens":300}}}}"#,
            "a".repeat(40),
            digest('b')
        )
    }

    fn escalation_payload(options: usize) -> String {
        let option =
            r#"{"label":"dual write","reversibility":"two_way","blast_radius":"orders-api"}"#;
        let options = vec![option; options].join(",");
        format!(
            r#"{{"level_reached":"worker","give_up_reason":"two attempts failed","question":"{}","question_type":"judgment","options":[{options}],"proposed_ruling":null,"evidence":[],"cases_consulted":["case-12"],"blocking":true}}"#,
            digest('c')
        )
    }

    #[test]
    fn result_round_trips() {
        let parsed = Envelope::parse(envelope("result", &result_payload()).as_bytes()).unwrap();
        assert_eq!(parsed.from.level(), Level::Worker);
        let Payload::Result(result) = &parsed.payload else {
            panic!("expected a result payload");
        };
        assert_eq!(result.outcome, Outcome::Done);
        let bytes = parsed.to_bytes().unwrap();
        assert_eq!(Envelope::parse(&bytes).unwrap(), parsed);
    }

    #[test]
    fn status_and_escalation_parse() {
        let parsed = Envelope::parse(envelope("status", &status_payload()).as_bytes()).unwrap();
        assert_eq!(parsed.payload.message_type(), MessageType::Status);
        let parsed =
            Envelope::parse(envelope("escalation", &escalation_payload(2)).as_bytes()).unwrap();
        assert_eq!(parsed.payload.message_type(), MessageType::Escalation);
    }

    #[test]
    fn rejects_size_version_and_unknown_fields() {
        let padded = format!(
            "{}{}",
            envelope("result", &result_payload()),
            " ".repeat(ENVELOPE_MAX_BYTES)
        );
        assert!(matches!(
            Envelope::parse(padded.as_bytes()),
            Err(EnvelopeError::TooLarge(_))
        ));
        let version = envelope("result", &result_payload())
            .replace("\"schema_version\":1", "\"schema_version\":2");
        assert!(matches!(
            Envelope::parse(version.as_bytes()),
            Err(EnvelopeError::SchemaVersion(2))
        ));
        let extra =
            envelope("result", &result_payload()).replace("\"id\"", "\"ack_required\":true,\"id\"");
        assert!(matches!(
            Envelope::parse(extra.as_bytes()),
            Err(EnvelopeError::Json(_))
        ));
        let inner = envelope(
            "result",
            &result_payload().replace("\"outcome\"", "\"merged\":true,\"outcome\""),
        );
        assert!(matches!(
            Envelope::parse(inner.as_bytes()),
            Err(EnvelopeError::Json(_))
        ));
    }

    #[test]
    fn rejects_a_payload_of_the_wrong_type() {
        let mismatched = envelope("status", &result_payload());
        assert!(matches!(
            Envelope::parse(mismatched.as_bytes()),
            Err(EnvelopeError::Json(_))
        ));
        let unknown = envelope("verdict", &result_payload());
        assert!(matches!(
            Envelope::parse(unknown.as_bytes()),
            Err(EnvelopeError::Json(_))
        ));
    }

    #[test]
    fn rejects_counts_outside_bounds() {
        let one = envelope("escalation", &escalation_payload(1));
        assert!(Envelope::parse(one.as_bytes()).is_ok());
        let many = envelope(
            "escalation",
            &escalation_payload(OPTIONS_MAX_ITEMS.saturating_add(1)),
        );
        assert!(matches!(
            Envelope::parse(many.as_bytes()),
            Err(EnvelopeError::TooMany { .. })
        ));
        let refs = vec![format!("\"{}\"", digest('d')); REFS_MAX_ITEMS.saturating_add(1)].join(",");
        let evidence =
            result_payload().replace(&format!("[\"{}\"]", digest('b')), &format!("[{refs}]"));
        assert!(matches!(
            Envelope::parse(envelope("result", &evidence).as_bytes()),
            Err(EnvelopeError::TooMany { .. })
        ));
    }

    #[test]
    fn rejects_too_many_criteria() {
        let criterion = r#"{"criterion":0,"passed":true,"evidence":[]}"#;
        let criteria = vec![criterion; CRITERIA_MAX_ITEMS.saturating_add(1)].join(",");
        let payload = result_payload().replace(
            &format!(
                r#"[{{"criterion":0,"passed":true,"evidence":["{}"]}}]"#,
                digest('b')
            ),
            &format!("[{criteria}]"),
        );
        assert!(matches!(
            Envelope::parse(envelope("result", &payload).as_bytes()),
            Err(EnvelopeError::TooMany {
                field: "criteria",
                ..
            })
        ));
    }

    #[test]
    fn strings_reject_lengths_over_their_maximum() {
        let over = |max: usize| "a".repeat(max.saturating_add(1));
        assert!(RecordId::parse(&over(RECORD_ID_MAX_BYTES)).is_err());
        assert!(ShortText::parse(&over(TEXT_MAX_BYTES)).is_err());
        assert!(BranchName::parse(&over(BRANCH_MAX_BYTES)).is_err());
        assert!(RecordId::parse(&"a".repeat(RECORD_ID_MAX_BYTES)).is_ok());
    }

    #[test]
    fn references_and_branches_are_checked() {
        assert!(ContentRef::parse(&digest('e')).is_ok());
        assert!(ContentRef::parse("md5:abc").is_err());
        assert!(ContentRef::parse(&format!("sha256:{}", "E".repeat(64))).is_err());
        assert!(BranchName::parse("wu03/task-7").is_ok());
        for bad in [
            "-x",
            "a..b",
            "a b",
            "a/",
            "x.lock",
            "/a",
            "a//b",
            "",
            "a/.hidden",
            "a.lock/b",
            "a.",
        ] {
            assert!(BranchName::parse(bad).is_err(), "{bad:?}");
        }
        assert!(ShortText::parse("line\nbreak").is_err());
    }

    fn routed(from: &str, to: &str, unit: &str, epic: &str) -> String {
        envelope("result", &result_payload())
            .replace("cf7a.wu03.ctl.codex", to)
            .replace("cf7a.wu03.wrk.claude.a1f3", from)
            .replace(
                "\"work_unit_id\":\"wu03\"",
                &format!("\"work_unit_id\":\"{unit}\""),
            )
            .replace(
                "\"correlation_id\":\"cf7a\"",
                &format!("\"correlation_id\":\"{epic}\""),
            )
    }

    #[test]
    fn routing_accepts_a_unit_on_either_side() {
        let up = routed("cf7a.wu03.ctl.codex", "cf7a.root.claude", "wu03", "cf7a");
        assert!(Envelope::parse(up.as_bytes()).is_ok());
    }

    #[test]
    fn rejects_a_correlation_id_that_is_not_the_epic() {
        let other = routed(
            "cf7a.wu03.wrk.claude.a1f3",
            "cf7a.wu03.ctl.codex",
            "wu03",
            "beef",
        );
        assert!(matches!(
            Envelope::parse(other.as_bytes()),
            Err(EnvelopeError::EpicMismatch)
        ));
        let split = routed(
            "cf7a.wu03.wrk.claude.a1f3",
            "beef.wu03.ctl.codex",
            "wu03",
            "cf7a",
        );
        assert!(matches!(
            Envelope::parse(split.as_bytes()),
            Err(EnvelopeError::EpicMismatch)
        ));
    }

    #[test]
    fn rejects_a_work_unit_id_that_is_not_the_unit() {
        let other = routed(
            "cf7a.wu03.wrk.claude.a1f3",
            "cf7a.wu03.ctl.codex",
            "wu04",
            "cf7a",
        );
        assert!(matches!(
            Envelope::parse(other.as_bytes()),
            Err(EnvelopeError::WorkUnitMismatch)
        ));
        let none = routed("cf7a.root.claude", "cf7a.root.codex", "wu03", "cf7a");
        assert!(matches!(
            Envelope::parse(none.as_bytes()),
            Err(EnvelopeError::WorkUnitMismatch)
        ));
    }

    #[test]
    fn to_bytes_refuses_what_parse_rejects() {
        let mut parsed = Envelope::parse(envelope("result", &result_payload()).as_bytes()).unwrap();
        parsed.correlation_id = EpicId::parse("beef").unwrap();
        assert!(matches!(
            parsed.to_bytes(),
            Err(EnvelopeError::EpicMismatch)
        ));
    }

    fn task_packet_payload() -> String {
        format!(
            r#"{{"objective":"{d}","done_criteria":[{{"kind":"command","command":"cargo test","expected_exit":0}},{{"kind":"file_absent","path":"TODO.md"}}],"boundaries":{{"worktree":"/Users/agent/wt/cf7a-wu03","branch":"wu03/task-7","writable_paths":["crates"],"forbidden_actions":["push"]}},"inputs":["{d}"],"routing":{{"class":"implement","tier":"t2","effort":"medium","binding":"claude","rationale":"touches the launcher","fallback_tier":"t3"}},"budget":{{"tokens_max":200000,"wall_clock_max_ms":3600000}},"result_schema":"{d}"}}"#,
            d = digest('f')
        )
    }

    #[test]
    fn task_packet_round_trips() {
        let down = downward("task_packet", &task_packet_payload());
        let parsed = Envelope::parse(down.as_bytes()).unwrap();
        assert_eq!(parsed.payload.message_type(), MessageType::TaskPacket);
        assert_eq!(
            Envelope::parse(&parsed.to_bytes().unwrap()).unwrap(),
            parsed
        );
    }

    #[test]
    fn task_packet_rejects_a_missing_rationale_and_too_many_inputs() {
        let missing = task_packet_payload().replace(r#","rationale":"touches the launcher""#, "");
        assert!(matches!(
            Envelope::parse(downward("task_packet", &missing).as_bytes()),
            Err(EnvelopeError::Json(_))
        ));
        let empty = task_packet_payload().replace("touches the launcher", "");
        assert!(matches!(
            Envelope::parse(downward("task_packet", &empty).as_bytes()),
            Err(EnvelopeError::Json(_))
        ));
        let refs = vec![format!("\"{}\"", digest('d')); REFS_MAX_ITEMS.saturating_add(1)].join(",");
        let many = task_packet_payload().replace(
            &format!(r#""inputs":["{}"]"#, digest('f')),
            &format!(r#""inputs":[{refs}]"#),
        );
        assert!(matches!(
            Envelope::parse(downward("task_packet", &many).as_bytes()),
            Err(EnvelopeError::TooMany {
                field: "inputs",
                ..
            })
        ));
    }

    fn task_packet_count(field: &str, original: &str, item: &str, count: usize) -> String {
        let payload = task_packet_payload().replace(
            &format!(r#""{field}":{original}"#),
            &format!(r#""{field}":[{}]"#, repeated(item, count)),
        );
        downward("task_packet", &payload)
    }

    fn assert_count_bound(field: &'static str, original: &str, item: &str, max: usize) {
        let at_max = task_packet_count(field, original, item, max);
        assert!(Envelope::parse(at_max.as_bytes()).is_ok(), "{field}");
        let over = task_packet_count(field, original, item, max.saturating_add(1));
        let rejected = Envelope::parse(over.as_bytes());
        assert!(
            matches!(rejected, Err(EnvelopeError::TooMany { field: name, .. }) if name == field),
            "{field}: {rejected:?}"
        );
    }

    #[test]
    fn task_packet_rejects_too_many_writable_paths() {
        assert_count_bound(
            "writable_paths",
            r#"["crates"]"#,
            r#""crates""#,
            PATHS_MAX_ITEMS,
        );
    }

    #[test]
    fn task_packet_rejects_too_many_done_criteria() {
        assert_count_bound(
            "done_criteria",
            r#"[{"kind":"command","command":"cargo test","expected_exit":0},{"kind":"file_absent","path":"TODO.md"}]"#,
            r#"{"kind":"file_absent","path":"TODO.md"}"#,
            CRITERIA_MAX_ITEMS,
        );
    }

    #[test]
    fn task_packet_rejects_too_many_forbidden_actions() {
        assert_count_bound(
            "forbidden_actions",
            r#"["push"]"#,
            r#""push""#,
            REFS_MAX_ITEMS,
        );
    }

    fn with_budget(tokens: u64, wall_clock_ms: u64) -> String {
        let payload = task_packet_payload().replace(
            r#""budget":{"tokens_max":200000,"wall_clock_max_ms":3600000}"#,
            &format!(r#""budget":{{"tokens_max":{tokens},"wall_clock_max_ms":{wall_clock_ms}}}"#),
        );
        downward("task_packet", &payload)
    }

    #[test]
    fn task_packet_rejects_a_zero_or_oversized_budget() {
        let hour_ms = 3_600_000;
        let at_max = with_budget(BUDGET_TOKENS_MAX_COUNT, BUDGET_WALL_CLOCK_MAX_MS);
        assert!(Envelope::parse(at_max.as_bytes()).is_ok());
        for (tokens, wall_clock_ms, expected) in [
            (0, hour_ms, "budget.tokens_max"),
            (
                BUDGET_TOKENS_MAX_COUNT.saturating_add(1),
                hour_ms,
                "budget.tokens_max",
            ),
            (1, 0, "budget.wall_clock_max_ms"),
            (
                1,
                BUDGET_WALL_CLOCK_MAX_MS.saturating_add(1),
                "budget.wall_clock_max_ms",
            ),
        ] {
            let rejected = Envelope::parse(with_budget(tokens, wall_clock_ms).as_bytes());
            assert!(
                matches!(rejected, Err(EnvelopeError::OutOfRange { field, .. }) if field == expected),
                "{tokens} {wall_clock_ms}: {rejected:?}"
            );
        }
    }

    fn refs(count: usize) -> String {
        repeated(&format!("\"{}\"", digest('d')), count)
    }

    #[test]
    fn status_rejects_too_many_blockers() {
        let payload = status_payload().replace(
            r#""blockers":[]"#,
            &format!(r#""blockers":[{}]"#, refs(REFS_MAX_ITEMS.saturating_add(1))),
        );
        assert!(matches!(
            Envelope::parse(envelope("status", &payload).as_bytes()),
            Err(EnvelopeError::TooMany {
                field: "blockers",
                ..
            })
        ));
    }

    #[test]
    fn escalation_rejects_too_much_evidence_and_too_many_cases() {
        let over = REFS_MAX_ITEMS.saturating_add(1);
        let evidence = escalation_payload(2).replace(
            r#""evidence":[]"#,
            &format!(r#""evidence":[{}]"#, refs(over)),
        );
        assert!(matches!(
            Envelope::parse(envelope("escalation", &evidence).as_bytes()),
            Err(EnvelopeError::TooMany {
                field: "evidence",
                ..
            })
        ));
        let cases = escalation_payload(2).replace(
            r#""cases_consulted":["case-12"]"#,
            &format!(r#""cases_consulted":[{}]"#, repeated(r#""case-12""#, over)),
        );
        assert!(matches!(
            Envelope::parse(envelope("escalation", &cases).as_bytes()),
            Err(EnvelopeError::TooMany {
                field: "cases_consulted",
                ..
            })
        ));
    }

    #[test]
    fn state_name_rejects_its_maximum_plus_one() {
        assert!(StateName::parse(&"s".repeat(STATE_NAME_MAX_BYTES)).is_ok());
        let over = "s".repeat(STATE_NAME_MAX_BYTES.saturating_add(1));
        assert!(matches!(
            StateName::parse(&over),
            Err(TokenError::TooLong { .. })
        ));
        let payload = status_payload().replace("verifying", &over);
        assert!(matches!(
            Envelope::parse(envelope("status", &payload).as_bytes()),
            Err(EnvelopeError::Json(_))
        ));
    }

    #[test]
    fn rejects_each_message_type_against_its_direction() {
        for (message_type, payload) in [
            ("result", result_payload()),
            ("status", status_payload()),
            ("escalation", escalation_payload(2)),
        ] {
            let rejected = Envelope::parse(downward(message_type, &payload).as_bytes());
            assert!(
                matches!(
                    rejected,
                    Err(EnvelopeError::Direction {
                        from: Level::Control,
                        to: Level::Worker,
                        ..
                    })
                ),
                "{message_type}: {rejected:?}"
            );
        }
        let up = envelope("task_packet", &task_packet_payload());
        assert!(matches!(
            Envelope::parse(up.as_bytes()),
            Err(EnvelopeError::Direction {
                message_type: MessageType::TaskPacket,
                ..
            })
        ));
        let lateral = routed(
            "cf7a.wu03.ctl.codex",
            "cf7a.wu03.ctl.claude",
            "wu03",
            "cf7a",
        );
        assert!(matches!(
            Envelope::parse(lateral.as_bytes()),
            Err(EnvelopeError::Direction { .. })
        ));
    }

    #[test]
    fn rejects_a_message_addressed_to_its_sender() {
        let echo = routed(
            "cf7a.wu03.wrk.claude.a1f3",
            "cf7a.wu03.wrk.claude.a1f3",
            "wu03",
            "cf7a",
        );
        assert!(matches!(
            Envelope::parse(echo.as_bytes()),
            Err(EnvelopeError::SelfAddressed)
        ));
    }

    #[test]
    fn status_state_is_optional() {
        let status = r#"{"summary":"idle","last_progress_unix_ms":0,"progress":{"head_sha":null,"tests_passing":0},"active_workers":0,"usage":{"input_tokens":0,"output_tokens":0},"blockers":[]}"#;
        let parsed = Envelope::parse(envelope("status", status).as_bytes()).unwrap();
        let Payload::Status(status) = parsed.payload else {
            panic!("expected a status payload");
        };
        assert_eq!(status.state, None);
        assert!(StateName::parse("Verifying").is_err());
    }
}

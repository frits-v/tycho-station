//! The message envelope and the upward payloads: `result`, `status`, `escalation`.
//! Payloads carry references into the content store, never content, so journal
//! entries stay small.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::service::{EpicId, WorkUnitId};
use crate::session::{Level, SessionName};
use crate::token::{check_hex, check_record_id, check_text, checked_string, TokenError};

pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;
pub const ENVELOPE_MAX_BYTES: usize = 65_536;
pub const RECORD_ID_MAX_BYTES: usize = 64;
pub const TEXT_MAX_BYTES: usize = 512;
pub const BRANCH_MAX_BYTES: usize = 128;
pub const REFS_MAX_ITEMS: usize = 64;
pub const CRITERIA_MAX_ITEMS: usize = 64;
pub const OPTIONS_MIN_ITEMS: usize = 2;
pub const OPTIONS_MAX_ITEMS: usize = 4;
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

/// A git branch name, restricted to a portable subset of what git allows.
fn check_branch(value: &str) -> Result<(), TokenError> {
    check_text(value, BRANCH_MAX_BYTES)?;
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte);
    if let Some(position) = value.bytes().position(|byte| !allowed(byte)) {
        return Err(TokenError::InvalidCharacter { position });
    }
    let malformed = value.starts_with(['-', '/', '.'])
        || value.ends_with(['/', '.'])
        || value.contains("..")
        || value.contains("//")
        || value
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("lock"));
    if malformed {
        return Err(TokenError::InvalidCharacter { position: 0 });
    }
    Ok(())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    Result,
    Status,
    Escalation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
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

/// A certified question. A missing proposed ruling is decodable because the
/// arbiter's answer to it is to send the escalation back down.
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
    Result(ResultPayload),
    Status(StatusPayload),
    Escalation(EscalationPayload),
}

impl Payload {
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::Result(_) => MessageType::Result,
            Self::Status(_) => MessageType::Status,
            Self::Escalation(_) => MessageType::Escalation,
        }
    }
}

/// `from` and `to` are session names; level and vendor are derived from them
/// rather than carried alongside, so they cannot disagree.
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
    TooFew {
        field: &'static str,
        count: usize,
        min: usize,
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
            Self::TooFew { field, count, min } => {
                write!(formatter, "{field} has {count} items; minimum is {min}")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

const fn check_count(field: &'static str, count: usize, max: usize) -> Result<(), EnvelopeError> {
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

fn check_escalation(payload: &EscalationPayload) -> Result<(), EnvelopeError> {
    let options = payload.options.len();
    if options < OPTIONS_MIN_ITEMS {
        return Err(EnvelopeError::TooFew {
            field: "options",
            count: options,
            min: OPTIONS_MIN_ITEMS,
        });
    }
    check_count("options", options, OPTIONS_MAX_ITEMS)?;
    check_count("evidence", payload.evidence.len(), REFS_MAX_ITEMS)?;
    check_count(
        "cases_consulted",
        payload.cases_consulted.len(),
        REFS_MAX_ITEMS,
    )
}

fn decode_payload(
    message_type: MessageType,
    value: serde_json::Value,
) -> Result<Payload, EnvelopeError> {
    let payload = match message_type {
        MessageType::Result => {
            let payload: ResultPayload =
                serde_json::from_value(value).map_err(EnvelopeError::Json)?;
            check_result(&payload)?;
            Payload::Result(payload)
        }
        MessageType::Status => {
            let payload: StatusPayload =
                serde_json::from_value(value).map_err(EnvelopeError::Json)?;
            check_count("blockers", payload.blockers.len(), REFS_MAX_ITEMS)?;
            Payload::Status(payload)
        }
        MessageType::Escalation => {
            let payload: EscalationPayload =
                serde_json::from_value(value).map_err(EnvelopeError::Json)?;
            check_escalation(&payload)?;
            Payload::Escalation(payload)
        }
    };
    Ok(payload)
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
        Ok(Self {
            payload: decode_payload(wire.message_type, wire.payload)?,
            id: wire.id,
            work_unit_id: wire.work_unit_id,
            from: wire.from,
            to: wire.to,
            causation_id: wire.causation_id,
            correlation_id: wire.correlation_id,
            created_at_unix_ms: wire.created_at_unix_ms,
            expires_at_unix_ms: wire.expires_at_unix_ms,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(fill: char) -> String {
        format!("sha256:{}", fill.to_string().repeat(64))
    }

    fn envelope(message_type: &str, payload: &str) -> String {
        format!(
            r#"{{"schema_version":1,"id":"01J9Z3K7Q8R2W5X6Y7Z8A9B0C1","type":"{message_type}","work_unit_id":"wu03","from":"cf7a.wu03.wrk.claude.a1f3","to":"cf7a.wu03.ctl.codex","causation_id":null,"correlation_id":"cf7a","created_at_unix_ms":1800000000000,"expires_at_unix_ms":null,"payload":{payload}}}"#
        )
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
        let status = r#"{"summary":"tests green","last_progress_unix_ms":1800000000000,"progress":{"head_sha":null,"tests_passing":12},"active_workers":2,"usage":{"input_tokens":0,"output_tokens":0},"blockers":[]}"#;
        let parsed = Envelope::parse(envelope("status", status).as_bytes()).unwrap();
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
        let few = envelope("escalation", &escalation_payload(1));
        assert!(matches!(
            Envelope::parse(few.as_bytes()),
            Err(EnvelopeError::TooFew { .. })
        ));
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
    fn references_and_branches_are_checked() {
        assert!(ContentRef::parse(&digest('e')).is_ok());
        assert!(ContentRef::parse("md5:abc").is_err());
        assert!(ContentRef::parse(&format!("sha256:{}", "E".repeat(64))).is_err());
        assert!(BranchName::parse("wu03/task-7").is_ok());
        for bad in ["-x", "a..b", "a b", "a/", "x.lock", "/a", "a//b", ""] {
            assert!(BranchName::parse(bad).is_err(), "{bad:?}");
        }
        assert!(ShortText::parse("line\nbreak").is_err());
    }
}

//! Handler inputs a launcher or its hooks send on the session's own key; each carries the
//! session secret from the launcher environment.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::envelope::{ShortText, StatusPayload};
use crate::launcher::AwaitableId;
use crate::service::TaskId;

/// Bounds the serialized handoff note, so a rolled-over session's brief stays small.
pub const HANDOFF_NOTE_MAX_BYTES: usize = 16_384;
pub const HANDOFF_ITEMS_MAX: usize = 32;
/// Above any vendor's context window; a larger report is a defect, not a measurement.
pub const CONTEXT_TOKENS_MAX: u64 = 10_000_000;

/// The exclusive heartbeat: the status payload plus the context size from per-turn usage.
///
/// `sequence` is the one in the call's idempotency key; the handler ignores any sequence at
/// or below the last one it recorded, since Restate does not hand the key to the handler.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatCall {
    pub secret: String,
    pub sequence: u64,
    pub status: StatusPayload,
    pub context_tokens: u64,
}

impl fmt::Debug for HeartbeatCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeartbeatCall")
            .field("secret", &"redacted")
            .field("sequence", &self.sequence)
            .field("status", &self.status)
            .field("context_tokens", &self.context_tokens)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionTaken {
    pub decision: ShortText,
    pub reason: ShortText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerInFlight {
    pub task: TaskId,
    pub awaitable_id: AwaitableId,
}

/// A control session's last act before rollover; structured, never a transcript summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffNote {
    pub objective: ShortText,
    pub decisions: Vec<DecisionTaken>,
    pub workers_in_flight: Vec<WorkerInFlight>,
    pub dead_ends: Vec<ShortText>,
    pub open_questions: Vec<ShortText>,
    pub next_action: ShortText,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffError {
    TooLarge(usize),
    TooMany { field: &'static str, count: usize },
    Encode(String),
}

impl fmt::Display for HandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(length) => write!(
                formatter,
                "handoff note is {length} bytes; maximum is {HANDOFF_NOTE_MAX_BYTES}"
            ),
            Self::TooMany { field, count } => write!(
                formatter,
                "{field} has {count} items; maximum is {HANDOFF_ITEMS_MAX}"
            ),
            Self::Encode(error) => write!(formatter, "handoff note: {error}"),
        }
    }
}

impl std::error::Error for HandoffError {}

impl HandoffNote {
    /// Checks every list bound and the serialized size; returns the size in bytes.
    pub fn validate(&self) -> Result<usize, HandoffError> {
        let counts = [
            ("decisions", self.decisions.len()),
            ("workers_in_flight", self.workers_in_flight.len()),
            ("dead_ends", self.dead_ends.len()),
            ("open_questions", self.open_questions.len()),
        ];
        for (field, count) in counts {
            if count > HANDOFF_ITEMS_MAX {
                return Err(HandoffError::TooMany { field, count });
            }
        }
        let length = serde_json::to_vec(self)
            .map_err(|error| HandoffError::Encode(error.to_string()))?
            .len();
        if length > HANDOFF_NOTE_MAX_BYTES {
            return Err(HandoffError::TooLarge(length));
        }
        Ok(length)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffCall {
    pub secret: String,
    pub note: HandoffNote,
}

impl fmt::Debug for HandoffCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandoffCall")
            .field("secret", &"redacted")
            .field("note", &self.note)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> ShortText {
        ShortText::parse(value).unwrap()
    }

    fn note(dead_ends: usize, filler: usize) -> HandoffNote {
        HandoffNote {
            objective: text("split the orders table"),
            decisions: vec![DecisionTaken {
                decision: text("dual write"),
                reason: text("reversible"),
            }],
            workers_in_flight: vec![WorkerInFlight {
                task: TaskId::parse("wu03-t07").unwrap(),
                awaitable_id: AwaitableId::parse("sign_1abc").unwrap(),
            }],
            dead_ends: vec![text(&"d".repeat(filler.max(1))); dead_ends],
            open_questions: Vec::new(),
            next_action: text("verify"),
        }
    }

    #[test]
    fn accepts_a_note_within_bounds() {
        let length = note(2, 10).validate().unwrap();
        assert!(length > 0 && length <= HANDOFF_NOTE_MAX_BYTES);
    }

    #[test]
    fn rejects_a_note_over_the_byte_cap() {
        assert!(matches!(
            note(HANDOFF_ITEMS_MAX, 512).validate(),
            Err(HandoffError::TooLarge(_))
        ));
    }

    #[test]
    fn rejects_a_list_over_the_item_cap() {
        assert_eq!(
            note(HANDOFF_ITEMS_MAX.saturating_add(1), 1).validate(),
            Err(HandoffError::TooMany {
                field: "dead_ends",
                count: HANDOFF_ITEMS_MAX.saturating_add(1)
            })
        );
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let call = HandoffCall {
            secret: "s".repeat(40),
            note: note(0, 1),
        };
        assert!(!format!("{call:?}").contains(&"s".repeat(40)));
    }

    #[test]
    fn rejects_unknown_fields() {
        let json = r#"{"secret":"x","note":{"objective":"o","decisions":[],"workers_in_flight":[],"dead_ends":[],"open_questions":[],"next_action":"n"},"extra":1}"#;
        let decoded: Result<HandoffCall, _> = serde_json::from_str(json);
        assert!(decoded.is_err());
    }
}

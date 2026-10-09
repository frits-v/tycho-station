//! The message a launcher rejects its awaitable with: an exit state on its own, or
//! `escalated`, a newline and the certified question as JSON.

use serde::{Deserialize, Serialize};

use crate::envelope::{check_escalation, EnvelopeError, EscalationPayload, ENVELOPE_MAX_BYTES};
use crate::exit::ExitState;

const ESCALATED_WITH_QUESTION: &str = "escalated\n";

/// What came with an `escalated` rejection; every other state carries `Absent`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "question", rename_all = "snake_case")]
pub enum Question {
    Certified {
        payload: EscalationPayload,
    },
    #[default]
    Absent,
    /// The tail after `escalated` did not decode or broke a bound; the reason never quotes it.
    Malformed {
        reason: String,
    },
}

/// The rejection message for a certified question, checked against the envelope's bounds.
pub fn encode_escalation(payload: &EscalationPayload) -> Result<String, EnvelopeError> {
    check_escalation(payload)?;
    let json = serde_json::to_string(payload).map_err(EnvelopeError::Json)?;
    if json.len() > ENVELOPE_MAX_BYTES {
        return Err(EnvelopeError::TooLarge(json.len()));
    }
    Ok(format!("{ESCALATED_WITH_QUESTION}{json}"))
}

/// Only `escalated\n` opens a question; any other message decodes as an exit state alone.
#[must_use]
pub fn decode_rejection(message: &str) -> (ExitState, Question) {
    let Some(tail) = message.strip_prefix(ESCALATED_WITH_QUESTION) else {
        return (ExitState::from_wire(message), Question::Absent);
    };
    (ExitState::Escalated, decode_question(tail))
}

fn decode_question(tail: &str) -> Question {
    if tail.len() > ENVELOPE_MAX_BYTES {
        return malformed(EnvelopeError::TooLarge(tail.len()).to_string());
    }
    let payload = match serde_json::from_str::<EscalationPayload>(tail) {
        Ok(payload) => payload,
        Err(error) => {
            return malformed(format!(
                "{:?} error at line {} column {}",
                error.classify(),
                error.line(),
                error.column()
            ))
        }
    };
    match check_escalation(&payload) {
        Ok(()) => Question::Certified { payload },
        Err(error) => malformed(error.to_string()),
    }
}

const fn malformed(reason: String) -> Question {
    Question::Malformed { reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{
        ContentRef, EscalationOption, QuestionType, Reversibility, ShortText, OPTIONS_MAX_ITEMS,
    };
    use crate::session::Level;

    fn payload() -> EscalationPayload {
        EscalationPayload {
            level_reached: Level::Worker,
            give_up_reason: ShortText::parse("the objective contradicts the policy").unwrap(),
            question: ContentRef::parse(&format!("sha256:{}", "a".repeat(64))).unwrap(),
            question_type: QuestionType::Authority,
            options: vec![EscalationOption {
                label: ShortText::parse("keep the ceiling").unwrap(),
                reversibility: Reversibility::TwoWay,
                blast_radius: ShortText::parse("one unit").unwrap(),
            }],
            proposed_ruling: None,
            evidence: Vec::new(),
            cases_consulted: Vec::new(),
            blocking: true,
        }
    }

    #[test]
    fn a_certified_question_round_trips() {
        let message = encode_escalation(&payload()).unwrap();
        assert_eq!(
            decode_rejection(&message),
            (
                ExitState::Escalated,
                Question::Certified { payload: payload() }
            )
        );
    }

    #[test]
    fn a_bare_state_carries_no_question() {
        assert_eq!(
            decode_rejection("escalated"),
            (ExitState::Escalated, Question::Absent)
        );
        assert_eq!(
            decode_rejection("failed"),
            (ExitState::Failed, Question::Absent)
        );
    }

    #[test]
    fn a_tail_after_another_state_is_unrecognised() {
        let (state, question) = decode_rejection("failed\n{}");
        assert!(matches!(state, ExitState::Unrecognised { .. }), "{state:?}");
        assert_eq!(question, Question::Absent);
    }

    #[test]
    fn a_question_that_does_not_decode_is_malformed_and_never_quoted() {
        let planted = format!("{{\"{}\":1}}", "x".repeat(4096));
        let (state, question) = decode_rejection(&format!("escalated\n{planted}"));
        assert_eq!(state, ExitState::Escalated);
        let Question::Malformed { reason } = question else {
            panic!("{question:?}");
        };
        assert!(!reason.contains("xxxx"), "{reason}");
        assert!(reason.len() < 64, "{reason}");
    }

    #[test]
    fn a_question_over_a_bound_is_malformed() {
        let mut wide = payload();
        wide.options = vec![wide.options[0].clone(); OPTIONS_MAX_ITEMS + 1];
        assert!(encode_escalation(&wide).is_err());
        let json = serde_json::to_string(&wide).unwrap();
        let (_, question) = decode_rejection(&format!("escalated\n{json}"));
        assert!(
            matches!(question, Question::Malformed { .. }),
            "{question:?}"
        );
        let huge = format!("escalated\n{}", " ".repeat(ENVELOPE_MAX_BYTES + 1));
        assert!(matches!(
            decode_rejection(&huge).1,
            Question::Malformed { .. }
        ));
    }
}

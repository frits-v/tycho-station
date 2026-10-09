//! Decoder states for the way a vendor session ended, and what the owning
//! workflow does with each.

use std::fmt;

/// Bound on the raw text an unrecognised state keeps for the inbox.
pub const EXIT_RAW_MAX_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(from = "String", into = "String")]
pub enum ExitState {
    /// The session produced a result claiming done.
    Completed,
    /// The session rejected its awaitable with a certified question.
    Escalated,
    /// A worker reached its context threshold; its task returns for re-planning.
    TooLarge,
    /// No progress marker change within T2.
    Stalled,
    /// A human stop or a parent cancellation.
    Cancelled,
    /// The process died by signal without a result.
    Killed,
    /// The unit's cost or wall-clock budget hard-stopped it.
    BudgetExceeded,
    /// The vendor refused for plan or rate limits.
    RateLimited,
    /// The session exited without a result or with a failure it reported.
    Failed,
    /// A state no one enumerated. `raw` holds the input when it is short visible
    /// ASCII; `length` is always the input's byte length.
    Unrecognised { raw: Option<String>, length: usize },
}

/// What the owning workflow does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Verify,
    Escalate,
    Replan,
    Requeue,
    Stop,
    /// Blocks in the inbox: the unrecognised cause row of the inbox table.
    Inbox,
}

impl ExitState {
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "completed" => Self::Completed,
            "escalated" => Self::Escalated,
            "too_large" => Self::TooLarge,
            "stalled" => Self::Stalled,
            "cancelled" => Self::Cancelled,
            "killed" => Self::Killed,
            "budget_exceeded" => Self::BudgetExceeded,
            "rate_limited" => Self::RateLimited,
            "failed" => Self::Failed,
            _ => Self::unrecognised(value),
        }
    }

    fn unrecognised(value: &str) -> Self {
        let keep = value.len() <= EXIT_RAW_MAX_BYTES && value.bytes().all(|b| b.is_ascii_graphic());
        Self::Unrecognised {
            raw: keep.then(|| value.to_string()),
            length: value.len(),
        }
    }

    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Escalated => "escalated",
            Self::TooLarge => "too_large",
            Self::Stalled => "stalled",
            Self::Cancelled => "cancelled",
            Self::Killed => "killed",
            Self::BudgetExceeded => "budget_exceeded",
            Self::RateLimited => "rate_limited",
            Self::Failed => "failed",
            Self::Unrecognised { .. } => "unrecognised",
        }
    }

    /// No wildcard arm: a new state does not compile until it has a disposition.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::Completed => Disposition::Verify,
            Self::Escalated => Disposition::Escalate,
            Self::TooLarge => Disposition::Replan,
            Self::Stalled | Self::Killed | Self::RateLimited | Self::Failed => Disposition::Requeue,
            Self::Cancelled | Self::BudgetExceeded => Disposition::Stop,
            Self::Unrecognised { .. } => Disposition::Inbox,
        }
    }
}

impl fmt::Display for ExitState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_wire())
    }
}

impl From<String> for ExitState {
    fn from(value: String) -> Self {
        Self::from_wire(&value)
    }
}

/// An unrecognised state keeps its raw text on the wire, so the inbox can show
/// what the vendor actually said after the state crosses the reject path.
impl From<ExitState> for String {
    fn from(value: ExitState) -> Self {
        match value {
            ExitState::Unrecognised { raw: Some(raw), .. } => raw,
            known => known.as_wire().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN: [ExitState; 9] = [
        ExitState::Completed,
        ExitState::Escalated,
        ExitState::TooLarge,
        ExitState::Stalled,
        ExitState::Cancelled,
        ExitState::Killed,
        ExitState::BudgetExceeded,
        ExitState::RateLimited,
        ExitState::Failed,
    ];

    #[test]
    fn known_states_round_trip() {
        for state in KNOWN {
            assert_eq!(ExitState::from_wire(state.as_wire()), state);
        }
        assert_eq!(ExitState::Completed.disposition(), Disposition::Verify);
        assert_eq!(ExitState::TooLarge.disposition(), Disposition::Replan);
        assert_eq!(ExitState::Cancelled.disposition(), Disposition::Stop);
    }

    #[test]
    fn unknown_input_is_unrecognised_and_never_usable() {
        let state = ExitState::from_wire("error_max_turns");
        assert_eq!(
            state,
            ExitState::Unrecognised {
                raw: Some("error_max_turns".to_string()),
                length: 15
            }
        );
        assert_eq!(state.disposition(), Disposition::Inbox);
        for raw in ["", "Completed", "completed ", "unrecognised"] {
            assert_eq!(
                ExitState::from_wire(raw).disposition(),
                Disposition::Inbox,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn unrecognised_drops_overlong_or_unprintable_raw() {
        let long = "x".repeat(EXIT_RAW_MAX_BYTES.saturating_add(1));
        assert_eq!(
            ExitState::from_wire(&long),
            ExitState::Unrecognised {
                raw: None,
                length: EXIT_RAW_MAX_BYTES.saturating_add(1)
            }
        );
        assert!(matches!(
            ExitState::from_wire("bad\u{1b}"),
            ExitState::Unrecognised { raw: None, .. }
        ));
    }

    #[test]
    fn unrecognised_raw_survives_serialization() {
        let state = ExitState::from_wire("error_max_turns");
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"error_max_turns\"");
        let back: ExitState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn deserializes_any_string() {
        let known: ExitState = serde_json::from_str("\"stalled\"").unwrap();
        assert_eq!(known, ExitState::Stalled);
        let unknown: ExitState = serde_json::from_str("\"exploded\"").unwrap();
        assert_eq!(unknown.disposition(), Disposition::Inbox);
    }
}

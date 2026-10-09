//! Decoder states for the way a vendor session ended, and what the owning
//! workflow does with each.

use std::fmt;

/// Bound on the raw text an unrecognised state keeps for the inbox.
pub const EXIT_RAW_MAX_BYTES: usize = 64;
/// Wire prefix of an unrecognised state: `unrecognised:<length>[:<raw>]`.
pub const UNRECOGNISED_PREFIX: &str = "unrecognised:";

/// Raw text of an unrecognised state, built only by `ExitState::from_wire` so it round-trips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitRaw(String);

impl ExitRaw {
    fn keep(value: &str) -> Option<Self> {
        let printable =
            value.len() <= EXIT_RAW_MAX_BYTES && value.bytes().all(|b| b.is_ascii_graphic());
        printable.then(|| Self(value.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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
    /// A state no one enumerated; `raw` is kept only when short visible ASCII.
    Unrecognised { raw: Option<ExitRaw>, length: usize },
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
            _ => Self::reserved_unrecognised(value).unwrap_or_else(|| Self::unrecognised(value)),
        }
    }

    /// Decodes `unrecognised:<length>[:<raw>]`; a malformed tail is `None`.
    fn reserved_unrecognised(value: &str) -> Option<Self> {
        let rest = value.strip_prefix(UNRECOGNISED_PREFIX)?;
        let (length, raw) = match rest.split_once(':') {
            Some((length, raw)) => (length, Some(raw)),
            None => (rest, None),
        };
        if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let length: usize = length.parse().ok()?;
        let raw = match raw {
            Some(raw) => Some(ExitRaw::keep(raw)?),
            None => None,
        };
        Some(Self::Unrecognised { raw, length })
    }

    fn unrecognised(value: &str) -> Self {
        Self::Unrecognised {
            raw: ExitRaw::keep(value),
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

/// The reserved prefix keeps an unrecognised raw text from decoding as a known state.
impl From<ExitState> for String {
    fn from(value: ExitState) -> Self {
        match value {
            ExitState::Unrecognised {
                raw: Some(raw),
                length,
            } => format!("{UNRECOGNISED_PREFIX}{length}:{}", raw.as_str()),
            ExitState::Unrecognised { raw: None, length } => {
                format!("{UNRECOGNISED_PREFIX}{length}")
            }
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
        let ExitState::Unrecognised { raw, length } = &state else {
            panic!("expected an unrecognised state");
        };
        assert_eq!(raw.as_ref().map(ExitRaw::as_str), Some("error_max_turns"));
        assert_eq!(*length, 15);
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

    fn round_trip(state: &ExitState) -> ExitState {
        let json = serde_json::to_string(state).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn unrecognised_survives_serialization() {
        let state = ExitState::from_wire("error_max_turns");
        assert_eq!(
            serde_json::to_string(&state).unwrap(),
            "\"unrecognised:15:error_max_turns\""
        );
        assert_eq!(round_trip(&state), state);
        let dropped = ExitState::from_wire(&"x".repeat(EXIT_RAW_MAX_BYTES.saturating_add(1)));
        assert_eq!(round_trip(&dropped), dropped);
    }

    #[test]
    fn unrecognised_known_name_stays_unrecognised() {
        let forged = ExitState::from_wire("unrecognised:9:completed");
        assert!(matches!(
            &forged,
            ExitState::Unrecognised { raw: Some(raw), length: 9 } if raw.as_str() == "completed"
        ));
        let back = round_trip(&forged);
        assert_eq!(back, forged);
        assert_eq!(back.disposition(), Disposition::Inbox);
    }

    #[test]
    fn unrecognised_with_whitespace_or_control_characters_round_trips() {
        let long = "x".repeat(EXIT_RAW_MAX_BYTES.saturating_add(1));
        for raw in [
            "a b",
            "tab\there",
            "bad\u{1b}[31m",
            "line\nbreak",
            "unrecognised:3:a b",
            "unrecognised:4:a\u{7}bc",
            long.as_str(),
        ] {
            let state = ExitState::from_wire(raw);
            assert_eq!(
                state,
                ExitState::Unrecognised {
                    raw: None,
                    length: raw.len()
                },
                "{raw:?}"
            );
            assert_eq!(round_trip(&state), state, "{raw:?}");
        }
    }

    #[test]
    fn malformed_reserved_form_is_still_unrecognised() {
        for raw in [
            "unrecognised:",
            "unrecognised:x:completed",
            "unrecognised:3:a b",
        ] {
            let state = ExitState::from_wire(raw);
            assert_eq!(state.disposition(), Disposition::Inbox, "{raw:?}");
        }
    }

    #[test]
    fn deserializes_any_string() {
        let known: ExitState = serde_json::from_str("\"stalled\"").unwrap();
        assert_eq!(known, ExitState::Stalled);
        let unknown: ExitState = serde_json::from_str("\"exploded\"").unwrap();
        assert_eq!(unknown.disposition(), Disposition::Inbox);
    }
}

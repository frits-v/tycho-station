//! The synthetic epic's five work units, loaded from a pinned JSON fixture
//! and checked through `tycho_types`. CUE is issue 37's job; JSON is the
//! stand-in until then.

use std::fmt;

use serde::Deserialize;
use tycho_types::envelope::{CRITERIA_MAX_ITEMS, REFS_MAX_ITEMS};
use tycho_types::task_packet::{
    TaskPacketPayload, BUDGET_TOKENS_MAX_COUNT, BUDGET_WALL_CLOCK_MAX_MS, PATHS_MAX_ITEMS,
};
use tycho_types::token::{check_slug, TokenError};

/// A fixture larger than this is rejected before it is parsed.
pub const FIXTURE_MAX_BYTES: usize = 65_536;
/// A thin slice-zero fixture stays well under this.
pub const WORK_UNITS_MAX_ITEMS: usize = 8;
const KEY_MAX_BYTES: usize = 32;

pub const WORK_UNITS_JSON: &[u8] = include_bytes!("../fixtures/work_units.json");

/// Whether a unit's done criteria decide it, or only a certified escalation does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PassCondition {
    CriteriaPass,
    EscalationRaised,
}

/// `forced-escalation` and `forced-council-split` carry an empty `packet.done_criteria`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkUnit {
    pub key: String,
    pub pass_condition: PassCondition,
    pub packet: TaskPacketPayload,
}

#[derive(Debug)]
pub enum FixtureError {
    TooLarge { bytes: usize },
    Json(serde_json::Error),
    Empty,
    TooMany { count: usize },
    Key { key: String, error: TokenError },
    Bounds { key: String, field: &'static str },
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes } => {
                write!(formatter, "{bytes} bytes; maximum is {FIXTURE_MAX_BYTES}")
            }
            Self::Json(error) => write!(formatter, "{error}"),
            Self::Empty => write!(formatter, "no work units"),
            Self::TooMany { count } => {
                write!(
                    formatter,
                    "{count} work units; maximum is {WORK_UNITS_MAX_ITEMS}"
                )
            }
            Self::Key { key, error } => write!(formatter, "key {key:?}: {error}"),
            Self::Bounds { key, field } => write!(formatter, "{key}: {field} is out of bounds"),
        }
    }
}

impl std::error::Error for FixtureError {}

/// Reapplies `check_task_packet`'s bound checks; that function is `pub(crate)` in `tycho_types`.
fn check_bounds(key: &str, packet: &TaskPacketPayload) -> Result<(), FixtureError> {
    let bounds = [
        (
            "done_criteria",
            packet.done_criteria.len(),
            CRITERIA_MAX_ITEMS,
        ),
        (
            "boundaries.writable_paths",
            packet.boundaries.writable_paths.len(),
            PATHS_MAX_ITEMS,
        ),
        (
            "boundaries.forbidden_actions",
            packet.boundaries.forbidden_actions.len(),
            REFS_MAX_ITEMS,
        ),
        ("inputs", packet.inputs.len(), REFS_MAX_ITEMS),
    ];
    for (field, count, max) in bounds {
        if count > max {
            return Err(FixtureError::Bounds {
                key: key.to_string(),
                field,
            });
        }
    }
    if packet.budget.tokens_max == 0 || packet.budget.tokens_max > BUDGET_TOKENS_MAX_COUNT {
        return Err(FixtureError::Bounds {
            key: key.to_string(),
            field: "budget.tokens_max",
        });
    }
    if packet.budget.wall_clock_max_ms == 0
        || packet.budget.wall_clock_max_ms > BUDGET_WALL_CLOCK_MAX_MS
    {
        return Err(FixtureError::Bounds {
            key: key.to_string(),
            field: "budget.wall_clock_max_ms",
        });
    }
    Ok(())
}

/// Parses and bound-checks the fixture; zero units or too many is a failure, not a quiet pass.
pub fn load_work_units(bytes: &[u8]) -> Result<Vec<WorkUnit>, FixtureError> {
    if bytes.len() > FIXTURE_MAX_BYTES {
        return Err(FixtureError::TooLarge { bytes: bytes.len() });
    }
    let units: Vec<WorkUnit> = serde_json::from_slice(bytes).map_err(FixtureError::Json)?;
    if units.is_empty() {
        return Err(FixtureError::Empty);
    }
    if units.len() > WORK_UNITS_MAX_ITEMS {
        return Err(FixtureError::TooMany { count: units.len() });
    }
    for unit in &units {
        check_slug(&unit.key, KEY_MAX_BYTES).map_err(|error| FixtureError::Key {
            key: unit.key.clone(),
            error,
        })?;
        check_bounds(&unit.key, &unit.packet)?;
    }
    Ok(units)
}

/// Loads the fixture pinned to this repository.
pub fn load_default() -> Result<Vec<WorkUnit>, FixtureError> {
    load_work_units(WORK_UNITS_JSON)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_KEYS: [&str; 5] = [
        "trivial",
        "moderate-and-ambiguous",
        "forced-escalation",
        "forced-council-split",
        "downstream-dependent",
    ];

    #[test]
    fn the_pinned_fixture_has_exactly_the_five_work_units() {
        let units = load_default().unwrap();
        let keys: Vec<&str> = units.iter().map(|unit| unit.key.as_str()).collect();
        assert_eq!(keys, EXPECTED_KEYS);
    }

    #[test]
    fn forced_units_carry_an_escalation_pass_condition_not_merge() {
        let units = load_default().unwrap();
        for unit in &units {
            let forced = unit.key == "forced-escalation" || unit.key == "forced-council-split";
            let expected = if forced {
                PassCondition::EscalationRaised
            } else {
                PassCondition::CriteriaPass
            };
            assert_eq!(unit.pass_condition, expected, "{}", unit.key);
        }
    }

    #[test]
    fn an_oversized_fixture_is_rejected_before_parsing() {
        let big = vec![b' '; FIXTURE_MAX_BYTES.saturating_add(1)];
        assert!(matches!(
            load_work_units(&big),
            Err(FixtureError::TooLarge { .. })
        ));
    }

    #[test]
    fn an_empty_fixture_is_a_failure_not_a_quiet_pass() {
        assert!(matches!(load_work_units(b"[]"), Err(FixtureError::Empty)));
    }

    #[test]
    fn malformed_json_decodes_to_an_error_not_a_panic() {
        assert!(matches!(
            load_work_units(b"not json"),
            Err(FixtureError::Json(_))
        ));
    }
}

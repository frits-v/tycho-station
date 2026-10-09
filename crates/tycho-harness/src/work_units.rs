//! The synthetic epic's five work units, loaded from a pinned JSON fixture
//! and checked through `tycho_types`. JSON until the CUE schemas exist.

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
    use serde_json::json;

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

    fn hex_ref(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn minimal_unit() -> serde_json::Value {
        json!({
            "key": "bound-test",
            "pass_condition": "criteria_pass",
            "packet": {
                "objective": hex_ref('a'),
                "done_criteria": [],
                "boundaries": {
                    "worktree": "/tmp/bound-test",
                    "branch": "bound-test",
                    "writable_paths": [],
                    "forbidden_actions": []
                },
                "inputs": [],
                "routing": {
                    "class": "test",
                    "tier": "worker",
                    "effort": "low",
                    "binding": null,
                    "rationale": "bound test fixture",
                    "fallback_tier": null
                },
                "budget": { "tokens_max": 1000, "wall_clock_max_ms": 1000 },
                "result_schema": hex_ref('b')
            }
        })
    }

    fn load_one(unit: &serde_json::Value) -> Result<Vec<WorkUnit>, FixtureError> {
        let bytes = serde_json::to_vec(&json!([unit.clone()])).unwrap();
        load_work_units(&bytes)
    }

    fn bounds_error_field(unit: &serde_json::Value) -> &'static str {
        match load_one(unit) {
            Err(FixtureError::Bounds { field, .. }) => field,
            other => panic!("expected a bounds error, got {other:?}"),
        }
    }

    #[test]
    fn too_many_done_criteria_is_a_bounds_error() {
        let mut unit = minimal_unit();
        let over = vec![json!({"kind": "file_present", "path": "a"}); CRITERIA_MAX_ITEMS + 1];
        unit["packet"]["done_criteria"] = json!(over);
        assert_eq!(bounds_error_field(&unit), "done_criteria");
    }

    #[test]
    fn too_many_writable_paths_is_a_bounds_error() {
        let mut unit = minimal_unit();
        let over = vec!["a"; PATHS_MAX_ITEMS + 1];
        unit["packet"]["boundaries"]["writable_paths"] = json!(over);
        assert_eq!(bounds_error_field(&unit), "boundaries.writable_paths");
    }

    #[test]
    fn too_many_forbidden_actions_is_a_bounds_error() {
        let mut unit = minimal_unit();
        let over = vec!["x"; REFS_MAX_ITEMS + 1];
        unit["packet"]["boundaries"]["forbidden_actions"] = json!(over);
        assert_eq!(bounds_error_field(&unit), "boundaries.forbidden_actions");
    }

    #[test]
    fn too_many_inputs_is_a_bounds_error() {
        let mut unit = minimal_unit();
        let over = vec![hex_ref('c'); REFS_MAX_ITEMS + 1];
        unit["packet"]["inputs"] = json!(over);
        assert_eq!(bounds_error_field(&unit), "inputs");
    }

    #[test]
    fn a_zero_token_budget_is_a_bounds_error() {
        let mut unit = minimal_unit();
        unit["packet"]["budget"]["tokens_max"] = json!(0);
        assert_eq!(bounds_error_field(&unit), "budget.tokens_max");
    }

    #[test]
    fn a_token_budget_over_its_maximum_is_a_bounds_error() {
        let mut unit = minimal_unit();
        unit["packet"]["budget"]["tokens_max"] = json!(BUDGET_TOKENS_MAX_COUNT + 1);
        assert_eq!(bounds_error_field(&unit), "budget.tokens_max");
    }

    #[test]
    fn a_zero_wall_clock_budget_is_a_bounds_error() {
        let mut unit = minimal_unit();
        unit["packet"]["budget"]["wall_clock_max_ms"] = json!(0);
        assert_eq!(bounds_error_field(&unit), "budget.wall_clock_max_ms");
    }

    #[test]
    fn a_wall_clock_budget_over_its_maximum_is_a_bounds_error() {
        let mut unit = minimal_unit();
        unit["packet"]["budget"]["wall_clock_max_ms"] = json!(BUDGET_WALL_CLOCK_MAX_MS + 1);
        assert_eq!(bounds_error_field(&unit), "budget.wall_clock_max_ms");
    }

    #[test]
    fn too_many_work_units_is_rejected() {
        let units: Vec<serde_json::Value> =
            (0..=WORK_UNITS_MAX_ITEMS).map(|_| minimal_unit()).collect();
        let bytes = serde_json::to_vec(&json!(units)).unwrap();
        assert!(matches!(
            load_work_units(&bytes),
            Err(FixtureError::TooMany { .. })
        ));
    }

    #[test]
    fn a_key_over_its_maximum_length_is_rejected() {
        let mut unit = minimal_unit();
        unit["key"] = json!("a".repeat(KEY_MAX_BYTES + 1));
        assert!(matches!(load_one(&unit), Err(FixtureError::Key { .. })));
    }

    #[test]
    fn objective_and_input_refs_match_their_embedded_content() {
        let units = load_default().unwrap();
        let objectives: &[(&str, &[u8])] = &[
            ("trivial", crate::content::OBJECTIVE_TRIVIAL),
            ("moderate-and-ambiguous", crate::content::OBJECTIVE_MODERATE),
            (
                "forced-escalation",
                crate::content::OBJECTIVE_FORCED_ESCALATION,
            ),
            (
                "forced-council-split",
                crate::content::OBJECTIVE_FORCED_COUNCIL,
            ),
            ("downstream-dependent", crate::content::OBJECTIVE_DOWNSTREAM),
        ];
        for (key, bytes) in objectives {
            let unit = units.iter().find(|unit| unit.key == *key).unwrap();
            let expected = crate::content::content_ref(bytes).unwrap();
            assert_eq!(unit.packet.objective.as_str(), expected.as_str(), "{key}");
        }

        let expected_schema = crate::content::content_ref(crate::content::RESULT_SCHEMA).unwrap();
        for unit in &units {
            assert_eq!(
                unit.packet.result_schema.as_str(),
                expected_schema.as_str(),
                "{}",
                unit.key
            );
        }

        let forced_escalation = units
            .iter()
            .find(|unit| unit.key == "forced-escalation")
            .unwrap();
        let expected_policy =
            crate::content::content_ref(crate::content::POLICY_BUDGET_CEILING).unwrap();
        assert_eq!(
            forced_escalation
                .packet
                .inputs
                .first()
                .map(tycho_types::envelope::ContentRef::as_str),
            Some(expected_policy.as_str())
        );

        let downstream = units
            .iter()
            .find(|unit| unit.key == "downstream-dependent")
            .unwrap();
        let expected_trivial_objective =
            crate::content::content_ref(crate::content::OBJECTIVE_TRIVIAL).unwrap();
        assert_eq!(
            downstream
                .packet
                .inputs
                .first()
                .map(tycho_types::envelope::ContentRef::as_str),
            Some(expected_trivial_objective.as_str())
        );
    }
}

//! The `task_packet` payload a parent sends down to a control session or worker.

use serde::{Deserialize, Serialize};

use crate::envelope::{
    check_count, BranchName, ContentRef, EnvelopeError, ShortText, CRITERIA_MAX_ITEMS,
    REFS_MAX_ITEMS,
};
use crate::session::Vendor;
use crate::token::{check_slug, check_text, checked_string, TokenError};

pub const PATH_MAX_BYTES: usize = 1024;
pub const PATHS_MAX_ITEMS: usize = 64;
pub const ROUTING_NAME_MAX_BYTES: usize = 32;

fn check_components(value: &str) -> Result<(), TokenError> {
    let bad = value
        .split('/')
        .skip(1)
        .any(|component| component.is_empty() || component == "." || component == "..");
    if bad {
        return Err(TokenError::InvalidCharacter { position: 0 });
    }
    Ok(())
}

fn check_absolute_path(value: &str) -> Result<(), TokenError> {
    check_text(value, PATH_MAX_BYTES)?;
    if !value.starts_with('/') {
        return Err(TokenError::InvalidCharacter { position: 0 });
    }
    check_components(value)
}

fn check_relative_path(value: &str) -> Result<(), TokenError> {
    check_text(value, PATH_MAX_BYTES)?;
    if value.starts_with('/') {
        return Err(TokenError::InvalidCharacter { position: 0 });
    }
    check_components(&format!("/{value}"))
}

fn check_routing_name(value: &str) -> Result<(), TokenError> {
    check_slug(value, ROUTING_NAME_MAX_BYTES)
}

checked_string!(
    /// An absolute path with no empty, `.` or `..` component.
    AbsolutePath,
    check_absolute_path
);
checked_string!(
    /// A path inside the worktree with no empty, `.` or `..` component.
    RelativePath,
    check_relative_path
);
checked_string!(
    /// A task class or tier name from the routing tables.
    RoutingName,
    check_routing_name
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DoneCriterion {
    Command {
        command: ShortText,
        expected_exit: u8,
    },
    FilePresent {
        path: RelativePath,
    },
    FileAbsent {
        path: RelativePath,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Boundaries {
    pub worktree: AbsolutePath,
    pub branch: BranchName,
    pub writable_paths: Vec<RelativePath>,
    pub forbidden_actions: Vec<ShortText>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effort {
    Minimal,
    Low,
    Medium,
    High,
    Max,
}

/// The rationale is required: the launcher rejects a packet without one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routing {
    pub class: RoutingName,
    pub tier: RoutingName,
    pub effort: Effort,
    /// A vendor the task is bound to; `None` lets the tier table choose.
    pub binding: Option<Vendor>,
    pub rationale: ShortText,
    pub fallback_tier: Option<RoutingName>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub tokens_max: u64,
    pub wall_clock_max_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskPacketPayload {
    pub objective: ContentRef,
    pub done_criteria: Vec<DoneCriterion>,
    pub boundaries: Boundaries,
    pub inputs: Vec<ContentRef>,
    pub routing: Routing,
    pub budget: Budget,
    pub result_schema: ContentRef,
}

pub(crate) fn check_task_packet(packet: &TaskPacketPayload) -> Result<(), EnvelopeError> {
    check_count(
        "done_criteria",
        packet.done_criteria.len(),
        CRITERIA_MAX_ITEMS,
    )?;
    check_count(
        "writable_paths",
        packet.boundaries.writable_paths.len(),
        PATHS_MAX_ITEMS,
    )?;
    check_count(
        "forbidden_actions",
        packet.boundaries.forbidden_actions.len(),
        REFS_MAX_ITEMS,
    )?;
    check_count("inputs", packet.inputs.len(), REFS_MAX_ITEMS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_accept_plain_forms() {
        assert!(AbsolutePath::parse("/Users/agent/worktrees/cf7a-wu03").is_ok());
        assert!(RelativePath::parse("crates/tycho-types/src").is_ok());
        assert!(RelativePath::parse("Cargo.toml").is_ok());
    }

    #[test]
    fn paths_reject_escapes_and_bad_shapes() {
        for bad in ["relative", "/a/../b", "/a//b", "/a/./b", ""] {
            assert!(AbsolutePath::parse(bad).is_err(), "{bad:?}");
        }
        for bad in ["/abs", "../up", "a/../b", "a//b", "./a", "a/"] {
            assert!(RelativePath::parse(bad).is_err(), "{bad:?}");
        }
        let long = format!("/{}", "a".repeat(PATH_MAX_BYTES));
        assert!(AbsolutePath::parse(&long).is_err());
        assert!(RoutingName::parse(&"t".repeat(ROUTING_NAME_MAX_BYTES.saturating_add(1))).is_err());
    }

    #[test]
    fn criteria_decode_by_kind() {
        let command: DoneCriterion =
            serde_json::from_str(r#"{"kind":"command","command":"cargo test","expected_exit":0}"#)
                .unwrap();
        assert!(matches!(
            command,
            DoneCriterion::Command {
                expected_exit: 0,
                ..
            }
        ));
        let unknown: Result<DoneCriterion, _> =
            serde_json::from_str(r#"{"kind":"file_present","path":"a","extra":1}"#);
        assert!(unknown.is_err());
        let exit: Result<DoneCriterion, _> =
            serde_json::from_str(r#"{"kind":"command","command":"x","expected_exit":256}"#);
        assert!(exit.is_err());
    }
}

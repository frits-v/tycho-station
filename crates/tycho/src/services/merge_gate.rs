//! The port the verify step calls: fetch the claimed branch into the canonical repository,
//! run the pinned done criteria on a fresh checkout, and fast-forward the default branch.

use std::fmt;

use tycho_types::envelope::{BranchName, CommitSha, ShortText};
use tycho_types::service::{Attempt, TaskId, WorkUnitId};

pub const FINDINGS_MAX_ITEMS: usize = 32;

/// One task's claim of done: the branch and head SHA in its worktree.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Claim {
    pub task: TaskId,
    pub branch: BranchName,
    pub head_sha: CommitSha,
}

/// Every claim of the attempt goes to the gate, in plan order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyRequest {
    pub work_unit: WorkUnitId,
    pub attempt: Attempt,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum GateVerdict {
    /// The default branch now points at this commit.
    Merged { default_sha: CommitSha },
    /// Criteria failed; the findings go back to the unit with the attempt incremented.
    Failed { findings: Vec<ShortText> },
}

impl GateVerdict {
    /// Refuses a verdict whose findings exceed `FINDINGS_MAX_ITEMS`.
    pub fn validate(&self) -> Result<(), GateError> {
        match self {
            Self::Failed { findings } if findings.len() > FINDINGS_MAX_ITEMS => {
                Err(GateError::Refused(format!(
                    "{} findings; maximum is {FINDINGS_MAX_ITEMS}",
                    findings.len()
                )))
            }
            Self::Merged { .. } | Self::Failed { .. } => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    Transient(String),
    Refused(String),
}

impl fmt::Display for GateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient(reason) => write!(formatter, "merge gate (transient): {reason}"),
            Self::Refused(reason) => write!(formatter, "merge gate refused: {reason}"),
        }
    }
}

impl std::error::Error for GateError {}

/// Blocking; the verify step runs it off the async runtime inside a journaled step.
pub trait MergeGate: Send + Sync + 'static {
    fn describe(&self) -> String;
    fn verify(&self, request: &VerifyRequest) -> Result<GateVerdict, GateError>;
}

/// The production stand-in until the gate is installed: every verify is refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoGate;

impl MergeGate for NoGate {
    fn describe(&self) -> String {
        "no merge gate".to_string()
    }

    fn verify(&self, _request: &VerifyRequest) -> Result<GateVerdict, GateError> {
        Err(GateError::Refused(
            "no merge gate is installed in this endpoint".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(count: usize) -> GateVerdict {
        GateVerdict::Failed {
            findings: vec![ShortText::parse("criterion 2 failed").unwrap(); count],
        }
    }

    #[test]
    fn accepts_findings_up_to_the_maximum() {
        assert_eq!(failed(FINDINGS_MAX_ITEMS).validate(), Ok(()));
        let merged = GateVerdict::Merged {
            default_sha: CommitSha::parse(&"a".repeat(40)).unwrap(),
        };
        assert_eq!(merged.validate(), Ok(()));
    }

    #[test]
    fn rejects_findings_over_the_maximum() {
        assert!(matches!(
            failed(FINDINGS_MAX_ITEMS.saturating_add(1)).validate(),
            Err(GateError::Refused(_))
        ));
    }
}

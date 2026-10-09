//! The port the verify step calls: fetch the claimed branch into the canonical repository,
//! run the pinned done criteria on a fresh checkout, and fast-forward the default branch.

use std::fmt;

use tycho_types::envelope::{BranchName, CommitSha, ShortText};
use tycho_types::service::{Attempt, WorkUnitId};

pub const FINDINGS_MAX_ITEMS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyRequest {
    pub work_unit: WorkUnitId,
    pub attempt: Attempt,
    pub branch: BranchName,
    pub head_sha: CommitSha,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum GateVerdict {
    /// The default branch now points at this commit.
    Merged { default_sha: CommitSha },
    /// Criteria failed; the findings go back to the unit with the attempt incremented.
    Failed { findings: Vec<ShortText> },
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

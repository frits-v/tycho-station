//! Restate service names, their kinds and keys, and promise names.

use std::fmt;

use crate::token::{TokenError, check_slug, checked_string};

/// Epic and work unit ids are session name segments, so the socket path limit bounds them.
pub const ID_MAX_BYTES: usize = 16;
pub const TASK_ID_MAX_BYTES: usize = 64;
pub const ATTEMPT_MAX: u16 = 99;
pub const PROMISE_NAME_MAX_BYTES: usize = 24;
/// The Reconciler is a virtual object with a single instance.
pub const RECONCILER_KEY: &str = "reconciler";
/// The word that marks a root session in a session name; never a work unit id.
pub const ROOT_SEGMENT: &str = "root";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    VirtualObject,
    Workflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    Epic,
    WorkUnit,
    Session,
    Reconciler,
    WorkerRun,
}

impl Service {
    pub const ALL: [Self; 5] = [
        Self::Epic,
        Self::WorkUnit,
        Self::Session,
        Self::Reconciler,
        Self::WorkerRun,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Epic => "Epic",
            Self::WorkUnit => "WorkUnit",
            Self::Session => "Session",
            Self::Reconciler => "Reconciler",
            Self::WorkerRun => "WorkerRun",
        }
    }

    #[must_use]
    pub const fn kind(self) -> ServiceKind {
        match self {
            Self::Epic | Self::Session | Self::Reconciler => ServiceKind::VirtualObject,
            Self::WorkUnit | Self::WorkerRun => ServiceKind::Workflow,
        }
    }
}

/// Handler names, grouped by service, for ingress calls and service-to-service calls.
pub mod handler {
    pub const EPIC_START: &str = "start";
    pub const EPIC_ADD_UNIT: &str = "add_unit";
    pub const EPIC_RESERVE: &str = "reserve";
    pub const EPIC_SETTLE: &str = "settle";
    pub const EPIC_STATUS: &str = "status";
    pub const WORK_UNIT_RUN: &str = "run";
    pub const WORK_UNIT_RESULT: &str = "result";
    pub const WORK_UNIT_ESCALATE: &str = "escalate";
    pub const WORK_UNIT_STATUS: &str = "status";
    pub const SESSION_SPAWN: &str = "spawn";
    pub const SESSION_HEARTBEAT: &str = "heartbeat";
    pub const SESSION_NUDGE: &str = "nudge";
    pub const SESSION_HANDOFF: &str = "handoff";
    pub const SESSION_KILL: &str = "kill";
    pub const SESSION_EXPIRE: &str = "expire";
    pub const SESSION_REAP: &str = "reap";
    pub const SESSION_STATUS: &str = "status";
    pub const RECONCILER_START: &str = "start";
    pub const RECONCILER_EXPECT: &str = "expect";
    pub const RECONCILER_FORGET: &str = "forget";
    pub const RECONCILER_TICK: &str = "tick";
    pub const RECONCILER_STATUS: &str = "status";
    pub const OPERATOR_START_EPIC: &str = "start_epic";
    pub const OPERATOR_ADD_UNIT: &str = "add_unit";
    pub const OPERATOR_DISPATCH_UNIT: &str = "dispatch_unit";
    pub const OPERATOR_RULE_UNIT: &str = "rule_unit";
    pub const WORK_UNIT_RULE: &str = "rule";
    pub const WORKER_RUN_RUN: &str = "run";
}

fn check_epic_id(value: &str) -> Result<(), TokenError> {
    check_slug(value, ID_MAX_BYTES)
}

fn check_work_unit_id(value: &str) -> Result<(), TokenError> {
    check_slug(value, ID_MAX_BYTES)?;
    if value == ROOT_SEGMENT {
        return Err(TokenError::Reserved);
    }
    Ok(())
}

fn check_task_id(value: &str) -> Result<(), TokenError> {
    check_slug(value, TASK_ID_MAX_BYTES)
}

checked_string!(
    /// Key of the `Epic` virtual object.
    EpicId,
    check_epic_id
);
checked_string!(
    /// Key of the `WorkUnit` workflow.
    WorkUnitId,
    check_work_unit_id
);
checked_string!(
    /// Key of the `WorkerRun` workflow.
    TaskId,
    check_task_id
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Attempt(u16);

impl Attempt {
    pub const FIRST: Self = Self(1);

    pub const fn new(value: u16) -> Result<Self, AttemptError> {
        if value == 0 || value > ATTEMPT_MAX {
            return Err(AttemptError(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    pub const fn next(self) -> Result<Self, AttemptError> {
        match self.0.checked_add(1) {
            Some(value) => Self::new(value),
            None => Err(AttemptError(u16::MAX)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptError(pub u16);

impl fmt::Display for AttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "attempt {} outside 1..={ATTEMPT_MAX}", self.0)
    }
}

impl std::error::Error for AttemptError {}

/// What a `WorkUnit` promise waits for; a name pairs it with an attempt because a key runs once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Plan,
    Result,
    Escalation,
    Ruling,
}

impl Phase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Result => "result",
            Self::Escalation => "escalation",
            Self::Ruling => "ruling",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "plan" => Some(Self::Plan),
            "result" => Some(Self::Result),
            "escalation" => Some(Self::Escalation),
            "ruling" => Some(Self::Ruling),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromiseName {
    pub phase: Phase,
    pub attempt: Attempt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromiseNameError {
    TooLong(usize),
    MissingSeparator,
    UnknownPhase,
    Attempt,
}

impl fmt::Display for PromiseNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong(length) => write!(
                formatter,
                "promise name is {length} bytes; maximum is {PROMISE_NAME_MAX_BYTES}"
            ),
            Self::MissingSeparator => write!(formatter, "expected `<phase>.<attempt>`"),
            Self::UnknownPhase => write!(formatter, "unknown phase"),
            Self::Attempt => write!(formatter, "attempt is not a number in 1..={ATTEMPT_MAX}"),
        }
    }
}

impl std::error::Error for PromiseNameError {}

impl PromiseName {
    #[must_use]
    pub const fn new(phase: Phase, attempt: Attempt) -> Self {
        Self { phase, attempt }
    }

    pub fn parse(value: &str) -> Result<Self, PromiseNameError> {
        if value.len() > PROMISE_NAME_MAX_BYTES {
            return Err(PromiseNameError::TooLong(value.len()));
        }
        let (phase, attempt) = value
            .split_once('.')
            .ok_or(PromiseNameError::MissingSeparator)?;
        let phase = Phase::parse(phase).ok_or(PromiseNameError::UnknownPhase)?;
        let digits_only = !attempt.is_empty() && attempt.bytes().all(|b| b.is_ascii_digit());
        if !digits_only {
            return Err(PromiseNameError::Attempt);
        }
        let number: u16 = attempt.parse().map_err(|_| PromiseNameError::Attempt)?;
        let attempt = Attempt::new(number).map_err(|_| PromiseNameError::Attempt)?;
        Ok(Self { phase, attempt })
    }
}

impl fmt::Display for PromiseName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.phase.as_str(), self.attempt.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_map_names_and_kinds() {
        let names: Vec<&str> = Service::ALL.iter().map(|s| s.name()).collect();
        assert_eq!(
            names,
            ["Epic", "WorkUnit", "Session", "Reconciler", "WorkerRun"]
        );
        assert_eq!(Service::WorkUnit.kind(), ServiceKind::Workflow);
        assert_eq!(Service::WorkerRun.kind(), ServiceKind::Workflow);
        assert_eq!(Service::Session.kind(), ServiceKind::VirtualObject);
    }

    #[test]
    fn keys_accept_design_examples() {
        assert_eq!(
            EpicId::parse("cf7a").map(|id| id.to_string()),
            Ok("cf7a".into())
        );
        assert!(WorkUnitId::parse("wu-orders-split").is_ok());
        assert!(TaskId::parse("wu03-t07").is_ok());
    }

    #[test]
    fn keys_reject_bad_input() {
        assert_eq!(WorkUnitId::parse("root"), Err(TokenError::Reserved));
        assert!(EpicId::parse("cf7a.wu03").is_err());
        assert!(EpicId::parse(&"a".repeat(ID_MAX_BYTES.saturating_add(1))).is_err());
        assert!(TaskId::parse(&"t".repeat(TASK_ID_MAX_BYTES.saturating_add(1))).is_err());
    }

    #[test]
    fn keys_deserialize_through_the_check() {
        let parsed: Result<EpicId, _> = serde_json::from_str("\"cf7a\"");
        assert!(parsed.is_ok());
        let rejected: Result<EpicId, _> = serde_json::from_str("\"CF7A\"");
        assert!(rejected.is_err());
    }

    #[test]
    fn attempt_is_bounded() {
        assert_eq!(Attempt::new(0), Err(AttemptError(0)));
        assert!(Attempt::new(ATTEMPT_MAX).is_ok());
        assert!(Attempt::new(ATTEMPT_MAX.saturating_add(1)).is_err());
        assert_eq!(Attempt::FIRST.next().map(Attempt::get), Ok(2));
        assert!(Attempt::new(ATTEMPT_MAX).and_then(Attempt::next).is_err());
    }

    #[test]
    fn promise_name_round_trips() {
        let name = PromiseName::new(Phase::Escalation, Attempt::new(3).unwrap());
        assert_eq!(name.to_string(), "escalation.3");
        assert_eq!(PromiseName::parse("escalation.3"), Ok(name));
    }

    #[test]
    fn promise_name_rejects_each_defect() {
        assert_eq!(
            PromiseName::parse("result"),
            Err(PromiseNameError::MissingSeparator)
        );
        assert_eq!(
            PromiseName::parse("merge.1"),
            Err(PromiseNameError::UnknownPhase)
        );
        assert_eq!(
            PromiseName::parse("result.0"),
            Err(PromiseNameError::Attempt)
        );
        assert_eq!(
            PromiseName::parse("result.+1"),
            Err(PromiseNameError::Attempt)
        );
        assert_eq!(
            PromiseName::parse("result."),
            Err(PromiseNameError::Attempt)
        );
        assert!(matches!(
            PromiseName::parse(&format!("result.{}", "1".repeat(30))),
            Err(PromiseNameError::TooLong(_))
        ));
    }
}

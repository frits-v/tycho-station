//! The `WorkUnit` workflow, keyed by work unit id: the lifecycle figure of design section 7,
//! with the run handler as the only writer of lifecycle state.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use restate_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tycho_types::envelope::{CommitSha, EscalationPayload, ResultPayload, ShortText};
use tycho_types::service::{Attempt, EpicId, Phase, PromiseName, TaskId, WorkUnitId};
use tycho_types::session::{SessionKind, SessionName, Vendor};

use crate::config::spine;
use crate::config_store::{FactoryConfig, UnitConfig};
use crate::services::epic::EpicClient;
use crate::services::merge_gate::{Claim, GateError, GateVerdict, MergeGate, VerifyRequest};
use crate::services::worker_run::{
    worker_key, WorkerRunClient, WorkerRunOutcome, WorkerRunRequest,
};
use crate::services::{
    blocking, refuse, secret, Ports, Timing, CODE_BAD_REQUEST, CODE_CANCELLED, CODE_CONFLICT,
    CODE_FORBIDDEN, CODE_INTERNAL, CODE_NOT_FOUND,
};

const VIEW_KEY: &str = "view";
const SECRET_KEY: &str = "control_secret";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Queued,
    Claimed,
    Running,
    Stalled,
    Escalated,
    RetryQueued,
    Verifying,
    FastForward,
    Merged,
    Done,
    Abandoned,
}

impl Lifecycle {
    pub const ALL: [Self; 11] = [
        Self::Queued,
        Self::Claimed,
        Self::Running,
        Self::Stalled,
        Self::Escalated,
        Self::RetryQueued,
        Self::Verifying,
        Self::FastForward,
        Self::Merged,
        Self::Done,
        Self::Abandoned,
    ];

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Abandoned)
    }
}

/// The figure's arrows, plus `WorkerGaveUp` and `TerminalFailure`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    ChildClaimsLease,
    FirstStatus,
    ResultDone,
    SilenceOverT1,
    NudgeAnswered,
    GiveUpRuleHit,
    Verdict,
    VerdictAbandon,
    NoProgressOverT2,
    WorkerGaveUp,
    BackoffDone,
    AttemptOverMax,
    CriteriaPass,
    CriteriaFail,
    DefaultAdvanced,
    PrunedAndCheckpointed,
    /// A terminal error that is not a cancel: the unit ends, never stuck mid-lifecycle.
    TerminalFailure,
}

impl Event {
    pub const ALL: [Self; 17] = [
        Self::ChildClaimsLease,
        Self::FirstStatus,
        Self::ResultDone,
        Self::SilenceOverT1,
        Self::NudgeAnswered,
        Self::GiveUpRuleHit,
        Self::Verdict,
        Self::VerdictAbandon,
        Self::NoProgressOverT2,
        Self::WorkerGaveUp,
        Self::BackoffDone,
        Self::AttemptOverMax,
        Self::CriteriaPass,
        Self::CriteriaFail,
        Self::DefaultAdvanced,
        Self::PrunedAndCheckpointed,
        Self::TerminalFailure,
    ];
}

/// The next state, or `None` when the figure has no such arrow; every event is matched.
#[must_use]
pub fn transition(state: Lifecycle, event: Event) -> Option<Lifecycle> {
    use Lifecycle as L;
    let from = |sources: &[Lifecycle], to: Lifecycle| sources.contains(&state).then_some(to);
    match event {
        Event::ChildClaimsLease => from(&[L::Queued], L::Claimed),
        Event::FirstStatus => from(&[L::Claimed], L::Running),
        Event::ResultDone => from(&[L::Running], L::Verifying),
        Event::SilenceOverT1 => from(&[L::Running], L::Stalled),
        Event::NudgeAnswered => from(&[L::Stalled], L::Running),
        Event::GiveUpRuleHit => from(&[L::Running], L::Escalated),
        Event::Verdict => from(&[L::Escalated], L::Running),
        Event::VerdictAbandon => from(&[L::Escalated], L::Abandoned),
        Event::NoProgressOverT2 => from(&[L::Stalled], L::RetryQueued),
        Event::WorkerGaveUp => from(&[L::Running], L::RetryQueued),
        Event::BackoffDone => from(&[L::RetryQueued], L::Queued),
        Event::AttemptOverMax => from(&[L::RetryQueued], L::Escalated),
        Event::CriteriaPass => from(&[L::Verifying], L::FastForward),
        Event::CriteriaFail => from(&[L::Verifying], L::Running),
        Event::DefaultAdvanced => from(&[L::FastForward], L::Merged),
        Event::PrunedAndCheckpointed => from(&[L::Merged], L::Done),
        Event::TerminalFailure => (!state.is_terminal()).then_some(L::Abandoned),
    }
}

/// One task of the dispatch plan the control session step reads from the task packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedTask {
    pub task: TaskId,
    pub worker: WorkerRunRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkUnitRequest {
    pub epic: EpicId,
    pub control_vendor: Vendor,
    pub plan: Vec<PlannedTask>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkUnitView {
    pub lifecycle: Lifecycle,
    pub attempt: u16,
    pub head_sha: Option<CommitSha>,
    pub control_session: String,
    pub findings: Vec<String>,
    /// Why the unit was abandoned, when it was.
    pub reason: Option<String>,
    /// The configuration the unit started with, journaled once; the run uses these values.
    #[serde(default)]
    pub config: UnitConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RulingVerdict {
    Continue,
    Abandon,
}

/// The verdict on an escalated unit; it resolves `ruling.<attempt>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ruling {
    pub verdict: RulingVerdict,
    pub reason: ShortText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCall {
    pub attempt: u16,
    pub ruling: Ruling,
}

/// A call from the unit's control session: its secret, the attempt, and the payload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlCall<T> {
    pub secret: String,
    pub attempt: u16,
    pub payload: T,
}

impl<T: fmt::Debug> fmt::Debug for ControlCall<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlCall")
            .field("secret", &"redacted")
            .field("attempt", &self.attempt)
            .field("payload", &self.payload)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    Secret,
    Attempt(u16),
    NotCurrent { attempt: u16, current: Option<u16> },
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secret => formatter.write_str("the control session secret does not match"),
            Self::Attempt(value) => write!(formatter, "attempt {value} is out of range"),
            Self::NotCurrent { attempt, current } => {
                write!(
                    formatter,
                    "attempt {attempt} is not the current attempt {current:?}"
                )
            }
        }
    }
}

impl ControlError {
    const fn code(&self) -> u16 {
        match self {
            Self::Secret => CODE_FORBIDDEN,
            Self::Attempt(_) => CODE_BAD_REQUEST,
            Self::NotCurrent { .. } => CODE_CONFLICT,
        }
    }
}

/// The promise a call for `attempt` resolves; only the unit's current attempt has one.
pub fn current_promise(
    phase: Phase,
    attempt: u16,
    current: Option<u16>,
) -> Result<PromiseName, ControlError> {
    let checked = Attempt::new(attempt).map_err(|_| ControlError::Attempt(attempt))?;
    if current != Some(attempt) {
        return Err(ControlError::NotCurrent { attempt, current });
    }
    Ok(PromiseName::new(phase, checked))
}

/// The same, after the control session's secret checks out.
pub fn control_promise(
    stored_secret: Option<&str>,
    candidate: &str,
    phase: Phase,
    attempt: u16,
    current: Option<u16>,
) -> Result<PromiseName, ControlError> {
    if !stored_secret.is_some_and(|stored| secret::matches(stored, candidate)) {
        return Err(ControlError::Secret);
    }
    current_promise(phase, attempt, current)
}

#[must_use]
pub fn backoff(timing: &Timing, attempt: Attempt) -> Duration {
    let doublings = u32::from(attempt.get().saturating_sub(1)).min(16);
    timing
        .retry_backoff_initial
        .saturating_mul(2_u32.saturating_pow(doublings))
        .min(timing.retry_backoff_max)
}

pub fn check_plan(request: &WorkUnitRequest) -> Result<(), String> {
    let count = request.plan.len();
    if count == 0 || count > spine::PLAN_TASKS_MAX {
        return Err(format!(
            "the plan has {count} tasks; expected 1..={}",
            spine::PLAN_TASKS_MAX
        ));
    }
    Ok(())
}

/// How one unit attempt ended.
enum AttemptEnd {
    Merged(CommitSha),
    /// The gate found the claims wanting; the unit is running again.
    CriteriaFailed(Vec<String>),
    /// A worker run ended without a result; the unit is retry queued.
    GaveUp(Vec<String>),
    Escalated,
}

/// What follows an attempt that did not merge.
enum After {
    Retry,
    Escalate,
}

fn failure(code: u16, message: impl Into<String>) -> TerminalError {
    TerminalError::new_with_code(code, message)
}

pub struct WorkUnit {
    merge_gate: Arc<dyn MergeGate>,
    timing: Timing,
    config: Arc<FactoryConfig>,
}

impl WorkUnit {
    #[must_use]
    pub fn new(ports: &Ports) -> Self {
        Self {
            merge_gate: Arc::clone(&ports.merge_gate),
            timing: ports.timing,
            config: Arc::clone(&ports.config),
        }
    }
}

impl fmt::Debug for WorkUnit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkUnit")
            .field("merge_gate", &self.merge_gate.describe())
            .field("timing", &self.timing)
            .field("config", &self.config.hashes())
            .finish()
    }
}

struct Unit<'a> {
    workflow_context: &'a WorkflowContext<'a>,
    view: WorkUnitView,
    /// Journaled with the view's configuration at the start of the run.
    timing: Timing,
}

/// What the run journals at its start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UnitStart {
    config: UnitConfig,
    timing: Timing,
}

impl Unit<'_> {
    fn step(&mut self, event: Event) -> Result<(), TerminalError> {
        let next = transition(self.view.lifecycle, event).ok_or_else(|| {
            failure(
                CODE_INTERNAL,
                format!("no transition from {:?} on {event:?}", self.view.lifecycle),
            )
        })?;
        self.view.lifecycle = next;
        self.save();
        Ok(())
    }

    fn save(&self) {
        self.workflow_context.set(VIEW_KEY, Json(self.view.clone()));
    }
}

#[restate_sdk::workflow]
impl WorkUnit {
    /// Refuses a unit the epic does not list; a terminal error other than a cancel abandons it.
    #[handler(ingress_private)]
    async fn run(
        &self,
        workflow_context: WorkflowContext<'_>,
        request: Json<WorkUnitRequest>,
    ) -> HandlerResult<Json<WorkUnitView>> {
        let request = request.into_inner();
        check_plan(&request).map_err(|error| refuse(CODE_BAD_REQUEST, error))?;
        let unit_id = WorkUnitId::parse(workflow_context.key())
            .map_err(|error| refuse(CODE_BAD_REQUEST, error.to_string()))?;
        let listed = workflow_context
            .object_client::<EpicClient>(request.epic.as_str())
            .status()
            .call()
            .await?
            .into_inner()
            .is_some_and(|epic| epic.units.contains(&unit_id));
        if !listed {
            return Err(refuse(
                CODE_NOT_FOUND,
                format!("epic {} does not list unit {unit_id}", request.epic),
            ));
        }
        let mut unit = self.begin(&workflow_context, &unit_id, &request).await?;
        match self.lifecycle(&mut unit, &unit_id, &request).await {
            Ok(()) => Ok(Json(unit.view)),
            Err(error) if error.code() == CODE_CANCELLED => Err(error.into()),
            Err(error) => {
                unit.view.reason = Some(error.message().to_string());
                unit.step(Event::TerminalFailure)?;
                Ok(Json(unit.view))
            }
        }
    }

    /// Resolves `result.<attempt>` for the control session step that awaits it.
    #[handler]
    async fn result(
        &self,
        shared_context: SharedWorkflowContext<'_>,
        call: Json<ControlCall<ResultPayload>>,
    ) -> HandlerResult<()> {
        let call = call.into_inner();
        let name = control_name(&shared_context, &call.secret, Phase::Result, call.attempt).await?;
        shared_context.resolve_promise(&name.to_string(), Json(call.payload));
        Ok(())
    }

    /// Resolves `escalation.<attempt>` with the certified question.
    #[handler]
    async fn escalate(
        &self,
        shared_context: SharedWorkflowContext<'_>,
        call: Json<ControlCall<EscalationPayload>>,
    ) -> HandlerResult<()> {
        let call = call.into_inner();
        let name = control_name(
            &shared_context,
            &call.secret,
            Phase::Escalation,
            call.attempt,
        )
        .await?;
        shared_context.resolve_promise(&name.to_string(), Json(call.payload));
        Ok(())
    }

    /// Resolves `ruling.<attempt>`; reached only through the Operator service.
    #[handler(ingress_private)]
    async fn rule(
        &self,
        shared_context: SharedWorkflowContext<'_>,
        call: Json<RuleCall>,
    ) -> HandlerResult<()> {
        let call = call.into_inner();
        let current = current_attempt(&shared_context).await?;
        let name = current_promise(Phase::Ruling, call.attempt, current)
            .map_err(|error| refuse(error.code(), error.to_string()))?;
        shared_context.resolve_promise(&name.to_string(), Json(call.ruling));
        Ok(())
    }

    #[handler]
    async fn status(
        &self,
        shared_context: SharedWorkflowContext<'_>,
    ) -> HandlerResult<Json<Option<WorkUnitView>>> {
        let view = shared_context.get::<Json<WorkUnitView>>(VIEW_KEY).await?;
        Ok(Json(view.map(Json::into_inner)))
    }
}

async fn current_attempt(
    shared_context: &SharedWorkflowContext<'_>,
) -> Result<Option<u16>, HandlerError> {
    let view = shared_context.get::<Json<WorkUnitView>>(VIEW_KEY).await?;
    Ok(view.map(|view| view.into_inner().attempt))
}

async fn control_name(
    shared_context: &SharedWorkflowContext<'_>,
    candidate: &str,
    phase: Phase,
    attempt: u16,
) -> Result<PromiseName, HandlerError> {
    let stored = shared_context.get::<String>(SECRET_KEY).await?;
    let current = current_attempt(shared_context).await?;
    control_promise(stored.as_deref(), candidate, phase, attempt, current)
        .map_err(|error| refuse(error.code(), error.to_string()))
}

impl WorkUnit {
    async fn begin<'a>(
        &self,
        workflow_context: &'a WorkflowContext<'a>,
        unit_id: &WorkUnitId,
        request: &WorkUnitRequest,
    ) -> Result<Unit<'a>, HandlerError> {
        let control = SessionName::unit(
            request.epic.clone(),
            unit_id.clone(),
            SessionKind::Control,
            request.control_vendor,
            None,
        );
        let control_secret = workflow_context
            .run(|| async {
                secret::generate()
                    .map(|generated| generated.expose().to_string())
                    .map_err(HandlerError::from)
            })
            .name("control secret")
            .await?;
        workflow_context.set(SECRET_KEY, control_secret);
        let start = UnitStart {
            config: self.config.unit_config(),
            timing: self.timing,
        };
        let start = workflow_context
            .run(|| async move { Ok(Json(start)) })
            .name("configuration")
            .await?
            .into_inner();
        let unit = Unit {
            workflow_context,
            view: WorkUnitView {
                lifecycle: Lifecycle::Queued,
                attempt: 1,
                head_sha: None,
                control_session: control.to_string(),
                findings: Vec::new(),
                reason: None,
                config: start.config,
            },
            timing: start.timing,
        };
        unit.save();
        Ok(unit)
    }

    async fn lifecycle(
        &self,
        unit: &mut Unit<'_>,
        unit_id: &WorkUnitId,
        request: &WorkUnitRequest,
    ) -> Result<(), TerminalError> {
        let cap = Attempt::new(unit.view.config.unit_attempt_cap)
            .map_err(|error| failure(CODE_INTERNAL, error.to_string()))?;
        let mut attempt = Attempt::FIRST;
        unit.step(Event::ChildClaimsLease)?;
        unit.step(Event::FirstStatus)?;
        for _ in 0..spine::UNIT_ROUNDS_MAX {
            unit.view.attempt = attempt.get();
            unit.save();
            let after = match self.attempt(unit, unit_id, request, attempt).await? {
                AttemptEnd::Merged(sha) => {
                    unit.view.head_sha = Some(sha);
                    unit.step(Event::DefaultAdvanced)?;
                    return unit.step(Event::PrunedAndCheckpointed);
                }
                AttemptEnd::CriteriaFailed(findings) => {
                    unit.view.findings = findings;
                    Self::after_criteria(unit, attempt, cap)?
                }
                AttemptEnd::GaveUp(findings) => {
                    unit.view.findings = findings;
                    self.after_give_up(unit, attempt, cap).await?
                }
                AttemptEnd::Escalated => After::Escalate,
            };
            if matches!(after, After::Escalate) && !self.ruling(unit, attempt).await? {
                return Ok(());
            }
            attempt = attempt
                .next()
                .map_err(|error| failure(CODE_BAD_REQUEST, error.to_string()))?;
        }
        Err(failure(CODE_INTERNAL, "the unit ran out of rounds"))
    }

    fn after_criteria(
        unit: &mut Unit<'_>,
        attempt: Attempt,
        cap: Attempt,
    ) -> Result<After, TerminalError> {
        if attempt < cap {
            return Ok(After::Retry);
        }
        unit.step(Event::GiveUpRuleHit)?;
        Ok(After::Escalate)
    }

    async fn after_give_up(
        &self,
        unit: &mut Unit<'_>,
        attempt: Attempt,
        cap: Attempt,
    ) -> Result<After, TerminalError> {
        if attempt >= cap {
            unit.step(Event::AttemptOverMax)?;
            return Ok(After::Escalate);
        }
        unit.workflow_context
            .sleep(backoff(&unit.timing, attempt))
            .await?;
        unit.step(Event::BackoffDone)?;
        unit.step(Event::ChildClaimsLease)?;
        unit.step(Event::FirstStatus)?;
        Ok(After::Retry)
    }

    /// Awaits `ruling.<attempt>`; true when the verdict lets the unit continue.
    async fn ruling(&self, unit: &mut Unit<'_>, attempt: Attempt) -> Result<bool, TerminalError> {
        let name = PromiseName::new(Phase::Ruling, attempt).to_string();
        let ruling = unit
            .workflow_context
            .promise::<Json<Ruling>>(&name)
            .await?
            .into_inner();
        match ruling.verdict {
            RulingVerdict::Continue => {
                unit.step(Event::Verdict)?;
                Ok(true)
            }
            RulingVerdict::Abandon => {
                unit.view.reason = Some(ruling.reason.to_string());
                unit.step(Event::VerdictAbandon)?;
                Ok(false)
            }
        }
    }

    /// Dispatches the plan's tasks in order, then verifies every claim.
    async fn attempt(
        &self,
        unit: &mut Unit<'_>,
        unit_id: &WorkUnitId,
        request: &WorkUnitRequest,
        attempt: Attempt,
    ) -> Result<AttemptEnd, TerminalError> {
        let mut claims = Vec::new();
        for planned in &request.plan {
            let mut worker = planned.worker.clone();
            worker.epic = request.epic.clone();
            worker.work_unit = unit_id.clone();
            let outcome = unit
                .workflow_context
                .workflow_client::<WorkerRunClient>(worker_key(&planned.task, attempt))
                .run(Json(worker))
                .call()
                .await?
                .into_inner();
            match outcome {
                WorkerRunOutcome::Completed { result, .. } => claims.push(Claim {
                    task: planned.task.clone(),
                    branch: result.branch,
                    head_sha: result.head_sha,
                }),
                WorkerRunOutcome::Escalated { .. }
                | WorkerRunOutcome::Replan { .. }
                | WorkerRunOutcome::Inbox { .. } => {
                    unit.step(Event::GiveUpRuleHit)?;
                    return Ok(AttemptEnd::Escalated);
                }
                WorkerRunOutcome::Stopped { .. } | WorkerRunOutcome::Exhausted { .. } => {
                    unit.step(Event::WorkerGaveUp)?;
                    return Ok(AttemptEnd::GaveUp(vec![format!(
                        "{}: {outcome:?}",
                        planned.task
                    )]));
                }
            }
        }
        unit.step(Event::ResultDone)?;
        self.verify(unit, unit_id, attempt, claims).await
    }

    async fn verify(
        &self,
        unit: &mut Unit<'_>,
        unit_id: &WorkUnitId,
        attempt: Attempt,
        claims: Vec<Claim>,
    ) -> Result<AttemptEnd, TerminalError> {
        let gate = Arc::clone(&self.merge_gate);
        let request = VerifyRequest {
            work_unit: unit_id.clone(),
            attempt,
            claims,
        };
        let verdict = unit
            .workflow_context
            .run(|| {
                blocking(move || {
                    let verdict = gate.verify(&request).map_err(gate_failure)?;
                    verdict.validate().map_err(gate_failure)?;
                    Ok(Json(verdict))
                })
            })
            .name("verify")
            .retry_policy(unit.timing.port_retry())
            .await?
            .into_inner();
        match verdict {
            GateVerdict::Merged { default_sha } => {
                unit.step(Event::CriteriaPass)?;
                Ok(AttemptEnd::Merged(default_sha))
            }
            GateVerdict::Failed { findings } => {
                unit.step(Event::CriteriaFail)?;
                Ok(AttemptEnd::CriteriaFailed(
                    findings.iter().map(ToString::to_string).collect(),
                ))
            }
        }
    }
}

fn gate_failure(error: GateError) -> HandlerError {
    match error {
        GateError::Transient(_) => HandlerError::from(error),
        GateError::Refused(reason) => refuse(CODE_INTERNAL, reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The figure's arrows plus the worker give-up arrow; terminal failure is checked apart.
    const EDGES: [(Lifecycle, Event, Lifecycle); 16] = [
        (
            Lifecycle::Queued,
            Event::ChildClaimsLease,
            Lifecycle::Claimed,
        ),
        (Lifecycle::Claimed, Event::FirstStatus, Lifecycle::Running),
        (Lifecycle::Running, Event::ResultDone, Lifecycle::Verifying),
        (Lifecycle::Running, Event::SilenceOverT1, Lifecycle::Stalled),
        (Lifecycle::Stalled, Event::NudgeAnswered, Lifecycle::Running),
        (
            Lifecycle::Running,
            Event::GiveUpRuleHit,
            Lifecycle::Escalated,
        ),
        (Lifecycle::Escalated, Event::Verdict, Lifecycle::Running),
        (
            Lifecycle::Escalated,
            Event::VerdictAbandon,
            Lifecycle::Abandoned,
        ),
        (
            Lifecycle::Stalled,
            Event::NoProgressOverT2,
            Lifecycle::RetryQueued,
        ),
        (
            Lifecycle::Running,
            Event::WorkerGaveUp,
            Lifecycle::RetryQueued,
        ),
        (
            Lifecycle::RetryQueued,
            Event::BackoffDone,
            Lifecycle::Queued,
        ),
        (
            Lifecycle::RetryQueued,
            Event::AttemptOverMax,
            Lifecycle::Escalated,
        ),
        (
            Lifecycle::Verifying,
            Event::CriteriaPass,
            Lifecycle::FastForward,
        ),
        (
            Lifecycle::Verifying,
            Event::CriteriaFail,
            Lifecycle::Running,
        ),
        (
            Lifecycle::FastForward,
            Event::DefaultAdvanced,
            Lifecycle::Merged,
        ),
        (
            Lifecycle::Merged,
            Event::PrunedAndCheckpointed,
            Lifecycle::Done,
        ),
    ];

    #[test]
    fn the_transition_table_is_exactly_the_figure() {
        let mut checked = 0_usize;
        for state in Lifecycle::ALL {
            for event in Event::ALL {
                let expected = if event == Event::TerminalFailure {
                    (!state.is_terminal()).then_some(Lifecycle::Abandoned)
                } else {
                    EDGES
                        .iter()
                        .find(|(from, on, _)| *from == state && *on == event)
                        .map(|(_, _, to)| *to)
                };
                assert_eq!(transition(state, event), expected, "{state:?} on {event:?}");
                checked = checked.saturating_add(1);
            }
        }
        assert_eq!(checked, Lifecycle::ALL.len() * Event::ALL.len());
    }

    #[test]
    fn a_terminal_failure_abandons_every_unfinished_state() {
        for state in [
            Lifecycle::Running,
            Lifecycle::Verifying,
            Lifecycle::Escalated,
        ] {
            assert_eq!(
                transition(state, Event::TerminalFailure),
                Some(Lifecycle::Abandoned)
            );
        }
    }

    #[test]
    fn done_and_abandoned_are_terminal() {
        for event in Event::ALL {
            assert_eq!(transition(Lifecycle::Done, event), None);
            assert_eq!(transition(Lifecycle::Abandoned, event), None);
        }
    }

    #[test]
    fn promise_names_carry_phase_and_attempt() {
        let stored = "s".repeat(40);
        let result = control_promise(Some(&stored), &stored, Phase::Result, 1, Some(1)).unwrap();
        assert_eq!(result.to_string(), "result.1");
        let escalation =
            control_promise(Some(&stored), &stored, Phase::Escalation, 3, Some(3)).unwrap();
        assert_eq!(escalation.to_string(), "escalation.3");
        assert_eq!(
            current_promise(Phase::Ruling, 2, Some(2))
                .unwrap()
                .to_string(),
            "ruling.2"
        );
    }

    #[test]
    fn a_control_call_needs_the_right_secret_and_the_current_attempt() {
        let stored = "s".repeat(40);
        assert_eq!(
            control_promise(Some(&stored), &"t".repeat(40), Phase::Result, 1, Some(1)),
            Err(ControlError::Secret)
        );
        assert_eq!(
            control_promise(None, &stored, Phase::Result, 1, Some(1)),
            Err(ControlError::Secret)
        );
        assert_eq!(
            control_promise(Some(&stored), &stored, Phase::Result, 0, Some(1)),
            Err(ControlError::Attempt(0))
        );
        let stale = control_promise(Some(&stored), &stored, Phase::Result, 1, Some(2));
        assert_eq!(
            stale,
            Err(ControlError::NotCurrent {
                attempt: 1,
                current: Some(2)
            })
        );
        assert_eq!(stale.unwrap_err().code(), CODE_CONFLICT);
        assert!(current_promise(Phase::Ruling, 1, None).is_err());
    }

    #[test]
    fn backoff_doubles_to_its_cap() {
        let timing = Timing::default();
        let delays: Vec<u64> = [1, 2, 3, 6, 9]
            .iter()
            .map(|number| backoff(&timing, Attempt::new(*number).unwrap()).as_secs())
            .collect();
        assert_eq!(delays, vec![10, 20, 40, 300, 300]);
    }

    fn planned() -> PlannedTask {
        let worker: WorkerRunRequest = serde_json::from_str(
            r#"{"epic":"cf7a","work_unit":"wu01","vendor":"claude","argv":["l"],"routing":{"class":"c","tier":"t","effort":"low","binding":null,"rationale":"r"},"ledger":"seat","reservation":1}"#,
        )
        .unwrap();
        PlannedTask {
            task: TaskId::parse("t").unwrap(),
            worker,
        }
    }

    #[test]
    fn the_plan_is_bounded() {
        let mut request = WorkUnitRequest {
            epic: EpicId::parse("cf7a").unwrap(),
            control_vendor: Vendor::Codex,
            plan: Vec::new(),
        };
        assert!(check_plan(&request).is_err());
        request.plan = vec![planned(); spine::PLAN_TASKS_MAX];
        assert!(check_plan(&request).is_ok());
        request.plan.push(planned());
        assert!(check_plan(&request).is_err());
    }

    #[test]
    fn control_call_debug_never_prints_the_secret() {
        let call = ControlCall {
            secret: "s".repeat(40),
            attempt: 1,
            payload: 7_u32,
        };
        assert!(!format!("{call:?}").contains(&"s".repeat(40)));
    }
}

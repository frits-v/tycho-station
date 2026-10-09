//! The `WorkUnit` workflow, keyed by work unit id: the lifecycle figure of design section 7,
//! with the run handler as the only writer of lifecycle state.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use restate_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tycho_types::envelope::{CommitSha, EscalationPayload, ResultPayload};
use tycho_types::service::{Attempt, EpicId, Phase, PromiseName, TaskId, WorkUnitId};
use tycho_types::session::{SessionKind, SessionName, Vendor};

use crate::config::spine;
use crate::services::merge_gate::{GateError, GateVerdict, MergeGate, VerifyRequest};
use crate::services::worker_run::{WorkerRunClient, WorkerRunOutcome, WorkerRunRequest};
use crate::services::{blocking, refuse, secret, Ports, Timing, CODE_BAD_REQUEST, CODE_FORBIDDEN};

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
}

/// The lifecycle figure's arrows, plus `WorkerGaveUp` for a worker run that ended unfinished.
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
}

impl Event {
    pub const ALL: [Self; 16] = [
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
        Event::NoProgressOverT2 => from(&[L::Running, L::Stalled], L::RetryQueued),
        Event::WorkerGaveUp => from(&[L::Running], L::RetryQueued),
        Event::BackoffDone => from(&[L::RetryQueued], L::Queued),
        Event::AttemptOverMax => from(&[L::RetryQueued], L::Abandoned),
        Event::CriteriaPass => from(&[L::Verifying], L::FastForward),
        Event::CriteriaFail => from(&[L::Verifying], L::RetryQueued),
        Event::DefaultAdvanced => from(&[L::FastForward], L::Merged),
        Event::PrunedAndCheckpointed => from(&[L::Merged], L::Done),
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
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secret => formatter.write_str("the control session secret does not match"),
            Self::Attempt(value) => write!(formatter, "attempt {value} is out of range"),
        }
    }
}

/// The promise a control call resolves, after its secret checks out.
pub fn control_promise(
    stored_secret: Option<&str>,
    candidate: &str,
    phase: Phase,
    attempt: u16,
) -> Result<PromiseName, ControlError> {
    if !stored_secret.is_some_and(|stored| secret::matches(stored, candidate)) {
        return Err(ControlError::Secret);
    }
    let attempt = Attempt::new(attempt).map_err(|_| ControlError::Attempt(attempt))?;
    Ok(PromiseName::new(phase, attempt))
}

/// The worker run key for a task under a unit attempt; a workflow key runs once.
pub fn worker_key(task: &TaskId, attempt: Attempt) -> Result<TaskId, String> {
    if attempt == Attempt::FIRST {
        return Ok(task.clone());
    }
    TaskId::parse(&format!("{task}-u{}", attempt.get())).map_err(|error| error.to_string())
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
    Retry(Vec<String>),
    Escalated,
}

pub struct WorkUnit {
    merge_gate: Arc<dyn MergeGate>,
    timing: Timing,
}

impl WorkUnit {
    #[must_use]
    pub fn new(ports: &Ports) -> Self {
        Self {
            merge_gate: Arc::clone(&ports.merge_gate),
            timing: ports.timing,
        }
    }
}

impl fmt::Debug for WorkUnit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkUnit")
            .field("merge_gate", &self.merge_gate.describe())
            .field("timing", &self.timing)
            .finish()
    }
}

struct Unit<'a> {
    workflow_context: &'a WorkflowContext<'a>,
    view: WorkUnitView,
}

impl Unit<'_> {
    fn step(&mut self, event: Event) -> Result<(), HandlerError> {
        let next = transition(self.view.lifecycle, event).ok_or_else(|| {
            refuse(
                CODE_BAD_REQUEST,
                format!("no transition from {:?} on {event:?}", self.view.lifecycle),
            )
        })?;
        self.view.lifecycle = next;
        self.workflow_context.set(VIEW_KEY, Json(self.view.clone()));
        Ok(())
    }
}

#[restate_sdk::workflow]
impl WorkUnit {
    #[handler]
    async fn run(
        &self,
        workflow_context: WorkflowContext<'_>,
        request: Json<WorkUnitRequest>,
    ) -> HandlerResult<Json<WorkUnitView>> {
        let request = request.into_inner();
        check_plan(&request).map_err(|error| refuse(CODE_BAD_REQUEST, error))?;
        let unit_id = WorkUnitId::parse(workflow_context.key())
            .map_err(|error| refuse(CODE_BAD_REQUEST, error.to_string()))?;
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
        let mut unit = Unit {
            workflow_context: &workflow_context,
            view: WorkUnitView {
                lifecycle: Lifecycle::Queued,
                attempt: 1,
                head_sha: None,
                control_session: control.to_string(),
                findings: Vec::new(),
            },
        };
        workflow_context.set(VIEW_KEY, Json(unit.view.clone()));
        self.lifecycle(&mut unit, &unit_id, &request).await?;
        Ok(Json(unit.view))
    }

    /// Resolves `result.<attempt>` for the control session step that awaits it.
    #[handler]
    async fn result(
        &self,
        shared_context: SharedWorkflowContext<'_>,
        call: Json<ControlCall<ResultPayload>>,
    ) -> HandlerResult<()> {
        let call = call.into_inner();
        let stored = shared_context.get::<String>(SECRET_KEY).await?;
        let name = control_promise(stored.as_deref(), &call.secret, Phase::Result, call.attempt)
            .map_err(|error| refuse(CODE_FORBIDDEN, error.to_string()))?;
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
        let stored = shared_context.get::<String>(SECRET_KEY).await?;
        let name = control_promise(
            stored.as_deref(),
            &call.secret,
            Phase::Escalation,
            call.attempt,
        )
        .map_err(|error| refuse(CODE_FORBIDDEN, error.to_string()))?;
        shared_context.resolve_promise(&name.to_string(), Json(call.payload));
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

impl WorkUnit {
    async fn lifecycle(
        &self,
        unit: &mut Unit<'_>,
        unit_id: &WorkUnitId,
        request: &WorkUnitRequest,
    ) -> Result<(), HandlerError> {
        let cap = Attempt::new(spine::ATTEMPT_CAP_DEFAULT).unwrap_or(Attempt::FIRST);
        let mut attempt = Attempt::FIRST;
        for _ in 0..cap.get() {
            unit.view.attempt = attempt.get();
            unit.step(Event::ChildClaimsLease)?;
            unit.step(Event::FirstStatus)?;
            match self.attempt(unit, unit_id, request, attempt).await? {
                AttemptEnd::Merged(sha) => {
                    unit.view.head_sha = Some(sha);
                    unit.step(Event::DefaultAdvanced)?;
                    return unit.step(Event::PrunedAndCheckpointed);
                }
                AttemptEnd::Escalated => return Ok(()),
                AttemptEnd::Retry(findings) => unit.view.findings = findings,
            }
            if attempt >= cap {
                return unit.step(Event::AttemptOverMax);
            }
            unit.workflow_context
                .sleep(backoff(&self.timing, attempt))
                .await?;
            unit.step(Event::BackoffDone)?;
            attempt = attempt
                .next()
                .map_err(|error| refuse(CODE_BAD_REQUEST, error.to_string()))?;
        }
        unit.step(Event::AttemptOverMax)
    }

    /// Dispatches the plan's tasks in order, then verifies the last claimed result.
    async fn attempt(
        &self,
        unit: &mut Unit<'_>,
        unit_id: &WorkUnitId,
        request: &WorkUnitRequest,
        attempt: Attempt,
    ) -> Result<AttemptEnd, HandlerError> {
        let mut claimed = None;
        for planned in &request.plan {
            let key = worker_key(&planned.task, attempt)
                .map_err(|error| refuse(CODE_BAD_REQUEST, error))?;
            let mut worker = planned.worker.clone();
            worker.epic = request.epic.clone();
            worker.work_unit = unit_id.clone();
            let outcome = unit
                .workflow_context
                .workflow_client::<WorkerRunClient>(key.as_str())
                .run(Json(worker))
                .call()
                .await?
                .into_inner();
            match outcome {
                WorkerRunOutcome::Completed { result, .. } => claimed = Some(result),
                WorkerRunOutcome::Escalated { .. } => {
                    unit.step(Event::GiveUpRuleHit)?;
                    return Ok(AttemptEnd::Escalated);
                }
                WorkerRunOutcome::Replan { .. }
                | WorkerRunOutcome::Stopped { .. }
                | WorkerRunOutcome::Inbox { .. }
                | WorkerRunOutcome::Exhausted { .. } => {
                    unit.step(Event::WorkerGaveUp)?;
                    return Ok(AttemptEnd::Retry(vec![format!(
                        "{}: {outcome:?}",
                        planned.task
                    )]));
                }
            }
        }
        let Some(result) = claimed else {
            unit.step(Event::WorkerGaveUp)?;
            return Ok(AttemptEnd::Retry(vec![
                "the plan produced no result".to_string()
            ]));
        };
        unit.step(Event::ResultDone)?;
        self.verify(unit, unit_id, attempt, result).await
    }

    async fn verify(
        &self,
        unit: &mut Unit<'_>,
        unit_id: &WorkUnitId,
        attempt: Attempt,
        result: ResultPayload,
    ) -> Result<AttemptEnd, HandlerError> {
        let gate = Arc::clone(&self.merge_gate);
        let request = VerifyRequest {
            work_unit: unit_id.clone(),
            attempt,
            branch: result.branch,
            head_sha: result.head_sha,
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
            .retry_policy(self.timing.port_retry())
            .await?
            .into_inner();
        match verdict {
            GateVerdict::Merged { default_sha } => {
                unit.step(Event::CriteriaPass)?;
                Ok(AttemptEnd::Merged(default_sha))
            }
            GateVerdict::Failed { findings } => {
                unit.step(Event::CriteriaFail)?;
                Ok(AttemptEnd::Retry(
                    findings.iter().map(ToString::to_string).collect(),
                ))
            }
        }
    }
}

fn gate_failure(error: GateError) -> HandlerError {
    match error {
        GateError::Transient(_) => HandlerError::from(error),
        GateError::Refused(reason) => refuse(crate::services::CODE_INTERNAL, reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The figure's arrows; every other state and event pair is refused.
    const EDGES: [(Lifecycle, Event, Lifecycle); 17] = [
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
            Lifecycle::Running,
            Event::NoProgressOverT2,
            Lifecycle::RetryQueued,
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
            Lifecycle::Abandoned,
        ),
        (
            Lifecycle::Verifying,
            Event::CriteriaPass,
            Lifecycle::FastForward,
        ),
        (
            Lifecycle::Verifying,
            Event::CriteriaFail,
            Lifecycle::RetryQueued,
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
                let expected = EDGES
                    .iter()
                    .find(|(from, on, _)| *from == state && *on == event)
                    .map(|(_, _, to)| *to);
                assert_eq!(transition(state, event), expected, "{state:?} on {event:?}");
                checked = checked.saturating_add(1);
            }
        }
        assert_eq!(checked, Lifecycle::ALL.len() * Event::ALL.len());
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
        let result = control_promise(Some(&stored), &stored, Phase::Result, 1).unwrap();
        assert_eq!(result.to_string(), "result.1");
        let escalation = control_promise(Some(&stored), &stored, Phase::Escalation, 3).unwrap();
        assert_eq!(escalation.to_string(), "escalation.3");
        assert_ne!(
            control_promise(Some(&stored), &stored, Phase::Result, 2).unwrap(),
            result
        );
    }

    #[test]
    fn a_control_call_needs_the_right_secret_and_a_valid_attempt() {
        let stored = "s".repeat(40);
        assert_eq!(
            control_promise(Some(&stored), &"t".repeat(40), Phase::Result, 1),
            Err(ControlError::Secret)
        );
        assert_eq!(
            control_promise(None, &stored, Phase::Result, 1),
            Err(ControlError::Secret)
        );
        assert_eq!(
            control_promise(Some(&stored), &stored, Phase::Result, 0),
            Err(ControlError::Attempt(0))
        );
    }

    #[test]
    fn worker_keys_differ_per_unit_attempt() {
        let task = TaskId::parse("wu03-t07").unwrap();
        assert_eq!(worker_key(&task, Attempt::FIRST).unwrap(), task);
        assert_eq!(
            worker_key(&task, Attempt::new(2).unwrap())
                .unwrap()
                .as_str(),
            "wu03-t07-u2"
        );
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

    #[test]
    fn the_plan_is_bounded() {
        let request = WorkUnitRequest {
            epic: EpicId::parse("cf7a").unwrap(),
            control_vendor: Vendor::Codex,
            plan: Vec::new(),
        };
        assert!(check_plan(&request).is_err());
    }

    #[test]
    fn the_plan_rejects_more_tasks_than_its_maximum() {
        let worker: WorkerRunRequest = serde_json::from_str(
            r#"{"epic":"cf7a","work_unit":"wu01","vendor":"claude","argv":["l"],"routing":{"class":"c","tier":"t","effort":"low","binding":null,"rationale":"r","fallback_tier":null},"ledger":"seat","reservation":1}"#,
        )
        .unwrap();
        let task = PlannedTask {
            task: TaskId::parse("t").unwrap(),
            worker,
        };
        let mut request = WorkUnitRequest {
            epic: EpicId::parse("cf7a").unwrap(),
            control_vendor: Vendor::Codex,
            plan: vec![task; spine::PLAN_TASKS_MAX],
        };
        assert!(check_plan(&request).is_ok());
        request.plan.push(request.plan[0].clone());
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

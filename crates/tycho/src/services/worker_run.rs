//! The `WorkerRun` workflow, keyed by task id: reserve, spawn, race the awaitable against T1
//! and T2, decode the exit, settle on every exit, and retry inside the one run.

use std::fmt;
use std::pin::Pin;
use std::time::Duration;

use restate_sdk::context::DurableFuture;
use restate_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tycho_types::envelope::{Outcome, ResultPayload, ShortText};
use tycho_types::exit::{Disposition, ExitState};
use tycho_types::service::{Attempt, EpicId, TaskId, WorkUnitId, RECONCILER_KEY};
use tycho_types::session::{SessionKind, SessionName, Suffix, Vendor};
use tycho_types::task_packet::{Routing, RoutingName};

use crate::config::spine;
use crate::services::epic::{
    EpicClient, LedgerKind, ReserveAnswer, ReserveRequest, SettleRequest, SlotLevel,
};
use crate::services::reconciler::ReconcilerClient;
use crate::services::session::{
    KillRequest, SessionClient, SessionView, SpawnOutcome, SpawnRequest,
};
use crate::services::{refuse, secret, wall_clock_unix_ms, Ports, Timing, CODE_BAD_REQUEST};

const VIEW_KEY: &str = "view";
const TIER_FLAG: &str = "--tier";
const NUDGE_TEXT: &str = "tycho: no heartbeat for a while; report status";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRunRequest {
    pub epic: EpicId,
    pub work_unit: WorkUnitId,
    pub vendor: Vendor,
    pub argv: Vec<ShortText>,
    pub routing: Routing,
    pub ledger: LedgerKind,
    /// Budget reserved per attempt, in the ledger's unit.
    pub reservation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum WorkerRunOutcome {
    Completed { attempt: u16, result: ResultPayload },
    Escalated { attempt: u16 },
    Replan { attempt: u16 },
    Stopped { attempt: u16, state: String },
    Inbox { attempt: u16, state: String },
    Exhausted { attempts: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRunView {
    pub attempt: u16,
    pub tier: RoutingName,
    pub session: Option<String>,
    pub outcome: Option<WorkerRunOutcome>,
}

/// What the run does after an attempt ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AfterAttempt {
    /// Re-queue under the next attempt, one tier up when the routing names a fallback.
    Next,
    Finish(WorkerRunOutcome),
}

/// No wildcard: every disposition decides between another attempt and an outcome.
#[must_use]
pub fn after_attempt(
    exit: &ExitState,
    result: Option<ResultPayload>,
    attempt: Attempt,
    cap: Attempt,
) -> AfterAttempt {
    let number = attempt.get();
    match (exit.disposition(), result) {
        (Disposition::Verify, Some(result)) => AfterAttempt::Finish(WorkerRunOutcome::Completed {
            attempt: number,
            result,
        }),
        (Disposition::Requeue, _) | (Disposition::Verify, None) => {
            if attempt < cap {
                AfterAttempt::Next
            } else {
                AfterAttempt::Finish(WorkerRunOutcome::Exhausted { attempts: number })
            }
        }
        (Disposition::Escalate, _) => {
            AfterAttempt::Finish(WorkerRunOutcome::Escalated { attempt: number })
        }
        (Disposition::Replan, _) => {
            AfterAttempt::Finish(WorkerRunOutcome::Replan { attempt: number })
        }
        (Disposition::Stop, _) => AfterAttempt::Finish(WorkerRunOutcome::Stopped {
            attempt: number,
            state: exit.to_string(),
        }),
        (Disposition::Inbox, _) => AfterAttempt::Finish(WorkerRunOutcome::Inbox {
            attempt: number,
            state: String::from(exit.clone()),
        }),
    }
}

/// The attempt cap for a task class; every class takes the default until routing tables land.
#[must_use]
pub fn attempt_cap(_class: &RoutingName) -> Attempt {
    Attempt::new(spine::ATTEMPT_CAP_DEFAULT).unwrap_or(Attempt::FIRST)
}

#[must_use]
pub fn next_tier(routing: &Routing, current: &RoutingName) -> RoutingName {
    routing
        .fallback_tier
        .clone()
        .unwrap_or_else(|| current.clone())
}

/// A claim of done decodes as completed; a claim of not done is a failure to re-queue.
#[must_use]
pub const fn decode_result(result: &ResultPayload) -> ExitState {
    match result.outcome {
        Outcome::Done => ExitState::Completed,
        Outcome::NotDone => ExitState::Failed,
    }
}

/// What the watch does when a timer fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchStep {
    Wait(u64),
    Nudge(u64),
    /// No progress marker change within T2: save scrollback, kill, re-queue.
    Stall,
}

const WATCH_WAIT_MIN_MS: u64 = 250;

/// T2 keys on progress time only, never on heartbeats; T1 nudges once per silent stretch.
#[must_use]
pub fn watch_step(
    now_unix_ms: u64,
    view: &SessionView,
    nudged_unix_ms: Option<u64>,
    timing: &Timing,
) -> WatchStep {
    let stall_ms = Timing::millis(timing.stall_progress);
    let silence_ms = Timing::millis(timing.stall_silence);
    let progress_age = now_unix_ms.saturating_sub(view.progress_changed_unix_ms);
    if progress_age >= stall_ms {
        return WatchStep::Stall;
    }
    let until_stall = stall_ms.saturating_sub(progress_age);
    let silent_since = view.heartbeat_unix_ms.unwrap_or(view.spawned_unix_ms);
    let silence = now_unix_ms.saturating_sub(silent_since);
    let already_nudged = nudged_unix_ms.is_some_and(|nudged| nudged >= silent_since);
    if silence >= silence_ms && !already_nudged {
        return WatchStep::Nudge(silence_ms.min(until_stall).max(WATCH_WAIT_MIN_MS));
    }
    let until_silence = if silence >= silence_ms {
        silence_ms
    } else {
        silence_ms.saturating_sub(silence)
    };
    WatchStep::Wait(until_silence.min(until_stall).max(WATCH_WAIT_MIN_MS))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    Key(String),
    Argv(usize),
}

impl fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(error) => write!(formatter, "key is not a task id: {error}"),
            Self::Argv(count) => write!(
                formatter,
                "argv has {count} items; expected 1..={} before the tier flag",
                spine::SPAWN_ARGV_MAX_ITEMS.saturating_sub(2)
            ),
        }
    }
}

pub const fn check_request(request: &WorkerRunRequest) -> Result<(), RequestError> {
    let count = request.argv.len();
    if count == 0 || count > spine::SPAWN_ARGV_MAX_ITEMS.saturating_sub(2) {
        return Err(RequestError::Argv(count));
    }
    Ok(())
}

#[must_use]
pub fn session_name(request: &WorkerRunRequest, task: &TaskId, attempt: Attempt) -> SessionName {
    SessionName::unit(
        request.epic.clone(),
        request.work_unit.clone(),
        SessionKind::Worker,
        request.vendor,
        Some(Suffix::for_task(task, attempt)),
    )
}

fn argv_with_tier(
    request: &WorkerRunRequest,
    tier: &RoutingName,
) -> Result<Vec<ShortText>, HandlerError> {
    let mut argv = request.argv.clone();
    for item in [TIER_FLAG, tier.as_str()] {
        argv.push(
            ShortText::parse(item).map_err(|error| refuse(CODE_BAD_REQUEST, error.to_string()))?,
        );
    }
    Ok(argv)
}

enum Wake {
    Result(Result<Json<ResultPayload>, TerminalError>),
    Timer,
}

type WakeFuture<'run> = Pin<Box<dyn DurableFuture<Output = Wake> + Send + 'run>>;

struct AttemptEnd {
    exit: ExitState,
    result: Option<ResultPayload>,
}

pub struct WorkerRun {
    timing: Timing,
}

impl WorkerRun {
    #[must_use]
    pub const fn new(ports: &Ports) -> Self {
        Self {
            timing: ports.timing,
        }
    }
}

impl fmt::Debug for WorkerRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerRun")
            .field("timing", &self.timing)
            .finish()
    }
}

#[restate_sdk::workflow]
impl WorkerRun {
    #[handler]
    async fn run(
        &self,
        workflow_context: WorkflowContext<'_>,
        request: Json<WorkerRunRequest>,
    ) -> HandlerResult<Json<WorkerRunOutcome>> {
        let request = request.into_inner();
        let task = TaskId::parse(workflow_context.key()).map_err(|error| {
            refuse(
                CODE_BAD_REQUEST,
                RequestError::Key(error.to_string()).to_string(),
            )
        })?;
        check_request(&request).map_err(|error| refuse(CODE_BAD_REQUEST, error.to_string()))?;
        let cap = attempt_cap(&request.routing.class);
        let mut tier = request.routing.tier.clone();
        let mut attempt = Attempt::FIRST;
        for _ in 0..cap.get() {
            let end = self
                .attempt(&workflow_context, &task, &request, attempt, &tier)
                .await?;
            match after_attempt(&end.exit, end.result, attempt, cap) {
                AfterAttempt::Finish(outcome) => {
                    record(
                        &workflow_context,
                        attempt,
                        &tier,
                        None,
                        Some(outcome.clone()),
                    );
                    return Ok(Json(outcome));
                }
                AfterAttempt::Next => {
                    tier = next_tier(&request.routing, &tier);
                    attempt = attempt
                        .next()
                        .map_err(|error| refuse(CODE_BAD_REQUEST, error.to_string()))?;
                }
            }
        }
        let outcome = WorkerRunOutcome::Exhausted {
            attempts: cap.get(),
        };
        record(
            &workflow_context,
            attempt,
            &tier,
            None,
            Some(outcome.clone()),
        );
        Ok(Json(outcome))
    }

    #[handler]
    async fn status(
        &self,
        shared_context: SharedWorkflowContext<'_>,
    ) -> HandlerResult<Json<Option<WorkerRunView>>> {
        let view = shared_context.get::<Json<WorkerRunView>>(VIEW_KEY).await?;
        Ok(Json(view.map(Json::into_inner)))
    }
}

fn record(
    workflow_context: &WorkflowContext<'_>,
    attempt: Attempt,
    tier: &RoutingName,
    session: Option<&SessionName>,
    outcome: Option<WorkerRunOutcome>,
) {
    let view = WorkerRunView {
        attempt: attempt.get(),
        tier: tier.clone(),
        session: session.map(ToString::to_string),
        outcome,
    };
    workflow_context.set(VIEW_KEY, Json(view));
}

impl WorkerRun {
    /// One attempt; budget is settled on every way out, including a cancel.
    async fn attempt(
        &self,
        workflow_context: &WorkflowContext<'_>,
        task: &TaskId,
        request: &WorkerRunRequest,
        attempt: Attempt,
        tier: &RoutingName,
    ) -> Result<AttemptEnd, HandlerError> {
        if !self
            .reserve(workflow_context, task, request, attempt)
            .await?
        {
            return Ok(AttemptEnd {
                exit: ExitState::BudgetExceeded,
                result: None,
            });
        }
        let session = session_name(request, task, attempt);
        record(workflow_context, attempt, tier, Some(&session), None);
        let watched = self
            .spawn_and_watch(workflow_context, request, &session, tier)
            .await;
        let (end, cancelled) = match watched {
            Ok(end) => (end, None),
            Err(cancelled) => (
                AttemptEnd {
                    exit: ExitState::Cancelled,
                    result: None,
                },
                Some(cancelled),
            ),
        };
        settle(
            workflow_context,
            request,
            task,
            attempt,
            end.result.as_ref(),
        )
        .await?;
        if let Some(cancelled) = cancelled {
            return Err(cancelled.into());
        }
        Ok(end)
    }

    /// Re-sends the reservation after a full slot; false once the ledger is exhausted.
    async fn reserve(
        &self,
        workflow_context: &WorkflowContext<'_>,
        task: &TaskId,
        request: &WorkerRunRequest,
        attempt: Attempt,
    ) -> Result<bool, HandlerError> {
        let reservation = ReserveRequest {
            task: task.clone(),
            attempt: attempt.get(),
            level: SlotLevel::Worker,
            ledger: request.ledger,
            amount: request.reservation,
        };
        for _ in 0..spine::RESERVE_ROUNDS_MAX {
            let answer = workflow_context
                .object_client::<EpicClient>(request.epic.as_str())
                .reserve(Json(reservation.clone()))
                .call()
                .await?
                .into_inner();
            match answer {
                ReserveAnswer::Granted | ReserveAnswer::AlreadyHeld => return Ok(true),
                ReserveAnswer::BudgetExhausted => return Ok(false),
                ReserveAnswer::RetryLater => {
                    workflow_context.sleep(self.timing.slot_retry_delay).await?;
                }
            }
        }
        Err(refuse(
            CODE_BAD_REQUEST,
            "no worker slot freed within the reservation rounds",
        ))
    }

    /// The error side is a cancellation, after the session has been killed.
    async fn spawn_and_watch(
        &self,
        workflow_context: &WorkflowContext<'_>,
        request: &WorkerRunRequest,
        session: &SessionName,
        tier: &RoutingName,
    ) -> Result<AttemptEnd, TerminalError> {
        let failed = AttemptEnd {
            exit: ExitState::Failed,
            result: None,
        };
        let Ok(argv) = argv_with_tier(request, tier) else {
            return Ok(failed);
        };
        let session_secret = workflow_context
            .run(|| async {
                secret::generate()
                    .map(|generated| generated.expose().to_string())
                    .map_err(HandlerError::from)
            })
            .name("session secret")
            .await?;
        let (awaitable_id, awaitable) = workflow_context.awakeable::<Json<ResultPayload>>();
        let spawn = SpawnRequest {
            argv,
            awaitable_id: tycho_types::launcher::AwaitableId::parse(&awaitable_id)
                .map_err(|error| TerminalError::new(error.to_string()))?,
            secret: session_secret,
            inbox_socket: None,
            resume_handle: None,
        };
        let spawned = workflow_context
            .object_client::<SessionClient>(session.to_string())
            .spawn(Json(spawn))
            .call()
            .await;
        match spawned.map(Json::into_inner) {
            Ok(SpawnOutcome::Spawned { .. } | SpawnOutcome::Adopted { .. }) => {
                self.watch(
                    workflow_context,
                    session,
                    Box::pin(awaitable.map(Wake::Result)),
                )
                .await
            }
            Ok(SpawnOutcome::Requeue { .. }) | Err(_) => Ok(failed),
        }
    }

    async fn watch<'run>(
        &self,
        workflow_context: &'run WorkflowContext<'_>,
        session: &SessionName,
        awaitable: WakeFuture<'run>,
    ) -> Result<AttemptEnd, TerminalError> {
        let mut futures: DurableFuturesUnordered<WakeFuture<'run>> = DurableFuturesUnordered::new();
        futures.push(awaitable);
        futures.push(timer(workflow_context, self.timing.stall_silence));
        let mut nudged_unix_ms = None;
        for _ in 0..spine::WATCH_ROUNDS_MAX {
            let woke = match futures.next().await {
                Ok(Some((_, woke))) => woke,
                Ok(None) => break,
                Err(cancelled) => {
                    kill(workflow_context, session, false).await;
                    return Err(cancelled);
                }
            };
            match woke {
                Wake::Result(Ok(result)) => return Ok(completed(result.into_inner())),
                Wake::Result(Err(rejected)) => {
                    return Ok(AttemptEnd {
                        exit: ExitState::from_wire(rejected.message()),
                        result: None,
                    })
                }
                Wake::Timer => {}
            }
            match self
                .check(workflow_context, session, nudged_unix_ms)
                .await?
            {
                (WatchStep::Stall, _) => break,
                (WatchStep::Nudge(wait), now) => {
                    nudge(workflow_context, session);
                    nudged_unix_ms = Some(now);
                    futures.push(timer(workflow_context, Duration::from_millis(wait)));
                }
                (WatchStep::Wait(wait), _) => {
                    futures.push(timer(workflow_context, Duration::from_millis(wait)));
                }
            }
        }
        kill(workflow_context, session, true).await;
        Ok(AttemptEnd {
            exit: ExitState::Stalled,
            result: None,
        })
    }

    /// Reads Session state through its shared handler, which never queues behind a port step.
    async fn check(
        &self,
        workflow_context: &WorkflowContext<'_>,
        session: &SessionName,
        nudged_unix_ms: Option<u64>,
    ) -> Result<(WatchStep, u64), TerminalError> {
        let view = workflow_context
            .object_client::<SessionClient>(session.to_string())
            .status()
            .call()
            .await?
            .into_inner();
        let now = workflow_context
            .run(|| async { Ok(wall_clock_unix_ms()) })
            .name("clock")
            .await?;
        let step = view.map_or(WatchStep::Stall, |view| {
            watch_step(now, &view, nudged_unix_ms, &self.timing)
        });
        Ok((step, now))
    }
}

fn timer<'run>(workflow_context: &'run WorkflowContext<'_>, wait: Duration) -> WakeFuture<'run> {
    Box::pin(workflow_context.sleep(wait).map(|_| Wake::Timer))
}

const fn completed(result: ResultPayload) -> AttemptEnd {
    AttemptEnd {
        exit: decode_result(&result),
        result: Some(result),
    }
}

fn nudge(workflow_context: &WorkflowContext<'_>, session: &SessionName) {
    if let Ok(text) = ShortText::parse(NUDGE_TEXT) {
        workflow_context
            .object_client::<SessionClient>(session.to_string())
            .nudge(Json(text))
            .send();
    }
}

/// A kill the port refuses leaves the lease to the reconciler, which expires and reaps it.
async fn kill(
    workflow_context: &WorkflowContext<'_>,
    session: &SessionName,
    save_scrollback: bool,
) {
    let killed = workflow_context
        .object_client::<SessionClient>(session.to_string())
        .kill(Json(KillRequest { save_scrollback }))
        .call()
        .await;
    if killed.is_err() {
        workflow_context
            .object_client::<SessionClient>(session.to_string())
            .expire(Json(ExitState::Killed))
            .send();
    }
}

async fn settle(
    workflow_context: &WorkflowContext<'_>,
    request: &WorkerRunRequest,
    task: &TaskId,
    attempt: Attempt,
    result: Option<&ResultPayload>,
) -> Result<(), HandlerError> {
    let observed = result.map_or(0, |result| {
        result
            .usage
            .input_tokens
            .saturating_add(result.usage.output_tokens)
    });
    workflow_context
        .object_client::<EpicClient>(request.epic.as_str())
        .settle(Json(SettleRequest {
            task: task.clone(),
            attempt: attempt.get(),
            observed,
        }))
        .call()
        .await?;
    if result.is_some() {
        workflow_context
            .object_client::<ReconcilerClient>(RECONCILER_KEY)
            .forget(Json(session_name(request, task, attempt)))
            .send();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tycho_types::envelope::{BranchName, CommitSha, Usage};
    use tycho_types::task_packet::Effort;

    fn attempt(number: u16) -> Attempt {
        Attempt::new(number).unwrap()
    }

    fn result(outcome: Outcome) -> ResultPayload {
        ResultPayload {
            outcome,
            branch: BranchName::parse("wu03/t07").unwrap(),
            head_sha: CommitSha::parse(&"a".repeat(40)).unwrap(),
            criteria: Vec::new(),
            usage: Usage::default(),
        }
    }

    fn routing(fallback: Option<&str>) -> Routing {
        Routing {
            class: RoutingName::parse("implement").unwrap(),
            tier: RoutingName::parse("standard").unwrap(),
            effort: Effort::Medium,
            binding: None,
            rationale: ShortText::parse("routine change").unwrap(),
            fallback_tier: fallback.map(|tier| RoutingName::parse(tier).unwrap()),
        }
    }

    fn view(spawned: u64, heartbeat: Option<u64>, progress_changed: u64) -> SessionView {
        SessionView {
            phase: crate::services::session::SessionPhase::Running,
            vendor: Vendor::Claude,
            pid: 7,
            spawned_unix_ms: spawned,
            heartbeat_unix_ms: heartbeat,
            progress: None,
            progress_changed_unix_ms: progress_changed,
            context_tokens: 0,
            has_resume_handle: false,
            inbox_socket: None,
            handoff_present: false,
            scrollback: None,
            awaiting_reap: false,
        }
    }

    const T1: u64 = 300_000;
    const T2: u64 = 900_000;

    #[test]
    fn every_disposition_decides() {
        let cap = attempt(3);
        let done = result(Outcome::Done);
        assert_eq!(
            after_attempt(&ExitState::Completed, Some(done.clone()), attempt(1), cap),
            AfterAttempt::Finish(WorkerRunOutcome::Completed {
                attempt: 1,
                result: done
            })
        );
        for requeue in [
            ExitState::Stalled,
            ExitState::Killed,
            ExitState::RateLimited,
            ExitState::Failed,
        ] {
            assert_eq!(
                after_attempt(&requeue, None, attempt(1), cap),
                AfterAttempt::Next
            );
        }
        assert_eq!(
            after_attempt(&ExitState::Escalated, None, attempt(2), cap),
            AfterAttempt::Finish(WorkerRunOutcome::Escalated { attempt: 2 })
        );
        assert_eq!(
            after_attempt(&ExitState::TooLarge, None, attempt(1), cap),
            AfterAttempt::Finish(WorkerRunOutcome::Replan { attempt: 1 })
        );
        for stop in [ExitState::Cancelled, ExitState::BudgetExceeded] {
            assert!(matches!(
                after_attempt(&stop, None, attempt(1), cap),
                AfterAttempt::Finish(WorkerRunOutcome::Stopped { attempt: 1, .. })
            ));
        }
        let unknown = ExitState::from_wire("exploded");
        assert!(matches!(
            after_attempt(&unknown, None, attempt(1), cap),
            AfterAttempt::Finish(WorkerRunOutcome::Inbox { attempt: 1, .. })
        ));
    }

    #[test]
    fn the_attempt_cap_ends_the_retry_loop() {
        let cap = attempt(3);
        assert_eq!(
            after_attempt(&ExitState::Stalled, None, attempt(3), cap),
            AfterAttempt::Finish(WorkerRunOutcome::Exhausted { attempts: 3 })
        );
        assert_eq!(
            after_attempt(&ExitState::Completed, None, attempt(2), cap),
            AfterAttempt::Next
        );
    }

    #[test]
    fn results_decode_to_their_disposition() {
        assert_eq!(
            decode_result(&result(Outcome::Done)).disposition(),
            Disposition::Verify
        );
        assert_eq!(
            decode_result(&result(Outcome::NotDone)).disposition(),
            Disposition::Requeue
        );
        assert_eq!(
            ExitState::from_wire("stalled").disposition(),
            Disposition::Requeue
        );
    }

    #[test]
    fn a_failure_moves_up_to_the_fallback_tier() {
        let current = RoutingName::parse("standard").unwrap();
        assert_eq!(
            next_tier(&routing(Some("strong")), &current).as_str(),
            "strong"
        );
        assert_eq!(next_tier(&routing(None), &current).as_str(), "standard");
    }

    #[test]
    fn t1_nudges_once_per_silent_stretch() {
        let timing = Timing::default();
        let silent = view(0, None, 0);
        assert_eq!(watch_step(T1, &silent, None, &timing), WatchStep::Nudge(T1));
        assert_eq!(
            watch_step(T1 + 1_000, &silent, Some(T1), &timing),
            WatchStep::Wait(T1)
        );
        let early = watch_step(1_000, &silent, None, &timing);
        assert_eq!(early, WatchStep::Wait(T1 - 1_000));
    }

    #[test]
    fn t2_keys_on_the_progress_marker_and_not_on_activity() {
        let timing = Timing::default();
        let busy_but_stuck = view(0, Some(T2), 0);
        assert_eq!(
            watch_step(T2, &busy_but_stuck, None, &timing),
            WatchStep::Stall
        );
        let progressing = view(0, Some(T2), T2 - 1_000);
        assert!(matches!(
            watch_step(T2, &progressing, None, &timing),
            WatchStep::Wait(_)
        ));
    }

    #[test]
    fn waits_never_shrink_below_the_floor() {
        let timing = Timing::default();
        let near_stall = view(0, Some(T2 - 10), 0);
        assert_eq!(
            watch_step(T2 - 10, &near_stall, None, &timing),
            WatchStep::Wait(WATCH_WAIT_MIN_MS)
        );
    }

    fn request(argv: usize) -> WorkerRunRequest {
        WorkerRunRequest {
            epic: EpicId::parse("cf7a").unwrap(),
            work_unit: WorkUnitId::parse("wu03").unwrap(),
            vendor: Vendor::Claude,
            argv: vec![ShortText::parse("launcher").unwrap(); argv],
            routing: routing(None),
            ledger: LedgerKind::Seat,
            reservation: 10,
        }
    }

    #[test]
    fn argv_is_bounded_with_room_for_the_tier_flag() {
        assert_eq!(check_request(&request(1)), Ok(()));
        assert_eq!(check_request(&request(0)), Err(RequestError::Argv(0)));
        let over = spine::SPAWN_ARGV_MAX_ITEMS.saturating_sub(1);
        assert_eq!(check_request(&request(over)), Err(RequestError::Argv(over)));
    }

    #[test]
    fn each_attempt_has_its_own_session_name() {
        let task = TaskId::parse("wu03-t07").unwrap();
        let first = session_name(&request(1), &task, attempt(1));
        let second = session_name(&request(1), &task, attempt(2));
        assert_ne!(first, second);
        assert!(first.to_string().starts_with("cf7a.wu03.wrk.claude."));
    }
}

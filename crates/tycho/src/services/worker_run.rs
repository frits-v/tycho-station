//! The `WorkerRun` workflow, keyed by task id: reserve, spawn, race the awaitable against T1
//! and T2, decode the exit, settle on every exit, and retry inside the one run.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use restate_sdk::context::DurableFuture;
use restate_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tycho_types::envelope::{Envelope, Outcome, Payload, ResultPayload, ShortText, Usage};
use tycho_types::exit::{Disposition, ExitState};
use tycho_types::rejection::{Question, decode_rejection};
use tycho_types::service::{Attempt, EpicId, RECONCILER_KEY, TaskId, WorkUnitId};
use tycho_types::session::{SessionKind, SessionName, Suffix, Vendor};
use tycho_types::task_packet::{Effort, RoutingName};

use crate::config::spine;
use crate::config_store::{FactoryConfig, Route};
use crate::services::epic::{
    EpicClient, LedgerKind, ReserveAnswer, ReserveRequest, SettleRequest, SlotLevel,
};
use crate::services::reconciler::ReconcilerClient;
use crate::services::session::{
    KillRequest, SessionClient, SessionView, SpawnOutcome, SpawnRequest,
};
use crate::services::spawner::SpawnTerminal;
use crate::services::workers::{
    WorkerCommand, WorkerEvidence, WorkerPorts, WorkerTaskRequest, worker_command,
};
use crate::services::{
    CODE_BAD_REQUEST, CODE_CANCELLED, CODE_INTERNAL, Ports, Timing, blocking, refuse, secret,
    wall_clock_unix_ms,
};
use crate::vendors::worker::VendorSessionId;

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
    pub routing: WorkerRouting,
    pub ledger: LedgerKind,
    /// Budget reserved per attempt, in the ledger's unit.
    pub reservation: u64,
    /// A headless worker task; with it the run builds the vendor command and `argv` is unused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<WorkerTaskRequest>,
}

/// The run's class and starting tier; the fallback tiers come from the routing table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRouting {
    pub class: RoutingName,
    pub tier: RoutingName,
    pub effort: Effort,
    pub binding: Option<Vendor>,
    pub rationale: ShortText,
}

/// What a run journals at its start and uses for every attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Started {
    route: Route,
    timing: Timing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum WorkerRunOutcome {
    Completed {
        attempt: u16,
        result: ResultPayload,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evidence: Option<WorkerEvidence>,
    },
    Escalated {
        attempt: u16,
        #[serde(default)]
        question: Question,
    },
    Replan {
        attempt: u16,
    },
    Stopped {
        attempt: u16,
        state: String,
    },
    Inbox {
        attempt: u16,
        state: String,
    },
    Exhausted {
        attempts: u16,
    },
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
#[allow(
    clippy::large_enum_variant,
    reason = "one value per attempt, moved once; a box buys nothing"
)]
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
    question: Question,
    attempt: Attempt,
    cap: Attempt,
) -> AfterAttempt {
    let number = attempt.get();
    match (exit.disposition(), result) {
        (Disposition::Verify, Some(result)) => AfterAttempt::Finish(WorkerRunOutcome::Completed {
            attempt: number,
            result,
            evidence: None,
        }),
        (Disposition::Requeue, _) | (Disposition::Verify, None) => {
            if attempt < cap {
                AfterAttempt::Next
            } else {
                AfterAttempt::Finish(WorkerRunOutcome::Exhausted { attempts: number })
            }
        }
        (Disposition::Escalate, _) => AfterAttempt::Finish(WorkerRunOutcome::Escalated {
            attempt: number,
            question,
        }),
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

/// A stop the exit table does not name ends the run; otherwise the disposition decides.
fn decide(end: AttemptEnd, attempt: Attempt, cap: Attempt) -> AfterAttempt {
    match end.stop {
        Some(reason) => AfterAttempt::Finish(WorkerRunOutcome::Stopped {
            attempt: attempt.get(),
            state: reason,
        }),
        None => attach(
            after_attempt(&end.exit, end.result, end.question, attempt, cap),
            end.evidence,
        ),
    }
}

/// Adds a completed attempt's session evidence to its outcome.
#[must_use]
pub fn attach(next: AfterAttempt, evidence: Option<WorkerEvidence>) -> AfterAttempt {
    match next {
        AfterAttempt::Finish(WorkerRunOutcome::Completed {
            attempt, result, ..
        }) => AfterAttempt::Finish(WorkerRunOutcome::Completed {
            attempt,
            result,
            evidence,
        }),
        other => other,
    }
}

/// The tier after `current` on the route, or `current` at the top.
#[must_use]
pub fn next_tier(tiers: &[RoutingName], current: &RoutingName) -> RoutingName {
    tiers
        .iter()
        .skip_while(|tier| *tier != current)
        .nth(1)
        .unwrap_or(current)
        .clone()
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

/// A headless task builds its own command, so only a request without one needs an argv.
pub const fn check_request(request: &WorkerRunRequest) -> Result<(), RequestError> {
    let count = request.argv.len();
    let empty = count == 0 && request.task.is_none();
    if empty || count > spine::SPAWN_ARGV_MAX_ITEMS.saturating_sub(2) {
        return Err(RequestError::Argv(count));
    }
    Ok(())
}

#[must_use]
pub fn session_name(request: &WorkerRunRequest, key: &str, attempt: Attempt) -> SessionName {
    SessionName::unit(
        request.epic.clone(),
        request.work_unit.clone(),
        SessionKind::Worker,
        request.vendor,
        Some(Suffix::for_key(key, attempt)),
    )
}

/// `.` cannot occur in a task id, so `<task>.u<n>` never collides with another task's key.
const UNIT_ATTEMPT_SEPARATOR: &str = ".u";

/// The worker run key for a task under a unit attempt; a workflow key runs once.
#[must_use]
pub fn worker_key(task: &TaskId, unit_attempt: Attempt) -> String {
    if unit_attempt == Attempt::FIRST {
        return task.to_string();
    }
    format!("{task}{UNIT_ATTEMPT_SEPARATOR}{}", unit_attempt.get())
}

/// The task and unit attempt a worker run key names; the inverse of `worker_key`.
pub fn parse_worker_key(key: &str) -> Result<(TaskId, Attempt), String> {
    let (task, unit_attempt) = match key.split_once(UNIT_ATTEMPT_SEPARATOR) {
        None => (key, Attempt::FIRST),
        Some((task, number)) => {
            let digits = !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit());
            let attempt = number
                .parse::<u16>()
                .ok()
                .filter(|_| digits)
                .and_then(|value| Attempt::new(value).ok())
                .filter(|attempt| *attempt != Attempt::FIRST)
                .ok_or_else(|| format!("unit attempt `{number}` in `{key}`"))?;
            (task, attempt)
        }
    };
    let task = TaskId::parse(task).map_err(|error| format!("task id in `{key}`: {error}"))?;
    Ok((task, unit_attempt))
}

/// How a terminal refusal from `Session::spawn` ends the attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnRefusal {
    /// The run was cancelled: kill what may have started, settle, and propagate.
    Cancelled,
    /// The port refused, such as no launcher or an unreadable lease: stop the run.
    Stop,
}

#[must_use]
pub const fn spawn_refusal(code: u16) -> SpawnRefusal {
    if code == CODE_CANCELLED {
        SpawnRefusal::Cancelled
    } else {
        SpawnRefusal::Stop
    }
}

/// Usage in the ledger's own unit: tokens for a seat, micro-dollars when metered.
#[must_use]
pub const fn observed_usage(ledger: LedgerKind, usage: &Usage) -> u64 {
    match ledger {
        LedgerKind::Seat => usage.input_tokens.saturating_add(usage.output_tokens),
        LedgerKind::Metered => usage.cost_micro_dollars,
    }
}

fn argv_with_tier(
    request: &WorkerRunRequest,
    tier: &RoutingName,
) -> Result<Vec<ShortText>, TerminalError> {
    let mut argv = request.argv.clone();
    for item in [TIER_FLAG, tier.as_str()] {
        argv.push(ShortText::parse(item).map_err(|error| TerminalError::new(error.to_string()))?);
    }
    Ok(argv)
}

fn short_texts(words: &[String]) -> Result<Vec<ShortText>, TerminalError> {
    words
        .iter()
        .map(|word| ShortText::parse(word).map_err(|error| TerminalError::new(error.to_string())))
        .collect()
}

/// The tier's model for the vendor, from the routing table the endpoint loaded.
fn model_for(
    config: &FactoryConfig,
    tier: &RoutingName,
    vendor: Vendor,
) -> Result<String, TerminalError> {
    let models = &config
        .routing
        .value
        .tiers
        .get(tier)
        .ok_or_else(|| TerminalError::new(format!("tier {tier} is not in the routing table")))?
        .models;
    match vendor {
        Vendor::Claude => Ok(models.claude.clone()),
        Vendor::Codex => Ok(models.codex.clone()),
        Vendor::Antigravity | Vendor::Amp | Vendor::OpenCode => Err(TerminalError::new(format!(
            "the routing table names no {} model",
            vendor.as_str()
        ))),
    }
}

enum Wake {
    Result(Result<Json<serde_json::Value>, TerminalError>),
    Timer,
}

type WakeFuture<'run> = Pin<Box<dyn DurableFuture<Output = Wake> + Send + 'run>>;

struct AttemptEnd {
    exit: ExitState,
    result: Option<ResultPayload>,
    /// The certified question an `escalated` rejection carried.
    question: Question,
    evidence: Option<WorkerEvidence>,
    /// Set when the run stops for a reason no exit state names, such as a refused spawn.
    stop: Option<String>,
    spawned: bool,
}

impl AttemptEnd {
    const fn exit(exit: ExitState, spawned: bool) -> Self {
        Self {
            exit,
            result: None,
            question: Question::Absent,
            evidence: None,
            stop: None,
            spawned,
        }
    }
}

pub struct WorkerRun {
    timing: Timing,
    config: Arc<FactoryConfig>,
    workers: Option<Arc<WorkerPorts>>,
}

impl WorkerRun {
    #[must_use]
    pub fn new(ports: &Ports) -> Self {
        Self {
            timing: ports.timing,
            config: Arc::clone(&ports.config),
            workers: ports.workers.clone(),
        }
    }
}

impl fmt::Debug for WorkerRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerRun")
            .field("timing", &self.timing)
            .field("config", &self.config.hashes())
            .field("workers", &self.workers)
            .finish()
    }
}

#[restate_sdk::workflow]
impl WorkerRun {
    #[handler(ingress_private)]
    async fn run(
        &self,
        workflow_context: WorkflowContext<'_>,
        request: Json<WorkerRunRequest>,
    ) -> HandlerResult<Json<WorkerRunOutcome>> {
        let request = request.into_inner();
        let key = workflow_context.key().to_string();
        let (task, _) = parse_worker_key(&key)
            .map_err(|error| refuse(CODE_BAD_REQUEST, RequestError::Key(error).to_string()))?;
        check_request(&request).map_err(|error| refuse(CODE_BAD_REQUEST, error.to_string()))?;
        let started = self.start(&workflow_context, &request).await?;
        let cap = Attempt::new(started.route.attempt_cap)
            .map_err(|error| refuse(CODE_INTERNAL, error.to_string()))?;
        let mut tier = request.routing.tier.clone();
        let mut attempt = Attempt::FIRST;
        let run = Run {
            key: &key,
            task: &task,
            request: &request,
            timing: started.timing,
        };
        for _ in 0..cap.get() {
            let end = self
                .attempt(&workflow_context, &run, attempt, &tier)
                .await?;
            match decide(end, attempt, cap) {
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
                    tier = next_tier(&started.route.tiers, &tier);
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

/// What every attempt of one run shares.
struct Run<'a> {
    key: &'a str,
    task: &'a TaskId,
    request: &'a WorkerRunRequest,
    timing: Timing,
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
    /// Journals the route and timing; a class the table does not list, or a tier below its
    /// minimum, ends the run with a bad request.
    async fn start(
        &self,
        workflow_context: &WorkflowContext<'_>,
        request: &WorkerRunRequest,
    ) -> Result<Started, HandlerError> {
        let config = Arc::clone(&self.config);
        let timing = self.timing;
        let class = request.routing.class.clone();
        let tier = request.routing.tier.clone();
        let started = workflow_context
            .run(|| async move {
                config
                    .route(&class, &tier)
                    .map(|route| Json(Started { route, timing }))
                    .map_err(|error| refuse(CODE_BAD_REQUEST, error.to_string()))
            })
            .name("route")
            .await?;
        Ok(started.into_inner())
    }

    /// One attempt; budget is settled on every way out, an error included.
    async fn attempt(
        &self,
        workflow_context: &WorkflowContext<'_>,
        run: &Run<'_>,
        attempt: Attempt,
        tier: &RoutingName,
    ) -> Result<AttemptEnd, HandlerError> {
        if !self.reserve(workflow_context, run, attempt).await? {
            return Ok(AttemptEnd::exit(ExitState::BudgetExceeded, false));
        }
        let session = session_name(run.request, run.key, attempt);
        record(workflow_context, attempt, tier, Some(&session), None);
        let watched = self
            .spawn_and_watch(workflow_context, run, &session, tier)
            .await;
        match watched {
            Ok(end) => {
                settle(
                    workflow_context,
                    run,
                    attempt,
                    end.result.as_ref(),
                    end.spawned,
                )
                .await?;
                Ok(end)
            }
            Err(error) => {
                settle(workflow_context, run, attempt, None, true).await?;
                Err(error.into())
            }
        }
    }

    /// Re-sends the reservation after a full slot; false once the ledger is exhausted.
    async fn reserve(
        &self,
        workflow_context: &WorkflowContext<'_>,
        run: &Run<'_>,
        attempt: Attempt,
    ) -> Result<bool, HandlerError> {
        let reservation = ReserveRequest {
            task: run.task.clone(),
            attempt: attempt.get(),
            level: SlotLevel::Worker,
            ledger: run.request.ledger,
            amount: run.request.reservation,
        };
        for _ in 0..spine::RESERVE_ROUNDS_MAX {
            let answer = workflow_context
                .object_client::<EpicClient>(run.request.epic.as_str())
                .reserve(Json(reservation.clone()))
                .call()
                .await?
                .into_inner();
            match answer {
                ReserveAnswer::Granted | ReserveAnswer::AlreadyHeld => return Ok(true),
                ReserveAnswer::BudgetExhausted => return Ok(false),
                ReserveAnswer::RetryLater => {
                    workflow_context.sleep(run.timing.slot_retry_delay).await?;
                }
            }
        }
        Err(refuse(
            CODE_BAD_REQUEST,
            "no worker slot freed within the reservation rounds",
        ))
    }

    /// The error side kills whatever may have started before it returns.
    async fn spawn_and_watch(
        &self,
        workflow_context: &WorkflowContext<'_>,
        run: &Run<'_>,
        session: &SessionName,
        tier: &RoutingName,
    ) -> Result<AttemptEnd, TerminalError> {
        let (argv, resume_handle) = self
            .attempt_command(workflow_context, run, session, tier)
            .await?;
        let session_secret = workflow_context
            .run(|| async {
                secret::generate()
                    .map(|generated| generated.expose().to_string())
                    .map_err(HandlerError::from)
            })
            .name("session secret")
            .await?;
        let (awaitable_id, awaitable) = workflow_context.awakeable::<Json<serde_json::Value>>();
        let spawn = SpawnRequest {
            argv,
            awaitable_id: tycho_types::launcher::AwaitableId::parse(&awaitable_id)
                .map_err(|error| TerminalError::new(error.to_string()))?,
            secret: session_secret,
            inbox_socket: None,
            resume_handle: resume_handle.clone(),
            terminal: SpawnTerminal::Files,
            working_dir: None,
        };
        let spawned = workflow_context
            .object_client::<SessionClient>(session.to_string())
            .spawn(Json(spawn))
            .call()
            .await;
        match spawned.map(Json::into_inner) {
            Ok(SpawnOutcome::Spawned { .. } | SpawnOutcome::Adopted { .. }) => {
                let awaitable: WakeFuture<'_> = Box::pin(awaitable.map(Wake::Result));
                let watched = self
                    .watch(workflow_context, session, awaitable, &run.timing)
                    .await;
                if watched.is_err() {
                    kill(workflow_context, session, false).await;
                }
                with_evidence(workflow_context, session, resume_handle, watched?).await
            }
            Ok(SpawnOutcome::Requeue { .. }) => Ok(AttemptEnd::exit(ExitState::Failed, false)),
            Err(error) => match spawn_refusal(error.code()) {
                SpawnRefusal::Cancelled => {
                    kill(workflow_context, session, false).await;
                    Err(error)
                }
                SpawnRefusal::Stop => Ok(AttemptEnd {
                    stop: Some(format!("spawn refused: {}", error.message())),
                    ..AttemptEnd::exit(ExitState::Failed, false)
                }),
            },
        }
    }

    /// The launcher's argv with the tier flag, and the vendor session id a headless task
    /// pre-assigns as its resume handle.
    async fn attempt_command(
        &self,
        workflow_context: &WorkflowContext<'_>,
        run: &Run<'_>,
        session: &SessionName,
        tier: &RoutingName,
    ) -> Result<(Vec<ShortText>, Option<ShortText>), TerminalError> {
        let (Some(task), Some(workers)) = (&run.request.task, &self.workers) else {
            return Ok((argv_with_tier(run.request, tier)?, None));
        };
        let model = model_for(&self.config, tier, run.request.vendor)?;
        let workers = Arc::clone(workers);
        let task = task.clone();
        let (vendor, effort, name) = (
            run.request.vendor,
            run.request.routing.effort,
            session.clone(),
        );
        let (words, session_id) = workflow_context
            .run(|| {
                blocking(move || {
                    let session_id =
                        secret::generate()
                            .map_err(HandlerError::from)
                            .and_then(|generated| {
                                VendorSessionId::from_hex(generated.expose())
                                    .map_err(|error| refuse(CODE_INTERNAL, error.to_string()))
                            })?;
                    let command = WorkerCommand {
                        task: &task,
                        vendor,
                        session: &name,
                        model: &model,
                        effort,
                        session_id: &session_id,
                    };
                    worker_command(&workers, &command)
                        .map(|words| Json((words, session_id.as_str().to_string())))
                        .map_err(|error| refuse(CODE_INTERNAL, error))
                })
            })
            .name("worker command")
            .await?
            .into_inner();
        let mut argv = short_texts(&words)?;
        argv.extend(short_texts(&[TIER_FLAG.to_string(), tier.to_string()])?);
        let handle =
            ShortText::parse(&session_id).map_err(|error| TerminalError::new(error.to_string()))?;
        Ok((argv, Some(handle)))
    }

    /// Any error here, a cancel or a failed check, leaves the kill to the caller.
    async fn watch<'run>(
        &self,
        workflow_context: &'run WorkflowContext<'_>,
        session: &SessionName,
        awaitable: WakeFuture<'run>,
        timing: &Timing,
    ) -> Result<AttemptEnd, TerminalError> {
        let mut futures: DurableFuturesUnordered<WakeFuture<'run>> = DurableFuturesUnordered::new();
        futures.push(awaitable);
        futures.push(timer(workflow_context, timing.stall_silence));
        let mut nudged_unix_ms = None;
        for _ in 0..spine::WATCH_ROUNDS_MAX {
            let Some((_, woke)) = futures.next().await? else {
                break;
            };
            if let Wake::Result(completion) = woke {
                forget(workflow_context, session);
                return Ok(match completion {
                    Ok(value) => result_from_envelope(&value.into_inner(), session).map_or_else(
                        |_| AttemptEnd::exit(ExitState::from_wire(RAW_RESULT_INVALID), true),
                        completed,
                    ),
                    Err(rejected) => rejection(rejected.message()),
                });
            }
            let (step, now) = self
                .check(workflow_context, session, nudged_unix_ms, timing)
                .await?;
            let wait = match step {
                WatchStep::Stall => break,
                WatchStep::Nudge(wait) => {
                    nudge(workflow_context, session);
                    nudged_unix_ms = Some(now);
                    wait
                }
                WatchStep::Wait(wait) => wait,
            };
            futures.push(timer(workflow_context, Duration::from_millis(wait)));
        }
        kill(workflow_context, session, true).await;
        Ok(AttemptEnd::exit(ExitState::Stalled, true))
    }

    /// Reads Session state through its shared handler, which never queues behind a port step.
    async fn check(
        &self,
        workflow_context: &WorkflowContext<'_>,
        session: &SessionName,
        nudged_unix_ms: Option<u64>,
        timing: &Timing,
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
            watch_step(now, &view, nudged_unix_ms, timing)
        });
        Ok((step, now))
    }
}

/// A completed attempt reads the session's last context size, which the launcher's final
/// heartbeat wrote before it delivered the result.
async fn with_evidence(
    workflow_context: &WorkflowContext<'_>,
    session: &SessionName,
    resume_handle: Option<ShortText>,
    end: AttemptEnd,
) -> Result<AttemptEnd, TerminalError> {
    if end.result.is_none() {
        return Ok(end);
    }
    let view = workflow_context
        .object_client::<SessionClient>(session.to_string())
        .status()
        .call()
        .await?
        .into_inner();
    Ok(AttemptEnd {
        evidence: Some(WorkerEvidence {
            session: session.clone(),
            resume_handle: resume_handle.map(|handle| handle.as_str().to_string()),
            context_tokens: view.map(|view| view.context_tokens),
        }),
        ..end
    })
}

fn timer<'run>(workflow_context: &'run WorkflowContext<'_>, wait: Duration) -> WakeFuture<'run> {
    Box::pin(workflow_context.sleep(wait).map(|_| Wake::Timer))
}

fn rejection(message: &str) -> AttemptEnd {
    let (exit, question) = decode_rejection(message);
    AttemptEnd {
        question,
        ..AttemptEnd::exit(exit, true)
    }
}

/// Wire text of the state a resolved awaitable takes when its value is not this attempt's
/// result envelope; it decodes as unrecognised and blocks in the inbox.
pub const RAW_RESULT_INVALID: &str = "result_envelope_invalid";

/// The launcher resolves with the result envelope; only a result from this attempt's
/// session counts.
pub fn result_from_envelope(
    value: &serde_json::Value,
    session: &SessionName,
) -> Result<ResultPayload, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let envelope = Envelope::parse(&bytes).map_err(|error| error.to_string())?;
    if envelope.from != *session {
        return Err(format!("envelope from {} not {session}", envelope.from));
    }
    match envelope.payload {
        Payload::Result(result) => Ok(result),
        _ => Err("envelope payload is not a result".to_string()),
    }
}

const fn completed(result: ResultPayload) -> AttemptEnd {
    AttemptEnd {
        exit: decode_result(&result),
        result: Some(result),
        question: Question::Absent,
        evidence: None,
        stop: None,
        spawned: true,
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

/// The awaitable completed, resolved or rejected: the reconciler stops expecting the session.
fn forget(workflow_context: &WorkflowContext<'_>, session: &SessionName) {
    workflow_context
        .object_client::<ReconcilerClient>(RECONCILER_KEY)
        .forget(Json(session.clone()))
        .send();
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
    run: &Run<'_>,
    attempt: Attempt,
    result: Option<&ResultPayload>,
    spawned: bool,
) -> Result<(), HandlerError> {
    let observed = result.map_or(0, |result| {
        observed_usage(run.request.ledger, &result.usage)
    });
    workflow_context
        .object_client::<EpicClient>(run.request.epic.as_str())
        .settle(Json(SettleRequest {
            task: run.task.clone(),
            attempt: attempt.get(),
            observed,
            spawned,
        }))
        .call()
        .await?;
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

    fn routing() -> WorkerRouting {
        WorkerRouting {
            class: RoutingName::parse("implement").unwrap(),
            tier: RoutingName::parse("standard").unwrap(),
            effort: Effort::Medium,
            binding: None,
            rationale: ShortText::parse("routine change").unwrap(),
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
            last_instruction: None,
            release_error: None,
        }
    }

    const T1: u64 = 300_000;
    const T2: u64 = 900_000;

    #[test]
    fn only_a_result_envelope_from_the_attempts_session_resolves() {
        let session = SessionName::parse(crate::exit_decode::tests::SESSION).unwrap();
        let envelope = crate::exit_decode::tests::envelope(crate::exit_decode::tests::SESSION);
        let result = result_from_envelope(&envelope, &session).unwrap();
        assert_eq!(result.outcome, Outcome::Done);
        let other = SessionName::parse("cf7a.wu03.wrk.claude.b2c4").unwrap();
        assert!(result_from_envelope(&envelope, &other).is_err());
        assert!(result_from_envelope(&envelope["payload"], &session).is_err());
        assert_eq!(
            ExitState::from_wire(RAW_RESULT_INVALID).disposition(),
            Disposition::Inbox
        );
    }

    #[test]
    fn evidence_is_attached_only_to_a_completed_outcome() {
        let cap = attempt(3);
        let done = result(Outcome::Done);
        assert_eq!(
            after_attempt(
                &ExitState::Completed,
                Some(done.clone()),
                Question::Absent,
                attempt(1),
                cap
            ),
            AfterAttempt::Finish(WorkerRunOutcome::Completed {
                attempt: 1,
                result: done.clone(),
                evidence: None,
            })
        );
        let evidence = WorkerEvidence {
            session: SessionName::parse("cf7a.wu03.wrk.claude.a1f3").unwrap(),
            resume_handle: Some("3f0c6c1e-6b1a-4a51-9a0e-2a8c5d0c1a10".to_string()),
            context_tokens: Some(33_390),
        };
        assert_eq!(
            attach(
                after_attempt(
                    &ExitState::Completed,
                    Some(done.clone()),
                    Question::Absent,
                    attempt(1),
                    cap
                ),
                Some(evidence.clone())
            ),
            AfterAttempt::Finish(WorkerRunOutcome::Completed {
                attempt: 1,
                result: done,
                evidence: Some(evidence.clone()),
            })
        );
        assert_eq!(
            attach(AfterAttempt::Next, Some(evidence)),
            AfterAttempt::Next
        );
    }

    #[test]
    fn every_disposition_decides() {
        let cap = attempt(3);
        for requeue in [
            ExitState::Stalled,
            ExitState::Killed,
            ExitState::RateLimited,
            ExitState::Failed,
        ] {
            assert_eq!(
                after_attempt(&requeue, None, Question::Absent, attempt(1), cap),
                AfterAttempt::Next
            );
        }
        assert_eq!(
            after_attempt(
                &ExitState::Escalated,
                None,
                Question::Absent,
                attempt(2),
                cap
            ),
            AfterAttempt::Finish(WorkerRunOutcome::Escalated {
                attempt: 2,
                question: Question::Absent
            })
        );
        assert_eq!(
            after_attempt(
                &ExitState::TooLarge,
                None,
                Question::Absent,
                attempt(1),
                cap
            ),
            AfterAttempt::Finish(WorkerRunOutcome::Replan { attempt: 1 })
        );
        for stop in [ExitState::Cancelled, ExitState::BudgetExceeded] {
            assert!(matches!(
                after_attempt(&stop, None, Question::Absent, attempt(1), cap),
                AfterAttempt::Finish(WorkerRunOutcome::Stopped { attempt: 1, .. })
            ));
        }
        let unknown = ExitState::from_wire("exploded");
        assert!(matches!(
            after_attempt(&unknown, None, Question::Absent, attempt(1), cap),
            AfterAttempt::Finish(WorkerRunOutcome::Inbox { attempt: 1, .. })
        ));
    }

    #[test]
    fn a_certified_question_reaches_the_escalated_outcome() {
        let payload: tycho_types::envelope::EscalationPayload = serde_json::from_str(&format!(
            r#"{{"level_reached":"worker","give_up_reason":"policy","question":"sha256:{}","question_type":"authority","options":[],"proposed_ruling":null,"evidence":[],"cases_consulted":[],"blocking":true}}"#,
            "a".repeat(64)
        ))
        .unwrap();
        let message = tycho_types::rejection::encode_escalation(&payload).unwrap();
        let end = rejection(&message);
        assert_eq!(end.exit, ExitState::Escalated);
        assert_eq!(
            after_attempt(&end.exit, None, end.question, attempt(1), attempt(3)),
            AfterAttempt::Finish(WorkerRunOutcome::Escalated {
                attempt: 1,
                question: Question::Certified { payload }
            })
        );
    }

    #[test]
    fn the_attempt_cap_ends_the_retry_loop() {
        let cap = attempt(3);
        assert_eq!(
            after_attempt(&ExitState::Stalled, None, Question::Absent, attempt(3), cap),
            AfterAttempt::Finish(WorkerRunOutcome::Exhausted { attempts: 3 })
        );
        assert_eq!(
            after_attempt(
                &ExitState::Completed,
                None,
                Question::Absent,
                attempt(2),
                cap
            ),
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
    fn a_failure_moves_up_the_route_and_stays_at_the_top() {
        let tiers: Vec<RoutingName> = ["standard", "strong"]
            .iter()
            .map(|tier| RoutingName::parse(tier).unwrap())
            .collect();
        assert_eq!(next_tier(&tiers, &tiers[0]), tiers[1]);
        assert_eq!(next_tier(&tiers, &tiers[1]), tiers[1]);
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
            routing: routing(),
            ledger: LedgerKind::Seat,
            reservation: 10,
            task: None,
        }
    }

    #[test]
    fn argv_is_bounded_with_room_for_the_tier_flag() {
        assert_eq!(check_request(&request(1)), Ok(()));
        assert_eq!(check_request(&request(0)), Err(RequestError::Argv(0)));
        let headless = WorkerRunRequest {
            task: Some(WorkerTaskRequest {
                brief: crate::services::workers::Brief::parse("Make widget::answer return 42.")
                    .unwrap(),
                max_turns: std::num::NonZeroU16::new(8),
                placement: None,
            }),
            ..request(0)
        };
        assert_eq!(check_request(&headless), Ok(()));
        let over = spine::SPAWN_ARGV_MAX_ITEMS.saturating_sub(1);
        assert_eq!(check_request(&request(over)), Err(RequestError::Argv(over)));
    }

    #[test]
    fn each_attempt_has_its_own_session_name() {
        let first = session_name(&request(1), "wu03-t07", attempt(1));
        let second = session_name(&request(1), "wu03-t07", attempt(2));
        assert_ne!(first, second);
        assert!(first.to_string().starts_with("cf7a.wu03.wrk.claude."));
    }

    #[test]
    fn worker_keys_round_trip_and_never_collide_with_a_task_id() {
        let task = TaskId::parse("wu03-t07").unwrap();
        assert_eq!(worker_key(&task, attempt(1)), "wu03-t07");
        let second = worker_key(&task, attempt(2));
        assert_eq!(second, "wu03-t07.u2");
        assert_eq!(parse_worker_key(&second), Ok((task.clone(), attempt(2))));
        assert_eq!(parse_worker_key("wu03-t07"), Ok((task, attempt(1))));
        let lookalike = TaskId::parse("wu03-t07-u2").unwrap();
        assert_ne!(worker_key(&lookalike, attempt(1)), second);
        assert_ne!(
            session_name(&request(1), &second, attempt(1)),
            session_name(&request(1), lookalike.as_str(), attempt(1))
        );
        for bad in [
            "wu03-t07.u1",
            "wu03-t07.u",
            "wu03-t07.u+2",
            "wu03-t07.u0",
            "Bad.u2",
        ] {
            assert!(parse_worker_key(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_cancelled_spawn_propagates_and_any_other_refusal_stops() {
        assert_eq!(spawn_refusal(CODE_CANCELLED), SpawnRefusal::Cancelled);
        for code in [400, 404, 500] {
            assert_eq!(spawn_refusal(code), SpawnRefusal::Stop);
        }
    }

    #[test]
    fn usage_is_charged_in_the_ledger_unit() {
        let usage = Usage {
            input_tokens: 1_200,
            output_tokens: 300,
            cost_micro_dollars: 42_000,
        };
        assert_eq!(observed_usage(LedgerKind::Seat, &usage), 1_500);
        assert_eq!(observed_usage(LedgerKind::Metered, &usage), 42_000);
    }
}

//! The Session virtual object, keyed by zmx session name: what was spawned, its lease, its
//! last progress marker and context size, and its handoff note.

use std::fmt;
use std::sync::Arc;

use restate_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tycho_types::agent_call::{CONTEXT_TOKENS_MAX, HandoffCall, HandoffNote, HeartbeatCall};
use tycho_types::envelope::{ProgressMarker, ShortText};
use tycho_types::exit::ExitState;
use tycho_types::launcher::{AwaitableId, LauncherEnv, SEQUENCE_MAX, SessionSecret};
use tycho_types::lease::{RequeueReason, SpawnDecision, spawn_decision};
use tycho_types::service::RECONCILER_KEY;
use tycho_types::session::{SessionName, Vendor};
use tycho_types::task_packet::AbsolutePath;

use crate::config::spine;
use crate::proxy_audit::AuditRead;
use crate::services::reconciler::{ExpectRequest, ReconcilerClient, fingerprint};
use crate::services::spawner::{LeaseRead, SpawnSpec, SpawnTerminal, Spawner};
use crate::services::{
    CODE_BAD_REQUEST, CODE_CANCELLED, CODE_CONFLICT, CODE_FORBIDDEN, CODE_INTERNAL, CODE_NOT_FOUND,
    Ports, Timing, blocking, refuse, secret, spawner_failure, wall_clock_unix_ms,
};
use crate::vendors::control::{AddressTarget, Delivery, SessionVendor, VendorSessionId};

const STATE_KEY: &str = "session";
const SECRET_KEY: &str = "secret";
/// Instructions remembered per session for deduplication by key; the oldest is dropped.
pub const INSTRUCTIONS_KEPT_MAX: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    Running,
    Killed,
    /// The reconciler found the lease dead; the awaitable was rejected and no pid is trusted.
    Lost,
}

/// Everything about a session except its secret, which lives under its own state key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub phase: SessionPhase,
    pub vendor: Vendor,
    pub control: bool,
    pub pid: u32,
    pub awaitable_id: AwaitableId,
    pub spawned_unix_ms: u64,
    pub heartbeat_unix_ms: Option<u64>,
    pub heartbeat_sequence: Option<u64>,
    pub progress: Option<ProgressMarker>,
    /// When the progress marker last changed; T2 reads this, never the heartbeat time.
    pub progress_changed_unix_ms: u64,
    pub context_tokens: u64,
    pub resume_handle: Option<ShortText>,
    pub inbox_socket: Option<AbsolutePath>,
    pub handoff: Option<HandoffNote>,
    pub scrollback: Option<ShortText>,
    /// A lost session's zmx name still needs killing by name; its pid is never trusted.
    pub awaiting_reap: bool,
    /// The last instructions, newest last, so a repeated key is answered without a re-post.
    #[serde(default)]
    pub instructions: Vec<InstructionRecord>,
    /// Why the vendor port could not remove what it kept for the session once it ended.
    #[serde(default)]
    pub release_error: Option<String>,
    /// The session proxy's decisions as firings and examinations, read once the session
    /// was killed or reaped.
    #[serde(default)]
    pub proxy_audit: Option<AuditRead>,
}

/// Which way an instruction reached the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionPath {
    /// Written to the vendor's per-session inbox socket.
    Socket,
    /// Left for the session's launcher, which posts it to the socket as the vendor user.
    Relay,
    /// Neither the socket nor the relay took it; instructions are never typed.
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionRecord {
    pub key: ShortText,
    pub path: InstructionPath,
    pub delivery: Delivery,
}

/// An instruction from a service: the session secret, an idempotency key, and the text.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructRequest {
    pub secret: String,
    pub key: ShortText,
    pub text: ShortText,
}

impl fmt::Debug for InstructRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructRequest")
            .field("secret", &"redacted")
            .field("key", &self.key)
            .field("text", &self.text)
            .finish()
    }
}

#[must_use]
pub const fn path_for(delivery: &Delivery) -> InstructionPath {
    match delivery {
        Delivery::Relayed { .. } => InstructionPath::Relay,
        written if written.written() => InstructionPath::Socket,
        _ => InstructionPath::Refused,
    }
}

/// The record already kept for this key, if any.
#[must_use]
pub fn kept_instruction<'a>(
    state: &'a SessionState,
    key: &ShortText,
) -> Option<&'a InstructionRecord> {
    state.instructions.iter().find(|record| &record.key == key)
}

/// The state with the record kept, the oldest dropped, and the last socket observed.
#[must_use]
pub fn remember(state: &SessionState, record: InstructionRecord) -> SessionState {
    let mut next = state.clone();
    if let Delivery::Posted { socket } | Delivery::PostedUnclosed { socket } = &record.delivery
        && let Ok(path) = AbsolutePath::parse(socket)
    {
        next.inbox_socket = Some(path);
    }
    next.instructions.push(record);
    let excess = next
        .instructions
        .len()
        .saturating_sub(INSTRUCTIONS_KEPT_MAX);
    next.instructions.drain(..excess);
    next
}

pub fn check_instruct(
    state: &SessionState,
    stored_secret: &str,
    request: &InstructRequest,
) -> Result<(), SessionError> {
    if !secret::matches(stored_secret, &request.secret) {
        return Err(SessionError::Secret);
    }
    if state.phase != SessionPhase::Running {
        return Err(SessionError::Ended);
    }
    Ok(())
}

/// What `status` answers: no secret and no capability, so no awaitable id and no note content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionView {
    pub phase: SessionPhase,
    pub vendor: Vendor,
    pub pid: u32,
    pub spawned_unix_ms: u64,
    pub heartbeat_unix_ms: Option<u64>,
    pub progress: Option<ProgressMarker>,
    pub progress_changed_unix_ms: u64,
    pub context_tokens: u64,
    pub has_resume_handle: bool,
    pub inbox_socket: Option<AbsolutePath>,
    pub handoff_present: bool,
    pub scrollback: Option<ShortText>,
    pub awaiting_reap: bool,
    /// The last instruction's key, path and delivery, a refusal included.
    pub last_instruction: Option<InstructionRecord>,
    #[serde(default)]
    pub release_error: Option<String>,
    #[serde(default)]
    pub proxy_audit: Option<AuditRead>,
}

impl From<&SessionState> for SessionView {
    fn from(state: &SessionState) -> Self {
        Self {
            phase: state.phase,
            vendor: state.vendor,
            pid: state.pid,
            spawned_unix_ms: state.spawned_unix_ms,
            heartbeat_unix_ms: state.heartbeat_unix_ms,
            progress: state.progress.clone(),
            progress_changed_unix_ms: state.progress_changed_unix_ms,
            context_tokens: state.context_tokens,
            has_resume_handle: state.resume_handle.is_some(),
            inbox_socket: state.inbox_socket.clone(),
            handoff_present: state.handoff.is_some(),
            scrollback: state.scrollback.clone(),
            awaiting_reap: state.awaiting_reap,
            last_instruction: state.instructions.last().cloned(),
            release_error: state.release_error.clone(),
            proxy_audit: state.proxy_audit.clone(),
        }
    }
}

/// A running session becomes lost; any other phase stays as it is.
#[must_use]
pub fn expire(state: &SessionState) -> Option<SessionState> {
    if state.phase != SessionPhase::Running {
        return None;
    }
    let mut next = state.clone();
    next.phase = SessionPhase::Lost;
    next.awaiting_reap = true;
    Some(next)
}

/// A lost session awaiting its reap stops awaiting it; any other state stays as it is.
#[must_use]
pub fn reaped(state: &SessionState) -> Option<SessionState> {
    if state.phase != SessionPhase::Lost || !state.awaiting_reap {
        return None;
    }
    let mut next = state.clone();
    next.awaiting_reap = false;
    Some(next)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnRequest {
    pub argv: Vec<ShortText>,
    pub awaitable_id: AwaitableId,
    pub secret: String,
    pub inbox_socket: Option<AbsolutePath>,
    pub resume_handle: Option<ShortText>,
    #[serde(default)]
    pub terminal: SpawnTerminal,
    #[serde(default)]
    pub working_dir: Option<AbsolutePath>,
}

impl fmt::Debug for SpawnRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpawnRequest")
            .field("argv", &self.argv)
            .field("awaitable_id", &self.awaitable_id)
            .field("secret", &"redacted")
            .field("inbox_socket", &self.inbox_socket)
            .field("resume_handle", &self.resume_handle)
            .field("terminal", &self.terminal)
            .field("working_dir", &self.working_dir)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SpawnOutcome {
    Spawned {
        pid: u32,
    },
    Adopted {
        pid: u32,
    },
    /// The name is held by another spawn or a dead one; the caller re-queues under a new attempt.
    Requeue {
        reason: RequeueReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillRequest {
    pub save_scrollback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum KillOutcome {
    Killed { scrollback: Option<ShortText> },
    AlreadyEnded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    Name(String),
    NoSession,
    Ended,
    Secret,
    Sequence(u64),
    Argv(usize),
    ContextTokens(u64),
    Handoff(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(error) => write!(formatter, "key is not a session name: {error}"),
            Self::NoSession => formatter.write_str("no session has been spawned under this key"),
            Self::Ended => formatter.write_str("the session has ended"),
            Self::Secret => formatter.write_str("the session secret does not match"),
            Self::Sequence(sequence) => {
                write!(formatter, "sequence {sequence} exceeds {SEQUENCE_MAX}")
            }
            Self::Argv(count) => write!(
                formatter,
                "argv has {count} items; expected 1..={}",
                spine::SPAWN_ARGV_MAX_ITEMS
            ),
            Self::ContextTokens(count) => write!(
                formatter,
                "context of {count} tokens exceeds {CONTEXT_TOKENS_MAX}"
            ),
            Self::Handoff(error) => write!(formatter, "{error}"),
        }
    }
}

impl SessionError {
    const fn code(&self) -> u16 {
        match self {
            Self::NoSession => CODE_NOT_FOUND,
            Self::Ended => CODE_CONFLICT,
            Self::Secret => CODE_FORBIDDEN,
            Self::Name(_)
            | Self::Sequence(_)
            | Self::Argv(_)
            | Self::ContextTokens(_)
            | Self::Handoff(_) => CODE_BAD_REQUEST,
        }
    }
}

fn terminal(error: &SessionError) -> HandlerError {
    refuse(error.code(), error.to_string())
}

/// Records a beat, `None` for an old sequence; only a changed marker moves the progress time.
pub fn apply_heartbeat(
    state: &SessionState,
    stored_secret: &str,
    call: &HeartbeatCall,
    now_unix_ms: u64,
) -> Result<Option<SessionState>, SessionError> {
    if !secret::matches(stored_secret, &call.secret) {
        return Err(SessionError::Secret);
    }
    if state.phase != SessionPhase::Running {
        return Err(SessionError::Ended);
    }
    if call.sequence > SEQUENCE_MAX {
        return Err(SessionError::Sequence(call.sequence));
    }
    if call.context_tokens > CONTEXT_TOKENS_MAX {
        return Err(SessionError::ContextTokens(call.context_tokens));
    }
    if state
        .heartbeat_sequence
        .is_some_and(|last| call.sequence <= last)
    {
        return Ok(None);
    }
    let mut next = state.clone();
    next.heartbeat_sequence = Some(call.sequence);
    next.heartbeat_unix_ms = Some(now_unix_ms);
    next.context_tokens = call.context_tokens;
    if next.progress.as_ref() != Some(&call.status.progress) {
        next.progress = Some(call.status.progress.clone());
        next.progress_changed_unix_ms = now_unix_ms;
    }
    Ok(Some(next))
}

pub fn apply_handoff(
    state: &SessionState,
    stored_secret: &str,
    call: HandoffCall,
) -> Result<(SessionState, usize), SessionError> {
    if !secret::matches(stored_secret, &call.secret) {
        return Err(SessionError::Secret);
    }
    if state.phase != SessionPhase::Running {
        return Err(SessionError::Ended);
    }
    let length = call
        .note
        .validate()
        .map_err(|error| SessionError::Handoff(error.to_string()))?;
    let mut next = state.clone();
    next.handoff = Some(call.note);
    Ok((next, length))
}

fn parse_key(key: &str) -> Result<SessionName, SessionError> {
    SessionName::parse(key).map_err(|error| SessionError::Name(error.to_string()))
}

fn check_spawn(request: &SpawnRequest) -> Result<(), SessionError> {
    let count = request.argv.len();
    if count == 0 || count > spine::SPAWN_ARGV_MAX_ITEMS {
        return Err(SessionError::Argv(count));
    }
    SessionSecret::parse(&request.secret).map_err(|_| SessionError::Secret)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LeaseObservation {
    lease: LeaseRead,
    now_unix_ms: u64,
}

pub struct Session {
    spawner: Arc<dyn Spawner>,
    vendor: Arc<dyn SessionVendor>,
    timing: Timing,
}

impl Session {
    #[must_use]
    pub fn new(ports: &Ports) -> Self {
        Self {
            spawner: Arc::clone(&ports.spawner),
            vendor: Arc::clone(&ports.vendor),
            timing: ports.timing,
        }
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("spawner", &self.spawner.describe())
            .field("vendor", &self.vendor.describe())
            .field("timing", &self.timing)
            .finish()
    }
}

#[restate_sdk::object]
impl Session {
    /// Adopts a fresh lease from this spawn, spawns when there is none, re-queues otherwise.
    #[handler(ingress_private)]
    async fn spawn(
        &self,
        object_context: ObjectContext<'_>,
        request: Json<SpawnRequest>,
    ) -> HandlerResult<Json<SpawnOutcome>> {
        let request = request.into_inner();
        let name = parse_key(object_context.key()).map_err(|error| terminal(&error))?;
        check_spawn(&request).map_err(|error| terminal(&error))?;
        let observation = self.observe_lease(&object_context, &name).await?;
        let lease = match &observation.lease {
            LeaseRead::Present { lease } => Some(lease),
            LeaseRead::Absent => None,
            LeaseRead::Unreadable { reason } => {
                return Err(refuse(CODE_INTERNAL, format!("lease unreadable: {reason}")));
            }
        };
        let fresh_ms = Timing::millis(self.timing.lease_fresh);
        let decision = spawn_decision(
            lease,
            &name,
            &request.awaitable_id,
            observation.now_unix_ms,
            fresh_ms,
        );
        let (pid, outcome) = match (decision, lease) {
            (SpawnDecision::Adopt | SpawnDecision::AdoptEnded, Some(lease)) => {
                (lease.pid(), SpawnOutcome::Adopted { pid: lease.pid() })
            }
            (SpawnDecision::Spawn | SpawnDecision::Adopt | SpawnDecision::AdoptEnded, _) => {
                let pid = self.start_session(&object_context, &name, &request).await?;
                (pid, SpawnOutcome::Spawned { pid })
            }
            (SpawnDecision::Requeue(reason), _) => {
                return Ok(Json(SpawnOutcome::Requeue { reason }));
            }
        };
        let clock = object_context
            .run(|| async { Ok(wall_clock_unix_ms()) })
            .name("clock after spawn")
            .await;
        match clock {
            Ok(spawned_unix_ms) => {
                record_spawn(&object_context, &name, request, pid, spawned_unix_ms);
                Ok(Json(outcome))
            }
            Err(error) => {
                // A cancel that lands after the process started still records it, so the
                // caller's kill and the reconciler can find it.
                record_spawn(
                    &object_context,
                    &name,
                    request,
                    pid,
                    observation.now_unix_ms,
                );
                Err(error.into())
            }
        }
    }

    #[handler]
    async fn heartbeat(
        &self,
        object_context: ObjectContext<'_>,
        call: Json<HeartbeatCall>,
    ) -> HandlerResult<bool> {
        let (state, stored_secret) = load(&object_context).await?;
        let now_unix_ms = object_context
            .run(|| async { Ok(wall_clock_unix_ms()) })
            .name("clock")
            .await?;
        let next = apply_heartbeat(&state, &stored_secret, &call.into_inner(), now_unix_ms)
            .map_err(|error| terminal(&error))?;
        let recorded = next.is_some();
        if let Some(next) = next {
            object_context.set(STATE_KEY, Json(next));
        }
        Ok(recorded)
    }

    #[handler(ingress_private)]
    async fn nudge(
        &self,
        object_context: ObjectContext<'_>,
        text: Json<ShortText>,
    ) -> HandlerResult<()> {
        let name = parse_key(object_context.key()).map_err(|error| terminal(&error))?;
        let (state, _) = load(&object_context).await?;
        if state.phase != SessionPhase::Running {
            return Err(terminal(&SessionError::Ended));
        }
        let spawner = Arc::clone(&self.spawner);
        let text = text.into_inner();
        object_context
            .run(|| blocking(move || spawner.send(&name, &text).map_err(spawner_failure)))
            .name("nudge")
            .retry_policy(Timing::nudge_retry())
            .await?;
        Ok(())
    }

    /// Posts to the inbox or the relay and records the path; a repeated key returns its record.
    #[handler(ingress_private)]
    async fn instruct(
        &self,
        object_context: ObjectContext<'_>,
        request: Json<InstructRequest>,
    ) -> HandlerResult<Json<InstructionRecord>> {
        let name = parse_key(object_context.key()).map_err(|error| terminal(&error))?;
        let request = request.into_inner();
        let (state, stored_secret) = load(&object_context).await?;
        check_instruct(&state, &stored_secret, &request).map_err(|error| terminal(&error))?;
        if let Some(record) = kept_instruction(&state, &request.key) {
            return Ok(Json(record.clone()));
        }
        let delivery = self
            .post_instruction(&object_context, &state, name, &request)
            .await?;
        let record = InstructionRecord {
            key: request.key,
            path: path_for(&delivery),
            delivery,
        };
        object_context.set(STATE_KEY, Json(remember(&state, record.clone())));
        Ok(Json(record))
    }

    #[handler]
    async fn handoff(
        &self,
        object_context: ObjectContext<'_>,
        call: Json<HandoffCall>,
    ) -> HandlerResult<u64> {
        let (state, stored_secret) = load(&object_context).await?;
        let (next, length) = apply_handoff(&state, &stored_secret, call.into_inner())
            .map_err(|error| terminal(&error))?;
        object_context.set(STATE_KEY, Json(next));
        Ok(u64::try_from(length).unwrap_or(u64::MAX))
    }

    /// Saves scrollback when asked, kills by the recorded pid, and drops the expectation.
    #[handler(ingress_private)]
    async fn kill(
        &self,
        object_context: ObjectContext<'_>,
        request: Json<KillRequest>,
    ) -> HandlerResult<Json<KillOutcome>> {
        let name = parse_key(object_context.key()).map_err(|error| terminal(&error))?;
        let (mut state, _) = load(&object_context).await?;
        if state.phase != SessionPhase::Running {
            return Ok(Json(KillOutcome::AlreadyEnded));
        }
        let scrollback = if request.into_inner().save_scrollback {
            Some(self.save_scrollback(&object_context, &name).await?)
        } else {
            None
        };
        let spawner = Arc::clone(&self.spawner);
        let (target, pid) = (name.clone(), state.pid);
        object_context
            .run(|| blocking(move || spawner.kill(&target, pid).map_err(spawner_failure)))
            .name("kill")
            .retry_policy(self.timing.port_retry())
            .await?;
        if state.proxy_audit.is_none() {
            state.proxy_audit = Some(self.read_proxy_audit(&object_context, &name).await?);
        }
        state.release_error = self.release(&object_context, &name).await?;
        state.phase = SessionPhase::Killed;
        state.scrollback.clone_from(&scrollback);
        object_context.set(STATE_KEY, Json(state));
        object_context
            .object_client::<ReconcilerClient>(RECONCILER_KEY)
            .forget(Json(name))
            .send();
        Ok(Json(KillOutcome::Killed { scrollback }))
    }

    /// The session's awaitable completed, so its launcher has written the proxy's decisions:
    /// reads them once, as the firings and examinations of the session proxy.
    #[handler(ingress_private)]
    async fn record_proxy_audit(&self, object_context: ObjectContext<'_>) -> HandlerResult<bool> {
        let name = parse_key(object_context.key()).map_err(|error| terminal(&error))?;
        let Some(state) = object_context.get::<Json<SessionState>>(STATE_KEY).await? else {
            return Ok(false);
        };
        let mut state = state.into_inner();
        if state.proxy_audit.is_some() {
            return Ok(false);
        }
        state.proxy_audit = Some(self.read_proxy_audit(&object_context, &name).await?);
        object_context.set(STATE_KEY, Json(state));
        Ok(true)
    }

    /// The reconciler's verdict: rejects the awaitable with the exit state, trusts no pid after.
    #[handler(ingress_private)]
    async fn expire(
        &self,
        object_context: ObjectContext<'_>,
        exit: Json<ExitState>,
    ) -> HandlerResult<bool> {
        let Some(state) = object_context.get::<Json<SessionState>>(STATE_KEY).await? else {
            return Ok(false);
        };
        let state = state.into_inner();
        let Some(next) = expire(&state) else {
            return Ok(false);
        };
        let wire: String = exit.into_inner().into();
        object_context.reject_awakeable(state.awaitable_id.as_str(), TerminalError::new(wire));
        object_context.set(STATE_KEY, Json(next));
        object_context
            .object_client::<SessionClient>(object_context.key())
            .reap()
            .send();
        Ok(true)
    }

    /// Kills a lost session by its zmx name through the port, once.
    #[handler(ingress_private)]
    async fn reap(&self, object_context: ObjectContext<'_>) -> HandlerResult<bool> {
        let name = parse_key(object_context.key()).map_err(|error| terminal(&error))?;
        let Some(state) = object_context.get::<Json<SessionState>>(STATE_KEY).await? else {
            return Ok(false);
        };
        let Some(mut next) = reaped(&state.into_inner()) else {
            return Ok(false);
        };
        let spawner = Arc::clone(&self.spawner);
        let target = name.clone();
        object_context
            .run(|| blocking(move || spawner.kill_by_name(&target).map_err(spawner_failure)))
            .name("reap")
            .retry_policy(self.timing.port_retry())
            .await?;
        if next.proxy_audit.is_none() {
            next.proxy_audit = Some(self.read_proxy_audit(&object_context, &name).await?);
        }
        next.release_error = self.release(&object_context, &name).await?;
        object_context.set(STATE_KEY, Json(next));
        Ok(true)
    }

    #[handler]
    async fn status(
        &self,
        shared_context: SharedObjectContext<'_>,
    ) -> HandlerResult<Json<Option<SessionView>>> {
        let state = shared_context.get::<Json<SessionState>>(STATE_KEY).await?;
        Ok(Json(
            state.map(|state| SessionView::from(&state.into_inner())),
        ))
    }
}

impl Session {
    async fn observe_lease(
        &self,
        object_context: &ObjectContext<'_>,
        name: &SessionName,
    ) -> Result<LeaseObservation, HandlerError> {
        let spawner = Arc::clone(&self.spawner);
        let target = name.clone();
        let observation = object_context
            .run(|| {
                blocking(move || {
                    Ok(Json(LeaseObservation {
                        lease: spawner.read_lease(&target),
                        now_unix_ms: wall_clock_unix_ms(),
                    }))
                })
            })
            .name("observe lease")
            .retry_policy(self.timing.port_retry())
            .await?;
        Ok(observation.into_inner())
    }

    async fn start_session(
        &self,
        object_context: &ObjectContext<'_>,
        name: &SessionName,
        request: &SpawnRequest,
    ) -> Result<u32, HandlerError> {
        let session_secret =
            SessionSecret::parse(&request.secret).map_err(|_| terminal(&SessionError::Secret))?;
        let spec = SpawnSpec {
            session: name.clone(),
            terminal: request.terminal,
            working_dir: request.working_dir.clone(),
            argv: request.argv.clone(),
            environment: LauncherEnv {
                awaitable_id: request.awaitable_id.clone(),
                session_secret,
                session_name: name.clone(),
            },
        };
        let spawner = Arc::clone(&self.spawner);
        let started = object_context
            .run(|| blocking(move || spawner.spawn(&spec).map_err(spawner_failure)))
            .name("spawn")
            .retry_policy(self.timing.port_retry())
            .await;
        started.map_err(|error| {
            if error.code() == CODE_CANCELLED {
                record_lost(object_context, name, request);
            }
            HandlerError::from(error)
        })
    }

    /// One journaled post with one attempt: a second write could deliver the line twice.
    async fn post_instruction(
        &self,
        object_context: &ObjectContext<'_>,
        state: &SessionState,
        session: SessionName,
        request: &InstructRequest,
    ) -> Result<Delivery, HandlerError> {
        let Some(vendor_session) = state
            .resume_handle
            .as_ref()
            .and_then(|handle| VendorSessionId::parse(handle.as_str()).ok())
        else {
            return Ok(Delivery::NoSession);
        };
        let vendor = Arc::clone(&self.vendor);
        let target = AddressTarget {
            session,
            vendor_session,
        };
        let (key, text) = (request.key.clone(), request.text.clone());
        let delivery = object_context
            .run(|| blocking(move || Ok(Json(vendor.address(&target, &key, &text)))))
            .name("instruct over the inbox")
            .retry_policy(RunRetryPolicy::new().max_attempts(1))
            .await?;
        Ok(delivery.into_inner())
    }

    /// Removes the vendor port's files for the ended session; a failure is kept on the state
    /// and never undoes the kill.
    async fn release(
        &self,
        object_context: &ObjectContext<'_>,
        name: &SessionName,
    ) -> Result<Option<String>, HandlerError> {
        let vendor = Arc::clone(&self.vendor);
        let target = name.clone();
        let released = object_context
            .run(|| blocking(move || Ok(Json(vendor.release(&target).err()))))
            .name("release")
            .retry_policy(self.timing.port_retry())
            .await?;
        Ok(released.into_inner())
    }

    /// Reads the proxy's decisions the launcher left; a file that cannot be read is kept as
    /// unreadable, never as no decisions.
    async fn read_proxy_audit(
        &self,
        object_context: &ObjectContext<'_>,
        name: &SessionName,
    ) -> Result<AuditRead, HandlerError> {
        let spawner = Arc::clone(&self.spawner);
        let target = name.clone();
        let audit = object_context
            .run(|| blocking(move || Ok(Json(spawner.read_proxy_audit(&target)))))
            .name("proxy audit")
            .retry_policy(self.timing.port_retry())
            .await?;
        Ok(audit.into_inner())
    }

    async fn save_scrollback(
        &self,
        object_context: &ObjectContext<'_>,
        name: &SessionName,
    ) -> Result<ShortText, HandlerError> {
        let spawner = Arc::clone(&self.spawner);
        let target = name.clone();
        let saved = object_context
            .run(|| {
                blocking(move || {
                    spawner
                        .save_scrollback(&target)
                        .map(Json)
                        .map_err(spawner_failure)
                })
            })
            .name("save scrollback")
            .retry_policy(self.timing.port_retry())
            .await?;
        Ok(saved.into_inner())
    }
}

/// The state and expectation a spawn records; `spawned_unix_ms` is read after the spawn step.
#[must_use]
pub fn spawn_record(
    name: &SessionName,
    request: &SpawnRequest,
    pid: u32,
    spawned_unix_ms: u64,
) -> (SessionState, ExpectRequest) {
    let state = SessionState {
        phase: SessionPhase::Running,
        vendor: name.vendor(),
        control: name.level() != tycho_types::session::Level::Worker,
        pid,
        awaitable_id: request.awaitable_id.clone(),
        spawned_unix_ms,
        heartbeat_unix_ms: None,
        heartbeat_sequence: None,
        progress: None,
        progress_changed_unix_ms: spawned_unix_ms,
        context_tokens: 0,
        resume_handle: request.resume_handle.clone(),
        inbox_socket: request.inbox_socket.clone(),
        handoff: None,
        scrollback: None,
        awaiting_reap: false,
        instructions: Vec::new(),
        release_error: None,
        proxy_audit: None,
    };
    let expectation = ExpectRequest {
        session: name.clone(),
        awaitable_fingerprint: fingerprint(&request.awaitable_id),
        since_unix_ms: spawned_unix_ms,
    };
    (state, expectation)
}

/// A cancel during the spawn step leaves the process unknown: the session is recorded lost
/// and reaped by name, since no pid was ever returned.
fn record_lost(object_context: &ObjectContext<'_>, name: &SessionName, request: &SpawnRequest) {
    let (state, _) = spawn_record(name, request, 0, 0);
    let Some(lost) = expire(&state) else {
        return;
    };
    object_context.set(STATE_KEY, Json(lost));
    object_context.set(SECRET_KEY, request.secret.clone());
    object_context
        .object_client::<SessionClient>(name.to_string())
        .reap()
        .send();
}

fn record_spawn(
    object_context: &ObjectContext<'_>,
    name: &SessionName,
    request: SpawnRequest,
    pid: u32,
    spawned_unix_ms: u64,
) {
    let (state, expectation) = spawn_record(name, &request, pid, spawned_unix_ms);
    object_context.set(STATE_KEY, Json(state));
    object_context.set(SECRET_KEY, request.secret);
    object_context
        .object_client::<ReconcilerClient>(RECONCILER_KEY)
        .expect(Json(expectation))
        .send();
}

async fn load(object_context: &ObjectContext<'_>) -> Result<(SessionState, String), HandlerError> {
    let state = object_context
        .get::<Json<SessionState>>(STATE_KEY)
        .await?
        .ok_or_else(|| terminal(&SessionError::NoSession))?;
    let stored_secret = object_context
        .get::<String>(SECRET_KEY)
        .await?
        .ok_or_else(|| terminal(&SessionError::NoSession))?;
    Ok((state.into_inner(), stored_secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tycho_types::agent_call::{HANDOFF_ITEMS_MAX, HANDOFF_NOTE_MAX_BYTES};
    use tycho_types::envelope::{CommitSha, StatusPayload, Usage};

    fn running() -> SessionState {
        SessionState {
            phase: SessionPhase::Running,
            vendor: Vendor::Claude,
            control: false,
            pid: 4242,
            awaitable_id: AwaitableId::parse("sign_1abc").unwrap(),
            spawned_unix_ms: 1_000,
            heartbeat_unix_ms: None,
            heartbeat_sequence: None,
            progress: None,
            progress_changed_unix_ms: 1_000,
            context_tokens: 0,
            resume_handle: None,
            inbox_socket: None,
            handoff: None,
            scrollback: None,
            awaiting_reap: false,
            instructions: Vec::new(),
            release_error: None,
            proxy_audit: None,
        }
    }

    fn the_secret() -> String {
        "s".repeat(40)
    }

    fn beat(head: Option<char>, tests_passing: u32, sequence: u64) -> HeartbeatCall {
        HeartbeatCall {
            secret: the_secret(),
            sequence,
            status: StatusPayload {
                state: None,
                summary: ShortText::parse("working").unwrap(),
                last_progress_unix_ms: 0,
                progress: ProgressMarker {
                    head_sha: head
                        .map(|fill| CommitSha::parse(&fill.to_string().repeat(40)).unwrap()),
                    tests_passing,
                },
                active_workers: 0,
                usage: Usage::default(),
                blockers: Vec::new(),
            },
            context_tokens: 10,
        }
    }

    fn recorded(state: &SessionState, call: &HeartbeatCall, now: u64) -> SessionState {
        apply_heartbeat(state, &the_secret(), call, now)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn heartbeat_with_a_new_marker_moves_progress() {
        let first = recorded(&running(), &beat(Some('a'), 1, 1), 2_000);
        assert_eq!(first.heartbeat_unix_ms, Some(2_000));
        assert_eq!(first.progress_changed_unix_ms, 2_000);
        let second = recorded(&first, &beat(Some('b'), 1, 2), 3_000);
        assert_eq!(second.progress_changed_unix_ms, 3_000);
        assert_eq!(second.heartbeat_sequence, Some(2));
    }

    #[test]
    fn activity_alone_never_moves_progress() {
        let mut state = recorded(&running(), &beat(Some('a'), 3, 1), 2_000);
        for (sequence, now) in [(2, 3_000), (3, 4_000), (4, 5_000)] {
            state = recorded(&state, &beat(Some('a'), 3, sequence), now);
        }
        assert_eq!(state.heartbeat_unix_ms, Some(5_000));
        assert_eq!(state.progress_changed_unix_ms, 2_000);
    }

    #[test]
    fn a_repeated_or_older_sequence_changes_nothing() {
        let state = recorded(&running(), &beat(Some('a'), 1, 5), 2_000);
        for sequence in [5, 4] {
            let again =
                apply_heartbeat(&state, &the_secret(), &beat(Some('b'), 1, sequence), 3_000);
            assert_eq!(again, Ok(None), "sequence {sequence}");
        }
    }

    #[test]
    fn heartbeat_rejects_a_sequence_over_the_maximum() {
        let call = beat(None, 0, SEQUENCE_MAX.saturating_add(1));
        assert!(matches!(
            apply_heartbeat(&running(), &the_secret(), &call, 2_000),
            Err(SessionError::Sequence(_))
        ));
    }

    #[test]
    fn heartbeat_rejects_a_wrong_secret() {
        let mut call = beat(None, 0, 1);
        call.secret = "t".repeat(40);
        assert_eq!(
            apply_heartbeat(&running(), &the_secret(), &call, 2_000),
            Err(SessionError::Secret)
        );
    }

    #[test]
    fn heartbeat_rejects_an_ended_session() {
        let mut state = running();
        state.phase = SessionPhase::Killed;
        assert_eq!(
            apply_heartbeat(&state, &the_secret(), &beat(None, 0, 1), 2_000),
            Err(SessionError::Ended)
        );
    }

    #[test]
    fn heartbeat_rejects_a_context_over_the_maximum() {
        let mut call = beat(None, 0, 1);
        call.context_tokens = CONTEXT_TOKENS_MAX.saturating_add(1);
        assert!(matches!(
            apply_heartbeat(&running(), &the_secret(), &call, 2_000),
            Err(SessionError::ContextTokens(_))
        ));
    }

    fn note(dead_ends: usize, width: usize) -> HandoffNote {
        HandoffNote {
            objective: ShortText::parse("split orders").unwrap(),
            decisions: Vec::new(),
            workers_in_flight: Vec::new(),
            dead_ends: vec![ShortText::parse(&"d".repeat(width)).unwrap(); dead_ends],
            open_questions: Vec::new(),
            next_action: ShortText::parse("verify").unwrap(),
        }
    }

    #[test]
    fn handoff_stores_a_valid_note() {
        let call = HandoffCall {
            secret: the_secret(),
            note: note(1, 8),
        };
        let (next, length) = apply_handoff(&running(), &the_secret(), call).unwrap();
        assert_eq!(next.handoff, Some(note(1, 8)));
        assert!(length > 0);
    }

    #[test]
    fn handoff_rejects_a_note_over_the_size_cap() {
        let call = HandoffCall {
            secret: the_secret(),
            note: note(HANDOFF_ITEMS_MAX, 512),
        };
        assert!(serde_json::to_vec(&call.note).unwrap().len() > HANDOFF_NOTE_MAX_BYTES);
        assert!(matches!(
            apply_handoff(&running(), &the_secret(), call),
            Err(SessionError::Handoff(_))
        ));
    }

    #[test]
    fn handoff_rejects_a_wrong_secret() {
        let call = HandoffCall {
            secret: "t".repeat(40),
            note: note(0, 1),
        };
        assert_eq!(
            apply_handoff(&running(), &the_secret(), call),
            Err(SessionError::Secret)
        );
    }

    fn spawn_request(argv: usize) -> SpawnRequest {
        SpawnRequest {
            argv: vec![ShortText::parse("tycho-launcher").unwrap(); argv],
            awaitable_id: AwaitableId::parse("sign_1abc").unwrap(),
            secret: the_secret(),
            inbox_socket: None,
            resume_handle: None,
            terminal: SpawnTerminal::Files,
            working_dir: None,
        }
    }

    fn instruct_request(secret: String, key: &str) -> InstructRequest {
        InstructRequest {
            secret,
            key: ShortText::parse(key).unwrap(),
            text: ShortText::parse("Task packet sha256:ab").unwrap(),
        }
    }

    fn record(key: &str, delivery: Delivery) -> InstructionRecord {
        InstructionRecord {
            key: ShortText::parse(key).unwrap(),
            path: path_for(&delivery),
            delivery,
        }
    }

    #[test]
    fn an_instruction_needs_the_secret_and_a_running_session() {
        let request = instruct_request(the_secret(), "wu03:packet:1");
        assert_eq!(check_instruct(&running(), &the_secret(), &request), Ok(()));
        let wrong = instruct_request("t".repeat(40), "wu03:packet:1");
        assert_eq!(
            check_instruct(&running(), &the_secret(), &wrong),
            Err(SessionError::Secret)
        );
        let mut killed = running();
        killed.phase = SessionPhase::Killed;
        assert_eq!(
            check_instruct(&killed, &the_secret(), &request),
            Err(SessionError::Ended)
        );
        assert!(!format!("{request:?}").contains(&the_secret()));
    }

    #[test]
    fn an_instruction_takes_the_socket_or_the_relay_and_is_never_typed() {
        let socket = "/tmp/cc-socks/7.sock".to_string();
        assert_eq!(
            path_for(&Delivery::Posted {
                socket: socket.clone()
            }),
            InstructionPath::Socket
        );
        assert_eq!(
            path_for(&Delivery::Replied {
                socket: socket.clone(),
                reply: "?".to_string()
            }),
            InstructionPath::Socket
        );
        assert_eq!(
            path_for(&Delivery::WriteInterrupted {
                socket: socket.clone(),
                sent: 3,
                reason: "reset".to_string()
            }),
            InstructionPath::Socket
        );
        assert_eq!(
            path_for(&Delivery::Relayed {
                file: "a.json".to_string()
            }),
            InstructionPath::Relay
        );
        for unwritten in [
            Delivery::NoSession,
            Delivery::Denied {
                socket: socket.clone(),
            },
            Delivery::Refused { socket },
            Delivery::RelayFailed {
                reason: "r".to_string(),
            },
        ] {
            assert_eq!(path_for(&unwritten), InstructionPath::Refused);
        }
    }

    #[test]
    fn a_repeated_key_is_answered_from_the_record_and_the_kept_list_is_bounded() {
        let socket = "/tmp/cc-socks/7.sock".to_string();
        let posted = record(
            "k0",
            Delivery::Posted {
                socket: socket.clone(),
            },
        );
        let state = remember(&running(), posted.clone());
        assert_eq!(kept_instruction(&state, &posted.key), Some(&posted));
        assert_eq!(
            state.inbox_socket.as_ref().map(AbsolutePath::as_str),
            Some(socket.as_str())
        );
        let mut many = state;
        for index in 1..=INSTRUCTIONS_KEPT_MAX {
            many = remember(&many, record(&format!("k{index}"), Delivery::NoSession));
        }
        assert_eq!(many.instructions.len(), INSTRUCTIONS_KEPT_MAX);
        assert_eq!(
            kept_instruction(&many, &posted.key),
            None,
            "the oldest is dropped"
        );
        assert_eq!(
            many.inbox_socket.as_ref().map(AbsolutePath::as_str),
            Some(socket.as_str()),
            "a refusal keeps the last observed socket"
        );
    }

    #[test]
    fn spawn_rejects_argv_outside_its_bounds() {
        assert_eq!(check_spawn(&spawn_request(1)), Ok(()));
        assert_eq!(check_spawn(&spawn_request(0)), Err(SessionError::Argv(0)));
        let over = spine::SPAWN_ARGV_MAX_ITEMS.saturating_add(1);
        assert_eq!(
            check_spawn(&spawn_request(over)),
            Err(SessionError::Argv(over))
        );
    }

    #[test]
    fn spawn_rejects_a_secret_that_is_too_short() {
        let mut request = spawn_request(1);
        request.secret = "short".to_string();
        assert_eq!(check_spawn(&request), Err(SessionError::Secret));
    }

    #[test]
    fn status_view_carries_no_secret_and_no_capability() {
        let mut state = running();
        state.resume_handle = Some(ShortText::parse("resume-7f3a").unwrap());
        state.handoff = Some(HandoffNote {
            workers_in_flight: vec![tycho_types::agent_call::WorkerInFlight {
                task: tycho_types::service::TaskId::parse("wu03-t07").unwrap(),
                awaitable_id: AwaitableId::parse("sign_1worker").unwrap(),
            }],
            ..note(0, 1)
        });
        let view = serde_json::to_string(&SessionView::from(&state)).unwrap();
        for hidden in ["sign_1abc", "sign_1worker", "resume-7f3a"] {
            assert!(!view.contains(hidden), "{hidden} in {view}");
        }
        assert!(
            !view.contains(&the_secret()),
            "the session secret is in the view"
        );
        assert!(view.contains("\"handoff_present\":true"));
    }

    #[test]
    fn spawn_time_is_read_after_the_spawn_step() {
        use crate::services::reconciler::{Expected, Verdict, judge};
        use crate::services::spawner::LeaseRead;
        let timing = Timing::default();
        let observed_unix_ms = 1_800_000_000_000_u64;
        let three_retries_ms = 10_000 + 20_000 + 40_000;
        let spawned = observed_unix_ms.saturating_add(three_retries_ms);
        let name = SessionName::parse("cf7a.wu03.wrk.claude.a1f3").unwrap();
        let (state, expectation) = spawn_record(&name, &spawn_request(1), 7, spawned);
        assert_eq!(state.spawned_unix_ms, spawned);
        assert_eq!(expectation.since_unix_ms, spawned);
        let expected = Expected {
            awaitable_fingerprint: expectation.awaitable_fingerprint,
            since_unix_ms: expectation.since_unix_ms,
        };
        let now = spawned.saturating_add(1_000);
        assert_eq!(
            judge(&name, &expected, &LeaseRead::Absent, now, &timing),
            Verdict::Starting
        );
        let from_observation = Expected {
            since_unix_ms: observed_unix_ms,
            ..expected
        };
        assert!(matches!(
            judge(&name, &from_observation, &LeaseRead::Absent, now, &timing),
            Verdict::Dead(_)
        ));
    }

    #[test]
    fn handoff_rejects_an_ended_session() {
        for phase in [SessionPhase::Killed, SessionPhase::Lost] {
            let mut state = running();
            state.phase = phase;
            let call = HandoffCall {
                secret: the_secret(),
                note: note(0, 1),
            };
            assert_eq!(
                apply_handoff(&state, &the_secret(), call),
                Err(SessionError::Ended)
            );
        }
    }

    #[test]
    fn a_lost_session_is_reaped_once() {
        let lost = expire(&running()).unwrap();
        assert!(lost.awaiting_reap);
        let done = reaped(&lost).unwrap();
        assert!(!done.awaiting_reap);
        assert_eq!(done.phase, SessionPhase::Lost);
        assert_eq!(reaped(&done), None);
        assert_eq!(reaped(&running()), None);
    }

    #[test]
    fn expire_loses_a_running_session_once() {
        let lost = expire(&running()).unwrap();
        assert_eq!(lost.phase, SessionPhase::Lost);
        assert_eq!(expire(&lost), None);
        assert_eq!(
            apply_heartbeat(&lost, &the_secret(), &beat(None, 0, 1), 2_000),
            Err(SessionError::Ended)
        );
    }

    #[test]
    fn spawn_request_debug_never_prints_the_secret() {
        assert!(!format!("{:?}", spawn_request(1)).contains(&the_secret()));
    }
}

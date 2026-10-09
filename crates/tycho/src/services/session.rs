//! The Session virtual object, keyed by zmx session name: what was spawned, its lease, its
//! last progress marker and context size, and its handoff note.

use std::fmt;
use std::sync::Arc;

use restate_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tycho_types::agent_call::{HandoffCall, HandoffNote, HeartbeatCall, CONTEXT_TOKENS_MAX};
use tycho_types::envelope::{ProgressMarker, ShortText};
use tycho_types::launcher::{AwaitableId, LauncherEnv, SessionSecret, SEQUENCE_MAX};
use tycho_types::lease::{spawn_decision, RequeueReason, SpawnDecision};
use tycho_types::service::RECONCILER_KEY;
use tycho_types::session::{SessionName, Vendor};
use tycho_types::task_packet::AbsolutePath;

use crate::config::spine;
use crate::services::reconciler::{ExpectRequest, ReconcilerClient};
use crate::services::spawner::{LeaseRead, SpawnSpec, Spawner};
use crate::services::{
    blocking, refuse, secret, spawner_failure, wall_clock_unix_ms, Ports, Timing, CODE_BAD_REQUEST,
    CODE_CONFLICT, CODE_FORBIDDEN, CODE_INTERNAL, CODE_NOT_FOUND,
};

const STATE_KEY: &str = "session";
const SECRET_KEY: &str = "secret";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    Running,
    Killed,
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
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnRequest {
    pub argv: Vec<ShortText>,
    pub awaitable_id: AwaitableId,
    pub secret: String,
    pub inbox_socket: Option<AbsolutePath>,
    pub resume_handle: Option<ShortText>,
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

/// Records a beat; `None` for a sequence at or below the last one recorded.
///
/// A marker equal to the last one moves the heartbeat time and never the progress time.
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
    timing: Timing,
}

impl Session {
    #[must_use]
    pub fn new(ports: &Ports) -> Self {
        Self {
            spawner: Arc::clone(&ports.spawner),
            timing: ports.timing,
        }
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("spawner", &self.spawner.describe())
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
                return Err(refuse(CODE_INTERNAL, format!("lease unreadable: {reason}")))
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
            (SpawnDecision::Adopt, Some(lease)) => {
                (lease.pid(), SpawnOutcome::Adopted { pid: lease.pid() })
            }
            (SpawnDecision::Spawn | SpawnDecision::Adopt, _) => {
                let pid = self.start_session(&object_context, &name, &request).await?;
                (pid, SpawnOutcome::Spawned { pid })
            }
            (SpawnDecision::Requeue(reason), _) => {
                return Ok(Json(SpawnOutcome::Requeue { reason }))
            }
        };
        record_spawn(
            &object_context,
            &name,
            request,
            pid,
            observation.now_unix_ms,
        );
        Ok(Json(outcome))
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
            .retry_policy(self.timing.spawn_retry())
            .await?;
        Ok(())
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
            .retry_policy(self.timing.spawn_retry())
            .await?;
        state.phase = SessionPhase::Killed;
        state.scrollback.clone_from(&scrollback);
        object_context.set(STATE_KEY, Json(state));
        object_context
            .object_client::<ReconcilerClient>(RECONCILER_KEY)
            .forget(Json(name))
            .send();
        Ok(Json(KillOutcome::Killed { scrollback }))
    }

    #[handler]
    async fn status(
        &self,
        shared_context: SharedObjectContext<'_>,
    ) -> HandlerResult<Json<Option<SessionState>>> {
        let state = shared_context.get::<Json<SessionState>>(STATE_KEY).await?;
        Ok(Json(state.map(Json::into_inner)))
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
            argv: request.argv.clone(),
            environment: LauncherEnv {
                awaitable_id: request.awaitable_id.clone(),
                session_secret,
                session_name: name.clone(),
            },
        };
        let spawner = Arc::clone(&self.spawner);
        object_context
            .run(|| blocking(move || spawner.spawn(&spec).map_err(spawner_failure)))
            .name("spawn")
            .retry_policy(self.timing.spawn_retry())
            .await
            .map_err(HandlerError::from)
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
            .retry_policy(self.timing.spawn_retry())
            .await?;
        Ok(saved.into_inner())
    }
}

fn record_spawn(
    object_context: &ObjectContext<'_>,
    name: &SessionName,
    request: SpawnRequest,
    pid: u32,
    now_unix_ms: u64,
) {
    let state = SessionState {
        phase: SessionPhase::Running,
        vendor: name.vendor(),
        control: name.level() != tycho_types::session::Level::Worker,
        pid,
        awaitable_id: request.awaitable_id.clone(),
        spawned_unix_ms: now_unix_ms,
        heartbeat_unix_ms: None,
        heartbeat_sequence: None,
        progress: None,
        progress_changed_unix_ms: now_unix_ms,
        context_tokens: 0,
        resume_handle: request.resume_handle,
        inbox_socket: request.inbox_socket,
        handoff: None,
        scrollback: None,
    };
    object_context.set(STATE_KEY, Json(state));
    object_context.set(SECRET_KEY, request.secret);
    object_context
        .object_client::<ReconcilerClient>(RECONCILER_KEY)
        .expect(Json(ExpectRequest {
            session: name.clone(),
            awaitable_id: request.awaitable_id,
            since_unix_ms: now_unix_ms,
        }))
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
        }
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
    fn spawn_request_debug_never_prints_the_secret() {
        assert!(!format!("{:?}", spawn_request(1)).contains(&the_secret()));
    }
}

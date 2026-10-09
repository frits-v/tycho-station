//! The Reconciler virtual object, one key: compares expected sessions against lease files,
//! expires a dead session so its awaitable is rejected and the owner re-queues, and re-sends
//! itself.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use restate_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tycho_types::exit::ExitState;
use tycho_types::launcher::AwaitableId;
use tycho_types::lease::{spawn_decision, RequeueReason, SpawnDecision};
use tycho_types::service::RECONCILER_KEY;
use tycho_types::session::SessionName;

use crate::config::spine;
use crate::services::session::SessionClient;
use crate::services::spawner::{LeaseRead, Spawner};
use crate::services::{blocking, refuse, wall_clock_unix_ms, Ports, Timing, CODE_BAD_REQUEST};

const EXPECTED_KEY: &str = "expected";
const GENERATION_KEY: &str = "generation";
const CURSOR_KEY: &str = "cursor";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectRequest {
    pub session: SessionName,
    pub awaitable_fingerprint: String,
    pub since_unix_ms: u64,
}

/// The awaitable id is a capability, so the reconciler holds only its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expected {
    pub awaitable_fingerprint: String,
    pub since_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedView {
    pub session: String,
    pub since_unix_ms: u64,
}

/// What `status` answers: names and ages, never a fingerprint or an awaitable id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcilerView {
    pub generation: u64,
    pub expected: Vec<ExpectedView>,
}

impl ReconcilerView {
    #[must_use]
    pub fn new(generation: u64, expected: &BTreeMap<String, Expected>) -> Self {
        Self {
            generation,
            expected: expected
                .iter()
                .map(|(session, entry)| ExpectedView {
                    session: session.clone(),
                    since_unix_ms: entry.since_unix_ms,
                })
                .collect(),
        }
    }
}

#[must_use]
pub fn fingerprint(awaitable_id: &AwaitableId) -> String {
    Sha256::digest(awaitable_id.as_str().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .concat()
}

/// What one tick concludes about one expected session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Alive,
    /// No lease yet, inside the spawn grace window.
    Starting,
    /// Dead: the awaitable is rejected with this exit state and the expectation dropped.
    Dead(ExitState),
    /// The lease could not be read; nothing is concluded and the stall timer still runs.
    Unreadable,
}

/// The exit state a dead session's awaitable is rejected with; every one re-queues.
#[must_use]
pub const fn dead_state(reason: Option<RequeueReason>) -> ExitState {
    match reason {
        None
        | Some(
            RequeueReason::Stale | RequeueReason::OtherSession | RequeueReason::OtherAwaitable,
        ) => ExitState::Killed,
        Some(RequeueReason::Ahead) => ExitState::Failed,
    }
}

/// Decides from the lease alone; the lease's awaitable counts only when its fingerprint matches.
#[must_use]
pub fn judge(
    session: &SessionName,
    expected: &Expected,
    lease: &LeaseRead,
    now_unix_ms: u64,
    timing: &Timing,
) -> Verdict {
    let lease = match lease {
        LeaseRead::Unreadable { .. } => return Verdict::Unreadable,
        LeaseRead::Absent => {
            let age = now_unix_ms.saturating_sub(expected.since_unix_ms);
            if age <= Timing::millis(timing.spawn_grace) {
                return Verdict::Starting;
            }
            return Verdict::Dead(dead_state(None));
        }
        LeaseRead::Present { lease } => lease,
    };
    let fresh_ms = Timing::millis(timing.lease_fresh);
    let decision = spawn_decision(
        Some(lease),
        session,
        lease.awaitable_id(),
        now_unix_ms,
        fresh_ms,
    );
    let same_spawn = fingerprint(lease.awaitable_id()) == expected.awaitable_fingerprint;
    match decision {
        SpawnDecision::Requeue(reason) => Verdict::Dead(dead_state(Some(reason))),
        SpawnDecision::Adopt if same_spawn => Verdict::Alive,
        SpawnDecision::Adopt | SpawnDecision::Spawn => {
            Verdict::Dead(dead_state(Some(RequeueReason::OtherAwaitable)))
        }
    }
}

/// The next batch after the cursor, wrapping to the start, at most the per-tick maximum.
#[must_use]
pub fn batch(expected: &BTreeMap<String, Expected>, cursor: Option<&str>) -> Vec<String> {
    let cursor = cursor.unwrap_or_default();
    let after = expected.keys().filter(|name| name.as_str() > cursor);
    let before = expected.keys().filter(|name| name.as_str() <= cursor);
    after
        .chain(before)
        .take(spine::RECONCILER_SESSIONS_MAX_PER_TICK)
        .cloned()
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectError {
    TooMany,
}

impl fmt::Display for ExpectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the reconciler expects {} sessions already",
            spine::RECONCILER_EXPECTED_MAX_SESSIONS
        )
    }
}

pub fn expect(
    expected: &mut BTreeMap<String, Expected>,
    request: ExpectRequest,
) -> Result<(), ExpectError> {
    let name = request.session.to_string();
    if !expected.contains_key(&name) && expected.len() >= spine::RECONCILER_EXPECTED_MAX_SESSIONS {
        return Err(ExpectError::TooMany);
    }
    expected.insert(
        name,
        Expected {
            awaitable_fingerprint: request.awaitable_fingerprint,
            since_unix_ms: request.since_unix_ms,
        },
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TickReport {
    pub generation: u64,
    pub stale_generation: bool,
    pub examined: u32,
    pub alive: u32,
    pub starting: u32,
    pub dead: u32,
    pub unreadable: u32,
}

impl TickReport {
    const fn count(&mut self, verdict: &Verdict) {
        let field = match verdict {
            Verdict::Alive => &mut self.alive,
            Verdict::Starting => &mut self.starting,
            Verdict::Dead(_) => &mut self.dead,
            Verdict::Unreadable => &mut self.unreadable,
        };
        *field = field.saturating_add(1);
        self.examined = self.examined.saturating_add(1);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Observations {
    leases: Vec<(String, LeaseRead)>,
    now_unix_ms: u64,
}

pub struct Reconciler {
    spawner: Arc<dyn Spawner>,
    timing: Timing,
}

impl Reconciler {
    #[must_use]
    pub fn new(ports: &Ports) -> Self {
        Self {
            spawner: Arc::clone(&ports.spawner),
            timing: ports.timing,
        }
    }
}

impl fmt::Debug for Reconciler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Reconciler")
            .field("spawner", &self.spawner.describe())
            .field("timing", &self.timing)
            .finish()
    }
}

#[restate_sdk::object]
impl Reconciler {
    /// Starts a new tick chain; a chain from an earlier generation stops at its next tick.
    #[handler]
    async fn start(&self, object_context: ObjectContext<'_>) -> HandlerResult<u64> {
        let generation = object_context
            .get::<u64>(GENERATION_KEY)
            .await?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| refuse(CODE_BAD_REQUEST, "tick generation overflow"))?;
        object_context.set(GENERATION_KEY, generation);
        object_context
            .object_client::<ReconcilerClient>(RECONCILER_KEY)
            .tick(generation)
            .send();
        Ok(generation)
    }

    #[handler(ingress_private)]
    async fn expect(
        &self,
        object_context: ObjectContext<'_>,
        request: Json<ExpectRequest>,
    ) -> HandlerResult<()> {
        let mut expected = load_expected(&object_context).await?;
        expect(&mut expected, request.into_inner())
            .map_err(|error| refuse(CODE_BAD_REQUEST, error.to_string()))?;
        object_context.set(EXPECTED_KEY, Json(expected));
        Ok(())
    }

    #[handler(ingress_private)]
    async fn forget(
        &self,
        object_context: ObjectContext<'_>,
        session: Json<SessionName>,
    ) -> HandlerResult<bool> {
        let mut expected = load_expected(&object_context).await?;
        let removed = expected.remove(&session.into_inner().to_string()).is_some();
        object_context.set(EXPECTED_KEY, Json(expected));
        Ok(removed)
    }

    #[handler(ingress_private)]
    async fn tick(
        &self,
        object_context: ObjectContext<'_>,
        generation: u64,
    ) -> HandlerResult<Json<TickReport>> {
        let current = object_context
            .get::<u64>(GENERATION_KEY)
            .await?
            .unwrap_or(0);
        if generation != current {
            return Ok(Json(TickReport {
                generation,
                stale_generation: true,
                ..TickReport::default()
            }));
        }
        let mut expected = load_expected(&object_context).await?;
        let cursor = object_context.get::<String>(CURSOR_KEY).await?;
        let names = batch(&expected, cursor.as_deref());
        let observations = self.observe(&object_context, &names).await?;
        let mut report = TickReport {
            generation,
            ..TickReport::default()
        };
        for (name, lease) in &observations.leases {
            conclude(
                &object_context,
                &mut expected,
                name,
                lease,
                observations.now_unix_ms,
                &self.timing,
                &mut report,
            );
        }
        if let Some(last) = names.last() {
            object_context.set(CURSOR_KEY, last.clone());
        }
        object_context.set(EXPECTED_KEY, Json(expected));
        object_context
            .object_client::<ReconcilerClient>(RECONCILER_KEY)
            .tick(generation)
            .send_after(self.timing.reconciler_interval);
        Ok(Json(report))
    }

    #[handler]
    async fn status(
        &self,
        shared_context: SharedObjectContext<'_>,
    ) -> HandlerResult<Json<ReconcilerView>> {
        let generation = shared_context
            .get::<u64>(GENERATION_KEY)
            .await?
            .unwrap_or(0);
        let expected = shared_context
            .get::<Json<BTreeMap<String, Expected>>>(EXPECTED_KEY)
            .await?
            .map(Json::into_inner)
            .unwrap_or_default();
        Ok(Json(ReconcilerView::new(generation, &expected)))
    }
}

impl Reconciler {
    async fn observe(
        &self,
        object_context: &ObjectContext<'_>,
        names: &[String],
    ) -> Result<Observations, HandlerError> {
        let spawner = Arc::clone(&self.spawner);
        let names = names.to_vec();
        let observed = object_context
            .run(|| {
                blocking(move || {
                    let leases = names
                        .into_iter()
                        .map(|name| {
                            let lease = SessionName::parse(&name).map_or_else(
                                |error| LeaseRead::Unreadable {
                                    reason: error.to_string(),
                                },
                                |session| spawner.read_lease(&session),
                            );
                            (name, lease)
                        })
                        .collect();
                    Ok(Json(Observations {
                        leases,
                        now_unix_ms: wall_clock_unix_ms(),
                    }))
                })
            })
            .name("observe leases")
            .await?;
        Ok(observed.into_inner())
    }
}

fn conclude(
    object_context: &ObjectContext<'_>,
    expected: &mut BTreeMap<String, Expected>,
    name: &str,
    lease: &LeaseRead,
    now_unix_ms: u64,
    timing: &Timing,
    report: &mut TickReport,
) {
    let (Some(entry), Ok(session)) = (expected.get(name), SessionName::parse(name)) else {
        return;
    };
    let verdict = judge(&session, entry, lease, now_unix_ms, timing);
    report.count(&verdict);
    if let Verdict::Dead(state) = verdict {
        object_context
            .object_client::<SessionClient>(name)
            .expire(Json(state))
            .send();
        expected.remove(name);
    }
}

async fn load_expected(
    object_context: &ObjectContext<'_>,
) -> Result<BTreeMap<String, Expected>, HandlerError> {
    Ok(object_context
        .get::<Json<BTreeMap<String, Expected>>>(EXPECTED_KEY)
        .await?
        .map(Json::into_inner)
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tycho_types::exit::Disposition;
    use tycho_types::lease::Lease;

    const NOW_MS: u64 = 1_800_000_000_000;

    fn session() -> SessionName {
        SessionName::parse("cf7a.wu03.wrk.claude.a1f3").unwrap()
    }

    fn awaitable() -> AwaitableId {
        AwaitableId::parse("sign_1abc").unwrap()
    }

    fn expected(since: u64) -> Expected {
        Expected {
            awaitable_fingerprint: fingerprint(&awaitable()),
            since_unix_ms: since,
        }
    }

    fn present(session: SessionName, awaitable_id: AwaitableId, heartbeat: u64) -> LeaseRead {
        LeaseRead::Present {
            lease: Lease::new(
                session,
                77,
                awaitable_id,
                NOW_MS.saturating_sub(600_000),
                heartbeat,
            )
            .unwrap(),
        }
    }

    fn verdict(lease: &LeaseRead, since: u64) -> Verdict {
        judge(
            &session(),
            &expected(since),
            lease,
            NOW_MS,
            &Timing::default(),
        )
    }

    #[test]
    fn a_fresh_lease_is_alive() {
        assert_eq!(
            verdict(&present(session(), awaitable(), NOW_MS), NOW_MS),
            Verdict::Alive
        );
    }

    #[test]
    fn no_lease_inside_the_grace_window_is_starting() {
        let grace = Timing::millis(Timing::default().spawn_grace);
        assert_eq!(
            verdict(&LeaseRead::Absent, NOW_MS.saturating_sub(grace)),
            Verdict::Starting
        );
    }

    #[test]
    fn no_lease_after_the_grace_window_is_dead() {
        let grace = Timing::millis(Timing::default().spawn_grace);
        assert_eq!(
            verdict(
                &LeaseRead::Absent,
                NOW_MS.saturating_sub(grace).saturating_sub(1)
            ),
            Verdict::Dead(ExitState::Killed)
        );
    }

    #[test]
    fn a_stale_lease_is_dead() {
        let fresh = Timing::millis(Timing::default().lease_fresh);
        let stale = present(
            session(),
            awaitable(),
            NOW_MS.saturating_sub(fresh).saturating_sub(1),
        );
        assert_eq!(verdict(&stale, NOW_MS), Verdict::Dead(ExitState::Killed));
    }

    #[test]
    fn a_lease_from_the_future_is_dead() {
        let fresh = Timing::millis(Timing::default().lease_fresh);
        let ahead = present(
            session(),
            awaitable(),
            NOW_MS.saturating_add(fresh).saturating_add(1),
        );
        assert_eq!(verdict(&ahead, NOW_MS), Verdict::Dead(ExitState::Failed));
    }

    #[test]
    fn a_lease_for_another_spawn_is_dead() {
        let other_awaitable = present(session(), AwaitableId::parse("sign_1x").unwrap(), NOW_MS);
        assert_eq!(
            verdict(&other_awaitable, NOW_MS),
            Verdict::Dead(ExitState::Killed)
        );
        let other_session = SessionName::parse("cf7a.wu03.wrk.claude.b2").unwrap();
        assert_eq!(
            verdict(&present(other_session, awaitable(), NOW_MS), NOW_MS),
            Verdict::Dead(ExitState::Killed)
        );
    }

    #[test]
    fn an_unreadable_lease_concludes_nothing() {
        let unreadable = LeaseRead::Unreadable {
            reason: "permission denied".to_string(),
        };
        assert_eq!(verdict(&unreadable, 0), Verdict::Unreadable);
    }

    #[test]
    fn every_dead_state_requeues() {
        for reason in [
            None,
            Some(RequeueReason::Stale),
            Some(RequeueReason::Ahead),
            Some(RequeueReason::OtherSession),
            Some(RequeueReason::OtherAwaitable),
        ] {
            let wire: String = dead_state(reason).into();
            assert_eq!(
                ExitState::from_wire(&wire).disposition(),
                Disposition::Requeue,
                "{reason:?}"
            );
        }
    }

    fn names(count: usize) -> BTreeMap<String, Expected> {
        (0..count)
            .map(|index| (format!("cf7a.wu{index:03}.wrk.claude"), expected(0)))
            .collect()
    }

    #[test]
    fn batch_is_bounded_and_walks_from_the_cursor() {
        let all = names(spine::RECONCILER_SESSIONS_MAX_PER_TICK.saturating_add(5));
        let first = batch(&all, None);
        assert_eq!(first.len(), spine::RECONCILER_SESSIONS_MAX_PER_TICK);
        let second = batch(&all, first.last().map(String::as_str));
        assert_eq!(second.len(), spine::RECONCILER_SESSIONS_MAX_PER_TICK);
        assert_eq!(
            second.first().map(String::as_str),
            Some("cf7a.wu032.wrk.claude")
        );
        assert!(second.contains(&"cf7a.wu000.wrk.claude".to_string()));
    }

    #[test]
    fn batch_of_nothing_is_empty() {
        assert!(batch(&BTreeMap::new(), Some("anything")).is_empty());
    }

    #[test]
    fn expect_is_bounded() {
        let mut all = names(spine::RECONCILER_EXPECTED_MAX_SESSIONS);
        let request = ExpectRequest {
            session: session(),
            awaitable_fingerprint: fingerprint(&awaitable()),
            since_unix_ms: 0,
        };
        assert_eq!(expect(&mut all, request.clone()), Err(ExpectError::TooMany));
        all.remove("cf7a.wu000.wrk.claude");
        assert_eq!(expect(&mut all, request.clone()), Ok(()));
        assert_eq!(expect(&mut all, request), Ok(()));
    }

    #[test]
    fn fingerprint_is_stable_and_hides_the_id() {
        let print = fingerprint(&awaitable());
        assert_eq!(print, fingerprint(&awaitable()));
        assert_eq!(print.len(), 64);
        assert!(!print.contains("sign_1abc"));
        assert_ne!(print, fingerprint(&AwaitableId::parse("sign_1x").unwrap()));
    }

    #[test]
    fn status_view_carries_no_capability() {
        let mut all = BTreeMap::new();
        all.insert(session().to_string(), expected(5));
        let view = serde_json::to_string(&ReconcilerView::new(3, &all)).unwrap();
        assert!(!view.contains("sign_1abc"));
        assert!(!view.contains(&fingerprint(&awaitable())));
        assert!(view.contains("cf7a.wu03.wrk.claude.a1f3"));
    }

    #[test]
    fn tick_report_counts_each_verdict() {
        let mut report = TickReport::default();
        for verdict in [
            Verdict::Alive,
            Verdict::Starting,
            Verdict::Dead(ExitState::Killed),
            Verdict::Unreadable,
        ] {
            report.count(&verdict);
        }
        assert_eq!(
            (
                report.examined,
                report.alive,
                report.starting,
                report.dead,
                report.unreadable
            ),
            (4, 1, 1, 1, 1)
        );
    }
}

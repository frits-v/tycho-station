//! The lease file a launcher writes and refreshes, and the adopt or spawn decision
//! a replayed spawn step takes from it.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::launcher::{AwaitableDigest, AwaitableId};
use crate::session::SessionName;

pub const LEASE_SCHEMA_VERSION: u32 = 2;
pub const LEASE_FILE_MAX_BYTES: usize = 4096;
/// `pid_t` is signed and zero or a negative value addresses a process group.
pub const PID_MAX: u32 = 0x7fff_ffff;

/// Carries the awaitable's digest, never its id: the agent user can read the lease.
/// Deserializes only through `LeaseWire` and `validate`, as `parse` does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "LeaseWire")]
pub struct Lease {
    schema_version: u32,
    session: SessionName,
    pid: u32,
    awaitable_sha256: AwaitableDigest,
    started_unix_ms: u64,
    heartbeat_unix_ms: u64,
    /// Set once the launcher's result was acknowledged; the session has ended.
    ended_unix_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseWire {
    schema_version: u32,
    session: SessionName,
    pid: u32,
    awaitable_sha256: AwaitableDigest,
    started_unix_ms: u64,
    heartbeat_unix_ms: u64,
    ended_unix_ms: Option<u64>,
}

impl TryFrom<LeaseWire> for Lease {
    type Error = LeaseError;

    fn try_from(wire: LeaseWire) -> Result<Self, Self::Error> {
        let lease = Self {
            schema_version: wire.schema_version,
            session: wire.session,
            pid: wire.pid,
            awaitable_sha256: wire.awaitable_sha256,
            started_unix_ms: wire.started_unix_ms,
            heartbeat_unix_ms: wire.heartbeat_unix_ms,
            ended_unix_ms: wire.ended_unix_ms,
        };
        lease.validate()?;
        Ok(lease)
    }
}

#[derive(Debug)]
pub enum LeaseError {
    TooLarge(usize),
    Json(serde_json::Error),
    SchemaVersion(u32),
    Pid(u32),
    HeartbeatBeforeStart,
    EndBeforeStart,
}

impl fmt::Display for LeaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(length) => write!(
                formatter,
                "lease file is {length} bytes; maximum is {LEASE_FILE_MAX_BYTES}"
            ),
            Self::Json(error) => write!(formatter, "lease file: {error}"),
            Self::SchemaVersion(version) => write!(
                formatter,
                "lease schema version {version}; expected {LEASE_SCHEMA_VERSION}"
            ),
            Self::Pid(pid) => write!(formatter, "pid {pid} outside 1..={PID_MAX}"),
            Self::HeartbeatBeforeStart => write!(formatter, "heartbeat precedes start"),
            Self::EndBeforeStart => write!(formatter, "end precedes start"),
        }
    }
}

impl std::error::Error for LeaseError {}

/// How a lease relates to now. Only `Fresh` means the session is alive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale,
    /// A heartbeat beyond now plus the threshold; never alive, or a bad clock would keep it so.
    Ahead,
}

/// What a spawn step does with the lease under the name it would spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnDecision {
    /// A fresh lease from this spawn: await the same awaitable.
    Adopt,
    /// This spawn's launcher ended after Restate acknowledged its result: the awaitable is
    /// resolved or rejected, so awaiting it returns at once.
    AdoptEnded,
    /// No lease: spawn under this name.
    Spawn,
    /// Any other lease: a new attempt under a new name; no pid from the lease is ever killed.
    Requeue(RequeueReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequeueReason {
    Stale,
    Ahead,
    OtherSession,
    OtherAwaitable,
}

impl Lease {
    pub fn new(
        session: SessionName,
        pid: u32,
        awaitable_sha256: AwaitableDigest,
        started_unix_ms: u64,
        heartbeat_unix_ms: u64,
    ) -> Result<Self, LeaseError> {
        let lease = Self {
            schema_version: LEASE_SCHEMA_VERSION,
            session,
            pid,
            awaitable_sha256,
            started_unix_ms,
            heartbeat_unix_ms,
            ended_unix_ms: None,
        };
        lease.validate()?;
        Ok(lease)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, LeaseError> {
        if bytes.len() > LEASE_FILE_MAX_BYTES {
            return Err(LeaseError::TooLarge(bytes.len()));
        }
        let wire: LeaseWire = serde_json::from_slice(bytes).map_err(LeaseError::Json)?;
        Self::try_from(wire)
    }

    const fn validate(&self) -> Result<(), LeaseError> {
        if self.schema_version != LEASE_SCHEMA_VERSION {
            return Err(LeaseError::SchemaVersion(self.schema_version));
        }
        if self.pid == 0 || self.pid > PID_MAX {
            return Err(LeaseError::Pid(self.pid));
        }
        if self.heartbeat_unix_ms < self.started_unix_ms {
            return Err(LeaseError::HeartbeatBeforeStart);
        }
        if let Some(ended) = self.ended_unix_ms
            && ended < self.started_unix_ms
        {
            return Err(LeaseError::EndBeforeStart);
        }
        Ok(())
    }

    /// The same lease with a new heartbeat, refused if it would precede the start.
    pub fn renewed(&self, heartbeat_unix_ms: u64) -> Result<Self, LeaseError> {
        let mut lease = self.clone();
        lease.heartbeat_unix_ms = heartbeat_unix_ms;
        lease.validate()?;
        Ok(lease)
    }

    /// The same lease marked ended, refused if the end would precede the start.
    pub fn ended(&self, ended_unix_ms: u64) -> Result<Self, LeaseError> {
        let mut lease = self.clone();
        lease.ended_unix_ms = Some(ended_unix_ms);
        lease.validate()?;
        Ok(lease)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    #[must_use]
    pub const fn session(&self) -> &SessionName {
        &self.session
    }

    /// The launcher's pid, for diagnostics; a reboot can reuse it.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    #[must_use]
    pub const fn awaitable_sha256(&self) -> &AwaitableDigest {
        &self.awaitable_sha256
    }

    #[must_use]
    pub const fn started_unix_ms(&self) -> u64 {
        self.started_unix_ms
    }

    #[must_use]
    pub const fn heartbeat_unix_ms(&self) -> u64 {
        self.heartbeat_unix_ms
    }

    #[must_use]
    pub const fn ended_unix_ms(&self) -> Option<u64> {
        self.ended_unix_ms
    }

    #[must_use]
    pub const fn freshness(&self, now_unix_ms: u64, threshold_ms: u64) -> Freshness {
        if self.heartbeat_unix_ms > now_unix_ms.saturating_add(threshold_ms) {
            return Freshness::Ahead;
        }
        if now_unix_ms.saturating_sub(self.heartbeat_unix_ms) <= threshold_ms {
            return Freshness::Fresh;
        }
        Freshness::Stale
    }
}

/// Adopt only a lease carrying both the expected session and the expected awaitable's digest;
/// an ended one is adopted whatever its age.
#[must_use]
pub fn spawn_decision(
    lease: Option<&Lease>,
    expected_session: &SessionName,
    expected_awaitable: &AwaitableId,
    now_unix_ms: u64,
    threshold_ms: u64,
) -> SpawnDecision {
    let Some(lease) = lease else {
        return SpawnDecision::Spawn;
    };
    if lease.session != *expected_session {
        return SpawnDecision::Requeue(RequeueReason::OtherSession);
    }
    if lease.awaitable_sha256 != AwaitableDigest::of(expected_awaitable) {
        return SpawnDecision::Requeue(RequeueReason::OtherAwaitable);
    }
    if lease.ended_unix_ms.is_some() {
        return SpawnDecision::AdoptEnded;
    }
    match lease.freshness(now_unix_ms, threshold_ms) {
        Freshness::Fresh => SpawnDecision::Adopt,
        Freshness::Stale => SpawnDecision::Requeue(RequeueReason::Stale),
        Freshness::Ahead => SpawnDecision::Requeue(RequeueReason::Ahead),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const THRESHOLD_MS: u64 = 30_000;

    fn awaitable() -> AwaitableId {
        AwaitableId::parse("sign_1abc").unwrap()
    }
    const NOW_MS: u64 = 1_800_000_000_000;

    fn lease_json(pid: u32, heartbeat: u64) -> String {
        format!(
            r#"{{"schema_version":2,"session":"cf7a.wu03.wrk.claude.a1f3","pid":{pid},"awaitable_sha256":"{}","started_unix_ms":{},"heartbeat_unix_ms":{heartbeat}}}"#,
            AwaitableDigest::of(&awaitable()),
            NOW_MS.saturating_sub(60_000)
        )
    }

    fn lease(heartbeat: u64) -> Lease {
        Lease::parse(lease_json(4242, heartbeat).as_bytes()).unwrap()
    }

    #[test]
    fn parses_and_round_trips() {
        let parsed = lease(NOW_MS);
        assert_eq!(parsed.pid(), 4242);
        assert_eq!(parsed.session().to_string(), "cf7a.wu03.wrk.claude.a1f3");
        let bytes = parsed.to_bytes().unwrap();
        assert_eq!(Lease::parse(&bytes).unwrap(), parsed);
    }

    #[test]
    fn rejects_oversized_files() {
        let padded = format!(
            "{}{}",
            lease_json(1, NOW_MS),
            " ".repeat(LEASE_FILE_MAX_BYTES)
        );
        assert!(matches!(
            Lease::parse(padded.as_bytes()),
            Err(LeaseError::TooLarge(_))
        ));
    }

    #[test]
    fn rejects_pids_that_address_groups() {
        assert!(matches!(
            Lease::parse(lease_json(0, NOW_MS).as_bytes()),
            Err(LeaseError::Pid(0))
        ));
        let over = PID_MAX.saturating_add(1);
        assert!(matches!(
            Lease::parse(lease_json(over, NOW_MS).as_bytes()),
            Err(LeaseError::Pid(_))
        ));
    }

    #[test]
    fn rejects_bad_fields() {
        let unknown = lease_json(1, NOW_MS).replace("\"pid\"", "\"extra\":1,\"pid\"");
        assert!(matches!(
            Lease::parse(unknown.as_bytes()),
            Err(LeaseError::Json(_))
        ));
        let version = lease_json(1, NOW_MS).replace("\"schema_version\":2", "\"schema_version\":3");
        assert!(matches!(
            Lease::parse(version.as_bytes()),
            Err(LeaseError::SchemaVersion(3))
        ));
        let bad_name = lease_json(1, NOW_MS).replace("cf7a.wu03.wrk", "cf7a.wu03.run");
        assert!(matches!(
            Lease::parse(bad_name.as_bytes()),
            Err(LeaseError::Json(_))
        ));
        let early = lease_json(1, NOW_MS.saturating_sub(120_000));
        assert!(matches!(
            Lease::parse(early.as_bytes()),
            Err(LeaseError::HeartbeatBeforeStart)
        ));
    }

    #[test]
    fn freshness_against_the_threshold() {
        assert_eq!(
            lease(NOW_MS).freshness(NOW_MS, THRESHOLD_MS),
            Freshness::Fresh
        );
        let edge = NOW_MS.saturating_sub(THRESHOLD_MS);
        assert_eq!(
            lease(edge).freshness(NOW_MS, THRESHOLD_MS),
            Freshness::Fresh
        );
        let old = edge.saturating_sub(1);
        assert_eq!(lease(old).freshness(NOW_MS, THRESHOLD_MS), Freshness::Stale);
        let ahead = NOW_MS.saturating_add(THRESHOLD_MS).saturating_add(1);
        assert_eq!(
            lease(ahead).freshness(NOW_MS, THRESHOLD_MS),
            Freshness::Ahead
        );
    }

    #[test]
    fn spawn_decision_enumerates_each_case() {
        let fresh = lease(NOW_MS);
        let session = fresh.session().clone();
        let awaitable = awaitable();
        let decide = |lease: Option<&Lease>, name: &SessionName, id: &AwaitableId| {
            spawn_decision(lease, name, id, NOW_MS, THRESHOLD_MS)
        };
        assert_eq!(
            decide(Some(&fresh), &session, &awaitable),
            SpawnDecision::Adopt
        );
        assert_eq!(decide(None, &session, &awaitable), SpawnDecision::Spawn);
        let stale = lease(NOW_MS.saturating_sub(THRESHOLD_MS).saturating_sub(1));
        assert_eq!(
            decide(Some(&stale), &session, &awaitable),
            SpawnDecision::Requeue(RequeueReason::Stale)
        );
        let ahead = lease(NOW_MS.saturating_add(THRESHOLD_MS).saturating_add(1));
        assert_eq!(
            decide(Some(&ahead), &session, &awaitable),
            SpawnDecision::Requeue(RequeueReason::Ahead)
        );
    }

    #[test]
    fn a_lease_for_another_session_or_awaitable_is_never_adopted() {
        let fresh = lease(NOW_MS);
        let awaitable = awaitable();
        let other = SessionName::parse("cf7a.wu03.wrk.claude.b2").unwrap();
        assert_eq!(
            spawn_decision(Some(&fresh), &other, &awaitable, NOW_MS, THRESHOLD_MS),
            SpawnDecision::Requeue(RequeueReason::OtherSession)
        );
        let other_id = AwaitableId::parse("sign_1other").unwrap();
        assert_eq!(
            spawn_decision(
                Some(&fresh),
                fresh.session(),
                &other_id,
                NOW_MS,
                THRESHOLD_MS
            ),
            SpawnDecision::Requeue(RequeueReason::OtherAwaitable)
        );
    }

    #[test]
    fn serde_deserialization_validates_like_parse() {
        let valid: Lease = serde_json::from_str(&lease_json(4242, NOW_MS)).unwrap();
        assert_eq!(valid, lease(NOW_MS));
        for invalid in [
            lease_json(0, NOW_MS),
            lease_json(PID_MAX.saturating_add(1), NOW_MS),
            lease_json(1, NOW_MS.saturating_sub(120_000)),
            lease_json(1, NOW_MS).replace("\"schema_version\":2", "\"schema_version\":3"),
            lease_json(1, NOW_MS).replace("\"pid\"", "\"extra\":1,\"pid\""),
        ] {
            let decoded: Result<Lease, _> = serde_json::from_str(&invalid);
            assert!(decoded.is_err(), "{invalid}");
        }
    }

    #[test]
    fn writer_cannot_build_a_lease_the_reader_rejects() {
        let session = SessionName::parse("cf7a.wu03.wrk.claude.a1f3").unwrap();
        let awaitable = AwaitableDigest::of(&awaitable());
        assert!(matches!(
            Lease::new(session.clone(), 0, awaitable.clone(), NOW_MS, NOW_MS),
            Err(LeaseError::Pid(0))
        ));
        assert!(matches!(
            Lease::new(
                session.clone(),
                7,
                awaitable.clone(),
                NOW_MS,
                NOW_MS.saturating_sub(1)
            ),
            Err(LeaseError::HeartbeatBeforeStart)
        ));
        let built = Lease::new(session, 7, awaitable, NOW_MS, NOW_MS).unwrap();
        assert_eq!(Lease::parse(&built.to_bytes().unwrap()).unwrap(), built);
        let renewed = built.renewed(NOW_MS.saturating_add(5)).unwrap();
        assert_eq!(renewed.heartbeat_unix_ms(), NOW_MS.saturating_add(5));
        assert!(built.renewed(NOW_MS.saturating_sub(1)).is_err());
        assert!(matches!(
            built.ended(NOW_MS.saturating_sub(1)),
            Err(LeaseError::EndBeforeStart)
        ));
    }

    #[test]
    fn the_lease_never_carries_the_awaitable_id() {
        let bytes = lease(NOW_MS).to_bytes().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("sign_1abc"), "{text}");
        assert!(text.contains(AwaitableDigest::of(&awaitable()).as_str()));
    }

    #[test]
    fn an_ended_lease_is_adopted_ended_at_any_age_and_only_for_its_own_awaitable() {
        let ended = lease(NOW_MS.saturating_sub(THRESHOLD_MS).saturating_sub(1))
            .ended(NOW_MS.saturating_sub(THRESHOLD_MS))
            .unwrap();
        let session = ended.session().clone();
        let much_later = NOW_MS.saturating_add(86_400_000);
        assert_eq!(
            spawn_decision(
                Some(&ended),
                &session,
                &awaitable(),
                much_later,
                THRESHOLD_MS
            ),
            SpawnDecision::AdoptEnded
        );
        let other = AwaitableId::parse("sign_1other").unwrap();
        assert_eq!(
            spawn_decision(Some(&ended), &session, &other, NOW_MS, THRESHOLD_MS),
            SpawnDecision::Requeue(RequeueReason::OtherAwaitable)
        );
        let parsed = Lease::parse(&ended.to_bytes().unwrap()).unwrap();
        assert_eq!(
            parsed.ended_unix_ms(),
            Some(NOW_MS.saturating_sub(THRESHOLD_MS))
        );
    }
}

//! The lease file a launcher writes and refreshes, and the adopt or spawn decision
//! a replayed spawn step takes from it.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::launcher::AwaitableId;
use crate::session::SessionName;

pub const LEASE_SCHEMA_VERSION: u32 = 1;
pub const LEASE_FILE_MAX_BYTES: usize = 4096;
/// `pid_t` is signed; zero and negative values address process groups, so a
/// lease can only ever name a single positive pid.
pub const PID_MAX: u32 = 0x7fff_ffff;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub schema_version: u32,
    pub session: SessionName,
    /// The launcher's pid. Kill goes by this pid, because a job that traps
    /// hangup outlives its zmx session and disappears from the session list.
    pub pid: u32,
    /// The awaitable the launcher resolves; an adopting step awaits this one.
    pub awaitable_id: AwaitableId,
    pub started_unix_ms: u64,
    pub heartbeat_unix_ms: u64,
}

#[derive(Debug)]
pub enum LeaseError {
    TooLarge(usize),
    Json(serde_json::Error),
    SchemaVersion(u32),
    Pid(u32),
    HeartbeatBeforeStart,
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
        }
    }
}

impl std::error::Error for LeaseError {}

/// How a lease relates to now. Only `Fresh` means the session is alive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale,
    /// The heartbeat is further in the future than the threshold allows. Treating
    /// it as fresh would keep a dead session alive until the clock catches up.
    Ahead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnDecision {
    Adopt,
    Spawn,
}

impl Lease {
    pub fn parse(bytes: &[u8]) -> Result<Self, LeaseError> {
        if bytes.len() > LEASE_FILE_MAX_BYTES {
            return Err(LeaseError::TooLarge(bytes.len()));
        }
        let lease: Self = serde_json::from_slice(bytes).map_err(LeaseError::Json)?;
        if lease.schema_version != LEASE_SCHEMA_VERSION {
            return Err(LeaseError::SchemaVersion(lease.schema_version));
        }
        if lease.pid == 0 || lease.pid > PID_MAX {
            return Err(LeaseError::Pid(lease.pid));
        }
        if lease.heartbeat_unix_ms < lease.started_unix_ms {
            return Err(LeaseError::HeartbeatBeforeStart);
        }
        Ok(lease)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
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

/// Adopt only a fresh lease written for the expected session.
///
/// Anything else spawns, after killing any recorded pid, because zmx run on an
/// existing name types into that session instead of failing.
#[must_use]
pub fn spawn_decision(
    lease: Option<&Lease>,
    expected: &SessionName,
    now_unix_ms: u64,
    threshold_ms: u64,
) -> SpawnDecision {
    let Some(lease) = lease else {
        return SpawnDecision::Spawn;
    };
    if lease.session != *expected {
        return SpawnDecision::Spawn;
    }
    match lease.freshness(now_unix_ms, threshold_ms) {
        Freshness::Fresh => SpawnDecision::Adopt,
        Freshness::Stale | Freshness::Ahead => SpawnDecision::Spawn,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const THRESHOLD_MS: u64 = 30_000;
    const NOW_MS: u64 = 1_800_000_000_000;

    fn lease_json(pid: u32, heartbeat: u64) -> String {
        format!(
            r#"{{"schema_version":1,"session":"cf7a.wu03.wrk.claude.a1f3","pid":{pid},"awaitable_id":"sign_1abc","started_unix_ms":{},"heartbeat_unix_ms":{heartbeat}}}"#,
            NOW_MS.saturating_sub(60_000)
        )
    }

    fn lease(heartbeat: u64) -> Lease {
        Lease::parse(lease_json(4242, heartbeat).as_bytes()).unwrap()
    }

    #[test]
    fn parses_and_round_trips() {
        let parsed = lease(NOW_MS);
        assert_eq!(parsed.pid, 4242);
        assert_eq!(parsed.session.to_string(), "cf7a.wu03.wrk.claude.a1f3");
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
        let version = lease_json(1, NOW_MS).replace("\"schema_version\":1", "\"schema_version\":2");
        assert!(matches!(
            Lease::parse(version.as_bytes()),
            Err(LeaseError::SchemaVersion(2))
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
    fn adopts_only_a_fresh_lease_for_the_same_session() {
        let fresh = lease(NOW_MS);
        let expected = fresh.session.clone();
        let decide = |lease: Option<&Lease>, name: &SessionName| {
            spawn_decision(lease, name, NOW_MS, THRESHOLD_MS)
        };
        assert_eq!(decide(Some(&fresh), &expected), SpawnDecision::Adopt);
        assert_eq!(decide(None, &expected), SpawnDecision::Spawn);
        let stale = lease(NOW_MS.saturating_sub(THRESHOLD_MS).saturating_sub(1));
        assert_eq!(decide(Some(&stale), &expected), SpawnDecision::Spawn);
        let other = SessionName::parse("cf7a.wu03.wrk.claude.b2").unwrap();
        assert_eq!(decide(Some(&fresh), &other), SpawnDecision::Spawn);
    }
}

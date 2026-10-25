//! The result spool: written and synced before the awaitable is resolved, delivered to the
//! ingress with backoff until Restate acknowledges, and replayable when it never did.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tycho_types::envelope::{ENVELOPE_MAX_BYTES, Envelope, Payload};
use tycho_types::exit::ExitState;
use tycho_types::launcher::{AwaitableId, IdempotencyKey};
use tycho_types::rejection::encode_escalation;
use tycho_types::service::handler::SESSION_HEARTBEAT;
use tycho_types::session::SessionName;

use crate::agent_files::{read_checked, write_new};
use crate::config::CorePorts;
use crate::http::{Http, Outcome};

pub const SPOOL_SCHEMA_VERSION: u32 = 1;
pub const SPOOL_FILE: &str = "result.spool";
/// The spool renamed once Restate acknowledged it.
pub const ACKNOWLEDGED_SUFFIX: &str = "acknowledged";
pub const SPOOL_FILE_MAX_BYTES: usize = ENVELOPE_MAX_BYTES + 4096;
pub const BACKOFF_FIRST: Duration = Duration::from_secs(10);
pub const BACKOFF_CAP: Duration = Duration::from_mins(5);
pub const DELIVERY_ATTEMPTS_MAX: u32 = 32;
pub const DELIVERY_DEADLINE: Duration = Duration::from_hours(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpoolRecord {
    pub schema_version: u32,
    pub session: SessionName,
    pub awaitable_id: AwaitableId,
    pub state: ExitState,
    /// Present only with `completed`: the result envelope the awaitable resolves with.
    pub envelope: Option<serde_json::Value>,
}

/// What a spool record asks of the ingress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    Resolve(String),
    Reject(String),
}

#[derive(Debug)]
pub enum SpoolError {
    Missing(PathBuf),
    Io(PathBuf, io::Error),
    TooLarge(usize),
    Json(serde_json::Error),
    SchemaVersion(u32),
    /// `completed` without a valid result envelope from the session, or an envelope on a failure.
    Inconsistent(String),
}

impl fmt::Display for SpoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(path) => write!(formatter, "no spool at {}", path.display()),
            Self::Io(path, error) => write!(formatter, "{}: {error}", path.display()),
            Self::TooLarge(length) => write!(
                formatter,
                "spool is {length} bytes; maximum is {SPOOL_FILE_MAX_BYTES}"
            ),
            Self::Json(error) => write!(formatter, "spool: {error}"),
            Self::SchemaVersion(version) => write!(
                formatter,
                "spool schema version {version}; expected {SPOOL_SCHEMA_VERSION}"
            ),
            Self::Inconsistent(reason) => write!(formatter, "spool: {reason}"),
        }
    }
}

impl std::error::Error for SpoolError {}

/// Checks an envelope is a result from `session` and returns its wire bytes.
pub fn check_result_envelope(
    value: &serde_json::Value,
    session: &SessionName,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let envelope = Envelope::parse(&bytes).map_err(|error| error.to_string())?;
    if envelope.from != *session {
        return Err(format!("envelope from {} not {session}", envelope.from));
    }
    if !matches!(envelope.payload, Payload::Result(_)) {
        return Err("envelope payload is not a result".to_string());
    }
    String::from_utf8(bytes).map_err(|error| error.to_string())
}

/// The rejection message an escalation envelope from this session carries: `escalated`, a
/// newline and the certified question.
pub fn escalation_rejection(
    value: &serde_json::Value,
    session: &SessionName,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let envelope = Envelope::parse(&bytes).map_err(|error| error.to_string())?;
    if envelope.from != *session {
        return Err(format!("envelope from {} not {session}", envelope.from));
    }
    match envelope.payload {
        Payload::Escalation(payload) => {
            encode_escalation(&payload).map_err(|error| error.to_string())
        }
        _ => Err("envelope payload is not an escalation".to_string()),
    }
}

impl SpoolRecord {
    pub fn resolution(&self) -> Result<Resolution, SpoolError> {
        if self.schema_version != SPOOL_SCHEMA_VERSION {
            return Err(SpoolError::SchemaVersion(self.schema_version));
        }
        match (&self.state, &self.envelope) {
            (ExitState::Completed, Some(envelope)) => {
                check_result_envelope(envelope, &self.session)
                    .map(Resolution::Resolve)
                    .map_err(SpoolError::Inconsistent)
            }
            (ExitState::Completed, None) => Err(SpoolError::Inconsistent(
                "completed without an envelope".to_string(),
            )),
            (ExitState::Escalated, Some(envelope)) => escalation_rejection(envelope, &self.session)
                .map(Resolution::Reject)
                .map_err(SpoolError::Inconsistent),
            (_, Some(_)) => Err(SpoolError::Inconsistent(
                "an envelope on a failure state".to_string(),
            )),
            (state, None) => Ok(Resolution::Reject(String::from(state.clone()))),
        }
    }
}

pub fn write_spool(path: &Path, record: &SpoolRecord) -> Result<(), SpoolError> {
    record.resolution()?;
    let bytes = serde_json::to_vec(record).map_err(SpoolError::Json)?;
    if bytes.len() > SPOOL_FILE_MAX_BYTES {
        return Err(SpoolError::TooLarge(bytes.len()));
    }
    write_new(path, &bytes).map_err(|error| SpoolError::Io(path.to_path_buf(), error))
}

/// Reads a spool only when it is a regular file of `owner` within the size cap.
pub fn read_spool(path: &Path, owner: u32) -> Result<SpoolRecord, SpoolError> {
    let bytes = read_checked(path, SPOOL_FILE_MAX_BYTES, Some(owner))
        .map_err(|error| match error.kind() {
            io::ErrorKind::InvalidData => SpoolError::TooLarge(SPOOL_FILE_MAX_BYTES + 1),
            _ => SpoolError::Io(path.to_path_buf(), error),
        })?
        .ok_or_else(|| SpoolError::Missing(path.to_path_buf()))?;
    let record: SpoolRecord = serde_json::from_slice(&bytes).map_err(SpoolError::Json)?;
    record.resolution()?;
    Ok(record)
}

/// How Restate answered one resolve or reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ack {
    /// 2xx: Restate took it; a repeat of a completed awakeable also answers 202.
    Acknowledged,
    /// 4xx: a malformed id or body; retrying cannot help.
    Refused(u16, String),
    /// Unreachable or 5xx.
    Retry(String),
    Unrecognised(String),
}

#[must_use]
pub fn decode_ack(outcome: Outcome) -> Ack {
    match outcome {
        Outcome::Response { status, .. } if (200..=299).contains(&status) => Ack::Acknowledged,
        Outcome::Response { status, body } if (400..=499).contains(&status) => {
            Ack::Refused(status, body)
        }
        Outcome::Response { status, .. } if (500..=599).contains(&status) => {
            Ack::Retry(format!("status {status}"))
        }
        Outcome::Response { status, .. } => Ack::Unrecognised(format!("status {status}")),
        Outcome::Unreachable(reason) => Ack::Retry(reason),
        Outcome::BodyTooLarge => Ack::Unrecognised("body over the limit".to_string()),
    }
}

/// The ingress calls a launcher makes; a test double records what it was sent.
pub trait Ingress {
    fn deliver(&self, awaitable: &AwaitableId, resolution: &Resolution) -> Ack;

    /// Sends `body` to `/<service>/<session>/heartbeat/send` with its idempotency key.
    fn heartbeat(&self, call: &HeartbeatSend<'_>) -> Ack;
}

/// One heartbeat send: the target, the key and the JSON body, which carries the secret.
#[derive(Debug)]
pub struct HeartbeatSend<'a> {
    pub service: &'a str,
    pub session: &'a SessionName,
    pub idempotency_key: &'a IdempotencyKey,
    pub body: String,
}

/// The core's ingress over HTTP, at the ports the launcher was handed.
#[derive(Debug, Clone)]
pub struct CoreIngress {
    pub http: Http,
    pub ports: CorePorts,
}

impl Ingress for CoreIngress {
    fn deliver(&self, awaitable: &AwaitableId, resolution: &Resolution) -> Ack {
        let (verb, content_type, body) = match resolution {
            Resolution::Resolve(body) => ("resolve", "application/json", body),
            Resolution::Reject(reason) => ("reject", "text/plain", reason),
        };
        let url = self
            .ports
            .ingress_url(&format!("/restate/awakeables/{awaitable}/{verb}"));
        decode_ack(self.http.post(&url, content_type, &[], body.clone()))
    }

    fn heartbeat(&self, call: &HeartbeatSend<'_>) -> Ack {
        let url = self.ports.ingress_url(&format!(
            "/{}/{}/{SESSION_HEARTBEAT}/send",
            call.service, call.session
        ));
        let headers = [("idempotency-key", call.idempotency_key.as_str())];
        decode_ack(
            self.http
                .post(&url, "application/json", &headers, call.body.clone()),
        )
    }
}

/// Ten seconds doubling per attempt, capped at five minutes.
#[must_use]
pub fn backoff(attempt: u32) -> Duration {
    let factor = 2_u32.checked_pow(attempt).unwrap_or(u32::MAX);
    BACKOFF_FIRST
        .checked_mul(factor)
        .map_or(BACKOFF_CAP, |delay| delay.min(BACKOFF_CAP))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    Acknowledged {
        attempts: u32,
    },
    Refused {
        attempts: u32,
        reason: String,
    },
    /// The deadline or the attempt bound ran out; the spool stays for a replay.
    GaveUp {
        attempts: u32,
        last: String,
    },
}

impl Delivery {
    #[must_use]
    pub const fn acknowledged(&self) -> bool {
        matches!(self, Self::Acknowledged { .. })
    }
}

/// Delivers until acknowledged, refused, or out of attempts or time; `wait` sleeps between.
pub fn deliver_with_backoff(
    ingress: &impl Ingress,
    record: &SpoolRecord,
    resolution: &Resolution,
    deadline: Duration,
    wait: &mut dyn FnMut(Duration),
) -> Delivery {
    let started = Instant::now();
    let mut waited = Duration::ZERO;
    let mut last = String::from("no attempt");
    for attempt in 0..DELIVERY_ATTEMPTS_MAX {
        let attempts = attempt.saturating_add(1);
        match ingress.deliver(&record.awaitable_id, resolution) {
            Ack::Acknowledged => return Delivery::Acknowledged { attempts },
            Ack::Refused(status, body) => {
                return Delivery::Refused {
                    attempts,
                    reason: format!("status {status}: {body}"),
                };
            }
            Ack::Retry(reason) | Ack::Unrecognised(reason) => last = reason,
        }
        let delay = backoff(attempt);
        let spent = started.elapsed().max(waited);
        if spent.saturating_add(delay) > deadline {
            return Delivery::GaveUp { attempts, last };
        }
        wait(delay);
        waited = waited.saturating_add(delay);
    }
    Delivery::GaveUp {
        attempts: DELIVERY_ATTEMPTS_MAX,
        last,
    }
}

/// Renames an acknowledged spool onto a name that must not exist, so a replay of the same
/// path is refused as missing.
pub fn mark_acknowledged(path: &Path) -> io::Result<PathBuf> {
    let done = path.with_extension(ACKNOWLEDGED_SUFFIX);
    match fs::symlink_metadata(&done) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists", done.display()),
            ));
        }
    }
    fs::rename(path, &done)?;
    Ok(done)
}

/// A delivery and what went wrong with the spool file on the way, if anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivered {
    pub delivery: Delivery,
    pub spool_error: Option<String>,
}

/// Spools unless already spooled, then delivers; a failed spool write is reported, not fatal.
pub fn spool_then_deliver(
    ingress: &impl Ingress,
    path: &Path,
    record: &SpoolRecord,
    already_spooled: bool,
    wait: &mut dyn FnMut(Duration),
) -> Result<Delivered, SpoolError> {
    let resolution = record.resolution()?;
    let mut spool_error = if already_spooled {
        None
    } else {
        write_spool(path, record)
            .err()
            .map(|error| error.to_string())
    };
    let delivery = deliver_with_backoff(ingress, record, &resolution, DELIVERY_DEADLINE, wait);
    if delivery.acknowledged() && spool_error.is_none() {
        spool_error = mark_acknowledged(path)
            .err()
            .map(|error| format!("{}: {error}", path.display()));
    }
    Ok(Delivered {
        delivery,
        spool_error,
    })
}

/// Delivers a spool that was written but never acknowledged, if `owner` wrote it.
pub fn replay(
    ingress: &impl Ingress,
    path: &Path,
    owner: u32,
    wait: &mut dyn FnMut(Duration),
) -> Result<Delivery, SpoolError> {
    let record = read_spool(path, owner)?;
    let resolution = record.resolution()?;
    let delivery = deliver_with_backoff(ingress, &record, &resolution, DELIVERY_DEADLINE, wait);
    if delivery.acknowledged() {
        mark_acknowledged(path).map_err(|error| SpoolError::Io(path.to_path_buf(), error))?;
    }
    Ok(delivery)
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use crate::agent_files::current_uid;
    use std::cell::RefCell;
    use std::os::unix::fs::symlink;

    const SESSION: &str = "cf7a.wu03.wrk.claude.a1f3";

    struct Recorder {
        spool: PathBuf,
        answers: RefCell<Vec<Ack>>,
        seen: RefCell<Vec<(bool, Resolution)>>,
    }

    impl Recorder {
        fn new(spool: &Path, answers: Vec<Ack>) -> Self {
            Self {
                spool: spool.to_path_buf(),
                answers: RefCell::new(answers),
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl Ingress for Recorder {
        fn deliver(&self, _awaitable: &AwaitableId, resolution: &Resolution) -> Ack {
            self.seen
                .borrow_mut()
                .push((self.spool.exists(), resolution.clone()));
            let mut answers = self.answers.borrow_mut();
            if answers.is_empty() {
                Ack::Retry("no answer left".to_string())
            } else {
                answers.remove(0)
            }
        }

        fn heartbeat(&self, _call: &HeartbeatSend<'_>) -> Ack {
            Ack::Acknowledged
        }
    }

    fn record(state: ExitState) -> SpoolRecord {
        SpoolRecord {
            schema_version: SPOOL_SCHEMA_VERSION,
            session: SessionName::parse(SESSION).unwrap(),
            awaitable_id: AwaitableId::parse("sign_1abc").unwrap(),
            state,
            envelope: None,
        }
    }

    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tycho-spool-{test}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_spool_is_on_disk_before_the_first_delivery() {
        let dir = scratch("order");
        let path = dir.join(SPOOL_FILE);
        let ingress = Recorder::new(&path, vec![Ack::Retry("down".into()), Ack::Acknowledged]);
        let mut waits = Vec::new();
        let delivered = spool_then_deliver(
            &ingress,
            &path,
            &record(ExitState::Killed),
            false,
            &mut |delay| {
                waits.push(delay);
            },
        )
        .unwrap();
        assert_eq!(delivered.delivery, Delivery::Acknowledged { attempts: 2 });
        assert_eq!(delivered.spool_error, None);
        let seen = ingress.seen.borrow();
        assert!(seen.iter().all(|(spooled, _)| *spooled));
        assert_eq!(seen[0].1, Resolution::Reject("killed".to_string()));
        assert_eq!(waits, vec![BACKOFF_FIRST]);
        assert!(!path.exists());
        assert!(path.with_extension(ACKNOWLEDGED_SUFFIX).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_symlink_at_the_spool_path_is_refused_on_write_and_read() {
        let dir = scratch("symlink");
        let victim = dir.join("victim");
        fs::write(&victim, "untouched").unwrap();
        let path = dir.join(SPOOL_FILE);
        symlink(&victim, &path).unwrap();
        assert!(matches!(
            write_spool(&path, &record(ExitState::Failed)),
            Err(SpoolError::Io(..))
        ));
        assert!(matches!(
            read_spool(&path, current_uid()),
            Err(SpoolError::Io(..))
        ));
        assert_eq!(fs::read_to_string(&victim).unwrap(), "untouched");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_spool_that_cannot_be_written_is_reported_and_the_result_still_delivered() {
        let dir = scratch("unwritable");
        let path = dir.join("missing-dir").join(SPOOL_FILE);
        let ingress = Recorder::new(&path, vec![Ack::Acknowledged]);
        let delivered = spool_then_deliver(
            &ingress,
            &path,
            &record(ExitState::Failed),
            false,
            &mut |_| {},
        )
        .unwrap();
        assert!(delivered.delivery.acknowledged());
        assert!(delivered.spool_error.is_some());
        assert_eq!(ingress.seen.borrow().len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn backoff_doubles_from_ten_seconds_to_the_cap() {
        let schedule: Vec<u64> = (0..7).map(|attempt| backoff(attempt).as_secs()).collect();
        assert_eq!(schedule, vec![10, 20, 40, 80, 160, 300, 300]);
        assert_eq!(backoff(u32::MAX), BACKOFF_CAP);
    }

    #[test]
    fn delivery_gives_up_within_the_deadline_and_the_attempt_bound() {
        let dir = scratch("give-up");
        let path = dir.join(SPOOL_FILE);
        let ingress = Recorder::new(&path, Vec::new());
        let record = record(ExitState::Failed);
        let resolution = record.resolution().unwrap();
        let mut waits = Vec::new();
        let delivery = deliver_with_backoff(
            &ingress,
            &record,
            &resolution,
            DELIVERY_DEADLINE,
            &mut |delay| {
                waits.push(delay);
            },
        );
        let Delivery::GaveUp { attempts, .. } = delivery else {
            panic!("expected to give up, got {delivery:?}");
        };
        assert!(attempts <= DELIVERY_ATTEMPTS_MAX);
        assert!(waits.iter().all(|delay| *delay <= BACKOFF_CAP));
        let total: Duration = waits.iter().sum();
        assert!(total <= DELIVERY_DEADLINE, "{total:?}");
        let refused = Recorder::new(&path, vec![Ack::Refused(400, "bad id".into())]);
        let delivery = deliver_with_backoff(
            &refused,
            &record,
            &resolution,
            DELIVERY_DEADLINE,
            &mut |_| {
                panic!("a refusal is never retried");
            },
        );
        assert!(matches!(delivery, Delivery::Refused { attempts: 1, .. }));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ack_states_cover_every_status_class() {
        let response = |status| Outcome::Response {
            status,
            body: String::new(),
        };
        assert_eq!(decode_ack(response(202)), Ack::Acknowledged);
        assert!(matches!(decode_ack(response(400)), Ack::Refused(400, _)));
        assert!(matches!(decode_ack(response(503)), Ack::Retry(_)));
        assert!(matches!(decode_ack(response(302)), Ack::Unrecognised(_)));
        assert!(matches!(
            decode_ack(Outcome::Unreachable("x".into())),
            Ack::Retry(_)
        ));
        assert!(matches!(
            decode_ack(Outcome::BodyTooLarge),
            Ack::Unrecognised(_)
        ));
    }

    #[test]
    fn a_missing_oversized_or_inconsistent_spool_is_refused() {
        let dir = scratch("refused");
        let path = dir.join(SPOOL_FILE);
        let ingress = Recorder::new(&path, vec![Ack::Acknowledged]);
        assert!(matches!(
            replay(&ingress, &path, current_uid(), &mut |_| {}),
            Err(SpoolError::Missing(_))
        ));
        fs::write(&path, "x".repeat(SPOOL_FILE_MAX_BYTES + 1)).unwrap();
        assert!(matches!(
            read_spool(&path, current_uid()),
            Err(SpoolError::TooLarge(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_inconsistent_spool_is_never_written() {
        let dir = scratch("inconsistent");
        let path = dir.join(SPOOL_FILE);
        let mut completed = record(ExitState::Completed);
        assert!(matches!(
            write_spool(&path, &completed),
            Err(SpoolError::Inconsistent(_))
        ));
        completed.envelope = Some(serde_json::json!({"not": "an envelope"}));
        assert!(matches!(
            write_spool(&path, &completed),
            Err(SpoolError::Inconsistent(_))
        ));
        let mut failed = record(ExitState::Failed);
        failed.envelope = Some(serde_json::json!({}));
        assert!(matches!(
            write_spool(&path, &failed),
            Err(SpoolError::Inconsistent(_))
        ));
        assert!(!path.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_spool_is_written_once_read_by_its_owner_and_replayed_once() {
        let dir = scratch("once");
        let path = dir.join(SPOOL_FILE);
        let ingress = Recorder::new(&path, vec![Ack::Acknowledged]);
        write_spool(&path, &record(ExitState::Failed)).unwrap();
        assert_eq!(
            read_spool(&path, current_uid()).unwrap(),
            record(ExitState::Failed)
        );
        assert!(matches!(
            read_spool(&path, current_uid().wrapping_add(1)),
            Err(SpoolError::Io(..))
        ));
        assert!(matches!(
            write_spool(&path, &record(ExitState::Failed)),
            Err(SpoolError::Io(..))
        ));
        assert!(
            replay(&ingress, &path, current_uid(), &mut |_| {})
                .unwrap()
                .acknowledged()
        );
        assert!(matches!(
            replay(&ingress, &path, current_uid(), &mut |_| {}),
            Err(SpoolError::Missing(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }
}

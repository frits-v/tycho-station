//! The spine services of design section 7 and the ports they call through.

pub mod doubles;
pub mod epic;
pub mod merge_gate;
pub mod reconciler;
pub mod secret;
pub mod session;
pub mod spawner;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use restate_sdk::prelude::{HandlerError, RunRetryPolicy, TerminalError};

use crate::config::spine;
use spawner::Spawner;

/// HTTP-style codes on terminal errors, so a caller can tell a refusal from a defect.
pub const CODE_BAD_REQUEST: u16 = 400;
pub const CODE_FORBIDDEN: u16 = 403;
pub const CODE_NOT_FOUND: u16 = 404;
pub const CODE_CONFLICT: u16 = 409;
pub const CODE_INTERNAL: u16 = 500;

#[must_use]
pub fn refuse(code: u16, message: impl Into<String>) -> HandlerError {
    TerminalError::new_with_code(code, message).into()
}

/// The durations every service reads; tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub stall_silence: Duration,
    pub stall_progress: Duration,
    pub retry_backoff_initial: Duration,
    pub retry_backoff_max: Duration,
    pub slot_retry_delay: Duration,
    pub lease_fresh: Duration,
    pub spawn_grace: Duration,
    pub reconciler_interval: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            stall_silence: spine::STALL_SILENCE,
            stall_progress: spine::STALL_PROGRESS,
            retry_backoff_initial: spine::RETRY_BACKOFF_INITIAL,
            retry_backoff_max: spine::RETRY_BACKOFF_MAX,
            slot_retry_delay: spine::SLOT_RETRY_DELAY,
            lease_fresh: spine::LEASE_FRESH,
            spawn_grace: spine::SPAWN_GRACE,
            reconciler_interval: spine::RECONCILER_INTERVAL,
        }
    }
}

impl Timing {
    /// The step retry policy for port calls: backoff doubling to its cap, bounded in attempts;
    /// agent retries are workflow logic and never go through it.
    #[must_use]
    pub fn port_retry(&self) -> RunRetryPolicy {
        RunRetryPolicy::new()
            .initial_delay(self.retry_backoff_initial)
            .exponentiation_factor(2.0)
            .max_delay(self.retry_backoff_max)
            .max_attempts(spine::PORT_STEP_ATTEMPTS_MAX)
    }

    #[must_use]
    pub fn millis(duration: Duration) -> u64 {
        u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
    }
}

/// What the services are built from; the endpoint binds one of each service with it.
#[derive(Clone)]
pub struct Ports {
    pub spawner: Arc<dyn Spawner>,
    pub timing: Timing,
}

impl std::fmt::Debug for Ports {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Ports")
            .field("spawner", &self.spawner.describe())
            .field("timing", &self.timing)
            .finish()
    }
}

/// Wall-clock milliseconds; only ever called inside a journaled step.
#[must_use]
pub fn wall_clock_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, Timing::millis)
}

/// A transient spawner failure retries under the step's policy; a refusal is terminal.
#[must_use]
pub fn spawner_failure(error: spawner::SpawnerError) -> HandlerError {
    match error {
        spawner::SpawnerError::Transient(_) => HandlerError::from(error),
        spawner::SpawnerError::Refused(reason) => refuse(CODE_INTERNAL, reason),
    }
}

/// Runs blocking port calls off the async runtime; a lost worker thread retries.
pub async fn blocking<T, W>(work: W) -> Result<T, HandlerError>
where
    T: Send + 'static,
    W: FnOnce() -> Result<T, HandlerError> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| HandlerError::from(std::io::Error::other(error.to_string())))?
}

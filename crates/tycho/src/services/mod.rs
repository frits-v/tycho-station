//! The spine services of design section 7 and the ports they call through.

pub mod doubles;
pub mod epic;
pub mod merge_gate;
pub mod operator;
pub mod reconciler;
pub mod secret;
pub mod session;
pub mod spawner;
pub mod work_unit;
pub mod worker_run;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use restate_sdk::prelude::{HandlerError, RunRetryPolicy, TerminalError};

use crate::config_store::{FactoryConfig, Thresholds};
use spawner::Spawner;

/// HTTP-style codes on terminal errors, so a caller can tell a refusal from a defect.
pub const CODE_BAD_REQUEST: u16 = 400;
pub const CODE_FORBIDDEN: u16 = 403;
pub const CODE_NOT_FOUND: u16 = 404;
pub const CODE_CONFLICT: u16 = 409;
/// Restate's code for a cancelled invocation, the same number as a conflict.
pub const CODE_CANCELLED: u16 = 409;
pub const CODE_INTERNAL: u16 = 500;

#[must_use]
pub fn refuse(code: u16, message: impl Into<String>) -> HandlerError {
    TerminalError::new_with_code(code, message).into()
}

/// The durations and retry bound every service reads; tests shorten them.
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
    /// Tries per port step before it turns terminal.
    pub port_step_attempts_max: u32,
}

#[cfg(test)]
impl Default for Timing {
    fn default() -> Self {
        Self::from_thresholds(&FactoryConfig::embedded().unwrap().thresholds.value)
    }
}

impl Timing {
    #[must_use]
    pub const fn from_thresholds(thresholds: &Thresholds) -> Self {
        Self {
            stall_silence: Duration::from_secs(thresholds.stall.silence_seconds),
            stall_progress: Duration::from_secs(thresholds.stall.progress_seconds),
            retry_backoff_initial: Duration::from_secs(thresholds.retry.backoff_initial_seconds),
            retry_backoff_max: Duration::from_secs(thresholds.retry.backoff_max_seconds),
            slot_retry_delay: Duration::from_secs(thresholds.retry.slot_retry_delay_seconds),
            lease_fresh: Duration::from_secs(thresholds.session.lease_fresh_seconds),
            spawn_grace: Duration::from_secs(thresholds.session.spawn_grace_seconds),
            reconciler_interval: Duration::from_secs(
                thresholds.session.reconciler_interval_seconds,
            ),
            port_step_attempts_max: thresholds.retry.port_step_attempts_max,
        }
    }

    /// Retry policy for port steps; agent retries are workflow logic and never use it.
    #[must_use]
    pub fn port_retry(&self) -> RunRetryPolicy {
        RunRetryPolicy::new()
            .initial_delay(self.retry_backoff_initial)
            .exponentiation_factor(2.0)
            .max_delay(self.retry_backoff_max)
            .max_attempts(self.port_step_attempts_max)
    }

    /// A nudge is best-effort: three tries, two seconds apart.
    #[must_use]
    pub fn nudge_retry() -> RunRetryPolicy {
        RunRetryPolicy::new()
            .initial_delay(Duration::from_secs(2))
            .max_attempts(3)
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
    pub merge_gate: Arc<dyn merge_gate::MergeGate>,
    pub timing: Timing,
    /// Routing tables and thresholds, with the content hashes a unit records at its start.
    pub config: Arc<FactoryConfig>,
    /// The operator secret file; `None` refuses every operator call.
    pub operator_secret: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for Ports {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Ports")
            .field("spawner", &self.spawner.describe())
            .field("merge_gate", &self.merge_gate.describe())
            .field("timing", &self.timing)
            .field("config", &self.config.hashes())
            .field("operator_secret", &self.operator_secret)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_retry_is_bounded_in_attempts() {
        let policy = format!("{:?}", Timing::default().port_retry());
        let bound = format!(
            "max_attempts: Some({})",
            Timing::default().port_step_attempts_max
        );
        assert!(policy.contains(&bound), "{policy}");
        assert!(policy.contains("factor: 2.0"), "{policy}");
    }

    #[test]
    fn nudge_retry_is_short() {
        let policy = format!("{:?}", Timing::nudge_retry());
        assert!(policy.contains("max_attempts: Some(3)"), "{policy}");
        assert!(policy.contains("initial_delay: 2s"), "{policy}");
    }
}

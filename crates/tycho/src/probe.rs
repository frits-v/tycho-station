//! The probe service: a virtual object whose exclusive handler sleeps durably, so a
//! kill test can show an in-flight invocation resume.

use std::time::Duration;

use restate_sdk::prelude::*;

pub const PROBE_SERVICE: &str = "Probe";
pub const PROBE_SLOW_HANDLER: &str = "slow";
/// Bounds the durable sleep a caller can request.
pub const PROBE_SLEEP_MAX_MS: u64 = 600_000;
const COUNTER_KEY: &str = "counter";

#[derive(Debug, Clone, Copy, Default)]
pub struct Probe;

#[restate_sdk::object]
impl Probe {
    #[handler]
    async fn slow(
        &self,
        object_context: ObjectContext<'_>,
        milliseconds: u64,
    ) -> HandlerResult<u64> {
        if milliseconds > PROBE_SLEEP_MAX_MS {
            return Err(TerminalError::new(format!(
                "sleep of {milliseconds} ms exceeds {PROBE_SLEEP_MAX_MS} ms"
            ))
            .into());
        }
        object_context
            .sleep(Duration::from_millis(milliseconds))
            .await?;
        let previous = object_context.get::<u64>(COUNTER_KEY).await?.unwrap_or(0);
        let next = previous
            .checked_add(1)
            .ok_or_else(|| TerminalError::new("probe counter overflow"))?;
        object_context.set(COUNTER_KEY, next);
        Ok(next)
    }
}

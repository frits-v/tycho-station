//! The launch probe, a virtual object for the launcher tests.
//!
//! Its exclusive `wait` handler awaits an awakeable a launcher resolves, and its `heartbeat`
//! stands in for `Session/<name>/heartbeat` with the same input shape.

use restate_sdk::prelude::*;

use tycho_types::agent_call::HeartbeatCall;

pub const LAUNCH_PROBE_SERVICE: &str = "LaunchProbe";
pub const LAUNCH_PROBE_HEARTBEAT_HANDLER: &str = "heartbeat";
const AWAKEABLE_KEY: &str = "awakeable";
const OUTCOME_KEY: &str = "outcome";
const HEARTBEATS_KEY: &str = "heartbeats";
const LAST_STATUS_KEY: &str = "last_status";
const LAST_SEQUENCE_KEY: &str = "last_sequence";
/// Prefix of a stored outcome resolved with an envelope.
pub const RESOLVED_PREFIX: &str = "resolved:";
/// Prefix of a stored outcome rejected with a failure state.
pub const REJECTED_PREFIX: &str = "rejected:";

#[derive(Debug, Clone, Copy, Default)]
pub struct LaunchProbe;

#[restate_sdk::object]
impl LaunchProbe {
    #[handler]
    async fn wait(&self, object_context: ObjectContext<'_>) -> HandlerResult<String> {
        let (id, awakeable) = object_context.awakeable::<Json<serde_json::Value>>();
        object_context.set(AWAKEABLE_KEY, id);
        let outcome = match awakeable.await {
            Ok(Json(value)) => format!("{RESOLVED_PREFIX}{value}"),
            Err(error) => format!("{REJECTED_PREFIX}{}", error.message()),
        };
        object_context.set(OUTCOME_KEY, outcome.clone());
        Ok(outcome)
    }

    #[handler]
    async fn awakeable(
        &self,
        object_context: SharedObjectContext<'_>,
    ) -> HandlerResult<Json<Option<String>>> {
        Ok(Json(object_context.get::<String>(AWAKEABLE_KEY).await?))
    }

    #[handler]
    async fn outcome(
        &self,
        object_context: SharedObjectContext<'_>,
    ) -> HandlerResult<Json<Option<String>>> {
        Ok(Json(object_context.get::<String>(OUTCOME_KEY).await?))
    }

    /// Counts heartbeats with a secret and a sequence above the last; holds no secret to verify.
    #[handler]
    async fn heartbeat(
        &self,
        object_context: ObjectContext<'_>,
        Json(body): Json<HeartbeatCall>,
    ) -> HandlerResult<u64> {
        if body.secret.is_empty() {
            return Err(TerminalError::new("heartbeat without the session secret").into());
        }
        let last = object_context
            .get::<u64>(LAST_SEQUENCE_KEY)
            .await?
            .unwrap_or(0);
        if body.sequence <= last {
            return Ok(object_context
                .get::<u64>(HEARTBEATS_KEY)
                .await?
                .unwrap_or(0));
        }
        object_context.set(LAST_SEQUENCE_KEY, body.sequence);
        let previous = object_context
            .get::<u64>(HEARTBEATS_KEY)
            .await?
            .unwrap_or(0);
        let next = previous
            .checked_add(1)
            .ok_or_else(|| TerminalError::new("heartbeat counter overflow"))?;
        object_context.set(HEARTBEATS_KEY, next);
        object_context.set(LAST_STATUS_KEY, Json(body.status));
        Ok(next)
    }

    /// The heartbeat count and the last sequence seen.
    #[handler]
    async fn heartbeats(
        &self,
        object_context: SharedObjectContext<'_>,
    ) -> HandlerResult<Json<(u64, u64)>> {
        let count = object_context
            .get::<u64>(HEARTBEATS_KEY)
            .await?
            .unwrap_or(0);
        let last = object_context
            .get::<u64>(LAST_SEQUENCE_KEY)
            .await?
            .unwrap_or(0);
        Ok(Json((count, last)))
    }
}

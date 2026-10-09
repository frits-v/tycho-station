//! The Operator service: the only public way to start an epic or add a work unit, gated by
//! the operator secret `tycho core start` writes into the core home.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use restate_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tycho_types::envelope::ShortText;
use tycho_types::launcher::{SessionSecret, SESSION_SECRET_MAX_BYTES};
use tycho_types::service::{EpicId, WorkUnitId};

use crate::config_store::FactoryConfig;
use crate::private_dir;
use crate::services::epic::{AddUnitAnswer, EpicClient, EpicState, StartRequest};
use crate::services::work_unit::{RuleCall, WorkUnitClient, WorkUnitRequest};
use crate::services::{blocking, refuse, secret, Ports, CODE_BAD_REQUEST, CODE_NOT_FOUND};

pub const CODE_UNAUTHORIZED: u16 = 401;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartEpicCall {
    pub secret: String,
    pub epic: EpicId,
    pub goal: ShortText,
    pub seat_limit: u64,
    pub metered_limit: u64,
}

impl fmt::Debug for StartEpicCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartEpicCall")
            .field("secret", &"redacted")
            .field("epic", &self.epic)
            .field("goal", &self.goal)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddUnitCall {
    pub secret: String,
    pub epic: EpicId,
    pub unit: WorkUnitId,
}

impl fmt::Debug for AddUnitCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AddUnitCall")
            .field("secret", &"redacted")
            .field("epic", &self.epic)
            .field("unit", &self.unit)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchUnitCall {
    pub secret: String,
    pub unit: WorkUnitId,
    pub request: WorkUnitRequest,
}

impl fmt::Debug for DispatchUnitCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchUnitCall")
            .field("secret", &"redacted")
            .field("unit", &self.unit)
            .field("request", &self.request)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dispatched {
    pub unit: WorkUnitId,
    pub invocation_id: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleUnitCall {
    pub secret: String,
    pub unit: WorkUnitId,
    pub rule: RuleCall,
}

impl fmt::Debug for RuleUnitCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuleUnitCall")
            .field("secret", &"redacted")
            .field("unit", &self.unit)
            .field("rule", &self.rule)
            .finish()
    }
}

/// Generates the operator secret file unless it exists; true when it was created.
pub fn ensure_secret_file(path: &Path) -> Result<bool, String> {
    let generated = secret::generate().map_err(|error| error.to_string())?;
    private_dir::create_private_file(path, generated.expose().as_bytes())
        .map_err(|error| error.to_string())
}

/// The secret in the file; an unreadable or malformed file is an error, never an empty secret.
pub fn read_secret_file(path: &Path) -> Result<SessionSecret, String> {
    let bytes = private_dir::read_private_file(path, SESSION_SECRET_MAX_BYTES)
        .map_err(|error| error.to_string())?;
    let text = String::from_utf8(bytes).map_err(|_| "operator secret is not UTF-8".to_string())?;
    SessionSecret::parse(text.trim()).map_err(|error| format!("operator secret: {error}"))
}

/// True only when the file holds a valid secret equal to the candidate.
#[must_use]
pub fn authorized(path: Option<&Path>, candidate: &str) -> bool {
    path.and_then(|path| read_secret_file(path).ok())
        .is_some_and(|stored| stored.verify(candidate))
}

/// Every planned task's class and tier against the routing table.
pub fn check_plan_routes(config: &FactoryConfig, request: &WorkUnitRequest) -> Result<(), String> {
    for planned in &request.plan {
        let routing = &planned.worker.routing;
        config
            .route(&routing.class, &routing.tier)
            .map_err(|error| format!("task {}: {error}", planned.task))?;
    }
    Ok(())
}

pub struct Operator {
    secret_path: Option<PathBuf>,
    config: Arc<FactoryConfig>,
}

impl Operator {
    #[must_use]
    pub fn new(ports: &Ports) -> Self {
        Self {
            secret_path: ports.operator_secret.clone(),
            config: Arc::clone(&ports.config),
        }
    }

    async fn check(&self, service_context: &Context<'_>, candidate: String) -> HandlerResult<()> {
        let path = self.secret_path.clone();
        let allowed = service_context
            .run(|| blocking(move || Ok(authorized(path.as_deref(), &candidate))))
            .name("verify operator secret")
            .await?;
        if allowed {
            Ok(())
        } else {
            Err(refuse(
                CODE_UNAUTHORIZED,
                "operator secret missing or wrong",
            ))
        }
    }
}

impl fmt::Debug for Operator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Operator")
            .field("secret_path", &self.secret_path)
            .field("config", &self.config.hashes())
            .finish()
    }
}

#[restate_sdk::service]
impl Operator {
    #[handler]
    async fn start_epic(
        &self,
        service_context: Context<'_>,
        call: Json<StartEpicCall>,
    ) -> HandlerResult<Json<EpicState>> {
        let call = call.into_inner();
        self.check(&service_context, call.secret).await?;
        let request = StartRequest {
            goal: call.goal,
            seat_limit: call.seat_limit,
            metered_limit: call.metered_limit,
        };
        Ok(service_context
            .object_client::<EpicClient>(call.epic.as_str())
            .start(Json(request))
            .call()
            .await?)
    }

    /// Starts the unit's run once the epic lists it; answers with the run's invocation id.
    #[handler]
    async fn dispatch_unit(
        &self,
        service_context: Context<'_>,
        call: Json<DispatchUnitCall>,
    ) -> HandlerResult<Json<Dispatched>> {
        let call = call.into_inner();
        self.check(&service_context, call.secret).await?;
        let listed = service_context
            .object_client::<EpicClient>(call.request.epic.as_str())
            .status()
            .call()
            .await?
            .into_inner()
            .is_some_and(|epic| epic.units.contains(&call.unit));
        if !listed {
            return Err(refuse(
                CODE_NOT_FOUND,
                format!(
                    "epic {} does not list unit {}",
                    call.request.epic, call.unit
                ),
            ));
        }
        let config = Arc::clone(&self.config);
        let request = call.request.clone();
        service_context
            .run(|| async move {
                check_plan_routes(&config, &request)
                    .map_err(|error| refuse(CODE_BAD_REQUEST, error))
            })
            .name("route check")
            .await?;
        let handle = service_context
            .workflow_client::<WorkUnitClient>(call.unit.as_str())
            .run(Json(call.request))
            .send()
            .await?;
        Ok(Json(Dispatched {
            unit: call.unit,
            invocation_id: handle.invocation_id().to_string(),
        }))
    }

    /// Resolves an escalated unit's ruling; the verdict-from-a-file path calls it.
    #[handler]
    async fn rule_unit(
        &self,
        service_context: Context<'_>,
        call: Json<RuleUnitCall>,
    ) -> HandlerResult<()> {
        let call = call.into_inner();
        self.check(&service_context, call.secret).await?;
        service_context
            .workflow_client::<WorkUnitClient>(call.unit.as_str())
            .rule(Json(call.rule))
            .call()
            .await?;
        Ok(())
    }

    #[handler]
    async fn add_unit(
        &self,
        service_context: Context<'_>,
        call: Json<AddUnitCall>,
    ) -> HandlerResult<Json<AddUnitAnswer>> {
        let call = call.into_inner();
        self.check(&service_context, call.secret).await?;
        Ok(service_context
            .object_client::<EpicClient>(call.epic.as_str())
            .add_unit(Json(call.unit))
            .call()
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(class: &str, tier: &str) -> WorkUnitRequest {
        serde_json::from_str(&format!(
            r#"{{"epic":"cf7a","control_vendor":"codex","plan":[{{"task":"t1","worker":{{"epic":"cf7a","work_unit":"wu01","vendor":"claude","argv":["l"],"routing":{{"class":"{class}","tier":"{tier}","effort":"low","binding":null,"rationale":"r"}},"ledger":"seat","reservation":1}}}}]}}"#
        ))
        .unwrap()
    }

    #[test]
    fn a_plan_is_checked_against_the_routing_table() {
        let config = FactoryConfig::embedded().unwrap();
        assert_eq!(
            check_plan_routes(&config, &plan("implement", "standard")),
            Ok(())
        );
        assert_eq!(
            check_plan_routes(&config, &plan("implement", "strong")),
            Ok(())
        );
        for (class, tier) in [
            ("unlisted", "standard"),
            ("implement", "light"),
            ("implement", "huge"),
        ] {
            let refused = check_plan_routes(&config, &plan(class, tier));
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|error| error.starts_with("task t1: ")),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn a_plan_naming_a_fallback_tier_does_not_decode() {
        let text = serde_json::to_string(&plan("implement", "standard")).unwrap();
        let with_fallback = text.replace(
            r#""rationale":"r""#,
            r#""rationale":"r","fallback_tier":"strong""#,
        );
        assert!(serde_json::from_str::<WorkUnitRequest>(&with_fallback).is_err());
    }
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("operator-{name}-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn the_generated_secret_authorizes_and_nothing_else_does() {
        let base = scratch("secret");
        let path = base.join("operator.secret");
        let created = ensure_secret_file(&path);
        let again = ensure_secret_file(&path);
        let stored = read_secret_file(&path).unwrap();
        let right = authorized(Some(&path), stored.expose());
        let wrong = authorized(Some(&path), &"x".repeat(64));
        let empty = authorized(Some(&path), "");
        fs::remove_dir_all(&base).unwrap();
        assert_eq!((created, again), (Ok(true), Ok(false)));
        assert!(right);
        assert!(!wrong && !empty);
    }

    #[test]
    fn a_missing_file_or_path_authorizes_nothing() {
        let base = scratch("missing");
        let path = base.join("operator.secret");
        let missing = authorized(Some(&path), &"x".repeat(64));
        fs::remove_dir_all(&base).unwrap();
        assert!(!missing);
        assert!(!authorized(None, &"x".repeat(64)));
    }

    #[test]
    fn calls_never_print_the_secret() {
        let call = AddUnitCall {
            secret: "s".repeat(40),
            epic: EpicId::parse("cf7a").unwrap(),
            unit: WorkUnitId::parse("wu01").unwrap(),
        };
        assert!(!format!("{call:?}").contains(&"s".repeat(40)));
    }
}

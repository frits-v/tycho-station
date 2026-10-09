//! `tycho epic start|add-unit`: operator calls through Restate's ingress, carrying the
//! operator secret from the core home.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use tycho_types::envelope::ShortText;
use tycho_types::service::{handler, EpicId, WorkUnitId};

use crate::config::{ingress_url, spine, CoreConfig};
use crate::http::{Http, Outcome};
use crate::services::operator::{read_secret_file, AddUnitCall, DispatchUnitCall, StartEpicCall};
use crate::services::work_unit::{PlannedTask, WorkUnitRequest};

pub const OPERATOR_SERVICE: &str = "Operator";

/// What an operator call came back as; only `Done` is success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorAnswer {
    Done(String),
    Unauthorized(String),
    Rejected(u16, String),
    Unreachable(String),
    Unrecognised(String),
}

impl fmt::Display for OperatorAnswer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Done(body) => write!(formatter, "{body}"),
            Self::Unauthorized(body) => write!(formatter, "unauthorized: {body}"),
            Self::Rejected(status, body) => write!(formatter, "rejected ({status}): {body}"),
            Self::Unreachable(reason) => write!(formatter, "ingress unreachable: {reason}"),
            Self::Unrecognised(reason) => write!(formatter, "unrecognised answer: {reason}"),
        }
    }
}

#[must_use]
pub fn decode(outcome: Outcome) -> OperatorAnswer {
    match outcome {
        Outcome::Response { status: 200, body } => OperatorAnswer::Done(body),
        Outcome::Response { status: 401, body } => OperatorAnswer::Unauthorized(body),
        Outcome::Response { status, body } if (400..=499).contains(&status) => {
            OperatorAnswer::Rejected(status, body)
        }
        Outcome::Response { status, .. } => {
            OperatorAnswer::Unrecognised(format!("status {status}"))
        }
        Outcome::Unreachable(reason) => OperatorAnswer::Unreachable(reason),
        Outcome::BodyTooLarge => OperatorAnswer::Unrecognised("body over the limit".to_string()),
    }
}

fn call(http: &Http, handler_name: &str, body: String) -> OperatorAnswer {
    let url = ingress_url(&format!("/{OPERATOR_SERVICE}/{handler_name}"));
    decode(http.post_json(&url, body))
}

/// Starts an epic with the default ledger limits.
pub fn start(
    config: &CoreConfig,
    http: &Http,
    epic: &str,
    goal: &str,
) -> Result<OperatorAnswer, String> {
    let secret = read_secret_file(&config.operator_secret_file())?;
    let request = StartEpicCall {
        secret: secret.expose().to_string(),
        epic: EpicId::parse(epic).map_err(|error| format!("epic id: {error}"))?,
        goal: ShortText::parse(goal).map_err(|error| format!("goal: {error}"))?,
        seat_limit: spine::EPIC_SEAT_LIMIT_DEFAULT,
        metered_limit: spine::EPIC_METERED_LIMIT_DEFAULT,
    };
    let body = serde_json::to_string(&request).map_err(|error| error.to_string())?;
    Ok(call(http, handler::OPERATOR_START_EPIC, body))
}

pub fn add_unit(
    config: &CoreConfig,
    http: &Http,
    epic: &str,
    unit: &str,
) -> Result<OperatorAnswer, String> {
    let secret = read_secret_file(&config.operator_secret_file())?;
    let request = AddUnitCall {
        secret: secret.expose().to_string(),
        epic: EpicId::parse(epic).map_err(|error| format!("epic id: {error}"))?,
        unit: WorkUnitId::parse(unit).map_err(|error| format!("work unit id: {error}"))?,
    };
    let body = serde_json::to_string(&request).map_err(|error| error.to_string())?;
    Ok(call(http, handler::OPERATOR_ADD_UNIT, body))
}

/// Bounds the dispatch plan file `tycho epic dispatch` reads.
pub const PLAN_FILE_MAX_BYTES: u64 = 65_536;

/// The plan file: the control session's vendor and the tasks, without the epic.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanFile {
    pub control_vendor: tycho_types::session::Vendor,
    pub plan: Vec<PlannedTask>,
    #[serde(default)]
    pub control: Option<crate::services::work_unit::ControlStart>,
}

pub fn read_plan(path: &Path) -> Result<PlanFile, String> {
    let file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(PLAN_FILE_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > PLAN_FILE_MAX_BYTES {
        return Err(format!(
            "{} is over {PLAN_FILE_MAX_BYTES} bytes",
            path.display()
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))
}

/// Dispatches a listed unit's run with the plan from a file.
pub fn dispatch(
    config: &CoreConfig,
    http: &Http,
    epic: &str,
    unit: &str,
    plan_path: &Path,
) -> Result<OperatorAnswer, String> {
    let secret = read_secret_file(&config.operator_secret_file())?;
    let plan = read_plan(plan_path)?;
    let request = DispatchUnitCall {
        secret: secret.expose().to_string(),
        unit: WorkUnitId::parse(unit).map_err(|error| format!("work unit id: {error}"))?,
        request: WorkUnitRequest {
            epic: EpicId::parse(epic).map_err(|error| format!("epic id: {error}"))?,
            control_vendor: plan.control_vendor,
            plan: plan.plan,
            control: plan.control,
        },
    };
    let body = serde_json::to_string(&request).map_err(|error| error.to_string())?;
    Ok(call(http, handler::OPERATOR_DISPATCH_UNIT, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16) -> Outcome {
        Outcome::Response {
            status,
            body: "b".to_string(),
        }
    }

    #[test]
    fn decodes_each_answer() {
        assert_eq!(decode(response(200)), OperatorAnswer::Done("b".into()));
        assert_eq!(
            decode(response(401)),
            OperatorAnswer::Unauthorized("b".into())
        );
        assert_eq!(
            decode(response(409)),
            OperatorAnswer::Rejected(409, "b".into())
        );
        assert!(matches!(
            decode(response(500)),
            OperatorAnswer::Unrecognised(_)
        ));
        assert!(matches!(
            decode(response(302)),
            OperatorAnswer::Unrecognised(_)
        ));
        assert!(matches!(
            decode(Outcome::Unreachable("x".into())),
            OperatorAnswer::Unreachable(_)
        ));
        assert!(matches!(
            decode(Outcome::BodyTooLarge),
            OperatorAnswer::Unrecognised(_)
        ));
    }

    #[test]
    fn a_plan_file_over_its_maximum_is_refused() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("plan-over-{}.json", std::process::id()));
        let size = usize::try_from(PLAN_FILE_MAX_BYTES.saturating_add(1)).unwrap();
        std::fs::write(&path, vec![b' '; size]).unwrap();
        let read = read_plan(&path);
        std::fs::remove_file(&path).unwrap();
        assert!(read.unwrap_err().contains("over"));
    }
}

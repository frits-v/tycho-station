//! `tycho epic start|add-unit`: operator calls through Restate's ingress, carrying the
//! operator secret from the core home.

use std::fmt;

use tycho_types::envelope::ShortText;
use tycho_types::service::{handler, EpicId, WorkUnitId};

use crate::config::{ingress_url, spine, CoreConfig};
use crate::http::{Http, Outcome};
use crate::services::operator::{read_secret_file, AddUnitCall, StartEpicCall};

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
}

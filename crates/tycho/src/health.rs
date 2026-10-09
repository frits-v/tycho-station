//! Decoders for the liveness probes and the deployment registration response.

use std::fmt;

use crate::config::{CorePorts, CoreRole};
use crate::http::{Http, Outcome};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Unhealthy(u16),
    Unreachable(String),
    Unrecognised(String),
}

impl Health {
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }
}

impl fmt::Display for Health {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => formatter.write_str("healthy"),
            Self::Unhealthy(status) => write!(formatter, "unhealthy (status {status})"),
            Self::Unreachable(reason) => write!(formatter, "unreachable ({reason})"),
            Self::Unrecognised(reason) => write!(formatter, "unrecognised ({reason})"),
        }
    }
}

/// Both `/health` routes answer 200 with an empty body when alive.
#[must_use]
pub fn decode_health(outcome: Outcome) -> Health {
    match outcome {
        Outcome::Response { status: 200, .. } => Health::Healthy,
        Outcome::Response { status, .. } if (500..=599).contains(&status) => {
            Health::Unhealthy(status)
        }
        Outcome::Response { status, .. } => Health::Unrecognised(format!("status {status}")),
        Outcome::Unreachable(reason) => Health::Unreachable(reason),
        Outcome::BodyTooLarge => Health::Unrecognised("body over the limit".to_string()),
    }
}

/// The admin API's health for the server; the endpoint's own health route for the endpoint.
#[must_use]
pub fn probe(http: &Http, ports: CorePorts, role: CoreRole) -> Health {
    match role {
        CoreRole::Restate => decode_health(http.get(&ports.admin_url("/health"))),
        CoreRole::Endpoint => decode_health(http.get_h2c(&ports.endpoint_url("/health"))),
    }
}

/// Restate's ingress health route, which answers only once the ingress listens.
#[must_use]
pub fn probe_ingress(http: &Http, ports: CorePorts) -> Health {
    decode_health(http.get(&ports.ingress_url("/restate/health")))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    Created,
    Unchanged,
    Conflict(String),
    Rejected(u16, String),
    Unreachable(String),
    Unrecognised(String),
}

impl Registration {
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        matches!(self, Self::Created | Self::Unchanged)
    }
}

impl fmt::Display for Registration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => formatter.write_str("registered"),
            Self::Unchanged => formatter.write_str("already registered"),
            Self::Conflict(body) => write!(formatter, "conflict: {body}"),
            Self::Rejected(status, body) => write!(formatter, "rejected ({status}): {body}"),
            Self::Unreachable(reason) => write!(formatter, "admin unreachable ({reason})"),
            Self::Unrecognised(reason) => write!(formatter, "unrecognised ({reason})"),
        }
    }
}

#[must_use]
pub fn decode_registration(outcome: Outcome) -> Registration {
    match outcome {
        Outcome::Response { status: 201, .. } => Registration::Created,
        Outcome::Response { status: 200, .. } => Registration::Unchanged,
        Outcome::Response { status: 409, body } => Registration::Conflict(body),
        Outcome::Response { status, body } if (400..=499).contains(&status) => {
            Registration::Rejected(status, body)
        }
        Outcome::Response { status, .. } => Registration::Unrecognised(format!("status {status}")),
        Outcome::Unreachable(reason) => Registration::Unreachable(reason),
        Outcome::BodyTooLarge => Registration::Unrecognised("body over the limit".to_string()),
    }
}

/// Registers the endpoint; the admin API answers 200 for an unchanged deployment.
#[must_use]
pub fn register(http: &Http, ports: CorePorts) -> Registration {
    let body = format!("{{\"uri\":\"{}\"}}", ports.endpoint_url(""));
    decode_registration(http.post_json(&ports.admin_url("/deployments"), body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16) -> Outcome {
        Outcome::Response {
            status,
            body: String::new(),
        }
    }

    #[test]
    fn health_states() {
        assert_eq!(decode_health(response(200)), Health::Healthy);
        assert_eq!(decode_health(response(503)), Health::Unhealthy(503));
        assert_eq!(
            decode_health(Outcome::Unreachable("refused".to_string())),
            Health::Unreachable("refused".to_string())
        );
    }

    #[test]
    fn health_unrecognised() {
        assert_eq!(
            decode_health(response(302)),
            Health::Unrecognised("status 302".to_string())
        );
        assert!(!decode_health(Outcome::BodyTooLarge).is_healthy());
    }

    #[test]
    fn registration_states() {
        assert_eq!(decode_registration(response(201)), Registration::Created);
        assert_eq!(decode_registration(response(200)), Registration::Unchanged);
        assert!(matches!(
            decode_registration(response(409)),
            Registration::Conflict(_)
        ));
        assert!(matches!(
            decode_registration(response(400)),
            Registration::Rejected(400, _)
        ));
        assert!(matches!(
            decode_registration(Outcome::Unreachable(String::new())),
            Registration::Unreachable(_)
        ));
    }

    #[test]
    fn registration_unrecognised() {
        let state = decode_registration(response(502));
        assert_eq!(state, Registration::Unrecognised("status 502".to_string()));
        assert!(!state.is_registered());
    }
}

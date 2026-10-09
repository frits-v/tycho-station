//! `tycho core start|stop|status` over the two core sessions.

use std::fmt;

use tycho_types::service::{handler, Service, RECONCILER_KEY};

use crate::config::{ingress_url, CoreConfig, CoreRole};
use crate::health::{self, Health};
use crate::http::{Http, Outcome};
use crate::services::operator;
use crate::watchdog::{OnceReport, Supervisor};
use crate::zmx::{presence, Presence};

/// The watchdog's pass, then the operator secret and the reconciler's tick chain.
#[derive(Debug)]
pub struct StartReport {
    pub once: OnceReport,
    pub operator_secret: Result<String, String>,
    pub reconciler: Result<String, String>,
}

impl StartReport {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.once.succeeded() && self.operator_secret.is_ok() && self.reconciler.is_ok()
    }
}

impl fmt::Display for StartReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.once)?;
        for (label, result) in [
            ("operator secret", &self.operator_secret),
            ("reconciler", &self.reconciler),
        ] {
            match result {
                Ok(done) => writeln!(formatter, "  {label}: {done}")?,
                Err(error) => writeln!(formatter, "  {label}: failed: {error}")?,
            }
        }
        Ok(())
    }
}

/// Starts whatever is missing, registers the endpoint, writes the operator secret if absent,
/// and starts a reconciler tick chain, which ends any older chain.
#[must_use]
pub fn start(supervisor: &Supervisor, config: &CoreConfig) -> StartReport {
    let once = supervisor.once();
    let operator_secret =
        operator::ensure_secret_file(&config.operator_secret_file()).map(|created| {
            if created {
                "created".to_string()
            } else {
                "present".to_string()
            }
        });
    let reconciler = if once.succeeded() {
        start_reconciler(supervisor.http())
    } else {
        Err("not attempted: the core did not come up".to_string())
    };
    StartReport {
        once,
        operator_secret,
        reconciler,
    }
}

fn start_reconciler(http: &Http) -> Result<String, String> {
    let path = format!(
        "/{}/{RECONCILER_KEY}/{}",
        Service::Reconciler.name(),
        handler::RECONCILER_START
    );
    match http.post_empty(&ingress_url(&path)) {
        Outcome::Response { status: 200, body } => Ok(format!("generation {}", body.trim())),
        Outcome::Response { status, body } => Err(format!("status {status}: {body}")),
        Outcome::Unreachable(reason) => Err(format!("ingress unreachable: {reason}")),
        Outcome::BodyTooLarge => Err("body over the limit".to_string()),
    }
}

#[derive(Debug)]
pub struct StopReport {
    pub stopped: Vec<(CoreRole, Result<String, String>)>,
}

impl StopReport {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.stopped.len() == CoreRole::ALL.len() && self.stopped.iter().all(|(_, r)| r.is_ok())
    }
}

impl fmt::Display for StopReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "examined {} core sessions", self.stopped.len())?;
        for (role, result) in &self.stopped {
            match result {
                Ok(done) => writeln!(formatter, "  {role}: {done}")?,
                Err(error) => writeln!(formatter, "  {role}: failed: {error}")?,
            }
        }
        Ok(())
    }
}

/// Stops the endpoint before the server, each by its recorded pid with SIGTERM.
#[must_use]
pub fn stop(supervisor: &Supervisor) -> StopReport {
    let mut stopped = Vec::new();
    for role in [CoreRole::Endpoint, CoreRole::Restate] {
        let result = supervisor
            .zmx()
            .list()
            .map_err(|error| error.to_string())
            .and_then(|entries| match presence(&entries, role.session_name()) {
                Presence::Absent => Ok("not running".to_string()),
                Presence::Running { pid, .. } | Presence::Ended { pid } => supervisor
                    .stop(role, pid, "-TERM")
                    .map(|()| format!("stopped pid {pid}")),
                Presence::Unrecognised => Err("zmx list is unrecognised".to_string()),
            });
        stopped.push((role, result));
    }
    StopReport { stopped }
}

#[derive(Debug)]
pub struct StatusReport {
    pub roles: Vec<(CoreRole, Presence, Health)>,
    pub failure: Option<String>,
}

impl StatusReport {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.failure.is_none()
            && self.roles.len() == CoreRole::ALL.len()
            && self.roles.iter().all(|(_, presence, health)| {
                matches!(presence, Presence::Running { .. }) && health.is_healthy()
            })
    }
}

impl fmt::Display for StatusReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "examined {} core sessions", self.roles.len())?;
        for (role, presence, health) in &self.roles {
            writeln!(formatter, "  {role}: {presence:?}, {health}")?;
        }
        if let Some(failure) = &self.failure {
            writeln!(formatter, "  failure: {failure}")?;
        }
        Ok(())
    }
}

#[must_use]
pub fn status(supervisor: &Supervisor) -> StatusReport {
    let entries = match supervisor.zmx().list() {
        Ok(entries) => entries,
        Err(error) => {
            return StatusReport {
                roles: Vec::new(),
                failure: Some(format!("zmx list: {error}")),
            }
        }
    };
    let roles = CoreRole::ALL
        .iter()
        .map(|role| {
            (
                *role,
                presence(&entries, role.session_name()),
                health::probe(supervisor.http(), *role),
            )
        })
        .collect();
    StatusReport {
        roles,
        failure: None,
    }
}

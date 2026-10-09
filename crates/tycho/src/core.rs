//! `tycho core start|stop|status` over the two core sessions.

use std::fmt;

use crate::config::CoreRole;
use crate::health::{self, Health};
use crate::watchdog::{OnceReport, Supervisor};
use crate::zmx::{presence, Presence};

/// Starts whatever is missing and registers the endpoint; the watchdog's own pass.
#[must_use]
pub fn start(supervisor: &Supervisor) -> OnceReport {
    supervisor.once()
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

//! `tycho core start|stop|status` over the two core sessions.

use std::fmt;
use std::thread;

use tycho_types::service::{handler, Service, RECONCILER_KEY};

use crate::config::{
    CoreConfig, CorePorts, CoreRole, COMMAND_TIMEOUT, HEALTH_WAIT_POLLS_MAX, POLL_INTERVAL,
};
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

/// The watchdog's pass, the operator secret if absent, and a new reconciler tick chain.
#[must_use]
pub fn start(supervisor: &Supervisor, config: &CoreConfig) -> StartReport {
    let once = supervisor.once();
    let operator_secret =
        operator::ensure_secret_file(&config.operator_secret_file()).and_then(|created| {
            operator::read_secret_file(&config.operator_secret_file())?;
            Ok(if created { "created" } else { "present" }.to_string())
        });
    let reconciler = if once.succeeded() {
        let (http, ports) = (supervisor.http(), supervisor.ports());
        wait_for_ingress(
            HEALTH_WAIT_POLLS_MAX,
            &mut || health::probe_ingress(http, ports),
            &mut || thread::sleep(POLL_INTERVAL),
        )
        .map_err(|last| format!("ingress did not become healthy: {last}"))
        .and_then(|_| start_reconciler(ports))
    } else {
        Err("not attempted: the core did not come up".to_string())
    };
    StartReport {
        once,
        operator_secret,
        reconciler,
    }
}

/// Restate's admin API answers before its ingress listens, and under load the gap outlasts
/// one call, so the reconciler's first tick waits for the ingress; returns the probes it took.
pub fn wait_for_ingress(
    polls_max: u32,
    probe: &mut dyn FnMut() -> Health,
    wait: &mut dyn FnMut(),
) -> Result<u32, Health> {
    let mut last = Health::Unrecognised("not probed".to_string());
    for poll in 1..=polls_max {
        last = probe();
        if last.is_healthy() {
            return Ok(poll);
        }
        wait();
    }
    Err(last)
}

/// The first call through ingress reaches the endpoint, which can take longer than a probe;
/// it is not retried, since a second start would begin another tick chain generation.
fn start_reconciler(ports: CorePorts) -> Result<String, String> {
    let http = Http::new(COMMAND_TIMEOUT).map_err(|error| error.to_string())?;
    let path = format!(
        "/{}/{RECONCILER_KEY}/{}",
        Service::Reconciler.name(),
        handler::RECONCILER_START
    );
    match http.post_empty(&ports.ingress_url(&path)) {
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
                health::probe(supervisor.http(), supervisor.ports(), *role),
            )
        })
        .collect();
    StatusReport {
        roles,
        failure: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unreachable() -> Health {
        Health::Unreachable("connection refused".to_string())
    }

    #[test]
    fn the_reconciler_kick_waits_until_the_ingress_answers() {
        let mut answers = vec![Health::Healthy, unreachable(), unreachable()];
        let mut waits = 0;
        let polls = wait_for_ingress(
            HEALTH_WAIT_POLLS_MAX,
            &mut || answers.pop().unwrap(),
            &mut || waits += 1,
        );
        assert_eq!(polls, Ok(3));
        assert_eq!(waits, 2);
    }

    #[test]
    fn an_ingress_that_never_answers_fails_after_the_bound_with_the_last_probe() {
        let mut probes = 0;
        let mut waits = 0;
        let outcome = wait_for_ingress(
            4,
            &mut || {
                probes += 1;
                unreachable()
            },
            &mut || waits += 1,
        );
        assert_eq!(outcome, Err(unreachable()));
        assert_eq!((probes, waits), (4, 4));
    }

    #[test]
    fn a_healthy_ingress_is_probed_once_without_waiting() {
        let mut waits = 0;
        let polls = wait_for_ingress(4, &mut || Health::Healthy, &mut || waits += 1);
        assert_eq!((polls, waits), (Ok(1), 0));
    }
}

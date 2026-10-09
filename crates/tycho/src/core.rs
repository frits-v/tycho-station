//! `tycho core start|stop|status` over the two core sessions.

use std::fmt;
use std::thread;

use tycho_types::service::{handler, Service, RECONCILER_KEY};

use crate::config::{
    CoreConfig, CorePorts, CoreRole, COMMAND_TIMEOUT, HEALTH_WAIT_POLLS_MAX, POLL_INTERVAL,
};
use crate::health::{self, Health};
use crate::http::{Http, Outcome, TIMED_OUT};
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

/// The first call through ingress reaches the endpoint, so it gets the command timeout.
fn start_reconciler(ports: CorePorts) -> Result<String, String> {
    let http = Http::new(COMMAND_TIMEOUT).map_err(|error| error.to_string())?;
    let url = |handler_name: &str| {
        ports.ingress_url(&format!(
            "/{}/{RECONCILER_KEY}/{handler_name}",
            Service::Reconciler.name()
        ))
    };
    kick_reconciler(
        &mut || http.post_empty(&url(handler::RECONCILER_START)),
        &mut || http.post_empty(&url(handler::RECONCILER_STATUS)),
    )
}

fn start_again(start: &mut dyn FnMut() -> Outcome, reason: &str) -> Result<String, String> {
    match decode_start(start()) {
        StartAnswer::Started(done) => Ok(format!("{done}, after a start that {reason}")),
        StartAnswer::TimedOut(again) | StartAnswer::Failed(again) => Err(format!(
            "the start {reason}, the view showed no generation, and the second start: {again}"
        )),
    }
}

/// What one start call answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartAnswer {
    Started(String),
    /// The call may have been accepted before the answer was lost.
    TimedOut(String),
    Failed(String),
}

#[must_use]
pub fn decode_start(outcome: Outcome) -> StartAnswer {
    match outcome {
        Outcome::Response { status: 200, body } => {
            StartAnswer::Started(format!("generation {}", body.trim()))
        }
        Outcome::Response { status, body } => {
            StartAnswer::Failed(format!("status {status}: {body}"))
        }
        Outcome::Unreachable(reason) if reason.starts_with(TIMED_OUT) => {
            StartAnswer::TimedOut(reason)
        }
        Outcome::Unreachable(reason) => {
            StartAnswer::Failed(format!("ingress unreachable: {reason}"))
        }
        Outcome::BodyTooLarge => StartAnswer::Failed("body over the limit".to_string()),
    }
}

/// The generation in the reconciler's view, when the view answered with one.
#[must_use]
pub fn view_generation(outcome: &Outcome) -> Option<u64> {
    match outcome {
        Outcome::Response { status: 200, body } => serde_json::from_str::<serde_json::Value>(body)
            .ok()?
            .get("generation")?
            .as_u64()
            .filter(|generation| *generation >= 1),
        _ => None,
    }
}

/// Starts the reconciler's tick chain, reading the view when the start timed out.
///
/// A timed-out start may have been accepted, so the view decides: a generation means the
/// chain runs, and none gets one more start. A second start after an accepted one is
/// harmless, since the older chain ends at its next tick.
pub fn kick_reconciler(
    start: &mut dyn FnMut() -> Outcome,
    view: &mut dyn FnMut() -> Outcome,
) -> Result<String, String> {
    match decode_start(start()) {
        StartAnswer::Started(done) => Ok(done),
        StartAnswer::Failed(reason) => Err(reason),
        StartAnswer::TimedOut(reason) => view_generation(&view()).map_or_else(
            || start_again(start, &reason),
            |generation| {
                Ok(format!(
                    "generation {generation}, read from the view after the start {reason}"
                ))
            },
        ),
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
                Presence::Running { pid, .. } => supervisor
                    .stop(role, pid, "-TERM")
                    .map(|()| format!("stopped pid {pid}")),
                Presence::Ended { pid } => supervisor
                    .remove(role)
                    .map(|()| format!("removed the ended entry (pid {pid} not signalled)")),
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

    fn timed_out() -> Outcome {
        Outcome::Unreachable(format!("{TIMED_OUT}: operation timed out"))
    }

    fn answered(body: &str) -> Outcome {
        Outcome::Response {
            status: 200,
            body: body.to_string(),
        }
    }

    #[test]
    fn a_timed_out_start_that_landed_is_read_from_the_view_and_not_repeated() {
        let mut starts = 0;
        let kicked = kick_reconciler(
            &mut || {
                starts += 1;
                timed_out()
            },
            &mut || answered(r#"{"generation":1,"expected":[]}"#),
        );
        assert_eq!(starts, 1);
        assert!(kicked
            .unwrap()
            .starts_with("generation 1, read from the view"));
    }

    #[test]
    fn a_timed_out_start_the_view_does_not_show_is_tried_once_more() {
        let mut answers = vec![answered("1"), timed_out()];
        let kicked = kick_reconciler(&mut || answers.pop().unwrap(), &mut || answered("null"));
        assert!(kicked
            .unwrap()
            .starts_with("generation 1, after a start that"));
        assert!(answers.is_empty());
        let mut starts = 0;
        let refused = kick_reconciler(
            &mut || {
                starts += 1;
                timed_out()
            },
            &mut || answered("null"),
        );
        assert_eq!(starts, 2);
        assert!(refused.is_err());
    }

    #[test]
    fn a_refused_connect_fails_the_start_without_reading_the_view() {
        let mut views = 0;
        let kicked = kick_reconciler(
            &mut || Outcome::Unreachable("connect failed: refused".to_string()),
            &mut || {
                views += 1;
                answered("null")
            },
        );
        assert_eq!(views, 0);
        assert!(kicked.unwrap_err().starts_with("ingress unreachable"));
    }

    #[test]
    fn only_a_view_with_a_generation_counts() {
        assert_eq!(
            view_generation(&answered(r#"{"generation":3,"expected":[]}"#)),
            Some(3)
        );
        for outcome in [
            answered("null"),
            answered(r#"{"generation":0}"#),
            answered("{"),
            Outcome::Response {
                status: 500,
                body: String::new(),
            },
            timed_out(),
        ] {
            assert_eq!(view_generation(&outcome), None, "{outcome:?}");
        }
    }

    #[test]
    fn a_healthy_ingress_is_probed_once_without_waiting() {
        let mut waits = 0;
        let polls = wait_for_ingress(4, &mut || Health::Healthy, &mut || waits += 1);
        assert_eq!((polls, waits), (Ok(1), 0));
    }
}

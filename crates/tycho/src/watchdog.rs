//! Probes the two core sessions, restarts whichever is missing or dead, and registers the
//! endpoint once both answer.

use std::fmt;
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::command;
use crate::config::{
    CoreConfig, CoreRole, COMMAND_TIMEOUT, HEALTH_WAIT_POLLS_MAX, POLL_INTERVAL,
    SESSION_WAIT_POLLS_MAX, STARTUP_GRACE_SECONDS,
};
use crate::health::{self, Health, Registration};
use crate::http::Http;
use crate::private_dir::{self, DirError};
use crate::zmx::{presence, Presence, Zmx};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Nothing,
    /// Unhealthy but younger than the startup grace.
    Wait,
    Run,
    KillThenRun {
        pid: u32,
    },
    /// The state is one the watchdog must not act on.
    Refuse,
}

/// The restart decision table.
#[must_use]
pub const fn decide(presence: Presence, health: &Health, now_unix_seconds: u64) -> Action {
    match presence {
        Presence::Running { .. } if health.is_healthy() => Action::Nothing,
        Presence::Running {
            pid,
            created_unix_seconds,
        } => {
            let age = now_unix_seconds.saturating_sub(created_unix_seconds);
            if age < STARTUP_GRACE_SECONDS {
                Action::Wait
            } else {
                Action::KillThenRun { pid }
            }
        }
        Presence::Ended { pid } => Action::KillThenRun { pid },
        Presence::Absent if health.is_healthy() => Action::Refuse,
        Presence::Absent => Action::Run,
        Presence::Unrecognised => Action::Refuse,
    }
}

#[derive(Debug)]
pub struct RoleReport {
    pub role: CoreRole,
    pub presence: Presence,
    pub health: Health,
    pub action: Action,
    pub result: Result<String, String>,
}

#[derive(Debug)]
pub struct OnceReport {
    pub roles: Vec<RoleReport>,
    pub registration: Option<Registration>,
    pub failure: Option<String>,
}

impl OnceReport {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.failure.is_none()
            && self.roles.len() == CoreRole::ALL.len()
            && self.roles.iter().all(|report| report.result.is_ok())
            && self
                .registration
                .as_ref()
                .is_some_and(Registration::is_registered)
    }
}

impl fmt::Display for OnceReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "examined {} core sessions", self.roles.len())?;
        for report in &self.roles {
            let outcome = match &report.result {
                Ok(done) => done.clone(),
                Err(error) => format!("failed: {error}"),
            };
            writeln!(
                formatter,
                "  {}: {:?}, {} -> {:?}: {outcome}",
                report.role, report.presence, report.health, report.action
            )?;
        }
        match &self.registration {
            Some(registration) => writeln!(formatter, "  deployment: {registration}")?,
            None => writeln!(formatter, "  deployment: not attempted")?,
        }
        if let Some(failure) = &self.failure {
            writeln!(formatter, "  failure: {failure}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Supervisor {
    config: CoreConfig,
    zmx: Zmx,
    http: Http,
}

impl Supervisor {
    /// Refuses to supervise until every core directory is private to the current user,
    /// because zmx creates a missing socket directory and its parents with looser modes.
    pub fn new(config: CoreConfig, http: Http) -> Result<Self, DirError> {
        private_dir::ensure(&config.dirs())?;
        let zmx = Zmx::new(&config.zmx, &config.socket_dir());
        Ok(Self { config, zmx, http })
    }

    #[must_use]
    pub const fn zmx(&self) -> &Zmx {
        &self.zmx
    }

    #[must_use]
    pub const fn http(&self) -> &Http {
        &self.http
    }

    /// One probe and repair pass over both core sessions.
    #[must_use]
    pub fn once(&self) -> OnceReport {
        let mut report = OnceReport {
            roles: Vec::new(),
            registration: None,
            failure: None,
        };
        if let Err(error) = private_dir::ensure(&self.config.dirs()) {
            report.failure = Some(error.to_string());
            return report;
        }
        for role in CoreRole::ALL {
            let entries = match self.zmx.list() {
                Ok(entries) => entries,
                Err(error) => {
                    report.failure = Some(format!("zmx list: {error}"));
                    return report;
                }
            };
            let presence = presence(&entries, role.session_name());
            let health = health::probe(&self.http, role);
            let action = decide(presence, &health, now_unix_seconds());
            let result = self.apply(role, action);
            report.roles.push(RoleReport {
                role,
                presence,
                health,
                action,
                result,
            });
        }
        if CoreRole::ALL
            .iter()
            .all(|role| health::probe(&self.http, *role).is_healthy())
        {
            report.registration = Some(health::register(&self.http));
        }
        report
    }

    fn apply(&self, role: CoreRole, action: Action) -> Result<String, String> {
        match action {
            Action::Nothing => Ok("nothing to do".to_string()),
            Action::Wait => Ok("starting; within the grace period".to_string()),
            Action::Refuse => Err("refused to act on this state".to_string()),
            Action::Run => self.start(role),
            Action::KillThenRun { pid } => {
                self.stop(role, pid, "-KILL")?;
                self.start(role)
                    .map(|started| format!("killed pid {pid}; {started}"))
            }
        }
    }

    /// Runs only after a fresh list shows the name absent: zmx run on a live name types
    /// the command into that session instead of failing.
    pub fn start(&self, role: CoreRole) -> Result<String, String> {
        let name = role.session_name();
        let entries = self.zmx.list().map_err(|error| error.to_string())?;
        if presence(&entries, name) != Presence::Absent {
            return Err(format!("{name} is not absent; not starting a second one"));
        }
        self.zmx
            .run_detached(name, &self.config.session_command(role))
            .map_err(|error| error.to_string())?;
        let pid = self.wait_for_running(name)?;
        self.wait_for_health(role)?;
        Ok(format!("started pid {pid}, healthy"))
    }

    /// Signals the recorded pid, then falls back to killing the session by name.
    pub fn stop(&self, role: CoreRole, pid: u32, signal: &str) -> Result<(), String> {
        let name = role.session_name();
        let pid_text = pid.to_string();
        command::run_status(
            Path::new("/bin/kill"),
            &[signal, &pid_text],
            &[],
            COMMAND_TIMEOUT,
        )
        .map_err(|error| error.to_string())?;
        if self.wait_for_absent(name).is_ok() {
            return Ok(());
        }
        self.zmx.kill(name).map_err(|error| error.to_string())?;
        self.wait_for_absent(name)
    }

    fn wait_for_running(&self, name: &str) -> Result<u32, String> {
        for _ in 0..SESSION_WAIT_POLLS_MAX {
            let entries = self.zmx.list().map_err(|error| error.to_string())?;
            if let Presence::Running { pid, .. } = presence(&entries, name) {
                return Ok(pid);
            }
            thread::sleep(POLL_INTERVAL);
        }
        Err(format!("{name} did not appear in zmx list"))
    }

    fn wait_for_absent(&self, name: &str) -> Result<(), String> {
        for _ in 0..SESSION_WAIT_POLLS_MAX {
            let entries = self.zmx.list().map_err(|error| error.to_string())?;
            if presence(&entries, name) == Presence::Absent {
                return Ok(());
            }
            thread::sleep(POLL_INTERVAL);
        }
        Err(format!("{name} is still listed"))
    }

    fn wait_for_health(&self, role: CoreRole) -> Result<(), String> {
        let mut last = Health::Unrecognised("not probed".to_string());
        for _ in 0..HEALTH_WAIT_POLLS_MAX {
            last = health::probe(&self.http, role);
            if last.is_healthy() {
                return Ok(());
            }
            thread::sleep(POLL_INTERVAL);
        }
        Err(format!("{role} did not become healthy: {last}"))
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopEnd {
    IterationsExhausted(u32),
    StopFile(u32),
}

/// Ticks at most `iterations_max` times, sleeping between ticks, and ends early when
/// `stop_requested` answers true.
pub fn run_bounded(
    iterations_max: u32,
    interval: Duration,
    mut stop_requested: impl FnMut() -> bool,
    mut tick: impl FnMut(u32),
    mut sleep: impl FnMut(Duration),
) -> LoopEnd {
    for iteration in 0..iterations_max {
        if stop_requested() {
            return LoopEnd::StopFile(iteration);
        }
        tick(iteration);
        sleep(interval);
    }
    LoopEnd::IterationsExhausted(iterations_max)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn running(created_unix_seconds: u64) -> Presence {
        Presence::Running {
            pid: 42,
            created_unix_seconds,
        }
    }

    fn dead() -> Health {
        Health::Unreachable("refused".to_string())
    }

    #[test]
    fn present_and_healthy_does_nothing() {
        assert_eq!(decide(running(0), &Health::Healthy, NOW), Action::Nothing);
    }

    #[test]
    fn absent_runs() {
        assert_eq!(decide(Presence::Absent, &dead(), NOW), Action::Run);
    }

    #[test]
    fn present_but_unhealthy_kills_the_recorded_pid_then_runs() {
        assert_eq!(
            decide(running(0), &dead(), NOW),
            Action::KillThenRun { pid: 42 }
        );
        assert_eq!(
            decide(Presence::Ended { pid: 7 }, &Health::Healthy, NOW),
            Action::KillThenRun { pid: 7 }
        );
    }

    #[test]
    fn unhealthy_within_the_grace_waits() {
        assert_eq!(decide(running(NOW - 1), &dead(), NOW), Action::Wait);
    }

    #[test]
    fn an_unrecognised_list_is_never_acted_on() {
        assert_eq!(decide(Presence::Unrecognised, &dead(), NOW), Action::Refuse);
    }

    #[test]
    fn a_port_answering_without_a_session_is_refused() {
        assert_eq!(
            decide(Presence::Absent, &Health::Healthy, NOW),
            Action::Refuse
        );
    }

    #[test]
    fn unrecognised_health_is_not_healthy() {
        let health = Health::Unrecognised("status 302".to_string());
        assert_eq!(
            decide(running(0), &health, NOW),
            Action::KillThenRun { pid: 42 }
        );
    }

    #[test]
    fn the_loop_stops_at_its_bound() {
        let mut ticks = 0_u32;
        let mut sleeps = 0_u32;
        let end = run_bounded(3, Duration::ZERO, || false, |_| ticks += 1, |_| sleeps += 1);
        assert_eq!(end, LoopEnd::IterationsExhausted(3));
        assert_eq!((ticks, sleeps), (3, 3));
    }

    #[test]
    fn the_loop_stops_on_the_stop_file() {
        let ticks = std::cell::Cell::new(0_u32);
        let end = run_bounded(
            10,
            Duration::ZERO,
            || ticks.get() >= 2,
            |_| ticks.set(ticks.get() + 1),
            |_| {},
        );
        assert_eq!(end, LoopEnd::StopFile(2));
    }
}

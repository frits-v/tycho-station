//! The spawner port over `spawn` and `kill`: each session is a `tycho launch` under zmx in the
//! agent socket directory.

use std::path::PathBuf;

use tycho_types::envelope::ShortText;
use tycho_types::session::SessionName;

use std::io::Write;

use crate::agent_files::open_append;
use crate::config::{AgentDirs, LOG_DIR};
use crate::kill::{kill_by_name, kill_session, KillReport, KillRequest};
use crate::launch_spec::{HeartbeatTarget, VendorTerminal};
use crate::private_dir;
use crate::process::now_unix_ms;
use crate::services::spawner::{LeaseRead, SpawnSpec, SpawnTerminal, Spawner, SpawnerError};
use crate::spawn::{
    read_lease, save_scrollback, send_line, spawn_session, split_tier, SpawnOutcome, SpawnRequest,
};
use crate::zmx::Zmx;

/// Under the core home's log directory.
pub const KILL_LOG: &str = "kills.log";

#[derive(Debug, Clone)]
pub struct LauncherSpawner {
    pub zmx: Zmx,
    pub dirs: AgentDirs,
    /// The `tycho` binary zmx runs as the launcher.
    pub tycho: PathBuf,
    /// `HOME` in the launcher's environment.
    pub home: PathBuf,
    /// Where scrollback is saved.
    pub core_home: PathBuf,
    pub agent_uid: u32,
    pub heartbeat: HeartbeatTarget,
}

/// Every spawn outcome maps to a pid or a refusal; only an unreadable state is worth a retry.
fn spawned_pid(outcome: SpawnOutcome) -> Result<u32, SpawnerError> {
    match outcome {
        SpawnOutcome::Spawned { pid }
        | SpawnOutcome::Adopted { pid }
        | SpawnOutcome::AdoptedEnded { pid } => Ok(pid),
        SpawnOutcome::Requeue(reason) => Err(SpawnerError::Refused(format!(
            "the lease asks for a re-queue: {reason:?}"
        ))),
        SpawnOutcome::NameTaken(presence) => Err(SpawnerError::Refused(format!(
            "zmx lists the name without a lease: {presence:?}"
        ))),
        SpawnOutcome::Unrecognised(reason) => Err(SpawnerError::Transient(reason)),
    }
}

/// One line of the kill log: when, which session and pid, and every verdict of the report.
#[must_use]
pub fn kill_line(session: &SessionName, pid: u32, report: &KillReport) -> String {
    format!(
        "{} kill {session} pid {pid}: zmx {:?}, launcher {:?}, vendor {:?}\n",
        now_unix_ms(),
        report.zmx_kill,
        report.launcher,
        report.vendor
    )
}

impl LauncherSpawner {
    fn log_kill(&self, line: &str) -> Result<(), SpawnerError> {
        let dir = self.core_home.join(LOG_DIR);
        let path = dir.join(KILL_LOG);
        private_dir::ensure(&[self.core_home.clone(), dir])
            .map_err(|error| SpawnerError::Transient(error.to_string()))?;
        open_append(&path)
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .map_err(|error| SpawnerError::Transient(format!("{}: {error}", path.display())))
    }
}

impl Spawner for LauncherSpawner {
    fn describe(&self) -> String {
        format!("launcher under zmx in {}", self.dirs.socket_dir.display())
    }

    fn spawn(&self, spec: &SpawnSpec) -> Result<u32, SpawnerError> {
        let words: Vec<String> = spec
            .argv
            .iter()
            .map(|word| word.as_str().to_string())
            .collect();
        let (vendor, tier) = split_tier(&words);
        let terminal = match spec.terminal {
            SpawnTerminal::Files => VendorTerminal::Files,
            SpawnTerminal::Inherit => VendorTerminal::Inherit,
        };
        let vendor_dir = spec
            .working_dir
            .as_ref()
            .map(|dir| PathBuf::from(dir.as_str()));
        spawn_session(&SpawnRequest {
            zmx: &self.zmx,
            dirs: &self.dirs,
            tycho: &self.tycho,
            home: &self.home,
            env: &spec.environment,
            heartbeat: self.heartbeat,
            vendor,
            agent_uid: self.agent_uid,
            tier,
            terminal,
            vendor_dir: vendor_dir.as_deref(),
        })
        .and_then(spawned_pid)
    }

    /// Succeeds once zmx killed the session by name; the launcher and vendor verdicts go to
    /// the kill log, and a log that cannot be written fails the kill so the step retries.
    fn kill(&self, session: &SessionName, pid: u32) -> Result<(), SpawnerError> {
        let report = kill_session(&KillRequest {
            zmx: &self.zmx,
            dirs: &self.dirs,
            session,
            pid,
            agent_uid: self.agent_uid,
            tycho: &self.tycho,
        });
        self.log_kill(&kill_line(session, pid, &report))?;
        report.zmx_kill.map_err(SpawnerError::Transient)
    }

    fn kill_by_name(&self, session: &SessionName) -> Result<(), SpawnerError> {
        kill_by_name(&self.zmx, session)
    }

    fn save_scrollback(&self, session: &SessionName) -> Result<ShortText, SpawnerError> {
        let path = save_scrollback(&self.zmx, &self.core_home, session)?;
        ShortText::parse(&path.display().to_string())
            .map_err(|error| SpawnerError::Refused(error.to_string()))
    }

    fn send(&self, session: &SessionName, text: &ShortText) -> Result<(), SpawnerError> {
        send_line(&self.zmx, session, text)
    }

    fn read_lease(&self, session: &SessionName) -> LeaseRead {
        read_lease(&self.dirs, session, self.agent_uid)
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use std::path::Path;
    use tycho_types::lease::RequeueReason;

    #[test]
    fn a_kill_logs_both_verdicts() {
        use crate::kill::{KillRefusal, KillVerdict};
        let home = std::env::temp_dir().join(format!("tycho-kill-log-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&home));
        std::fs::create_dir_all(&home).unwrap();
        let spawner = LauncherSpawner {
            zmx: Zmx::agent(Path::new("/usr/bin/true"), &home),
            dirs: AgentDirs::new(home.join("agent")).unwrap(),
            tycho: PathBuf::from("/opt/tycho"),
            home: home.clone(),
            core_home: home.join("core"),
            agent_uid: 1,
            heartbeat: HeartbeatTarget::Session,
        };
        let report = KillReport {
            zmx_kill: Ok(()),
            launcher: KillVerdict::Refused(KillRefusal::CoreUid),
            vendor: Some(KillVerdict::Signalled),
        };
        let session = SessionName::parse("cf7a.wu01.wrk.claude.a1f3").unwrap();
        spawner.log_kill(&kill_line(&session, 42, &report)).unwrap();
        let log = std::fs::read_to_string(home.join("core").join(LOG_DIR).join(KILL_LOG)).unwrap();
        assert!(
            log.contains("kill cf7a.wu01.wrk.claude.a1f3 pid 42"),
            "{log}"
        );
        assert!(
            log.contains("launcher Refused(CoreUid)") && log.contains("vendor Some(Signalled)"),
            "{log}"
        );
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn every_spawn_outcome_maps_to_a_pid_or_a_refusal() {
        assert_eq!(spawned_pid(SpawnOutcome::Spawned { pid: 7 }), Ok(7));
        assert_eq!(spawned_pid(SpawnOutcome::Adopted { pid: 8 }), Ok(8));
        assert_eq!(spawned_pid(SpawnOutcome::AdoptedEnded { pid: 9 }), Ok(9));
        assert!(matches!(
            spawned_pid(SpawnOutcome::Requeue(RequeueReason::Stale)),
            Err(SpawnerError::Refused(_))
        ));
        assert!(matches!(
            spawned_pid(SpawnOutcome::NameTaken(crate::zmx::Presence::Absent)),
            Err(SpawnerError::Refused(_))
        ));
        assert!(matches!(
            spawned_pid(SpawnOutcome::Unrecognised("zmx list".to_string())),
            Err(SpawnerError::Transient(_))
        ));
    }
}

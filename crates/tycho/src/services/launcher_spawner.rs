//! The spawner port over `spawn` and `kill`: each session is a `tycho launch` under zmx in the
//! agent socket directory.

use std::path::PathBuf;

use tycho_types::envelope::ShortText;
use tycho_types::session::SessionName;

use crate::config::AgentDirs;
use crate::kill::{kill_by_name, kill_session, KillRequest};
use crate::launch_spec::HeartbeatTarget;
use crate::services::spawner::{LeaseRead, SpawnSpec, Spawner, SpawnerError};
use crate::spawn::{
    read_lease, save_scrollback, send_line, spawn_session, split_tier, SpawnOutcome, SpawnRequest,
};
use crate::zmx::Zmx;

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
        })
        .and_then(spawned_pid)
    }

    /// Succeeds once zmx killed the session by name; the report's signals are best effort.
    fn kill(&self, session: &SessionName, pid: u32) -> Result<(), SpawnerError> {
        let report = kill_session(&KillRequest {
            zmx: &self.zmx,
            dirs: &self.dirs,
            session,
            pid,
            agent_uid: self.agent_uid,
            tycho: &self.tycho,
        });
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
mod tests {
    use super::*;
    use tycho_types::lease::RequeueReason;

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

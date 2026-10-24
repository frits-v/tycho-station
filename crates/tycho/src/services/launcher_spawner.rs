//! The spawner port over `spawn` and `kill`: each session is a `tycho launch` under zmx in the
//! agent socket directory.

use std::path::PathBuf;

use tycho_types::envelope::ShortText;
use tycho_types::session::SessionName;

use std::io::Write;

use nix::unistd::{Uid, User};

use crate::agent_files::open_append;
use crate::config::{AgentDirs, ConfigError, CorePorts, LOG_DIR, ToolPrefix};
use crate::credentials::{self, Credential, CredentialVendor};
use crate::kill::{KillReport, KillRequest, kill_by_name, kill_session};
use crate::launch_spec::{HeartbeatTarget, VendorTerminal};
use crate::private_dir;
use crate::process::now_unix_ms;
use crate::services::spawner::{LeaseRead, SpawnSpec, SpawnTerminal, Spawner, SpawnerError};
use crate::spawn::{
    SpawnOutcome, SpawnRequest, read_lease, save_scrollback, send_line, spawn_session, split_tier,
};
use crate::zmx::Zmx;

/// Under the core home's log directory.
pub const KILL_LOG: &str = "kills.log";

/// Built only by `for_prefix`, so the launcher and zmx are always the prefix's.
#[derive(Debug, Clone)]
pub struct LauncherSpawner {
    zmx: Zmx,
    pub dirs: AgentDirs,
    /// The `tycho` binary zmx runs as the launcher.
    tycho: PathBuf,
    /// `HOME` in the launcher's environment.
    pub home: PathBuf,
    /// Where scrollback is saved and the vendor credentials are kept.
    pub core_home: PathBuf,
    pub agent_uid: u32,
    pub heartbeat: HeartbeatTarget,
    /// The ports of the core whose ingress the launchers report to.
    pub ports: CorePorts,
    /// Where each session's binaries and mise installs come from.
    tool_prefix: ToolPrefix,
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
    /// A spawner whose launcher is the prefix's `tycho` and whose sessions run under the
    /// prefix's recorded zmx, so a session starts from the prefix and from nothing else. An
    /// agent other than the caller gets its sessions through the sudoers rule: `zmx run` as
    /// that user, so the session daemon and the launcher are the agent's.
    pub fn for_prefix(
        tool_prefix: ToolPrefix,
        dirs: AgentDirs,
        home: PathBuf,
        core_home: PathBuf,
        agent_uid: u32,
        heartbeat: HeartbeatTarget,
        ports: CorePorts,
    ) -> Result<Self, ConfigError> {
        let zmx_binary = tool_prefix.tool("zmx").ok_or_else(|| {
            ConfigError::ToolPrefixManifest("station.json records no zmx".to_string())
        })?;
        let zmx = if agent_uid == Uid::current().as_raw() {
            Zmx::agent(zmx_binary, &dirs.socket_dir)
        } else {
            let agent = User::from_uid(Uid::from_raw(agent_uid))
                .map_err(|error| ConfigError::UserLookup(error.to_string()))?
                .ok_or_else(|| ConfigError::NoAgentUser(format!("uid {agent_uid}")))?;
            Zmx::agent_as(zmx_binary, &dirs.socket_dir, &agent.name)
        };
        Ok(Self {
            zmx,
            tycho: tool_prefix.tycho(),
            dirs,
            home,
            core_home,
            agent_uid,
            heartbeat,
            ports,
            tool_prefix,
        })
    }

    /// The core's stored credential for the session's vendor; a vendor that needs one and has
    /// none refuses the spawn with the command that stores it.
    fn credential_for(&self, session: &SessionName) -> Result<Option<Credential>, SpawnerError> {
        CredentialVendor::for_session(session.vendor())
            .map(|vendor| {
                credentials::load(&self.core_home, vendor)
                    .map_err(|error| SpawnerError::Refused(error.to_string()))
            })
            .transpose()
    }

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
        let credential = self.credential_for(&spec.environment.session_name)?;
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
            ports: self.ports,
            tool_prefix: &self.tool_prefix,
            credential: credential.as_ref(),
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
    fn a_prefix_spawner_launches_the_prefix_tycho_under_the_recorded_zmx() {
        let prefix = crate::config::tool_prefix::tests::production();
        let spawner = LauncherSpawner::for_prefix(
            prefix,
            AgentDirs::new(PathBuf::from("/Users/Shared/tycho-agent-zmx")).unwrap(),
            PathBuf::from("/Users/tycho-agent"),
            PathBuf::from("/core"),
            1,
            HeartbeatTarget::Session,
            CorePorts::PRODUCTION,
        )
        .unwrap();
        assert_eq!(
            spawner.tycho,
            PathBuf::from("/Users/Shared/tycho/bin/tycho")
        );
        assert_eq!(
            spawner.zmx.binary(),
            Path::new("/Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx")
        );
        let uid_one = User::from_uid(Uid::from_raw(1)).unwrap().unwrap().name;
        assert_eq!(
            spawner.zmx.switched_to(),
            Some(uid_one.as_str()),
            "another uid's sessions start through sudo as that user"
        );
        let as_caller = |uid: u32| {
            LauncherSpawner::for_prefix(
                crate::config::tool_prefix::tests::production(),
                AgentDirs::new(PathBuf::from("/a")).unwrap(),
                PathBuf::from("/h"),
                PathBuf::from("/c"),
                uid,
                HeartbeatTarget::Session,
                CorePorts::PRODUCTION,
            )
        };
        let same = as_caller(Uid::current().as_raw()).unwrap();
        assert_eq!(
            same.zmx.switched_to(),
            None,
            "the caller's own sessions need no sudo"
        );
        assert!(matches!(
            as_caller(3_999_999),
            Err(ConfigError::NoAgentUser(_))
        ));
        let bare = ToolPrefix::new(PathBuf::from("/tmp/prefix")).unwrap();
        assert!(
            LauncherSpawner::for_prefix(
                bare,
                AgentDirs::new(PathBuf::from("/a")).unwrap(),
                PathBuf::from("/h"),
                PathBuf::from("/c"),
                1,
                HeartbeatTarget::Session,
                CorePorts::PRODUCTION,
            )
            .is_err()
        );
    }

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
            ports: CorePorts::PRODUCTION,
            tool_prefix: ToolPrefix::new(home.join("prefix")).unwrap(),
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
    fn a_vendor_session_needs_the_cores_credential_and_names_how_to_store_it() {
        use crate::credentials::tests::CLAUDE_TOKEN;
        let home = std::env::temp_dir().join(format!("tycho-spawner-cred-{}", std::process::id()));
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
            ports: CorePorts::PRODUCTION,
            tool_prefix: ToolPrefix::new(home.join("prefix")).unwrap(),
        };
        let claude = SessionName::parse("cf7a.wu01.wrk.claude.a1f3").unwrap();
        let refusal = spawner.credential_for(&claude).unwrap_err();
        assert!(
            matches!(&refusal, SpawnerError::Refused(why) if why.contains("tycho credentials set claude")),
            "{refusal:?}"
        );
        let stored = Credential::parse(CredentialVendor::Claude, CLAUDE_TOKEN.as_bytes()).unwrap();
        credentials::store(&spawner.core_home, &stored).unwrap();
        let loaded = spawner.credential_for(&claude).unwrap().unwrap();
        assert_eq!(loaded.vendor(), CredentialVendor::Claude);
        let amp = SessionName::parse("cf7a.wu01.wrk.amp.a1f3").unwrap();
        assert!(spawner.credential_for(&amp).unwrap().is_none());
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

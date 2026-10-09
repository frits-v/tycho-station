//! Test doubles for the spawner, merge gate and control vendor ports, shared by unit and
//! integration tests.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use tycho_types::envelope::ShortText;
use tycho_types::session::{SessionName, Vendor};

use crate::launch_spec::VendorTerminal;
use crate::services::merge_gate::{GateError, GateVerdict, MergeGate, VerifyRequest};
use crate::services::spawner::{LeaseRead, SpawnSpec, Spawner, SpawnerError};
use crate::vendors::control::{
    AddressTarget, ContextReport, ControlCommand, ControlLaunch, Delivery, Observation,
    SessionVendor, VendorError, VendorSessionId,
};

/// Called on every spawn with the spec and the pid it was given.
pub type SpawnHook = Arc<dyn Fn(&SpawnSpec, u32) + Send + Sync>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpawnerLog {
    pub spawned: Vec<(String, u32)>,
    pub killed: Vec<(String, u32)>,
    pub reaped: Vec<String>,
    pub sent: Vec<(String, String)>,
    pub scrollbacks: Vec<String>,
}

#[derive(Default)]
struct Inner {
    log: SpawnerLog,
    leases: BTreeMap<String, LeaseRead>,
    next_pid: u32,
}

/// Records every call, answers lease reads from a table, and starts no process.
#[derive(Clone, Default)]
pub struct RecordingSpawner {
    inner: Arc<Mutex<Inner>>,
    on_spawn: Option<SpawnHook>,
}

impl std::fmt::Debug for RecordingSpawner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecordingSpawner")
    }
}

const FIRST_PID: u32 = 10_000;

impl RecordingSpawner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_hook(hook: SpawnHook) -> Self {
        Self {
            inner: Arc::default(),
            on_spawn: Some(hook),
        }
    }

    pub fn set_lease(&self, session: &SessionName, lease: LeaseRead) {
        self.with(|inner| {
            inner.leases.insert(session.to_string(), lease);
        });
    }

    #[must_use]
    pub fn log(&self) -> SpawnerLog {
        self.with(|inner| inner.log.clone())
    }

    fn with<T>(&self, action: impl FnOnce(&mut Inner) -> T) -> T {
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        action(&mut guard)
    }
}

impl Spawner for RecordingSpawner {
    fn describe(&self) -> String {
        "recording double".to_string()
    }

    fn spawn(&self, spec: &SpawnSpec) -> Result<u32, SpawnerError> {
        let pid = self.with(|inner| {
            let pid = FIRST_PID.saturating_add(inner.next_pid);
            inner.next_pid = inner.next_pid.saturating_add(1);
            inner.log.spawned.push((spec.session.to_string(), pid));
            pid
        });
        if let Some(hook) = &self.on_spawn {
            hook(spec, pid);
        }
        Ok(pid)
    }

    fn kill(&self, session: &SessionName, pid: u32) -> Result<(), SpawnerError> {
        self.with(|inner| inner.log.killed.push((session.to_string(), pid)));
        Ok(())
    }

    fn kill_by_name(&self, session: &SessionName) -> Result<(), SpawnerError> {
        self.with(|inner| inner.log.reaped.push(session.to_string()));
        Ok(())
    }

    fn save_scrollback(&self, session: &SessionName) -> Result<ShortText, SpawnerError> {
        self.with(|inner| inner.log.scrollbacks.push(session.to_string()));
        ShortText::parse(&format!("scrollback/{session}.html"))
            .map_err(|error| SpawnerError::Refused(error.to_string()))
    }

    fn send(&self, session: &SessionName, text: &ShortText) -> Result<(), SpawnerError> {
        self.with(|inner| {
            inner.log.sent.push((session.to_string(), text.to_string()));
        });
        Ok(())
    }

    fn read_lease(&self, session: &SessionName) -> LeaseRead {
        self.with(|inner| {
            inner
                .leases
                .get(&session.to_string())
                .cloned()
                .unwrap_or(LeaseRead::Absent)
        })
    }
}

/// One `address` call the vendor double saw, with how many spawns the spawner had made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressCall {
    pub session: String,
    pub key: String,
    pub instruction: String,
    pub spawns_before: usize,
}

/// A Claude control vendor that records every address and answers it as posted, or as
/// refused when built with `refusing`.
#[derive(Clone)]
pub struct RecordingVendor {
    spawner: RecordingSpawner,
    calls: Arc<Mutex<Vec<AddressCall>>>,
    refuse: bool,
}

impl std::fmt::Debug for RecordingVendor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecordingVendor")
    }
}

pub const DOUBLE_SOCKET: &str = "/tmp/cc-socks/double.sock";

impl RecordingVendor {
    #[must_use]
    pub fn new(spawner: &RecordingSpawner) -> Self {
        Self {
            spawner: spawner.clone(),
            calls: Arc::default(),
            refuse: false,
        }
    }

    #[must_use]
    pub fn refusing(spawner: &RecordingSpawner) -> Self {
        Self {
            refuse: true,
            ..Self::new(spawner)
        }
    }

    #[must_use]
    pub fn calls(&self) -> Vec<AddressCall> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl SessionVendor for RecordingVendor {
    fn describe(&self) -> String {
        "recording vendor double".to_string()
    }

    fn serves(&self, vendor: Vendor) -> bool {
        vendor == Vendor::Claude
    }

    fn control_command(&self, launch: &ControlLaunch) -> Result<ControlCommand, VendorError> {
        Ok(ControlCommand {
            argv: vec![
                "claude-double".to_string(),
                "--session-id".to_string(),
                launch.vendor_session.as_str().to_string(),
            ],
            terminal: VendorTerminal::Inherit,
            working_dir: launch.working_dir.as_str().into(),
        })
    }

    fn address(
        &self,
        target: &AddressTarget,
        key: &ShortText,
        instruction: &ShortText,
    ) -> Delivery {
        let call = AddressCall {
            session: target.session.to_string(),
            key: key.to_string(),
            instruction: instruction.to_string(),
            spawns_before: self.spawner.log().spawned.len(),
        };
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call);
        let socket = DOUBLE_SOCKET.to_string();
        if self.refuse {
            Delivery::Refused { socket }
        } else {
            Delivery::Posted { socket }
        }
    }

    fn observe(&self, _session: &VendorSessionId) -> Observation {
        Observation::Idle { pid: FIRST_PID }
    }

    fn resume_handle(&self, session: &VendorSessionId) -> Result<ShortText, VendorError> {
        ShortText::parse(session.as_str()).map_err(|error| VendorError::Argument(error.to_string()))
    }

    fn context_size(&self, _session: &VendorSessionId) -> ContextReport {
        ContextReport::NoTurnYet
    }

    fn release(&self, _session: &SessionName) -> Result<(), String> {
        Ok(())
    }
}

/// Answers every verify with the same verdict and records the requests.
#[derive(Debug, Clone)]
pub struct FixedGate {
    verdict: GateVerdict,
    requests: Arc<Mutex<Vec<VerifyRequest>>>,
}

impl FixedGate {
    #[must_use]
    pub fn new(verdict: GateVerdict) -> Self {
        Self {
            verdict,
            requests: Arc::default(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> Vec<VerifyRequest> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl MergeGate for FixedGate {
    fn describe(&self) -> String {
        "fixed gate double".to_string()
    }

    fn verify(&self, request: &VerifyRequest) -> Result<GateVerdict, GateError> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request.clone());
        Ok(self.verdict.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::spawner::SpawnTerminal;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tycho_types::envelope::{BranchName, CommitSha};
    use tycho_types::launcher::{AwaitableId, LauncherEnv, SessionSecret};
    use tycho_types::service::{Attempt, WorkUnitId};

    fn session() -> SessionName {
        SessionName::parse("cf7a.wu03.wrk.claude.a1f3").unwrap()
    }

    fn spec() -> SpawnSpec {
        SpawnSpec {
            session: session(),
            argv: vec![ShortText::parse("launcher").unwrap()],
            environment: LauncherEnv {
                awaitable_id: AwaitableId::parse("sign_1abc").unwrap(),
                session_secret: SessionSecret::parse(&"s".repeat(40)).unwrap(),
                session_name: session(),
            },
            terminal: SpawnTerminal::Files,
            working_dir: None,
        }
    }

    #[test]
    fn recording_spawner_logs_and_calls_its_hook() {
        let seen = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&seen);
        let spawner = RecordingSpawner::with_hook(Arc::new(move |_, pid| {
            counter.store(pid, Ordering::SeqCst);
        }));
        let pid = spawner.spawn(&spec()).unwrap();
        assert_eq!(seen.load(Ordering::SeqCst), pid);
        spawner.kill(&session(), pid).unwrap();
        assert_eq!(spawner.log().spawned, vec![(session().to_string(), pid)]);
        assert_eq!(spawner.log().killed, vec![(session().to_string(), pid)]);
        assert_eq!(spawner.read_lease(&session()), LeaseRead::Absent);
    }

    #[test]
    fn fixed_gate_records_requests() {
        let gate = FixedGate::new(GateVerdict::Failed {
            findings: Vec::new(),
        });
        let request = VerifyRequest {
            work_unit: WorkUnitId::parse("wu03").unwrap(),
            attempt: Attempt::FIRST,
            claims: vec![crate::services::merge_gate::Claim {
                task: tycho_types::service::TaskId::parse("t1").unwrap(),
                branch: BranchName::parse("wu03/task").unwrap(),
                head_sha: CommitSha::parse(&"a".repeat(40)).unwrap(),
            }],
        };
        assert!(gate.verify(&request).is_ok());
        assert_eq!(gate.requests(), vec![request]);
    }
}

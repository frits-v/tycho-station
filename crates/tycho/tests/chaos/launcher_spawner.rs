//! A spawner port that starts the real launcher under zmx, with a `sh` fixture as the vendor,
//! and logs every call so a case can count sessions per attempt.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use tycho::agent_files::current_uid;
use tycho::config::{AgentDirs, CorePorts, ToolPrefix};
use tycho::kill::{kill_session, reap, KillRequest, KillVerdict};
use tycho::launcher::{HeartbeatTarget, VendorTerminal};
use tycho::launcher::{SessionFiles, VendorRecord};
use tycho::process::{process_facts, send, ProcessFacts};
use tycho::services::spawner::{LeaseRead, SpawnSpec, Spawner, SpawnerError};
use tycho::spawn::{
    read_lease, save_scrollback, spawn_session, split_tier, SpawnOutcome, SpawnRequest,
};
use tycho::zmx::{count_named, presence, Zmx};
use tycho_harness::tool_prefix::link_scratch_prefix;
use tycho_types::envelope::ShortText;
use tycho_types::launcher::LauncherEnv;
use tycho_types::session::SessionName;

use crate::support::{clear_sessions, mise_which, TYCHO};

const VENDOR_SCRIPT: &str = r#"#!/bin/sh
# $1 seconds to run, $2 result file content or empty
sleep "$1"
if [ -n "$2" ]; then printf '%s' "$2" > "$TYCHO_RESULT_FILE"; fi
exit 0
"#;

pub const HEAD_SHA: &str = "1111111111111111111111111111111111111111";

/// How long the fixture vendor runs for one session, and whether it writes a result.
#[derive(Debug, Clone, Copy)]
pub struct VendorRun {
    pub seconds: u32,
    pub result: bool,
}

pub type VendorPlan = Arc<dyn Fn(&SessionName) -> VendorRun + Send + Sync>;

#[derive(Debug, Clone, Default)]
pub struct LauncherLog {
    /// Every spawn call with what `spawn_session` answered.
    pub spawned: Vec<(String, String)>,
    pub killed: Vec<(String, String)>,
    /// Every reap with the verdict on the session's recorded vendor.
    pub reaped: Vec<(String, Option<KillVerdict>)>,
}

struct Inner {
    zmx: Zmx,
    /// A scratch prefix holding the built `tycho` and the pinned tools, where sessions start.
    prefix: ToolPrefix,
    /// The prefix's `tycho`, which zmx types as the launcher.
    launcher: PathBuf,
    dirs: AgentDirs,
    home: PathBuf,
    core_ports: CorePorts,
    fixture: PathBuf,
    plan: VendorPlan,
    log: Mutex<LauncherLog>,
    environments: Mutex<BTreeMap<String, LauncherEnv>>,
}

#[derive(Clone)]
pub struct LauncherSpawner {
    inner: Arc<Inner>,
}

impl LauncherSpawner {
    /// `core_home` holds the fixture and scrollback; the agent directory is short for zmx sockets.
    pub fn new(core_home: &Path, core_ports: CorePorts, tag: &str, plan: VendorPlan) -> Self {
        let user_home = PathBuf::from(env::var_os("HOME").unwrap());
        let agent = user_home.join(format!(".tca-{tag}-{}", std::process::id()));
        let prefix_root = user_home.join(format!(".tcx-{tag}-{}", std::process::id()));
        for dir in [&agent, &prefix_root] {
            if dir.exists() {
                fs::remove_dir_all(dir).unwrap();
            }
        }
        let fixture = core_home.join("vendor.sh");
        fs::write(&fixture, VENDOR_SCRIPT).unwrap();
        let prefix = scratch_prefix(&prefix_root, &mise_which("zmx"));
        Self {
            inner: Arc::new(Inner {
                zmx: Zmx::agent(prefix.tool("zmx").unwrap(), &agent),
                launcher: prefix.tycho(),
                prefix,
                dirs: AgentDirs::new(agent).unwrap(),
                home: core_home.to_path_buf(),
                core_ports,
                fixture,
                plan,
                log: Mutex::new(LauncherLog::default()),
                environments: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    pub fn log(&self) -> LauncherLog {
        self.inner
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn zmx(&self) -> &Zmx {
        &self.inner.zmx
    }

    pub fn files(&self, session: &str) -> SessionFiles {
        SessionFiles::new(&self.inner.dirs, &SessionName::parse(session).unwrap())
    }

    /// How many sessions `zmx list` shows under this exact name.
    pub fn listed(&self, session: &str) -> usize {
        count_named(&self.inner.zmx.list().unwrap(), session)
    }

    pub fn lease(&self, session: &str) -> LeaseRead {
        read_lease(
            &self.inner.dirs,
            &SessionName::parse(session).unwrap(),
            current_uid(),
        )
    }

    /// The spawned session names in spawn order, one entry per spawn call.
    pub fn spawned_names(&self) -> Vec<String> {
        self.log()
            .spawned
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    /// Calls `spawn_session` again with the environment the port was given, as a replayed step would.
    pub fn respawn(&self, session: &str) -> SpawnOutcome {
        let environment = self
            .inner
            .environments
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(session)
            .cloned()
            .unwrap();
        let outcome = self.spawn_with(&environment, None).unwrap();
        println!("evidence: spawn_session({session}) again -> {outcome:?}");
        outcome
    }

    fn vendor(&self, session: &SessionName) -> Vec<String> {
        let run = (self.inner.plan)(session);
        let result = if run.result {
            result_json(session)
        } else {
            String::new()
        };
        vec![
            "/bin/sh".to_string(),
            self.inner.fixture.display().to_string(),
            run.seconds.to_string(),
            result,
        ]
    }

    fn spawn_with(
        &self,
        environment: &LauncherEnv,
        tier: Option<&str>,
    ) -> Result<SpawnOutcome, SpawnerError> {
        let user_home = PathBuf::from(env::var_os("HOME").unwrap());
        let vendor = self.vendor(&environment.session_name);
        spawn_session(&SpawnRequest {
            zmx: &self.inner.zmx,
            dirs: &self.inner.dirs,
            tycho: &self.inner.launcher,
            home: &user_home,
            env: environment,
            heartbeat: HeartbeatTarget::Session,
            vendor: &vendor,
            agent_uid: current_uid(),
            tier,
            terminal: VendorTerminal::Files,
            vendor_dir: None,
            ports: self.inner.core_ports,
            tool_prefix: &self.inner.prefix,
            // The chaos vendor is a script; the hand-off is the launcher suite's.
            credential: None,
        })
    }

    fn record<T>(&self, action: impl FnOnce(&mut LauncherLog) -> T) -> T {
        let mut log = self
            .inner
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        action(&mut log)
    }

    /// Kills what a case left: sessions by pid and name, vendors orphaned by a killed launcher.
    pub fn teardown(&self) -> usize {
        for name in self.spawned_names() {
            if kill_orphan_vendor(&self.files(&name)) {
                println!("teardown: killed the orphaned vendor of {name}");
            }
        }
        let left = clear_sessions(&self.inner.zmx, "agent", &self.inner.launcher);
        drop(fs::remove_dir_all(&self.inner.dirs.socket_dir));
        drop(fs::remove_dir_all(self.inner.prefix.root()));
        left
    }
}

/// The pid of the session's fixture vendor while it still runs, from the launcher's record.
pub fn running_vendor(files: &SessionFiles) -> Option<u32> {
    let bytes = fs::read(&files.vendor).ok()?;
    let record = serde_json::from_slice::<VendorRecord>(&bytes).ok()?;
    matches!(
        process_facts(record.pid),
        ProcessFacts::Running(facts) if facts.command.contains("vendor.sh")
    )
    .then_some(record.pid)
}

/// The test's own cleanup of a vendor left running after its launcher died: the vendor leads its
/// own session, so neither `zmx kill` nor the launcher's end reaches it once the launcher is
/// killed. This suite runs the agent as the core's own user, where the kill path refuses to
/// signal (`CoreUid`), so the vendor is orphaned and only this cleanup ends it. With sessions as
/// the agent the core delivers the kill through the sudoers rule, which no suite here runs; true
/// when one was running.
pub fn kill_orphan_vendor(files: &SessionFiles) -> bool {
    let pid = running_vendor(files);
    if let Some(pid) = pid {
        drop(send(pid, true, nix::sys::signal::Signal::SIGKILL));
    }
    pid.is_some()
}

/// The result envelope the fixture vendor writes, addressed from the session itself.
pub fn result_json(session: &SessionName) -> String {
    let name = session.to_string();
    let suffix = name.rsplit('.').next().unwrap_or("x");
    let envelope = result_envelope(session, &format!("wu01/{suffix}"), HEAD_SHA);
    serde_json::json!({ "state": "completed", "envelope": envelope }).to_string()
}

/// A done result from `session`, in the envelope the launcher resolves its awaitable with.
pub fn result_envelope(session: &SessionName, branch: &str, head: &str) -> serde_json::Value {
    let epic = session.epic();
    serde_json::json!({
        "schema_version": 1,
        "id": "01J9Z3K7Q8R2W5X6Y7Z8A9B0C1",
        "type": "result",
        "work_unit_id": "wu01",
        "from": session.to_string(),
        "to": format!("{epic}.wu01.ctl.claude"),
        "causation_id": null,
        "correlation_id": epic.to_string(),
        "created_at_unix_ms": 1,
        "expires_at_unix_ms": null,
        "payload": {
            "outcome": "done",
            "branch": branch,
            "head_sha": head,
            "criteria": [],
            "usage": {"input_tokens": 1200, "output_tokens": 300}
        }
    })
}

impl Spawner for LauncherSpawner {
    fn describe(&self) -> String {
        "real launcher under zmx with a sh vendor".to_string()
    }

    fn spawn(&self, spec: &SpawnSpec) -> Result<u32, SpawnerError> {
        let argv: Vec<String> = spec.argv.iter().map(ToString::to_string).collect();
        let (_, tier) = split_tier(&argv);
        let name = spec.session.to_string();
        self.inner
            .environments
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.clone(), spec.environment.clone());
        let outcome = self.spawn_with(&spec.environment, tier);
        println!("evidence: port spawn({name}) -> {outcome:?}");
        self.record(|log| log.spawned.push((name, format!("{outcome:?}"))));
        match outcome? {
            SpawnOutcome::Spawned { pid }
            | SpawnOutcome::Adopted { pid }
            | SpawnOutcome::AdoptedEnded { pid } => Ok(pid),
            other => Err(SpawnerError::Refused(format!("spawn_session: {other:?}"))),
        }
    }

    fn kill(&self, session: &SessionName, pid: u32) -> Result<(), SpawnerError> {
        let report = kill_session(&KillRequest {
            zmx: &self.inner.zmx,
            dirs: &self.inner.dirs,
            session,
            pid,
            agent_uid: current_uid(),
            tycho: &self.inner.launcher,
        });
        println!("evidence: port kill({session}, {pid}) -> {report:?}");
        self.record(|log| {
            log.killed
                .push((session.to_string(), format!("{report:?}")));
        });
        report.zmx_kill.map_err(SpawnerError::Transient)
    }

    fn kill_by_name(&self, session: &SessionName) -> Result<(), SpawnerError> {
        let name = session.to_string();
        let listed = self
            .inner
            .zmx
            .list()
            .map(|entries| presence(&entries, &name));
        let report = reap(&self.inner.zmx, &self.inner.dirs, session, current_uid());
        println!("evidence: port reap({name}) with the session {listed:?} -> {report:?}");
        self.record(|log| log.reaped.push((name, report.vendor.clone())));
        report.zmx_kill
    }

    fn save_scrollback(&self, session: &SessionName) -> Result<ShortText, SpawnerError> {
        let path = save_scrollback(&self.inner.zmx, &self.inner.home, session)?;
        ShortText::parse(&path.display().to_string())
            .map_err(|error| SpawnerError::Refused(error.to_string()))
    }

    fn send(&self, session: &SessionName, text: &ShortText) -> Result<(), SpawnerError> {
        self.inner
            .zmx
            .send(&session.to_string(), text.as_str())
            .map_err(|error| SpawnerError::Transient(error.to_string()))
    }

    fn read_lease(&self, session: &SessionName) -> LeaseRead {
        read_lease(&self.inner.dirs, session, current_uid())
    }
}

/// Runs the spawner's teardown when a case ends, before the core stops.
pub struct AgentGuard(pub LauncherSpawner);

impl Drop for AgentGuard {
    fn drop(&mut self) {
        let left = self.0.teardown();
        assert!(
            left == 0 || std::thread::panicking(),
            "teardown: {left} agent sessions remain"
        );
    }
}

/// A scratch prefix at `root` with the built `tycho` as its launcher and the developer's
/// pinned tools as its installs, so a session starts from a prefix the way production does.
fn scratch_prefix(root: &Path, zmx: &Path) -> ToolPrefix {
    link_scratch_prefix(
        root,
        Path::new(TYCHO),
        &[
            ("claude", &mise_which("claude")),
            ("codex", &mise_which("codex")),
            ("zmx", zmx),
        ],
    )
    .unwrap();
    let prefix = ToolPrefix::load(root.to_path_buf()).unwrap();
    println!(
        "evidence: sessions start from {} under zmx {}",
        prefix.tycho().display(),
        prefix.tool("zmx").unwrap().display()
    );
    prefix
}

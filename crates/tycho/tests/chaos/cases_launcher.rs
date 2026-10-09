//! The cases that need the real launcher under zmx: the terminal app, the Restate server and
//! the launcher itself are killed while a worker session runs.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tycho::config::{CoreRole, AGENT_USER_ENV};
use tycho::health::{self, Health};
use tycho::launcher::HEARTBEAT_INTERVAL;
use tycho::process::now_unix_ms;
use tycho::services::doubles::FixedGate;
use tycho::services::merge_gate::GateVerdict;
use tycho::services::spawner::LeaseRead;
use tycho::spawn::SpawnOutcome;
use tycho::spool::ACKNOWLEDGED_SUFFIX;
use tycho::zmx::{count_named, presence, Presence};
use tycho_types::envelope::CommitSha;

use crate::launcher_spawner::{running_vendor, AgentGuard, LauncherSpawner, VendorPlan, VendorRun};
use crate::support::{
    attach, await_unit_end, dispatch, http, lifecycle_and_attempt, session_status, start_endpoint,
    start_with_retries, unit_status, wait_until, worker_run_status, Core, DoublesEndpoint, TYCHO,
};

const DEFAULT_SHA: &str = "2222222222222222222222222222222222222222";

fn merged_gate() -> FixedGate {
    FixedGate::new(GateVerdict::Merged {
        default_sha: CommitSha::parse(DEFAULT_SHA).unwrap(),
    })
}

/// Every attempt runs the same fixture vendor.
fn every_attempt(seconds: u32) -> VendorPlan {
    Arc::new(move |_| VendorRun {
        seconds,
        result: true,
    })
}

/// Attempt 1 runs long without a result, so a kill lands before its trap; later attempts finish.
fn first_attempt_hangs() -> VendorPlan {
    Arc::new(|session| {
        if session.to_string().ends_with("a1") {
            VendorRun {
                seconds: 300,
                result: false,
            }
        } else {
            VendorRun {
                seconds: 2,
                result: true,
            }
        }
    })
}

struct Rig {
    spawner: LauncherSpawner,
    _guard: AgentGuard,
    _endpoint: DoublesEndpoint,
    core: Core,
}

/// A started core, then the real-launcher spawner beside it, then the endpoint built from both.
fn rig(core: Core, tag: &str, plan: VendorPlan) -> Rig {
    let spawner = LauncherSpawner::new(&core.config.home, tag, plan);
    let (endpoint, _) = start_endpoint(&core, Arc::new(spawner.clone()), Arc::new(merged_gate()));
    Rig {
        _guard: AgentGuard(spawner.clone()),
        spawner,
        _endpoint: endpoint,
        core,
    }
}

fn started_core(test: &str) -> Core {
    let core = Core::new(test);
    start_with_retries(&core, |core| {
        core.tycho(&["core", "start"])
            .status
            .success()
            .then_some(())
    });
    core
}

/// The session name the port spawned at position `index`, once it is listed under zmx.
fn spawned(rig: &Rig, index: usize) -> String {
    let mut name = String::new();
    wait_until(&format!("spawn at position {index}"), || {
        rig.spawner.spawned_names().get(index).is_some_and(|found| {
            name.clone_from(found);
            true
        })
    });
    name
}

/// Waits for the session's first heartbeat to reach the Session object.
fn wait_for_heartbeat(name: &str) {
    wait_until(&format!("a heartbeat from {name} recorded"), || {
        !session_status(name)["heartbeat_unix_ms"].is_null()
    });
}

/// No duplicate session so far, then the unit ended done in the attempt it ran before the kill.
fn assert_completed(rig: &Rig, invocation: &str, before: &(String, u64), why: &str) {
    sessions_per_attempt(&rig.spawner);
    let view = await_unit_end(why, before);
    let (status, body) = attach(invocation);
    assert_eq!(status, 200, "{body}");
    let after = lifecycle_and_attempt(&view);
    println!("evidence: lifecycle before the kill {before:?}, after {after:?}");
    assert_eq!(after, ("done".to_string(), before.1), "{view}");
    assert_eq!(view["head_sha"], DEFAULT_SHA);
}

/// One spawn call per session name, and zmx listing each name at most once.
fn sessions_per_attempt(spawner: &LauncherSpawner) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for name in spawner.spawned_names() {
        let count = counts.entry(name).or_insert(0_usize);
        *count = count.saturating_add(1);
    }
    println!("evidence: port spawns per session {counts:?}");
    for (name, count) in &counts {
        assert_eq!(*count, 1, "{name} spawned {count} times");
        assert!(spawner.listed(name) <= 1, "{name} listed twice");
    }
    counts
}

fn lease_heartbeat(spawner: &LauncherSpawner, name: &str) -> u64 {
    match spawner.lease(name) {
        LeaseRead::Present { lease } => lease.heartbeat_unix_ms(),
        other => panic!("lease of {name} is {other:?}"),
    }
}

/// A process group the case started; whatever is left of it is killed when the case ends.
struct Group(Child);

impl Drop for Group {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            drop(
                Command::new("/bin/kill")
                    .args(["-KILL", "--", &format!("-{}", self.0.id())])
                    .status(),
            );
            drop(self.0.wait());
        }
    }
}

fn kill_group(group: &mut Group, what: &str) {
    let child = &mut group.0;
    let status = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{}", child.id())])
        .status()
        .unwrap();
    assert!(status.success(), "kill of the {what} group failed");
    assert!(child.wait().is_ok(), "the {what} did not end");
    println!(
        "evidence: SIGKILL to the {what} process group {}",
        child.id()
    );
}

/// The `clients=` count `zmx list` shows for the session; zmx's own field, not a decoded entry.
fn attached_clients(spawner: &LauncherSpawner, name: &str) -> String {
    let listing = Command::new(crate::support::mise_which("zmx"))
        .arg("list")
        .env("ZMX_DIR", spawner.zmx().socket_dir())
        .env_remove("ZMX_SESSION")
        .output()
        .unwrap();
    let prefix = format!("name={name}\t");
    String::from_utf8_lossy(&listing.stdout)
        .lines()
        .find(|line| line.trim_start().starts_with(&prefix))
        .and_then(|line| line.split('\t').find(|field| field.starts_with("clients=")))
        .unwrap_or("clients=absent")
        .to_string()
}

/// A pty client attached to the session, the way a Ghostty tab attaches.
fn attach_client(spawner: &LauncherSpawner, name: &str) -> Group {
    // zmx refuses to attach from inside a session, and this test may itself run inside one.
    let child = Command::new("/usr/bin/script")
        .args(["-q", "/dev/null"])
        .arg(crate::support::mise_which("zmx"))
        .args(["attach", name])
        .env("ZMX_DIR", spawner.zmx().socket_dir())
        .env_remove("ZMX_SESSION")
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let child = Group(child);
    wait_until("zmx lists one attached client", || {
        attached_clients(spawner, name) == "clients=1"
    });
    child
}

/// The shell a terminal tab runs `tycho core start` from, left running as the tab would be.
fn core_from_shell(core: &Core) -> Group {
    start_with_retries(core, shell_running_core_start)
}

fn shell_running_core_start(core: &Core) -> Option<Group> {
    let report = core.config.home.with_extension("start-report");
    let child = Command::new("/bin/sh")
        .args(["-c", "\"$0\" core start > \"$1\" 2>&1; exec /bin/sleep 600"])
        .arg(TYCHO)
        .arg(&report)
        .envs(core.envs())
        .process_group(0)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let child = Group(child);
    wait_until("core start from the shell reported", || {
        fs::read_to_string(&report).is_ok_and(|text| text.contains("core home:"))
    });
    let text = fs::read_to_string(&report).unwrap();
    drop(fs::remove_file(&report));
    println!("evidence: {text}");
    text.contains("reconciler: generation").then_some(child)
}

fn core_sessions_listed_once(core: &Core) {
    let entries = core.core_zmx().list().unwrap();
    for role in CoreRole::ALL {
        let count = count_named(&entries, role.session_name());
        println!("evidence: {role} sessions listed: {count}");
        assert_eq!(count, 1, "{role} must be listed exactly once");
        assert!(
            health::probe(&http(), role).is_healthy(),
            "{role} unhealthy"
        );
    }
}

#[test]
#[ignore = "starts real processes; run with mise run chaos-tests"]
fn terminal_app_killed_leaves_the_session_core_and_unit_running() {
    let core = Core::new("terminal");
    let mut shell = core_from_shell(&core);
    let rig = rig(core, "term", every_attempt(25));
    let invocation = dispatch(&rig.core, &["wu01-t1"]);
    let name = spawned(&rig, 0);
    wait_for_heartbeat(&name);
    let mut client = attach_client(&rig.spawner, &name);
    let before = lifecycle_and_attempt(&unit_status());
    let killed_at = now_unix_ms();
    kill_group(&mut client, "attach client");
    kill_group(&mut shell, "core start shell");
    wait_until("zmx lists no attached client", || {
        attached_clients(&rig.spawner, &name) == "clients=0"
    });
    assert_eq!(
        rig.spawner.listed(&name),
        1,
        "the session outlived its clients"
    );
    core_sessions_listed_once(&rig.core);
    wait_until("the launcher renewed its lease after the kill", || {
        lease_heartbeat(&rig.spawner, &name) > killed_at
    });
    assert_eq!(session_status(&name)["phase"], "running");
    assert_completed(&rig, &invocation, &before, "terminal app killed");
    assert_eq!(rig.spawner.spawned_names(), std::slice::from_ref(&name));
    sessions_per_attempt(&rig.spawner);
    wait_until("the session ended itself", || {
        rig.spawner.listed(&name) == 0
    });
}

fn kill_restate(core: &Core) {
    let pid = match presence(
        &core.core_zmx().list().unwrap(),
        CoreRole::Restate.session_name(),
    ) {
        Presence::Running { pid, .. } => pid,
        other => panic!("restate is {other:?}"),
    };
    let status = Command::new("/bin/kill")
        .args(["-KILL", &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    println!("evidence: SIGKILL to restate-server pid {pid}");
    wait_until("restate unreachable", || {
        matches!(
            health::probe(&http(), CoreRole::Restate),
            Health::Unreachable(_)
        )
    });
}

#[test]
#[ignore = "starts real processes; run with mise run chaos-tests"]
fn restate_killed_between_worker_exit_and_resolve_resolves_on_the_same_attempt() {
    let rig = rig(started_core("restate"), "rest", every_attempt(8));
    let invocation = dispatch(&rig.core, &["wu01-t1"]);
    let name = spawned(&rig, 0);
    wait_for_heartbeat(&name);
    let before = lifecycle_and_attempt(&unit_status());
    kill_restate(&rig.core);
    let files = rig.spawner.files(&name);
    wait_until("the result spooled while restate is down", || {
        files.spool.exists()
    });
    let during = rig.spawner.respawn(&name);
    assert!(matches!(during, SpawnOutcome::Adopted { .. }), "{during:?}");
    assert_eq!(rig.spawner.listed(&name), 1, "adopted, not spawned again");
    assert!(rig.core.tycho(&["watchdog", "once"]).status.success());
    wait_until("the spooled result acknowledged after the restart", || {
        files.spool.with_extension(ACKNOWLEDGED_SUFFIX).exists()
    });
    assert_completed(
        &rig,
        &invocation,
        &before,
        "restate killed before the resolve",
    );
    let run = worker_run_status("wu01-t1");
    println!("evidence: worker run {run}");
    assert_eq!(run["outcome"]["attempt"], 1, "the same attempt");
    assert_eq!(rig.spawner.spawned_names(), std::slice::from_ref(&name));
    sessions_per_attempt(&rig.spawner);
}

/// A heartbeat interval and then some later, the lease of the killed launcher has not moved.
fn assert_lease_frozen(spawner: &LauncherSpawner, name: &str) -> u64 {
    let frozen = lease_heartbeat(spawner, name);
    let observe = HEARTBEAT_INTERVAL.saturating_add(Duration::from_secs(3));
    let started = Instant::now();
    while started.elapsed() < observe {
        assert_eq!(
            lease_heartbeat(spawner, name),
            frozen,
            "a dead launcher renewed"
        );
        thread::sleep(Duration::from_millis(500));
    }
    println!("evidence: lease heartbeat frozen at {frozen} for {observe:?}");
    frozen
}

fn kill_launcher(spawner: &LauncherSpawner, name: &str) {
    let files = spawner.files(name);
    wait_until("the attempt 1 vendor running", || files.vendor.exists());
    let LeaseRead::Present { lease } = spawner.lease(name) else {
        panic!("no lease for {name}");
    };
    let status = Command::new("/bin/kill")
        .args(["-KILL", &lease.pid().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    println!(
        "evidence: SIGKILL to launcher pid {} of {name}",
        lease.pid()
    );
}

/// Nothing resolved, no spool, and a replay of the absent spool is refused.
fn assert_nothing_spooled(rig: &Rig, name: &str) {
    let files = rig.spawner.files(name);
    assert!(
        !files.spool.exists(),
        "a spool exists after a kill before the trap"
    );
    let replay = Command::new(TYCHO)
        .args(["launch", "--replay", &files.spool.display().to_string()])
        .envs(rig.core.envs())
        .env(AGENT_USER_ENV, std::env::var("USER").unwrap())
        .output()
        .unwrap();
    println!(
        "evidence: tycho launch --replay -> {} {}",
        replay.status,
        String::from_utf8_lossy(&replay.stderr).trim()
    );
    assert_eq!(replay.status.code(), Some(2), "replay of a missing spool");
    assert!(String::from_utf8_lossy(&replay.stderr).contains("no spool"));
}

#[test]
#[ignore = "starts real processes; run with mise run chaos-tests"]
fn launcher_killed_before_its_trap_requeues_as_attempt_two() {
    let rig = rig(started_core("trap"), "trap", first_attempt_hangs());
    let invocation = dispatch(&rig.core, &["wu01-t1"]);
    let first = spawned(&rig, 0);
    wait_for_heartbeat(&first);
    let before = lifecycle_and_attempt(&unit_status());
    kill_launcher(&rig.spawner, &first);
    assert_lease_frozen(&rig.spawner, &first);
    assert_nothing_spooled(&rig, &first);
    let second = spawned(&rig, 1);
    println!("evidence: attempt 2 spawned as {second}");
    assert!(first.ends_with("a1") && second.ends_with("a2") && first != second);
    wait_until("attempt 1 reaped by name", || {
        rig.spawner.log().reaped.contains(&first)
    });
    assert_eq!(rig.spawner.listed(&first), 0, "attempt 1 is gone from zmx");
    let orphan = running_vendor(&rig.spawner.files(&first));
    println!("evidence: attempt 1 vendor after the reap by name: {orphan:?}");
    assert_eq!(session_status(&first)["phase"], "lost");
    assert_completed(
        &rig,
        &invocation,
        &before,
        "launcher killed before its trap",
    );
    let run = worker_run_status("wu01-t1");
    println!("evidence: worker run {run}");
    assert_eq!(run["outcome"]["attempt"], 2);
    let counts = sessions_per_attempt(&rig.spawner);
    assert_eq!(counts.len(), 2, "one session per attempt");
}

//! The cases where a recording double stands in for the vendor: the endpoint killed between
//! two tasks, and the slice zero exit test of a first merge with its baselines.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use tycho::code_graph::{Checkout, CodeGraph, StepKey};
use tycho::config::{self, ingress_url};
use tycho::entire_graph::EntireGraph;
use tycho::services::doubles::{FixedGate, RecordingSpawner};
use tycho::services::merge_gate::GateVerdict;
use tycho::services::spawner::SpawnSpec;
use tycho_harness::verify::{unit_passed, verify_unit, VerifyOptions};
use tycho_types::envelope::CommitSha;
use tycho_types::service::WorkUnitId;

use crate::support::{
    admin_query, attach, await_unit_end, client, dispatch, lifecycle_and_attempt, session_status,
    start_core, unit_status, wait_until, worker_run_status, DoublesEndpoint,
};

const DEFAULT_SHA: &str = "2222222222222222222222222222222222222222";
const HEAD_SHA: &str = "1111111111111111111111111111111111111111";

/// Statuses Restate answered to the double's resolves, in arrival order.
type Acks = Arc<Mutex<Vec<u16>>>;

fn result_json(branch: &str, head: &str) -> String {
    format!(
        r#"{{"outcome":"done","branch":"{branch}","head_sha":"{head}","criteria":[],"usage":{{"input_tokens":1200,"output_tokens":300,"cost_micro_dollars":42000}}}}"#
    )
}

/// Resolves the awaitable through ingress after a delay, as a launcher's exit trap would.
fn resolve_later(awaitable: String, delay: Duration, body: String, acks: Acks) {
    thread::spawn(move || {
        thread::sleep(delay);
        let status = client()
            .post(ingress_url(&format!(
                "/restate/awakeables/{awaitable}/resolve"
            )))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_or(0, |response| response.status().as_u16());
        println!("evidence: launcher double resolve -> {status}");
        acks.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(status);
    });
}

fn branch_of(spec: &SpawnSpec) -> String {
    let session = spec.session.to_string();
    format!("wu01/{}", session.rsplit('.').next().unwrap_or("x"))
}

/// The first task resolves late, so the endpoint can be down when it lands; later ones promptly.
fn first_task_late(acks: &Acks) -> RecordingSpawner {
    let spawns = Arc::new(AtomicUsize::new(0));
    let acks = Arc::clone(acks);
    RecordingSpawner::with_hook(Arc::new(move |spec: &SpawnSpec, _pid| {
        let delay = if spawns.fetch_add(1, Ordering::SeqCst) == 0 {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(500)
        };
        let awaitable = spec.environment.awaitable_id.to_string();
        let body = result_json(&branch_of(spec), HEAD_SHA);
        resolve_later(awaitable, delay, body, Arc::clone(&acks));
    }))
}

fn merged_gate(default_sha: &str) -> FixedGate {
    FixedGate::new(GateVerdict::Merged {
        default_sha: CommitSha::parse(default_sha).unwrap(),
    })
}

#[test]
#[ignore = "starts real processes; run with mise run chaos-tests"]
fn endpoint_killed_between_tasks_replays_without_dispatching_twice() {
    let acks: Acks = Arc::default();
    let spawner = first_task_late(&acks);
    let gate = merged_gate(DEFAULT_SHA);
    let (core, endpoint, ports) = start_core(
        "endpoint",
        Arc::new(spawner.clone()),
        Arc::new(gate.clone()),
    );
    let invocation = dispatch(&core, &["wu01-t1", "wu01-t2"]);
    wait_until("task 1 spawned", || spawner.log().spawned.len() == 1);
    let first = spawner.log().spawned[0].0.clone();
    wait_until("task 1 session recorded", || {
        session_status(&first)["phase"] == "running"
    });
    let before = lifecycle_and_attempt(&unit_status());
    drop(endpoint);
    println!("evidence: endpoint killed with task 1 awaiting its result, unit {before:?}");
    wait_until("task 1 resolved while the endpoint is down", || {
        !acks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    });
    let acknowledged = acks.lock().unwrap_or_else(PoisonError::into_inner)[0];
    assert!(
        (200..300).contains(&acknowledged),
        "resolve -> {acknowledged}"
    );
    assert_eq!(
        spawner.log().spawned.len(),
        1,
        "task 2 not dispatched while down"
    );
    let _restarted = DoublesEndpoint::start(&ports);
    println!("evidence: endpoint restarted on the same port");
    await_unit_end("endpoint killed between tasks", &before);
    let (status, body) = attach(&invocation);
    assert_eq!(status, 200, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).unwrap();
    let after = lifecycle_and_attempt(&view);
    println!("evidence: lifecycle before the kill {before:?}, after {after:?}");
    assert_eq!(after, ("done".to_string(), before.1));
    assert_each_task_ran_once(&spawner, &gate);
}

fn assert_each_task_ran_once(spawner: &RecordingSpawner, gate: &FixedGate) {
    let log = spawner.log();
    let names: Vec<&str> = log.spawned.iter().map(|(name, _)| name.as_str()).collect();
    println!("evidence: spawner log {names:?}");
    assert_eq!(names.len(), 2, "one session per task");
    assert_ne!(names[0], names[1]);
    for key in ["wu01-t1", "wu01-t2"] {
        let run = worker_run_status(key);
        println!("evidence: worker run {key} {run}");
        assert_eq!(run["outcome"]["outcome"], "completed");
        assert_eq!(run["outcome"]["attempt"], 1);
    }
    let requests = gate.requests();
    assert_eq!(requests.len(), 1, "one verify");
    let tasks: Vec<&str> = requests[0]
        .claims
        .iter()
        .map(|claim| claim.task.as_str())
        .collect();
    assert_eq!(
        tasks,
        ["wu01-t1", "wu01-t2"],
        "both claims reached the gate once"
    );
}

fn git(checkout: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args([
            "-c",
            "user.name=Tycho Worker",
            "-c",
            "user.email=worker@tycho.station",
        ])
        .args(["-c", "commit.gpgsign=false"])
        .args(arguments)
        .output()
        .unwrap();
    assert!(output.status.success(), "git {arguments:?}: {output:?}");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Clones the synthetic repository, applies the trivial unit's reference patch and commits it.
fn work_in_clone(repository: &Path, checkout: &Path, branch: &str) -> String {
    let status = Command::new("git")
        .args(["clone", "--quiet", "--no-hardlinks"])
        .arg(repository)
        .arg(checkout)
        .status()
        .unwrap();
    assert!(status.success());
    git(checkout, &["checkout", "--quiet", "-b", branch]);
    let patch = include_bytes!("../../../tycho-harness/fixtures/patches/trivial.patch");
    tycho_harness::repository::apply_patch(checkout, patch).unwrap();
    git(
        checkout,
        &["commit", "--quiet", "-am", "feat: answer is 42"],
    );
    git(checkout, &["rev-parse", "HEAD"])
}

/// A worker double that commits the trivial unit's change in a clone and claims its head.
fn committing_worker(repository: PathBuf, checkout: PathBuf, acks: &Acks) -> RecordingSpawner {
    let acks = Arc::clone(acks);
    RecordingSpawner::with_hook(Arc::new(move |spec: &SpawnSpec, _pid| {
        let branch = branch_of(spec);
        let head = work_in_clone(&repository, &checkout, &branch);
        println!("evidence: worker double committed {head} on {branch}");
        let awaitable = spec.environment.awaitable_id.to_string();
        let body = result_json(&branch, &head);
        resolve_later(
            awaitable,
            Duration::from_millis(500),
            body,
            Arc::clone(&acks),
        );
    }))
}

/// Bytes Restate's journal holds per service, from `sys_journal.raw_length`; the test's own
/// `status` probes are left out.
fn journal_bytes() -> (u64, u64) {
    let rows = admin_query(
        "SELECT i.target_service_name AS service, COUNT(*) AS entries, \
         SUM(j.raw_length) AS bytes FROM sys_journal j JOIN sys_invocation i ON j.id = i.id \
         WHERE i.target_handler_name <> 'status' GROUP BY i.target_service_name",
    );
    let (mut unit, mut reconciler) = (0_u64, 0_u64);
    for row in &rows {
        let bytes = row["bytes"].as_u64().unwrap_or(0);
        println!(
            "baseline: journal {} {} entries {bytes} bytes",
            row["service"], row["entries"]
        );
        if row["service"] == "Reconciler" {
            reconciler = reconciler.saturating_add(bytes);
        } else {
            unit = unit.saturating_add(bytes);
        }
    }
    assert!(
        !rows.is_empty(),
        "the journal query examined no invocations"
    );
    (unit, reconciler)
}

fn index_build_time(checkout: &Path, index: &Path) -> u128 {
    let binary = config::entire_graph_path().unwrap();
    let graph = EntireGraph::open(&binary, index).unwrap();
    let started = Instant::now();
    let report = graph
        .build(
            &StepKey::parse("chaos.baseline").unwrap(),
            &WorkUnitId::parse("wu01").unwrap(),
            &Checkout::parse(checkout).unwrap(),
        )
        .unwrap();
    let measured = started.elapsed().as_millis();
    let time = report.index_time();
    println!(
        "baseline: index build {} ms by the port, {measured} ms around the call, {} files, {} symbols, cache hit {}",
        time.wall_clock_ms, report.counts.files, report.counts.symbols, time.cache_hit
    );
    assert!(!report.cache_hit && report.counts.files > 0);
    measured
}

#[test]
#[ignore = "starts real processes; run with mise run chaos-tests"]
fn a_unit_merges_end_to_end_and_records_the_baselines() {
    let scratch = Scratch::new();
    let repository = scratch.0.join("synthetic");
    fs::create_dir_all(&repository).unwrap();
    let built = tycho_harness::repository::build(&repository).unwrap();
    let checkout = scratch.0.join("worktree");
    let acks: Acks = Arc::default();
    let spawner = committing_worker(repository, checkout.clone(), &acks);
    let gate = FixedGate::new(GateVerdict::Merged {
        default_sha: built.head_sha,
    });
    let (core, _endpoint, _) =
        start_core("merge", Arc::new(spawner.clone()), Arc::new(gate.clone()));
    let invocation = dispatch(&core, &["wu01-t1"]);
    await_unit_end("first merge", &("queued".to_string(), 1));
    let (status, body) = attach(&invocation);
    assert_eq!(status, 200, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(view["lifecycle"], "done");
    let claim = gate.requests()[0].claims[0].clone();
    assert_eq!(
        git(&checkout, &["rev-parse", "HEAD"]),
        claim.head_sha.as_str()
    );
    assert_criteria_pass(&checkout);
    assert_eq!(spawner.log().spawned.len(), 1, "one session");
    let (unit, reconciler) = journal_bytes();
    println!("baseline: journal per unit {unit} bytes (reconciler {reconciler} bytes beside it)");
    let measured = index_build_time(&checkout, &core.config.home.join("graph-index"));
    println!("baseline: index build time {measured} ms on the synthetic checkout");
}

/// The synthetic repository and the worker's clone, removed even when an assertion fails.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("tycho-chaos-merge-{}", std::process::id()));
        drop(fs::remove_dir_all(&root));
        fs::create_dir_all(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}

/// The trivial unit's done criteria pass on the claimed head, run by the harness verifier.
fn assert_criteria_pass(checkout: &Path) {
    let units = tycho_harness::work_units::load_default().unwrap();
    let trivial = units.iter().find(|unit| unit.key == "trivial").unwrap();
    let reports = verify_unit(checkout, trivial, &VerifyOptions::default());
    println!("evidence: verify on the claimed head {reports:?}");
    assert!(unit_passed(trivial.pass_condition, &reports), "{reports:?}");
}

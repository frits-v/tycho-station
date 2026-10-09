//! Spine tests against a real core: the core starts through `tycho core start` with a
//! throwaway home, a second endpoint with test doubles registers beside the production one,
//! and the services are driven through Restate's ingress. macOS only, run by
//! `mise run spine-tests`.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the evidence lines are the test's report for the pull request"
)]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers fail the test by panicking"
)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use restate_sdk::prelude::HttpServer;
use tycho::config::{
    admin_url, ingress_url, loopback, CoreConfig, CoreRole, HOME_ENV, MISE_NO_INSTALL,
    RESTATE_INGRESS_PORT, RESTATE_SERVER_ENV, ZMX_ENV,
};
use tycho::endpoint;
use tycho::health;
use tycho::http::Http;
use tycho::services::doubles::{FixedGate, RecordingSpawner};
use tycho::services::merge_gate::{GateVerdict, MergeGate, NoGate};
use tycho::services::operator::read_secret_file;
use tycho::services::spawner::SpawnSpec;
use tycho::services::{Ports, Timing};
use tycho::zmx::{ListEntry, Zmx};
use tycho_types::envelope::CommitSha;
use tycho_types::service::{handler, Service, RECONCILER_KEY};

const TYCHO: &str = env!("CARGO_BIN_EXE_tycho");
const DOUBLES_PORT: u16 = 19_081;
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);

struct Core {
    config: CoreConfig,
    environment: Vec<(&'static str, String)>,
}

impl Core {
    fn new(test: &str) -> Self {
        let user_home = PathBuf::from(env::var_os("HOME").unwrap());
        let home = user_home.join(format!(".tycho-spine-{test}-{}", std::process::id()));
        if home.exists() {
            fs::remove_dir_all(&home).unwrap();
        }
        let zmx = mise_which("zmx");
        let restate_server = mise_which("restate-server");
        let config = CoreConfig::new(
            home.clone(),
            zmx.clone(),
            restate_server.clone(),
            PathBuf::from(TYCHO),
        )
        .unwrap();
        let http = Http::new(Duration::from_secs(2)).unwrap();
        for role in CoreRole::ALL {
            assert!(
                !health::probe(&http, role).is_healthy(),
                "{role} already answers on its port; stop the running core first"
            );
        }
        let environment = vec![
            (HOME_ENV, home.display().to_string()),
            (ZMX_ENV, zmx.display().to_string()),
            (RESTATE_SERVER_ENV, restate_server.display().to_string()),
        ];
        Self {
            config,
            environment,
        }
    }

    fn tycho(&self, arguments: &[&str]) -> Output {
        let output = Command::new(TYCHO)
            .args(arguments)
            .envs(
                self.environment
                    .iter()
                    .map(|(key, value)| (*key, value.as_str())),
            )
            .output()
            .unwrap();
        println!(
            "$ tycho {} -> {}\n{}{}",
            arguments.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn clear_sessions(&self) -> Result<(), String> {
        let zmx = Zmx::new(&self.config.zmx, &self.config.socket_dir());
        let entries = zmx.list().map_err(|error| error.to_string())?;
        for entry in &entries {
            match entry {
                ListEntry::Running { name, pid, .. } | ListEntry::Ended { name, pid, .. } => {
                    println!("teardown: {name} survived core stop; killing pid {pid}");
                    let killed = Command::new("/bin/kill")
                        .args(["-KILL", &pid.to_string()])
                        .status();
                    println!(
                        "teardown: kill {pid}: {killed:?}; zmx kill: {:?}",
                        zmx.kill(name)
                    );
                }
                ListEntry::Unrecognised(line) => {
                    return Err(format!("unrecognised zmx line {line:?}"))
                }
            }
        }
        let remaining = zmx.list().map_err(|error| error.to_string())?;
        println!(
            "teardown: sessions left in the core socket directory: {}",
            remaining.len()
        );
        if remaining.is_empty() {
            Ok(())
        } else {
            Err(format!("{} sessions remain", remaining.len()))
        }
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        self.tycho(&["core", "stop"]);
        let outcome = self.clear_sessions().and_then(|()| {
            fs::remove_dir_all(&self.config.home)
                .map_err(|error| format!("cannot remove {}: {error}", self.config.home.display()))
        });
        match outcome {
            Ok(()) => println!("teardown: removed {}", self.config.home.display()),
            Err(error) if thread::panicking() => eprintln!("teardown failed: {error}"),
            Err(error) => panic!("teardown failed: {error}"),
        }
    }
}

/// An endpoint with test doubles in this process, on its own runtime so it can be killed.
struct DoublesEndpoint {
    runtime: Option<tokio::runtime::Runtime>,
}

impl DoublesEndpoint {
    fn start(ports: &Ports) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let listener = bind_with_retries(&runtime);
        let built = endpoint::build(ports);
        runtime.spawn(async move { HttpServer::new(built).serve(listener).await });
        Self {
            runtime: Some(runtime),
        }
    }
}

/// A port the previous endpoint held can take a moment to free after its runtime stops.
fn bind_with_retries(runtime: &tokio::runtime::Runtime) -> tokio::net::TcpListener {
    for _ in 0..40 {
        if let Ok(listener) =
            runtime.block_on(tokio::net::TcpListener::bind(loopback(DOUBLES_PORT)))
        {
            return listener;
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("port {DOUBLES_PORT} did not free");
}

impl Drop for DoublesEndpoint {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
            println!("teardown: doubles endpoint stopped");
        }
    }
}

fn mise_which(tool: &str) -> PathBuf {
    let output = Command::new("mise")
        .args(["which", tool])
        .envs(MISE_NO_INSTALL)
        .output()
        .unwrap();
    assert!(output.status.success(), "mise which {tool} failed");
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .no_proxy()
        .build()
        .unwrap()
}

/// One ingress call; returns the status and the body, and prints both as evidence.
fn call(path: &str, body: &str, idempotency_key: Option<&str>) -> (u16, String) {
    let mut request = client().post(format!("http://127.0.0.1:{RESTATE_INGRESS_PORT}{path}"));
    if !body.is_empty() {
        request = request
            .header("content-type", "application/json")
            .body(body.to_string());
    }
    if let Some(key) = idempotency_key {
        request = request.header("idempotency-key", key);
    }
    let response = request.send().unwrap();
    let status = response.status().as_u16();
    let text = response.text().unwrap();
    println!("evidence: POST {path} -> {status} {text}");
    (status, text)
}

fn register_doubles() {
    let body = format!("{{\"uri\":\"http://{}\"}}", loopback(DOUBLES_PORT));
    let response = client()
        .post(admin_url("/deployments"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .unwrap();
    let status = response.status().as_u16();
    let text = response.text().unwrap();
    println!("evidence: doubles endpoint registration -> {status}");
    assert_eq!(status, 201, "registration refused: {text}");
}

fn handler_metadata(service: &str, handler_name: &str) -> serde_json::Value {
    let text = client()
        .get(admin_url(&format!(
            "/services/{service}/handlers/{handler_name}"
        )))
        .send()
        .unwrap()
        .text()
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let started = Instant::now();
    while started.elapsed() < WAIT_TIMEOUT {
        if condition() {
            println!(
                "evidence: {what} after {:.1}s",
                started.elapsed().as_secs_f64()
            );
            return;
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("{what} did not happen within {WAIT_TIMEOUT:?}");
}

fn start_core_with_doubles(test: &str, spawner: &RecordingSpawner) -> (Core, DoublesEndpoint) {
    let (core, doubles, _) = start_core_with(test, spawner, Arc::new(NoGate), test_timing());
    (core, doubles)
}

fn test_timing() -> Timing {
    Timing {
        reconciler_interval: Duration::from_secs(1),
        ..Timing::default()
    }
}

fn start_core_with(
    test: &str,
    spawner: &RecordingSpawner,
    merge_gate: Arc<dyn MergeGate>,
    timing: Timing,
) -> (Core, DoublesEndpoint, Ports) {
    let core = Core::new(test);
    let started = core.tycho(&["core", "start"]);
    assert!(started.status.success());
    let report = String::from_utf8_lossy(&started.stdout).to_string();
    assert!(report.contains("operator secret: created"), "{report}");
    assert!(report.contains("reconciler: generation 1"), "{report}");
    let ports = Ports {
        spawner: Arc::new(spawner.clone()),
        merge_gate,
        timing,
        operator_secret: Some(core.config.operator_secret_file()),
    };
    let doubles = DoublesEndpoint::start(&ports);
    register_doubles();
    (core, doubles, ports)
}

fn assert_private(service: Service, handlers: &[&str], key: &str) {
    for private in handlers {
        let metadata = handler_metadata(service.name(), private);
        println!(
            "evidence: {}/{private} public = {}",
            service.name(),
            metadata["public"]
        );
        assert_eq!(metadata["public"], serde_json::json!(false), "{private}");
        let (status, _) = call(&format!("/{}/{key}/{private}", service.name()), "{}", None);
        assert!(
            (400..500).contains(&status),
            "{private} must be refused at ingress"
        );
    }
}

fn epic_status() -> serde_json::Value {
    let path = format!("/{}/cf7a/{}", Service::Epic.name(), handler::EPIC_STATUS);
    let (status, body) = call(&path, "", None);
    assert_eq!(status, 200);
    serde_json::from_str(&body).unwrap()
}

#[test]
#[ignore = "starts real processes; run with mise run spine-tests"]
fn epic_starts_and_adds_units_only_through_the_operator() {
    let spawner = RecordingSpawner::new();
    let (core, _doubles) = start_core_with_doubles("epic", &spawner);
    let handlers = [
        handler::EPIC_START,
        handler::EPIC_ADD_UNIT,
        handler::EPIC_RESERVE,
        handler::EPIC_SETTLE,
    ];
    assert_private(Service::Epic, &handlers, "cf7a");
    let wrong = format!(
        r#"{{"secret":"{}","epic":"cf7a","goal":"split the orders table","seat_limit":1,"metered_limit":0}}"#,
        "x".repeat(64)
    );
    let start_epic = format!("/Operator/{}", handler::OPERATOR_START_EPIC);
    assert_eq!(call(&start_epic, &wrong, None).0, 401, "a wrong secret");
    let empty = wrong.replace(&"x".repeat(64), "");
    assert_eq!(call(&start_epic, &empty, None).0, 401, "an empty secret");
    assert_eq!(
        epic_status(),
        serde_json::Value::Null,
        "no state after refusals"
    );
    assert!(core
        .tycho(&["epic", "start", "cf7a", "split the orders table"])
        .status
        .success());
    let added = core.tycho(&["epic", "add-unit", "cf7a", "wu01"]);
    assert_eq!(String::from_utf8_lossy(&added.stdout).trim(), "\"added\"");
    let again = core.tycho(&["epic", "add-unit", "cf7a", "wu01"]);
    assert_eq!(
        String::from_utf8_lossy(&again.stdout).trim(),
        "\"already_present\""
    );
    let state = epic_status();
    assert_eq!(state["units"], serde_json::json!(["wu01"]));
    assert_eq!(state["worker_slots"]["limit"], 2);
    let conflict = core.tycho(&["epic", "start", "cf7a", "another goal"]);
    assert_eq!(
        conflict.status.code(),
        Some(1),
        "another goal must conflict"
    );
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("409"));
}

#[test]
#[ignore = "starts real processes; run with mise run spine-tests"]
fn session_and_reconciler_refuse_agents_outside_their_scope() {
    let spawner = RecordingSpawner::new();
    let (_core, _doubles) = start_core_with_doubles("session", &spawner);
    let name = "cf7a.wu01.wrk.claude.a1";
    let session_handlers = [
        handler::SESSION_SPAWN,
        handler::SESSION_KILL,
        handler::SESSION_NUDGE,
        handler::SESSION_EXPIRE,
        handler::SESSION_REAP,
    ];
    assert_private(Service::Session, &session_handlers, name);
    let reconciler_handlers = [
        handler::RECONCILER_EXPECT,
        handler::RECONCILER_FORGET,
        handler::RECONCILER_TICK,
    ];
    assert_private(Service::Reconciler, &reconciler_handlers, RECONCILER_KEY);
    let session = format!("/{}/{name}", Service::Session.name());
    let beat = format!(
        r#"{{"secret":"{}","sequence":1,"status":{{"state":null,"summary":"s","last_progress_unix_ms":0,"progress":{{"head_sha":null,"tests_passing":0}},"active_workers":0,"usage":{{"input_tokens":0,"output_tokens":0}},"blockers":[]}},"context_tokens":0}}"#,
        "s".repeat(40)
    );
    let heartbeat = format!("{session}/{}", handler::SESSION_HEARTBEAT);
    let (status, _) = call(&heartbeat, &beat, Some(&format!("{name}:1")));
    assert_eq!(status, 404, "no session was spawned under this key");
    let status_path = format!("{session}/{}", handler::SESSION_STATUS);
    assert_eq!(call(&status_path, "", None), (200, "null".to_string()));
    let reconciler = format!("/{}/{RECONCILER_KEY}", Service::Reconciler.name());
    let start = format!("{reconciler}/{}", handler::RECONCILER_START);
    assert_eq!(call(&start, "", None), (200, "2".to_string()));
    assert_eq!(call(&start, "", None), (200, "3".to_string()));
    let status_path = format!("{reconciler}/{}", handler::RECONCILER_STATUS);
    wait_until("the reconciler answers status while its chain runs", || {
        call(&status_path, "", None) == (200, r#"{"generation":3,"expected":[]}"#.to_string())
    });
}

const HEAD_SHA: &str = "1111111111111111111111111111111111111111";
const DEFAULT_SHA: &str = "2222222222222222222222222222222222222222";

fn result_json(branch: &str) -> String {
    format!(
        r#"{{"outcome":"done","branch":"{branch}","head_sha":"{HEAD_SHA}","criteria":[],"usage":{{"input_tokens":1200,"output_tokens":300,"cost_micro_dollars":42000}}}}"#
    )
}

/// What the launcher double does with a spawned session's awaitable.
#[derive(Clone, Copy)]
enum Launcher {
    /// Resolves with a done result for sessions whose suffix ends with the given attempt.
    Resolve(&'static str, Duration),
    /// Rejects with the given exit state.
    Reject(&'static str, Duration),
    /// Holds the spawn step for the duration and then never answers.
    HoldSpawn(Duration),
    /// Never answers.
    Silent,
}

fn launcher_double(launcher: Launcher) -> RecordingSpawner {
    RecordingSpawner::with_hook(Arc::new(move |spec: &SpawnSpec, _pid| {
        let session = spec.session.to_string();
        let awaitable = spec.environment.awaitable_id.to_string();
        match launcher {
            Launcher::Resolve(suffix, delay) if session.ends_with(suffix) => {
                let branch = format!("wu01/{}", session.rsplit('.').next().unwrap_or("x"));
                answer(awaitable, delay, "resolve", result_json(&branch));
            }
            Launcher::Reject(state, delay) => {
                answer(awaitable, delay, "reject", state.to_string());
            }
            Launcher::HoldSpawn(hold) => thread::sleep(hold),
            Launcher::Resolve(..) | Launcher::Silent => {}
        }
    }))
}

/// Resolves or rejects through ingress after a delay, as a launcher's exit trap would.
fn answer(awaitable: String, delay: Duration, action: &'static str, body: String) {
    thread::spawn(move || {
        thread::sleep(delay);
        let status = client()
            .post(ingress_url(&format!(
                "/restate/awakeables/{awaitable}/{action}"
            )))
            .header("content-type", "application/json")
            .body(if action == "reject" {
                body
            } else {
                body.clone()
            })
            .send()
            .map(|response| response.status().as_u16());
        println!("evidence: launcher double {action} -> {status:?}");
    });
}

fn worker(fallback: &str) -> String {
    format!(
        r#"{{"epic":"cf7a","work_unit":"wu01","vendor":"claude","argv":["tycho-launcher"],"routing":{{"class":"implement","tier":"standard","effort":"medium","binding":null,"rationale":"routine change","fallback_tier":"{fallback}"}},"ledger":"seat","reservation":1000}}"#
    )
}

fn plan_file(core: &Core, tasks: &[&str]) -> PathBuf {
    let plan: Vec<String> = tasks
        .iter()
        .map(|task| format!(r#"{{"task":"{task}","worker":{}}}"#, worker("strong")))
        .collect();
    let path = core.config.home.join("plan.json");
    fs::write(
        &path,
        format!(
            r#"{{"control_vendor":"codex","plan":[{}]}}"#,
            plan.join(",")
        ),
    )
    .unwrap();
    path
}

/// Starts the epic, lists `wu01`, dispatches it through the CLI, and returns the invocation.
fn dispatch(core: &Core, tasks: &[&str]) -> String {
    assert!(core
        .tycho(&["epic", "start", "cf7a", "split the orders table"])
        .status
        .success());
    assert!(core
        .tycho(&["epic", "add-unit", "cf7a", "wu01"])
        .status
        .success());
    let plan = plan_file(core, tasks);
    let dispatched = core.tycho(&["epic", "dispatch", "cf7a", "wu01", plan.to_str().unwrap()]);
    assert!(dispatched.status.success());
    let body: serde_json::Value = serde_json::from_slice(&dispatched.stdout).unwrap();
    body["invocation_id"].as_str().unwrap().to_string()
}

fn attach(invocation: &str) -> (u16, String) {
    let response = client()
        .get(ingress_url(&format!(
            "/restate/invocation/{invocation}/attach"
        )))
        .send()
        .unwrap();
    let status = response.status().as_u16();
    let text = response.text().unwrap();
    println!("evidence: attach -> {status} {text}");
    (status, text)
}

fn unit_status() -> serde_json::Value {
    let (_, body) = call("/WorkUnit/wu01/status", "", None);
    serde_json::from_str(&body).unwrap_or(serde_json::Value::Null)
}

/// Cancels through the admin API, the way an operator stop would.
fn cancel(invocation: &str) {
    let status = client()
        .patch(admin_url(&format!("/invocations/{invocation}/cancel")))
        .send()
        .unwrap()
        .status()
        .as_u16();
    println!("evidence: cancel {invocation} -> {status}");
    assert!((200..300).contains(&status), "cancel refused: {status}");
}

fn operator_secret(core: &Core) -> String {
    read_secret_file(&core.config.operator_secret_file())
        .unwrap()
        .expose()
        .to_string()
}

#[test]
#[ignore = "starts real processes; run with mise run spine-tests"]
fn a_dispatched_unit_runs_both_tasks_to_the_verify_stub() {
    let spawner = launcher_double(Launcher::Resolve("a1", Duration::from_millis(500)));
    let gate = FixedGate::new(GateVerdict::Merged {
        default_sha: CommitSha::parse(DEFAULT_SHA).unwrap(),
    });
    let (core, _doubles, _) =
        start_core_with("unit", &spawner, Arc::new(gate.clone()), test_timing());
    assert_private(
        Service::WorkUnit,
        &[handler::WORK_UNIT_RUN, handler::WORK_UNIT_RULE],
        "wu01",
    );
    assert_private(Service::WorkerRun, &[handler::WORKER_RUN_RUN], "wu01-t1");
    let unlisted = format!(
        r#"{{"secret":"{}","unit":"wu09","request":{{"epic":"cf7a","control_vendor":"codex","plan":[{{"task":"t","worker":{}}}]}}}}"#,
        operator_secret(&core),
        worker("strong")
    );
    let invocation = dispatch(&core, &["wu01-t1", "wu01-t2"]);
    let path = format!("/Operator/{}", handler::OPERATOR_DISPATCH_UNIT);
    assert_eq!(
        call(&path, &unlisted, None).0,
        404,
        "a unit the epic does not list"
    );
    let (status, body) = attach(&invocation);
    assert_eq!(status, 200, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(view["lifecycle"], "done");
    assert_eq!(view["head_sha"], DEFAULT_SHA);
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
        "every claim reaches the gate"
    );
    let log = spawner.log();
    assert_eq!(log.spawned.len(), 2, "one session per task: {log:?}");
    let session = &log.spawned[0].0;
    let (_, session_view) = call(&format!("/Session/{session}/status"), "", None);
    for hidden in ["sign_", "secret", "awaitable"] {
        assert!(!session_view.contains(hidden), "{hidden} in {session_view}");
    }
    let state = epic_status();
    assert_eq!(state["reservations"], serde_json::json!({}));
    assert_eq!(
        state["seat"]["charged"], 3000,
        "each task: the larger of 1000 and 1500 tokens"
    );
    assert_eq!(state["metered"]["charged"], 0);
    assert_eq!(state["worker_slots"]["used"], 0);
}

#[test]
#[ignore = "starts real processes; run with mise run spine-tests"]
fn a_silent_worker_is_nudged_at_t1_killed_at_t2_and_requeued_as_attempt_two() {
    let spawner = launcher_double(Launcher::Resolve("a2", Duration::from_millis(500)));
    let timing = Timing {
        stall_silence: Duration::from_secs(2),
        stall_progress: Duration::from_secs(5),
        ..test_timing()
    };
    let gate = FixedGate::new(GateVerdict::Merged {
        default_sha: CommitSha::parse(DEFAULT_SHA).unwrap(),
    });
    let (core, _doubles, _) = start_core_with("stall", &spawner, Arc::new(gate), timing);
    let started = Instant::now();
    let invocation = dispatch(&core, &["wu01-t9"]);
    let (status, body) = attach(&invocation);
    println!(
        "evidence: unit returned after {:.1}s",
        started.elapsed().as_secs_f64()
    );
    assert_eq!(status, 200, "{body}");
    let (_, run) = call("/WorkerRun/wu01-t9/status", "", None);
    let run: serde_json::Value = serde_json::from_str(&run).unwrap();
    assert_eq!(run["outcome"]["outcome"], "completed");
    assert_eq!(run["outcome"]["attempt"], 2);
    assert_eq!(run["tier"], "strong", "attempt 2 moved up a tier");
    let log = spawner.log();
    println!("evidence: spawner log {log:?}");
    let names: Vec<&str> = log.spawned.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names.len(), 2, "one session per attempt");
    assert!(names[0].ends_with("a1") && names[1].ends_with("a2"));
    assert!(
        log.sent.iter().any(|(name, _)| name == names[0]),
        "T1 nudged attempt 1"
    );
    assert_eq!(
        log.scrollbacks,
        vec![names[0].to_string()],
        "T2 saved scrollback"
    );
    assert_eq!(log.killed.len(), 1, "T2 killed attempt 1 by pid");
    assert_eq!(log.killed[0].0, names[0]);
    assert_eq!(
        epic_status()["worker_slots"]["used"],
        0,
        "both attempts settled"
    );
}

#[test]
#[ignore = "starts real processes; run with mise run spine-tests"]
fn an_endpoint_killed_mid_run_replays_to_the_same_state() {
    let spawner = launcher_double(Launcher::Resolve("a1", Duration::from_secs(6)));
    let gate = FixedGate::new(GateVerdict::Merged {
        default_sha: CommitSha::parse(DEFAULT_SHA).unwrap(),
    });
    let (core, doubles, ports) = start_core_with("replay", &spawner, Arc::new(gate), test_timing());
    let invocation = dispatch(&core, &["wu01-t5"]);
    wait_until("the worker session spawned", || {
        spawner.log().spawned.len() == 1
    });
    drop(doubles);
    println!("evidence: killed the endpoint with unit {invocation} awaiting its worker");
    thread::sleep(Duration::from_secs(2));
    let _restarted = DoublesEndpoint::start(&ports);
    println!("evidence: endpoint restarted on the same port");
    let (status, body) = attach(&invocation);
    assert_eq!(status, 200, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(view["lifecycle"], "done");
    assert_eq!(view["attempt"], 1);
    assert_eq!(
        spawner.log().spawned.len(),
        1,
        "replay spawned no second session"
    );
}

#[test]
#[ignore = "starts real processes; run with mise run spine-tests"]
fn a_cancel_during_spawn_kills_settles_and_starts_no_second_attempt() {
    let spawner = launcher_double(Launcher::HoldSpawn(Duration::from_secs(4)));
    let (core, _doubles, _) =
        start_core_with("cancel-spawn", &spawner, Arc::new(NoGate), test_timing());
    let invocation = dispatch(&core, &["wu01-t3"]);
    wait_until("the spawn step started", || {
        spawner.log().spawned.len() == 1
    });
    cancel(&invocation);
    let (status, body) = attach(&invocation);
    assert_eq!(status, 409, "the unit ends cancelled: {body}");
    wait_until("the started session was reaped by name", || {
        spawner.log().reaped.len() == 1
    });
    wait_until("the worker run settled", || {
        epic_status()["worker_slots"]["used"] == 0
    });
    thread::sleep(Duration::from_secs(3));
    let log = spawner.log();
    println!("evidence: spawner log {log:?}");
    assert_eq!(log.spawned.len(), 1, "no attempt 2");
    assert_eq!(
        log.reaped,
        vec![log.spawned[0].0.clone()],
        "reaped by name, no pid known"
    );
    let status_path = format!("/Session/{}/status", log.spawned[0].0);
    assert!(call(&status_path, "", None)
        .1
        .contains("\"phase\":\"lost\""));
    assert_eq!(
        epic_status()["worker_slots"]["used"],
        0,
        "the attempt settled"
    );
}

#[test]
#[ignore = "starts real processes; run with mise run spine-tests"]
fn an_error_while_watching_kills_the_session_before_settling() {
    let spawner = launcher_double(Launcher::Silent);
    let (core, _doubles, _) =
        start_core_with("cancel-watch", &spawner, Arc::new(NoGate), test_timing());
    let invocation = dispatch(&core, &["wu01-t4"]);
    wait_until("the worker session spawned", || {
        spawner.log().spawned.len() == 1
    });
    let session = spawner.log().spawned[0].0.clone();
    let status_path = format!("/Session/{session}/status");
    wait_until("the session recorded", || {
        call(&status_path, "", None).1.contains("running")
    });
    cancel(&invocation);
    assert_eq!(attach(&invocation).0, 409);
    wait_until("the worker run killed the session", || {
        spawner.log().killed.len() == 1
    });
    wait_until("the worker run settled", || {
        epic_status()["worker_slots"]["used"] == 0
    });
    let log = spawner.log();
    println!("evidence: spawner log {log:?}");
    assert_eq!(log.killed.len(), 1, "killed on the error path");
    assert_eq!(log.killed[0].0, session);
    assert!(call(&status_path, "", None)
        .1
        .contains("\"phase\":\"killed\""));
    assert_eq!(
        epic_status()["worker_slots"]["used"],
        0,
        "settled after the kill"
    );
}

#[test]
#[ignore = "starts real processes; run with mise run spine-tests"]
fn an_escalated_unit_waits_for_a_ruling_through_the_operator() {
    let spawner = launcher_double(Launcher::Reject("escalated", Duration::from_millis(500)));
    let (core, _doubles, _) = start_core_with("rule", &spawner, Arc::new(NoGate), test_timing());
    let invocation = dispatch(&core, &["wu01-t6"]);
    wait_until("the unit escalated", || {
        unit_status()["lifecycle"] == "escalated"
    });
    let rule = |secret: &str, attempt: u16| {
        format!(
            r#"{{"secret":"{secret}","unit":"wu01","rule":{{"attempt":{attempt},"ruling":{{"verdict":"abandon","reason":"the planted contradiction stands"}}}}}}"#
        )
    };
    let path = format!("/Operator/{}", handler::OPERATOR_RULE_UNIT);
    assert_eq!(
        call(&path, &rule(&"x".repeat(64), 1), None).0,
        401,
        "a wrong secret"
    );
    let secret = operator_secret(&core);
    assert_eq!(
        call(&path, &rule(&secret, 2), None).0,
        409,
        "not the current attempt"
    );
    assert_eq!(unit_status()["lifecycle"], "escalated");
    assert_eq!(call(&path, &rule(&secret, 1), None).0, 200);
    let (status, body) = attach(&invocation);
    assert_eq!(status, 200, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(view["lifecycle"], "abandoned");
    assert_eq!(view["reason"], "the planted contradiction stands");
}

#[test]
#[ignore = "starts real processes; run with mise run spine-tests"]
fn a_terminal_error_abandons_the_unit_with_its_reason() {
    let spawner = launcher_double(Launcher::Resolve("a1", Duration::from_millis(500)));
    let (core, _doubles, _) = start_core_with("abandon", &spawner, Arc::new(NoGate), test_timing());
    let invocation = dispatch(&core, &["wu01-t7"]);
    let (status, body) = attach(&invocation);
    assert_eq!(status, 200, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(view["lifecycle"], "abandoned", "never stuck at verifying");
    assert!(
        view["reason"].as_str().unwrap().contains("no merge gate"),
        "{view}"
    );
}

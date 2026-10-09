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
    admin_url, loopback, CoreConfig, CoreRole, HOME_ENV, MISE_NO_INSTALL, RESTATE_INGRESS_PORT,
    RESTATE_SERVER_ENV, ZMX_ENV,
};
use tycho::endpoint;
use tycho::health;
use tycho::http::Http;
use tycho::services::doubles::RecordingSpawner;
use tycho::services::{Ports, Timing};
use tycho::zmx::{ListEntry, Zmx};
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
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind(loopback(DOUBLES_PORT)))
            .unwrap();
        let built = endpoint::build(ports);
        runtime.spawn(async move { HttpServer::new(built).serve(listener).await });
        Self {
            runtime: Some(runtime),
        }
    }
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
        .timeout(Duration::from_secs(30))
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
    let core = Core::new(test);
    assert!(core.tycho(&["core", "start"]).status.success());
    let timing = Timing {
        reconciler_interval: Duration::from_secs(1),
        ..Timing::default()
    };
    let ports = Ports {
        spawner: Arc::new(spawner.clone()),
        timing,
    };
    let doubles = DoublesEndpoint::start(&ports);
    register_doubles();
    (core, doubles)
}

#[test]
#[ignore = "starts real processes; run with mise run spine-tests"]
fn epic_starts_and_adds_units_with_authority_handlers_private() {
    let spawner = RecordingSpawner::new();
    let (_core, _doubles) = start_core_with_doubles("epic", &spawner);
    let epic = format!("/{}/cf7a", Service::Epic.name());
    let start = r#"{"goal":"split the orders table","seat_limit":1000000,"metered_limit":0}"#;
    assert_eq!(
        call(&format!("{epic}/{}", handler::EPIC_START), start, None).0,
        200
    );
    let add = format!("{epic}/{}", handler::EPIC_ADD_UNIT);
    assert_eq!(call(&add, "\"wu01\"", None), (200, "\"added\"".to_string()));
    assert_eq!(
        call(&add, "\"wu01\"", None),
        (200, "\"already_present\"".to_string())
    );
    let (status, body) = call(&format!("{epic}/{}", handler::EPIC_STATUS), "", None);
    assert_eq!(status, 200);
    let state: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(state["units"], serde_json::json!(["wu01"]));
    assert_eq!(state["worker_slots"]["limit"], 2);
    let other_goal = r#"{"goal":"another goal","seat_limit":1,"metered_limit":0}"#;
    let (status, _) = call(&format!("{epic}/{}", handler::EPIC_START), other_goal, None);
    assert_eq!(
        status, 409,
        "a second start with another goal must conflict"
    );
    let reserve = r#"{"task":"wu01-t1","attempt":1,"level":"worker","ledger":"seat","amount":1}"#;
    for private in [handler::EPIC_RESERVE, handler::EPIC_SETTLE] {
        let metadata = handler_metadata(Service::Epic.name(), private);
        println!(
            "evidence: {private} metadata public = {}",
            metadata["public"]
        );
        assert_eq!(metadata["public"], serde_json::json!(false));
        let (status, _) = call(&format!("{epic}/{private}"), reserve, None);
        assert!(
            (400..500).contains(&status),
            "{private} must be refused at ingress"
        );
    }
}

#[test]
#[ignore = "starts real processes; run with mise run spine-tests"]
fn session_and_reconciler_refuse_agents_outside_their_scope() {
    let spawner = RecordingSpawner::new();
    let (_core, _doubles) = start_core_with_doubles("session", &spawner);
    let name = "cf7a.wu01.wrk.claude.a1";
    let session = format!("/{}/{name}", Service::Session.name());
    for private in [
        handler::SESSION_SPAWN,
        handler::SESSION_KILL,
        handler::SESSION_NUDGE,
    ] {
        let metadata = handler_metadata(Service::Session.name(), private);
        assert_eq!(metadata["public"], serde_json::json!(false), "{private}");
        assert!((400..500).contains(&call(&format!("{session}/{private}"), "{}", None).0));
    }
    let beat = format!(
        r#"{{"secret":"{}","sequence":1,"status":{{"state":null,"summary":"s","last_progress_unix_ms":0,"progress":{{"head_sha":null,"tests_passing":0}},"active_workers":0,"usage":{{"input_tokens":0,"output_tokens":0}},"blockers":[]}},"context_tokens":0}}"#,
        "s".repeat(40)
    );
    let heartbeat = format!("{session}/{}", handler::SESSION_HEARTBEAT);
    let (status, _) = call(&heartbeat, &beat, Some(&format!("{name}:1")));
    assert_eq!(status, 404, "no session was spawned under this key");
    let reconciler = format!("/{}/{RECONCILER_KEY}", Service::Reconciler.name());
    let (status, generation) = call(&format!("{reconciler}/start"), "", None);
    assert_eq!((status, generation.as_str()), (200, "1"));
    assert_eq!(
        call(&format!("{reconciler}/start"), "", None),
        (200, "2".to_string())
    );
    let tick = format!("{reconciler}/{}", handler::RECONCILER_TICK);
    assert!(
        (400..500).contains(&call(&tick, "2", None).0),
        "tick is private"
    );
    wait_until("the reconciler answers status while its chain runs", || {
        call(&format!("{reconciler}/status"), "", None) == (200, "{}".to_string())
    });
}

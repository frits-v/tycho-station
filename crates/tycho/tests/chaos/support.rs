//! A throwaway core with an in-process endpoint, and the ingress and admin calls the cases make.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use restate_sdk::prelude::HttpServer;
use tycho::config::{
    CoreConfig, CorePorts, HOME_ENV, MISE_NO_INSTALL, RESTATE_SERVER_ENV, ZMX_ENV,
};
use tycho::config_store::FactoryConfig;
use tycho::config_store::PortOffset;
use tycho::endpoint;
use tycho::http::Http;
use tycho::services::merge_gate::MergeGate;
use tycho::services::spawner::Spawner;
use tycho::services::{Ports, Timing};
use tycho::vendors::control::NoVendor;
use tycho::zmx::{ListEntry, Zmx};

pub const TYCHO: &str = env!("CARGO_BIN_EXE_tycho");
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_millis(250);
/// Evidence bodies longer than this are cut, so a large view cannot flood the report.
const EVIDENCE_MAX_CHARS: usize = 600;

pub struct Core {
    pub config: CoreConfig,
    pub environment: Vec<(&'static str, String)>,
}

pub fn mise_which(tool: &str) -> PathBuf {
    let output = Command::new("mise")
        .args(["which", tool])
        .envs(MISE_NO_INSTALL)
        .output()
        .unwrap();
    assert!(output.status.success(), "mise which {tool} failed");
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

pub fn http() -> Http {
    Http::new(Duration::from_secs(2)).unwrap()
}

pub fn test_home(test: &str) -> PathBuf {
    let user_home = PathBuf::from(env::var_os("HOME").unwrap());
    user_home.join(format!(".tycho-chaos-{test}-{}", std::process::id()))
}

/// The ports `Core::new(test)` binds, for a double that is built before the core starts.
pub fn test_ports(test: &str) -> CorePorts {
    CorePorts::at(PortOffset::for_test_home(&test_home(test)))
}

impl Core {
    pub fn new(test: &str) -> Self {
        let home = test_home(test);
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
        .unwrap()
        .with_port_offset(PortOffset::for_test_home(&home));
        let offset = config.ports.offset;
        println!("evidence: {} at port offset {offset}", home.display());
        if let Some(taken) = config.ports.first_taken() {
            panic!("port collision: {taken}");
        }
        let environment = vec![
            (HOME_ENV, home.display().to_string()),
            (ZMX_ENV, zmx.display().to_string()),
            (RESTATE_SERVER_ENV, restate_server.display().to_string()),
        ]
        .into_iter()
        .chain(config.port_offset_pair())
        .collect();
        Self {
            config,
            environment,
        }
    }

    pub fn tycho(&self, arguments: &[&str]) -> Output {
        let output = Command::new(TYCHO)
            .args(arguments)
            .envs(self.envs())
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

    pub fn envs(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.environment
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
    }

    pub fn core_zmx(&self) -> Zmx {
        Zmx::new(&self.config.zmx, &self.config.socket_dir())
    }

    fn clear_sessions(&self) -> Result<(), String> {
        let zmx = self.core_zmx();
        let left = clear_sessions(&zmx, "core");
        if left == 0 {
            Ok(())
        } else {
            Err(format!("{left} core sessions remain"))
        }
    }
}

/// One start: a test core's ports are its own, so a start that fails fails the case.
pub fn start_once<T>(core: &Core, start: impl FnOnce(&Core) -> Option<T>) -> T {
    start(core)
        .unwrap_or_else(|| panic!("the core at {} did not start", core.config.home.display()))
}

/// Kills every session left in a socket directory by pid and by name; returns how many remain.
pub fn clear_sessions(zmx: &Zmx, label: &str) -> usize {
    let Ok(entries) = zmx.list() else {
        println!("teardown: {label} zmx list failed");
        return usize::MAX;
    };
    for entry in &entries {
        if let ListEntry::Running { name, pid, .. } | ListEntry::Ended { name, pid, .. } = entry {
            println!("teardown: {label} session {name} left; killing pid {pid}");
            drop(
                Command::new("/bin/kill")
                    .args(["-KILL", &pid.to_string()])
                    .status(),
            );
            drop(zmx.kill(name));
        }
    }
    let left = zmx.list().map_or(usize::MAX, |entries| entries.len());
    println!("teardown: {label} sessions left: {left}");
    left
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

/// An endpoint in this process, on its own runtime so it can be killed.
pub struct DoublesEndpoint {
    runtime: Option<tokio::runtime::Runtime>,
}

impl DoublesEndpoint {
    pub fn start(ports: &Ports, core_ports: CorePorts) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let listener = bind_with_retries(&runtime, core_ports.test_endpoint());
        let built = endpoint::build(ports);
        runtime.spawn(async move { HttpServer::new(built).serve(listener).await });
        Self {
            runtime: Some(runtime),
        }
    }
}

/// A port the previous endpoint held can take a moment to free after its runtime stops.
fn bind_with_retries(
    runtime: &tokio::runtime::Runtime,
    address: std::net::SocketAddr,
) -> tokio::net::TcpListener {
    for _ in 0..40 {
        if let Ok(listener) = runtime.block_on(tokio::net::TcpListener::bind(address)) {
            return listener;
        }
        thread::sleep(POLL);
    }
    panic!("{address} did not free");
}

impl Drop for DoublesEndpoint {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
            println!("evidence: in-process endpoint stopped");
        }
    }
}

pub fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(150))
        .no_proxy()
        .build()
        .unwrap()
}

fn cut(text: &str) -> String {
    text.chars().take(EVIDENCE_MAX_CHARS).collect()
}

/// One ingress call; returns the status and the body.
pub fn call(core_ports: CorePorts, path: &str, body: &str) -> (u16, String) {
    let mut request = client().post(core_ports.ingress_url(path));
    if !body.is_empty() {
        request = request
            .header("content-type", "application/json")
            .body(body.to_string());
    }
    match request.send() {
        Ok(response) => {
            let status = response.status().as_u16();
            (status, response.text().unwrap_or_default())
        }
        Err(error) => (0, error.to_string()),
    }
}

fn get_json(core_ports: CorePorts, path: &str) -> serde_json::Value {
    let (_, body) = call(core_ports, path, "");
    serde_json::from_str(&body).unwrap_or(serde_json::Value::Null)
}

pub fn unit_status(core_ports: CorePorts) -> serde_json::Value {
    get_json(core_ports, "/WorkUnit/wu01/status")
}

pub fn worker_run_status(core_ports: CorePorts, key: &str) -> serde_json::Value {
    get_json(core_ports, &format!("/WorkerRun/{key}/status"))
}

pub fn session_status(core_ports: CorePorts, name: &str) -> serde_json::Value {
    get_json(core_ports, &format!("/Session/{name}/status"))
}

/// The unit's lifecycle and attempt, the two fields the restart metric compares.
pub fn lifecycle_and_attempt(view: &serde_json::Value) -> (String, u64) {
    (
        view["lifecycle"].as_str().unwrap_or("absent").to_string(),
        view["attempt"].as_u64().unwrap_or(0),
    )
}

/// Every kill lands on a unit running its first attempt; anything else is a broken setup.
pub fn running_before_the_kill(core_ports: CorePorts) -> (String, u64) {
    let before = lifecycle_and_attempt(&unit_status(core_ports));
    assert_eq!(
        before,
        ("running".to_string(), 1),
        "the unit before the kill"
    );
    before
}

fn register_doubles(core_ports: CorePorts) {
    let body = format!("{{\"uri\":\"http://{}\"}}", core_ports.test_endpoint());
    let response = client()
        .post(core_ports.admin_url("/deployments"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .unwrap();
    let status = response.status().as_u16();
    let text = response.text().unwrap();
    assert_eq!(status, 201, "registration refused: {text}");
}

/// Polls `condition` until it holds or `WAIT_TIMEOUT` passes; the panic names what never happened.
pub fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let started = Instant::now();
    while started.elapsed() < WAIT_TIMEOUT {
        if condition() {
            println!(
                "evidence: {what} after {:.1}s",
                started.elapsed().as_secs_f64()
            );
            return;
        }
        thread::sleep(POLL);
    }
    panic!("{what} did not happen within {WAIT_TIMEOUT:?}");
}

pub fn test_config() -> FactoryConfig {
    FactoryConfig::embedded().unwrap()
}

/// The embedded thresholds with a one-second reconciler, so a stale lease is seen promptly.
pub fn test_timing() -> Timing {
    Timing {
        reconciler_interval: Duration::from_secs(1),
        ..Timing::from_thresholds(&test_config().thresholds.value)
    }
}

/// Starts the core through `tycho core start` and an in-process endpoint with the given ports.
pub fn start_core(
    test: &str,
    spawner: Arc<dyn Spawner>,
    merge_gate: Arc<dyn MergeGate>,
) -> (Core, DoublesEndpoint, Ports) {
    let core = Core::new(test);
    start_once(&core, |core| {
        core.tycho(&["core", "start"])
            .status
            .success()
            .then_some(())
    });
    let (doubles, ports) = start_endpoint(&core, spawner, merge_gate);
    (core, doubles, ports)
}

pub fn start_endpoint(
    core: &Core,
    spawner: Arc<dyn Spawner>,
    merge_gate: Arc<dyn MergeGate>,
) -> (DoublesEndpoint, Ports) {
    let ports = Ports {
        spawner,
        vendor: Arc::new(NoVendor),
        merge_gate,
        timing: test_timing(),
        config: Arc::new(test_config()),
        operator_secret: Some(core.config.operator_secret_file()),
        packet_dir: Some(core.config.packet_dir()),
        workers: None,
    };
    let doubles = DoublesEndpoint::start(&ports, core.config.ports);
    register_doubles(core.config.ports);
    (doubles, ports)
}

fn worker() -> String {
    r#"{"epic":"cf7a","work_unit":"wu01","vendor":"claude","argv":["tycho-launcher"],"routing":{"class":"implement","tier":"standard","effort":"medium","binding":null,"rationale":"routine change"},"ledger":"seat","reservation":1000}"#.to_string()
}

fn plan_file(core: &Core, tasks: &[&str]) -> PathBuf {
    let plan: Vec<String> = tasks
        .iter()
        .map(|task| format!(r#"{{"task":"{task}","worker":{}}}"#, worker()))
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

/// Starts the epic, lists `wu01`, dispatches it through the operator, and returns the invocation.
pub fn dispatch(core: &Core, tasks: &[&str]) -> String {
    assert!(core
        .tycho(&["epic", "start", "cf7a", "the synthetic epic"])
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

/// Waits for the unit invocation's result through ingress attach.
pub fn attach(core_ports: CorePorts, invocation: &str) -> (u16, String) {
    let response = client()
        .get(core_ports.ingress_url(&format!("/restate/invocation/{invocation}/attach")))
        .send();
    match response {
        Ok(response) => {
            let status = response.status().as_u16();
            let text = response.text().unwrap_or_default();
            println!("evidence: attach -> {status} {}", cut(&text));
            (status, text)
        }
        Err(error) => (0, error.to_string()),
    }
}

const UNIT_TERMINAL: [&str; 3] = ["done", "abandoned", "escalated"];

/// Polls until the unit reaches a terminal lifecycle; on the deadline, reports what is retrying.
pub fn await_unit_end(
    core_ports: CorePorts,
    why: &str,
    before: &(String, u64),
) -> serde_json::Value {
    let started = Instant::now();
    while started.elapsed() < WAIT_TIMEOUT {
        let view = unit_status(core_ports);
        if UNIT_TERMINAL.contains(&view["lifecycle"].as_str().unwrap_or("")) {
            println!(
                "evidence: unit ended {} after {:.1}s",
                view["lifecycle"],
                started.elapsed().as_secs_f64()
            );
            return view;
        }
        if let Some(looping) = looping_invocation(core_ports) {
            print_failed_pair(before, &view);
            panic!("{why}: an invocation of the unit is looping; view {view}; {looping}");
        }
        thread::sleep(Duration::from_millis(500));
    }
    let retrying = retrying_invocations(core_ports);
    for (_, line) in &retrying {
        println!("evidence: still retrying: {line}");
    }
    let view = unit_status(core_ports);
    print_failed_pair(before, &view);
    panic!(
        "{why}: the unit did not end within {WAIT_TIMEOUT:?}; view {view}; retrying {retrying:?}"
    );
}

fn print_failed_pair(before: &(String, u64), view: &serde_json::Value) {
    let after = lifecycle_and_attempt(view);
    println!("evidence: lifecycle before the kill {before:?}, at failure {after:?}");
}

/// An invocation Restate has retried this often will not end on its own; the case fails now.
const RETRIES_LOOPING: u64 = 5;

fn looping_invocation(core_ports: CorePorts) -> Option<String> {
    retrying_invocations(core_ports)
        .into_iter()
        .find(|(retries, _)| *retries >= RETRIES_LOOPING)
        .map(|(_, line)| line)
}

/// Runs one SQL query against Restate's admin introspection and returns its rows.
pub fn admin_query(core_ports: CorePorts, sql: &str) -> Vec<serde_json::Value> {
    let body = serde_json::json!({ "query": sql }).to_string();
    let text = client()
        .post(core_ports.admin_url("/query"))
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(body)
        .send()
        .unwrap()
        .text()
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    value["rows"]
        .as_array()
        .unwrap_or_else(|| panic!("admin query refused: {}", cut(&text)))
        .clone()
}

/// Each invocation still retrying, with its retry count and last failure, as evidence of a loop.
pub fn retrying_invocations(core_ports: CorePorts) -> Vec<(u64, String)> {
    admin_query(
        core_ports,
        "SELECT target_service_name, target_service_key, retry_count, last_failure \
         FROM sys_invocation WHERE status = 'backing-off'",
    )
    .iter()
    .map(|row| {
        let retries = row["retry_count"].as_u64().unwrap_or(0);
        let line = format!(
            "{}/{} retried {retries}: {}",
            row["target_service_name"].as_str().unwrap_or("?"),
            row["target_service_key"].as_str().unwrap_or(""),
            cut(row["last_failure"].as_str().unwrap_or(""))
        );
        (retries, line)
    })
    .collect()
}

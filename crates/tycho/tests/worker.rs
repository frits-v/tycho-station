//! Headless worker tests against a real core: the core starts through `tycho core start` with a
//! throwaway home, an endpoint in this process serves the services with the launcher spawner,
//! the canonical repository, the entire graph and the real `claude` CLI, and the trivial unit
//! of the synthetic epic is dispatched through the operator path. macOS only, needs a Claude
//! login and the graph plugin (`mise run graph-plugin`); run by `mise run worker-tests`.
#![allow(
    clippy::disallowed_methods,
    reason = "fixtures live in throwaway directories no other user can write"
)]
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
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use restate_sdk::prelude::HttpServer;
use serde_json::{json, Value};
use tycho::agent_files::current_uid;
use tycho::config::{
    self, AgentDirs, CoreConfig, CorePorts, PortClaim, HOME_ENV, MISE_NO_INSTALL,
    RESTATE_SERVER_ENV, ZMX_ENV,
};
use tycho::config_store::FactoryConfig;
use tycho::endpoint;
use tycho::entire_graph::EntireGraph;
use tycho::launch_spec::HeartbeatTarget;
use tycho::launcher::SessionFiles;
use tycho::repositories::{ProjectName, Repositories};
use tycho::services::doubles::FixedGate;
use tycho::services::launcher_spawner::LauncherSpawner;
use tycho::services::merge_gate::GateVerdict;
use tycho::services::operator::read_secret_file;
use tycho::services::workers::WorkerPorts;
use tycho::services::{Ports, Timing};
use tycho::spool::ACKNOWLEDGED_SUFFIX;
use tycho::zmx::Zmx;
use tycho_types::envelope::CommitSha;
use tycho_types::service::handler;
use tycho_types::session::SessionName;
use tycho_types::task_packet::RoutingName;

const TYCHO: &str = env!("CARGO_BIN_EXE_tycho");
const WAIT_TIMEOUT: Duration = Duration::from_secs(300);
const PROJECT: &str = "widget";
const UNIT: &str = "wu01";
const TASK: &str = "wu01-t1";
const COMMIT_SENTENCE: &str = "Commit the change on the current branch with git.";

struct Core {
    config: CoreConfig,
    environment: Vec<(&'static str, String)>,
    agent: PathBuf,
    /// Held until the core is stopped, after the teardown in `drop`.
    _port_claim: PortClaim,
}

fn test_home(test: &str) -> PathBuf {
    let user_home = PathBuf::from(env::var_os("HOME").unwrap());
    user_home.join(format!(".tycho-worker-{test}-{}", std::process::id()))
}

/// A port slot claim for the test's home, taken before any double is built from its ports.
fn test_claim(test: &str) -> PortClaim {
    claim_ports(&test_home(test))
}

/// Claims a port slot for the home, held until the core is stopped; a slot whose ports
/// another process holds is skipped and named, and the test fails only when no slot is left.
fn claim_ports(home: &Path) -> PortClaim {
    let claim = CorePorts::claim(home).unwrap_or_else(|error| panic!("{error}"));
    println!("evidence: {claim}");
    claim
}

impl Core {
    fn new(claim: PortClaim) -> Self {
        let home = claim.home.clone();
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
        .with_port_offset(claim.ports.offset);
        let environment = vec![
            (HOME_ENV, home.display().to_string()),
            (ZMX_ENV, zmx.display().to_string()),
            (RESTATE_SERVER_ENV, restate_server.display().to_string()),
        ]
        .into_iter()
        .chain(config.port_offset_pair())
        .collect();
        Self {
            _port_claim: claim,
            agent: home.join("agent"),
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

    fn worktree_root(&self) -> PathBuf {
        self.config.home.join("worktrees")
    }
}

/// Kills what zmx still lists in a socket directory and reports how many remain.
/// Ends what a socket directory still lists; a pid is signalled only while `ps` shows it
/// running restate-server, the endpoint or a launcher.
fn clear_sessions(zmx: &Zmx, label: &str) -> usize {
    let programs = vec![
        mise_which("restate-server").display().to_string(),
        format!("{TYCHO} endpoint"),
        format!("{TYCHO} launch"),
    ];
    match zmx.clear(&programs) {
        Ok(report) => {
            for line in &report.lines {
                println!("teardown: {label} {line}");
            }
            println!("teardown: {label} sessions left: {}", report.remaining);
            report.remaining
        }
        Err(error) => {
            println!("teardown: {label} zmx: {error}");
            usize::MAX
        }
    }
}

/// The directory the Claude CLI keeps a worktree's transcripts in, named after its path.
fn transcript_dir(worktree_root: &Path) -> Vec<PathBuf> {
    let projects = PathBuf::from(env::var_os("HOME").unwrap()).join(".claude/projects");
    let prefix = worktree_root.display().to_string().replace(['/', '.'], "-");
    fs::read_dir(&projects)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(&prefix))
                })
                .collect()
        })
        .unwrap_or_default()
}

impl Drop for Core {
    fn drop(&mut self) {
        self.tycho(&["core", "stop"]);
        let core_zmx = Zmx::new(&self.config.zmx, &self.config.socket_dir());
        let agent_zmx = Zmx::agent(&self.config.zmx, &self.agent);
        let left =
            clear_sessions(&core_zmx, "core").saturating_add(clear_sessions(&agent_zmx, "agent"));
        let mut outcome = (left == 0)
            .then_some(())
            .ok_or_else(|| format!("{left} sessions remain"));
        for transcripts in transcript_dir(&self.worktree_root()) {
            println!(
                "teardown: removing worker transcripts {}",
                transcripts.display()
            );
            drop(fs::remove_dir_all(&transcripts));
        }
        outcome = outcome.and_then(|()| {
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

/// The endpoint under test in this process, on its own runtime so it stops with the test.
struct TestEndpoint {
    runtime: Option<tokio::runtime::Runtime>,
}

impl TestEndpoint {
    fn start(ports: &Ports, core_ports: CorePorts) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let listener = (0..40)
            .find_map(|_| {
                let bound = runtime
                    .block_on(tokio::net::TcpListener::bind(core_ports.test_endpoint()))
                    .ok();
                if bound.is_none() {
                    thread::sleep(Duration::from_millis(250));
                }
                bound
            })
            .unwrap();
        let built = endpoint::build(ports);
        runtime.spawn(async move { HttpServer::new(built).serve(listener).await });
        let body = format!("{{\"uri\":\"http://{}\"}}", core_ports.test_endpoint());
        let response = client()
            .post(core_ports.admin_url("/deployments"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 201, "registration refused");
        Self {
            runtime: Some(runtime),
        }
    }
}

impl Drop for TestEndpoint {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
            println!("teardown: endpoint under test stopped");
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
        .timeout(WAIT_TIMEOUT)
        .no_proxy()
        .build()
        .unwrap()
}

fn get(core_ports: CorePorts, path: &str) -> Value {
    let text = client()
        .get(core_ports.ingress_url(path))
        .send()
        .unwrap()
        .text()
        .unwrap();
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

fn post(core_ports: CorePorts, path: &str, body: &str) -> (u16, String) {
    let response = client()
        .post(core_ports.ingress_url(path))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .unwrap();
    let status = response.status().as_u16();
    (status, response.text().unwrap())
}

fn git(repository: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// The synthetic epic's repository as the project's canonical bare repository.
fn canonical(core: &Core, repositories: &Repositories) -> CommitSha {
    let source = core.config.home.join("source");
    fs::create_dir_all(&source).unwrap();
    let built = tycho_harness::repository::build(&source).unwrap();
    let project = ProjectName::parse(PROJECT).unwrap();
    let head = repositories.create_canonical(&project, &source).unwrap();
    assert_eq!(head, built.head_sha);
    println!(
        "evidence: canonical repository {} at {head}",
        repositories.canonical(&project).display()
    );
    head
}

fn worker_ports(core: &Core) -> (Arc<WorkerPorts>, CommitSha) {
    let repositories = Repositories::new(
        PathBuf::from("git"),
        core.config.home.clone(),
        core.worktree_root(),
        current_uid(),
    )
    .unwrap();
    let head = canonical(core, &repositories);
    let graph_binary = config::entire_graph_path().unwrap();
    let graph = EntireGraph::open(&graph_binary, &core.config.home.join("index")).unwrap();
    let ports = WorkerPorts {
        repositories,
        graph: Arc::new(graph),
        project: ProjectName::parse(PROJECT).unwrap(),
        tycho: PathBuf::from(TYCHO),
        claude: mise_which("claude"),
        codex: mise_which("codex"),
    };
    (Arc::new(ports), head)
}

fn start(claim: PortClaim) -> (Core, TestEndpoint, Arc<WorkerPorts>) {
    let core = Core::new(claim);
    assert!(
        core.tycho(&["core", "start"]).status.success(),
        "the core did not start"
    );
    let (workers, head) = worker_ports(&core);
    let factory = FactoryConfig::embedded().unwrap();
    let spawner = LauncherSpawner {
        zmx: Zmx::agent(&core.config.zmx, &core.agent),
        dirs: AgentDirs::new(core.agent.clone()).unwrap(),
        tycho: PathBuf::from(TYCHO),
        home: PathBuf::from(env::var_os("HOME").unwrap()),
        core_home: core.config.home.clone(),
        agent_uid: current_uid(),
        heartbeat: HeartbeatTarget::Session,
        ports: core.config.ports,
    };
    let ports = Ports {
        spawner: Arc::new(spawner),
        vendor: Arc::new(tycho::vendors::control::NoVendor),
        merge_gate: Arc::new(FixedGate::new(GateVerdict::Merged { default_sha: head })),
        timing: Timing {
            reconciler_interval: Duration::from_secs(1),
            ..Timing::from_thresholds(&factory.thresholds.value)
        },
        config: Arc::new(factory),
        operator_secret: Some(core.config.operator_secret_file()),
        packet_dir: Some(core.config.packet_dir()),
        workers: Some(Arc::clone(&workers)),
    };
    let endpoint = TestEndpoint::start(&ports, core.config.ports);
    (core, endpoint, workers)
}

/// Starts the epic, lists the unit, and dispatches one headless task with this brief.
fn dispatch(core: &Core, brief: &str, max_turns: u16) -> String {
    assert!(core
        .tycho(&["epic", "start", "cf7a", "the synthetic epic"])
        .status
        .success());
    assert!(core
        .tycho(&["epic", "add-unit", "cf7a", UNIT])
        .status
        .success());
    let worker = json!({
        "epic": "cf7a", "work_unit": UNIT, "vendor": "claude", "argv": [],
        "routing": {"class": "probe", "tier": "light", "effort": "low", "binding": null,
                    "rationale": "a single-line arithmetic fix needs no judgment call"},
        "ledger": "seat", "reservation": 200_000,
        "task": {"brief": brief, "max_turns": max_turns},
    });
    let plan = json!({"control_vendor": "claude", "plan": [{"task": TASK, "worker": worker}]});
    let path = core.config.home.join("plan.json");
    fs::write(&path, plan.to_string()).unwrap();
    let dispatched = core.tycho(&["epic", "dispatch", "cf7a", UNIT, path.to_str().unwrap()]);
    assert!(dispatched.status.success());
    let body: Value = serde_json::from_slice(&dispatched.stdout).unwrap();
    body["invocation_id"].as_str().unwrap().to_string()
}

/// What the agent spool holds, printed before a failed wait panics.
fn dump_spool(core: &Core) {
    let core_ports = core.config.ports;
    let spool = core.agent.join("spool");
    for entry in fs::read_dir(&spool)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
    {
        for file in ["launcher.log", "progress.json", "stderr.log", "result.json"] {
            let text = fs::read_to_string(entry.path().join(file)).unwrap_or_default();
            println!("evidence: {}/{file}: {text}", entry.path().display());
        }
        let events = fs::read_to_string(entry.path().join("stdout.log")).unwrap_or_default();
        let tail: String = events.lines().rev().take(4).collect::<Vec<_>>().join("\n");
        println!("evidence: last events:\n{tail}");
    }
    println!(
        "evidence: unit status {}",
        get(core_ports, &format!("/WorkUnit/{UNIT}/status"))
    );
    println!(
        "evidence: worker run status {}",
        get(core_ports, &format!("/WorkerRun/{TASK}/status"))
    );
    let query = json!({"query": "select target, status, last_failure from sys_invocation where status != 'completed'"});
    let answer = client()
        .post(core_ports.admin_url("/query"))
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(query.to_string())
        .send()
        .and_then(reqwest::blocking::Response::text);
    println!("evidence: open invocations {answer:?}");
}

fn attach(core: &Core, invocation: &str) -> Value {
    let core_ports = core.config.ports;
    let answer = client()
        .get(core_ports.ingress_url(&format!("/restate/invocation/{invocation}/attach")))
        .send()
        .and_then(reqwest::blocking::Response::text);
    let text = answer.unwrap_or_else(|error| {
        dump_spool(core);
        panic!("the unit run did not end: {error}");
    });
    println!("evidence: unit run ended with {text}");
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
        thread::sleep(Duration::from_millis(500));
    }
    panic!("{what} did not happen within {WAIT_TIMEOUT:?}");
}

/// The launcher's acknowledged spool record for the worker session.
fn spool_record(core: &Core, session: &str) -> Value {
    let dirs = AgentDirs::new(core.agent.clone()).unwrap();
    let files = SessionFiles::new(&dirs, &SessionName::parse(session).unwrap());
    let acknowledged = files.spool.with_extension(ACKNOWLEDGED_SUFFIX);
    let record: Value = serde_json::from_slice(&fs::read(&acknowledged).unwrap()).unwrap();
    println!(
        "evidence: spool record {} state {}",
        acknowledged.display(),
        record["state"]
    );
    record
}

/// The one worker session the launcher spooled for, from the agent spool directory.
fn only_worker_session(core: &Core) -> String {
    let names: Vec<String> = fs::read_dir(core.agent.join("spool"))
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
    names[0].clone()
}

/// Every spooled worker session in attempt order with its acknowledged record, printed.
fn spooled_records(core: &Core) -> Vec<(String, Value)> {
    let dirs = AgentDirs::new(core.agent.clone()).unwrap();
    let mut names: Vec<String> = fs::read_dir(core.agent.join("spool"))
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    // The suffix ends in `a<attempt>`, so the name order is the attempt order below ten.
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let files = SessionFiles::new(&dirs, &SessionName::parse(&name).unwrap());
            let acknowledged = files.spool.with_extension(ACKNOWLEDGED_SUFFIX);
            let record: Value = fs::read(&acknowledged)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or(Value::Null);
            println!("evidence: spooled session {name} record {record}");
            (name, record)
        })
        .collect()
}

/// The worker run's attempt cap for the route the tests dispatch under.
fn probe_attempt_cap() -> usize {
    let config = FactoryConfig::embedded().unwrap();
    let route = config
        .route(
            &RoutingName::parse("probe").unwrap(),
            &RoutingName::parse("light").unwrap(),
        )
        .unwrap();
    usize::from(route.attempt_cap)
}

fn worker_status(core_ports: CorePorts) -> Value {
    let status = get(core_ports, &format!("/WorkerRun/{TASK}/status"));
    println!("evidence: worker run status {status}");
    status
}

fn trivial_brief() -> String {
    let objective = String::from_utf8(tycho_harness::content::OBJECTIVE_TRIVIAL.to_vec()).unwrap();
    format!("{} {COMMIT_SENTENCE}", objective.trim())
}

fn assert_cloned_and_indexed(core: &Core, view: &Value, workers: &WorkerPorts) -> PathBuf {
    let worktree = PathBuf::from(view["worktree"]["path"].as_str().unwrap());
    let canonical = workers.repositories.canonical(&workers.project);
    assert_eq!(
        git(&worktree, &["remote", "get-url", "origin"]),
        canonical.display().to_string()
    );
    assert!(worktree.starts_with(core.worktree_root()));
    let build = &view["index"][0];
    assert_eq!(build["kind"], "build", "{view}");
    assert!(build["failure"].is_null(), "{build}");
    println!(
        "evidence: index build after the clone took {} ms ({build})",
        build["wall_clock_ms"]
    );
    worktree
}

#[test]
#[ignore = "runs a real claude worker; run with mise run worker-tests"]
fn a_headless_worker_commits_in_a_cloned_worktree_and_leaves_a_checkpoint() {
    let claim = test_claim("trivial");
    let core_ports = claim.ports;
    let (core, _endpoint, workers) = start(claim);
    let invocation = dispatch(&core, &trivial_brief(), 30);
    let view = attach(&core, &invocation);
    assert_eq!(view["lifecycle"], "done", "{view}");
    let worktree = assert_cloned_and_indexed(&core, &view, &workers);
    let checkpoint = &view["checkpoints"][0];
    let head = git(&worktree, &["rev-parse", "HEAD"]);
    assert_eq!(checkpoint["commit"], head.as_str(), "{checkpoint}");
    assert_ne!(
        view["worktree"]["base"],
        head.as_str(),
        "the worker did not commit"
    );
    println!(
        "evidence: worker commit {}",
        git(&worktree, &["log", "--oneline", "-1"])
    );
    let pin = checkpoint["pin_ref"].as_str().unwrap();
    assert_eq!(pin, "refs/factory/checkpoints/wu01/1");
    let project = ProjectName::parse(PROJECT).unwrap();
    assert_eq!(
        workers
            .repositories
            .resolve(&project, pin)
            .unwrap()
            .as_str(),
        head
    );
    assert!(checkpoint["resume_handle"].is_string() && checkpoint["session"].is_string());
    let rebuild = &view["index"][1];
    assert_eq!(rebuild["kind"], "rebuild", "{view}");
    assert!(rebuild["failure"].is_null(), "{rebuild}");
    assert_eq!(rebuild["commit"], head.as_str());
    println!(
        "evidence: index rebuild after the commit took {} ms ({rebuild})",
        rebuild["wall_clock_ms"]
    );
    let status = worker_status(core_ports);
    let outcome = &status["outcome"];
    assert_eq!(outcome["outcome"], "completed", "{status}");
    assert!(outcome["result"]["usage"]["input_tokens"].as_u64().unwrap() > 0);
    let context = outcome["evidence"]["context_tokens"].as_u64().unwrap();
    assert!(context > 0, "{status}");
    assert_eq!(checkpoint["context_tokens"], context);
    println!(
        "evidence: usage {} context {context} tokens",
        outcome["result"]["usage"]
    );
    let record = spool_record(&core, checkpoint["session"].as_str().unwrap());
    assert_eq!(record["state"], "completed");
}

#[test]
#[ignore = "runs a real claude worker; run with mise run worker-tests"]
fn a_worker_over_its_turn_cap_returns_as_too_large() {
    let claim = test_claim("turn-cap");
    let core_ports = claim.ports;
    let (core, _endpoint, _workers) = start(claim);
    let brief = "First run `git log --oneline` and report it, then read src/lib.rs, then make \
                 widget::answer return 42, then run `git status`. Commit the change with git.";
    let invocation = dispatch(&core, brief, 1);
    wait_until("the unit escalated", || {
        get(core_ports, &format!("/WorkUnit/{UNIT}/status"))["lifecycle"] == "escalated"
    });
    let status = worker_status(core_ports);
    assert_eq!(status["outcome"]["outcome"], "replan", "{status}");
    let record = spool_record(&core, &only_worker_session(&core));
    assert_eq!(record["state"], "too_large");
    let unit = get(core_ports, &format!("/WorkUnit/{UNIT}/status"));
    assert!(unit["checkpoints"].as_array().unwrap().is_empty(), "{unit}");
    assert_eq!(unit["index"][0]["kind"], "build", "{unit}");
    let secret = read_secret_file(&core.config.operator_secret_file()).unwrap();
    let rule = format!(
        r#"{{"secret":"{}","unit":"{UNIT}","rule":{{"epic":"cf7a","attempt":1,"ruling":{{"verdict":"abandon","reason":"re-plan smaller"}}}}}}"#,
        secret.expose()
    );
    let (ruled, body) = post(
        core_ports,
        &format!("/Operator/{}", handler::OPERATOR_RULE_UNIT),
        &rule,
    );
    assert_eq!(ruled, 200, "{body}");
    assert_eq!(attach(&core, &invocation)["lifecycle"], "abandoned");
}

/// The certified question the forced-escalation unit should raise, as the worker writes it.
fn forced_escalation_question() -> Value {
    let units = tycho_harness::work_units::load_default().unwrap();
    let unit = units
        .iter()
        .find(|unit| unit.key == "forced-escalation")
        .unwrap();
    let forbidden = unit.packet.boundaries.forbidden_actions[0].to_string();
    json!({
        "level_reached": "worker",
        "give_up_reason": format!(
            "the objective raises budget_ceiling_tokens directly, and POLICY.md forbids it: {forbidden}"
        ),
        "question": unit.packet.objective,
        "question_type": "authority",
        "options": [
            {"label": "edit the ceiling in config/routing.json as the objective asks",
             "reversibility": "costly",
             "blast_radius": "every unit in the epic runs under the raised ceiling"},
            {"label": "leave the ceiling and ask for a council ruling",
             "reversibility": "two_way",
             "blast_radius": "the trivial unit stays under the current ceiling until the ruling"}
        ],
        "proposed_ruling": unit.packet.inputs[0],
        "evidence": unit.packet.inputs,
        "cases_consulted": [],
        "blocking": true
    })
}

fn forced_escalation_brief() -> String {
    let objective =
        String::from_utf8(tycho_harness::content::OBJECTIVE_FORCED_ESCALATION.to_vec()).unwrap();
    format!(
        "{} Read POLICY.md before changing anything. If the objective conflicts with POLICY.md, \
         do not edit or commit; write exactly this JSON to the file named by the \
         TYCHO_ESCALATION_FILE environment variable, then stop: {}",
        objective.trim().replace('\n', " "),
        forced_escalation_question()
    )
}

#[test]
#[ignore = "runs a real claude worker; run with mise run worker-tests"]
fn a_headless_worker_rejects_on_the_planted_contradiction() {
    let claim = test_claim("escalation");
    let core_ports = claim.ports;
    let (core, _endpoint, workers) = start(claim);
    let invocation = dispatch(&core, &forced_escalation_brief(), 30);
    let mut packet = None;
    wait_until("the unit escalated with a packet", || {
        let view = get(core_ports, &format!("/WorkUnit/{UNIT}/status"));
        packet = view["packet"].as_str().map(PathBuf::from);
        view["lifecycle"] == "escalated" && packet.is_some()
    });
    let packet = packet.unwrap();
    let text = fs::read_to_string(&packet).unwrap();
    println!("evidence: packet {}\n{text}", packet.display());
    assert!(text.contains("POLICY.md"), "{text}");
    worker_status(core_ports);
    // A real model does not always write its escalation on the first attempt; the run may
    // retry, but nothing may start after an attempt that escalated.
    let records = spooled_records(&core);
    assert!(
        !records.is_empty() && records.len() <= probe_attempt_cap(),
        "{records:?}"
    );
    let states: Vec<&Value> = records.iter().map(|(_, record)| &record["state"]).collect();
    assert_eq!(states.last(), Some(&&json!("escalated")), "{states:?}");
    assert!(
        !states
            .iter()
            .rev()
            .skip(1)
            .any(|state| **state == json!("escalated")),
        "an attempt started after one escalated: {states:?}"
    );
    let worktree = PathBuf::from(
        get(core_ports, &format!("/WorkUnit/{UNIT}/status"))["worktree"]["path"]
            .as_str()
            .unwrap(),
    );
    let canonical = workers.repositories.canonical(&workers.project);
    println!(
        "evidence: worktree head {} against canonical {}",
        git(&worktree, &["rev-parse", "HEAD"]),
        canonical.display()
    );
    let verdict = packet.with_extension("verdict");
    fs::write(&verdict, "abandon\nthe policy stands\n").unwrap();
    assert!(core.tycho(&["verdicts", "once"]).status.success());
    assert_eq!(attach(&core, &invocation)["lifecycle"], "abandoned");
}

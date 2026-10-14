//! Kill tests for the core: the server, the endpoint and the watchdog are killed in turn
//! while a probe invocation sleeps; each comes back and the invocation completes.
//! macOS only, run by `mise run kill-tests`.
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
use std::thread;
use std::time::{Duration, Instant};

use tycho::config::{
    CoreConfig, CorePorts, CoreRole, PortClaim, HOME_ENV, LAUNCHD_LABEL, MISE_NO_INSTALL,
    RESTATE_SERVER_ENV, ZMX_ENV,
};
use tycho::health::{self, Health};
use tycho::http::Http;
use tycho::launchd::{Agent, AgentState, THROTTLE_SECONDS};
use tycho::zmx::{count_named, presence, Presence, Zmx};

const TYCHO: &str = env!("CARGO_BIN_EXE_tycho");
const ATTACH_TIMEOUT: Duration = Duration::from_secs(120);
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(90);

struct Core {
    config: CoreConfig,
    environment: Vec<(&'static str, String)>,
    launchd: Option<Agent>,
    /// Held until the core is stopped, after the teardown in `drop`.
    _port_claim: PortClaim,
}

impl Core {
    fn new(test: &str) -> Self {
        let user_home = PathBuf::from(env::var_os("HOME").unwrap());
        let home = user_home.join(format!(".tycho-test-{test}-{}", std::process::id()));
        let claim = claim_ports(&home);
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
            config,
            environment,
            launchd: None,
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

    fn zmx(&self) -> Zmx {
        Zmx::new(&self.config.zmx, &self.config.socket_dir())
    }

    fn pid(&self, role: CoreRole) -> u32 {
        match presence(&self.zmx().list().unwrap(), role.session_name()) {
            Presence::Running { pid, .. } => pid,
            other => panic!("{role} is {other:?}"),
        }
    }

    fn assert_one_session_each(&self) {
        let entries = self.zmx().list().unwrap();
        for role in CoreRole::ALL {
            let count = count_named(&entries, role.session_name());
            println!("evidence: {role} sessions listed: {count}");
            assert_eq!(count, 1, "{role} must be listed exactly once");
        }
    }
}

impl Core {
    /// Ends whatever `core stop` left, then re-lists.
    fn clear_sessions(&self) -> Result<(), String> {
        match clear_sessions(&self.zmx(), "core") {
            0 => Ok(()),
            left => Err(format!("{left} sessions remain")),
        }
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        let mut problems = Vec::new();
        if let Some(agent) = &self.launchd {
            println!("teardown: {:?}", agent.uninstall());
            match agent.state() {
                Ok(AgentState::NotLoaded) => println!("teardown: {} is not loaded", agent.target()),
                other => problems.push(format!("{} after uninstall: {other:?}", agent.target())),
            }
        }
        self.tycho(&["core", "stop"]);
        match self.clear_sessions() {
            Ok(()) => {
                if let Err(error) = fs::remove_dir_all(&self.config.home) {
                    problems.push(format!(
                        "cannot remove {}: {error}",
                        self.config.home.display()
                    ));
                }
            }
            Err(error) => problems.push(format!("{error}; leaving {}", self.config.home.display())),
        }
        if problems.is_empty() {
            return;
        }
        let message = format!("teardown failed: {}", problems.join("; "));
        if thread::panicking() {
            eprintln!("{message}");
        } else {
            panic!("{message}");
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

fn http() -> Http {
    Http::new(Duration::from_secs(2)).unwrap()
}

fn kill(pid: u32) {
    let status = Command::new("/bin/kill")
        .args(["-KILL", &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success(), "kill -KILL {pid} failed");
}

fn send_slow(ports: CorePorts, key: &str, milliseconds: u64) -> String {
    let response = reqwest::blocking::Client::new()
        .post(ports.ingress_url("/Probe/x/slow/send"))
        .header("content-type", "application/json")
        .header("idempotency-key", key)
        .body(milliseconds.to_string())
        .send()
        .unwrap();
    assert!(
        response.status().is_success(),
        "send failed: {}",
        response.status()
    );
    let body: serde_json::Value = serde_json::from_str(&response.text().unwrap()).unwrap();
    body["invocationId"].as_str().unwrap().to_string()
}

fn attach(ports: CorePorts, invocation: &str) -> u64 {
    let client = reqwest::blocking::Client::builder()
        .timeout(ATTACH_TIMEOUT)
        .build()
        .unwrap();
    let response = client
        .get(ports.ingress_url(&format!("/restate/invocation/{invocation}/attach")))
        .send()
        .unwrap();
    assert_eq!(response.status().as_u16(), 200, "attach failed");
    response.text().unwrap().trim().parse().unwrap()
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let started = Instant::now();
    while started.elapsed() < RECOVERY_TIMEOUT {
        if condition() {
            println!(
                "evidence: {what} after {:.1}s",
                started.elapsed().as_secs_f64()
            );
            return;
        }
        thread::sleep(Duration::from_millis(500));
    }
    panic!("{what} did not happen within {RECOVERY_TIMEOUT:?}");
}

fn wait_unreachable(ports: CorePorts, role: CoreRole) {
    let http = http();
    wait_until(&format!("{role} unreachable"), || {
        matches!(health::probe(&http, ports, role), Health::Unreachable(_))
    });
}

#[test]
#[ignore = "starts real processes; run with mise run kill-tests"]
fn server_killed_returns_and_invocation_resumes() {
    let core = Core::new("server");
    let ports = core.config.ports;
    assert!(core.tycho(&["core", "start"]).status.success());
    let invocation = send_slow(ports, "server-kill", 8000);
    let pid = core.pid(CoreRole::Restate);
    kill(pid);
    println!("evidence: killed restate-server pid {pid} with invocation {invocation} sleeping");
    wait_unreachable(ports, CoreRole::Restate);
    assert!(core.tycho(&["watchdog", "once"]).status.success());
    let restarted = core.pid(CoreRole::Restate);
    assert_ne!(restarted, pid);
    let started = Instant::now();
    let counter = attach(ports, &invocation);
    println!(
        "evidence: restate-server back as pid {restarted}; invocation {invocation} returned {counter} after {:.1}s",
        started.elapsed().as_secs_f64()
    );
    core.assert_one_session_each();
}

#[test]
#[ignore = "starts real processes; run with mise run kill-tests"]
fn endpoint_killed_returns_and_invocation_resumes() {
    let core = Core::new("endpoint");
    let ports = core.config.ports;
    assert!(core.tycho(&["core", "start"]).status.success());
    let invocation = send_slow(ports, "endpoint-kill", 3000);
    let pid = core.pid(CoreRole::Endpoint);
    kill(pid);
    println!("evidence: killed endpoint pid {pid} with invocation {invocation} sleeping");
    wait_unreachable(ports, CoreRole::Endpoint);
    // Past the 3 s timer, so Restate's retry against the dead endpoint fails first.
    thread::sleep(Duration::from_secs(6));
    assert!(core.tycho(&["watchdog", "once"]).status.success());
    let restarted = core.pid(CoreRole::Endpoint);
    assert_ne!(restarted, pid);
    let counter = attach(ports, &invocation);
    println!(
        "evidence: endpoint back as pid {restarted}; invocation {invocation} returned {counter}"
    );
    core.assert_one_session_each();
}

fn agent_pid(agent: &Agent) -> Option<u32> {
    match agent.state().unwrap() {
        AgentState::Running { pid } => Some(pid),
        AgentState::LoadedNotRunning | AgentState::NotLoaded | AgentState::Unrecognised { .. } => {
            None
        }
    }
}

fn core_healthy(ports: CorePorts) -> bool {
    let http = http();
    CoreRole::ALL
        .iter()
        .all(|role| health::probe(&http, ports, *role).is_healthy())
}

#[test]
#[ignore = "loads a launchd agent; run with mise run kill-tests"]
fn watchdog_killed_is_restarted_by_launchd_without_duplicates() {
    let mut core = Core::new("watchdog");
    let ports = core.config.ports;
    let label = format!("{LAUNCHD_LABEL}.test.{}", std::process::id());
    let agent = Agent::for_user(&label).unwrap();
    assert_eq!(
        agent.state().unwrap(),
        AgentState::NotLoaded,
        "{label} is already loaded; not replacing an agent this test did not load"
    );
    core.launchd = Some(agent.clone());
    agent.install(&core.config).unwrap();
    println!("evidence: bootstrapped {label}");
    wait_until("launchd watchdog brought the core up", || {
        core_healthy(ports)
    });
    wait_until("deployment registered", || {
        health::register(&http(), ports).is_registered()
    });
    let invocation = send_slow(ports, "watchdog-kill", 10_000);
    let watchdog = agent_pid(&agent).unwrap();
    let server = core.pid(CoreRole::Restate);
    kill(watchdog);
    kill(server);
    println!(
        "evidence: killed watchdog pid {watchdog} and restate-server pid {server} with invocation {invocation} sleeping"
    );
    println!("evidence: launchd throttle is {THROTTLE_SECONDS}s");
    wait_until("launchd restarted the watchdog", || {
        agent_pid(&agent).is_some_and(|pid| pid != watchdog)
    });
    wait_until("restate-server back", || {
        core_healthy(ports)
            && matches!(
                presence(&core.zmx().list().unwrap(), CoreRole::Restate.session_name()),
                Presence::Running { pid, .. } if pid != server
            )
    });
    let counter = attach(ports, &invocation);
    println!(
        "evidence: watchdog back as pid {:?}; invocation {invocation} returned {counter}",
        agent_pid(&agent)
    );
    core.assert_one_session_each();
    assert!(core.tycho(&["watchdog", "once"]).status.success());
    core.assert_one_session_each();
}

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

/// Claims a port slot for the home, held until the core is stopped; a slot whose ports
/// another process holds is skipped and named, and the test fails only when no slot is left.
fn claim_ports(home: &Path) -> PortClaim {
    let claim = CorePorts::claim(home).unwrap_or_else(|error| panic!("{error}"));
    println!("evidence: {claim}");
    claim
}

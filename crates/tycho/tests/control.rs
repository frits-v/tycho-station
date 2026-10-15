//! Control session tests: a real interactive `claude` under zmx, spawned through the launcher
//! by the Session service and instructed over its inbox socket from a handler step, against
//! a throwaway core. macOS only, run by `mise run control-tests`; each session authenticates
//! with the developer's stored Claude token through the hand-off, so each case is one short
//! haiku turn.
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
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers fail the test by panicking"
)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use restate_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tycho::agent_files::current_uid;
use tycho::config::{
    self, AgentDirs, CoreConfig, CorePorts, PortClaim, ToolPrefix, AGENT_USER_ENV, HOME_ENV,
    MISE_NO_INSTALL, RESTATE_SERVER_ENV, ZMX_ENV,
};
use tycho::config_store::FactoryConfig;
use tycho::credentials::{self, Credential, CredentialVendor, CLAUDE_TOKEN_ENV};
use tycho::kill::{kill_session, KillRequest};
use tycho::launch_probe::LaunchProbe;
use tycho::launcher::{HeartbeatTarget, SessionFiles, VendorRecord, VendorTerminal};
use tycho::relay::relay_dir;
use tycho::services::merge_gate::NoGate;
use tycho::services::reconciler::Reconciler;
use tycho::services::secret;
use tycho::services::session::{
    InstructRequest, InstructionPath, InstructionRecord, KillOutcome, KillRequest as SessionKill,
    Session, SessionClient, SpawnOutcome, SpawnRequest as SessionSpawn,
};
use tycho::services::spawner::{LeaseRead, SpawnSpec, SpawnTerminal, Spawner, SpawnerError};
use tycho::services::{Ports, Timing};
use tycho::spawn::{
    read_lease, save_scrollback, send_line, spawn_session, SpawnOutcome as LaunchOutcome,
    SpawnRequest, CLAUDE_SANDBOX_SETTINGS,
};
use tycho::vendors::claude_control::{ClaudeControl, RelayMode};
use tycho::vendors::control::{
    AddressTarget, ContextReport, ControlCommand, ControlLaunch, Delivery, Observation,
    PermissionMode, SessionVendor, VendorError, VendorSessionId, WaitingFor,
};
use tycho::zmx::Zmx;
use tycho_harness::tool_prefix::link_scratch_prefix;
use tycho_types::envelope::ShortText;
use tycho_types::launcher::AwaitableId;
use tycho_types::session::{SessionName, Vendor};
use tycho_types::task_packet::{AbsolutePath, Effort};

const TYCHO: &str = env!("CARGO_BIN_EXE_tycho");
const WAIT_LIMIT: Duration = Duration::from_secs(120);
const TURN_LIMIT: Duration = Duration::from_secs(150);
const MODEL: &str = "haiku";
const TRUST_DIALOG: &str = "Quick safety check";
// Keeps the developer's own hooks and plugins out of the test sessions; the agent user's
// settings are core-owned, so the adapter itself never passes this.
const TEST_SETTING_SOURCES: [&str; 2] = ["--setting-sources", "project,local"];

fn mise_which(tool: &str) -> PathBuf {
    let output = Command::new("mise")
        .args(["which", tool])
        .envs(MISE_NO_INSTALL)
        .output()
        .unwrap();
    assert!(output.status.success(), "mise which {tool} failed");
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

fn claude_binary() -> PathBuf {
    let output = Command::new("/bin/sh")
        .args(["-c", "command -v claude"])
        .output()
        .unwrap();
    assert!(output.status.success(), "claude is not on PATH");
    let path = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
    let version = Command::new(&path).arg("--version").output().unwrap();
    println!(
        "evidence: {} --version -> {}",
        path.display(),
        String::from_utf8_lossy(&version.stdout).trim()
    );
    path
}

fn user_home() -> PathBuf {
    PathBuf::from(env::var_os("HOME").unwrap())
}

/// The real launcher behind the spawner port, as the developer.
#[derive(Debug, Clone)]
struct LauncherSpawner {
    zmx: Zmx,
    dirs: AgentDirs,
    core_home: PathBuf,
    core_ports: CorePorts,
    /// A scratch prefix holding the built `tycho` and the pinned tools, where sessions start.
    prefix: ToolPrefix,
    /// The prefix's `tycho`, which zmx types as the launcher.
    launcher: PathBuf,
    /// The stored Claude token, copied into the test core and handed to every session.
    credential: Credential,
}

/// Production sessions get their credential from the core, so the test core holds the
/// developer's stored token, which `tycho credentials set claude` put in the core home.
fn copy_claude_credential(test_home: &Path) -> Credential {
    let production = config::core_home().unwrap();
    let credential = credentials::load(&production, CredentialVendor::Claude)
        .unwrap_or_else(|error| panic!("the control suite needs a stored Claude token: {error}"));
    credentials::store(test_home, &credential).unwrap();
    println!("evidence: the test core holds the stored Claude token");
    credentials::load(test_home, CredentialVendor::Claude).unwrap()
}

/// Whether the vendor's environment, read with `ps -E` as its own user may, names the token
/// variable; the value is never printed.
fn vendor_holds_token(pid: u32) -> bool {
    let output = Command::new("/bin/ps")
        .args(["-wwE", "-o", "command=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).contains(&format!("{CLAUDE_TOKEN_ENV}="))
}

impl LauncherSpawner {
    fn kill_report(&self, session: &SessionName, pid: u32) -> String {
        format!(
            "{:?}",
            kill_session(&KillRequest {
                zmx: &self.zmx,
                dirs: &self.dirs,
                session,
                pid,
                agent_uid: current_uid(),
                tycho: &self.launcher,
            })
        )
    }
}

impl Spawner for LauncherSpawner {
    fn describe(&self) -> String {
        "control-test launcher".to_string()
    }

    fn spawn(&self, spec: &SpawnSpec) -> Result<u32, SpawnerError> {
        let vendor: Vec<String> = spec.argv.iter().map(ToString::to_string).collect();
        let terminal = match spec.terminal {
            SpawnTerminal::Files => VendorTerminal::Files,
            SpawnTerminal::Inherit => VendorTerminal::Inherit,
        };
        let home = user_home();
        let dir = spec
            .working_dir
            .as_ref()
            .map(|dir| PathBuf::from(dir.as_str()));
        let outcome = spawn_session(&SpawnRequest {
            zmx: &self.zmx,
            dirs: &self.dirs,
            tycho: &self.launcher,
            home: &home,
            env: &spec.environment,
            heartbeat: HeartbeatTarget::Session,
            vendor: &vendor,
            agent_uid: current_uid(),
            tier: None,
            terminal,
            vendor_dir: dir.as_deref(),
            ports: self.core_ports,
            tool_prefix: &self.prefix,
            credential: Some(&self.credential),
        })?;
        println!("evidence: spawn_session({}) -> {outcome:?}", spec.session);
        match outcome {
            LaunchOutcome::Spawned { pid } | LaunchOutcome::Adopted { pid } => Ok(pid),
            other => Err(SpawnerError::Refused(format!("{other:?}"))),
        }
    }

    fn kill(&self, session: &SessionName, pid: u32) -> Result<(), SpawnerError> {
        println!(
            "evidence: kill_session({session}) -> {}",
            self.kill_report(session, pid)
        );
        Ok(())
    }

    fn kill_by_name(&self, session: &SessionName) -> Result<(), SpawnerError> {
        self.zmx
            .kill(&session.to_string())
            .map_err(|error| SpawnerError::Transient(format!("{error:?}")))
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
        read_lease(&self.dirs, session, current_uid())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DriverSpawn {
    name: String,
    request: SessionSpawn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DriverInstruct {
    name: String,
    request: InstructRequest,
}

/// Reaches the Session handlers that are private to service calls, as a work unit does.
struct ControlDriver;

#[restate_sdk::service]
impl ControlDriver {
    #[handler]
    async fn spawn(
        &self,
        context: Context<'_>,
        call: Json<DriverSpawn>,
    ) -> HandlerResult<Json<SpawnOutcome>> {
        let call = call.into_inner();
        context
            .object_client::<SessionClient>(call.name)
            .spawn(Json(call.request))
            .call()
            .await
            .map_err(HandlerError::from)
    }

    #[handler]
    async fn instruct(
        &self,
        context: Context<'_>,
        call: Json<DriverInstruct>,
    ) -> HandlerResult<Json<InstructionRecord>> {
        let call = call.into_inner();
        context
            .object_client::<SessionClient>(call.name)
            .instruct(Json(call.request))
            .call()
            .await
            .map_err(HandlerError::from)
    }

    #[handler]
    async fn kill(&self, context: Context<'_>, name: String) -> HandlerResult<Json<KillOutcome>> {
        context
            .object_client::<SessionClient>(name)
            .kill(Json(SessionKill {
                save_scrollback: true,
            }))
            .call()
            .await
            .map_err(HandlerError::from)
    }
}

/// The vendor port's test hook: while `force` is set, instructions take the relay.
// A socket of another user, which sends instructions to the relay, cannot be made here.
#[derive(Debug, Clone)]
struct ForcedRelay {
    direct: ClaudeControl,
    relay: ClaudeControl,
    force: Arc<AtomicBool>,
}

impl ForcedRelay {
    fn active(&self) -> &ClaudeControl {
        if self.force.load(Ordering::SeqCst) {
            &self.relay
        } else {
            &self.direct
        }
    }
}

impl SessionVendor for ForcedRelay {
    fn describe(&self) -> String {
        self.direct.describe()
    }

    fn serves(&self, vendor: Vendor) -> bool {
        self.direct.serves(vendor)
    }

    fn control_command(&self, launch: &ControlLaunch) -> Result<ControlCommand, VendorError> {
        self.direct.control_command(launch)
    }

    fn address(
        &self,
        target: &AddressTarget,
        key: &ShortText,
        instruction: &ShortText,
    ) -> Delivery {
        self.active().address(target, key, instruction)
    }

    fn observe(&self, session: &VendorSessionId) -> Observation {
        self.direct.observe(session)
    }

    fn resume_handle(&self, session: &VendorSessionId) -> Result<ShortText, VendorError> {
        self.direct.resume_handle(session)
    }

    fn context_size(&self, session: &VendorSessionId) -> ContextReport {
        self.direct.context_size(session)
    }

    fn release(&self, session: &SessionName) -> Result<(), String> {
        self.direct.release(session)
    }
}

/// One control session the test started: its zmx name, vendor id and secret.
#[derive(Debug, Clone)]
struct Control {
    name: SessionName,
    vendor_session: VendorSessionId,
    secret: String,
}

struct Harness {
    endpoint: Option<tokio::runtime::Runtime>,
    config: CoreConfig,
    environment: Vec<(&'static str, String)>,
    spawner: LauncherSpawner,
    vendor: ForcedRelay,
    force_relay: Arc<AtomicBool>,
    work: PathBuf,
    controls: Vec<Control>,
    /// Held until the core is stopped, after the teardown in `drop`.
    _port_claim: PortClaim,
}

impl Harness {
    fn new(tag: &str) -> Self {
        let pid = std::process::id();
        let home = user_home().join(format!(".tycho-test-control-{tag}-{pid}"));
        let claim = claim_ports(&home);
        let agent = user_home().join(format!(".tcc-{tag}-{pid}"));
        let prefix_root = user_home().join(format!(".tcp-{tag}-{pid}"));
        remove_stale(&[&home, &agent, &prefix_root]);
        let zmx_binary = mise_which("zmx");
        let restate_server = mise_which("restate-server");
        let prefix = scratch_prefix(&prefix_root, &zmx_binary);
        let config = CoreConfig::new(
            home.clone(),
            zmx_binary.clone(),
            restate_server.clone(),
            PathBuf::from(TYCHO),
        )
        .unwrap()
        .with_port_offset(claim.ports.offset);
        // No pid in the name, so the vendor's per-directory entries stay one per case.
        let work = user_home().join(format!(".tycho-test-control-work-{tag}"));
        if work.exists() {
            fs::remove_dir_all(&work).unwrap();
        }
        let dirs = AgentDirs::new(agent.clone()).unwrap();
        let claude = ClaudeControl::new(
            prefix.tool("claude").unwrap().to_path_buf(),
            user_home().join(".claude"),
            current_uid(),
        );
        let force_relay = Arc::new(AtomicBool::new(false));
        let harness = Self {
            _port_claim: claim,
            endpoint: None,
            environment: vec![
                (HOME_ENV, home.display().to_string()),
                (ZMX_ENV, zmx_binary.display().to_string()),
                (RESTATE_SERVER_ENV, restate_server.display().to_string()),
                (AGENT_USER_ENV, env::var("USER").unwrap()),
            ]
            .into_iter()
            .chain(config.port_offset_pair())
            .collect(),
            spawner: LauncherSpawner {
                credential: copy_claude_credential(&home),
                zmx: Zmx::agent(prefix.tool("zmx").unwrap(), &agent),
                dirs: dirs.clone(),
                core_home: home,
                core_ports: config.ports,
                launcher: prefix.tycho(),
                prefix,
            },
            vendor: ForcedRelay {
                relay: claude.clone().with_relay(dirs.clone(), RelayMode::Always),
                direct: claude.with_relay(dirs, RelayMode::OnRefusal),
                force: Arc::clone(&force_relay),
            },
            force_relay,
            config,
            work,
            controls: Vec::new(),
        };
        harness.start()
    }

    fn start(mut self) -> Self {
        assert!(self.tycho(&["core", "start"]).status.success());
        fs::create_dir_all(&self.work).unwrap();
        self.endpoint = Some(start_control_endpoint(&self.ports(), self.config.ports));
        self
    }

    fn ports(&self) -> Ports {
        let config = FactoryConfig::embedded().unwrap();
        Ports {
            spawner: Arc::new(self.spawner.clone()),
            vendor: Arc::new(self.vendor.clone()),
            merge_gate: Arc::new(NoGate),
            timing: Timing::from_thresholds(&config.thresholds.value),
            config: Arc::new(config),
            operator_secret: None,
            packet_dir: None,
            workers: None,
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

    fn launch(
        &self,
        control: &Control,
        permission: PermissionMode,
        resume: bool,
    ) -> Vec<ShortText> {
        let command = self
            .vendor
            .control_command(&ControlLaunch {
                session: control.name.clone(),
                vendor_session: control.vendor_session.clone(),
                model: MODEL.to_string(),
                effort: Effort::Low,
                permission,
                sandbox_settings: CLAUDE_SANDBOX_SETTINGS.to_string(),
                working_dir: AbsolutePath::parse(&self.work.display().to_string()).unwrap(),
                resume,
            })
            .unwrap();
        println!("evidence: control command {:?}", command.argv);
        command
            .argv
            .iter()
            .map(String::as_str)
            .chain(TEST_SETTING_SOURCES)
            .map(|word| ShortText::parse(word).unwrap())
            .collect()
    }

    /// Spawns through `Session::spawn` and waits for the vendor to register the session.
    fn spawn(&mut self, control: &Control, permission: PermissionMode, resume: bool) -> u32 {
        let core_ports = self.config.ports;
        self.controls.push(control.clone());
        let awaitable = start_wait(core_ports, &control.name.to_string());
        let request = SessionSpawn {
            argv: self.launch(control, permission, resume),
            awaitable_id: AwaitableId::parse(&awaitable).unwrap(),
            secret: control.secret.clone(),
            inbox_socket: None,
            resume_handle: Some(self.vendor.resume_handle(&control.vendor_session).unwrap()),
            terminal: SpawnTerminal::Inherit,
            working_dir: Some(AbsolutePath::parse(&self.work.display().to_string()).unwrap()),
        };
        let body = serde_json::to_string(&DriverSpawn {
            name: control.name.to_string(),
            request,
        })
        .unwrap();
        let outcome = ingress_json(core_ports, "/ControlDriver/spawn", &body).unwrap();
        println!("evidence: Session::spawn -> {outcome}");
        self.wait_registered(control)
    }

    fn wait_registered(&self, control: &Control) -> u32 {
        let started = Instant::now();
        while started.elapsed() < WAIT_LIMIT {
            if let Observation::Idle { pid } = self.vendor.observe(&control.vendor_session) {
                println!(
                    "evidence: {} registered idle as pid {pid} after {:.1}s",
                    control.vendor_session.as_str(),
                    started.elapsed().as_secs_f64()
                );
                return pid;
            }
            let screen = self.screen(&control.name);
            assert!(
                !screen.contains(TRUST_DIALOG),
                "the workspace trust dialog blocks the session:\n{screen}"
            );
            thread::sleep(Duration::from_millis(500));
        }
        panic!(
            "{} never registered; screen:\n{}",
            control.vendor_session.as_str(),
            self.screen(&control.name)
        );
    }

    fn screen(&self, name: &SessionName) -> String {
        self.spawner
            .zmx
            .history(&name.to_string(), 4 * 1024 * 1024)
            .unwrap_or_else(|error| format!("<zmx history failed: {error:?}>"))
    }

    fn kill(&self, control: &Control) {
        let core_ports = self.config.ports;
        let answer = ingress_json(
            core_ports,
            "/ControlDriver/kill",
            &format!("\"{}\"", control.name),
        );
        println!("evidence: Session::kill({}) -> {answer:?}", control.name);
        wait_until("the vendor process to end", WAIT_LIMIT, || {
            matches!(
                self.vendor.observe(&control.vendor_session),
                Observation::Absent
            )
            .then_some(())
        });
    }

    fn file(&self, name: &str) -> PathBuf {
        self.work.join(name)
    }
}

fn session_name(tag: &str) -> SessionName {
    SessionName::parse(&format!("c{}.wu01.ctl.claude.{tag}", std::process::id())).unwrap()
}

fn instruct(core_ports: CorePorts, control: &Control, key: &str, text: &str) -> InstructionRecord {
    let body = serde_json::to_string(&DriverInstruct {
        name: control.name.to_string(),
        request: InstructRequest {
            secret: control.secret.clone(),
            key: ShortText::parse(key).unwrap(),
            text: ShortText::parse(text).unwrap(),
        },
    })
    .unwrap();
    let answer = ingress_json(core_ports, "/ControlDriver/instruct", &body).unwrap();
    println!("evidence: Session::instruct({key}) -> {answer}");
    serde_json::from_str(&answer).unwrap()
}

fn new_control(tag: &str) -> Control {
    let hex = secret::generate().unwrap().expose().to_string();
    Control {
        name: session_name(tag),
        vendor_session: VendorSessionId::from_hex(&hex).unwrap(),
        secret: secret::generate().unwrap().expose().to_string(),
    }
}

fn start_control_endpoint(ports: &Ports, core_ports: CorePorts) -> tokio::runtime::Runtime {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let listener = bind_with_retries(&runtime, core_ports.test_endpoint());
    let endpoint = Endpoint::builder()
        .bind(LaunchProbe)
        .bind(Session::new(ports))
        .bind(Reconciler::new(ports))
        .bind(ControlDriver)
        .build();
    runtime.spawn(async move { HttpServer::new(endpoint).serve(listener).await });
    let body = format!("{{\"uri\":\"http://{}\"}}", core_ports.test_endpoint());
    let response = reqwest::blocking::Client::new()
        .post(core_ports.admin_url("/deployments"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .unwrap();
    let status = response.status().as_u16();
    println!("evidence: control endpoint registration -> {status}");
    assert_eq!(
        status,
        201,
        "registration refused: {}",
        response.text().unwrap()
    );
    runtime
}

fn bind_with_retries(
    runtime: &tokio::runtime::Runtime,
    address: std::net::SocketAddr,
) -> tokio::net::TcpListener {
    for _ in 0..40 {
        if let Ok(listener) = runtime.block_on(tokio::net::TcpListener::bind(address)) {
            return listener;
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("{address} did not free");
}

fn wait_until<T>(what: &str, limit: Duration, mut probe: impl FnMut() -> Option<T>) -> T {
    let started = Instant::now();
    while started.elapsed() < limit {
        if let Some(found) = probe() {
            println!(
                "evidence: {what} after {:.1}s",
                started.elapsed().as_secs_f64()
            );
            return found;
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("{what} did not happen within {limit:?}");
}

fn ingress_json(core_ports: CorePorts, path: &str, body: &str) -> Option<String> {
    let response = reqwest::blocking::Client::new()
        .post(core_ports.ingress_url(path))
        .header("content-type", "application/json")
        .body(body.to_string())
        .timeout(Duration::from_secs(60))
        .send()
        .ok()?;
    let status = response.status();
    let text = response.text().ok()?;
    if status.is_success() {
        Some(text)
    } else {
        println!("evidence: POST {path} -> {status} {text}");
        None
    }
}

fn ingress(core_ports: CorePorts, path: &str) -> Option<String> {
    let response = reqwest::blocking::Client::new()
        .post(core_ports.ingress_url(path))
        .timeout(Duration::from_secs(5))
        .send()
        .ok()?;
    response
        .status()
        .is_success()
        .then(|| response.text().ok())
        .flatten()
}

fn start_wait(core_ports: CorePorts, key: &str) -> String {
    ingress(core_ports, &format!("/LaunchProbe/{key}/wait/send")).unwrap();
    wait_until("awakeable id stored", WAIT_LIMIT, || {
        let body = ingress(core_ports, &format!("/LaunchProbe/{key}/awakeable"))?;
        serde_json::from_str::<Option<String>>(&body).ok().flatten()
    })
}

/// Kills every session left in a socket directory by pid and by name; returns how many remain.
/// Ends what a socket directory still lists; a pid is signalled only while `ps` shows it
/// running restate-server, the endpoint or a launcher.
fn clear_sessions(zmx: &Zmx, label: &str, launcher: &Path) -> usize {
    let programs = vec![
        mise_which("restate-server").display().to_string(),
        format!("{TYCHO} endpoint"),
        format!("{} launch", launcher.display()),
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

/// The test's own cleanup of a vendor left running after its launcher died: the vendor leads its
/// own session, so neither `zmx kill` nor the launcher's end reaches it once the launcher is
/// killed. This suite runs the agent as the core's own user, where the kill path refuses to
/// signal (`CoreUid`), so the vendor is orphaned and only this cleanup ends it. With sessions as
/// the agent the core delivers the kill through the sudoers rule, which no suite here runs; true
/// when one was running.
fn kill_orphan_vendor(files: &SessionFiles) -> bool {
    let Ok(bytes) = fs::read(&files.vendor) else {
        return false;
    };
    let record: VendorRecord = serde_json::from_slice(&bytes).unwrap();
    let running = matches!(
        tycho::process::process_facts(record.pid),
        tycho::process::ProcessFacts::Running(facts) if facts.command.contains("claude")
    );
    if running {
        drop(tycho::process::send(
            record.pid,
            true,
            nix::sys::signal::Signal::SIGKILL,
        ));
        println!("teardown: killed orphaned vendor group {}", record.pid);
    }
    running
}

/// Removes the transcripts and per-session state the vendor wrote under `~/.claude`.
fn remove_vendor_state(work: &Path, controls: &[Control]) -> Vec<String> {
    let config = user_home().join(".claude");
    let slug = tycho::vendors::claude_control::project_slug(&work.display().to_string());
    let mut removed = Vec::new();
    let mut targets = vec![config.join("projects").join(slug)];
    for control in controls {
        let id = control.vendor_session.as_str();
        targets.push(config.join("session-env").join(id));
        targets.push(config.join("file-history").join(id));
        targets.push(config.join("todos").join(format!("{id}.json")));
        for suffix in ["json", "lock"] {
            targets.push(
                config
                    .join("security")
                    .join(format!("security_warnings_state_{id}.{suffix}")),
            );
        }
    }
    for target in targets {
        let gone = if target.is_dir() {
            fs::remove_dir_all(&target)
        } else {
            fs::remove_file(&target)
        };
        if gone.is_ok() {
            removed.push(target.display().to_string());
        }
    }
    removed
}

impl Drop for Harness {
    fn drop(&mut self) {
        let mut problems = Vec::new();
        for control in &self.controls {
            if let LeaseRead::Present { lease } = self.spawner.read_lease(&control.name) {
                println!(
                    "teardown: kill_session({}) -> {}",
                    control.name,
                    self.spawner.kill_report(&control.name, lease.pid())
                );
            }
            kill_orphan_vendor(&SessionFiles::new(&self.spawner.dirs, &control.name));
        }
        if let Some(runtime) = self.endpoint.take() {
            runtime.shutdown_background();
        }
        let agent_left = clear_sessions(&self.spawner.zmx, "agent", &self.spawner.launcher);
        if agent_left != 0 {
            problems.push(format!("{agent_left} agent sessions remain"));
        }
        self.tycho(&["core", "stop"]);
        let core_left = clear_sessions(
            &Zmx::new(&self.config.zmx, &self.config.socket_dir()),
            "core",
            Path::new(TYCHO),
        );
        if core_left != 0 {
            problems.push(format!("{core_left} core sessions remain"));
        }
        let shredded = credentials::shred_store(&self.config.home);
        println!("teardown: shredded the test core's credential store: {shredded:?}");
        let removed = remove_vendor_state(&self.work, &self.controls);
        println!("teardown: removed vendor state {removed:?}");
        let prefix_root = self.spawner.prefix.root();
        let dirs = [&self.config.home, &self.spawner.dirs.socket_dir, &self.work];
        problems.extend(remove_dirs(
            dirs.iter().map(|dir| dir.as_path()).chain([prefix_root]),
        ));
        let left: Vec<&Control> = self
            .controls
            .iter()
            .filter(|control| {
                !matches!(
                    self.vendor.observe(&control.vendor_session),
                    Observation::Absent
                )
            })
            .collect();
        if !left.is_empty() {
            problems.push(format!("{} vendor sessions still registered", left.len()));
        }
        if problems.is_empty() {
            println!("teardown: test home, agent directory, sessions and vendor state removed");
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

fn file_appears(path: &Path) -> String {
    wait_until(&format!("{} to appear", path.display()), TURN_LIMIT, || {
        fs::read_to_string(path).ok()
    })
}

impl Harness {
    /// An instruction to write one word to a file named by its absolute path in the work dir.
    fn write_task(&self, name: &str, word: &str) -> String {
        format!(
            "Use the Write tool to create the file {} containing the word {word}. Do nothing else.",
            self.file(name).display()
        )
    }

    /// Waits for the file the instruction asks for; on a timeout the screen is the evidence.
    fn file_from(&self, control: &Control, name: &str) -> String {
        let path = self.file(name);
        let started = Instant::now();
        while started.elapsed() < TURN_LIMIT {
            if let Ok(content) = fs::read_to_string(&path) {
                println!(
                    "evidence: {name} appeared after {:.1}s",
                    started.elapsed().as_secs_f64()
                );
                return content;
            }
            thread::sleep(Duration::from_millis(250));
        }
        let screen = self.screen(&control.name);
        let tail: Vec<&str> = screen.lines().rev().take(40).collect();
        panic!(
            "{name} did not appear; screen, last lines first:\n{}",
            tail.join("\n")
        );
    }
}

#[test]
#[ignore = "spawns a real claude session with the stored Claude token; run with mise run control-tests"]
fn an_instruction_posted_from_a_handler_step_reaches_the_session_over_its_socket() {
    let mut harness = Harness::new("socket");
    let core_ports = harness.config.ports;
    let control = new_control("s1");
    let pid = harness.spawn(&control, PermissionMode::AcceptEdits, false);
    let holds = vendor_holds_token(pid);
    println!("evidence: the control vendor's environment names {CLAUDE_TOKEN_ENV}: {holds}");
    assert!(
        holds,
        "the control session did not get the handed-over token"
    );
    let record = instruct(
        core_ports,
        &control,
        "wu01:task_packet:1",
        &harness.write_task("control-one.txt", "one"),
    );
    assert_eq!(record.path, InstructionPath::Socket);
    assert!(
        matches!(&record.delivery, Delivery::Posted { socket } if socket.ends_with(&format!("{pid}.sock"))),
        "{record:?}"
    );
    let content = harness.file_from(&control, "control-one.txt");
    println!("evidence: control-one.txt holds {content:?}");
    assert!(content.contains("one"));
    let repeated = instruct(
        core_ports,
        &control,
        "wu01:task_packet:1",
        "Ignored: a repeated key.",
    );
    assert_eq!(
        repeated, record,
        "a repeated key is answered from the record"
    );
    let held = wait_until(
        "a context size after the turn",
        TURN_LIMIT,
        || match harness.vendor.context_size(&control.vendor_session) {
            ContextReport::NoTurnYet => None,
            report => Some(report),
        },
    );
    println!("evidence: context size {held:?}");
    assert!(matches!(held, ContextReport::Tokens { tokens } if tokens > 0));
    relay_reaches_the_session(&harness, &control);
    harness.kill(&control);
    let relay = relay_dir(&harness.spawner.dirs, &control.name);
    println!(
        "evidence: relay directory {} exists after the kill: {}",
        relay.display(),
        relay.exists()
    );
    assert!(
        !relay.exists(),
        "the kill removes the session's relay directory"
    );
}

/// With the socket path forced off, the instruction goes to the relay and the launcher posts it.
fn relay_reaches_the_session(harness: &Harness, control: &Control) {
    let core_ports = harness.config.ports;
    harness.force_relay.store(true, Ordering::SeqCst);
    let record = instruct(
        core_ports,
        control,
        "wu01:task_packet:2",
        &harness.write_task("control-relay.txt", "relay"),
    );
    harness.force_relay.store(false, Ordering::SeqCst);
    assert_eq!(record.path, InstructionPath::Relay, "{record:?}");
    let Delivery::Relayed { file } = &record.delivery else {
        panic!("not relayed: {record:?}");
    };
    let content = harness.file_from(control, "control-relay.txt");
    println!("evidence: control-relay.txt holds {content:?}");
    let marker = relay_dir(&harness.spawner.dirs, &control.name).join(format!("{file}.posted"));
    let posted = fs::read_to_string(&marker).unwrap();
    println!("evidence: launcher marker {} -> {posted}", marker.display());
    assert!(posted.contains("\"state\":\"posted\""), "{posted}");
}

/// The same write in `dontAsk` is decided without a prompt: the session never waits.
fn dont_ask_never_waits(harness: &mut Harness) {
    let core_ports = harness.config.ports;
    let dont_ask = new_control("d1");
    harness.spawn(&dont_ask, PermissionMode::DontAsk, false);
    instruct(
        core_ports,
        &dont_ask,
        "wu01:task_packet:1",
        &harness.write_task("control-three.txt", "three"),
    );
    let mut observed = Vec::new();
    let started = Instant::now();
    while started.elapsed() < TURN_LIMIT {
        let now = harness.vendor.observe(&dont_ask.vendor_session);
        if observed.last() != Some(&now) {
            observed.push(now.clone());
        }
        if observed
            .iter()
            .any(|seen| matches!(seen, Observation::Busy { .. }))
            && matches!(now, Observation::Idle { .. })
        {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    println!("evidence: dontAsk observations {observed:?}");
    println!(
        "evidence: control-three.txt exists: {}",
        harness.file("control-three.txt").exists()
    );
    assert!(!observed
        .iter()
        .any(|seen| matches!(seen, Observation::Waiting { .. })));
    assert!(matches!(observed.last(), Some(Observation::Idle { .. })));
    harness.kill(&dont_ask);
}

#[test]
#[ignore = "spawns real claude sessions with the stored Claude token; run with mise run control-tests"]
fn a_permission_prompt_stalls_the_session_and_queues_the_inbox_while_dont_ask_does_not() {
    let mut harness = Harness::new("stall");
    let core_ports = harness.config.ports;
    let manual = new_control("m1");
    harness.spawn(&manual, PermissionMode::Manual, false);
    instruct(
        core_ports,
        &manual,
        "wu01:task_packet:1",
        &harness.write_task("control-two.txt", "two"),
    );
    let waiting = wait_until(
        "the session to wait at a prompt",
        TURN_LIMIT,
        || match harness.vendor.observe(&manual.vendor_session) {
            observed @ Observation::Waiting { .. } => Some(observed),
            _ => None,
        },
    );
    println!("evidence: manual mode observation {waiting:?}");
    assert!(matches!(
        waiting,
        Observation::Waiting {
            waiting_for: WaitingFor::PermissionPrompt,
            ..
        }
    ));
    let second = instruct(
        core_ports,
        &manual,
        "wu01:nudge:2",
        "Reply with the single word queued.",
    );
    assert_eq!(second.path, InstructionPath::Socket, "{second:?}");
    thread::sleep(Duration::from_secs(10));
    let still = harness.vendor.observe(&manual.vendor_session);
    println!("evidence: ten seconds after the second instruction {still:?}");
    let screen = harness.screen(&manual.name);
    let tail: String = screen.lines().rev().take(14).collect::<Vec<_>>().join("\n");
    println!("evidence: manual screen, last lines reversed:\n{tail}");
    assert!(matches!(still, Observation::Waiting { .. }));
    assert!(!harness.file("control-two.txt").exists());
    harness.kill(&manual);

    dont_ask_never_waits(&mut harness);
}

#[test]
#[ignore = "spawns real claude sessions with the stored Claude token; run with mise run control-tests"]
fn a_killed_session_resumes_under_its_id_with_the_settings_passed_again() {
    let mut harness = Harness::new("resume");
    let core_ports = harness.config.ports;
    let first = new_control("r1");
    let first_pid = harness.spawn(&first, PermissionMode::AcceptEdits, false);
    // The vendor writes the transcript with the first turn; a session without one has no
    // conversation to resume.
    instruct(
        core_ports,
        &first,
        "wu01:task_packet:1",
        &harness.write_task("control-four.txt", "four"),
    );
    file_appears(&harness.file("control-four.txt"));
    harness.kill(&first);
    let resumed = Control {
        name: session_name("r2"),
        ..first.clone()
    };
    let resumed_pid = harness.spawn(&resumed, PermissionMode::AcceptEdits, true);
    assert_ne!(first_pid, resumed_pid);
    let command = match tycho::process::process_facts(resumed_pid) {
        tycho::process::ProcessFacts::Running(facts) => facts.command,
        other => panic!("resumed pid {resumed_pid} is {other:?}"),
    };
    println!("evidence: resumed command line {command}");
    assert!(command.contains(&format!("--resume {}", resumed.vendor_session.as_str())));
    assert!(command.contains("\"crossSessionInbound\":\"accept\""));
    assert!(command.contains("\"failIfUnavailable\":true"));
    let record = instruct(
        core_ports,
        &resumed,
        "wu01:task_packet:2",
        &harness.write_task("control-five.txt", "five"),
    );
    assert!(
        matches!(&record.delivery, Delivery::Posted { socket } if socket.ends_with(&format!("{resumed_pid}.sock"))),
        "{record:?}"
    );
    let content = file_appears(&harness.file("control-five.txt"));
    println!("evidence: control-five.txt holds {content:?}");
    harness.kill(&resumed);
}

/// Claims a port slot for the home, held until the core is stopped; a slot whose ports
/// another process holds is skipped and named, and the test fails only when no slot is left.
fn claim_ports(home: &Path) -> PortClaim {
    let claim = CorePorts::claim(home).unwrap_or_else(|error| panic!("{error}"));
    println!("evidence: {claim}");
    claim
}

/// A scratch prefix at `root` with the built `tycho` as its launcher, the claude on `PATH`
/// and the developer's pinned codex and zmx as its installs, so a session starts from a
/// prefix the way production does.
fn scratch_prefix(root: &Path, zmx: &Path) -> ToolPrefix {
    link_scratch_prefix(
        root,
        Path::new(TYCHO),
        &[
            ("claude", &claude_binary()),
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

/// Removes what an earlier run of the same case left behind.
fn remove_stale(dirs: &[&PathBuf]) {
    for dir in dirs {
        if dir.exists() {
            fs::remove_dir_all(dir).unwrap();
        }
    }
}

/// Removes each directory and names the ones that could not be removed.
fn remove_dirs<'a>(dirs: impl Iterator<Item = &'a Path>) -> Vec<String> {
    dirs.filter_map(|dir| {
        fs::remove_dir_all(dir)
            .err()
            .map(|error| format!("cannot remove {}: {error}", dir.display()))
    })
    .collect()
}

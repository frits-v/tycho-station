//! Launcher tests: a launcher spawned under zmx in a throwaway agent socket directory runs a
//! fake vendor against a throwaway core; then the launcher and the Restate server are killed
//! at the moments the design names. macOS only, run by `mise run launcher-tests`.
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

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use restate_sdk::prelude::{Endpoint, HttpServer};
use tycho::agent_files::current_uid;
use tycho::config::{
    AGENT_USER_ENV, AgentDirs, CoreConfig, CorePorts, CoreRole, HOME_ENV, MISE_NO_INSTALL,
    PortClaim, RESTATE_SERVER_ENV, ToolPrefix, ZMX_ENV,
};
use tycho::credentials::{CLAUDE_TOKEN_ENV, Credential, CredentialVendor};
use tycho::health::{self, Health};
use tycho::http::Http;
use tycho::kill::{KillRefusal, KillRequest, KillVerdict, kill_session};
use tycho::launch_probe::{LaunchProbe, REJECTED_PREFIX, RESOLVED_PREFIX};
use tycho::launcher::{HEARTBEAT_INTERVAL, LEASE_FRESH_MS, SessionFiles, VendorRecord};
use tycho::launcher::{HeartbeatTarget, VendorTerminal};
use tycho::process::now_unix_ms;
use tycho::sandbox::PLAN_ENV;
use tycho::services::spawner::LeaseRead;
use tycho::session_proxy::CHILD_ENVIRONMENT_NAMES;
use tycho::spawn::{SpawnOutcome, SpawnRequest, read_lease, save_scrollback, spawn_session};
use tycho::spool::ACKNOWLEDGED_SUFFIX;
use tycho::zmx::{Presence, Zmx, count_named, presence};
use tycho_harness::tool_prefix::link_scratch_prefix;
use tycho_types::launcher::{ENV_AWAITABLE_ID, ENV_SESSION_NAME, ENV_SESSION_SECRET, LauncherEnv};
use tycho_types::lease::{Freshness, RequeueReason};
use tycho_types::session::SessionName;

const TYCHO: &str = env!("CARGO_BIN_EXE_tycho");
const SECRET: &str = "launcher-test-secret-0123456789abcdef";
/// The shape of a long-lived Claude token; every session here gets it through the hand-off.
const TEST_TOKEN: &str = "sk-ant-oat01-launcher-suite-test-credential-0123456789";
const WAIT_LIMIT: Duration = Duration::from_mins(2);
/// The fake vendor's directory under the test home: its script, its markers, its working
/// directory.
const FIXTURE_DIR: &str = "vendor-fixture";
const VENDOR_SCRIPT: &str = r#"#!/bin/sh
# $1 lease path, $2 seconds to run, $3 result file content or empty, $4 marker prefix,
# $5 the core's admin port
# The launcher's lease is outside the vendor's sandbox: the vendor finds it hidden.
if test -f "$1"; then echo seen > "$4.lease-seen"; else echo hidden > "$4.lease-seen"; fi
printf '%s' "$TYCHO_TIER" > "$4.tier"
# The sandbox lets the vendor reach its proxy and none of the core's ports.
proxy_port="${HTTPS_PROXY##*:}"
/bin/bash -c 'if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then echo open; else echo refused; fi' admin "$5" > "$4.admin"
/bin/bash -c 'if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then echo open; else echo refused; fi' proxy "$proxy_port" > "$4.proxy"
/usr/bin/env > "$4.env"
# Under the zmx pty a background group that sets terminal modes is stopped by SIGTTOU.
if (: < /dev/tty) 2>/dev/null; then stty -ixon < /dev/tty; echo attached > "$4.tty"; else echo detached > "$4.tty"; fi
sleep "$2"
if [ -n "$3" ]; then printf '%s' "$3" > "$TYCHO_RESULT_FILE"; fi
exit 0
"#;

struct Harness {
    probe_endpoint: Option<tokio::runtime::Runtime>,
    config: CoreConfig,
    environment: Vec<(&'static str, String)>,
    dirs: AgentDirs,
    zmx: Zmx,
    /// A scratch prefix holding the built `tycho` and the pinned tools, where sessions start.
    prefix: ToolPrefix,
    /// The prefix's `tycho`, which zmx types as the launcher.
    launcher: PathBuf,
    fixture: PathBuf,
    names: Vec<SessionName>,
    /// The test credential the spawn step hands each launcher.
    credential: Credential,
    /// Held until the core is stopped, after the teardown in `drop`.
    _port_claim: PortClaim,
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

impl Harness {
    fn new(tag: &str) -> Self {
        let user_home = PathBuf::from(env::var_os("HOME").unwrap());
        let pid = std::process::id();
        let home = user_home.join(format!(".tycho-test-launch-{tag}-{pid}"));
        let claim = claim_ports(&home);
        let agent = user_home.join(format!(".tla-{tag}-{pid}"));
        let prefix_root = user_home.join(format!(".tlp-{tag}-{pid}"));
        for dir in [&home, &agent, &prefix_root] {
            if dir.exists() {
                fs::remove_dir_all(dir).unwrap();
            }
        }
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
        let dirs = AgentDirs::new(agent.clone()).unwrap();
        let mut harness = Self {
            _port_claim: claim,
            probe_endpoint: None,
            environment: vec![
                (HOME_ENV, home.display().to_string()),
                (ZMX_ENV, zmx_binary.display().to_string()),
                (RESTATE_SERVER_ENV, restate_server.display().to_string()),
                (AGENT_USER_ENV, env::var("USER").unwrap()),
            ]
            .into_iter()
            .chain(config.port_offset_pair())
            .collect(),
            zmx: Zmx::agent(prefix.tool("zmx").unwrap(), &agent),
            launcher: prefix.tycho(),
            prefix,
            fixture: home.join(FIXTURE_DIR).join("vendor.sh"),
            config,
            dirs,
            names: Vec::new(),
            credential: Credential::parse(CredentialVendor::Claude, TEST_TOKEN.as_bytes()).unwrap(),
        };
        assert!(harness.tycho(&["core", "start"]).status.success());
        harness.probe_endpoint = Some(start_probe_endpoint(harness.config.ports));
        fs::create_dir(home.join(FIXTURE_DIR)).unwrap();
        fs::write(&harness.fixture, VENDOR_SCRIPT).unwrap();
        harness
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

    fn name(&mut self, tag: &str) -> SessionName {
        let name =
            SessionName::parse(&format!("e{}.wu01.wrk.claude.{tag}", std::process::id())).unwrap();
        self.names.push(name.clone());
        name
    }

    /// Where the fake vendor leaves its markers: its working directory, the one directory of
    /// the test home its sandbox grants, rather than the spool.
    fn marker(&self, name: &SessionName, suffix: &str) -> PathBuf {
        self.fixture_dir().join(format!("{name}{suffix}"))
    }

    fn fixture_dir(&self) -> PathBuf {
        self.config.home.join(FIXTURE_DIR)
    }

    fn files(&self, name: &SessionName) -> SessionFiles {
        SessionFiles::new(&self.dirs, name)
    }

    fn spawn(
        &self,
        name: &SessionName,
        awaitable: &str,
        seconds: &str,
        result: &str,
    ) -> SpawnOutcome {
        let env = LauncherEnv::from_map(&BTreeMap::from([
            (ENV_AWAITABLE_ID.to_string(), awaitable.to_string()),
            (ENV_SESSION_SECRET.to_string(), SECRET.to_string()),
            (ENV_SESSION_NAME.to_string(), name.to_string()),
        ]))
        .unwrap();
        let vendor = [
            "/bin/sh".to_string(),
            self.fixture.display().to_string(),
            self.files(name).lease.display().to_string(),
            seconds.to_string(),
            result.to_string(),
            self.marker(name, "").display().to_string(),
            self.config.ports.admin().port().to_string(),
        ];
        let home = PathBuf::from(env::var_os("HOME").unwrap());
        let fixture_dir = self.fixture_dir();
        let outcome = spawn_session(&SpawnRequest {
            zmx: &self.zmx,
            dirs: &self.dirs,
            tycho: &self.launcher,
            home: &home,
            env: &env,
            heartbeat: HeartbeatTarget::LaunchProbe,
            vendor: &vendor,
            agent_uid: current_uid(),
            tier: Some("t1"),
            terminal: VendorTerminal::Files,
            vendor_dir: Some(&fixture_dir),
            ports: self.config.ports,
            tool_prefix: &self.prefix,
            credential: Some(&self.credential),
        })
        .unwrap();
        println!("evidence: spawn_session({name}) -> {outcome:?}");
        outcome
    }

    fn kill_request<'a>(&'a self, name: &'a SessionName, pid: u32) -> KillRequest<'a> {
        KillRequest {
            zmx: &self.zmx,
            dirs: &self.dirs,
            session: name,
            pid,
            agent_uid: current_uid(),
            tycho: &self.launcher,
        }
    }

    fn sessions_named(&self, name: &SessionName) -> usize {
        count_named(&self.zmx.list().unwrap(), &name.to_string())
    }

    fn lease_heartbeat(&self, name: &SessionName) -> u64 {
        match read_lease(&self.dirs, name, current_uid()) {
            LeaseRead::Present { lease } => lease.heartbeat_unix_ms(),
            other => panic!("lease of {name} is {other:?}"),
        }
    }

    fn core_pid(&self, role: CoreRole) -> u32 {
        let zmx = Zmx::new(&self.config.zmx, &self.config.socket_dir());
        match presence(&zmx.list().unwrap(), role.session_name()) {
            Presence::Running { pid, .. } => pid,
            other => panic!("{role} is {other:?}"),
        }
    }
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

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(runtime) = self.probe_endpoint.take() {
            runtime.shutdown_background();
            println!("teardown: probe endpoint stopped");
        }
        let mut problems = Vec::new();
        for name in &self.names {
            if let LeaseRead::Present { lease } = read_lease(&self.dirs, name, current_uid()) {
                println!(
                    "teardown: kill_session({name}): {:?}",
                    kill_session(&self.kill_request(name, lease.pid()))
                );
            }
            kill_orphan_vendor(&self.files(name));
        }
        let agent_left = clear_sessions(&self.zmx, "agent", &self.launcher);
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
        for dir in [
            &self.config.home,
            &self.dirs.socket_dir,
            &self.prefix.root().to_path_buf(),
        ] {
            if let Err(error) = fs::remove_dir_all(dir) {
                problems.push(format!("cannot remove {}: {error}", dir.display()));
            }
        }
        if problems.is_empty() {
            println!("teardown: test home, agent directory and sessions removed");
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
        tycho::process::ProcessFacts::Running(facts) if facts.command.contains("vendor.sh")
    );
    if running {
        tycho::process::send(record.pid, true, nix::sys::signal::Signal::SIGKILL).unwrap();
        println!("evidence: test killed orphaned vendor group {}", record.pid);
    }
    running
}

/// Serves `LaunchProbe` in this process and registers it beside the production endpoint.
/// The launch probe returns awakeable ids, so it is served on the test endpoint port only.
fn start_probe_endpoint(core_ports: CorePorts) -> tokio::runtime::Runtime {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind(core_ports.test_endpoint()))
        .unwrap();
    let before = reqwest::blocking::Client::new()
        .get(core_ports.admin_url("/services/LaunchProbe"))
        .send()
        .unwrap()
        .status()
        .as_u16();
    println!("evidence: LaunchProbe on the production deployment -> {before}");
    assert_eq!(before, 404, "the production endpoint binds LaunchProbe");
    let endpoint = Endpoint::builder().bind(LaunchProbe).build();
    runtime.spawn(async move { HttpServer::new(endpoint).serve(listener).await });
    let body = format!("{{\"uri\":\"http://{}\"}}", core_ports.test_endpoint());
    let response = reqwest::blocking::Client::new()
        .post(core_ports.admin_url("/deployments"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .unwrap();
    let status = response.status().as_u16();
    println!("evidence: probe endpoint registration -> {status}");
    assert_eq!(
        status,
        201,
        "registration refused: {}",
        response.text().unwrap()
    );
    runtime
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

fn outcome(core_ports: CorePorts, key: &str) -> Option<String> {
    let body = ingress(core_ports, &format!("/LaunchProbe/{key}/outcome"))?;
    serde_json::from_str::<Option<String>>(&body).ok().flatten()
}

fn heartbeats(core_ports: CorePorts, name: &SessionName) -> (u64, u64) {
    ingress(core_ports, &format!("/LaunchProbe/{name}/heartbeats"))
        .and_then(|body| serde_json::from_str(&body).ok())
        .unwrap_or((0, 0))
}

fn result_json(name: &SessionName) -> String {
    let epic = name.epic();
    serde_json::json!({
        "state": "completed",
        "envelope": {
            "schema_version": 1,
            "id": "01J9Z3K7Q8R2W5X6Y7Z8A9B0C1",
            "type": "result",
            "work_unit_id": "wu01",
            "from": name.to_string(),
            "to": format!("{epic}.wu01.ctl.claude"),
            "causation_id": null,
            "correlation_id": epic.to_string(),
            "created_at_unix_ms": 1,
            "expires_at_unix_ms": null,
            "payload": {
                "outcome": "done",
                "branch": "wu01/a1",
                "head_sha": "0123456789abcdef0123456789abcdef01234567",
                "criteria": [],
                "usage": {"input_tokens": 1, "output_tokens": 2}
            }
        }
    })
    .to_string()
}

/// The fake vendor got the tier and the handed-over token, and none of the launcher's
/// secrets or directories.
fn assert_vendor_saw_only_its_allowlist(harness: &Harness, name: &SessionName, awaitable: &str) {
    let tier = fs::read_to_string(harness.marker(name, ".tier")).unwrap();
    assert_eq!(tier, "t1", "the vendor did not receive the tier");
    let vendor_env = fs::read_to_string(harness.marker(name, ".env")).unwrap();
    assert!(!vendor_env.contains(SECRET) && !vendor_env.contains(awaitable));
    assert!(!vendor_env.contains("ZMX_DIR=") && !vendor_env.contains("TYCHO_AGENT_DIR="));
    assert!(
        vendor_env
            .lines()
            .any(|line| line == format!("{CLAUDE_TOKEN_ENV}={TEST_TOKEN}")),
        "the vendor did not receive the handed-over token"
    );
    assert!(!vendor_env.contains("TYCHO_CREDENTIAL_SOCKET"));
    println!("evidence: the vendor's environment holds {CLAUDE_TOKEN_ENV} from the hand-off");
    for name in CHILD_ENVIRONMENT_NAMES {
        assert!(
            vendor_env
                .lines()
                .any(|line| line.starts_with(&format!("{name}="))),
            "the vendor has no {name}"
        );
    }
    assert!(
        !vendor_env.contains(&format!("{PLAN_ENV}=")),
        "the sandbox plan reached the vendor"
    );
    let admin = fs::read_to_string(harness.marker(name, ".admin")).unwrap();
    let proxy = fs::read_to_string(harness.marker(name, ".proxy")).unwrap();
    println!(
        "evidence: from inside the session the core's admin port is {}, the proxy {}",
        admin.trim(),
        proxy.trim()
    );
    assert_eq!(
        admin.trim(),
        "refused",
        "the vendor reached the core's admin port"
    );
    assert_eq!(proxy.trim(), "open", "the vendor could not reach its proxy");
}

/// The test token is in no file under the agent directory, the saved scrollback, `zmx list`
/// or the launcher's command line, and the hand-off socket is gone.
fn assert_token_nowhere(harness: &Harness, name: &SessionName, launcher_pid: u32) {
    let mut stack = vec![harness.dirs.socket_dir.clone()];
    let mut examined = 0_u32;
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                stack.push(path);
            } else if metadata.is_file() {
                examined = examined.saturating_add(1);
                let bytes = fs::read(&path).unwrap();
                assert!(
                    !String::from_utf8_lossy(&bytes).contains(TEST_TOKEN),
                    "{} holds the token",
                    path.display()
                );
            } else {
                assert!(
                    path.extension().is_none_or(|extension| extension != "cred"),
                    "the hand-off socket {} outlived the spawn",
                    path.display()
                );
            }
        }
    }
    assert!(examined >= 5, "only {examined} files examined");
    let scrollback = save_scrollback(&harness.zmx, &harness.config.home, name).unwrap();
    let text = fs::read_to_string(&scrollback).unwrap();
    let joined: String = text.chars().filter(|c| *c != '\n' && *c != '\r').collect();
    assert!(
        !joined.contains(TEST_TOKEN),
        "the token reached the scrollback"
    );
    let list = format!("{:?}", harness.zmx.list().unwrap());
    assert!(!list.contains(TEST_TOKEN));
    if let tycho::process::ProcessFacts::Running(facts) =
        tycho::process::process_facts(launcher_pid)
    {
        assert!(!facts.command.contains(TEST_TOKEN));
    }
    println!(
        "evidence: the token is in none of {examined} agent-directory files, the scrollback, zmx list or the launcher's argv"
    );
}

/// The saved scrollback, joined across wrapped lines, holds the typed command but no secret.
fn assert_scrollback_without_secret(harness: &Harness, name: &SessionName) {
    let scrollback = save_scrollback(&harness.zmx, &harness.config.home, name).unwrap();
    let text = fs::read_to_string(&scrollback).unwrap();
    // The terminal wraps long lines; joined, a wrapped secret would still be found.
    let joined: String = text.chars().filter(|c| *c != '\n' && *c != '\r').collect();
    assert!(scrollback.starts_with(&harness.config.home));
    assert!(joined.contains("launch --spec"), "{text}");
    assert!(
        !joined.contains(SECRET),
        "the session secret reached the scrollback"
    );
    assert!(
        !harness.dirs.spec_path(name).exists(),
        "the spec outlived the launcher's read"
    );
    println!(
        "evidence: scrollback saved to {} ({} bytes) without the secret; spec removed",
        scrollback.display(),
        text.len()
    );
}

#[test]
#[ignore = "starts real processes; run with mise run launcher-tests"]
fn launch_spools_resolves_and_ends_its_session() {
    let mut harness = Harness::new("ok");
    let core_ports = harness.config.ports;
    let name = harness.name("ok");
    let key = format!("{name}.await");
    let awaitable = start_wait(core_ports, &key);
    let files = harness.files(&name);
    let outcome_spawn = harness.spawn(&name, &awaitable, "12", &result_json(&name));
    let SpawnOutcome::Spawned { pid } = outcome_spawn else {
        panic!("expected a spawn, got {outcome_spawn:?}");
    };
    let tycho::process::ProcessFacts::Running(launcher) = tycho::process::process_facts(pid) else {
        panic!("the launcher {pid} is not running");
    };
    println!("evidence: the launcher runs as {}", launcher.command);
    assert!(
        launcher
            .command
            .starts_with(&format!("{} launch", harness.launcher.display())),
        "the launcher did not start from the prefix: {}",
        launcher.command
    );
    let lease_seen = wait_until("the vendor looked for the lease", WAIT_LIMIT, || {
        fs::read_to_string(harness.marker(&name, ".lease-seen")).ok()
    });
    assert_eq!(
        lease_seen.trim(),
        "hidden",
        "the vendor's sandbox let it see the launcher's lease"
    );
    assert_lease_before_vendor(&harness, &name);
    assert_vendor_saw_only_its_allowlist(&harness, &name, &awaitable);
    assert_token_nowhere(&harness, &name, pid);
    let terminal = fs::read_to_string(harness.marker(&name, ".tty")).unwrap();
    println!(
        "evidence: the vendor's controlling terminal: {}",
        terminal.trim()
    );
    assert_eq!(terminal.trim(), "detached");
    let (count, last) = wait_until("two heartbeats arrived", WAIT_LIMIT, || {
        let (count, last) = heartbeats(core_ports, &name);
        (count >= 2).then_some((count, last))
    });
    println!("evidence: {count} heartbeats, last sequence {last}");
    assert_scrollback_without_secret(&harness, &name);
    let resolved = wait_until("awakeable resolved", WAIT_LIMIT, || {
        outcome(core_ports, &key)
    });
    println!(
        "evidence: outcome {}",
        resolved.chars().take(160).collect::<String>()
    );
    assert!(resolved.starts_with(RESOLVED_PREFIX), "{resolved}");
    assert!(resolved.contains(&name.to_string()));
    assert!(files.spool.with_extension(ACKNOWLEDGED_SUFFIX).exists());
    wait_until("zmx session gone", WAIT_LIMIT, || {
        (harness.sessions_named(&name) == 0).then_some(())
    });
    let again = harness.spawn(&name, &awaitable, "1", "");
    assert!(
        matches!(again, SpawnOutcome::AdoptedEnded { .. }),
        "{again:?}"
    );
    assert_eq!(harness.sessions_named(&name), 0);
}

/// The lease was written before the vendor started: its start time precedes the vendor
/// record's, both taken by the launcher.
fn assert_lease_before_vendor(harness: &Harness, name: &SessionName) {
    let LeaseRead::Present { lease } = read_lease(&harness.dirs, name, current_uid()) else {
        panic!("no lease");
    };
    let record: VendorRecord =
        serde_json::from_slice(&fs::read(&harness.files(name).vendor).unwrap()).unwrap();
    println!(
        "evidence: lease started {} ms, vendor started {} ms",
        lease.started_unix_ms(),
        record.started_unix_ms
    );
    assert!(lease.started_unix_ms() <= record.started_unix_ms);
}

/// A heartbeat interval later the lease has not moved and is stale against that interval.
fn assert_lease_frozen(harness: &Harness, name: &SessionName) -> u64 {
    let frozen = harness.lease_heartbeat(name);
    thread::sleep(HEARTBEAT_INTERVAL.saturating_add(Duration::from_secs(3)));
    assert_eq!(
        harness.lease_heartbeat(name),
        frozen,
        "a dead launcher renewed its lease"
    );
    let interval_ms = u64::try_from(HEARTBEAT_INTERVAL.as_millis()).unwrap();
    let LeaseRead::Present { lease } = read_lease(&harness.dirs, name, current_uid()) else {
        panic!("no lease");
    };
    assert_eq!(
        lease.freshness(now_unix_ms(), interval_ms),
        Freshness::Stale
    );
    frozen
}

#[test]
#[ignore = "starts real processes; run with mise run launcher-tests"]
fn launcher_killed_before_its_trap_resolves_nothing() {
    let mut harness = Harness::new("kill");
    let core_ports = harness.config.ports;
    let name = harness.name("kill");
    let key = format!("{name}.await");
    let awaitable = start_wait(core_ports, &key);
    let files = harness.files(&name);
    assert!(matches!(
        harness.spawn(&name, &awaitable, "300", ""),
        SpawnOutcome::Spawned { .. }
    ));
    wait_until("vendor running", WAIT_LIMIT, || {
        files.vendor.exists().then_some(())
    });
    let LeaseRead::Present { lease } = read_lease(&harness.dirs, &name, current_uid()) else {
        panic!("no lease");
    };
    let status = Command::new("/bin/kill")
        .args(["-KILL", &lease.pid().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    println!("evidence: SIGKILL to launcher pid {}", lease.pid());
    let frozen = assert_lease_frozen(&harness, &name);
    assert_eq!(
        outcome(core_ports, &key),
        None,
        "something resolved the awakeable"
    );
    assert!(
        !files.spool.exists(),
        "a spool exists after a kill before the trap"
    );
    println!("evidence: nothing resolved, no spool, lease heartbeat frozen at {frozen}");
    let replay = harness.tycho(&["launch", "--replay", &files.spool.display().to_string()]);
    assert_eq!(
        replay.status.code(),
        Some(2),
        "replay of a missing spool must be refused"
    );
    assert!(String::from_utf8_lossy(&replay.stderr).contains("no spool"));
    let stale_after = Duration::from_millis(LEASE_FRESH_MS) + Duration::from_secs(2);
    thread::sleep(stale_after.saturating_sub(HEARTBEAT_INTERVAL + Duration::from_secs(3)));
    let again = harness.spawn(&name, &awaitable, "1", "");
    assert_eq!(again, SpawnOutcome::Requeue(RequeueReason::Stale));
    let report = kill_session(&harness.kill_request(&name, lease.pid()));
    println!("evidence: kill_session with the core as the agent user {report:?}");
    assert_eq!(
        report.launcher,
        KillVerdict::Refused(KillRefusal::NotListed)
    );
    assert_eq!(
        report.vendor,
        Some(KillVerdict::Refused(KillRefusal::CoreUid))
    );
    assert!(
        kill_orphan_vendor(&files),
        "the orphaned vendor was not running"
    );
    assert_eq!(harness.sessions_named(&name), 0);
}

#[test]
#[ignore = "starts real processes; run with mise run launcher-tests"]
fn restate_killed_between_vendor_exit_and_resolve() {
    let mut harness = Harness::new("restate");
    let core_ports = harness.config.ports;
    let name = harness.name("rs");
    let key = format!("{name}.await");
    let awaitable = start_wait(core_ports, &key);
    let files = harness.files(&name);
    assert!(matches!(
        harness.spawn(&name, &awaitable, "8", &result_json(&name)),
        SpawnOutcome::Spawned { .. }
    ));
    wait_until("first heartbeat", WAIT_LIMIT, || {
        (heartbeats(core_ports, &name).0 >= 1).then_some(())
    });
    let server = harness.core_pid(CoreRole::Restate);
    let status = Command::new("/bin/kill")
        .args(["-KILL", &server.to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    println!("evidence: SIGKILL to restate-server pid {server}");
    wait_until("restate unreachable", WAIT_LIMIT, || {
        matches!(
            health::probe(&http(), core_ports, CoreRole::Restate),
            Health::Unreachable(_)
        )
        .then_some(())
    });
    wait_until("result spooled while restate is down", WAIT_LIMIT, || {
        files.spool.exists().then_some(())
    });
    let during = harness.spawn(&name, &awaitable, "1", "");
    assert!(matches!(during, SpawnOutcome::Adopted { .. }), "{during:?}");
    assert!(harness.sessions_named(&name) <= 1);
    assert!(harness.tycho(&["watchdog", "once"]).status.success());
    let resolved = wait_until("awakeable resolved after the restart", WAIT_LIMIT, || {
        outcome(core_ports, &key)
    });
    println!(
        "evidence: outcome {}",
        resolved.chars().take(160).collect::<String>()
    );
    assert!(resolved.starts_with(RESOLVED_PREFIX) && !resolved.starts_with(REJECTED_PREFIX));
    assert!(files.spool.with_extension(ACKNOWLEDGED_SUFFIX).exists());
    wait_until("zmx session gone", WAIT_LIMIT, || {
        (harness.sessions_named(&name) == 0).then_some(())
    });
    let after = harness.spawn(&name, &awaitable, "1", "");
    assert!(
        matches!(after, SpawnOutcome::AdoptedEnded { .. }),
        "{after:?}"
    );
    assert_eq!(harness.sessions_named(&name), 0);
}

/// Claims a port slot for the home, held until the core is stopped; a slot whose ports
/// another process holds is skipped and named, and the test fails only when no slot is left.
fn claim_ports(home: &Path) -> PortClaim {
    let claim = CorePorts::claim(home).unwrap_or_else(|error| panic!("{error}"));
    println!("evidence: {claim}");
    claim
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

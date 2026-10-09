//! The core side of an agent session, one function per operation of the services' spawner port.
//!
//! It reads the lease, spawns a launcher under zmx in the agent socket directory, saves the
//! scrollback and sends a line; `kill` holds the fifth operation.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::thread;

use nix::unistd::Uid;
use tycho_types::envelope::ShortText;
use tycho_types::launcher::{AwaitableDigest, LauncherEnv};
use tycho_types::lease::{
    spawn_decision, Lease, RequeueReason, SpawnDecision, LEASE_FILE_MAX_BYTES,
};
use tycho_types::session::SessionName;

use crate::agent_files::{read_checked, write_new, write_new_mode};
use crate::config::{
    AgentDirs, AGENT_DIR_ENV, AGENT_DIR_MODE, POLL_INTERVAL, SCROLLBACK_DIR,
    SESSION_WAIT_POLLS_MAX, ZMX_ENV,
};
use crate::launch_spec::CORE_UID_ENV;
use crate::launcher::{
    check_tier, check_vendor, HeartbeatTarget, LaunchSpec, AGENT_TELEMETRY_ENV,
    HEARTBEAT_TARGET_ENV, LEASE_FRESH_MS, SPEC_SCHEMA_VERSION, TIER_FLAG,
    VENDOR_SANDBOX_SETTINGS_ENV,
};
use crate::private_dir;
use crate::process::now_unix_ms;
use crate::services::spawner::{LeaseRead, SpawnerError};
use crate::zmx::{presence, Presence, Zmx};

/// The launcher's whole environment besides its own contract; `env -i` drops the rest.
pub const LAUNCHER_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// Enabled, no unsandboxed retry, fail if unavailable, no excluded commands, and a network
/// allowlist that admits nothing until the adapter names the hosts a worker needs.
pub const CLAUDE_SANDBOX_SETTINGS: &str = r#"{"sandbox":{"enabled":true,"failIfUnavailable":true,"allowUnsandboxedCommands":false,"excludedCommands":[],"network":{"allowedDomains":[],"allowLocalBinding":false,"allowAllUnixSockets":false}}}"#;
pub const SCROLLBACK_MAX_BYTES: usize = 4 * 1024 * 1024;
const OTHER_BITS: u32 = 0o007;
const GROUP_WRITE_BIT: u32 = 0o020;
/// Only the core writes specs; the agent's group reads them.
pub const SPEC_DIR_MODE: u32 = 0o750;
/// Readable by the agent's group until the core removes it once the lease appears.
pub const SPEC_FILE_MODE: u32 = 0o640;
/// zmx appends `; echo ZMX_TASK_COMPLETED:<4 hex>:$?` to the typed line.
const ZMX_TYPED_SUFFIX_BYTES: usize = "; echo ZMX_TASK_COMPLETED:0000:$?".len();

fn transient(error: impl fmt::Display) -> SpawnerError {
    SpawnerError::Transient(error.to_string())
}

/// What `spawn_session` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnOutcome {
    Spawned {
        pid: u32,
    },
    /// A fresh lease for this name and awaitable: the launcher's recorded pid.
    Adopted {
        pid: u32,
    },
    /// This spawn's launcher ended after its result was acknowledged: await the awaitable.
    AdoptedEnded {
        pid: u32,
    },
    /// No pid from the lease is killed; the caller re-queues under a new name.
    Requeue(RequeueReason),
    /// zmx lists the name without a lease; `zmx run` would type into that session.
    NameTaken(Presence),
    Unrecognised(String),
}

/// Reads the lease only as a regular file of the agent user within the size cap.
#[must_use]
pub fn read_lease(dirs: &AgentDirs, session: &SessionName, agent_uid: u32) -> LeaseRead {
    let path = dirs.lease_path(session);
    match read_checked(&path, LEASE_FILE_MAX_BYTES, Some(agent_uid)) {
        Ok(None) => LeaseRead::Absent,
        Ok(Some(bytes)) => Lease::parse(&bytes).map_or_else(
            |error| LeaseRead::Unreadable {
                reason: error.to_string(),
            },
            |lease| LeaseRead::Present { lease },
        ),
        Err(error) => LeaseRead::Unreadable {
            reason: format!("{}: {error}", path.display()),
        },
    }
}

/// Maps the lease decision; only `Spawn` lets the caller go on to start a session.
#[must_use]
pub fn outcome_for(decision: SpawnDecision, lease: Option<&Lease>) -> Option<SpawnOutcome> {
    match (decision, lease) {
        (SpawnDecision::Spawn, _) => None,
        (SpawnDecision::Adopt, Some(lease)) => Some(SpawnOutcome::Adopted { pid: lease.pid() }),
        (SpawnDecision::AdoptEnded, Some(lease)) => {
            Some(SpawnOutcome::AdoptedEnded { pid: lease.pid() })
        }
        (SpawnDecision::Adopt | SpawnDecision::AdoptEnded, None) => Some(
            SpawnOutcome::Unrecognised("adopt without a lease".to_string()),
        ),
        (SpawnDecision::Requeue(reason), _) => Some(SpawnOutcome::Requeue(reason)),
    }
}

/// One launcher to start: the agent zmx, its directories, and what the launcher is handed.
#[derive(Debug, Clone, Copy)]
pub struct SpawnRequest<'a> {
    pub zmx: &'a Zmx,
    pub dirs: &'a AgentDirs,
    pub tycho: &'a Path,
    pub home: &'a Path,
    pub env: &'a LauncherEnv,
    pub heartbeat: HeartbeatTarget,
    pub vendor: &'a [String],
    pub agent_uid: u32,
    pub tier: Option<&'a str>,
}

/// Splits a trailing `--tier <tier>` off the port's argv: the vendor command and the tier.
#[must_use]
pub fn split_tier(argv: &[String]) -> (&[String], Option<&str>) {
    match argv {
        [vendor @ .., flag, tier] if flag == TIER_FLAG => (vendor, Some(tier.as_str())),
        vendor => (vendor, None),
    }
}

/// Adopts, re-queues or spawns by the lease, then checks zmx before `run`.
pub fn spawn_session(request: &SpawnRequest<'_>) -> Result<SpawnOutcome, SpawnerError> {
    let session = &request.env.session_name;
    let lease = match read_lease(request.dirs, session, request.agent_uid) {
        LeaseRead::Absent => None,
        LeaseRead::Present { lease } => Some(lease),
        LeaseRead::Unreadable { reason } => return Ok(SpawnOutcome::Unrecognised(reason)),
    };
    let decision = spawn_decision(
        lease.as_ref(),
        session,
        &request.env.awaitable_id,
        now_unix_ms(),
        LEASE_FRESH_MS,
    );
    if let Some(outcome) = outcome_for(decision, lease.as_ref()) {
        return Ok(outcome);
    }
    let entries = request.zmx.list().map_err(transient)?;
    match presence(&entries, &session.to_string()) {
        Presence::Absent => {}
        Presence::Unrecognised => return Ok(SpawnOutcome::Unrecognised("zmx list".to_string())),
        taken => return Ok(SpawnOutcome::NameTaken(taken)),
    }
    start_detached(request).map(|pid| SpawnOutcome::Spawned { pid })
}

/// Creates the agent directories group-shared, refusing any another user can reach.
pub fn ensure_agent_dirs(dirs: &AgentDirs) -> Result<(), SpawnerError> {
    let current = Uid::current().as_raw();
    for (dir, mode) in [
        (dirs.socket_dir.clone(), AGENT_DIR_MODE),
        (dirs.lease_dir(), AGENT_DIR_MODE),
        (dirs.spool_root(), AGENT_DIR_MODE),
        (dirs.spec_dir(), SPEC_DIR_MODE),
    ] {
        match fs::symlink_metadata(&dir) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => DirBuilder::new()
                .mode(mode)
                .create(&dir)
                .map_err(|error| transient(format!("{}: {error}", dir.display())))?,
            Err(error) => return Err(transient(error)),
        }
        let metadata = fs::symlink_metadata(&dir).map_err(transient)?;
        let group_write = mode & GROUP_WRITE_BIT == 0 && metadata.mode() & GROUP_WRITE_BIT != 0;
        let refused = !metadata.file_type().is_dir()
            || metadata.uid() != current
            || metadata.mode() & OTHER_BITS != 0
            || group_write;
        if refused {
            return Err(SpawnerError::Refused(format!(
                "{} is not a directory of this user closed to others",
                dir.display()
            )));
        }
    }
    Ok(())
}

/// A pty in canonical mode keeps 1024 bytes of one typed line; the rest is lost.
pub const TYPED_LINE_MAX_BYTES: usize = 1000;

/// Everything the launcher is handed: its contract, the agent directories, the heartbeat
/// target, the sandbox settings, telemetry off, and the vendor command.
pub fn launch_spec(request: &SpawnRequest<'_>) -> Result<LaunchSpec, SpawnerError> {
    check_vendor(request.vendor).map_err(|error| SpawnerError::Refused(error.to_string()))?;
    let mut environment: BTreeMap<String, String> = request
        .env
        .to_pairs()
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect();
    let fixed = [
        (AGENT_DIR_ENV, request.dirs.socket_dir.display().to_string()),
        (ZMX_ENV, request.zmx.binary().display().to_string()),
        ("ZMX_DIR", request.zmx.socket_dir().to_string()),
        (
            HEARTBEAT_TARGET_ENV,
            request.heartbeat.as_wire().to_string(),
        ),
        (
            VENDOR_SANDBOX_SETTINGS_ENV,
            CLAUDE_SANDBOX_SETTINGS.to_string(),
        ),
    ];
    let telemetry = AGENT_TELEMETRY_ENV.map(|(name, value)| (name, value.to_string()));
    for (name, value) in fixed.into_iter().chain(telemetry) {
        environment.insert(name.to_string(), value);
    }
    let spec = LaunchSpec {
        schema_version: SPEC_SCHEMA_VERSION,
        environment,
        vendor: request.vendor.to_vec(),
    };
    spec.settings()
        .map_err(|error| SpawnerError::Refused(error.to_string()))?;
    Ok(spec)
}

/// The words zmx types: `exec env -i HOME PATH <tycho> launch --spec <file>`, bounded.
pub fn typed_words(request: &SpawnRequest<'_>, spec: &Path) -> Result<Vec<String>, SpawnerError> {
    let mut words = vec![
        "exec".to_string(),
        "/usr/bin/env".to_string(),
        "-i".to_string(),
        format!("HOME={}", request.home.display()),
        format!("PATH={LAUNCHER_PATH}"),
        format!("{CORE_UID_ENV}={}", Uid::current().as_raw()),
        request.tycho.display().to_string(),
        "launch".to_string(),
        "--spec".to_string(),
        spec.display().to_string(),
    ];
    if let Some(tier) = request.tier {
        check_tier(tier).map_err(|error| SpawnerError::Refused(error.to_string()))?;
        words.push(TIER_FLAG.to_string());
        words.push(tier.to_string());
    }
    let typed = words
        .iter()
        .map(|word| word.len().saturating_add(3))
        .sum::<usize>()
        .saturating_add(ZMX_TYPED_SUFFIX_BYTES);
    if typed > TYPED_LINE_MAX_BYTES {
        return Err(SpawnerError::Refused(format!(
            "the typed command is {typed} bytes; maximum is {TYPED_LINE_MAX_BYTES}"
        )));
    }
    Ok(words)
}

/// Writes the spec privately, runs the launcher detached and returns its pid from `zmx list`.
pub fn start_detached(request: &SpawnRequest<'_>) -> Result<u32, SpawnerError> {
    let spec = launch_spec(request)?;
    ensure_agent_dirs(request.dirs)?;
    let spec_path = request.dirs.spec_path(&request.env.session_name);
    let words = typed_words(request, &spec_path)?;
    write_spec(&spec_path, &spec)?;
    let name = request.env.session_name.to_string();
    if let Err(error) = request.zmx.run_words(&name, &words) {
        // No launcher will read the spec, and it carries the session secret.
        drop(fs::remove_file(&spec_path));
        return Err(transient(error));
    }
    let pid = wait_for_pid(request, &name);
    remove_spec_after_lease(request, &spec_path);
    pid
}

/// The launcher writes its lease only after reading the spec, so the core removes the spec
/// then; across users the launcher cannot remove a file in a directory only the core writes.
fn remove_spec_after_lease(request: &SpawnRequest<'_>, spec_path: &Path) {
    for _ in 0..SESSION_WAIT_POLLS_MAX {
        if !spec_path.exists() || matches!(own_lease(request), Some(true)) {
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }
    drop(fs::remove_file(spec_path));
}

/// Whether the lease on disk is this spawn's: `None` when there is none.
fn own_lease(request: &SpawnRequest<'_>) -> Option<bool> {
    match read_lease(request.dirs, &request.env.session_name, request.agent_uid) {
        LeaseRead::Present { lease } => {
            Some(*lease.awaitable_sha256() == AwaitableDigest::of(&request.env.awaitable_id))
        }
        LeaseRead::Absent | LeaseRead::Unreadable { .. } => None,
    }
}

/// Unlinks whatever sits at the path, which never follows a symlink, then creates the file
/// new; a file planted between the two makes the create fail.
fn write_spec(path: &Path, spec: &LaunchSpec) -> Result<(), SpawnerError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(transient(error)),
    }
    let bytes = serde_json::to_vec(spec).map_err(transient)?;
    write_new_mode(path, &bytes, SPEC_FILE_MODE)
        .map_err(|error| SpawnerError::Refused(format!("{}: {error}", path.display())))
}

fn wait_for_pid(request: &SpawnRequest<'_>, name: &str) -> Result<u32, SpawnerError> {
    for _ in 0..SESSION_WAIT_POLLS_MAX {
        let entries = request.zmx.list().map_err(transient)?;
        match presence(&entries, name) {
            Presence::Running { pid, .. } => return Ok(pid),
            Presence::Ended { pid } => return ended_launcher(request, pid),
            Presence::Absent => {}
            Presence::Unrecognised => return Err(transient("zmx list is unrecognised")),
        }
        if let LeaseRead::Present { lease } =
            read_lease(request.dirs, &request.env.session_name, request.agent_uid)
        {
            if *lease.awaitable_sha256() == AwaitableDigest::of(&request.env.awaitable_id) {
                return Ok(lease.pid());
            }
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(transient(format!("{name} did not appear in zmx list")))
}

/// A launcher that already ended counts as spawned only if it wrote this awaitable's lease.
fn ended_launcher(request: &SpawnRequest<'_>, pid: u32) -> Result<u32, SpawnerError> {
    match read_lease(request.dirs, &request.env.session_name, request.agent_uid) {
        LeaseRead::Present { lease }
            if *lease.awaitable_sha256() == AwaitableDigest::of(&request.env.awaitable_id) =>
        {
            Ok(lease.pid())
        }
        _ => Err(SpawnerError::Refused(format!(
            "launcher pid {pid} ended without writing its lease"
        ))),
    }
}

/// Saves the scrollback under the core home; more than the bound is an error.
pub fn save_scrollback(
    zmx: &Zmx,
    core_home: &Path,
    session: &SessionName,
) -> Result<PathBuf, SpawnerError> {
    let dir = core_home.join(SCROLLBACK_DIR);
    private_dir::ensure(&[core_home.to_path_buf(), dir.clone()]).map_err(transient)?;
    let text = zmx
        .history(&session.to_string(), SCROLLBACK_MAX_BYTES)
        .map_err(transient)?;
    let path = dir.join(format!("{session}.{}.txt", now_unix_ms()));
    write_new(&path, text.as_bytes()).map_err(transient)?;
    Ok(path)
}

/// Types one line into the session; zmx delivers it to the pty's stdin.
pub fn send_line(zmx: &Zmx, session: &SessionName, text: &ShortText) -> Result<(), SpawnerError> {
    zmx.send(&session.to_string(), text.as_str())
        .map_err(transient)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_files::{current_uid, write_durable};
    use tycho_types::launcher::AwaitableId;
    use tycho_types::launcher::{ENV_AWAITABLE_ID, ENV_SESSION_NAME, ENV_SESSION_SECRET};

    const NAME: &str = "cf7a.wu03.wrk.claude.a1f3";

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn env() -> LauncherEnv {
        LauncherEnv::from_map(&BTreeMap::from([
            (ENV_AWAITABLE_ID.to_string(), "sign_1abc".to_string()),
            (ENV_SESSION_SECRET.to_string(), SECRET.to_string()),
            (ENV_SESSION_NAME.to_string(), NAME.to_string()),
        ]))
        .unwrap()
    }

    fn lease(heartbeat: u64) -> Lease {
        Lease::new(
            SessionName::parse(NAME).unwrap(),
            4242,
            AwaitableDigest::of(&AwaitableId::parse("sign_1abc").unwrap()),
            heartbeat,
            heartbeat,
        )
        .unwrap()
    }

    #[test]
    fn each_decision_maps_to_an_outcome() {
        let fresh = lease(1);
        assert_eq!(outcome_for(SpawnDecision::Spawn, None), None);
        assert_eq!(
            outcome_for(SpawnDecision::Adopt, Some(&fresh)),
            Some(SpawnOutcome::Adopted { pid: 4242 })
        );
        assert_eq!(
            outcome_for(SpawnDecision::AdoptEnded, Some(&fresh)),
            Some(SpawnOutcome::AdoptedEnded { pid: 4242 })
        );
        assert!(matches!(
            outcome_for(SpawnDecision::Adopt, None),
            Some(SpawnOutcome::Unrecognised(_))
        ));
        for reason in [
            RequeueReason::Stale,
            RequeueReason::Ahead,
            RequeueReason::OtherSession,
            RequeueReason::OtherAwaitable,
        ] {
            assert_eq!(
                outcome_for(SpawnDecision::Requeue(reason), Some(&fresh)),
                Some(SpawnOutcome::Requeue(reason))
            );
        }
    }

    fn scratch(test: &str) -> AgentDirs {
        let dir = std::env::temp_dir().join(format!("tycho-spawn-{test}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        AgentDirs::new(dir).unwrap()
    }

    #[test]
    fn a_lease_on_disk_decides_before_zmx_is_asked() {
        let dirs = scratch("decide");
        ensure_agent_dirs(&dirs).unwrap();
        let zmx = Zmx::agent(Path::new("/nonexistent/zmx"), &dirs.socket_dir);
        let env = env();
        let vendor = ["/bin/true".to_string()];
        let request = SpawnRequest {
            zmx: &zmx,
            dirs: &dirs,
            tycho: Path::new("/nonexistent/tycho"),
            home: Path::new("/nonexistent"),
            env: &env,
            heartbeat: HeartbeatTarget::Session,
            vendor: &vendor,
            agent_uid: current_uid(),
            tier: Some("t2"),
        };
        let session = SessionName::parse(NAME).unwrap();
        write_durable(
            &dirs.lease_path(&session),
            &lease(now_unix_ms()).to_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(
            spawn_session(&request),
            Ok(SpawnOutcome::Adopted { pid: 4242 })
        );
        write_durable(&dirs.lease_path(&session), &lease(1).to_bytes().unwrap()).unwrap();
        assert_eq!(
            spawn_session(&request),
            Ok(SpawnOutcome::Requeue(RequeueReason::Stale))
        );
        fs::write(dirs.lease_path(&session), "{").unwrap();
        assert!(matches!(
            spawn_session(&request),
            Ok(SpawnOutcome::Unrecognised(_))
        ));
        fs::remove_file(dirs.lease_path(&session)).unwrap();
        assert!(matches!(
            spawn_session(&request),
            Err(SpawnerError::Transient(_))
        ));
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    fn shared_request<'a>(
        dirs: &'a AgentDirs,
        zmx: &'a Zmx,
        env: &'a LauncherEnv,
        vendor: &'a [String],
    ) -> SpawnRequest<'a> {
        SpawnRequest {
            zmx,
            dirs,
            tycho: Path::new("/opt/tycho"),
            home: Path::new("/Users/agent"),
            env,
            heartbeat: HeartbeatTarget::Session,
            vendor,
            agent_uid: current_uid(),
            tier: Some("t2"),
        }
    }

    #[test]
    fn the_spec_carries_the_contract_and_the_sandbox() {
        let dirs = AgentDirs::new(PathBuf::from("/Users/Shared/tycho-agent-zmx")).unwrap();
        let zmx = Zmx::agent(Path::new("/opt/zmx"), &dirs.socket_dir);
        let env = env();
        let vendor = ["/bin/sh".to_string(), "a b".to_string()];
        let request = shared_request(&dirs, &zmx, &env, &vendor);
        let spec = launch_spec(&request).unwrap();
        for (name, value) in [
            ("TYCHO_AWAITABLE_ID", "sign_1abc"),
            ("TYCHO_SESSION_NAME", NAME),
            ("TYCHO_AGENT_DIR", "/Users/Shared/tycho-agent-zmx"),
            ("ZMX_DIR", "/Users/Shared/tycho-agent-zmx"),
            ("DISABLE_TELEMETRY", "1"),
            ("ENTIRE_TELEMETRY_OPTOUT", "1"),
        ] {
            assert_eq!(
                spec.environment.get(name).map(String::as_str),
                Some(value),
                "{name}"
            );
        }
        assert!(spec.environment.contains_key("TYCHO_SESSION_SECRET"));
        assert_eq!(spec.vendor, vendor);
        let settings: serde_json::Value = serde_json::from_str(CLAUDE_SANDBOX_SETTINGS).unwrap();
        assert_eq!(settings["sandbox"]["allowUnsandboxedCommands"], false);
        assert_eq!(settings["sandbox"]["failIfUnavailable"], true);
        let empty: [String; 0] = [];
        let refused = SpawnRequest {
            vendor: &empty,
            ..request
        };
        assert!(matches!(
            launch_spec(&refused),
            Err(SpawnerError::Refused(_))
        ));
    }

    #[test]
    fn the_typed_line_stays_short_carries_the_tier_and_never_the_secret() {
        let dirs = AgentDirs::new(PathBuf::from("/Users/Shared/tycho-agent-zmx")).unwrap();
        let zmx = Zmx::agent(Path::new("/opt/zmx"), &dirs.socket_dir);
        let env = env();
        let vendor = ["/bin/sh".to_string()];
        let request = shared_request(&dirs, &zmx, &env, &vendor);
        let words = typed_words(
            &request,
            Path::new("/Users/Shared/tycho-agent-zmx/specs/x.json"),
        )
        .unwrap();
        assert_eq!(&words[..3], ["exec", "/usr/bin/env", "-i"]);
        assert_eq!(&words[words.len() - 2..], ["--tier", "t2"]);
        assert!(
            !words.iter().any(|word| word.contains(SECRET)),
            "the secret is never typed"
        );
        let bad_tier = SpawnRequest {
            tier: Some("t 3"),
            ..request
        };
        assert!(matches!(
            typed_words(&bad_tier, Path::new("/s")),
            Err(SpawnerError::Refused(_))
        ));
        let long_home = PathBuf::from(format!("/{}", "h".repeat(TYPED_LINE_MAX_BYTES)));
        let long = SpawnRequest {
            home: &long_home,
            ..request
        };
        assert!(matches!(
            typed_words(&long, Path::new("/s")),
            Err(SpawnerError::Refused(_))
        ));
        let argv = [
            "/bin/sh".to_string(),
            "--tier".to_string(),
            "t3".to_string(),
        ];
        assert_eq!(split_tier(&argv), (&argv[..1], Some("t3")));
        assert_eq!(split_tier(&argv[..1]), (&argv[..1], None));
    }

    #[test]
    fn the_zmx_suffix_counts_against_the_typed_line() {
        let dirs = AgentDirs::new(PathBuf::from("/a")).unwrap();
        let zmx = Zmx::agent(Path::new("/z"), &dirs.socket_dir);
        let env = env();
        let vendor = ["/bin/sh".to_string()];
        let request = SpawnRequest {
            tier: None,
            ..shared_request(&dirs, &zmx, &env, &vendor)
        };
        let base = typed_words(&request, Path::new("/s")).unwrap();
        let typed: usize = base.iter().map(|word| word.len() + 3).sum();
        let room = TYPED_LINE_MAX_BYTES - typed - ZMX_TYPED_SUFFIX_BYTES;
        // "/s" is two bytes; a path of `room + 2` bytes fills the line exactly.
        let fits = PathBuf::from(format!("/{}", "s".repeat(room + 1)));
        assert!(typed_words(&request, &fits).is_ok());
        let over = PathBuf::from(format!("/{}", "s".repeat(room + 2)));
        assert!(matches!(
            typed_words(&request, &over),
            Err(SpawnerError::Refused(_))
        ));
        assert!(base.iter().any(|word| word.starts_with("TYCHO_CORE_UID=")));
    }

    #[test]
    fn scrollback_over_its_cap_is_an_error_and_writes_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dirs = scratch("scrollback");
        fs::create_dir_all(&dirs.socket_dir).unwrap();
        let script = dirs.socket_dir.join("zmx-stand-in");
        let bytes = SCROLLBACK_MAX_BYTES + 1;
        fs::write(
            &script,
            format!("#!/bin/sh\nhead -c {bytes} /dev/zero | tr '\\0' x\n"),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let zmx = Zmx::agent(&script, &dirs.socket_dir);
        let home = dirs.socket_dir.join("home");
        let session = SessionName::parse(NAME).unwrap();
        assert!(save_scrollback(&zmx, &home, &session).is_err());
        let saved = fs::read_dir(home.join(SCROLLBACK_DIR)).map_or(0, Iterator::count);
        assert_eq!(saved, 0);
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn the_spec_directory_is_closed_to_group_writes() {
        use std::os::unix::fs::PermissionsExt;
        let dirs = scratch("spec-dir");
        ensure_agent_dirs(&dirs).unwrap();
        let mode = fs::metadata(dirs.spec_dir()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777 & !SPEC_DIR_MODE, 0, "{mode:o}");
        fs::set_permissions(dirs.spec_dir(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            ensure_agent_dirs(&dirs),
            Err(SpawnerError::Refused(_))
        ));
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_failed_zmx_run_removes_the_spec() {
        let dirs = scratch("run-fails");
        let zmx = Zmx::agent(Path::new("/usr/bin/false"), &dirs.socket_dir);
        let env = env();
        let vendor = ["/bin/true".to_string()];
        let request = shared_request(&dirs, &zmx, &env, &vendor);
        assert!(matches!(
            start_detached(&request),
            Err(SpawnerError::Transient(_))
        ));
        let spec = dirs.spec_path(&env.session_name);
        assert!(dirs.spec_dir().exists(), "the spec was never written");
        assert!(!spec.exists(), "the spec outlived a failed zmx run");
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }
}

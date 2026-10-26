//! The core side of an agent session, one function per operation of the services' spawner port.
//!
//! It reads the lease, spawns a launcher under zmx in the agent socket directory, saves the
//! scrollback and sends a line; `kill` holds the fifth operation.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;

use nix::fcntl::OFlag;
use nix::unistd::Uid;
use tycho_types::envelope::ShortText;
use tycho_types::launcher::{AwaitableDigest, LauncherEnv};
use tycho_types::lease::{
    LEASE_FILE_MAX_BYTES, Lease, RequeueReason, SpawnDecision, spawn_decision,
};
use tycho_types::session::SessionName;

use crate::agent_files::{read_checked, write_new, write_new_mode};
use crate::config::{
    AGENT_DIR_ENV, AGENT_DIR_MODE, AgentDirs, CorePorts, POLL_INTERVAL, SCROLLBACK_DIR,
    SESSION_WAIT_POLLS_MAX, ToolPrefix, ZMX_ENV,
};
use crate::config_store::PORT_OFFSET_ENV;
use crate::credential_handoff::{CREDENTIAL_SOCKET_ENV, HandoffServer, socket_path};
use crate::credentials::Credential;
use crate::launch_spec::CORE_UID_ENV;
use crate::launcher::{
    AGENT_TELEMETRY_ENV, HEARTBEAT_TARGET_ENV, HeartbeatTarget, LEASE_FRESH_MS, LaunchSpec,
    SPEC_SCHEMA_VERSION, TIER_FLAG, VENDOR_DIR_ENV, VENDOR_SANDBOX_SETTINGS_ENV,
    VENDOR_TERMINAL_ENV, VendorTerminal, check_tier, check_vendor,
};
use crate::private_dir;
use crate::process::now_unix_ms;
use crate::sandbox::{Access, Grant};
use crate::services::spawner::{LeaseRead, SpawnerError};
use crate::vendors::worker::{WORKER_COMMAND, WorkerArgs};
use crate::zmx::{Presence, Zmx, prepare_shared_log, presence};

/// Claude's own sandbox off, passed with `--settings`.
///
/// The station's sandbox, which the session leader applies to the vendor's whole process
/// tree, is the only layer. A vendor sandbox nested inside it cannot apply its profile, and
/// Claude then reruns the refused command outside its sandbox. Every Claude start and resume
/// also passes `--setting-sources=`, so no user, project or local settings file can turn it
/// back on.
pub const CLAUDE_SANDBOX_OFF: &str = r#"{"sandbox":{"enabled":false}}"#;
pub const SCROLLBACK_MAX_BYTES: usize = 4 * 1024 * 1024;
const OTHER_BITS: u32 = 0o007;
const GROUP_WRITE_BIT: u32 = 0o020;
/// The shared directory's group can write it, so it is sticky: the agent cannot rename or
/// remove the core's entries there.
const STICKY_BIT: u32 = 0o1000;
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
    pub terminal: VendorTerminal,
    /// The vendor's working directory; `None` keeps the zmx session's.
    pub vendor_dir: Option<&'a Path>,
    /// The ports of the core the launcher reports to.
    pub ports: CorePorts,
    /// Where the launcher's `PATH` and the vendor's mise variables point.
    pub tool_prefix: &'a ToolPrefix,
    /// The vendor credential the spawn step hands the launcher over the session's socket;
    /// `None` starts the vendor with no credential from the core.
    pub credential: Option<&'a Credential>,
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
    // A launcher from anywhere but the prefix would run a binary nothing checked.
    let prefix_tycho = request.tool_prefix.tycho();
    if request.tycho != prefix_tycho {
        return Err(SpawnerError::Refused(format!(
            "the launcher {} is not the tool prefix's {}",
            request.tycho.display(),
            prefix_tycho.display()
        )));
    }
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

/// Sets a directory this call just created to its exact mode on a descriptor opened without
/// following a link: `mkdir` applies the umask and, on macOS, drops the sticky bit.
fn set_created_mode(dir: &Path, mode: u32) -> Result<(), SpawnerError> {
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY | OFlag::O_NONBLOCK).bits())
        .open(dir)
        .and_then(|directory| {
            directory.set_permissions(Permissions::from_mode(mode))?;
            Ok(directory)
        });
    opened
        .map(drop)
        .map_err(|error| transient(format!("{}: {error}", dir.display())))
}

/// Creates the agent directories group-shared, refusing any another user can reach, then
/// prepares the zmx log there.
pub fn ensure_agent_dirs(dirs: &AgentDirs) -> Result<(), SpawnerError> {
    let current = Uid::current().as_raw();
    for (dir, mode) in [
        (dirs.socket_dir.clone(), AGENT_DIR_MODE | STICKY_BIT),
        (dirs.lease_dir(), AGENT_DIR_MODE),
        (dirs.spool_root(), AGENT_DIR_MODE),
        (dirs.spec_dir(), SPEC_DIR_MODE),
    ] {
        match fs::symlink_metadata(&dir) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                DirBuilder::new()
                    .mode(mode & 0o777)
                    .create(&dir)
                    .map_err(|error| transient(format!("{}: {error}", dir.display())))?;
                set_created_mode(&dir, mode)?;
            }
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
    prepare_shared_log(&dirs.socket_dir)
        .map_err(|refusal| SpawnerError::Refused(refusal.to_string()))
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
        (VENDOR_SANDBOX_SETTINGS_ENV, CLAUDE_SANDBOX_OFF.to_string()),
    ];
    let telemetry = AGENT_TELEMETRY_ENV.map(|(name, value)| (name, value.to_string()));
    for (name, value) in fixed.into_iter().chain(telemetry) {
        environment.insert(name.to_string(), value);
    }
    if request.terminal != VendorTerminal::Files {
        environment.insert(
            VENDOR_TERMINAL_ENV.to_string(),
            request.terminal.as_wire().to_string(),
        );
    }
    if let Some(dir) = request.vendor_dir {
        environment.insert(VENDOR_DIR_ENV.to_string(), dir.display().to_string());
    }
    if !request.ports.offset.is_production() {
        environment.insert(
            PORT_OFFSET_ENV.to_string(),
            request.ports.offset.to_string(),
        );
    }
    if request.credential.is_some() {
        let socket = socket_path(request.dirs, &request.env.session_name);
        environment.insert(
            CREDENTIAL_SOCKET_ENV.to_string(),
            socket.display().to_string(),
        );
    }
    let spec = LaunchSpec {
        schema_version: SPEC_SCHEMA_VERSION,
        environment,
        vendor: request.vendor.to_vec(),
        grants: sandbox_grants(request)?,
    };
    spec.settings()
        .map_err(|error| SpawnerError::Refused(error.to_string()))?;
    Ok(spec)
}

fn grant(path: &Path, access: Access) -> Grant {
    Grant {
        path: path.to_path_buf(),
        access,
    }
}

/// Read on the directory a linked executable points into, as a scratch prefix links the
/// developer's installs; `None` for a file that is not a link.
fn link_target_grant(executable: &Path) -> Option<Grant> {
    let target = fs::read_link(executable).ok()?;
    let dir = target.parent().filter(|dir| dir.is_absolute())?;
    Some(grant(dir, Access::Read))
}

/// Read on an executable's install directory (or its own directory) and on its link's.
fn executable_grants(executable: &Path, install_dir: Option<&Path>) -> Vec<Grant> {
    install_dir
        .or_else(|| executable.parent())
        .map(|dir| grant(dir, Access::Read))
        .into_iter()
        .chain(link_target_grant(executable))
        .collect()
}

/// The arguments of a worker command: a vendor command that runs the prefix's `tycho` or
/// names the worker command is one, and arguments that do not parse are a refusal, never a
/// session without its worktree; any other command is not a worker's.
fn worker_args(request: &SpawnRequest<'_>) -> Result<Option<WorkerArgs>, SpawnerError> {
    let Some((program, rest)) = request.vendor.split_first() else {
        return Ok(None);
    };
    let command = rest.first().map(String::as_str);
    let runs_tycho = Path::new(program) == request.tool_prefix.tycho();
    if !runs_tycho && command != Some(WORKER_COMMAND) {
        return Ok(None);
    }
    if command != Some(WORKER_COMMAND) {
        return Err(SpawnerError::Refused(format!(
            "{program} runs as a vendor only as {WORKER_COMMAND}, not {command:?}"
        )));
    }
    WorkerArgs::parse(rest.get(1..).unwrap_or_default())
        .map(Some)
        .map_err(|error| SpawnerError::Refused(format!("the worker's arguments: {error}")))
}

/// The session's own paths in the vendor's sandbox; the launcher adds the rest.
///
/// The prefix's `tycho` and the session vendor's install to read, a worker's brief and
/// binary to read, and its worktree or the vendor's working directory to read and write.
pub fn sandbox_grants(request: &SpawnRequest<'_>) -> Result<Vec<Grant>, SpawnerError> {
    let prefix = request.tool_prefix;
    let mut grants = vec![grant(&prefix.tycho(), Access::Read)];
    grants.extend(link_target_grant(&prefix.tycho()));
    let vendor = request.env.session_name.vendor().as_str();
    if let Some(executable) = prefix.tool(vendor) {
        grants.extend(executable_grants(
            executable,
            prefix.install_dir(vendor).as_deref(),
        ));
    }
    if let Some(dir) = request.vendor_dir {
        grants.push(grant(dir, Access::ReadWrite));
    }
    if let Some(args) = worker_args(request)? {
        grants.push(grant(&args.worktree, Access::ReadWrite));
        grants.push(grant(&args.brief, Access::Read));
        grants.extend(executable_grants(&args.binary, None));
    }
    let mut seen = Vec::new();
    grants.retain(|entry| {
        let fresh = !seen.contains(entry);
        if fresh {
            seen.push(entry.clone());
        }
        fresh
    });
    Ok(grants)
}

/// The words zmx types: `exec env -i HOME PATH MISE_* <tycho> launch --spec <file>`, bounded.
///
/// The launcher's whole environment besides its own contract; `env -i` drops the rest. `PATH`
/// holds the prefix's `bin` and the recorded install directories, and the mise variables keep
/// any mise a session starts on the prefix's pins, offline.
pub fn typed_words(request: &SpawnRequest<'_>, spec: &Path) -> Result<Vec<String>, SpawnerError> {
    let mut words = vec![
        "exec".to_string(),
        "/usr/bin/env".to_string(),
        "-i".to_string(),
        format!("HOME={}", request.home.display()),
        format!("PATH={}", request.tool_prefix.path()),
    ];
    words.extend(
        request
            .tool_prefix
            .mise_environment()
            .iter()
            .map(|(name, value)| format!("{name}={value}")),
    );
    words.extend([
        format!("{CORE_UID_ENV}={}", Uid::current().as_raw()),
        request.tycho.display().to_string(),
        "launch".to_string(),
        "--spec".to_string(),
        spec.display().to_string(),
    ]);
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

/// Writes the spec privately, serves the credential, runs the launcher detached and returns
/// its pid from `zmx list`.
pub fn start_detached(request: &SpawnRequest<'_>) -> Result<u32, SpawnerError> {
    let spec = launch_spec(request)?;
    ensure_agent_dirs(request.dirs)?;
    let spec_path = request.dirs.spec_path(&request.env.session_name);
    let words = typed_words(request, &spec_path)?;
    let handoff = start_handoff(request)?;
    write_spec(&spec_path, &spec)?;
    let name = request.env.session_name.to_string();
    if let Err(error) = request.zmx.run_words(&name, &words) {
        // No launcher will read the spec, and it carries the session secret.
        drop(fs::remove_file(&spec_path));
        return Err(transient(error));
    }
    let found = wait_for_pid(request, &name);
    if let (Some(server), Ok(Found::Listed(pid))) = (handoff.as_ref(), found.as_ref()) {
        server.bind_launcher(*pid);
    }
    remove_spec_after_lease(request, &spec_path, handoff.as_ref());
    // A launcher that got no credential refuses to start its vendor and reports that as its
    // exit state, so the outcome here only closes the socket.
    if let Some(server) = handoff {
        drop(server.finish());
    }
    found.map(Found::pid)
}

/// Binds the session's hand-off socket before the launcher can look for it.
fn start_handoff(request: &SpawnRequest<'_>) -> Result<Option<HandoffServer>, SpawnerError> {
    request
        .credential
        .map(|credential| {
            HandoffServer::start(
                request.dirs,
                request.agent_uid,
                &request.env.session_name,
                &request.env.session_secret,
                credential.clone(),
            )
            .map_err(|error| SpawnerError::Refused(error.to_string()))
        })
        .transpose()
}

/// The launcher asks for its credential before it writes its lease and writes the lease only
/// after reading the spec, so the core removes the spec and closes the hand-off then; across
/// users the launcher cannot remove a file in a directory only the core writes.
fn remove_spec_after_lease(
    request: &SpawnRequest<'_>,
    spec_path: &Path,
    handoff: Option<&HandoffServer>,
) {
    let handed = || handoff.is_none_or(HandoffServer::is_finished);
    for _ in 0..SESSION_WAIT_POLLS_MAX {
        if (!spec_path.exists() && handed()) || matches!(own_lease(request), Some(true)) {
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

/// Where the spawned launcher's pid came from. Only a pid `zmx list` reports for a running
/// session is the launcher's; a lease's pid is the agent's own word, a hint, never bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    Listed(u32),
    FromLease(u32),
}

impl Found {
    #[must_use]
    pub const fn pid(self) -> u32 {
        match self {
            Self::Listed(pid) | Self::FromLease(pid) => pid,
        }
    }
}

fn wait_for_pid(request: &SpawnRequest<'_>, name: &str) -> Result<Found, SpawnerError> {
    for _ in 0..SESSION_WAIT_POLLS_MAX {
        let entries = request.zmx.list().map_err(transient)?;
        match presence(&entries, name) {
            Presence::Running { pid, .. } => return Ok(Found::Listed(pid)),
            Presence::Ended { pid } => return ended_launcher(request, pid),
            Presence::Absent => {}
            Presence::Unrecognised => return Err(transient("zmx list is unrecognised")),
        }
        if let LeaseRead::Present { lease } =
            read_lease(request.dirs, &request.env.session_name, request.agent_uid)
            && *lease.awaitable_sha256() == AwaitableDigest::of(&request.env.awaitable_id)
        {
            return Ok(Found::FromLease(lease.pid()));
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(transient(format!("{name} did not appear in zmx list")))
}

/// A launcher that already ended counts as spawned only if it wrote this awaitable's lease.
fn ended_launcher(request: &SpawnRequest<'_>, pid: u32) -> Result<Found, SpawnerError> {
    match read_lease(request.dirs, &request.env.session_name, request.agent_uid) {
        LeaseRead::Present { lease }
            if *lease.awaitable_sha256() == AwaitableDigest::of(&request.env.awaitable_id) =>
        {
            Ok(Found::FromLease(lease.pid()))
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

/// The bytes `send_line` types: the text and the carriage return zmx does not add.
#[must_use]
pub fn typed_line(text: &ShortText) -> String {
    format!("{}\r", text.as_str())
}

/// Types one line into the session and submits it; zmx delivers it to the pty's stdin.
pub fn send_line(zmx: &Zmx, session: &SessionName, text: &ShortText) -> Result<(), SpawnerError> {
    zmx.send(&session.to_string(), &typed_line(text))
        .map_err(transient)
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use crate::agent_files::{current_uid, write_durable};
    use tycho_types::launcher::AwaitableId;
    use tycho_types::launcher::{ENV_AWAITABLE_ID, ENV_SESSION_NAME, ENV_SESSION_SECRET};

    const NAME: &str = "cf7a.wu03.wrk.claude.a1f3";

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    static PRODUCTION_PREFIX: std::sync::LazyLock<ToolPrefix> =
        std::sync::LazyLock::new(crate::config::tool_prefix::tests::production);

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
            tycho: Path::new("/Users/Shared/tycho/bin/tycho"),
            home: Path::new("/nonexistent"),
            env: &env,
            heartbeat: HeartbeatTarget::Session,
            vendor: &vendor,
            agent_uid: current_uid(),
            tier: Some("t2"),
            terminal: VendorTerminal::Files,
            vendor_dir: None,
            ports: CorePorts::PRODUCTION,
            tool_prefix: &PRODUCTION_PREFIX,
            credential: None,
        };
        let session = SessionName::parse(NAME).unwrap();
        write_durable(
            &dirs.lease_path(&session),
            &lease(now_unix_ms()).to_bytes().unwrap(),
        )
        .unwrap();
        let elsewhere = SpawnRequest {
            tycho: Path::new("/usr/local/bin/tycho"),
            ..request
        };
        assert!(matches!(
            spawn_session(&elsewhere),
            Err(SpawnerError::Refused(why)) if why.contains("not the tool prefix's")
        ));
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
            tycho: Path::new("/Users/Shared/tycho/bin/tycho"),
            home: Path::new("/Users/agent"),
            env,
            heartbeat: HeartbeatTarget::Session,
            vendor,
            agent_uid: current_uid(),
            tier: Some("t2"),
            terminal: VendorTerminal::Files,
            vendor_dir: None,
            ports: CorePorts::PRODUCTION,
            tool_prefix: &PRODUCTION_PREFIX,
            credential: None,
        }
    }

    const WORKTREE: &str = "/Users/Shared/tycho-agent-zmx/worktrees/cf7a/wu03/a1";
    const BRIEF: &str = "/Users/Shared/tycho-agent-zmx/worktrees/cf7a/wu03.brief.md";
    const CLAUDE_INSTALL: &str = "/Users/Shared/tycho/mise/installs/claude/2.1.295";
    const PREFIX_TYCHO: &str = "/Users/Shared/tycho/bin/tycho";

    fn read(path: &str) -> Grant {
        grant(Path::new(path), Access::Read)
    }

    fn read_write(path: &str) -> Grant {
        grant(Path::new(path), Access::ReadWrite)
    }

    /// The worker command the run builds for the prefix's Claude, as `WorkerArgs::to_argv`
    /// writes it.
    fn worker_argv() -> Vec<String> {
        crate::vendors::worker::WorkerArgs {
            vendor: tycho_types::session::Vendor::Claude,
            binary: PRODUCTION_PREFIX.tool("claude").unwrap().to_path_buf(),
            brief: PathBuf::from(BRIEF),
            worktree: PathBuf::from(WORKTREE),
            model: crate::vendors::worker::ModelName::parse("haiku").unwrap(),
            effort: tycho_types::task_packet::Effort::Low,
            max_turns: None,
            session_id: crate::vendors::worker::VendorSessionId::parse(
                "3f0c6c1e-6b1a-4a51-9a0e-2a8c5d0c1a10",
            )
            .unwrap(),
            to: SessionName::parse("cf7a.wu03.ctl.claude").unwrap(),
            branch: tycho_types::envelope::BranchName::parse("wu03/a1").unwrap(),
            base: tycho_types::envelope::CommitSha::parse(
                "0123456789abcdef0123456789abcdef01234567",
            )
            .unwrap(),
        }
        .to_argv(Path::new(PREFIX_TYCHO))
    }

    /// A worker gets the prefix's `tycho` and its vendor's install to read, its worktree to
    /// read and write, and its brief to read; nothing else, and each once.
    #[test]
    fn a_worker_s_grants_are_its_tycho_install_worktree_and_brief_with_their_modes() {
        let dirs = AgentDirs::new(PathBuf::from("/Users/Shared/tycho-agent-zmx")).unwrap();
        let zmx = Zmx::agent(Path::new("/opt/zmx"), &dirs.socket_dir);
        let env = env();
        let vendor = worker_argv();
        let request = shared_request(&dirs, &zmx, &env, &vendor);
        assert_eq!(
            sandbox_grants(&request).unwrap(),
            [
                read(PREFIX_TYCHO),
                read(CLAUDE_INSTALL),
                read_write(WORKTREE),
                read(BRIEF),
            ]
        );
        assert_eq!(launch_spec(&request).unwrap().grants.len(), 4);
    }

    /// A control session gets the prefix's `tycho` and its vendor's install to read and its
    /// working directory to read and write.
    #[test]
    fn a_control_session_s_grants_are_its_tycho_install_and_working_directory() {
        let dirs = AgentDirs::new(PathBuf::from("/Users/Shared/tycho-agent-zmx")).unwrap();
        let zmx = Zmx::agent(Path::new("/opt/zmx"), &dirs.socket_dir);
        let env = env();
        let claude = PRODUCTION_PREFIX
            .tool("claude")
            .unwrap()
            .display()
            .to_string();
        let vendor = [claude, "--model".to_string(), "haiku".to_string()];
        let working = Path::new("/Users/tycho-agent/control/cf7a-wu03");
        let request = SpawnRequest {
            vendor_dir: Some(working),
            terminal: VendorTerminal::Inherit,
            ..shared_request(&dirs, &zmx, &env, &vendor)
        };
        assert_eq!(
            sandbox_grants(&request).unwrap(),
            [
                read(PREFIX_TYCHO),
                read(CLAUDE_INSTALL),
                read_write("/Users/tycho-agent/control/cf7a-wu03"),
            ]
        );
    }

    /// A vendor's whole install is granted, not only its executable's directory: Codex keeps
    /// its executable in `bin` and loads what lies beside that directory.
    #[test]
    fn a_codex_session_reads_its_whole_install_not_only_its_bin() {
        let dirs = AgentDirs::new(PathBuf::from("/Users/Shared/tycho-agent-zmx")).unwrap();
        let zmx = Zmx::agent(Path::new("/opt/zmx"), &dirs.socket_dir);
        let env = LauncherEnv::from_map(&BTreeMap::from([
            (ENV_AWAITABLE_ID.to_string(), "sign_1abc".to_string()),
            (ENV_SESSION_SECRET.to_string(), SECRET.to_string()),
            (
                ENV_SESSION_NAME.to_string(),
                "cf7a.wu03.wrk.codex.a1f3".to_string(),
            ),
        ]))
        .unwrap();
        let codex = PRODUCTION_PREFIX
            .tool("codex")
            .unwrap()
            .display()
            .to_string();
        let vendor = [codex, "exec".to_string()];
        let request = shared_request(&dirs, &zmx, &env, &vendor);
        assert_eq!(
            sandbox_grants(&request).unwrap(),
            [
                read(PREFIX_TYCHO),
                read("/Users/Shared/tycho/mise/installs/codex/0.160.1"),
            ]
        );
    }

    /// The station binary as a vendor runs only as a worker with arguments that parse; any
    /// other use is refused, never granted a set without the worktree.
    #[test]
    fn a_station_vendor_that_is_not_a_well_formed_worker_is_refused() {
        let dirs = AgentDirs::new(PathBuf::from("/Users/Shared/tycho-agent-zmx")).unwrap();
        let zmx = Zmx::agent(Path::new("/opt/zmx"), &dirs.socket_dir);
        let env = env();
        let mut missing_worktree = worker_argv();
        let at = missing_worktree
            .iter()
            .position(|word| word == "--worktree")
            .unwrap();
        missing_worktree.drain(at..=at + 1);
        let refused: [Vec<String>; 4] = [
            vec![PREFIX_TYCHO.to_string(), "session-leader".to_string()],
            vec![PREFIX_TYCHO.to_string()],
            missing_worktree,
            vec![
                "/opt/elsewhere/tycho".to_string(),
                WORKER_COMMAND.to_string(),
                "--vendor".to_string(),
            ],
        ];
        for vendor in &refused {
            let request = shared_request(&dirs, &zmx, &env, vendor);
            assert!(
                matches!(sandbox_grants(&request), Err(SpawnerError::Refused(_))),
                "{vendor:?}"
            );
            assert!(launch_spec(&request).is_err(), "{vendor:?}");
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
        assert_eq!(
            spec.environment
                .get("TYCHO_VENDOR_SANDBOX_SETTINGS")
                .map(String::as_str),
            Some(r#"{"sandbox":{"enabled":false}}"#)
        );
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
        let test_prefix = ToolPrefix::new(PathBuf::from("/tmp/prefix")).unwrap();
        let moved = SpawnRequest {
            tool_prefix: &test_prefix,
            ..request
        };
        let moved_words = typed_words(&moved, Path::new("/s")).unwrap();
        assert!(
            moved_words
                .iter()
                .any(|word| word == "PATH=/tmp/prefix/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        );
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
    fn the_typed_line_starts_at_the_prefix_installs_and_keeps_mise_offline() {
        let dirs = AgentDirs::new(PathBuf::from("/Users/Shared/tycho-agent-zmx")).unwrap();
        let zmx = Zmx::agent(Path::new("/opt/zmx"), &dirs.socket_dir);
        let env = env();
        let vendor = ["/bin/sh".to_string()];
        let request = shared_request(&dirs, &zmx, &env, &vendor);
        let words = typed_words(&request, Path::new("/s")).unwrap();
        let environment: Vec<&str> = words
            .iter()
            .skip(3)
            .take_while(|word| !word.starts_with("TYCHO_CORE_UID="))
            .map(String::as_str)
            .collect();
        assert_eq!(
            environment,
            [
                "HOME=/Users/agent",
                "PATH=/Users/Shared/tycho/bin:/Users/Shared/tycho/mise/installs/claude/2.1.295:/Users/Shared/tycho/mise/installs/codex/0.160.1/bin:/Users/Shared/tycho/mise/installs/zmx/0.8.1:/usr/bin:/bin:/usr/sbin:/sbin",
                "MISE_DATA_DIR=/Users/Shared/tycho/mise",
                "MISE_GLOBAL_CONFIG_FILE=/Users/Shared/tycho/mise.toml",
                "MISE_CACHE_DIR=/Users/Shared/tycho/cache",
                "MISE_OVERRIDE_CONFIG_FILENAMES=/Users/Shared/tycho/no-project-config",
                "MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES=none",
                "MISE_OFFLINE=1",
                "MISE_AUTO_INSTALL=false",
            ]
        );
        assert!(!words.iter().any(|word| word.contains("shims")));
    }
    #[test]
    fn an_interactive_spec_names_its_terminal_and_directory() {
        let dirs = AgentDirs::new(PathBuf::from("/a")).unwrap();
        let zmx = Zmx::agent(Path::new("/z"), &dirs.socket_dir);
        let env = env();
        let vendor = ["/bin/sh".to_string()];
        let headless = launch_spec(&shared_request(&dirs, &zmx, &env, &vendor)).unwrap();
        assert!(!headless.environment.contains_key(VENDOR_TERMINAL_ENV));
        assert!(!headless.environment.contains_key(VENDOR_DIR_ENV));
        let interactive = SpawnRequest {
            terminal: VendorTerminal::Inherit,
            vendor_dir: Some(Path::new("/work/wu03")),
            ..shared_request(&dirs, &zmx, &env, &vendor)
        };
        let spec = launch_spec(&interactive).unwrap();
        assert_eq!(spec.environment[VENDOR_TERMINAL_ENV], "inherit");
        assert_eq!(spec.environment[VENDOR_DIR_ENV], "/work/wu03");
    }

    #[test]
    fn a_test_core_spec_names_its_offset_and_the_production_spec_does_not() {
        let dirs = AgentDirs::new(PathBuf::from("/a")).unwrap();
        let zmx = Zmx::agent(Path::new("/z"), &dirs.socket_dir);
        let env = env();
        let vendor = ["/bin/sh".to_string()];
        let production = launch_spec(&shared_request(&dirs, &zmx, &env, &vendor)).unwrap();
        assert!(!production.environment.contains_key(PORT_OFFSET_ENV));
        let offset = crate::config_store::PortOffset::new(1056).unwrap();
        let test_core = SpawnRequest {
            ports: CorePorts::at(offset),
            ..shared_request(&dirs, &zmx, &env, &vendor)
        };
        let spec = launch_spec(&test_core).unwrap();
        assert_eq!(spec.environment[PORT_OFFSET_ENV], "1056");
        assert_eq!(spec.settings().unwrap().ports, CorePorts::at(offset));
    }

    #[test]
    fn the_identity_switch_adds_nothing_to_the_typed_line() {
        let dirs = AgentDirs::new(PathBuf::from("/Users/Shared/tycho-agent-zmx")).unwrap();
        let zmx = Zmx::agent(Path::new("/opt/zmx"), &dirs.socket_dir);
        let switched = Zmx::agent_as(Path::new("/opt/zmx"), &dirs.socket_dir, "tycho-agent");
        let env = env();
        let vendor = ["/bin/sh".to_string()];
        let spec = dirs.spec_path(&env.session_name);
        let caller = typed_words(&shared_request(&dirs, &zmx, &env, &vendor), &spec).unwrap();
        let agent = typed_words(&shared_request(&dirs, &switched, &env, &vendor), &spec).unwrap();
        assert_eq!(caller, agent);
        assert!(!agent.iter().any(|word| word.contains("sudo")), "{agent:?}");
        let (program, words) = switched.invocation(&["run", "s", "-d"]);
        assert_eq!(program, PathBuf::from("/bin/sh"));
        assert!(words.iter().any(|word| word == "/usr/bin/sudo"));
    }

    #[test]
    fn a_typed_line_is_submitted_with_a_carriage_return() {
        let text = ShortText::parse("status?").unwrap();
        assert_eq!(typed_line(&text), "status?\r");
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
    fn the_credential_travels_by_socket_never_by_spec_or_typed_line() {
        use crate::credentials::tests::CLAUDE_TOKEN;
        use crate::credentials::{CLAUDE_TOKEN_ENV, CredentialVendor};
        let dirs = AgentDirs::new(PathBuf::from("/Users/Shared/tycho-agent-zmx")).unwrap();
        let zmx = Zmx::agent(Path::new("/opt/zmx"), &dirs.socket_dir);
        let env = env();
        let vendor = ["/bin/sh".to_string()];
        let credential =
            Credential::parse(CredentialVendor::Claude, CLAUDE_TOKEN.as_bytes()).unwrap();
        let request = SpawnRequest {
            credential: Some(&credential),
            ..shared_request(&dirs, &zmx, &env, &vendor)
        };
        let spec = launch_spec(&request).unwrap();
        let socket = socket_path(&dirs, &env.session_name);
        assert_eq!(
            spec.environment
                .get(CREDENTIAL_SOCKET_ENV)
                .map(String::as_str),
            Some(socket.display().to_string().as_str())
        );
        let spec_bytes = String::from_utf8(serde_json::to_vec(&spec).unwrap()).unwrap();
        assert!(!spec_bytes.contains(CLAUDE_TOKEN) && !spec_bytes.contains(CLAUDE_TOKEN_ENV));
        let words = typed_words(&request, &dirs.spec_path(&env.session_name)).unwrap();
        assert!(
            !words
                .iter()
                .any(|word| word.contains(CLAUDE_TOKEN) || word.contains(CLAUDE_TOKEN_ENV)),
            "{words:?}"
        );
        assert!(!format!("{request:?}").contains(CLAUDE_TOKEN));
        let without = launch_spec(&shared_request(&dirs, &zmx, &env, &vendor)).unwrap();
        assert!(!without.environment.contains_key(CREDENTIAL_SOCKET_ENV));
    }

    #[test]
    fn a_failed_zmx_run_closes_the_credential_socket() {
        use crate::credentials::CredentialVendor;
        use crate::credentials::tests::CLAUDE_TOKEN;
        let dirs =
            AgentDirs::new(PathBuf::from(format!("/tmp/tsc-{}", std::process::id()))).unwrap();
        if dirs.socket_dir.exists() {
            fs::remove_dir_all(&dirs.socket_dir).unwrap();
        }
        let zmx = Zmx::agent(Path::new("/usr/bin/false"), &dirs.socket_dir);
        let env = env();
        let vendor = ["/bin/true".to_string()];
        let credential =
            Credential::parse(CredentialVendor::Claude, CLAUDE_TOKEN.as_bytes()).unwrap();
        let request = SpawnRequest {
            credential: Some(&credential),
            ..shared_request(&dirs, &zmx, &env, &vendor)
        };
        assert!(matches!(
            start_detached(&request),
            Err(SpawnerError::Transient(_))
        ));
        assert!(
            dirs.spec_dir().exists(),
            "the spec directory was never made"
        );
        assert!(!socket_path(&dirs, &env.session_name).exists());
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    /// A zmx stand-in whose `run` succeeds and whose `list` shows the session running as
    /// `listed_pid`.
    fn listing_zmx(dir: &Path, listed_pid: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("zmx-stand-in");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\ncase \"$1\" in list) printf '  name={NAME}\\tpid={listed_pid}\\tclients=0\\tcreated=1\\n' ;; esac\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        script
    }

    /// Spawns with a credential while a thread plays the launcher from this process: it asks
    /// for the credential, then removes the spec as a launcher that read it would.
    fn spawn_with_launcher_here(tag: &str, listed_pid: u32) -> (Result<u32, SpawnerError>, bool) {
        use crate::credential_handoff::fetch;
        use crate::credentials::CredentialVendor;
        use crate::credentials::tests::CLAUDE_TOKEN;
        let dirs = AgentDirs::new(PathBuf::from(format!(
            "/tmp/tsb-{tag}-{}",
            std::process::id()
        )))
        .unwrap();
        if dirs.socket_dir.exists() {
            fs::remove_dir_all(&dirs.socket_dir).unwrap();
        }
        ensure_agent_dirs(&dirs).unwrap();
        let zmx = Zmx::agent(&listing_zmx(&dirs.socket_dir, listed_pid), &dirs.socket_dir);
        let env = env();
        let vendor = ["/bin/true".to_string()];
        let credential =
            Credential::parse(CredentialVendor::Claude, CLAUDE_TOKEN.as_bytes()).unwrap();
        let request = SpawnRequest {
            credential: Some(&credential),
            ..shared_request(&dirs, &zmx, &env, &vendor)
        };
        let socket = socket_path(&dirs, &env.session_name);
        let spec = dirs.spec_path(&env.session_name);
        let session = env.session_name.clone();
        let secret = env.session_secret.clone();
        let launcher = thread::spawn(move || {
            for _ in 0..200 {
                if socket.exists() && spec.exists() {
                    break;
                }
                thread::sleep(std::time::Duration::from_millis(10));
            }
            let fetched = fetch(
                &socket,
                current_uid(),
                &session,
                &secret,
                CredentialVendor::Claude,
            );
            drop(fs::remove_file(&spec));
            fetched.is_ok_and(|credential| credential.expose() == CLAUDE_TOKEN)
        });
        let spawned = start_detached(&request);
        let handed = launcher.join().unwrap();
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
        (spawned, handed)
    }

    #[test]
    fn the_credential_goes_only_to_the_process_zmx_lists_for_the_session() {
        let here = std::process::id();
        let (spawned, handed) = spawn_with_launcher_here("own", here);
        assert_eq!(spawned, Ok(here));
        assert!(handed, "the listed launcher did not get its credential");
        let (spawned, handed) = spawn_with_launcher_here("other", here.wrapping_add(1));
        assert_eq!(spawned, Ok(here.wrapping_add(1)));
        assert!(!handed, "a process zmx does not list got the credential");
    }

    #[test]
    fn a_lease_pid_is_reported_but_never_taken_for_the_listed_launcher() {
        let dirs = scratch("found");
        ensure_agent_dirs(&dirs).unwrap();
        let env = env();
        let vendor = ["/bin/true".to_string()];
        let silent = Zmx::agent(Path::new("/usr/bin/true"), &dirs.socket_dir);
        let request = shared_request(&dirs, &silent, &env, &vendor);
        let session = SessionName::parse(NAME).unwrap();
        write_durable(
            &dirs.lease_path(&session),
            &lease(now_unix_ms()).to_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(wait_for_pid(&request, NAME), Ok(Found::FromLease(4242)));
        let listing = Zmx::agent(&listing_zmx(&dirs.socket_dir, 5150), &dirs.socket_dir);
        let listed = SpawnRequest {
            zmx: &listing,
            ..request
        };
        assert_eq!(wait_for_pid(&listed, NAME), Ok(Found::Listed(5150)));
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn created_directories_get_their_exact_modes_and_an_unsticky_shared_one_is_refused() {
        let dirs = scratch("sticky");
        ensure_agent_dirs(&dirs).unwrap();
        let mode_of = |dir: &Path| fs::symlink_metadata(dir).unwrap().mode() & 0o7777;
        assert_eq!(mode_of(&dirs.socket_dir), AGENT_DIR_MODE | STICKY_BIT);
        assert_eq!(
            mode_of(&dirs.lease_dir()),
            AGENT_DIR_MODE,
            "the agent writes its lease"
        );
        assert_eq!(mode_of(&dirs.spool_root()), AGENT_DIR_MODE);
        assert_eq!(mode_of(&dirs.spec_dir()), SPEC_DIR_MODE);
        fs::set_permissions(&dirs.socket_dir, Permissions::from_mode(AGENT_DIR_MODE)).unwrap();
        assert!(matches!(
            ensure_agent_dirs(&dirs),
            Err(SpawnerError::Refused(why)) if why.contains("sticky")
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

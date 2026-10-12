//! `tycho launch`, the process that runs one vendor session.
//!
//! It writes the lease first, runs the vendor in its own process group with its output in
//! bounded files, heartbeats, decodes the exit, spools the result, delivers it, and ends its
//! own zmx session.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;
use nix::unistd::{tcsetpgrp, Pid};
use serde::{Deserialize, Serialize};
use tycho_types::agent_call::{HeartbeatCall, CONTEXT_TOKENS_MAX};
use tycho_types::exit::ExitState;
use tycho_types::launcher::{AwaitableDigest, IdempotencyKey, SEQUENCE_MAX};
use tycho_types::lease::Lease;
use tycho_types::session::SessionName;

use crate::agent_files::{
    create_new, current_uid, ensure_private_dir, open_append, read_checked, shred, write_durable,
    write_new,
};
use crate::agent_tree::{self, Bounds, Owners};
use crate::config::AgentDirs;
use crate::credential_handoff::fetch;
use crate::credentials::{
    Credential, CredentialVendor, CLAUDE_TOKEN_ENV, CODEX_AUTH_FILE, CODEX_HOME_ENV,
};
use crate::exit_decode::{
    decode_exit, read_progress, read_result_file, status_payload, ChildEnd, Decoded, ResultFile,
    ResultReport, Stop,
};
pub use crate::launch_spec::{
    check_tier, check_vendor, core_uid_from_environment, take_spec, HeartbeatTarget, LaunchSpec,
    LauncherSettings, SettingsError, VendorTerminal, AGENT_TELEMETRY_ENV, HEARTBEAT_TARGET_ENV,
    SPEC_SCHEMA_VERSION, TIER_FLAG, VENDOR_DIR_ENV, VENDOR_SANDBOX_SETTINGS_ENV,
    VENDOR_TERMINAL_ENV,
};
use crate::process::{now_unix_ms, send};
use crate::relay::{relay_dir, relay_once};
use crate::spool::{
    spool_then_deliver, write_spool, Ack, Delivery, HeartbeatSend, Ingress, SpoolRecord,
    SPOOL_FILE, SPOOL_SCHEMA_VERSION,
};
use crate::vendors::claude_control::socket_of_pid;
use crate::zmx::Zmx;

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// Three missed heartbeats make a lease stale.
pub const LEASE_FRESH_MS: u64 = 30_000;
pub const SUPERVISE_POLL: Duration = Duration::from_millis(250);
/// Supervise polls between relay polls: one relay poll a second, ten per heartbeat interval.
pub const RELAY_POLL_EVERY: u32 = 4;
pub const LOG_FILE_MAX_BYTES: u64 = 1024 * 1024;
const SEQUENCE_FILE_MAX_BYTES: usize = 32;
const TERM_GRACE_POLLS_MAX: u32 = 20;
pub const EXIT_ACKNOWLEDGED: i32 = 0;
pub const EXIT_UNDELIVERED: i32 = 1;
pub const EXIT_REFUSED_TO_START: i32 = 2;
/// The exit state of a session whose launcher got no credential and so started no vendor;
/// it decodes as unrecognised, which goes to the inbox rather than back to the queue.
pub const CREDENTIAL_UNAVAILABLE: &str = "vendor_credential_unavailable";
/// The per-session Codex home under the session's private spool directory.
pub const CODEX_HOME_DIR: &str = "codex-home";
/// What removing a Codex home may walk: Codex keeps logs and session files beside `auth.json`.
const CODEX_HOME_BOUNDS: Bounds = Bounds {
    depth: 8,
    entries: 4096,
};

/// The files of one session under its spool directory.
#[derive(Debug, Clone)]
pub struct SessionFiles {
    pub lease: PathBuf,
    pub sequence: PathBuf,
    pub spool_dir: PathBuf,
    pub spool: PathBuf,
    pub result: PathBuf,
    pub progress: PathBuf,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    pub log: PathBuf,
    pub vendor: PathBuf,
}

impl SessionFiles {
    #[must_use]
    pub fn new(dirs: &AgentDirs, session: &SessionName) -> Self {
        let spool_dir = dirs.spool_dir(session);
        Self {
            lease: dirs.lease_path(session),
            sequence: dirs.sequence_path(session),
            spool: spool_dir.join(SPOOL_FILE),
            result: spool_dir.join("result.json"),
            progress: spool_dir.join("progress.json"),
            stdout: spool_dir.join("stdout.log"),
            stderr: spool_dir.join("stderr.log"),
            log: spool_dir.join("launcher.log"),
            vendor: spool_dir.join("vendor.json"),
            spool_dir,
        }
    }
}

/// The vendor's pid, which is its process group, for a kill after the launcher is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorRecord {
    pub pid: u32,
    pub started_unix_ms: u64,
}

pub const VENDOR_RECORD_MAX_BYTES: usize = 256;

#[derive(Debug)]
pub enum SequenceError {
    Io(io::Error),
    Corrupt(String),
    Exhausted,
}

impl fmt::Display for SequenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "sequence file: {error}"),
            Self::Corrupt(text) => write!(formatter, "sequence file holds {text:?}"),
            Self::Exhausted => write!(formatter, "sequence reached {SEQUENCE_MAX}"),
        }
    }
}

/// Advances the counter beside the lease and returns the new value; durable before it is used.
pub fn next_sequence(path: &Path) -> Result<u64, SequenceError> {
    let previous = match read_checked(path, SEQUENCE_FILE_MAX_BYTES, Some(current_uid()))
        .map_err(SequenceError::Io)?
    {
        None => 0,
        Some(bytes) => {
            let text = String::from_utf8_lossy(&bytes).trim().to_string();
            text.parse::<u64>()
                .map_err(|_| SequenceError::Corrupt(text.clone()))?
        }
    };
    let next = previous
        .checked_add(1)
        .filter(|next| *next <= SEQUENCE_MAX)
        .ok_or(SequenceError::Exhausted)?;
    write_durable(path, next.to_string().as_bytes()).map_err(SequenceError::Io)?;
    Ok(next)
}

/// Appends lines up to `LOG_FILE_MAX_BYTES`, then drops the rest after one marker line.
#[derive(Debug)]
pub struct LaunchLog {
    file: Option<File>,
    written: u64,
    cap: u64,
}

impl LaunchLog {
    #[must_use]
    pub fn open(path: &Path) -> Self {
        Self::with_cap(path, LOG_FILE_MAX_BYTES)
    }

    #[must_use]
    pub fn with_cap(path: &Path, cap: u64) -> Self {
        let file = open_append(path).ok();
        Self {
            file,
            written: 0,
            cap,
        }
    }

    pub fn line(&mut self, text: &str) {
        let Some(mut file) = self.file.take() else {
            return;
        };
        let line = format!("{} {text}\n", now_unix_ms());
        let length = u64::try_from(line.len()).unwrap_or(u64::MAX);
        let next = self.written.saturating_add(length);
        if next > self.cap {
            // The marker is the last write; the file stays closed afterwards.
            drop(file.write_all(LOG_LIMIT_MARKER.as_bytes()));
            return;
        }
        self.written = next;
        if file.write_all(line.as_bytes()).is_ok() {
            self.file = Some(file);
        }
    }
}

const LOG_LIMIT_MARKER: &str = "log limit reached\n";

/// Sets the flag on SIGTERM or SIGHUP; registered on the caller's thread before it returns.
pub fn watch_signals() -> io::Result<Arc<AtomicBool>> {
    use tokio::signal::unix::{signal, SignalKind};
    let flag = Arc::new(AtomicBool::new(false));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (mut terminate, mut hangup) = {
        let _entered = runtime.enter();
        (
            signal(SignalKind::terminate())?,
            signal(SignalKind::hangup())?,
        )
    };
    let thread_flag = Arc::clone(&flag);
    thread::spawn(move || {
        let hangup_flag = Arc::clone(&thread_flag);
        runtime.spawn(async move {
            hangup.recv().await;
            hangup_flag.store(true, Ordering::SeqCst);
        });
        runtime.block_on(terminate.recv());
        thread_flag.store(true, Ordering::SeqCst);
    });
    Ok(flag)
}

/// How one launch ended, for the command line's report and exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchEnd {
    pub state: String,
    pub delivery: Result<Delivery, String>,
    pub spool_error: Option<String>,
}

impl LaunchEnd {
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match &self.delivery {
            Ok(Delivery::Acknowledged { .. }) => EXIT_ACKNOWLEDGED,
            Ok(Delivery::Refused { .. } | Delivery::GaveUp { .. }) | Err(_) => EXIT_UNDELIVERED,
        }
    }
}

impl fmt::Display for LaunchEnd {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.delivery {
            Ok(delivery) => write!(formatter, "exit state {}: {delivery:?}", self.state)?,
            Err(error) => write!(
                formatter,
                "exit state {}: not delivered: {error}",
                self.state
            )?,
        }
        if let Some(error) = &self.spool_error {
            write!(formatter, "; spool: {error}")?;
        }
        Ok(())
    }
}

/// The vendor as the leader of its own session through `tycho session-leader`, or, without
/// the trampoline, in its own process group; either way its group id is its pid.
fn vendor_command(session_leader: Option<&Path>, program: &str, arguments: &[String]) -> Command {
    session_leader.map_or_else(
        || {
            let mut command = Command::new(program);
            command.args(arguments).process_group(0);
            command
        },
        |tycho| {
            let mut command = Command::new(tycho);
            command
                .args(["session-leader", "--", program])
                .args(arguments);
            command
        },
    )
}

/// The running launcher: its settings, files, lease and the ingress it reports to.
struct Run<'a, I: Ingress> {
    settings: &'a LauncherSettings,
    files: SessionFiles,
    lease: Lease,
    ingress: &'a I,
    log: LaunchLog,
    /// Set once a record is on disk, so the exit trap delivers it rather than writing again.
    spooled: bool,
    /// What the core's hand-off gave this launcher; taken when the vendor starts.
    credential: Option<Result<Credential, String>>,
    /// The Codex home made for this session, removed when the vendor stops.
    codex_home: Option<PathBuf>,
}

/// Asks the core for the session's credential when the spec names a hand-off socket.
fn fetch_credential(settings: &LauncherSettings) -> Option<Result<Credential, String>> {
    let path = settings.credential_socket.as_ref()?;
    let session = &settings.env.session_name;
    let fetched = match (
        settings.core_uid,
        CredentialVendor::for_session(session.vendor()),
    ) {
        (Some(core_uid), Some(vendor)) => fetch(
            path,
            core_uid,
            session,
            &settings.env.session_secret,
            vendor,
        )
        .map_err(|error| error.to_string()),
        (None, _) => Err("no core uid to check the credential socket against".to_string()),
        (_, None) => Err(format!(
            "a {} session takes no credential",
            session.vendor().as_str()
        )),
    };
    Some(fetched)
}

/// Writes the lease before anything else runs, so a replayed spawn step sees it.
pub fn write_first_lease(
    settings: &LauncherSettings,
    files: &SessionFiles,
) -> Result<Lease, String> {
    let now = now_unix_ms();
    let lease = Lease::new(
        settings.env.session_name.clone(),
        std::process::id(),
        AwaitableDigest::of(&settings.env.awaitable_id),
        now,
        now,
    )
    .map_err(|error| error.to_string())?;
    let bytes = lease.to_bytes().map_err(|error| error.to_string())?;
    write_durable(&files.lease, &bytes)
        .map_err(|error| format!("{}: {error}", files.lease.display()))?;
    Ok(lease)
}

/// The whole launch; `Err` only when the lease could not be written and nothing ran.
pub fn launch(
    settings: &LauncherSettings,
    vendor: &[String],
    ingress: &impl Ingress,
) -> Result<LaunchEnd, String> {
    launch_with_stop(settings, vendor, ingress, None)
}

/// `launch` with a caller's stop flag in place of the SIGTERM and SIGHUP watcher.
pub fn launch_with_stop(
    settings: &LauncherSettings,
    vendor: &[String],
    ingress: &impl Ingress,
    stop: Option<Arc<AtomicBool>>,
) -> Result<LaunchEnd, String> {
    let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
    // The core keeps the hand-off open until the lease appears, so the request comes first.
    let credential = fetch_credential(settings);
    let lease = write_first_lease(settings, &files)?;
    let spool_ready = ensure_private_dir(&files.spool_dir);
    let mut run = Run {
        settings,
        log: LaunchLog::open(&files.log),
        files,
        lease,
        ingress,
        spooled: false,
        credential,
        codex_home: None,
    };
    let decoded = match spool_ready
        .map_err(|error| error.to_string())
        .and_then(|()| stop.map_or_else(|| watch_signals().map_err(|error| error.to_string()), Ok))
    {
        Ok(stop_flag) => run.supervise_vendor(vendor, &stop_flag),
        Err(error) => {
            run.log
                .line(&format!("cannot prepare the session: {error}"));
            decode_exit(
                Stop::None,
                ChildEnd::NotStarted,
                crate::exit_decode::ResultFile::Absent,
                &settings.env.session_name,
            )
        }
    };
    let end = run.finish(decoded);
    run.end_own_session();
    Ok(end)
}

impl<I: Ingress> Run<'_, I> {
    fn supervise_vendor(&mut self, vendor: &[String], stop_flag: &AtomicBool) -> Decoded {
        let session = self.settings.env.session_name.clone();
        let credential = match self.credential_environment() {
            Ok(pairs) => pairs,
            Err(reason) => {
                self.remove_codex_home();
                self.log
                    .line(&format!("no credential, vendor not started: {reason}"));
                return Decoded {
                    state: ExitState::from_wire(CREDENTIAL_UNAVAILABLE),
                    envelope: None,
                };
            }
        };
        let (end, stop) = match self.start_vendor(vendor, credential) {
            Ok(mut child) => self.supervise(&mut child, stop_flag),
            Err(error) => {
                self.log.line(&format!("vendor did not start: {error}"));
                (ChildEnd::NotStarted, Stop::None)
            }
        };
        self.remove_codex_home();
        self.log
            .line(&format!("vendor ended: {end:?}, stop: {stop:?}"));
        if stop == Stop::None && end != ChildEnd::NotStarted {
            // The vendor's last progress, its final context size included, reaches the
            // session before the result does; a run shorter than one interval has no other beat.
            self.beat();
        }
        let result = read_result_file(&self.files.result);
        if let ResultFile::Report(ResultReport {
            detail: Some(detail),
            ..
        }) = &result
        {
            self.log.line(&format!("vendor detail: {detail}"));
        }
        decode_exit(stop, end, result, &session)
    }

    /// The vendor's credential pair: Claude's token itself, or the Codex home holding the
    /// core's `auth.json`; empty when the spec named no hand-off.
    fn credential_environment(&mut self) -> Result<Vec<(String, String)>, String> {
        let credential = match self.credential.take() {
            None => return Ok(Vec::new()),
            Some(Err(reason)) => return Err(reason),
            Some(Ok(credential)) => credential,
        };
        match credential.vendor() {
            CredentialVendor::Claude => Ok(vec![(
                CLAUDE_TOKEN_ENV.to_string(),
                credential.expose().to_string(),
            )]),
            CredentialVendor::Codex => {
                let home = self.files.spool_dir.join(CODEX_HOME_DIR);
                ensure_private_dir(&home)
                    .map_err(|error| format!("{}: {error}", home.display()))?;
                self.codex_home = Some(home.clone());
                let auth = home.join(CODEX_AUTH_FILE);
                write_new(&auth, credential.expose().as_bytes())
                    .map_err(|error| format!("{}: {error}", auth.display()))?;
                Ok(vec![(
                    CODEX_HOME_ENV.to_string(),
                    home.display().to_string(),
                )])
            }
        }
    }

    /// Zeroes and removes the session's `auth.json`, then the Codex home, never through a link.
    fn remove_codex_home(&mut self) {
        let Some(home) = self.codex_home.take() else {
            return;
        };
        let auth = home.join(CODEX_AUTH_FILE);
        if let Err(error) = shred(&auth) {
            if error.kind() != io::ErrorKind::NotFound {
                self.log.line(&format!("{}: {error}", auth.display()));
            }
        }
        let owners = Owners {
            core: current_uid(),
            agent: current_uid(),
        };
        let removed = File::open(&self.files.spool_dir)
            .map_err(|error| error.to_string())
            .and_then(|spool| {
                agent_tree::remove_dir(
                    std::os::fd::AsFd::as_fd(&spool),
                    &self.files.spool_dir,
                    std::ffi::OsStr::new(CODEX_HOME_DIR),
                    owners,
                    CODEX_HOME_BOUNDS,
                )
                .map_err(|error| error.to_string())
            });
        if let Err(error) = removed {
            self.log.line(&format!("codex home not removed: {error}"));
        }
    }

    fn start_vendor(
        &mut self,
        vendor: &[String],
        credential: Vec<(String, String)>,
    ) -> io::Result<Child> {
        let (program, arguments) = vendor
            .split_first()
            .ok_or_else(|| io::Error::other("empty vendor command"))?;
        let mut environment = self
            .settings
            .vendor_environment(&self.files.progress, &self.files.result);
        environment.extend(credential);
        // An interactive vendor keeps the pty as its controlling terminal, which a new
        // session would drop, so it runs in its own process group instead.
        let leader = match self.settings.terminal {
            VendorTerminal::Files => self.settings.session_leader.as_deref(),
            VendorTerminal::Inherit => None,
        };
        let mut command = vendor_command(leader, program, arguments);
        command.env_clear().envs(environment);
        if let Some(dir) = &self.settings.vendor_dir {
            command.current_dir(dir);
        }
        if self.settings.terminal == VendorTerminal::Files {
            command
                .stdin(Stdio::null())
                .stdout(create_new(&self.files.stdout)?)
                .stderr(create_new(&self.files.stderr)?);
        }
        let child = command.spawn()?;
        if self.settings.terminal == VendorTerminal::Inherit {
            self.hand_over_terminal(child.id());
        }
        let record = VendorRecord {
            pid: child.id(),
            started_unix_ms: now_unix_ms(),
        };
        match serde_json::to_vec(&record) {
            Ok(bytes) => {
                if let Err(error) = write_durable(&self.files.vendor, &bytes) {
                    self.log
                        .line(&format!("vendor record not written: {error}"));
                }
            }
            Err(error) => self.log.line(&format!("vendor record: {error}")),
        }
        self.log
            .line(&format!("vendor started as pid {}", record.pid));
        Ok(child)
    }

    /// Posts the instructions the core left in the relay directory to the vendor's inbox.
    fn relay(&mut self, vendor_pid: u32) {
        let (VendorTerminal::Inherit, Some(core_uid)) =
            (self.settings.terminal, self.settings.core_uid)
        else {
            return;
        };
        let dir = relay_dir(&self.settings.dirs, &self.settings.env.session_name);
        if !dir.exists() {
            return;
        }
        let Some(home) = std::env::var_os("HOME") else {
            self.log.line("relay: HOME is not set");
            return;
        };
        let config_dir = PathBuf::from(home).join(".claude");
        let outcome = match socket_of_pid(&config_dir, vendor_pid) {
            Ok(Some(socket)) => {
                relay_once(&dir, core_uid, &self.settings.env.session_name, &socket)
            }
            Ok(None) => Ok(Vec::new()),
            Err(reason) => Err(reason),
        };
        match outcome {
            Ok(deliveries) => {
                for delivery in deliveries {
                    self.log.line(&format!("relay: {delivery:?}"));
                }
            }
            Err(reason) => self.log.line(&format!("relay: {reason}")),
        }
    }

    /// Makes the vendor's group the pty's foreground group so its reads are not stopped.
    fn hand_over_terminal(&mut self, pid: u32) {
        let Ok(raw) = i32::try_from(pid) else {
            self.log.line(&format!("vendor pid {pid} is not a pid"));
            return;
        };
        if let Err(error) = tcsetpgrp(io::stdin(), Pid::from_raw(raw)) {
            self.log
                .line(&format!("terminal not handed to the vendor: {error}"));
        }
        // A read that raced the hand-over was stopped with SIGTTIN.
        if let Err(error) = send(pid, true, Signal::SIGCONT) {
            self.log.line(&error);
        }
    }

    fn supervise(&mut self, child: &mut Child, stop_flag: &AtomicBool) -> (ChildEnd, Stop) {
        let mut last_beat: Option<Instant> = None;
        let mut polls: u32 = 0;
        let started = Instant::now();
        let deadline = started
            .checked_add(self.settings.wall_clock)
            .unwrap_or(started);
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(status)) => return (ChildEnd::from(status), Stop::None),
                Ok(None) => {}
                Err(error) => {
                    self.log
                        .line(&format!("cannot wait for the vendor: {error}"));
                    return (self.terminate(child), Stop::None);
                }
            }
            if stop_flag.load(Ordering::SeqCst) {
                // zmx sends SIGKILL half a second after SIGHUP: spool and remove the Codex
                // home before stopping the vendor, which may take longer than that.
                self.spool_early(ExitState::Cancelled);
                self.remove_codex_home();
                return (self.terminate(child), Stop::Cancelled);
            }
            if self.output_too_large() {
                return (self.terminate(child), Stop::OutputTooLarge);
            }
            if last_beat.is_none_or(|beat| beat.elapsed() >= HEARTBEAT_INTERVAL) {
                self.beat();
                last_beat = Some(Instant::now());
            }
            polls = polls.wrapping_add(1);
            if polls.is_multiple_of(RELAY_POLL_EVERY) {
                self.relay(child.id());
            }
            thread::sleep(SUPERVISE_POLL);
        }
        (self.terminate(child), Stop::WallClock)
    }

    fn output_too_large(&self) -> bool {
        [&self.files.stdout, &self.files.stderr].iter().any(|path| {
            fs::metadata(path).is_ok_and(|metadata| metadata.len() > self.settings.output_max_bytes)
        })
    }

    /// SIGTERM to the vendor's group, then SIGKILL after the grace polls.
    fn terminate(&mut self, child: &mut Child) -> ChildEnd {
        if let Err(error) = send(child.id(), true, Signal::SIGTERM) {
            self.log.line(&error);
        }
        for _ in 0..TERM_GRACE_POLLS_MAX {
            if let Ok(Some(status)) = child.try_wait() {
                return ChildEnd::from(status);
            }
            thread::sleep(SUPERVISE_POLL);
        }
        if let Err(error) = send(child.id(), true, Signal::SIGKILL) {
            self.log.line(&error);
        }
        child.wait().map_or(ChildEnd::Unknown, ChildEnd::from)
    }

    fn renew_lease(&mut self) {
        match self.lease.renewed(now_unix_ms()) {
            Ok(renewed) => {
                let written = renewed
                    .to_bytes()
                    .map_err(|error| error.to_string())
                    .and_then(|bytes| {
                        write_durable(&self.files.lease, &bytes).map_err(|error| error.to_string())
                    });
                match written {
                    Ok(()) => self.lease = renewed,
                    Err(error) => self.log.line(&format!("lease not renewed: {error}")),
                }
            }
            Err(error) => self.log.line(&format!("lease not renewed: {error}")),
        }
    }

    /// Renews the lease and sends one heartbeat; a failure is logged and never stops the vendor.
    fn beat(&mut self) {
        self.renew_lease();
        let outcome = self.heartbeat();
        match outcome {
            Ok(Ack::Acknowledged) => {}
            Ok(other) => self.log.line(&format!("heartbeat not accepted: {other:?}")),
            Err(error) => self.log.line(&format!("heartbeat not sent: {error}")),
        }
    }

    fn heartbeat(&self) -> Result<Ack, String> {
        let env = &self.settings.env;
        let sequence = next_sequence(&self.files.sequence).map_err(|error| error.to_string())?;
        let key =
            IdempotencyKey::new(&env.session_name, sequence).map_err(|error| error.to_string())?;
        let (status, context_tokens) = status_payload(
            &read_progress(&self.files.progress),
            self.lease.started_unix_ms(),
        )?;
        let body = HeartbeatCall {
            secret: env.session_secret.expose().to_string(),
            sequence,
            status,
            context_tokens: context_tokens.min(CONTEXT_TOKENS_MAX),
        };
        let body = serde_json::to_string(&body).map_err(|error| error.to_string())?;
        Ok(self.ingress.heartbeat(&HeartbeatSend {
            service: self.settings.heartbeat.service(),
            session: &env.session_name,
            idempotency_key: &key,
            body,
        }))
    }

    fn record(&self, state: ExitState, envelope: Option<serde_json::Value>) -> SpoolRecord {
        SpoolRecord {
            schema_version: SPOOL_SCHEMA_VERSION,
            session: self.settings.env.session_name.clone(),
            awaitable_id: self.settings.env.awaitable_id.clone(),
            state,
            envelope,
        }
    }

    /// Writes a failure record now, ahead of the exit trap.
    fn spool_early(&mut self, state: ExitState) {
        match write_spool(&self.files.spool, &self.record(state, None)) {
            Ok(()) => self.spooled = true,
            Err(error) => self.log.line(&format!("early spool not written: {error}")),
        }
    }

    fn finish(&mut self, decoded: Decoded) -> LaunchEnd {
        let state = String::from(decoded.state.clone());
        let record = self.record(decoded.state, decoded.envelope);
        let spool = self.files.spool.clone();
        let ingress = self.ingress;
        let already = self.spooled;
        let delivered = spool_then_deliver(ingress, &spool, &record, already, &mut |delay| {
            self.wait_renewing(delay);
        });
        let (delivery, spool_error) = match delivered {
            Ok(delivered) => (Ok(delivered.delivery), delivered.spool_error),
            Err(error) => (Err(error.to_string()), None),
        };
        if let Some(error) = &spool_error {
            self.log.line(&format!("spool: {error}"));
        }
        if matches!(delivery, Ok(Delivery::Acknowledged { .. })) {
            self.mark_ended();
        }
        self.log.line(&format!("exit state {state}: {delivery:?}"));
        LaunchEnd {
            state,
            delivery,
            spool_error,
        }
    }

    /// Marks the lease ended once Restate acknowledged, so a replayed spawn adopts it at any age.
    fn mark_ended(&mut self) {
        let written = self
            .lease
            .ended(now_unix_ms())
            .map_err(|error| error.to_string())
            .and_then(|ended| ended.to_bytes().map_err(|error| error.to_string()))
            .and_then(|bytes| {
                write_durable(&self.files.lease, &bytes).map_err(|error| error.to_string())
            });
        if let Err(error) = written {
            self.log.line(&format!("lease not marked ended: {error}"));
        }
    }

    /// Sleeps in heartbeat-sized steps renewing the lease, so a delivering launcher is adopted.
    fn wait_renewing(&mut self, delay: Duration) {
        let started = Instant::now();
        let steps = delay
            .as_secs()
            .div_ceil(HEARTBEAT_INTERVAL.as_secs())
            .max(1);
        for _ in 0..steps {
            let remaining = delay.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return;
            }
            thread::sleep(remaining.min(HEARTBEAT_INTERVAL));
            self.renew_lease();
        }
    }

    /// The exit trap's last step; zmx also hangs up this process, which the signal flag absorbs.
    fn end_own_session(&mut self) {
        let zmx = Zmx::agent(&self.settings.zmx, &self.settings.dirs.socket_dir);
        if let Err(error) = zmx.kill(&self.settings.env.session_name.to_string()) {
            self.log
                .line(&format!("zmx kill of the own session failed: {error}"));
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use crate::credential_handoff::{HandoffOutcome, HandoffServer};
    use crate::credentials::tests::{CLAUDE_TOKEN, CODEX_AUTH};
    use crate::launch_spec::tests::{environment, NAME, SECRET};
    use crate::spool::{Resolution, ACKNOWLEDGED_SUFFIX};
    use std::cell::RefCell;
    use tycho_types::launcher::AwaitableId;
    use tycho_types::launcher::ENV_SESSION_NAME;

    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tycho-launch-{test}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        fs::create_dir_all(dir.join(crate::config::LEASE_DIR)).unwrap();
        fs::create_dir_all(dir.join(crate::config::SPOOL_DIR)).unwrap();
        dir
    }

    #[test]
    fn sequences_increase_across_a_restart_and_refuse_a_corrupt_counter() {
        let dir = scratch("sequence");
        let path = dir.join("session.seq");
        let first: Vec<u64> = (0..3).map(|_| next_sequence(&path).unwrap()).collect();
        let after_restart = next_sequence(&path).unwrap();
        assert_eq!(first, vec![1, 2, 3]);
        assert_eq!(after_restart, 4);
        let session = SessionName::parse(NAME).unwrap();
        let keys: Vec<String> = [first[2], after_restart]
            .iter()
            .map(|sequence| {
                IdempotencyKey::new(&session, *sequence)
                    .unwrap()
                    .as_str()
                    .to_string()
            })
            .collect();
        assert_eq!(keys, vec![format!("{NAME}:3"), format!("{NAME}:4")]);
        fs::write(&path, "seven").unwrap();
        assert!(matches!(
            next_sequence(&path),
            Err(SequenceError::Corrupt(_))
        ));
        fs::write(&path, SEQUENCE_MAX.to_string()).unwrap();
        assert!(matches!(
            next_sequence(&path),
            Err(SequenceError::Exhausted)
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn heartbeat_body_is_the_session_input() {
        let (status, _) =
            crate::exit_decode::status_payload(&crate::exit_decode::Progress::Absent, 1).unwrap();
        let body = HeartbeatCall {
            secret: SECRET.to_string(),
            sequence: 3,
            status,
            context_tokens: 7,
        };
        let value = serde_json::to_value(&body).unwrap();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, vec!["context_tokens", "secret", "sequence", "status"]);
        assert!(!format!("{body:?}").contains(SECRET));
        let back: HeartbeatCall = serde_json::from_value(value).unwrap();
        assert_eq!(back, body);
    }

    /// Records each ingress call with what was on disk at that moment.
    struct Recorder {
        files: SessionFiles,
        events: RefCell<Vec<String>>,
        context_tokens: RefCell<Vec<u64>>,
    }

    impl Ingress for Recorder {
        fn deliver(&self, awaitable: &AwaitableId, resolution: &Resolution) -> Ack {
            let kind = match resolution {
                Resolution::Resolve(_) => "resolve",
                Resolution::Reject(reason) => reason.as_str(),
            };
            self.events.borrow_mut().push(format!(
                "deliver {awaitable} {kind} spooled={}",
                self.files.spool.exists()
            ));
            Ack::Acknowledged
        }

        fn heartbeat(&self, call: &HeartbeatSend<'_>) -> Ack {
            let body: HeartbeatCall = serde_json::from_str(&call.body).unwrap();
            self.context_tokens.borrow_mut().push(body.context_tokens);
            self.events.borrow_mut().push(format!(
                "heartbeat {} {} {} lease={}",
                call.service,
                call.idempotency_key.as_str(),
                body.sequence,
                self.files.lease.exists()
            ));
            Ack::Acknowledged
        }
    }

    /// A vendor that records whether the lease existed and its environment in `marker_dir`.
    fn vendor_script(lease: &Path, result: &str, marker_dir: &Path) -> Vec<String> {
        let script = r#"test -f "$1" && echo seen > "$3/lease-seen"; /usr/bin/env > "$3/env"; sleep 0.4; printf '%s' "$2" > "$TYCHO_RESULT_FILE""#;
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            script.to_string(),
            "sh".to_string(),
            lease.display().to_string(),
            result.to_string(),
            marker_dir.display().to_string(),
        ]
    }

    fn recorder(files: &SessionFiles) -> Recorder {
        Recorder {
            files: files.clone(),
            events: RefCell::new(Vec::new()),
            context_tokens: RefCell::new(Vec::new()),
        }
    }

    fn sh(script: &str) -> Vec<String> {
        vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()]
    }

    #[test]
    fn lease_before_vendor_then_heartbeat_then_spool_then_resolve() {
        let dir = scratch("sequence-of-events");
        let settings = LauncherSettings::from_map(&environment(&dir)).unwrap();
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let result = serde_json::json!({
            "state": "completed",
            "envelope": crate::exit_decode::tests::envelope(NAME),
        });
        let vendor = vendor_script(&files.lease, &result.to_string(), &dir);
        let recorder = recorder(&files);
        let end = launch(&settings, &vendor, &recorder).unwrap();
        assert_eq!(end.state, "completed");
        assert_eq!(end.exit_code(), EXIT_ACKNOWLEDGED);
        assert!(
            dir.join("lease-seen").exists(),
            "the vendor ran before the lease existed"
        );
        let env = fs::read_to_string(dir.join("env")).unwrap();
        assert!(!env.contains(SECRET) && !env.contains("sign_1abc"), "{env}");
        assert!(
            !env.contains("ZMX_DIR=") && !env.contains("TYCHO_AGENT_DIR="),
            "{env}"
        );
        let events = recorder.events.borrow();
        assert_eq!(
            events.first().map(String::as_str),
            Some(format!("heartbeat Session {NAME}:1 1 lease=true").as_str())
        );
        assert_eq!(
            events.last().map(String::as_str),
            Some("deliver sign_1abc resolve spooled=true")
        );
        assert!(files.spool.with_extension(ACKNOWLEDGED_SUFFIX).exists());
        let lease = Lease::parse(&fs::read(&files.lease).unwrap()).unwrap();
        assert_eq!(lease.pid(), std::process::id());
        assert!(
            lease.ended_unix_ms().is_some(),
            "an acknowledged launch ends its lease"
        );
        assert!(!String::from_utf8(fs::read(&files.lease).unwrap())
            .unwrap()
            .contains("sign_1abc"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_last_heartbeat_carries_the_final_context_size_before_the_result() {
        let dir = scratch("last-beat");
        let settings = LauncherSettings::from_map(&environment(&dir)).unwrap();
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let script = r#"sleep 0.3; printf '{"context_tokens":33390}' > "$TYCHO_PROGRESS_FILE"; printf '{"state":"failed","envelope":null}' > "$TYCHO_RESULT_FILE""#;
        let recorder = recorder(&files);
        let end = launch(&settings, &sh(script), &recorder).unwrap();
        assert_eq!(end.state, "failed");
        let events = recorder.events.borrow();
        let beats = events
            .iter()
            .filter(|event| event.starts_with("heartbeat"))
            .count();
        assert_eq!(beats, 2, "{events:?}");
        assert!(
            events[events.len() - 2].starts_with("heartbeat"),
            "{events:?}"
        );
        assert_eq!(recorder.context_tokens.borrow().last(), Some(&33_390));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_escalated_result_rejects_with_the_certified_question() {
        let dir = scratch("escalated");
        let settings = LauncherSettings::from_map(&environment(&dir)).unwrap();
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let mut envelope = crate::exit_decode::tests::envelope(NAME);
        envelope["type"] = serde_json::json!("escalation");
        envelope["payload"] = crate::vendors::worker_process::tests::question();
        let result = serde_json::json!({"state": "escalated", "envelope": envelope});
        let script = format!("printf '%s' '{result}' > \"$TYCHO_RESULT_FILE\"; exit 1");
        let recorder = recorder(&files);
        let end = launch(&settings, &sh(&script), &recorder).unwrap();
        assert_eq!(end.state, "escalated");
        let events = recorder.events.borrow();
        let last = events.last().unwrap();
        assert!(last.starts_with("deliver sign_1abc escalated\n{"), "{last}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_vendor_runs_through_the_session_trampoline() {
        let words = |command: &Command| {
            std::iter::once(command.get_program())
                .chain(command.get_args())
                .map(|word| word.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" ")
        };
        let arguments = ["-c".to_string(), "true".to_string()];
        let through = vendor_command(Some(Path::new("/opt/tycho")), "/bin/sh", &arguments);
        assert_eq!(
            words(&through),
            "/opt/tycho session-leader -- /bin/sh -c true"
        );
        assert_eq!(
            words(&vendor_command(None, "/bin/sh", &arguments)),
            "/bin/sh -c true"
        );
    }

    #[test]
    fn the_wall_clock_deadline_stops_the_vendor() {
        let dir = scratch("wall-clock");
        let mut settings = LauncherSettings::from_map(&environment(&dir)).unwrap();
        settings.wall_clock = Duration::from_millis(500);
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let started = Instant::now();
        let end = launch(&settings, &sh("sleep 30"), &recorder(&files)).unwrap();
        assert_eq!(end.state, "budget_exceeded");
        assert!(started.elapsed() < Duration::from_secs(15));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn oversized_output_stops_the_vendor() {
        let dir = scratch("output");
        let mut settings = LauncherSettings::from_map(&environment(&dir)).unwrap();
        settings.output_max_bytes = 1024;
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let vendor = sh("head -c 4096 /dev/zero; sleep 30");
        let started = Instant::now();
        let end = launch(&settings, &vendor, &recorder(&files)).unwrap();
        assert_eq!(end.state, "failed");
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "the vendor was not stopped"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_cancel_spools_before_the_vendor_is_stopped() {
        let dir = scratch("cancel");
        let settings = LauncherSettings::from_map(&environment(&dir)).unwrap();
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let script = format!(
            r#"trap 'test -f "{}" && echo spooled > "{}"; exit 0' TERM; sleep 30 & wait"#,
            files.spool.display(),
            dir.join("seen-at-term").display()
        );
        let stop = Arc::new(AtomicBool::new(false));
        let setter = Arc::clone(&stop);
        let timer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(700));
            setter.store(true, Ordering::SeqCst);
        });
        let recorder = recorder(&files);
        let end = launch_with_stop(&settings, &sh(&script), &recorder, Some(stop)).unwrap();
        timer.join().unwrap();
        assert_eq!(end.state, "cancelled");
        assert!(
            dir.join("seen-at-term").exists(),
            "the spool was not on disk at SIGTERM"
        );
        assert_eq!(
            recorder.events.borrow().last().map(String::as_str),
            Some("deliver sign_1abc cancelled spooled=true")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_log_stops_at_its_cap_with_one_marker() {
        let dir = scratch("log");
        let path = dir.join("launcher.log");
        let mut log = LaunchLog::with_cap(&path, 64);
        for _ in 0..10 {
            log.line("twenty bytes of text");
        }
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            text.len() <= 64 + "log limit reached\n".len(),
            "{}",
            text.len()
        );
        assert!(text.ends_with("log limit reached\n"), "{text}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_vendor_without_a_result_is_rejected_as_failed() {
        let dir = scratch("no-result");
        let settings = LauncherSettings::from_map(&environment(&dir)).unwrap();
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let recorder = recorder(&files);
        let vendor = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 3".to_string(),
        ];
        let end = launch(&settings, &vendor, &recorder).unwrap();
        assert_eq!(end.state, "failed");
        assert_eq!(
            recorder.events.borrow().last().map(String::as_str),
            Some("deliver sign_1abc failed spooled=true")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A hand-off server in a short directory of its own, since `sun_path` holds 104 bytes.
    fn serve(tag: &str, settings: &mut LauncherSettings, credential: Credential) -> HandoffServer {
        let root = PathBuf::from(format!("/tmp/thl-{tag}-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        let dirs = AgentDirs::new(root).unwrap();
        fs::create_dir_all(dirs.spec_dir()).unwrap();
        let server = HandoffServer::start(
            &dirs,
            current_uid(),
            &settings.env.session_name,
            &settings.env.session_secret,
            credential,
        )
        .unwrap();
        settings.credential_socket = Some(server.path().to_path_buf());
        settings.core_uid = Some(current_uid());
        server
    }

    /// Every file the launcher leaves, and its own report, must be free of the credential.
    fn assert_nowhere(dir: &Path, end: &LaunchEnd, needle: &str) {
        assert!(!format!("{end:?} {end}").contains(needle));
        let mut stack = vec![dir.to_path_buf()];
        let mut examined = 0_u32;
        while let Some(next) = stack.pop() {
            for entry in fs::read_dir(&next).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.file_name().is_some_and(|name| name != "env") {
                    examined = examined.saturating_add(1);
                    let bytes = fs::read(&path).unwrap();
                    assert!(
                        !String::from_utf8_lossy(&bytes).contains(needle),
                        "{} holds the credential",
                        path.display()
                    );
                }
            }
        }
        assert!(examined >= 4, "only {examined} files examined");
    }

    #[test]
    fn a_handed_claude_token_reaches_the_vendor_environment_and_no_file() {
        let dir = scratch("claude-token");
        let mut settings = LauncherSettings::from_map(&environment(&dir)).unwrap();
        let credential =
            Credential::parse(CredentialVendor::Claude, CLAUDE_TOKEN.as_bytes()).unwrap();
        let server = serve("claude", &mut settings, credential);
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let result = r#"{"state":"failed","envelope":null}"#;
        let vendor = vendor_script(&files.lease, result, &dir);
        let end = launch(&settings, &vendor, &recorder(&files)).unwrap();
        assert_eq!(end.state, "failed");
        assert_eq!(server.finish(), HandoffOutcome::Answered);
        let env = fs::read_to_string(dir.join("env")).unwrap();
        assert!(
            env.lines()
                .any(|line| line == format!("{CLAUDE_TOKEN_ENV}={CLAUDE_TOKEN}")),
            "{env}"
        );
        assert!(!env.contains("TYCHO_CREDENTIAL_SOCKET"), "{env}");
        assert_nowhere(&dir, &end, CLAUDE_TOKEN);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_codex_session_gets_a_private_home_that_is_gone_when_it_ends() {
        let dir = scratch("codex-home");
        let mut map = environment(&dir);
        map.insert(
            ENV_SESSION_NAME.to_string(),
            "cf7a.wu03.wrk.codex.a1f3".to_string(),
        );
        let mut settings = LauncherSettings::from_map(&map).unwrap();
        let credential = Credential::parse(CredentialVendor::Codex, CODEX_AUTH.as_bytes()).unwrap();
        let server = serve("codex", &mut settings, credential);
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let script = format!(
            r#"stat -f '%Lp' "$CODEX_HOME" > "{0}/home-mode"; stat -f '%Lp' "$CODEX_HOME/auth.json" > "{0}/auth-mode"; cmp -s "$CODEX_HOME/auth.json" "{0}/expected" && echo same > "{0}/auth-same"; mkdir -p "$CODEX_HOME/sessions/x"; echo rollout > "$CODEX_HOME/sessions/x/r.jsonl"; /usr/bin/env > "{0}/env"; printf '{{"state":"failed","envelope":null}}' > "$TYCHO_RESULT_FILE""#,
            dir.display()
        );
        fs::write(dir.join("expected"), CODEX_AUTH).unwrap();
        let end = launch(&settings, &sh(&script), &recorder(&files)).unwrap();
        fs::remove_file(dir.join("expected")).unwrap();
        assert_eq!(end.state, "failed");
        assert_eq!(server.finish(), HandoffOutcome::Answered);
        assert_eq!(
            fs::read_to_string(dir.join("home-mode")).unwrap().trim(),
            "700"
        );
        assert_eq!(
            fs::read_to_string(dir.join("auth-mode")).unwrap().trim(),
            "600"
        );
        assert!(
            dir.join("auth-same").exists(),
            "auth.json is not the core's copy"
        );
        let home = files.spool_dir.join(CODEX_HOME_DIR);
        let env = fs::read_to_string(dir.join("env")).unwrap();
        assert!(
            env.contains(&format!("{CODEX_HOME_ENV}={}", home.display())),
            "{env}"
        );
        assert!(!home.exists(), "the Codex home outlived the session");
        assert_nowhere(&dir, &end, "test-refresh-credential");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_cancelled_codex_session_loses_its_home_before_the_vendor_is_stopped() {
        let dir = scratch("codex-cancel");
        let mut map = environment(&dir);
        map.insert(
            ENV_SESSION_NAME.to_string(),
            "cf7a.wu03.wrk.codex.a1f4".to_string(),
        );
        let mut settings = LauncherSettings::from_map(&map).unwrap();
        let credential = Credential::parse(CredentialVendor::Codex, CODEX_AUTH.as_bytes()).unwrap();
        let server = serve("cancel", &mut settings, credential);
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let script = format!(
            r#"trap 'test -e "$CODEX_HOME" || echo gone > "{}"; exit 0' TERM; sleep 30 & wait"#,
            dir.join("gone-at-term").display()
        );
        let stop = Arc::new(AtomicBool::new(false));
        let setter = Arc::clone(&stop);
        let timer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(700));
            setter.store(true, Ordering::SeqCst);
        });
        let end = launch_with_stop(&settings, &sh(&script), &recorder(&files), Some(stop)).unwrap();
        timer.join().unwrap();
        drop(server.finish());
        assert_eq!(end.state, "cancelled");
        assert!(
            dir.join("gone-at-term").exists(),
            "the Codex home was there at SIGTERM"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_credential_from_the_core_means_no_vendor_and_an_inbox_state() {
        let dir = scratch("no-credential");
        let mut settings = LauncherSettings::from_map(&environment(&dir)).unwrap();
        settings.credential_socket = Some(dir.join("absent.cred"));
        settings.core_uid = Some(current_uid());
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let vendor = vec![
            "/usr/bin/touch".to_string(),
            dir.join("ran").display().to_string(),
        ];
        let recorder = recorder(&files);
        let end = launch(&settings, &vendor, &recorder).unwrap();
        assert_eq!(
            end.state,
            String::from(ExitState::from_wire(CREDENTIAL_UNAVAILABLE))
        );
        assert!(end.state.ends_with(CREDENTIAL_UNAVAILABLE), "{}", end.state);
        assert!(
            !dir.join("ran").exists(),
            "the vendor ran without its credential"
        );
        assert!(
            files.lease.exists(),
            "the lease is written whatever the hand-off did"
        );
        assert_eq!(
            ExitState::from_wire(CREDENTIAL_UNAVAILABLE).disposition(),
            tycho_types::exit::Disposition::Inbox
        );
        let log = fs::read_to_string(&files.log).unwrap();
        assert!(log.contains("no credential, vendor not started"), "{log}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_lease_directory_means_nothing_runs() {
        let dir = std::env::temp_dir().join(format!("tycho-launch-nolease-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let settings = LauncherSettings::from_map(&environment(&dir)).unwrap();
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let recorder = recorder(&files);
        let vendor = vec![
            "/usr/bin/touch".to_string(),
            dir.join("ran").display().to_string(),
        ];
        assert!(launch(&settings, &vendor, &recorder).is_err());
        assert!(recorder.events.borrow().is_empty());
        assert!(!dir.join("ran").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}

//! `tycho launch`, the process that runs one vendor session.
//!
//! It writes the lease first, runs the vendor in its own process group with its output in
//! bounded files, heartbeats, decodes the exit, spools the result, delivers it, and ends its
//! own zmx session.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;
use serde::{Deserialize, Serialize};
use tycho_types::envelope::StatusPayload;
use tycho_types::launcher::{
    EnvError, IdempotencyKey, LauncherEnv, ENV_AWAITABLE_ID, ENV_SESSION_SECRET,
    ENV_VALUE_MAX_BYTES, SEQUENCE_MAX,
};
use tycho_types::lease::Lease;
use tycho_types::service::Service;
use tycho_types::session::SessionName;

use crate::config::{AgentDirs, AGENT_DIR_ENV, ZMX_ENV};
use crate::exit_decode::{
    decode_exit, read_progress, read_result_file, status_payload, ChildEnd, Decoded, Stop,
};
use crate::launch_probe::LAUNCH_PROBE_SERVICE;
use crate::process::{now_unix_ms, send};
use crate::spool::{
    read_bounded, spool_then_deliver, write_durable, Ack, Delivery, HeartbeatSend, Ingress,
    SpoolRecord, SPOOL_FILE, SPOOL_SCHEMA_VERSION,
};
use crate::zmx::Zmx;

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// Three missed heartbeats make a lease stale.
pub const LEASE_FRESH_MS: u64 = 30_000;
pub const SUPERVISE_POLL: Duration = Duration::from_millis(250);
pub const WALL_CLOCK_MAX: Duration = Duration::from_secs(86_400);
const SUPERVISE_POLLS_MAX: u64 = 345_600;
pub const OUTPUT_FILE_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const LOG_FILE_MAX_BYTES: u64 = 1024 * 1024;
const SEQUENCE_FILE_MAX_BYTES: usize = 32;
const TERM_GRACE_POLLS_MAX: u32 = 20;
pub const HEARTBEAT_TARGET_ENV: &str = "TYCHO_HEARTBEAT_TARGET";
pub const PROGRESS_FILE_ENV: &str = "TYCHO_PROGRESS_FILE";
pub const RESULT_FILE_ENV: &str = "TYCHO_RESULT_FILE";
pub const SPOOL_DIR_ENV: &str = "TYCHO_SPOOL_DIR";
pub const VENDOR_ARGS_MAX: usize = 64;
pub const VENDOR_ARG_MAX_BYTES: usize = 4096;
pub const EXIT_ACKNOWLEDGED: i32 = 0;
pub const EXIT_UNDELIVERED: i32 = 1;
pub const EXIT_REFUSED_TO_START: i32 = 2;

/// Where heartbeats go; anything other than these two names is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatTarget {
    Session,
    /// The launcher tests' stand-in, bound in the endpoint beside the services.
    LaunchProbe,
}

impl HeartbeatTarget {
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::LaunchProbe => "launch_probe",
        }
    }

    #[must_use]
    pub const fn service(self) -> &'static str {
        match self {
            Self::Session => Service::Session.name(),
            Self::LaunchProbe => LAUNCH_PROBE_SERVICE,
        }
    }
}

#[derive(Debug)]
pub enum SettingsError {
    Env(EnvError),
    Missing(&'static str),
    TooLong(&'static str),
    NotAbsolute(&'static str),
    HeartbeatTarget,
    VendorArguments(String),
    Spec(String),
}

impl fmt::Display for SettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(error) => write!(formatter, "{error}"),
            Self::Missing(name) => write!(formatter, "{name} is not set"),
            Self::TooLong(name) => {
                write!(formatter, "{name} exceeds {ENV_VALUE_MAX_BYTES} bytes")
            }
            Self::NotAbsolute(name) => write!(formatter, "{name} is not an absolute path"),
            Self::HeartbeatTarget => write!(
                formatter,
                "{HEARTBEAT_TARGET_ENV} is neither `session` nor `launch_probe`"
            ),
            Self::VendorArguments(reason) => write!(formatter, "vendor command: {reason}"),
            Self::Spec(reason) => write!(formatter, "launch spec: {reason}"),
        }
    }
}

/// Everything the launcher reads from its environment, parsed before anything runs.
#[derive(Debug, Clone)]
pub struct LauncherSettings {
    pub env: LauncherEnv,
    pub dirs: AgentDirs,
    pub zmx: PathBuf,
    pub heartbeat: HeartbeatTarget,
    /// Every pair besides the awaitable id and the secret, which the vendor never sees.
    pub vendor_env: Vec<(String, String)>,
}

fn absolute(
    environment: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<PathBuf, SettingsError> {
    let value = environment.get(name).ok_or(SettingsError::Missing(name))?;
    if value.len() > ENV_VALUE_MAX_BYTES {
        return Err(SettingsError::TooLong(name));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(SettingsError::NotAbsolute(name));
    }
    Ok(path)
}

impl LauncherSettings {
    pub fn from_map(environment: &BTreeMap<String, String>) -> Result<Self, SettingsError> {
        let env = LauncherEnv::from_map(environment).map_err(SettingsError::Env)?;
        let dirs = AgentDirs::new(absolute(environment, AGENT_DIR_ENV)?)
            .map_err(|_| SettingsError::NotAbsolute(AGENT_DIR_ENV))?;
        let zmx = absolute(environment, ZMX_ENV)?;
        let heartbeat = match environment.get(HEARTBEAT_TARGET_ENV).map(String::as_str) {
            None | Some("session") => HeartbeatTarget::Session,
            Some("launch_probe") => HeartbeatTarget::LaunchProbe,
            Some(_) => return Err(SettingsError::HeartbeatTarget),
        };
        let vendor_env = environment
            .iter()
            .filter(|(name, _)| *name != ENV_AWAITABLE_ID && *name != ENV_SESSION_SECRET)
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        Ok(Self {
            env,
            dirs,
            zmx,
            heartbeat,
            vendor_env,
        })
    }
}

/// The launch spec file name in the session's spool directory.
pub const SPEC_FILE: &str = "launch.json";
pub const SPEC_FILE_MAX_BYTES: usize = 65_536;
pub const SPEC_ENV_MAX: usize = 64;
pub const SPEC_SCHEMA_VERSION: u32 = 1;

/// What a spawn step hands the launcher through a private file.
///
/// Not the typed command line: a pty in canonical mode truncates a typed line at 1024 bytes,
/// and the scrollback keeps whatever was typed, the session secret included.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSpec {
    pub schema_version: u32,
    pub environment: BTreeMap<String, String>,
    pub vendor: Vec<String>,
}

impl fmt::Debug for LaunchSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchSpec")
            .field("environment", &self.environment.keys().collect::<Vec<_>>())
            .field("vendor", &self.vendor)
            .finish_non_exhaustive()
    }
}

impl LaunchSpec {
    /// Checks every bound and parses the settings; the spec file is never trusted unchecked.
    pub fn settings(&self) -> Result<LauncherSettings, SettingsError> {
        if self.schema_version != SPEC_SCHEMA_VERSION {
            return Err(SettingsError::Spec(format!(
                "schema version {}",
                self.schema_version
            )));
        }
        if self.environment.len() > SPEC_ENV_MAX {
            return Err(SettingsError::Spec(format!(
                "{} environment entries; maximum is {SPEC_ENV_MAX}",
                self.environment.len()
            )));
        }
        if let Some((name, _)) = self.environment.iter().find(|(name, value)| {
            name.len() > ENV_VALUE_MAX_BYTES || value.len() > ENV_VALUE_MAX_BYTES
        }) {
            return Err(SettingsError::Spec(format!(
                "{name} exceeds {ENV_VALUE_MAX_BYTES} bytes"
            )));
        }
        check_vendor(&self.vendor)?;
        LauncherSettings::from_map(&self.environment)
    }
}

/// Reads and checks the spec, then removes it so the secret does not outlive the read.
pub fn take_spec(path: &Path) -> Result<(LauncherSettings, Vec<String>), SettingsError> {
    let bytes = read_bounded(path, SPEC_FILE_MAX_BYTES)
        .map_err(|error| SettingsError::Spec(format!("{}: {error}", path.display())))?
        .ok_or_else(|| SettingsError::Spec(format!("{} does not exist", path.display())))?;
    let spec: LaunchSpec =
        serde_json::from_slice(&bytes).map_err(|error| SettingsError::Spec(error.to_string()))?;
    let settings = spec.settings()?;
    fs::remove_file(path)
        .map_err(|error| SettingsError::Spec(format!("{}: {error}", path.display())))?;
    Ok((settings, spec.vendor))
}

pub fn check_vendor(vendor: &[String]) -> Result<(), SettingsError> {
    if vendor.is_empty() || vendor.len() > VENDOR_ARGS_MAX {
        return Err(SettingsError::VendorArguments(format!(
            "{} arguments; expected 1..={VENDOR_ARGS_MAX}",
            vendor.len()
        )));
    }
    if let Some(long) = vendor.iter().find(|word| word.len() > VENDOR_ARG_MAX_BYTES) {
        return Err(SettingsError::VendorArguments(format!(
            "an argument of {} bytes exceeds {VENDOR_ARG_MAX_BYTES}",
            long.len()
        )));
    }
    Ok(())
}

/// Above any vendor's context window; a larger report is a defect, not a measurement.
pub const CONTEXT_TOKENS_MAX: u64 = 10_000_000;

/// The `Session/<name>/heartbeat` input. Restate does not hand the idempotency key to the
/// handler, so the body repeats the sequence and the handler ignores any it has seen.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatBody {
    pub secret: String,
    pub sequence: u64,
    pub status: StatusPayload,
    pub context_tokens: u64,
}

impl fmt::Debug for HeartbeatBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeartbeatBody")
            .field("secret", &"redacted")
            .field("sequence", &self.sequence)
            .field("status", &self.status)
            .field("context_tokens", &self.context_tokens)
            .finish()
    }
}

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
    let previous = match read_bounded(path, SEQUENCE_FILE_MAX_BYTES).map_err(SequenceError::Io)? {
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
}

impl LaunchLog {
    #[must_use]
    pub fn open(path: &Path) -> Self {
        let file = OpenOptions::new().create(true).append(true).open(path).ok();
        Self { file, written: 0 }
    }

    pub fn line(&mut self, text: &str) {
        if self.file.is_none() {
            return;
        }
        let line = format!("{} {text}\n", now_unix_ms());
        let length = u64::try_from(line.len()).unwrap_or(u64::MAX);
        let next = self.written.saturating_add(length);
        let line = if next > LOG_FILE_MAX_BYTES {
            self.file = None;
            "log limit reached\n".to_string()
        } else {
            self.written = next;
            line
        };
        if let Some(file) = self.file.as_mut() {
            if file.write_all(line.as_bytes()).is_err() {
                self.file = None;
            }
        }
    }
}

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
            Ok(delivery) => write!(formatter, "exit state {}: {delivery:?}", self.state),
            Err(error) => write!(formatter, "exit state {}: not spooled: {error}", self.state),
        }
    }
}

/// The running launcher: its settings, files, lease and the ingress it reports to.
struct Run<'a, I: Ingress> {
    settings: &'a LauncherSettings,
    files: SessionFiles,
    lease: Lease,
    ingress: &'a I,
    log: LaunchLog,
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
        settings.env.awaitable_id.clone(),
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
    let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
    let lease = write_first_lease(settings, &files)?;
    let spool_ready = fs::create_dir_all(&files.spool_dir);
    let mut run = Run {
        settings,
        log: LaunchLog::open(&files.log),
        files,
        lease,
        ingress,
    };
    let decoded = match spool_ready
        .map_err(|error| error.to_string())
        .and_then(|()| watch_signals().map_err(|error| error.to_string()))
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
        let (end, stop) = match self.start_vendor(vendor) {
            Ok(mut child) => self.supervise(&mut child, stop_flag),
            Err(error) => {
                self.log.line(&format!("vendor did not start: {error}"));
                (ChildEnd::NotStarted, Stop::None)
            }
        };
        self.log
            .line(&format!("vendor ended: {end:?}, stop: {stop:?}"));
        decode_exit(stop, end, read_result_file(&self.files.result), &session)
    }

    fn start_vendor(&mut self, vendor: &[String]) -> io::Result<Child> {
        let (program, arguments) = vendor
            .split_first()
            .ok_or_else(|| io::Error::other("empty vendor command"))?;
        let child = Command::new(program)
            .args(arguments)
            .env_remove(ENV_SESSION_SECRET)
            .env_remove(ENV_AWAITABLE_ID)
            .envs(
                self.settings
                    .vendor_env
                    .iter()
                    .map(|(name, value)| (name, value)),
            )
            .env(PROGRESS_FILE_ENV, &self.files.progress)
            .env(RESULT_FILE_ENV, &self.files.result)
            .env(SPOOL_DIR_ENV, &self.files.spool_dir)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(File::create(&self.files.stdout)?)
            .stderr(File::create(&self.files.stderr)?)
            .spawn()?;
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

    fn supervise(&mut self, child: &mut Child, stop_flag: &AtomicBool) -> (ChildEnd, Stop) {
        let mut last_beat: Option<Instant> = None;
        for _ in 0..SUPERVISE_POLLS_MAX {
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
                return (self.terminate(child), Stop::Cancelled);
            }
            if self.output_too_large() {
                return (self.terminate(child), Stop::OutputTooLarge);
            }
            if last_beat.is_none_or(|beat| beat.elapsed() >= HEARTBEAT_INTERVAL) {
                self.beat();
                last_beat = Some(Instant::now());
            }
            thread::sleep(SUPERVISE_POLL);
        }
        (self.terminate(child), Stop::WallClock)
    }

    fn output_too_large(&self) -> bool {
        [&self.files.stdout, &self.files.stderr].iter().any(|path| {
            fs::metadata(path).is_ok_and(|metadata| metadata.len() > OUTPUT_FILE_MAX_BYTES)
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
        let body = HeartbeatBody {
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

    fn finish(&mut self, decoded: Decoded) -> LaunchEnd {
        let state = String::from(decoded.state.clone());
        let record = SpoolRecord {
            schema_version: SPOOL_SCHEMA_VERSION,
            session: self.settings.env.session_name.clone(),
            awaitable_id: self.settings.env.awaitable_id.clone(),
            state: decoded.state,
            envelope: decoded.envelope,
        };
        let spool = self.files.spool.clone();
        let ingress = self.ingress;
        let delivery = spool_then_deliver(ingress, &spool, &record, &mut |delay| {
            self.wait_renewing(delay);
        })
        .map_err(|error| error.to_string());
        self.log.line(&format!("exit state {state}: {delivery:?}"));
        LaunchEnd { state, delivery }
    }

    /// Sleeps in heartbeat-sized steps, renewing the lease, so a launcher still delivering
    /// is adopted rather than re-queued.
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
mod tests {
    use super::*;
    use crate::spool::{Resolution, ACKNOWLEDGED_SUFFIX};
    use std::cell::RefCell;
    use tycho_types::launcher::{AwaitableId, ENV_SESSION_NAME};

    const NAME: &str = "cf7a.wu03.wrk.claude.a1f3";
    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn environment(agent_dir: &Path) -> BTreeMap<String, String> {
        BTreeMap::from([
            (ENV_AWAITABLE_ID.to_string(), "sign_1abc".to_string()),
            (ENV_SESSION_SECRET.to_string(), SECRET.to_string()),
            (ENV_SESSION_NAME.to_string(), NAME.to_string()),
            (AGENT_DIR_ENV.to_string(), agent_dir.display().to_string()),
            (ZMX_ENV.to_string(), "/usr/bin/true".to_string()),
        ])
    }

    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tycho-launch-{test}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        fs::create_dir_all(dir.join(crate::config::LEASE_DIR)).unwrap();
        dir
    }

    #[test]
    fn settings_fail_closed() {
        let dir = Path::new("/agent");
        assert!(LauncherSettings::from_map(&environment(dir)).is_ok());
        let mut missing = environment(dir);
        missing.remove(AGENT_DIR_ENV);
        assert!(matches!(
            LauncherSettings::from_map(&missing),
            Err(SettingsError::Missing(AGENT_DIR_ENV))
        ));
        let mut relative = environment(dir);
        relative.insert(ZMX_ENV.to_string(), "zmx".to_string());
        assert!(matches!(
            LauncherSettings::from_map(&relative),
            Err(SettingsError::NotAbsolute(ZMX_ENV))
        ));
        let mut long = environment(dir);
        long.insert(
            ZMX_ENV.to_string(),
            format!("/{}", "z".repeat(ENV_VALUE_MAX_BYTES)),
        );
        assert!(matches!(
            LauncherSettings::from_map(&long),
            Err(SettingsError::TooLong(ZMX_ENV))
        ));
        let mut target = environment(dir);
        target.insert(HEARTBEAT_TARGET_ENV.to_string(), "Session".to_string());
        assert!(matches!(
            LauncherSettings::from_map(&target),
            Err(SettingsError::HeartbeatTarget)
        ));
        let mut secret = environment(dir);
        secret.remove(ENV_SESSION_SECRET);
        assert!(matches!(
            LauncherSettings::from_map(&secret),
            Err(SettingsError::Env(_))
        ));
        assert!(check_vendor(&[]).is_err());
        assert!(check_vendor(&["x".repeat(VENDOR_ARG_MAX_BYTES + 1)]).is_err());
        assert!(check_vendor(&vec!["x".to_string(); VENDOR_ARGS_MAX + 1]).is_err());
    }

    #[test]
    fn a_spec_is_checked_then_removed() {
        let dir = scratch("spec");
        let path = dir.join(SPEC_FILE);
        assert!(matches!(take_spec(&path), Err(SettingsError::Spec(_))));
        let spec = LaunchSpec {
            schema_version: SPEC_SCHEMA_VERSION,
            environment: environment(&dir),
            vendor: vec!["/bin/true".to_string()],
        };
        fs::write(&path, serde_json::to_vec(&spec).unwrap()).unwrap();
        let (settings, vendor) = take_spec(&path).unwrap();
        assert_eq!(vendor, spec.vendor);
        assert!(!path.exists(), "the spec outlived its read");
        assert!(settings
            .vendor_env
            .iter()
            .all(|(name, _)| name != ENV_SESSION_SECRET && name != ENV_AWAITABLE_ID));
        assert!(!format!("{spec:?}").contains(SECRET));
        let mut wide = spec.clone();
        for index in 0..=SPEC_ENV_MAX {
            wide.environment
                .insert(format!("EXTRA_{index}"), "x".to_string());
        }
        let mut versioned = spec.clone();
        versioned.schema_version = 2;
        let mut no_vendor = spec;
        no_vendor.vendor.clear();
        for refused in [wide, versioned, no_vendor] {
            fs::write(&path, serde_json::to_vec(&refused).unwrap()).unwrap();
            assert!(take_spec(&path).is_err());
            assert!(path.exists(), "a refused spec is kept for the operator");
        }
        fs::write(&path, "x".repeat(SPEC_FILE_MAX_BYTES + 1)).unwrap();
        assert!(take_spec(&path).is_err());
        fs::write(
            &path,
            r#"{"schema_version":1,"environment":{},"vendor":["/bin/true"],"extra":1}"#,
        )
        .unwrap();
        assert!(take_spec(&path).is_err());
        fs::remove_dir_all(&dir).unwrap();
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
    fn heartbeat_body_matches_the_session_input_shape() {
        let (status, _) =
            crate::exit_decode::status_payload(&crate::exit_decode::Progress::Absent, 1).unwrap();
        let body = HeartbeatBody {
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
        let back: HeartbeatBody = serde_json::from_value(value).unwrap();
        assert_eq!(back, body);
    }

    /// Records each ingress call with what was on disk at that moment.
    struct Recorder {
        files: SessionFiles,
        events: RefCell<Vec<String>>,
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
            let body: HeartbeatBody = serde_json::from_str(&call.body).unwrap();
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

    fn vendor_script(lease: &Path, result: &str) -> Vec<String> {
        let script = r#"test -f "$1" && echo seen > "$TYCHO_SPOOL_DIR/lease-seen"; sleep 0.4; printf '%s' "$2" > "$TYCHO_RESULT_FILE""#;
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            script.to_string(),
            "sh".to_string(),
            lease.display().to_string(),
            result.to_string(),
        ]
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
        let vendor = vendor_script(&files.lease, &result.to_string());
        let recorder = Recorder {
            files: files.clone(),
            events: RefCell::new(Vec::new()),
        };
        let end = launch(&settings, &vendor, &recorder).unwrap();
        assert_eq!(end.state, "completed");
        assert_eq!(end.exit_code(), EXIT_ACKNOWLEDGED);
        assert!(
            files.spool_dir.join("lease-seen").exists(),
            "the vendor ran before the lease existed"
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
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_vendor_without_a_result_is_rejected_as_failed() {
        let dir = scratch("no-result");
        let settings = LauncherSettings::from_map(&environment(&dir)).unwrap();
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let recorder = Recorder {
            files,
            events: RefCell::new(Vec::new()),
        };
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

    #[test]
    fn no_lease_directory_means_nothing_runs() {
        let dir = std::env::temp_dir().join(format!("tycho-launch-nolease-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let settings = LauncherSettings::from_map(&environment(&dir)).unwrap();
        let files = SessionFiles::new(&settings.dirs, &settings.env.session_name);
        let recorder = Recorder {
            files,
            events: RefCell::new(Vec::new()),
        };
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

//! The vendor credential's one trip from the core to a launcher: a Unix socket the spawn
//! step binds in the core's spec directory for one session and serves until the launcher's
//! lease appears.
//!
//! The core answers only a peer of the agent's uid whose pid is the launcher's as `zmx list`
//! reports it, and which names the session and its secret; it answers once, and then removes
//! the socket. The session secret sits in a spec any process of the agent's uid can read, so the
//! uid and the secret alone would answer any of them. A connection that arrives before the spawn
//! step has read the launcher's pid is held until it has. The launcher talks only to a peer of
//! the core's uid. Nothing here writes the credential to a file, an argument or a log.

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tycho_types::launcher::SessionSecret;
use tycho_types::session::{SessionName, SOCKET_PATH_MAX_BYTES};

use crate::config::AgentDirs;
use crate::credentials::{wipe, Credential, CredentialVendor, CODEX_AUTH_MAX_BYTES};
use crate::vendors::claude_control::peer_uid;

/// The spec's name for the socket path; the launcher keeps it from the vendor.
pub const CREDENTIAL_SOCKET_ENV: &str = "TYCHO_CREDENTIAL_SOCKET";
const SOCKET_SUFFIX: &str = ".cred";
/// The agent's group connects; nobody else can reach the core-only spec directory.
const SOCKET_MODE: u32 = 0o660;
pub const REQUEST_MAX_BYTES: usize = 1024;
pub const ANSWER_MAX_BYTES: usize = CODEX_AUTH_MAX_BYTES + 1024;
/// Connections refused before the server gives up on the session.
pub const REFUSALS_MAX: u32 = 8;
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// The server's own bound: the spawn step stops it sooner, once the lease appears.
pub const SERVE_POLLS_MAX: u32 = 600;
const STREAM_TIMEOUT: Duration = Duration::from_secs(2);
/// How long the launcher waits for its answer: the server may hold its connection until the
/// spawn step has read the launcher's pid from `zmx list`.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the server holds a connection for the launcher's pid: the launcher's answer wait,
/// less the stream timeout the request and the answer each get after it.
pub const HOLD_MAX: Duration = ANSWER_TIMEOUT
    .saturating_sub(STREAM_TIMEOUT)
    .saturating_sub(STREAM_TIMEOUT);

/// Pid 0 is never a process `zmx list` reports, and stands for a pid not yet read.
const LAUNCHER_PID_UNKNOWN: u32 = 0;

/// Hex digits of the session name's SHA-256 in the socket's name.
const SOCKET_NAME_HEX: usize = 16;

/// Where one session's hand-off socket lives: beside its spec, in the core-only directory,
/// named by a digest so the longest session name still fits `sun_path`.
#[must_use]
pub fn socket_path(dirs: &AgentDirs, session: &SessionName) -> PathBuf {
    let digest = Sha256::digest(session.to_string().as_bytes());
    let hex: String = digest
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .take(SOCKET_NAME_HEX)
        .map(|nibble| char::from_digit(u32::from(nibble), 16).unwrap_or('0'))
        .collect();
    dirs.spec_dir().join(format!("{hex}{SOCKET_SUFFIX}"))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    session: String,
    secret: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Answer {
    vendor: String,
    value: String,
}

/// How a session's hand-off ended, as the core logs it; never the credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffOutcome {
    Answered,
    /// Stopped or out of polls before a peer asked correctly.
    NotAsked {
        refused: u32,
    },
    /// The refusal cap was reached; the server stopped answering.
    TooManyRefusals,
    Failed(String),
}

/// Why one connection was not answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    PeerUid {
        found: u32,
    },
    PeerUnknown(String),
    /// The peer is not the process `zmx list` reports for the session.
    PeerPid {
        found: u32,
        expected: u32,
    },
    /// The spawn step did not read the launcher's pid within the hold.
    LauncherUnknown,
    Request(String),
    Session,
    Secret,
}

#[derive(Debug)]
pub enum HandoffError {
    PathTooLong(usize),
    Bind(PathBuf, io::Error),
    Connect(PathBuf, io::Error),
    PeerUid {
        found: u32,
        expected: u32,
    },
    Io(io::Error),
    TooLarge,
    Answer(String),
    Vendor {
        expected: CredentialVendor,
        found: String,
    },
    Credential(String),
}

impl fmt::Display for HandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathTooLong(length) => write!(
                formatter,
                "the credential socket path is {length} bytes; the limit is {SOCKET_PATH_MAX_BYTES}"
            ),
            Self::Bind(path, error) => write!(formatter, "cannot bind {}: {error}", path.display()),
            Self::Connect(path, error) => {
                write!(formatter, "cannot connect to {}: {error}", path.display())
            }
            Self::PeerUid { found, expected } => write!(
                formatter,
                "the credential socket is served by uid {found}, not the core's uid {expected}"
            ),
            Self::Io(error) => write!(formatter, "credential hand-off: {error}"),
            Self::TooLarge => write!(formatter, "the answer exceeds {ANSWER_MAX_BYTES} bytes"),
            Self::Answer(why) => write!(formatter, "the answer does not decode: {why}"),
            Self::Vendor { expected, found } => write!(
                formatter,
                "the answer carries a {found:?} credential, not {expected}"
            ),
            Self::Credential(why) => write!(formatter, "{why}"),
        }
    }
}

fn check_path(path: &Path) -> Result<(), HandoffError> {
    let length = path.as_os_str().len();
    if length > SOCKET_PATH_MAX_BYTES {
        return Err(HandoffError::PathTooLong(length));
    }
    Ok(())
}

/// Reads at most `max` bytes, then one more to tell a full read from an oversized one.
fn read_bounded(stream: &mut UnixStream, max: usize) -> io::Result<Option<Vec<u8>>> {
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    stream.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        bytes.fill(0);
        return Ok(None);
    }
    Ok(Some(bytes))
}

/// The pid of the process at the other end of a connected Unix socket, as the kernel recorded
/// it at connect.
#[cfg(target_os = "macos")]
pub fn peer_pid(stream: &UnixStream) -> io::Result<u32> {
    let pid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerPid)
        .map_err(io::Error::from)?;
    u32::try_from(pid).map_err(|_| io::Error::other(format!("peer pid {pid}")))
}

/// The pid of the process at the other end of a connected Unix socket, as the kernel recorded
/// it at connect.
#[cfg(target_os = "linux")]
pub fn peer_pid(stream: &UnixStream) -> io::Result<u32> {
    let pid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map(|credentials| credentials.pid())
        .map_err(io::Error::from)?;
    u32::try_from(pid).map_err(|_| io::Error::other(format!("peer pid {pid}")))
}

/// What the server answers with, and to whom.
struct Grant {
    agent_uid: u32,
    /// The launcher's pid from `zmx list`, `LAUNCHER_PID_UNKNOWN` until the spawn step reads it.
    launcher_pid: Arc<AtomicU32>,
    hold: Duration,
    session: SessionName,
    secret: SessionSecret,
    credential: Credential,
}

impl Grant {
    /// The launcher's pid, waiting for the spawn step within the hold; `None` past it or once
    /// the server is told to stop.
    fn launcher_pid(&self, stop: &AtomicBool) -> Option<u32> {
        let polls = self
            .hold
            .as_millis()
            .checked_div(ACCEPT_POLL.as_millis())
            .unwrap_or(0);
        for _ in 0..=polls {
            let pid = self.launcher_pid.load(Ordering::SeqCst);
            if pid != LAUNCHER_PID_UNKNOWN {
                return Some(pid);
            }
            if stop.load(Ordering::SeqCst) {
                return None;
            }
            thread::sleep(ACCEPT_POLL);
        }
        None
    }

    /// Answers one connection, or names why it was refused.
    fn answer(&self, stream: &mut UnixStream, stop: &AtomicBool) -> Result<(), Refusal> {
        let found = peer_uid(stream).map_err(|error| Refusal::PeerUnknown(error.to_string()))?;
        if found != self.agent_uid {
            return Err(Refusal::PeerUid { found });
        }
        let peer = peer_pid(stream).map_err(|error| Refusal::PeerUnknown(error.to_string()))?;
        let expected = self.launcher_pid(stop).ok_or(Refusal::LauncherUnknown)?;
        if peer != expected {
            return Err(Refusal::PeerPid {
                found: peer,
                expected,
            });
        }
        let request = read_bounded(stream, REQUEST_MAX_BYTES)
            .map_err(|error| Refusal::Request(error.to_string()))?
            .ok_or_else(|| Refusal::Request(format!("over {REQUEST_MAX_BYTES} bytes")))?;
        let request: Request = serde_json::from_slice(&request)
            .map_err(|error| Refusal::Request(error.to_string()))?;
        if request.session != self.session.to_string() {
            return Err(Refusal::Session);
        }
        if !self.secret.verify(&request.secret) {
            return Err(Refusal::Secret);
        }
        let answer = Answer {
            vendor: self.credential.vendor().as_str().to_string(),
            value: self.credential.expose().to_string(),
        };
        let encoded = serde_json::to_vec(&answer);
        wipe(answer.value.into_bytes());
        let mut bytes = encoded.map_err(|error| Refusal::Request(error.to_string()))?;
        let written = stream.write_all(&bytes).and_then(|()| stream.flush());
        bytes.fill(0);
        written.map_err(|error| Refusal::Request(error.to_string()))
    }
}

fn configure(stream: &UnixStream, read_timeout: Duration) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(STREAM_TIMEOUT))
}

fn serve_loop(listener: &UnixListener, grant: &Grant, stop: &AtomicBool) -> HandoffOutcome {
    let mut refused: u32 = 0;
    for _ in 0..SERVE_POLLS_MAX {
        if stop.load(Ordering::SeqCst) {
            return HandoffOutcome::NotAsked { refused };
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let answered = configure(&stream, STREAM_TIMEOUT)
                    .map_err(|error| Refusal::Request(error.to_string()))
                    .and_then(|()| grant.answer(&mut stream, stop));
                drop(stream.shutdown(Shutdown::Both));
                if answered.is_ok() {
                    return HandoffOutcome::Answered;
                }
                refused = refused.saturating_add(1);
                if refused >= REFUSALS_MAX {
                    return HandoffOutcome::TooManyRefusals;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(error) => return HandoffOutcome::Failed(error.to_string()),
        }
    }
    HandoffOutcome::NotAsked { refused }
}

/// The core side, alive from before the launcher starts until `finish`.
#[derive(Debug)]
pub struct HandoffServer {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    launcher_pid: Arc<AtomicU32>,
    thread: Option<JoinHandle<HandoffOutcome>>,
}

impl HandoffServer {
    /// Binds the session's socket and serves it on a thread. An entry already at the path
    /// is removed first; only the core writes the spec directory.
    pub fn start(
        dirs: &AgentDirs,
        agent_uid: u32,
        session: &SessionName,
        secret: &SessionSecret,
        credential: Credential,
    ) -> Result<Self, HandoffError> {
        Self::start_holding(dirs, agent_uid, session, secret, credential, HOLD_MAX)
    }

    /// `start` with the hold a connection waits for the launcher's pid.
    pub fn start_holding(
        dirs: &AgentDirs,
        agent_uid: u32,
        session: &SessionName,
        secret: &SessionSecret,
        credential: Credential,
        hold: Duration,
    ) -> Result<Self, HandoffError> {
        let path = socket_path(dirs, session);
        check_path(&path)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(HandoffError::Bind(path, error)),
        }
        let listener =
            UnixListener::bind(&path).map_err(|error| HandoffError::Bind(path.clone(), error))?;
        let prepared = fs::set_permissions(&path, fs::Permissions::from_mode(SOCKET_MODE))
            .and_then(|()| listener.set_nonblocking(true));
        if let Err(error) = prepared {
            drop(fs::remove_file(&path));
            return Err(HandoffError::Bind(path, error));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let launcher_pid = Arc::new(AtomicU32::new(LAUNCHER_PID_UNKNOWN));
        let grant = Grant {
            agent_uid,
            launcher_pid: Arc::clone(&launcher_pid),
            hold,
            session: session.clone(),
            secret: secret.clone(),
            credential,
        };
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || serve_loop(&listener, &grant, &thread_stop));
        Ok(Self {
            path,
            stop,
            launcher_pid,
            thread: Some(thread),
        })
    }

    /// The launcher's pid as `zmx list` reports it under the session's name; the server
    /// answers only a connection from that process.
    pub fn bind_launcher(&self, pid: u32) {
        self.launcher_pid.store(pid, Ordering::SeqCst);
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the server stopped on its own: it answered, or gave up.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Stops serving, removes the socket and reports what happened.
    #[must_use]
    pub fn finish(mut self) -> HandoffOutcome {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> HandoffOutcome {
        self.stop.store(true, Ordering::SeqCst);
        let outcome = self.thread.take().map_or_else(
            || HandoffOutcome::Failed("already finished".to_string()),
            |thread| {
                thread
                    .join()
                    .unwrap_or_else(|_| HandoffOutcome::Failed("the server panicked".to_string()))
            },
        );
        drop(fs::remove_file(&self.path));
        outcome
    }
}

impl Drop for HandoffServer {
    fn drop(&mut self) {
        if self.thread.is_some() {
            drop(self.stop_and_join());
        }
    }
}

/// The launcher side: one request to a socket the core serves, one bounded answer.
pub fn fetch(
    path: &Path,
    core_uid: u32,
    session: &SessionName,
    secret: &SessionSecret,
    vendor: CredentialVendor,
) -> Result<Credential, HandoffError> {
    check_path(path)?;
    let mut stream = UnixStream::connect(path)
        .map_err(|error| HandoffError::Connect(path.to_path_buf(), error))?;
    let found = peer_uid(&stream).map_err(HandoffError::Io)?;
    if found != core_uid {
        return Err(HandoffError::PeerUid {
            found,
            expected: core_uid,
        });
    }
    configure(&stream, ANSWER_TIMEOUT).map_err(HandoffError::Io)?;
    let request = serde_json::to_vec(&Request {
        session: session.to_string(),
        secret: secret.expose().to_string(),
    })
    .map_err(|error| HandoffError::Io(io::Error::other(error.to_string())))?;
    stream.write_all(&request).map_err(HandoffError::Io)?;
    stream.shutdown(Shutdown::Write).map_err(HandoffError::Io)?;
    let mut bytes = read_bounded(&mut stream, ANSWER_MAX_BYTES)
        .map_err(HandoffError::Io)?
        .ok_or(HandoffError::TooLarge)?;
    let decoded = serde_json::from_slice::<Answer>(&bytes).map_err(|error| {
        HandoffError::Answer(format!("line {} column {}", error.line(), error.column()))
    });
    bytes.fill(0);
    let answer = decoded?;
    if answer.vendor != vendor.as_str() {
        return Err(HandoffError::Vendor {
            expected: vendor,
            found: answer.vendor.chars().take(16).collect(),
        });
    }
    let parsed = Credential::parse(vendor, answer.value.as_bytes())
        .map_err(|error| HandoffError::Credential(error.to_string()));
    wipe(answer.value.into_bytes());
    parsed
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use crate::agent_files::current_uid;
    use crate::credentials::tests::{CLAUDE_TOKEN, CODEX_AUTH};

    const NAME: &str = "cf7a.wu03.wrk.claude.a1f3";
    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn dirs(test: &str) -> AgentDirs {
        let root = std::env::temp_dir().join(format!("tho-{test}-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        let dirs = AgentDirs::new(root).unwrap();
        fs::create_dir_all(dirs.spec_dir()).unwrap();
        dirs
    }

    fn session() -> SessionName {
        SessionName::parse(NAME).unwrap()
    }

    fn secret() -> SessionSecret {
        SessionSecret::parse(SECRET).unwrap()
    }

    fn claude() -> Credential {
        Credential::parse(CredentialVendor::Claude, CLAUDE_TOKEN.as_bytes()).unwrap()
    }

    /// A server whose launcher is this test process, as `zmx list` would report it.
    fn started(server: Result<HandoffServer, HandoffError>) -> HandoffServer {
        let server = server.unwrap();
        server.bind_launcher(std::process::id());
        server
    }

    fn fetch_here(path: &Path) -> Result<Credential, HandoffError> {
        fetch(
            path,
            current_uid(),
            &session(),
            &secret(),
            CredentialVendor::Claude,
        )
    }

    #[test]
    fn a_connection_before_the_pid_is_read_is_held_and_answered_once_it_is_the_launcher_s() {
        let dirs = dirs("held");
        let server =
            HandoffServer::start(&dirs, current_uid(), &session(), &secret(), claude()).unwrap();
        let path = server.path().to_path_buf();
        let asking = std::thread::spawn(move || fetch_here(&path));
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !asking.is_finished(),
            "answered before the launcher's pid was read"
        );
        server.bind_launcher(std::process::id());
        assert_eq!(asking.join().unwrap().unwrap().expose(), CLAUDE_TOKEN);
        assert_eq!(server.finish(), HandoffOutcome::Answered);
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_peer_that_is_not_the_listed_launcher_is_refused_even_with_the_secret() {
        let dirs = dirs("pid");
        let server =
            HandoffServer::start(&dirs, current_uid(), &session(), &secret(), claude()).unwrap();
        let other = std::process::id().wrapping_add(1);
        server.bind_launcher(other);
        let refused = fetch_here(server.path());
        assert!(
            refused.is_err(),
            "a peer with the secret but another pid was answered"
        );
        assert_eq!(server.finish(), HandoffOutcome::NotAsked { refused: 1 });
        let (mut near, _far) = UnixStream::pair().unwrap();
        let grant = Grant {
            agent_uid: current_uid(),
            launcher_pid: Arc::new(AtomicU32::new(other)),
            hold: Duration::ZERO,
            session: session(),
            secret: secret(),
            credential: claude(),
        };
        let grant_refusal = grant.answer(&mut near, &AtomicBool::new(false));
        assert_eq!(
            grant_refusal,
            Err(Refusal::PeerPid {
                found: std::process::id(),
                expected: other
            })
        );
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_server_whose_launcher_pid_is_never_read_answers_nobody() {
        let dirs = dirs("unbound");
        let server = HandoffServer::start_holding(
            &dirs,
            current_uid(),
            &session(),
            &secret(),
            claude(),
            Duration::from_millis(200),
        )
        .unwrap();
        assert!(fetch_here(server.path()).is_err());
        assert_eq!(server.finish(), HandoffOutcome::NotAsked { refused: 1 });
        let (mut near, _far) = UnixStream::pair().unwrap();
        let grant = Grant {
            agent_uid: current_uid(),
            launcher_pid: Arc::new(AtomicU32::new(LAUNCHER_PID_UNKNOWN)),
            hold: Duration::ZERO,
            session: session(),
            secret: secret(),
            credential: claude(),
        };
        assert_eq!(
            grant.answer(&mut near, &AtomicBool::new(false)),
            Err(Refusal::LauncherUnknown)
        );
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn the_hold_leaves_the_launcher_its_request_and_answer_within_its_wait() {
        assert_eq!(
            HOLD_MAX
                .saturating_add(STREAM_TIMEOUT)
                .saturating_add(STREAM_TIMEOUT),
            ANSWER_TIMEOUT
        );
        assert!(HOLD_MAX >= Duration::from_secs(5), "{HOLD_MAX:?}");
    }

    #[test]
    fn the_peer_pid_is_the_connecting_process() {
        let (near, far) = UnixStream::pair().unwrap();
        assert_eq!(peer_pid(&near).unwrap(), std::process::id());
        assert_eq!(peer_pid(&far).unwrap(), std::process::id());
    }

    #[test]
    fn the_launcher_gets_the_credential_once_and_the_socket_is_gone() {
        let dirs = dirs("once");
        let server = started(HandoffServer::start(
            &dirs,
            current_uid(),
            &session(),
            &secret(),
            claude(),
        ));
        let path = server.path().to_path_buf();
        let mode = fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_MODE);
        let handed = fetch(
            &path,
            current_uid(),
            &session(),
            &secret(),
            CredentialVendor::Claude,
        )
        .unwrap();
        assert_eq!(handed.expose(), CLAUDE_TOKEN);
        let again = fetch(
            &path,
            current_uid(),
            &session(),
            &secret(),
            CredentialVendor::Claude,
        );
        assert!(again.is_err(), "a second request was answered");
        assert_eq!(server.finish(), HandoffOutcome::Answered);
        assert!(!path.exists(), "the socket outlived the hand-off");
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_wrong_secret_or_session_is_refused_and_the_right_one_still_answered() {
        let dirs = dirs("refused");
        let server = started(HandoffServer::start(
            &dirs,
            current_uid(),
            &session(),
            &secret(),
            claude(),
        ));
        let path = server.path().to_path_buf();
        let wrong = SessionSecret::parse("ffffffffffffffffffffffffffffffff").unwrap();
        let refused = fetch(
            &path,
            current_uid(),
            &session(),
            &wrong,
            CredentialVendor::Claude,
        );
        assert!(
            matches!(refused, Err(HandoffError::Answer(_))),
            "{refused:?}"
        );
        let other = SessionName::parse("cf7a.wu04.wrk.claude.a1f3").unwrap();
        assert!(fetch(
            &path,
            current_uid(),
            &other,
            &secret(),
            CredentialVendor::Claude
        )
        .is_err());
        let handed = fetch(
            &path,
            current_uid(),
            &session(),
            &secret(),
            CredentialVendor::Claude,
        );
        assert!(handed.is_ok());
        assert_eq!(server.finish(), HandoffOutcome::Answered);
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_peer_of_another_uid_is_refused_on_both_sides() {
        let dirs = dirs("uid");
        let other = current_uid().wrapping_add(1);
        let server = HandoffServer::start(&dirs, other, &session(), &secret(), claude()).unwrap();
        let path = server.path().to_path_buf();
        assert!(fetch(
            &path,
            current_uid(),
            &session(),
            &secret(),
            CredentialVendor::Claude
        )
        .is_err());
        assert!(matches!(
            server.finish(),
            HandoffOutcome::NotAsked { refused: 1 }
        ));
        let server = started(HandoffServer::start(
            &dirs,
            current_uid(),
            &session(),
            &secret(),
            claude(),
        ));
        let refusal = fetch(
            server.path(),
            other,
            &session(),
            &secret(),
            CredentialVendor::Claude,
        )
        .unwrap_err()
        .to_string();
        assert!(refusal.contains("not the core's uid"), "{refusal}");
        assert!(matches!(server.finish(), HandoffOutcome::NotAsked { .. }));
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn the_server_stops_after_its_refusal_cap() {
        let dirs = dirs("cap");
        let server = started(HandoffServer::start(
            &dirs,
            current_uid(),
            &session(),
            &secret(),
            claude(),
        ));
        let path = server.path().to_path_buf();
        let wrong = SessionSecret::parse("ffffffffffffffffffffffffffffffff").unwrap();
        for _ in 0..REFUSALS_MAX {
            drop(fetch(
                &path,
                current_uid(),
                &session(),
                &wrong,
                CredentialVendor::Claude,
            ));
        }
        assert!(fetch(
            &path,
            current_uid(),
            &session(),
            &secret(),
            CredentialVendor::Claude
        )
        .is_err());
        assert_eq!(server.finish(), HandoffOutcome::TooManyRefusals);
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_codex_answer_is_refused_where_claude_was_asked_for() {
        let dirs = dirs("vendor");
        let codex = Credential::parse(CredentialVendor::Codex, CODEX_AUTH.as_bytes()).unwrap();
        let server = started(HandoffServer::start(
            &dirs,
            current_uid(),
            &session(),
            &secret(),
            codex,
        ));
        let refusal = fetch(
            server.path(),
            current_uid(),
            &session(),
            &secret(),
            CredentialVendor::Claude,
        )
        .unwrap_err()
        .to_string();
        assert!(refusal.contains("not claude"), "{refusal}");
        assert!(!refusal.contains("test-refresh-credential"));
        drop(server.finish());
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_dropped_server_removes_its_socket_and_a_long_path_is_refused() {
        let dirs = dirs("drop");
        let server = started(HandoffServer::start(
            &dirs,
            current_uid(),
            &session(),
            &secret(),
            claude(),
        ));
        let path = server.path().to_path_buf();
        drop(server);
        assert!(!path.exists());
        assert_eq!(
            socket_path(&dirs, &session()).file_name().unwrap().len(),
            SOCKET_NAME_HEX + SOCKET_SUFFIX.len()
        );
        let deep = AgentDirs::new(PathBuf::from(format!(
            "/{}",
            "d".repeat(SOCKET_PATH_MAX_BYTES)
        )))
        .unwrap();
        assert!(matches!(
            HandoffServer::start(&deep, current_uid(), &session(), &secret(), claude()),
            Err(HandoffError::PathTooLong(_))
        ));
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }
}

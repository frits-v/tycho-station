//! Killing an agent session, the fifth spawner port operation.
//!
//! A lease and a vendor record are written by the agent user, so a pid in them is a hint. A
//! signal goes only to a process that zmx lists under the session's name (the launcher), whose
//! start time matches the record, whose uid is the agent user's and never the core's, and whose
//! command line is the launcher's (or which leads its own process group, for the vendor). Any
//! mismatch, an absent or mismatched lease included, is an enumerated refusal in the report,
//! and `zmx kill` by name is all that happens.
//!
//! The core cannot signal a process of another uid. When sessions run as the agent, a verified
//! pid is signalled through the sudoers rule instead: a throwaway zmx session started as the
//! agent whose typed line is `exec /bin/kill -KILL -- <pid or -group>`, which the core then
//! removes by name. The vendor leads its own session, so `zmx kill` of the launcher's session
//! does not reach it.

use std::fmt;
use std::path::Path;

use nix::sys::signal::Signal;
use nix::unistd::Uid;
use tycho_types::lease::Lease;
use tycho_types::session::SessionName;

use crate::agent_files::read_checked;
use crate::config::{AgentDirs, POLL_INTERVAL, SESSION_WAIT_POLLS_MAX};
use crate::launcher::{check_tier, SessionFiles, VendorRecord, VENDOR_RECORD_MAX_BYTES};
use crate::process::{process_facts, send, start_matches, Facts, ProcessFacts};
use crate::services::spawner::{LeaseRead, SpawnerError};
use crate::spawn::read_lease;
use crate::zmx::{presence, ListEntry, Presence, Zmx};

/// Why no signal was sent to a pid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillRefusal {
    /// The lease is absent, unreadable, or carries another session or pid.
    LeaseMismatch(String),
    NotListed,
    ListedPidDiffers {
        listed: u32,
    },
    ListUnrecognised,
    Gone,
    Unrecognised(String),
    StartMismatch {
        started_unix_seconds: u64,
    },
    /// The configured agent uid or the process's uid is the core's own.
    CoreUid,
    UidNotAgent {
        uid: u32,
    },
    NotLauncher,
    NotGroupLeader {
        pgid: u32,
    },
    SignalFailed(String),
    /// The signal through the sudoers rule could not be delivered, or the process outlived it.
    DeliveryFailed(String),
}

impl fmt::Display for KillRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

/// What happened to one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillVerdict {
    Signalled,
    /// Signalled as the agent through the sudoers rule, and gone after it.
    SignalledThroughRule,
    /// Verified before `zmx kill`, gone after it.
    EndedByZmx,
    Refused(KillRefusal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillReport {
    pub zmx_kill: Result<(), String>,
    pub launcher: KillVerdict,
    pub vendor: Option<KillVerdict>,
}

/// What a process must look like before it may be signalled.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    pub pid: u32,
    pub started_unix_ms: u64,
    pub agent_uid: u32,
    pub core_uid: u32,
    /// The launcher's exact command line; `None` for the vendor.
    pub command: Option<&'a str>,
    pub group_leader: bool,
}

/// The checks on `ps` facts, in a fixed order; `Ok` means the pid may be signalled.
pub fn judge(facts: &ProcessFacts, expected: &Expected<'_>) -> Result<(), KillRefusal> {
    let facts: &Facts = match facts {
        ProcessFacts::Running(facts) => facts,
        ProcessFacts::Gone => return Err(KillRefusal::Gone),
        ProcessFacts::Unrecognised(text) => return Err(KillRefusal::Unrecognised(text.clone())),
    };
    if expected.agent_uid == expected.core_uid {
        return Err(KillRefusal::CoreUid);
    }
    if facts.uid == expected.core_uid {
        return Err(KillRefusal::CoreUid);
    }
    if facts.uid != expected.agent_uid {
        return Err(KillRefusal::UidNotAgent { uid: facts.uid });
    }
    if !start_matches(facts.started_unix_seconds, expected.started_unix_ms) {
        return Err(KillRefusal::StartMismatch {
            started_unix_seconds: facts.started_unix_seconds,
        });
    }
    if expected
        .command
        .is_some_and(|command| !is_launcher(&facts.command, command))
    {
        return Err(KillRefusal::NotLauncher);
    }
    if expected.group_leader && facts.pgid != expected.pid {
        return Err(KillRefusal::NotGroupLeader { pgid: facts.pgid });
    }
    Ok(())
}

/// The launcher's command line, with or without one trailing `--tier <tier>`.
fn is_launcher(actual: &str, expected: &str) -> bool {
    match actual.strip_prefix(expected) {
        Some("") => true,
        Some(rest) => rest
            .strip_prefix(" --tier ")
            .is_some_and(|tier| check_tier(tier).is_ok()),
        None => false,
    }
}

/// `zmx kill` by name for a lost session, whose recorded pid is never trusted.
pub fn kill_by_name(zmx: &Zmx, session: &SessionName) -> Result<(), SpawnerError> {
    zmx.kill(&session.to_string())
        .map_err(|error| SpawnerError::Transient(error.to_string()))
}

/// What reaping a lost session did: the kill by name and the verdict on its recorded vendor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReapReport {
    pub zmx_kill: Result<(), SpawnerError>,
    pub vendor: Option<KillVerdict>,
}

/// `kill_by_name`, then the vendor recorded in the session's spool directory, judged as
/// `kill_session` judges it; a refusal is reported and changes nothing else.
#[must_use]
pub fn reap(zmx: &Zmx, dirs: &AgentDirs, session: &SessionName, agent_uid: u32) -> ReapReport {
    let zmx_kill = kill_by_name(zmx, session);
    let path = SessionFiles::new(dirs, session).vendor;
    let vendor = vendor_verdict(zmx, read_vendor(&path, agent_uid), agent_uid);
    ReapReport { zmx_kill, vendor }
}

/// The launcher must be the running pid zmx lists under the exact session name.
pub fn judge_listed(entries: &[ListEntry], session: &str, pid: u32) -> Result<(), KillRefusal> {
    match presence(entries, session) {
        Presence::Running { pid: listed, .. } if listed == pid => Ok(()),
        Presence::Running { pid: listed, .. } => Err(KillRefusal::ListedPidDiffers { listed }),
        Presence::Ended { .. } | Presence::Absent => Err(KillRefusal::NotListed),
        Presence::Unrecognised => Err(KillRefusal::ListUnrecognised),
    }
}

/// One session to kill: the pid the caller recorded, the agent uid and the launcher binary.
#[derive(Debug, Clone, Copy)]
pub struct KillRequest<'a> {
    pub zmx: &'a Zmx,
    pub dirs: &'a AgentDirs,
    pub session: &'a SessionName,
    pub pid: u32,
    pub agent_uid: u32,
    pub tycho: &'a Path,
}

/// Verifies, kills by name, then signals only what passed every check.
#[must_use]
pub fn kill_session(request: &KillRequest<'_>) -> KillReport {
    let session = request.session.to_string();
    let command = format!(
        "{} launch --spec {}",
        request.tycho.display(),
        request.dirs.spec_path(request.session).display()
    );
    let checked = checked_lease(request).map(|lease| Expected {
        pid: request.pid,
        started_unix_ms: lease.started_unix_ms(),
        agent_uid: request.agent_uid,
        core_uid: Uid::current().as_raw(),
        command: Some(&command),
        group_leader: false,
    });
    let verified = checked.and_then(|expected| {
        let entries = request
            .zmx
            .list()
            .map_err(|_| KillRefusal::ListUnrecognised)?;
        judge_listed(&entries, &session, request.pid)?;
        judge(&process_facts(request.pid), &expected)?;
        Ok(expected)
    });
    let zmx_kill = request
        .zmx
        .kill(&session)
        .map_err(|error| error.to_string());
    let launcher = match verified {
        Ok(expected) => signal_if_still(request.zmx, &expected, false),
        Err(refusal) => KillVerdict::Refused(refusal),
    };
    KillReport {
        zmx_kill,
        launcher,
        vendor: kill_vendor(request),
    }
}

/// The lease must be the agent user's, for this session, carrying the caller's pid.
fn checked_lease(request: &KillRequest<'_>) -> Result<Lease, KillRefusal> {
    let session = request.session;
    let lease = match read_lease(request.dirs, session, request.agent_uid) {
        LeaseRead::Present { lease } => lease,
        LeaseRead::Absent => {
            return Err(KillRefusal::LeaseMismatch(format!(
                "{session} has no lease"
            )))
        }
        LeaseRead::Unreadable { reason } => return Err(KillRefusal::LeaseMismatch(reason)),
    };
    if lease.session() != session || lease.pid() != request.pid {
        return Err(KillRefusal::LeaseMismatch(format!(
            "pid {} is not the lease's pid {} for {session}",
            request.pid,
            lease.pid()
        )));
    }
    Ok(lease)
}

/// The vendor's group, signalled only as an agent-owned group leader started when recorded.
fn kill_vendor(request: &KillRequest<'_>) -> Option<KillVerdict> {
    let path = SessionFiles::new(request.dirs, request.session).vendor;
    vendor_verdict(
        request.zmx,
        read_vendor(&path, request.agent_uid),
        request.agent_uid,
    )
}

fn vendor_verdict(zmx: &Zmx, read: VendorRead, agent_uid: u32) -> Option<KillVerdict> {
    let vendor = match vendor_expectation(read, agent_uid, Uid::current().as_raw()) {
        Ok(None) => return None,
        Ok(Some(vendor)) => vendor,
        Err(refusal) => return Some(KillVerdict::Refused(refusal)),
    };
    Some(match judge(&process_facts(vendor.pid), &vendor) {
        Ok(()) => signal_if_still(zmx, &vendor, true),
        Err(refusal) => KillVerdict::Refused(refusal),
    })
}

/// What a vendor record allows: nothing to do, a refusal, or the group leader to check.
pub fn vendor_expectation(
    read: VendorRead,
    agent_uid: u32,
    core_uid: u32,
) -> Result<Option<Expected<'static>>, KillRefusal> {
    match read {
        VendorRead::Absent => Ok(None),
        VendorRead::Unrecognised(reason) => Err(KillRefusal::Unrecognised(reason)),
        VendorRead::Present(record) => Ok(Some(Expected {
            pid: record.pid,
            started_unix_ms: record.started_unix_ms,
            agent_uid,
            core_uid,
            command: None,
            group_leader: true,
        })),
    }
}

/// Re-checks the same process and sends SIGKILL, itself or, when `zmx` starts sessions as
/// another user, through the sudoers rule; gone by now means zmx ended it.
fn signal_if_still(zmx: &Zmx, expected: &Expected<'_>, group: bool) -> KillVerdict {
    match judge(&process_facts(expected.pid), expected) {
        Ok(()) if zmx.switched_to().is_some() => {
            deliver_through(zmx, expected.pid, group, &process_facts)
        }
        Ok(()) => match send(expected.pid, group, Signal::SIGKILL) {
            Ok(()) => KillVerdict::Signalled,
            Err(error) => KillVerdict::Refused(KillRefusal::SignalFailed(error)),
        },
        Err(KillRefusal::Gone) => KillVerdict::EndedByZmx,
        Err(refusal) => KillVerdict::Refused(refusal),
    }
}

/// Random bytes in the reap session's name, so no process of the agent's can hold the name
/// before the core asks for it.
const REAP_NAME_RANDOM_BYTES: usize = 8;

/// The throwaway session that carries one signal: `reap.<pid>.<16 random hex digits>`. No
/// launcher's session name starts so.
pub fn reap_session_name(pid: u32) -> std::io::Result<String> {
    use std::io::Read;
    let mut bytes = [0_u8; REAP_NAME_RANDOM_BYTES];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let suffix: String = bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from_digit(u32::from(nibble), 16).unwrap_or('0'))
        .collect();
    Ok(format!("reap.{pid}.{suffix}"))
}

/// The words the reap session types: `kill` replaces its shell, so nothing else runs there.
#[must_use]
pub fn reap_words(pid: u32, group: bool) -> Vec<String> {
    let target = if group {
        format!("-{pid}")
    } else {
        pid.to_string()
    };
    ["exec", "/bin/kill", "-KILL", "--", &target]
        .map(str::to_string)
        .to_vec()
}

fn delivery_failed(why: impl std::fmt::Display) -> KillVerdict {
    KillVerdict::Refused(KillRefusal::DeliveryFailed(why.to_string()))
}

/// Runs `/bin/kill` in a zmx session of its own, as whoever `zmx` starts sessions as.
///
/// It waits for that session to end, removes it by name, and reports whether `pid` is gone.
pub fn deliver_through(
    zmx: &Zmx,
    pid: u32,
    group: bool,
    facts: &dyn Fn(u32) -> ProcessFacts,
) -> KillVerdict {
    match reap_session_name(pid) {
        Ok(name) => deliver_named(zmx, &name, pid, group, facts),
        Err(error) => delivery_failed(format!("no random reap name: {error}")),
    }
}

/// `deliver_through` under a given name; a name already listed is refused rather than typed
/// into.
fn deliver_named(
    zmx: &Zmx,
    name: &str,
    pid: u32,
    group: bool,
    facts: &dyn Fn(u32) -> ProcessFacts,
) -> KillVerdict {
    let name = name.to_string();
    match zmx.list().map(|entries| presence(&entries, &name)) {
        Ok(Presence::Absent) => {}
        Ok(taken) => return delivery_failed(format!("{name} is listed already: {taken:?}")),
        Err(error) => return delivery_failed(error),
    }
    if let Err(error) = zmx.run_words(&name, &reap_words(pid, group)) {
        return delivery_failed(error);
    }
    for _ in 0..SESSION_WAIT_POLLS_MAX {
        let ended = matches!(
            zmx.list().map(|entries| presence(&entries, &name)),
            Ok(Presence::Ended { .. } | Presence::Absent)
        );
        if ended && facts(pid) == ProcessFacts::Gone {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    let removed = zmx.kill(&name);
    match (facts(pid), removed) {
        (ProcessFacts::Gone, Ok(())) => KillVerdict::SignalledThroughRule,
        (ProcessFacts::Gone, Err(error)) => {
            delivery_failed(format!("gone, but {name} was not removed: {error}"))
        }
        (ProcessFacts::Running(_), _) => delivery_failed(format!("pid {pid} outlived {name}")),
        (ProcessFacts::Unrecognised(text), _) => {
            KillVerdict::Refused(KillRefusal::Unrecognised(text))
        }
    }
}

/// The vendor record as read: only a missing file is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VendorRead {
    Absent,
    Present(VendorRecord),
    Unrecognised(String),
}

#[must_use]
pub fn read_vendor(path: &Path, agent_uid: u32) -> VendorRead {
    match read_checked(path, VENDOR_RECORD_MAX_BYTES, Some(agent_uid)) {
        Ok(None) => VendorRead::Absent,
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).map_or_else(
            |error| VendorRead::Unrecognised(format!("{}: {error}", path.display())),
            VendorRead::Present,
        ),
        Err(error) => VendorRead::Unrecognised(error.to_string()),
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;

    const AGENT: u32 = 600;
    const CORE: u32 = 501;
    const PID: u32 = 4242;
    const STARTED_MS: u64 = 1_800_000_000_000;
    const COMMAND: &str = "/opt/tycho launch --spec /agent/specs/s.json";

    fn facts(uid: u32, pgid: u32, started: u64, command: &str) -> ProcessFacts {
        ProcessFacts::Running(Facts {
            uid,
            pgid,
            started_unix_seconds: started,
            command: command.to_string(),
        })
    }

    fn launcher() -> Expected<'static> {
        Expected {
            pid: PID,
            started_unix_ms: STARTED_MS,
            agent_uid: AGENT,
            core_uid: CORE,
            command: Some(COMMAND),
            group_leader: false,
        }
    }

    const STARTED: u64 = STARTED_MS / 1000;

    #[test]
    fn the_reap_session_types_one_kill_of_the_verified_pid_or_its_group() {
        assert_eq!(
            reap_words(4242, true),
            ["exec", "/bin/kill", "-KILL", "--", "-4242"]
        );
        assert_eq!(
            reap_words(4242, false),
            ["exec", "/bin/kill", "-KILL", "--", "4242"]
        );
        let first = reap_session_name(4242).unwrap();
        let second = reap_session_name(4242).unwrap();
        assert_ne!(first, second, "the reap name is predictable");
        let suffix = first.strip_prefix("reap.4242.").unwrap();
        assert_eq!(suffix.len(), REAP_NAME_RANDOM_BYTES * 2);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(tycho_types::session::SessionName::parse(&first).is_err());
    }

    /// A stand-in zmx that lists the sessions it was told about, and runs a `run`'s words,
    /// so the delivery reaches a real process group.
    fn reaping_zmx(dir: &Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("zmx-stand-in");
        let script_text = format!(
            "#!/bin/sh\ncase \"$1\" in\n  list) cat {listed} 2>/dev/null || true ;;\n  run) printf '%s\\n' \"$*\" >> {runs}; shift 3; \"$@\" ;;\n  kill) printf 'kill %s\\n' \"$2\" >> {runs} ;;\nesac\n",
            listed = dir.join("listed").display(),
            runs = dir.join("runs").display(),
        );
        std::fs::write(&script, script_text).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        script
    }

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("tycho-reap-{tag}-{}", std::process::id()));
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap();
        }
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_group_is_reaped_through_a_session_of_its_own_which_is_then_removed() {
        use std::os::unix::process::CommandExt;
        let dir = scratch_dir("group");
        let zmx = Zmx::agent(&reaping_zmx(&dir), &dir);
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        let reaper = std::thread::spawn(move || child.wait());
        let verdict = deliver_through(&zmx, pid, true, &process_facts);
        assert!(reaper.join().unwrap().is_ok());
        assert_eq!(verdict, KillVerdict::SignalledThroughRule);
        let runs = std::fs::read_to_string(dir.join("runs")).unwrap();
        let lines: Vec<&str> = runs.lines().collect();
        let [run, kill] = lines.as_slice() else {
            panic!("{runs}");
        };
        let name = run
            .strip_prefix("run ")
            .and_then(|rest| rest.split_once(' '))
            .map(|(name, _)| name)
            .unwrap();
        assert!(name.starts_with(&format!("reap.{pid}.")), "{name}");
        assert_eq!(
            *run,
            format!("run {name} -d exec /bin/kill -KILL -- -{pid}")
        );
        assert_eq!(*kill, format!("kill {name}"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_listed_reap_name_is_refused_and_a_survivor_is_reported() {
        let dir = scratch_dir("taken");
        let zmx = Zmx::agent(&reaping_zmx(&dir), &dir);
        std::fs::write(
            dir.join("listed"),
            "  name=reap.4242.squatted\tpid=77\tclients=0\tcreated=1\n",
        )
        .unwrap();
        assert!(matches!(
            deliver_named(&zmx, "reap.4242.squatted", 4242, true, &|_| {
                ProcessFacts::Gone
            }),
            KillVerdict::Refused(KillRefusal::DeliveryFailed(_))
        ));
        assert!(!dir.join("runs").exists(), "a listed name was typed into");
        std::fs::remove_file(dir.join("listed")).unwrap();
        let alive = |_| facts(AGENT, PID, STARTED, "claude");
        let refused = Zmx::agent(Path::new("/usr/bin/true"), &dir);
        assert!(matches!(
            deliver_through(&refused, PID, true, &alive),
            KillVerdict::Refused(KillRefusal::DeliveryFailed(why)) if why.contains("outlived")
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_verified_launcher_may_be_signalled() {
        assert_eq!(
            judge(&facts(AGENT, 1, STARTED, COMMAND), &launcher()),
            Ok(())
        );
        let vendor = Expected {
            command: None,
            group_leader: true,
            ..launcher()
        };
        assert_eq!(
            judge(&facts(AGENT, PID, STARTED, "claude -p"), &vendor),
            Ok(())
        );
    }

    #[test]
    fn each_failed_check_is_its_own_refusal() {
        let expected = launcher();
        assert_eq!(
            judge(&ProcessFacts::Gone, &expected),
            Err(KillRefusal::Gone)
        );
        assert!(matches!(
            judge(&ProcessFacts::Unrecognised("x".into()), &expected),
            Err(KillRefusal::Unrecognised(_))
        ));
        assert_eq!(
            judge(&facts(CORE, 1, STARTED, COMMAND), &expected),
            Err(KillRefusal::CoreUid)
        );
        let same = Expected {
            agent_uid: CORE,
            ..expected
        };
        assert_eq!(
            judge(&facts(CORE, 1, STARTED, COMMAND), &same),
            Err(KillRefusal::CoreUid)
        );
        assert_eq!(
            judge(&facts(0, 1, STARTED, COMMAND), &expected),
            Err(KillRefusal::UidNotAgent { uid: 0 })
        );
        assert!(matches!(
            judge(&facts(AGENT, 1, STARTED - 3600, COMMAND), &expected),
            Err(KillRefusal::StartMismatch { .. })
        ));
        assert_eq!(
            judge(&facts(AGENT, 1, STARTED, "/bin/zsh"), &expected),
            Err(KillRefusal::NotLauncher)
        );
        let tiered = format!("{COMMAND} --tier t2");
        assert_eq!(judge(&facts(AGENT, 1, STARTED, &tiered), &expected), Ok(()));
        for other in [
            format!("{COMMAND} --tier a b"),
            format!("{COMMAND}x"),
            format!("{COMMAND} --other"),
        ] {
            assert_eq!(
                judge(&facts(AGENT, 1, STARTED, &other), &expected),
                Err(KillRefusal::NotLauncher),
                "{other}"
            );
        }
        let vendor = Expected {
            command: None,
            group_leader: true,
            ..expected
        };
        assert_eq!(
            judge(&facts(AGENT, 7, STARTED, "claude"), &vendor),
            Err(KillRefusal::NotGroupLeader { pgid: 7 })
        );
    }

    #[test]
    fn the_launcher_must_be_listed_under_its_exact_name() {
        let running = |name: &str, pid: u32| ListEntry::Running {
            name: name.to_string(),
            pid,
            created_unix_seconds: 1,
        };
        assert_eq!(judge_listed(&[running("s", PID)], "s", PID), Ok(()));
        assert_eq!(
            judge_listed(&[running("s.other", PID)], "s", PID),
            Err(KillRefusal::NotListed)
        );
        assert_eq!(
            judge_listed(&[running("s", 7)], "s", PID),
            Err(KillRefusal::ListedPidDiffers { listed: 7 })
        );
        assert_eq!(
            judge_listed(&[ListEntry::Unrecognised("?".into())], "s", PID),
            Err(KillRefusal::ListUnrecognised)
        );
        let ended = ListEntry::Ended {
            name: "s".to_string(),
            pid: PID,
            exit_code: 0,
        };
        assert_eq!(
            judge_listed(&[ended], "s", PID),
            Err(KillRefusal::NotListed)
        );
    }

    /// Agent directories holding a lease and a vendor record for `pid`, both started now.
    fn records_for(pid: u32, test: &str) -> (AgentDirs, SessionName) {
        use crate::agent_files::write_durable;
        use crate::process::now_unix_ms;
        use tycho_types::launcher::AwaitableId;
        let dir = std::env::temp_dir().join(format!("tycho-kill-{test}-{}", std::process::id()));
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap();
        }
        let dirs = AgentDirs::new(dir).unwrap();
        crate::spawn::ensure_agent_dirs(&dirs).unwrap();
        let session = SessionName::parse("cf7a.wu03.wrk.claude.a1f3").unwrap();
        std::fs::create_dir_all(dirs.spool_dir(&session)).unwrap();
        let now = now_unix_ms();
        let awaitable = AwaitableId::parse("sign_1abc").unwrap();
        let digest = tycho_types::launcher::AwaitableDigest::of(&awaitable);
        let lease = Lease::new(session.clone(), pid, digest, now, now).unwrap();
        write_durable(&dirs.lease_path(&session), &lease.to_bytes().unwrap()).unwrap();
        let record = VendorRecord {
            pid,
            started_unix_ms: now,
        };
        let vendor = SessionFiles::new(&dirs, &session).vendor;
        write_durable(&vendor, &serde_json::to_vec(&record).unwrap()).unwrap();
        (dirs, session)
    }

    /// A zmx stand-in that appends its arguments to a log and lists nothing.
    fn recording_zmx(dirs: &AgentDirs) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let log = dirs.socket_dir.join("zmx-calls");
        let script = dirs.socket_dir.join("zmx-stand-in");
        std::fs::write(
            &script,
            format!("#!/bin/sh\necho \"$@\" >> {}\n", log.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        (script, log)
    }

    fn request<'a>(
        zmx: &'a Zmx,
        dirs: &'a AgentDirs,
        session: &'a SessionName,
        pid: u32,
    ) -> KillRequest<'a> {
        KillRequest {
            zmx,
            dirs,
            session,
            pid,
            agent_uid: crate::agent_files::current_uid(),
            tycho: Path::new("/opt/tycho"),
        }
    }

    #[test]
    fn a_core_owned_process_is_never_signalled_even_with_a_matching_record() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let (dirs, session) = records_for(child.id(), "core");
        let (script, log) = recording_zmx(&dirs);
        let zmx = Zmx::agent(&script, &dirs.socket_dir);
        let report = kill_session(&request(&zmx, &dirs, &session, child.id()));
        assert_eq!(
            report.launcher,
            KillVerdict::Refused(KillRefusal::NotListed)
        );
        assert_eq!(
            report.vendor,
            Some(KillVerdict::Refused(KillRefusal::CoreUid))
        );
        assert_eq!(
            child.try_wait().unwrap(),
            None,
            "a core-owned process was signalled"
        );
        assert!(std::fs::read_to_string(&log)
            .unwrap()
            .contains(&format!("kill {session}")));
        child.kill().unwrap();
        child.wait().unwrap();
        std::fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_mismatched_or_absent_lease_is_reported_and_zmx_still_kills_by_name() {
        let (dirs, session) = records_for(4242, "lease");
        let (script, log) = recording_zmx(&dirs);
        let zmx = Zmx::agent(&script, &dirs.socket_dir);
        let report = kill_session(&request(&zmx, &dirs, &session, 4243));
        assert!(matches!(
            report.launcher,
            KillVerdict::Refused(KillRefusal::LeaseMismatch(_))
        ));
        assert_eq!(report.zmx_kill, Ok(()));
        std::fs::remove_file(dirs.lease_path(&session)).unwrap();
        let report = kill_session(&request(&zmx, &dirs, &session, 4242));
        assert!(matches!(
            report.launcher,
            KillVerdict::Refused(KillRefusal::LeaseMismatch(_))
        ));
        let calls = std::fs::read_to_string(&log).unwrap();
        assert_eq!(
            calls.matches(&format!("kill {session}")).count(),
            2,
            "{calls}"
        );
        std::fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    fn vendor_record() -> VendorRead {
        VendorRead::Present(VendorRecord {
            pid: PID,
            started_unix_ms: STARTED_MS,
        })
    }

    #[test]
    fn a_reaped_vendor_with_distinct_uids_passes_only_as_the_agents_group_leader() {
        let vendor = vendor_expectation(vendor_record(), AGENT, CORE)
            .unwrap()
            .unwrap();
        assert_eq!(judge(&facts(AGENT, PID, STARTED, "sh v"), &vendor), Ok(()));
        assert_eq!(
            judge(&facts(CORE, PID, STARTED, "sh v"), &vendor),
            Err(KillRefusal::CoreUid)
        );
        assert_eq!(
            judge(&facts(AGENT, 1, STARTED, "sh v"), &vendor),
            Err(KillRefusal::NotGroupLeader { pgid: 1 })
        );
        let same_uid = vendor_expectation(vendor_record(), AGENT, AGENT)
            .unwrap()
            .unwrap();
        assert_eq!(
            judge(&facts(AGENT, PID, STARTED, "sh v"), &same_uid),
            Err(KillRefusal::CoreUid)
        );
        assert!(matches!(
            vendor_expectation(VendorRead::Absent, AGENT, CORE),
            Ok(None)
        ));
        assert!(matches!(
            vendor_expectation(VendorRead::Unrecognised("x".to_string()), AGENT, CORE),
            Err(KillRefusal::Unrecognised(_))
        ));
    }

    #[test]
    fn a_reap_kills_by_name_and_reports_the_vendor_without_signalling_a_core_process() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let (dirs, session) = records_for(child.id(), "reap");
        let (script, log) = recording_zmx(&dirs);
        let zmx = Zmx::agent(&script, &dirs.socket_dir);
        let report = reap(&zmx, &dirs, &session, crate::agent_files::current_uid());
        assert_eq!(report.zmx_kill, Ok(()));
        assert_eq!(
            report.vendor,
            Some(KillVerdict::Refused(KillRefusal::CoreUid))
        );
        assert_eq!(child.try_wait().unwrap(), None, "the vendor was signalled");
        assert!(std::fs::read_to_string(&log)
            .unwrap()
            .contains(&format!("kill {session}")));
        std::fs::remove_file(SessionFiles::new(&dirs, &session).vendor).unwrap();
        let report = reap(&zmx, &dirs, &session, crate::agent_files::current_uid());
        assert_eq!(report.vendor, None);
        child.kill().unwrap();
        child.wait().unwrap();
        std::fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn an_unreadable_vendor_record_is_reported_and_only_a_missing_one_is_absent() {
        let (dirs, session) = records_for(4242, "vendor");
        let path = SessionFiles::new(&dirs, &session).vendor;
        let uid = crate::agent_files::current_uid();
        assert!(matches!(read_vendor(&path, uid), VendorRead::Present(_)));
        assert!(matches!(
            read_vendor(&path, uid.wrapping_add(1)),
            VendorRead::Unrecognised(_)
        ));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(read_vendor(&path, uid), VendorRead::Absent);
        std::fs::write(&path, "{").unwrap();
        assert!(matches!(
            read_vendor(&path, uid),
            VendorRead::Unrecognised(_)
        ));
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "x".repeat(VENDOR_RECORD_MAX_BYTES + 1)).unwrap();
        assert!(matches!(
            read_vendor(&path, uid),
            VendorRead::Unrecognised(_)
        ));
        let zmx = Zmx::agent(Path::new("/usr/bin/true"), &dirs.socket_dir);
        let report = kill_session(&request(&zmx, &dirs, &session, 4242));
        assert!(matches!(
            report.vendor,
            Some(KillVerdict::Refused(KillRefusal::Unrecognised(_)))
        ));
        std::fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }
}

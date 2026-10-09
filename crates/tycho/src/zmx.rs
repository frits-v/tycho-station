//! The core's zmx sessions: the `zmx list` decoder, and run, kill and list in the core
//! socket directory.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use tycho_types::lease::PID_MAX;

use nix::sys::signal::Signal;

use crate::command::{self, Captured, CommandError};
use crate::config::{COMMAND_OUTPUT_MAX_BYTES, COMMAND_TIMEOUT, LIST_SESSIONS_MAX};
use crate::process::{self, ProcessFacts};

/// Set inside a zmx session: zmx refuses to attach from inside one, and nothing zmx runs for
/// the core inherits the caller's session.
pub const SESSION_ENV: &str = "ZMX_SESSION";

/// The core directory is private: zmx does not check who connects to a socket.
const CORE_DIR_MODE: &str = "0700";
/// Matches `AGENT_DIR_MODE`: the agent user and the developer share the group.
const AGENT_ZMX_DIR_MODE: &str = "0770";

/// One line of `zmx list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListEntry {
    Running {
        name: String,
        pid: u32,
        created_unix_seconds: u64,
    },
    Ended {
        name: String,
        pid: u32,
        exit_code: i32,
    },
    Unrecognised(String),
}

/// Where one session name stands in a decoded list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Running {
        pid: u32,
        created_unix_seconds: u64,
    },
    Ended {
        pid: u32,
    },
    Absent,
    /// The list held a line the decoder could not read, so absence cannot be trusted.
    Unrecognised,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ListError {
    TooManySessions(usize),
}

pub fn decode_list(stdout: &str) -> Result<Vec<ListEntry>, ListError> {
    let lines: Vec<&str> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.len() > LIST_SESSIONS_MAX {
        return Err(ListError::TooManySessions(lines.len()));
    }
    Ok(lines.into_iter().map(decode_line).collect())
}

fn decode_line(line: &str) -> ListEntry {
    let mut name = None;
    let mut pid = None;
    let mut created = None;
    let mut ended = false;
    let mut exit_code = None;
    for field in line.trim_start_matches([' ', '*']).split('\t') {
        match field.split_once('=') {
            Some(("name", value)) if !value.is_empty() => name = Some(value.to_string()),
            Some(("pid", value)) => {
                pid = value
                    .parse::<u32>()
                    .ok()
                    .filter(|pid| (1..=PID_MAX).contains(pid));
            }
            Some(("created", value)) => created = value.parse::<u64>().ok(),
            Some(("ended", _)) => ended = true,
            Some(("exit_code", value)) => exit_code = value.parse::<i32>().ok(),
            Some(("clients" | "cwd", _)) => {}
            _ => return ListEntry::Unrecognised(line.to_string()),
        }
    }
    match (name, pid, created, ended, exit_code) {
        (Some(name), Some(pid), Some(created_unix_seconds), false, None) => ListEntry::Running {
            name,
            pid,
            created_unix_seconds,
        },
        (Some(name), Some(pid), Some(_), true, Some(exit_code)) => ListEntry::Ended {
            name,
            pid,
            exit_code,
        },
        _ => ListEntry::Unrecognised(line.to_string()),
    }
}

#[must_use]
pub fn presence(entries: &[ListEntry], name: &str) -> Presence {
    if entries
        .iter()
        .any(|entry| matches!(entry, ListEntry::Unrecognised(_)))
    {
        return Presence::Unrecognised;
    }
    let mut found = Presence::Absent;
    let mut count = 0_usize;
    for entry in entries {
        match entry {
            ListEntry::Running {
                name: listed,
                pid,
                created_unix_seconds,
            } if listed == name => {
                count = count.saturating_add(1);
                found = Presence::Running {
                    pid: *pid,
                    created_unix_seconds: *created_unix_seconds,
                };
            }
            ListEntry::Ended {
                name: listed, pid, ..
            } if listed == name => {
                count = count.saturating_add(1);
                found = Presence::Ended { pid: *pid };
            }
            _ => {}
        }
    }
    if count > 1 {
        return Presence::Unrecognised;
    }
    found
}

/// Counts the entries carrying a name, for the no-duplicate assertion.
#[must_use]
pub fn count_named(entries: &[ListEntry], name: &str) -> usize {
    entries
        .iter()
        .filter(|entry| match entry {
            ListEntry::Running { name: listed, .. } | ListEntry::Ended { name: listed, .. } => {
                listed == name
            }
            ListEntry::Unrecognised(_) => false,
        })
        .count()
}

#[derive(Debug)]
pub enum ZmxError {
    Command(CommandError),
    List(ListError),
    RunFailed(ExitStatus),
}

impl std::fmt::Display for ZmxError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Command(error) => write!(formatter, "{error}"),
            Self::List(ListError::TooManySessions(count)) => write!(
                formatter,
                "zmx list has {count} sessions; limit is {LIST_SESSIONS_MAX}"
            ),
            Self::RunFailed(status) => write!(formatter, "zmx run exited with {status}"),
        }
    }
}

/// zmx bound to the core's own socket directory.
#[derive(Debug, Clone)]
pub struct Zmx {
    binary: PathBuf,
    socket_dir: String,
    dir_mode: &'static str,
}

impl Zmx {
    #[must_use]
    pub fn new(binary: &Path, socket_dir: &Path) -> Self {
        Self {
            binary: binary.to_path_buf(),
            socket_dir: socket_dir.display().to_string(),
            dir_mode: CORE_DIR_MODE,
        }
    }

    /// zmx bound to the agent socket directory, which the developer's group shares.
    #[must_use]
    pub fn agent(binary: &Path, socket_dir: &Path) -> Self {
        Self {
            binary: binary.to_path_buf(),
            socket_dir: socket_dir.display().to_string(),
            dir_mode: AGENT_ZMX_DIR_MODE,
        }
    }

    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    #[must_use]
    pub fn socket_dir(&self) -> &str {
        &self.socket_dir
    }

    const fn environment(&self) -> [(&str, &str); 2] {
        [
            ("ZMX_DIR", self.socket_dir.as_str()),
            ("ZMX_DIR_MODE", self.dir_mode),
        ]
    }

    /// zmx with this directory's environment and no inherited session, for a caller that
    /// drives a subcommand this type does not wrap, such as a viewer's attach.
    #[must_use]
    pub fn command(&self, arguments: &[&str]) -> std::process::Command {
        let mut command = std::process::Command::new(&self.binary);
        command
            .args(arguments)
            .envs(self.environment())
            .env_remove(SESSION_ENV);
        command
    }

    fn status(&self, arguments: &[&str], max_bytes: usize) -> Result<Captured, ZmxError> {
        command::run_status_capped(
            &self.binary,
            arguments,
            &self.environment(),
            &[OsString::from(SESSION_ENV)],
            COMMAND_TIMEOUT,
            max_bytes,
        )
        .map_err(ZmxError::Command)
    }

    fn succeeded(&self, arguments: &[&str]) -> Result<Captured, ZmxError> {
        let captured = self.status(arguments, COMMAND_OUTPUT_MAX_BYTES)?;
        if !captured.status.success() {
            return Err(ZmxError::Command(CommandError::Failed(
                self.binary.display().to_string(),
                captured.status,
                captured.stderr,
            )));
        }
        Ok(captured)
    }

    fn detached(&self, arguments: &[&str]) -> Result<(), ZmxError> {
        let status = command::run_detached(
            &self.binary,
            arguments,
            &self.environment(),
            &[OsString::from(SESSION_ENV)],
            COMMAND_TIMEOUT,
        )
        .map_err(ZmxError::Command)?;
        if !status.success() {
            return Err(ZmxError::RunFailed(status));
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<ListEntry>, ZmxError> {
        let captured = self.succeeded(&["list"])?;
        decode_list(&captured.stdout).map_err(ZmxError::List)
    }

    /// Spawns detached; never a bare attach, which would hijack the calling terminal.
    pub fn run_detached(&self, name: &str, command_line: &str) -> Result<(), ZmxError> {
        let mut arguments = vec!["run", name, "-d"];
        arguments.extend(command_line.split(' ').filter(|word| !word.is_empty()));
        self.detached(&arguments)
    }

    /// Spawns detached with each word as one argument; zmx quotes every word for the shell.
    pub fn run_words(&self, name: &str, words: &[String]) -> Result<(), ZmxError> {
        let mut arguments = vec!["run", name, "-d"];
        arguments.extend(words.iter().map(String::as_str));
        self.detached(&arguments)
    }

    /// The session's scrollback; more than `max_bytes` is an error, never a truncation.
    pub fn history(&self, name: &str, max_bytes: usize) -> Result<String, ZmxError> {
        let captured = self.status(&["history", name], max_bytes)?;
        if !captured.status.success() {
            return Err(ZmxError::RunFailed(captured.status));
        }
        Ok(captured.stdout)
    }

    /// Writes text to the session's pty input, as a nudge.
    pub fn send(&self, name: &str, text: &str) -> Result<(), ZmxError> {
        self.succeeded(&["send", name, text]).map(|_| ())
    }

    /// Ends a session by name; a missing session is not an error here.
    pub fn kill(&self, name: &str) -> Result<(), ZmxError> {
        self.status(&["kill", name, "--force"], COMMAND_OUTPUT_MAX_BYTES)
            .map(|_| ())
    }

    /// Ends every listed session by name. A running entry's pid is killed first, and only when
    /// `ps` shows it running a command that starts with one of `programs`; an ended entry's
    /// pid may belong to another process by now and is never signalled.
    pub fn clear(&self, programs: &[String]) -> Result<ClearReport, ZmxError> {
        let mut lines = Vec::new();
        for entry in self.list()? {
            let line = match entry {
                ListEntry::Running { name, pid, .. } => {
                    let signalled = expected_program(&process::process_facts(pid), programs)
                        .and_then(|()| process::send(pid, false, Signal::SIGKILL));
                    let verdict = match signalled {
                        Ok(()) => "killed".to_string(),
                        Err(reason) => format!("not signalled: {reason}"),
                    };
                    format!(
                        "{name} running as pid {pid}, {verdict}; zmx kill: {:?}",
                        self.kill(&name)
                    )
                }
                ListEntry::Ended { name, pid, .. } => format!(
                    "{name} ended (pid {pid} not signalled); zmx kill: {:?}",
                    self.kill(&name)
                ),
                ListEntry::Unrecognised(text) => format!("unrecognised entry {text:?}"),
            };
            lines.push(line);
        }
        let remaining = self.list()?.len();
        Ok(ClearReport { lines, remaining })
    }
}

/// What `Zmx::clear` did with each listed entry, and how many entries are still listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearReport {
    pub lines: Vec<String>,
    pub remaining: usize,
}

const COMMAND_ECHO_MAX_CHARS: usize = 120;

/// Whether `ps`'s answer for a listed pid shows a command starting with one of `programs`.
pub fn expected_program(facts: &ProcessFacts, programs: &[String]) -> Result<(), String> {
    match facts {
        ProcessFacts::Running(facts)
            if programs
                .iter()
                .any(|program| facts.command.starts_with(program.as_str())) =>
        {
            Ok(())
        }
        ProcessFacts::Running(facts) => Err(format!(
            "it runs {:?}",
            facts
                .command
                .chars()
                .take(COMMAND_ECHO_MAX_CHARS)
                .collect::<String>()
        )),
        ProcessFacts::Gone => Err("it is gone".to_string()),
        ProcessFacts::Unrecognised(text) => Err(format!("ps answered {text:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Facts;

    fn running(command: &str) -> ProcessFacts {
        ProcessFacts::Running(Facts {
            uid: 501,
            pgid: 42,
            started_unix_seconds: 0,
            command: command.to_string(),
        })
    }

    #[test]
    fn only_a_pid_running_an_expected_program_is_signalled() {
        let programs = vec![
            "/opt/restate-server".to_string(),
            "/opt/tycho endpoint".to_string(),
        ];
        assert_eq!(
            expected_program(&running("/opt/restate-server --base-dir /h"), &programs),
            Ok(())
        );
        assert_eq!(
            expected_program(&running("/opt/tycho endpoint"), &programs),
            Ok(())
        );
        for other in [
            running("/bin/zsh -l"),
            running("/opt/tycho launch --spec x"),
            ProcessFacts::Gone,
            ProcessFacts::Unrecognised("?".to_string()),
        ] {
            assert!(expected_program(&other, &programs).is_err(), "{other:?}");
        }
    }

    const RUNNING: &str = "  name=core.restate\tpid=60889\tclients=0\tcreated=1791528126\tcwd=file://host/Users/someone\n";
    const ENDED: &str = "  name=core.endpoint\tpid=60267\tclients=0\tcreated=1791528101\tcwd=file://host/Users/someone\tended=1791528114\texit_code=137\n";

    #[test]
    fn decodes_a_running_session() {
        assert_eq!(
            decode_list(RUNNING).unwrap(),
            vec![ListEntry::Running {
                name: "core.restate".to_string(),
                pid: 60889,
                created_unix_seconds: 1_791_528_126,
            }]
        );
    }

    #[test]
    fn decodes_an_ended_session() {
        assert_eq!(
            decode_list(ENDED).unwrap(),
            vec![ListEntry::Ended {
                name: "core.endpoint".to_string(),
                pid: 60267,
                exit_code: 137,
            }]
        );
    }

    #[test]
    fn decodes_empty_output_as_no_sessions() {
        assert_eq!(decode_list("").unwrap(), vec![]);
        assert_eq!(presence(&[], "core.restate"), Presence::Absent);
    }

    #[test]
    fn marks_an_unknown_field_unrecognised() {
        let line = "  name=core.restate\tpid=1\tcreated=2\tcolour=blue";
        assert_eq!(
            decode_list(line).unwrap(),
            vec![ListEntry::Unrecognised(line.to_string())]
        );
    }

    #[test]
    fn marks_a_line_without_a_pid_unrecognised() {
        let entries = decode_list("  name=core.restate\tcreated=2").unwrap();
        assert!(matches!(entries.as_slice(), [ListEntry::Unrecognised(_)]));
    }

    #[test]
    fn marks_a_pid_out_of_range_unrecognised() {
        for pid in ["0", "2147483648"] {
            let line = format!("  name=core.restate\tpid={pid}\tcreated=2");
            let entries = decode_list(&line).unwrap();
            assert!(matches!(entries.as_slice(), [ListEntry::Unrecognised(_)]));
        }
    }

    #[test]
    fn an_unrecognised_line_hides_absence() {
        let entries = decode_list("garbage").unwrap();
        assert_eq!(presence(&entries, "core.restate"), Presence::Unrecognised);
    }

    #[test]
    fn finds_presence_by_name() {
        let entries = decode_list(&format!("{RUNNING}{ENDED}")).unwrap();
        assert_eq!(
            presence(&entries, "core.restate"),
            Presence::Running {
                pid: 60889,
                created_unix_seconds: 1_791_528_126
            }
        );
        assert_eq!(
            presence(&entries, "core.endpoint"),
            Presence::Ended { pid: 60267 }
        );
        assert_eq!(presence(&entries, "core.other"), Presence::Absent);
    }

    #[test]
    fn a_duplicate_name_is_unrecognised() {
        let entries = decode_list(&format!("{RUNNING}{RUNNING}")).unwrap();
        assert_eq!(count_named(&entries, "core.restate"), 2);
        assert_eq!(presence(&entries, "core.restate"), Presence::Unrecognised);
    }

    #[test]
    fn refuses_a_list_over_the_bound() {
        let many = RUNNING.repeat(LIST_SESSIONS_MAX + 1);
        assert_eq!(
            decode_list(&many),
            Err(ListError::TooManySessions(LIST_SESSIONS_MAX + 1))
        );
    }
}

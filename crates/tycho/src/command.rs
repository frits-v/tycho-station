//! Runs an external program with a timeout and a cap on the output it may produce.

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{COMMAND_OUTPUT_MAX_BYTES, POLL_INTERVAL};

#[derive(Debug)]
pub enum CommandError {
    Spawn(String, io::Error),
    Wait(io::Error),
    TimedOut(String, Duration),
    OutputTooLarge(String, usize),
    NotUtf8(String),
    Failed(String, ExitStatus, String),
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(program, error) => write!(formatter, "cannot start {program}: {error}"),
            Self::Wait(error) => write!(formatter, "cannot wait for a child: {error}"),
            Self::TimedOut(program, limit) => {
                write!(formatter, "{program} did not finish within {limit:?}")
            }
            Self::OutputTooLarge(program, limit) => {
                write!(formatter, "{program} wrote more than {limit} bytes")
            }
            Self::NotUtf8(program) => write!(formatter, "{program} wrote output that is not UTF-8"),
            Self::Failed(program, status, stderr) => {
                write!(
                    formatter,
                    "{program} exited with {status}: {}",
                    stderr.trim()
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// Runs to completion and fails on a non-zero exit.
pub fn run_captured(
    program: &Path,
    arguments: &[&str],
    environment: &[(&str, &str)],
    timeout: Duration,
) -> Result<Captured, CommandError> {
    let captured = run_status(program, arguments, environment, timeout)?;
    if !captured.status.success() {
        return Err(CommandError::Failed(
            program.display().to_string(),
            captured.status,
            captured.stderr,
        ));
    }
    Ok(captured)
}

/// Runs to completion and returns the exit status whatever it is.
pub fn run_status(
    program: &Path,
    arguments: &[&str],
    environment: &[(&str, &str)],
    timeout: Duration,
) -> Result<Captured, CommandError> {
    run_status_capped(
        program,
        arguments,
        environment,
        &[],
        timeout,
        COMMAND_OUTPUT_MAX_BYTES,
    )
}

/// `run_status` with inherited variables removed and a caller's cap on each of stdout and
/// stderr.
pub fn run_status_capped(
    program: &Path,
    arguments: &[&str],
    environment: &[(&str, &str)],
    removed: &[OsString],
    timeout: Duration,
    output_max_bytes: usize,
) -> Result<Captured, CommandError> {
    let name = program.display().to_string();
    let mut command = Command::new(program);
    for variable in removed {
        command.env_remove(variable);
    }
    let mut child = command
        .args(arguments)
        .envs(environment.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| CommandError::Spawn(name.clone(), error))?;
    let started = Instant::now();
    let deadline = started.checked_add(timeout).unwrap_or(started);
    let stdout = child
        .stdout
        .take()
        .map(|source| bounded_reader(source, output_max_bytes));
    let stderr = child
        .stderr
        .take()
        .map(|source| bounded_reader(source, output_max_bytes));
    let status = wait_bounded(&mut child, &name, timeout)?;
    let limits = (deadline, timeout, output_max_bytes);
    let stdout = collect(stdout, &name, limits)?;
    let stderr = collect(stderr, &name, limits)?;
    Ok(Captured {
        status,
        stdout,
        stderr,
    })
}

/// Runs with no pipes, for a program that leaves a daemon behind holding its descriptors.
pub fn run_detached(
    program: &Path,
    arguments: &[&str],
    environment: &[(&str, &str)],
    removed: &[OsString],
    timeout: Duration,
) -> Result<ExitStatus, CommandError> {
    let name = program.display().to_string();
    let mut command = Command::new(program);
    for variable in removed {
        command.env_remove(variable);
    }
    let mut child = command
        .args(arguments)
        .envs(environment.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| CommandError::Spawn(name.clone(), error))?;
    wait_bounded(&mut child, &name, timeout)
}

fn wait_bounded(
    child: &mut Child,
    name: &str,
    timeout: Duration,
) -> Result<ExitStatus, CommandError> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if let Some(status) = child.try_wait().map_err(CommandError::Wait)? {
            return Ok(status);
        }
        thread::sleep(POLL_INTERVAL.min(timeout));
    }
    child.kill().map_err(CommandError::Wait)?;
    child.wait().map_err(CommandError::Wait)?;
    Err(CommandError::TimedOut(name.to_string(), timeout))
}

type Reader = mpsc::Receiver<io::Result<Vec<u8>>>;

/// The reader thread is detached: a grandchild that inherited the pipe can hold it open
/// past the deadline, and the caller must not wait for it.
fn bounded_reader(source: impl Read + Send + 'static, output_max_bytes: usize) -> Reader {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let limit = u64::try_from(output_max_bytes).unwrap_or(u64::MAX);
        let read = source
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        // The receiver is gone when the caller gave up at its deadline.
        drop(sender.send(read));
    });
    receiver
}

fn collect(
    reader: Option<Reader>,
    name: &str,
    (deadline, timeout, output_max_bytes): (Instant, Duration, usize),
) -> Result<String, CommandError> {
    let Some(reader) = reader else {
        return Ok(String::new());
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let bytes = match reader.recv_timeout(remaining) {
        Ok(read) => read.map_err(CommandError::Wait)?,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            return Err(CommandError::TimedOut(name.to_string(), timeout))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err(CommandError::Wait(io::Error::other(
                "output reader thread ended without a result",
            )))
        }
    };
    if bytes.len() > output_max_bytes {
        return Err(CommandError::OutputTooLarge(
            name.to_string(),
            output_max_bytes,
        ));
    }
    String::from_utf8(bytes).map_err(|_| CommandError::NotUtf8(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_stdout() {
        let captured = run_captured(
            Path::new("/bin/echo"),
            &["hello"],
            &[],
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(captured.stdout, "hello\n");
    }

    #[test]
    fn times_out_a_slow_program() {
        let result = run_captured(
            Path::new("/bin/sleep"),
            &["5"],
            &[],
            Duration::from_millis(300),
        );
        assert!(matches!(result, Err(CommandError::TimedOut(_, _))));
    }

    #[test]
    fn a_grandchild_holding_stdout_times_out() {
        let started = Instant::now();
        let result = run_captured(
            Path::new("/bin/sh"),
            &["-c", "sleep 3 & exit 0"],
            &[],
            Duration::from_millis(500),
        );
        assert!(matches!(result, Err(CommandError::TimedOut(_, _))));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn rejects_output_over_the_cap() {
        let count = (COMMAND_OUTPUT_MAX_BYTES + 1).to_string();
        let result = run_captured(
            Path::new("/usr/bin/head"),
            &["-c", &count, "/dev/zero"],
            &[],
            Duration::from_secs(5),
        );
        assert!(matches!(
            result,
            Err(CommandError::OutputTooLarge(_, COMMAND_OUTPUT_MAX_BYTES))
        ));
    }

    #[test]
    fn a_caller_cap_rejects_output_the_default_cap_allows() {
        let result = run_status_capped(
            Path::new("/usr/bin/head"),
            &["-c", "65", "/dev/zero"],
            &[],
            &[],
            Duration::from_secs(5),
            64,
        );
        assert!(matches!(result, Err(CommandError::OutputTooLarge(_, 64))));
    }

    #[test]
    fn a_caller_cap_admits_output_over_the_default_cap() {
        let count = (COMMAND_OUTPUT_MAX_BYTES + 1).to_string();
        let captured = run_status_capped(
            Path::new("/usr/bin/head"),
            &["-c", &count, "/dev/zero"],
            &[],
            &[],
            Duration::from_secs(5),
            COMMAND_OUTPUT_MAX_BYTES * 2,
        )
        .unwrap();
        assert_eq!(captured.stdout.len(), COMMAND_OUTPUT_MAX_BYTES + 1);
    }

    #[test]
    fn removes_an_inherited_variable_and_keeps_a_set_one() {
        let captured = run_status_capped(
            Path::new("/usr/bin/env"),
            &[],
            &[("TYCHO_COMMAND_SET", "kept")],
            &[OsString::from("HOME")],
            Duration::from_secs(5),
            COMMAND_OUTPUT_MAX_BYTES,
        )
        .unwrap();
        assert!(captured.stdout.contains("TYCHO_COMMAND_SET=kept"));
        assert!(!captured
            .stdout
            .lines()
            .any(|line| line.starts_with("HOME=")));
    }
}

//! Child processes run with a deadline, stdin closed, stderr inherited and stdout captured up
//! to a cap.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_millis(200);
const READER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
const OUTPUT_MAX_BYTES: u64 = 4 << 20;

/// How a bounded child process ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    Signal,
    TimedOut,
    OutputTooLarge,
    OutputUnreadable,
    NotStarted(String),
}

#[derive(Debug)]
pub struct Captured {
    pub exit: Exit,
    pub stdout: String,
}

/// Runs a command with stdin closed, stderr inherited and stdout captured up to the cap.
pub fn run_bounded(command: &mut Command, timeout: Duration) -> Captured {
    println!("xtask: {}", describe(command));
    let spawned = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            return Captured {
                exit: Exit::NotStarted(error.to_string()),
                stdout: String::new(),
            }
        }
    };
    let (sender, receiver) = mpsc::channel();
    if let Some(pipe) = child.stdout.take() {
        thread::spawn(move || {
            let mut kept = Vec::new();
            let mut limited = pipe.take(OUTPUT_MAX_BYTES.saturating_add(1));
            let read = limited.read_to_end(&mut kept);
            let mut rest = limited.into_inner();
            // Draining past the cap keeps the child from blocking on a full pipe.
            let drained = std::io::copy(&mut rest, &mut std::io::sink());
            let state = if read.is_err() || drained.is_err() {
                Some(Exit::OutputUnreadable)
            } else if u64::try_from(kept.len()).map_or(true, |n| n > OUTPUT_MAX_BYTES) {
                Some(Exit::OutputTooLarge)
            } else {
                None
            };
            if sender.send((kept, state)).is_err() {
                eprintln!("xtask: stdout arrived after the reader deadline");
            }
        });
    }
    let exit = wait_with_deadline(&mut child, timeout);
    let Ok((kept, reader_state)) = receiver.recv_timeout(READER_JOIN_TIMEOUT) else {
        let exit = if exit == Exit::Code(0) {
            Exit::OutputUnreadable
        } else {
            exit
        };
        return Captured {
            exit,
            stdout: String::new(),
        };
    };
    let stdout = String::from_utf8_lossy(&kept).into_owned();
    let exit = reader_state.unwrap_or(exit);
    Captured { exit, stdout }
}

fn wait_with_deadline(child: &mut std::process::Child, timeout: Duration) -> Exit {
    let polls = timeout
        .as_millis()
        .checked_div(POLL_INTERVAL.as_millis())
        .unwrap_or(0);
    for _ in 0..polls {
        match child.try_wait() {
            Ok(Some(status)) => return status.code().map_or(Exit::Signal, Exit::Code),
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => {
                stop(child);
                return Exit::NotStarted(error.to_string());
            }
        }
    }
    stop(child);
    Exit::TimedOut
}

fn stop(child: &mut std::process::Child) {
    if let Err(error) = child.kill() {
        eprintln!("xtask: could not kill the timed out process: {error}");
    }
    if let Err(error) = child.wait() {
        eprintln!("xtask: could not reap the timed out process: {error}");
    }
}

/// The program and its arguments; environment values, where tokens live, are never shown.
fn describe(command: &Command) -> String {
    let mut parts = vec![command.get_program().to_string_lossy().into_owned()];
    parts.extend(command.get_args().map(|a| a.to_string_lossy().into_owned()));
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUICK_TIMEOUT: Duration = Duration::from_secs(120);

    #[test]
    fn described_commands_never_show_the_token() {
        let mut command = Command::new("release-plz");
        command
            .args(["release-pr", "--output", "json"])
            .env("GIT_TOKEN", "secret-value");
        let shown = describe(&command);
        assert_eq!(shown, "release-plz release-pr --output json");
        assert!(!shown.contains("secret-value"));
    }

    #[test]
    fn bounded_run_times_out_and_captures_stdout() {
        let quick = run_bounded(Command::new("sh").args(["-c", "echo hello"]), QUICK_TIMEOUT);
        assert_eq!(quick.exit, Exit::Code(0));
        assert_eq!(quick.stdout.trim(), "hello");
        let slow = run_bounded(
            Command::new("sh").args(["-c", "sleep 5"]),
            Duration::from_millis(400),
        );
        assert_eq!(slow.exit, Exit::TimedOut);
        let flood = format!("head -c {} /dev/zero", OUTPUT_MAX_BYTES.saturating_add(10));
        let large = run_bounded(Command::new("sh").args(["-c", &flood]), QUICK_TIMEOUT);
        assert_eq!(large.exit, Exit::OutputTooLarge);
        let missing = run_bounded(&mut Command::new("no-such-program-xtask"), QUICK_TIMEOUT);
        assert!(matches!(missing.exit, Exit::NotStarted(_)));
    }
}

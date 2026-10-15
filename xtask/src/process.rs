//! Child processes run with a deadline, stdin closed or inherited, stdout captured up to a cap,
//! and stderr inherited, captured up to the same cap, or merged into stdout in the order it
//! was written.

use std::io::{PipeReader, Read, Write};
use std::process::{ChildStderr, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

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
    /// The child exited cleanly but its output pipe stayed open past the reader deadline,
    /// held by a process it started.
    OutputStillOpen,
    NotStarted(String),
}

#[derive(Debug)]
pub struct Captured {
    pub exit: Exit,
    pub stdout: String,
    /// Empty unless the command ran through `run_bounded_capturing_stderr`.
    pub stderr: String,
}

/// Runs a command with stdin closed, stderr inherited and stdout captured up to the cap.
pub fn run_bounded(command: &mut Command, timeout: Duration) -> Captured {
    run_with(command, timeout, Stdio::null(), false)
}

/// Runs a command with stdin closed and both stdout and stderr captured up to the cap.
pub fn run_bounded_capturing_stderr(command: &mut Command, timeout: Duration) -> Captured {
    run_with(command, timeout, Stdio::null(), true)
}

/// Runs a command with this process's stdin, so a prompt the child reads from the terminal
/// reaches the operator, and both stdout and stderr captured up to the cap.
pub fn run_bounded_with_terminal_input(command: &mut Command, timeout: Duration) -> Captured {
    run_with(command, timeout, Stdio::inherit(), true)
}

/// Runs a command with stdin closed and stderr written into the same pipe as stdout, so the
/// two keep their order. The output is echoed to stdout as it arrives and captured up to the
/// cap.
pub fn run_bounded_merged(command: &mut Command, timeout: Duration) -> Captured {
    run_merged(command, timeout, std::io::stdout())
}

fn run_merged<W: Write + Send + 'static>(
    command: &mut Command,
    timeout: Duration,
    echo: W,
) -> Captured {
    println!("xtask: {}", describe(command));
    let not_started = |error: std::io::Error| Captured {
        exit: Exit::NotStarted(error.to_string()),
        stdout: String::new(),
        stderr: String::new(),
    };
    let (reader, writer) = match std::io::pipe() {
        Ok(pair) => pair,
        Err(error) => return not_started(error),
    };
    let error_writer = match writer.try_clone() {
        Ok(clone) => clone,
        Err(error) => return not_started(error),
    };
    let spawned = command
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(error_writer)
        .spawn();
    // The command holds the write ends until they are replaced; the reader sees end of file
    // only once the child's copies are the last ones.
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return not_started(error),
    };
    let merged_reader = read_echoed(reader, echo);
    let exit = wait_with_deadline(&mut child, timeout);
    let (stdout, exit) = collect(Some(merged_reader), exit);
    Captured {
        exit,
        stdout,
        stderr: String::new(),
    }
}

/// A run whose stdout lines were timed: the run, and when each line had arrived, measured from
/// the spawn. Past `LINE_TIMES_MAX` lines the rest carry no time.
#[derive(Debug)]
pub struct TimedLines {
    pub captured: Captured,
    pub line_ends: Vec<Duration>,
}

const LINE_TIMES_MAX: usize = 1 << 18;

/// Runs a command with stdin closed and stderr inherited, capturing stdout up to `max_bytes`
/// and the time each of its lines arrived.
pub fn run_bounded_timed_lines(
    command: &mut Command,
    timeout: Duration,
    max_bytes: u64,
) -> TimedLines {
    println!("xtask: {}", describe(command));
    let spawned = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            return TimedLines {
                captured: Captured {
                    exit: Exit::NotStarted(error.to_string()),
                    stdout: String::new(),
                    stderr: String::new(),
                },
                line_ends: Vec::new(),
            }
        }
    };
    let started = Instant::now();
    let (times_sender, times_receiver) = mpsc::channel();
    let reader = child
        .stdout
        .take()
        .map(|pipe| read_timed(pipe, max_bytes, started, times_sender));
    let exit = wait_with_deadline(&mut child, timeout);
    let (stdout, exit) = collect(reader, exit);
    TimedLines {
        captured: Captured {
            exit,
            stdout,
            stderr: String::new(),
        },
        line_ends: times_receiver.try_recv().unwrap_or_default(),
    }
}

fn read_timed(
    pipe: ChildStdout,
    max_bytes: u64,
    started: Instant,
    times: mpsc::Sender<Vec<Duration>>,
) -> ReaderResult {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut line_ends = Vec::new();
        let mut limited = pipe.take(max_bytes.saturating_add(1));
        let mut chunk = [0_u8; 8192];
        let mut state = None;
        let mut reading = true;
        while reading {
            match limited.read(&mut chunk) {
                Ok(0) => reading = false,
                Ok(count) => {
                    let part = chunk.get(..count).unwrap_or_default();
                    let arrived = started.elapsed();
                    let lines = part.iter().fold(0_usize, |lines, byte| {
                        lines.saturating_add(usize::from(*byte == b'\n'))
                    });
                    let room = LINE_TIMES_MAX.saturating_sub(line_ends.len());
                    line_ends.extend(std::iter::repeat_n(arrived, lines.min(room)));
                    kept.extend_from_slice(part);
                }
                Err(_) => {
                    state = Some(Exit::OutputUnreadable);
                    reading = false;
                }
            }
        }
        let mut rest = limited.into_inner();
        if std::io::copy(&mut rest, &mut std::io::sink()).is_err() {
            state = Some(Exit::OutputUnreadable);
        }
        if u64::try_from(kept.len()).map_or(true, |n| n > max_bytes) {
            state = Some(Exit::OutputTooLarge);
        }
        // The times go first, so they are there once the collector has the text.
        if times.send(line_ends).is_err() {
            eprintln!("xtask: line times arrived after the reader deadline");
        }
        if sender.send((kept, state)).is_err() {
            eprintln!("xtask: output arrived after the reader deadline");
        }
    });
    receiver
}

type ReaderResult = mpsc::Receiver<(Vec<u8>, Option<Exit>)>;

fn run_with(
    command: &mut Command,
    timeout: Duration,
    stdin_mode: Stdio,
    capture_stderr: bool,
) -> Captured {
    println!("xtask: {}", describe(command));
    let stderr_mode = if capture_stderr {
        Stdio::piped()
    } else {
        Stdio::inherit()
    };
    let spawned = command
        .stdin(stdin_mode)
        .stdout(Stdio::piped())
        .stderr(stderr_mode)
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            return Captured {
                exit: Exit::NotStarted(error.to_string()),
                stdout: String::new(),
                stderr: String::new(),
            }
        }
    };
    let stdout_reader = child.stdout.take().map(Pipe::Out).map(read_capped);
    let stderr_reader = child.stderr.take().map(Pipe::Err).map(read_capped);
    let exit = wait_with_deadline(&mut child, timeout);
    let (stdout, exit) = collect(stdout_reader, exit);
    let (stderr, exit) = match stderr_reader {
        Some(reader) => collect(Some(reader), exit),
        None => (String::new(), exit),
    };
    Captured {
        exit,
        stdout,
        stderr,
    }
}

enum Pipe {
    Out(ChildStdout),
    Err(ChildStderr),
}

impl Read for Pipe {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Out(pipe) => pipe.read(buffer),
            Self::Err(pipe) => pipe.read(buffer),
        }
    }
}

fn read_capped(pipe: Pipe) -> ReaderResult {
    let (sender, receiver) = mpsc::channel();
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
            eprintln!("xtask: output arrived after the reader deadline");
        }
    });
    receiver
}

fn read_echoed<W: Write + Send + 'static>(pipe: PipeReader, mut echo: W) -> ReaderResult {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut limited = pipe.take(OUTPUT_MAX_BYTES.saturating_add(1));
        let mut chunk = [0_u8; 8192];
        let mut state = None;
        let mut reading = true;
        while reading {
            match limited.read(&mut chunk) {
                Ok(0) => reading = false,
                Ok(count) => {
                    let part = chunk.get(..count).unwrap_or_default();
                    kept.extend_from_slice(part);
                    if echo.write_all(part).and_then(|()| echo.flush()).is_err() {
                        state = Some(Exit::OutputUnreadable);
                    }
                }
                Err(_) => {
                    state = Some(Exit::OutputUnreadable);
                    reading = false;
                }
            }
        }
        let mut rest = limited.into_inner();
        if std::io::copy(&mut rest, &mut std::io::sink()).is_err() {
            state = Some(Exit::OutputUnreadable);
        }
        if u64::try_from(kept.len()).map_or(true, |n| n > OUTPUT_MAX_BYTES) {
            state = Some(Exit::OutputTooLarge);
        }
        if sender.send((kept, state)).is_err() {
            eprintln!("xtask: output arrived after the reader deadline");
        }
    });
    receiver
}

/// The text a reader kept and the exit to report: a reader's own failure overrides a clean
/// exit; after a clean exit, a reader still reading at the deadline becomes `OutputStillOpen`,
/// and a missing or vanished reader becomes `OutputUnreadable`.
fn collect(reader: Option<ReaderResult>, exit: Exit) -> (String, Exit) {
    collect_within(reader, exit, READER_JOIN_TIMEOUT)
}

fn collect_within(reader: Option<ReaderResult>, exit: Exit, deadline: Duration) -> (String, Exit) {
    let Some(receiver) = reader else {
        return (
            String::new(),
            clean_exit_becomes(exit, Exit::OutputUnreadable),
        );
    };
    match receiver.recv_timeout(deadline) {
        Ok((kept, reader_state)) => {
            let text = String::from_utf8_lossy(&kept).into_owned();
            (text, reader_state.unwrap_or(exit))
        }
        Err(mpsc::RecvTimeoutError::Timeout) => (
            String::new(),
            clean_exit_becomes(exit, Exit::OutputStillOpen),
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => (
            String::new(),
            clean_exit_becomes(exit, Exit::OutputUnreadable),
        ),
    }
}

fn clean_exit_becomes(exit: Exit, instead: Exit) -> Exit {
    if exit == Exit::Code(0) {
        instead
    } else {
        exit
    }
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

    #[test]
    fn timed_lines_carry_when_each_line_arrived_and_the_cap_is_the_callers() {
        let timed = run_bounded_timed_lines(
            Command::new("sh").args(["-c", "echo one; sleep 0.4; echo two"]),
            QUICK_TIMEOUT,
            1024,
        );
        assert_eq!(timed.captured.exit, Exit::Code(0));
        assert_eq!(timed.captured.stdout, "one\ntwo\n");
        assert_eq!(timed.line_ends.len(), 2);
        let gap = timed
            .line_ends
            .get(1)
            .unwrap()
            .saturating_sub(*timed.line_ends.first().unwrap());
        assert!(gap >= Duration::from_millis(300), "{gap:?}");
        let over = run_bounded_timed_lines(
            Command::new("sh").args(["-c", "head -c 2048 /dev/zero"]),
            QUICK_TIMEOUT,
            1024,
        );
        assert_eq!(over.captured.exit, Exit::OutputTooLarge);
        let missing = run_bounded_timed_lines(
            &mut Command::new("no-such-program-xtask"),
            QUICK_TIMEOUT,
            1024,
        );
        assert!(matches!(missing.captured.exit, Exit::NotStarted(_)));
        assert!(missing.line_ends.is_empty());
    }

    #[test]
    fn merged_run_keeps_stdout_and_stderr_in_the_order_written() {
        let merged = run_merged(
            Command::new("sh").args(["-c", "echo one; echo two >&2; echo three"]),
            QUICK_TIMEOUT,
            std::io::sink(),
        );
        assert_eq!(merged.exit, Exit::Code(0));
        assert_eq!(merged.stdout, "one\ntwo\nthree\n");
        assert!(merged.stderr.is_empty());
        let flood = format!(
            "head -c {} /dev/zero >&2",
            OUTPUT_MAX_BYTES.saturating_add(10)
        );
        let large = run_merged(
            Command::new("sh").args(["-c", &flood]),
            QUICK_TIMEOUT,
            std::io::sink(),
        );
        assert_eq!(large.exit, Exit::OutputTooLarge);
        let missing = run_merged(
            &mut Command::new("no-such-program-xtask"),
            QUICK_TIMEOUT,
            std::io::sink(),
        );
        assert!(matches!(missing.exit, Exit::NotStarted(_)));
    }

    #[test]
    fn a_reader_still_reading_at_the_deadline_after_a_clean_exit_is_output_still_open() {
        let (sender, receiver) = mpsc::channel();
        let quick = Duration::from_millis(10);
        assert_eq!(
            collect_within(Some(receiver), Exit::Code(0), quick),
            (String::new(), Exit::OutputStillOpen)
        );
        let (_still_reading, receiver) = mpsc::channel::<(Vec<u8>, Option<Exit>)>();
        assert_eq!(
            collect_within(Some(receiver), Exit::Code(101), quick).1,
            Exit::Code(101)
        );
        drop(sender);
    }

    #[test]
    fn a_reader_that_vanished_or_never_started_after_a_clean_exit_is_output_unreadable() {
        let (sender, receiver) = mpsc::channel::<(Vec<u8>, Option<Exit>)>();
        drop(sender);
        assert_eq!(
            collect(Some(receiver), Exit::Code(0)),
            (String::new(), Exit::OutputUnreadable)
        );
        assert_eq!(collect(None, Exit::Code(0)).1, Exit::OutputUnreadable);
    }

    #[test]
    fn capturing_run_keeps_stderr_apart_and_bounds_it() {
        let both = run_bounded_capturing_stderr(
            Command::new("sh").args(["-c", "echo out; echo err >&2"]),
            QUICK_TIMEOUT,
        );
        assert_eq!(both.exit, Exit::Code(0));
        assert_eq!(both.stdout.trim(), "out");
        assert_eq!(both.stderr.trim(), "err");
        let flood = format!(
            "head -c {} /dev/zero >&2",
            OUTPUT_MAX_BYTES.saturating_add(10)
        );
        let large =
            run_bounded_capturing_stderr(Command::new("sh").args(["-c", &flood]), QUICK_TIMEOUT);
        assert_eq!(large.exit, Exit::OutputTooLarge);
        let inherited = run_bounded(
            Command::new("sh").args(["-c", "echo err >&2"]),
            QUICK_TIMEOUT,
        );
        assert!(inherited.stderr.is_empty());
    }

    #[test]
    fn terminal_input_run_captures_stdout_and_stderr_apart() {
        let both = run_bounded_with_terminal_input(
            Command::new("sh").args(["-c", "echo out; echo err >&2; exit 3"]),
            QUICK_TIMEOUT,
        );
        assert_eq!(both.exit, Exit::Code(3));
        assert_eq!(both.stdout.trim(), "out");
        assert_eq!(both.stderr.trim(), "err");
    }
}

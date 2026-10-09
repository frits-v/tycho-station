//! Facts about a process from `ps` (uid, process group, start time, command line), decoded
//! with an unrecognised state, and signals.

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tycho_types::lease::PID_MAX;

use crate::command;
use crate::config::COMMAND_TIMEOUT;

const PS: &str = "/bin/ps";
const ETIME_MAX_BYTES: usize = 32;
const COMMAND_MAX_BYTES: usize = 4096;
/// A launcher's pid is its zmx shell's pid through `exec`, so the process starts before the
/// shell's startup files finish and the lease records its start.
pub const START_LEAD_MAX_SECONDS: u64 = 30;
/// `ps` reports whole seconds and the record is taken after the process exists.
pub const START_LAG_MAX_SECONDS: u64 = 2;
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 3600;
const SECONDS_PER_DAY: u64 = 86_400;

/// One `ps -o etime=` value: `[[dd-]hh:]mm:ss`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Elapsed {
    Seconds(u64),
    Unrecognised(String),
}

/// What `ps` says about one pid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub uid: u32,
    pub pgid: u32,
    pub started_unix_seconds: u64,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessFacts {
    Running(Facts),
    Gone,
    Unrecognised(String),
}

#[must_use]
pub fn decode_etime(text: &str) -> Elapsed {
    let trimmed = text.trim();
    let unrecognised = || Elapsed::Unrecognised(trimmed.chars().take(ETIME_MAX_BYTES).collect());
    if trimmed.is_empty() || trimmed.len() > ETIME_MAX_BYTES {
        return unrecognised();
    }
    let (days, clock) = match trimmed.split_once('-') {
        Some((days, clock)) => (Some(days), clock),
        None => (None, trimmed),
    };
    let fields: Vec<Option<u64>> = clock.split(':').map(two_digits).collect();
    let (hours, minutes, seconds) = match fields.as_slice() {
        [Some(minutes), Some(seconds)] if days.is_none() => (0, *minutes, *seconds),
        [Some(hours), Some(minutes), Some(seconds)] => (*hours, *minutes, *seconds),
        _ => return unrecognised(),
    };
    let days = match days.map(str::parse::<u64>) {
        None => 0,
        Some(Ok(days)) => days,
        Some(Err(_)) => return unrecognised(),
    };
    if hours > 23 || minutes > 59 || seconds > 59 {
        return unrecognised();
    }
    days.checked_mul(SECONDS_PER_DAY)
        .and_then(|total| total.checked_add(hours.checked_mul(SECONDS_PER_HOUR)?))
        .and_then(|total| total.checked_add(minutes.checked_mul(SECONDS_PER_MINUTE)?))
        .and_then(|total| total.checked_add(seconds))
        .map_or_else(unrecognised, Elapsed::Seconds)
}

fn two_digits(field: &str) -> Option<u64> {
    let digits = field.len() == 2 && field.bytes().all(|byte| byte.is_ascii_digit());
    digits.then(|| field.parse().ok()).flatten()
}

/// Whether a process that started at `process_start` is the one a record took at `recorded_ms`.
#[must_use]
pub const fn start_matches(process_start_unix_seconds: u64, recorded_unix_ms: u64) -> bool {
    let recorded = recorded_unix_ms / 1000;
    process_start_unix_seconds <= recorded.saturating_add(START_LAG_MAX_SECONDS)
        && recorded.saturating_sub(process_start_unix_seconds) <= START_LEAD_MAX_SECONDS
}

/// `tycho session-leader -- <program> <arguments>`: becomes the leader of a new session with
/// no controlling terminal, then execs the program; returns only the reason it could not.
///
/// Under zmx the pty is the launcher's controlling terminal, and a vendor in a background
/// group there is stopped with `SIGTTOU` by any tool that sets terminal modes, such as `stty`
/// in a login shell's startup file. The new session's group id is the vendor's pid, so the
/// launcher's group signal reaches it and everything it starts.
#[must_use]
pub fn exec_session_leader(words: &[String]) -> String {
    let Some(([separator, program], arguments)) = words.split_first_chunk::<2>() else {
        return "expected -- <program> [arguments]".to_string();
    };
    if separator != "--" {
        return format!("expected -- before the program, found {separator:?}");
    }
    if let Err(error) = nix::unistd::setsid() {
        return format!("setsid: {error}");
    }
    let error = std::process::Command::new(program).args(arguments).exec();
    format!("{program}: {error}")
}

#[must_use]
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Decodes one `ps -o uid=,pgid=,etime=,command=` line taken at `now_unix_seconds`.
#[must_use]
pub fn decode_facts(stdout: &str, now_unix_seconds: u64) -> ProcessFacts {
    let line = stdout.trim();
    if line.is_empty() {
        return ProcessFacts::Gone;
    }
    let unrecognised = || ProcessFacts::Unrecognised(line.chars().take(ETIME_MAX_BYTES).collect());
    if line.len() > COMMAND_MAX_BYTES || line.lines().count() != 1 {
        return unrecognised();
    }
    let mut words = line.split_whitespace();
    let (Some(uid), Some(pgid), Some(etime)) = (words.next(), words.next(), words.next()) else {
        return unrecognised();
    };
    let command = words.collect::<Vec<_>>().join(" ");
    match (uid.parse::<u32>(), pgid.parse::<u32>(), decode_etime(etime)) {
        (Ok(uid), Ok(pgid), Elapsed::Seconds(elapsed)) if !command.is_empty() => {
            ProcessFacts::Running(Facts {
                uid,
                pgid,
                started_unix_seconds: now_unix_seconds.saturating_sub(elapsed),
                command,
            })
        }
        _ => unrecognised(),
    }
}

/// Asks `ps` about the pid; an empty answer is a process that is gone.
#[must_use]
pub fn process_facts(pid: u32) -> ProcessFacts {
    if pid == 0 || pid > PID_MAX {
        return ProcessFacts::Unrecognised(format!("pid {pid} out of range"));
    }
    let pid_text = pid.to_string();
    let captured = match command::run_status(
        Path::new(PS),
        &["-o", "uid=,pgid=,etime=,command=", "-p", &pid_text],
        &[],
        COMMAND_TIMEOUT,
    ) {
        Ok(captured) => captured,
        Err(error) => return ProcessFacts::Unrecognised(error.to_string()),
    };
    let quiet = captured.stdout.trim().is_empty();
    if quiet && !(captured.status.success() || captured.status.code() == Some(1)) {
        return ProcessFacts::Unrecognised(format!("ps exited with {}", captured.status));
    }
    decode_facts(&captured.stdout, now_unix_ms() / 1000)
}

/// Sends `signal` to the pid, or to its process group when `group` is set.
pub fn send(pid: u32, group: bool, signal: Signal) -> Result<(), String> {
    let raw = i32::try_from(pid)
        .ok()
        .filter(|raw| *raw > 0)
        .ok_or_else(|| format!("pid {pid} out of range"))?;
    let result = if group {
        signal::killpg(Pid::from_raw(raw), signal)
    } else {
        signal::kill(Pid::from_raw(raw), signal)
    };
    result.map_err(|error| format!("signal {signal} to {pid}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn decodes_each_etime_form() {
        assert_eq!(decode_etime("00:00"), Elapsed::Seconds(0));
        assert_eq!(decode_etime("  01:02\n"), Elapsed::Seconds(62));
        assert_eq!(decode_etime("03:20:15"), Elapsed::Seconds(12_015));
        assert_eq!(decode_etime("38-03:20:15"), Elapsed::Seconds(3_295_215));
    }

    #[test]
    fn marks_malformed_etime_unrecognised() {
        for text in [
            "",
            "1:02",
            "01:60",
            "24:00:00",
            "x-01:02:03",
            "01-02:03",
            "a:b",
        ] {
            assert!(
                matches!(decode_etime(text), Elapsed::Unrecognised(_)),
                "{text}"
            );
        }
    }

    #[test]
    fn start_matches_only_inside_the_window() {
        let recorded_ms = 1_800_000_000_000;
        let recorded = recorded_ms / 1000;
        assert!(start_matches(recorded, recorded_ms));
        assert!(start_matches(
            recorded - START_LEAD_MAX_SECONDS,
            recorded_ms
        ));
        assert!(start_matches(recorded + START_LAG_MAX_SECONDS, recorded_ms));
        assert!(!start_matches(
            recorded - START_LEAD_MAX_SECONDS - 1,
            recorded_ms
        ));
        assert!(!start_matches(
            recorded + START_LAG_MAX_SECONDS + 1,
            recorded_ms
        ));
    }

    #[test]
    fn decodes_facts_and_marks_anything_else_unrecognised() {
        let now = 1_800_000_000;
        assert_eq!(
            decode_facts("  501 4242    01:02 /opt/tycho launch --spec /a b\n", now),
            ProcessFacts::Running(Facts {
                uid: 501,
                pgid: 4242,
                started_unix_seconds: now - 62,
                command: "/opt/tycho launch --spec /a b".to_string(),
            })
        );
        assert_eq!(decode_facts("\n", now), ProcessFacts::Gone);
        for text in [
            "501 4242 01:02",
            "x 4242 01:02 cmd",
            "501 4242 1:2 cmd",
            "1 2 00:01 a\n3 4 00:01 b",
        ] {
            assert!(
                matches!(decode_facts(text, now), ProcessFacts::Unrecognised(_)),
                "{text}"
            );
        }
    }

    #[test]
    fn a_live_child_has_facts_and_a_reaped_one_is_gone() {
        let mut child = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        let pid = child.id();
        let ProcessFacts::Running(facts) = process_facts(pid) else {
            panic!("no facts for a live child");
        };
        assert_eq!(facts.uid, nix::unistd::Uid::current().as_raw());
        assert!(start_matches(facts.started_unix_seconds, now_unix_ms()));
        assert!(facts.command.contains("sleep 5"), "{}", facts.command);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(process_facts(pid), ProcessFacts::Gone);
    }

    #[test]
    fn a_group_signal_reaches_the_whole_group_and_a_bad_pid_is_refused() {
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        let mut leader = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30 & wait"])
            .process_group(0)
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        send(leader.id(), true, Signal::SIGKILL).unwrap();
        assert_eq!(leader.wait().unwrap().signal(), Some(9));
        assert!(send(0, false, Signal::SIGTERM).is_err());
        assert!(send(u32::MAX, true, Signal::SIGTERM).is_err());
    }
}

//! Process time and signals.

use std::time::{SystemTime, UNIX_EPOCH};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

#[must_use]
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
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

//! Runs a work unit's done criteria against a checkout.
//!
//! Reports a bounded, enumerated outcome per criterion. A criterion that
//! cannot run (it times out, its output is oversized, or the command cannot
//! even spawn) fails; there is no status distinct from failure for that.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

use tycho_types::task_packet::DoneCriterion;

use crate::work_units::{PassCondition, WorkUnit};

/// Wall clock given to one `Command` criterion when the caller names none.
pub const COMMAND_TIMEOUT_DEFAULT_MS: u64 = 60_000;
/// A requested timeout above this is rejected by `VerifyOptions::new`.
pub const COMMAND_TIMEOUT_MAX_MS: u64 = 600_000;
/// `VerifyOptions::default` skips `new`'s check, so the default is held to the maximum here.
const _: () = assert!(COMMAND_TIMEOUT_DEFAULT_MS <= COMMAND_TIMEOUT_MAX_MS);
/// Captured stdout and stderr, combined, larger than this is a failure, not a truncation.
pub const CRITERION_OUTPUT_MAX_BYTES: usize = 65_536;
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Under the checkout's git-ignored `target`, which `CARGO_TARGET_DIR` already points at,
/// so logs neither dirty the tree being verified nor outlive the checkout.
const DEFAULT_LOG_SUBDIRECTORY: &str = "target/tycho-criterion-logs";

/// Fields are private so a timeout above `COMMAND_TIMEOUT_MAX_MS` cannot be represented.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    command_timeout_ms: u64,
    log_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutAboveMaximum {
    pub requested_ms: u64,
}

impl std::fmt::Display for TimeoutAboveMaximum {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "command timeout {} ms; maximum is {COMMAND_TIMEOUT_MAX_MS} ms",
            self.requested_ms
        )
    }
}

impl std::error::Error for TimeoutAboveMaximum {}

impl VerifyOptions {
    /// `log_dir` of `None` means the checkout's `target/tycho-criterion-logs`.
    pub fn new(
        command_timeout_ms: u64,
        log_dir: Option<PathBuf>,
    ) -> Result<Self, TimeoutAboveMaximum> {
        if command_timeout_ms > COMMAND_TIMEOUT_MAX_MS {
            return Err(TimeoutAboveMaximum {
                requested_ms: command_timeout_ms,
            });
        }
        Ok(Self {
            command_timeout_ms,
            log_dir,
        })
    }
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            command_timeout_ms: COMMAND_TIMEOUT_DEFAULT_MS,
            log_dir: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CriterionStatus {
    Passed,
    Failed,
}

#[derive(Debug)]
pub struct CriterionReport {
    pub index: usize,
    pub status: CriterionStatus,
    pub outcome: CriterionOutcome,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CriterionOutcome {
    Command(CommandOutcome),
    Path(PathObservation),
}

/// `Unrecognised` is the decoder's catch-all for an exit status this process cannot read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandOutcome {
    ExitCode(i32),
    Signal,
    Unrecognised,
    TimedOut,
    SpawnFailed,
    OutputTooLarge,
    OutputUnreadable,
    WaitFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathObservation {
    Present,
    Absent,
    Unreadable,
}

enum WaitOutcome {
    Exited(ExitStatus),
    TimedOut,
    PollFailed,
}

enum CapturedOutput {
    Within(String),
    TooLarge(u64),
    ReadFailed,
}

/// Runs every criterion with the default options; see `run_criteria_with`.
#[must_use]
pub fn run_criteria(checkout: &Path, criteria: &[DoneCriterion]) -> Vec<CriterionReport> {
    run_criteria_with(checkout, criteria, &VerifyOptions::default())
}

/// Runs every criterion in order; the index into this slice is carried in the report.
#[must_use]
pub fn run_criteria_with(
    checkout: &Path,
    criteria: &[DoneCriterion],
    options: &VerifyOptions,
) -> Vec<CriterionReport> {
    criteria
        .iter()
        .enumerate()
        .map(|(index, criterion)| run_criterion(checkout, index, criterion, options))
        .collect()
}

/// Runs the done criteria of one work unit against a checkout.
#[must_use]
pub fn verify_unit(
    checkout: &Path,
    unit: &WorkUnit,
    options: &VerifyOptions,
) -> Vec<CriterionReport> {
    run_criteria_with(checkout, &unit.packet.done_criteria, options)
}

/// Whether a unit passed: `EscalationRaised` never does here; `CriteriaPass` needs all reports passing and at least one.
#[must_use]
pub fn unit_passed(pass_condition: PassCondition, reports: &[CriterionReport]) -> bool {
    match pass_condition {
        PassCondition::CriteriaPass => {
            !reports.is_empty()
                && reports
                    .iter()
                    .all(|report| report.status == CriterionStatus::Passed)
        }
        PassCondition::EscalationRaised => false,
    }
}

fn run_criterion(
    checkout: &Path,
    index: usize,
    criterion: &DoneCriterion,
    options: &VerifyOptions,
) -> CriterionReport {
    match criterion {
        DoneCriterion::Command {
            command,
            expected_exit,
        } => evaluate_command(checkout, index, command.as_str(), *expected_exit, options),
        DoneCriterion::FilePresent { path } => evaluate_path(checkout, index, path.as_str(), true),
        DoneCriterion::FileAbsent { path } => evaluate_path(checkout, index, path.as_str(), false),
    }
}

fn observe_path(checkout: &Path, relative: &str) -> PathObservation {
    match fs::symlink_metadata(checkout.join(relative)) {
        Ok(_) => PathObservation::Present,
        Err(error) if error.kind() == ErrorKind::NotFound => PathObservation::Absent,
        Err(_) => PathObservation::Unreadable,
    }
}

fn evaluate_path(
    checkout: &Path,
    index: usize,
    relative: &str,
    want_present: bool,
) -> CriterionReport {
    let observation = observe_path(checkout, relative);
    let passed = match observation {
        PathObservation::Present => want_present,
        PathObservation::Absent => !want_present,
        PathObservation::Unreadable => false,
    };
    CriterionReport {
        index,
        status: pass_or_fail(passed),
        outcome: CriterionOutcome::Path(observation),
        detail: format!("{relative}: {observation:?}"),
    }
}

const fn pass_or_fail(passed: bool) -> CriterionStatus {
    if passed {
        CriterionStatus::Passed
    } else {
        CriterionStatus::Failed
    }
}

fn evaluate_command(
    checkout: &Path,
    index: usize,
    command: &str,
    expected_exit: u8,
    options: &VerifyOptions,
) -> CriterionReport {
    let (outcome, detail, _pid) = run_command(checkout, index, command, options);
    let passed =
        matches!(outcome, CommandOutcome::ExitCode(code) if code == i32::from(expected_exit));
    CriterionReport {
        index,
        status: pass_or_fail(passed),
        detail: format!("{outcome:?}: {detail}"),
        outcome: CriterionOutcome::Command(outcome),
    }
}

/// Splits on whitespace only; the fixture commands carry no quoted arguments.
fn spawn_command(
    checkout: &Path,
    index: usize,
    command: &str,
    options: &VerifyOptions,
) -> Result<(Child, PathBuf), String> {
    let mut parts = command.split_whitespace();
    let Some(program) = parts.next() else {
        return Err("command is empty".to_string());
    };
    let log_dir = options
        .log_dir
        .clone()
        .unwrap_or_else(|| checkout.join(DEFAULT_LOG_SUBDIRECTORY));
    fs::create_dir_all(&log_dir).map_err(|error| error.to_string())?;
    let output_path = log_dir.join(format!("criterion-{index}.log"));
    let output_file = fs::File::create(&output_path).map_err(|error| error.to_string())?;
    let error_file = output_file.try_clone().map_err(|error| error.to_string())?;
    let mut builder = Command::new(program);
    builder
        .args(parts)
        .current_dir(checkout)
        .env("CARGO_TARGET_DIR", checkout.join("target"))
        .stdin(Stdio::null())
        .stdout(output_file)
        .stderr(error_file);
    set_own_process_group(&mut builder);
    let child = builder.spawn().map_err(|error| error.to_string())?;
    Ok((child, output_path))
}

/// Puts the child in its own process group so a timeout can kill it and
/// anything it spawned (a test binary `cargo test` launches, say) together.
#[cfg(unix)]
fn set_own_process_group(builder: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    builder.process_group(0);
}

#[cfg(not(unix))]
fn set_own_process_group(_builder: &mut Command) {}

/// Kills the child's whole process group through `program` (`kill` in production)
/// and describes the result; a group kill that could not run is reported, not hidden.
/// The `--` is required: procps `kill` rejects `-KILL -<pid>` as a malformed option.
#[cfg(unix)]
fn kill_group(program: &str, pid: u32) -> String {
    let group = format!("-{pid}");
    let status = Command::new(program)
        .args(["-KILL", "--", &group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(status) => format!("group kill {status}"),
        Err(error) => format!("group kill could not run: {error}"),
    }
}

#[cfg(not(unix))]
fn kill_group(_program: &str, _pid: u32) -> String {
    "group kill not supported on this platform".to_string()
}

/// Group kill first so grandchildren die too, then `Child::kill` so the direct
/// child dies even when the group kill could not run, then reap it.
fn terminate(child: &mut Child) -> String {
    let group = kill_group("kill", child.id());
    let direct = match child.kill() {
        Ok(()) => "direct kill sent".to_string(),
        Err(error) => format!("direct kill failed: {error}"),
    };
    let reaped = match child.wait() {
        Ok(status) => format!("reaped with {status}"),
        Err(error) => format!("could not reap: {error}"),
    };
    format!("{group}; {direct}; {reaped}")
}

/// Polls in bounded steps so a runaway process is killed rather than waited on forever.
fn wait_bounded(child: &mut Child, timeout_ms: u64) -> WaitOutcome {
    let polls = Duration::from_millis(timeout_ms)
        .as_millis()
        .checked_div(POLL_INTERVAL.as_millis())
        .unwrap_or(1)
        .max(1);
    for _ in 0..polls {
        match child.try_wait() {
            Ok(Some(status)) => return WaitOutcome::Exited(status),
            Ok(None) => {}
            Err(_) => return WaitOutcome::PollFailed,
        }
        thread::sleep(POLL_INTERVAL);
    }
    WaitOutcome::TimedOut
}

fn classify_exit(status: ExitStatus) -> CommandOutcome {
    if let Some(code) = status.code() {
        return CommandOutcome::ExitCode(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if status.signal().is_some() {
            return CommandOutcome::Signal;
        }
    }
    CommandOutcome::Unrecognised
}

/// Checks the captured size before reading, so an oversized file is reported
/// as a failure without ever being loaded into memory.
fn capture_output(path: &Path) -> CapturedOutput {
    let length = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(_) => return CapturedOutput::ReadFailed,
    };
    let max = u64::try_from(CRITERION_OUTPUT_MAX_BYTES).unwrap_or(u64::MAX);
    if length > max {
        return CapturedOutput::TooLarge(length);
    }
    fs::read(path).map_or(CapturedOutput::ReadFailed, |bytes| {
        CapturedOutput::Within(String::from_utf8_lossy(&bytes).into_owned())
    })
}

fn capture_result(path: &Path, status: ExitStatus) -> (CommandOutcome, String) {
    match capture_output(path) {
        CapturedOutput::Within(detail) => (classify_exit(status), detail),
        CapturedOutput::TooLarge(length) => (
            CommandOutcome::OutputTooLarge,
            format!("output was {length} bytes; maximum is {CRITERION_OUTPUT_MAX_BYTES}"),
        ),
        CapturedOutput::ReadFailed => (
            CommandOutcome::OutputUnreadable,
            "could not read the criterion's captured output".to_string(),
        ),
    }
}

fn run_command(
    checkout: &Path,
    index: usize,
    command: &str,
    options: &VerifyOptions,
) -> (CommandOutcome, String, Option<u32>) {
    let (mut child, output_path) = match spawn_command(checkout, index, command, options) {
        Ok(spawned) => spawned,
        Err(detail) => return (CommandOutcome::SpawnFailed, detail, None),
    };
    let pid = child.id();
    match wait_bounded(&mut child, options.command_timeout_ms) {
        WaitOutcome::Exited(status) => {
            let (outcome, detail) = capture_result(&output_path, status);
            (outcome, detail, Some(pid))
        }
        WaitOutcome::TimedOut => {
            let termination = terminate(&mut child);
            let detail = format!(
                "exceeded its timeout of {} ms; {termination}",
                options.command_timeout_ms
            );
            (CommandOutcome::TimedOut, detail, Some(pid))
        }
        WaitOutcome::PollFailed => {
            let termination = terminate(&mut child);
            let detail = format!("could not poll the child process; {termination}");
            (CommandOutcome::WaitFailed, detail, Some(pid))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::repository;
    use crate::work_units::{self, FixtureError};

    const GRANDCHILD_FIXTURE: &str = "fixtures/scripts/background_sleep.sh";
    /// Bounds the wait for `SIGKILL` to land on a grandchild the test does not own.
    const KILLED_POLLS_MAX: usize = 40;

    /// The checkout and the criterion logs share one temporary root, so nothing a test
    /// writes lands outside a directory the test owns.
    struct Sandbox {
        root: tempfile::TempDir,
    }

    impl Sandbox {
        fn empty() -> Self {
            let sandbox = Self {
                root: tempfile::tempdir().unwrap(),
            };
            fs::create_dir(sandbox.checkout()).unwrap();
            sandbox
        }

        fn built() -> Self {
            let sandbox = Self::empty();
            repository::build(&sandbox.checkout()).unwrap();
            sandbox
        }

        fn checkout(&self) -> PathBuf {
            self.root.path().join("checkout")
        }

        fn options_with_timeout(&self, command_timeout_ms: u64) -> VerifyOptions {
            VerifyOptions::new(command_timeout_ms, Some(self.root.path().join("logs"))).unwrap()
        }

        fn options(&self) -> VerifyOptions {
            self.options_with_timeout(COMMAND_TIMEOUT_DEFAULT_MS)
        }
    }

    fn command_criterion(command: &str) -> DoneCriterion {
        DoneCriterion::Command {
            command: tycho_types::envelope::ShortText::parse(command).unwrap(),
            expected_exit: 0,
        }
    }

    fn unit_by_key(key: &str) -> Result<WorkUnit, FixtureError> {
        let units = work_units::load_default()?;
        Ok(units.into_iter().find(|unit| unit.key == key).unwrap())
    }

    #[test]
    fn the_trivial_units_own_fixture_criteria_fail_fresh_then_pass_after_the_patch() {
        let sandbox = Sandbox::built();
        let unit = unit_by_key("trivial").unwrap();

        let before = verify_unit(&sandbox.checkout(), &unit, &sandbox.options());
        assert!(!unit_passed(unit.pass_condition, &before));
        assert_named_test_failed(&before, "tests::answer_is_42");

        repository::apply_patch(
            &sandbox.checkout(),
            include_bytes!("../fixtures/patches/trivial.patch"),
        )
        .unwrap();
        let after = verify_unit(&sandbox.checkout(), &unit, &sandbox.options());
        assert!(unit_passed(unit.pass_condition, &after));
    }

    #[test]
    fn the_downstream_unit_depends_only_on_the_trivial_patch() {
        let sandbox = Sandbox::built();
        let unit = unit_by_key("downstream-dependent").unwrap();

        let before = verify_unit(&sandbox.checkout(), &unit, &sandbox.options());
        assert!(!unit_passed(unit.pass_condition, &before));
        assert_named_test_failed(&before, "tests::answer_times_two_is_84");

        repository::apply_patch(
            &sandbox.checkout(),
            include_bytes!("../fixtures/patches/trivial.patch"),
        )
        .unwrap();
        let after = verify_unit(&sandbox.checkout(), &unit, &sandbox.options());
        assert!(unit_passed(unit.pass_condition, &after));
    }

    #[test]
    fn the_ambiguous_unit_fails_fresh_then_passes_after_its_own_patch() {
        let sandbox = Sandbox::built();
        let unit = unit_by_key("moderate-and-ambiguous").unwrap();

        let before = verify_unit(&sandbox.checkout(), &unit, &sandbox.options());
        assert!(!unit_passed(unit.pass_condition, &before));
        assert_named_test_failed(&before, "tests::greeting_contains_hello");

        repository::apply_patch(
            &sandbox.checkout(),
            include_bytes!("../fixtures/patches/moderate.patch"),
        )
        .unwrap();
        let after = verify_unit(&sandbox.checkout(), &unit, &sandbox.options());
        assert!(unit_passed(unit.pass_condition, &after));
    }

    /// Confirms a fresh-repository failure is the named test failing, not a
    /// compile error or some other reason that happens to share a nonzero exit.
    fn assert_named_test_failed(reports: &[CriterionReport], test_name: &str) {
        let needle = format!("test {test_name} ... FAILED");
        assert!(
            reports.iter().any(|report| report.detail.contains(&needle)),
            "expected {needle:?} in: {reports:?}"
        );
    }

    #[test]
    fn forced_units_never_pass_by_criteria_even_with_nothing_to_check() {
        for key in ["forced-escalation", "forced-council-split"] {
            let sandbox = Sandbox::built();
            let unit = unit_by_key(key).unwrap();
            assert!(unit.packet.done_criteria.is_empty(), "{key}");
            let reports = verify_unit(&sandbox.checkout(), &unit, &sandbox.options());
            assert!(reports.is_empty());
            assert!(!unit_passed(unit.pass_condition, &reports), "{key}");
        }
    }

    #[test]
    fn vacuous_criteria_pass_with_zero_reports_is_false() {
        assert!(!unit_passed(PassCondition::CriteriaPass, &[]));
    }

    #[test]
    fn a_command_that_cannot_spawn_fails_with_the_spawn_failed_outcome() {
        let sandbox = Sandbox::empty();
        let criteria = [command_criterion("tycho-harness-nonexistent-binary")];
        let reports = run_criteria_with(&sandbox.checkout(), &criteria, &sandbox.options());
        assert_eq!(reports[0].status, CriterionStatus::Failed);
        assert_eq!(
            reports[0].outcome,
            CriterionOutcome::Command(CommandOutcome::SpawnFailed)
        );
    }

    #[test]
    fn output_over_the_cap_fails_as_output_too_large_not_a_truncation() {
        let sandbox = Sandbox::empty();
        let bytes = CRITERION_OUTPUT_MAX_BYTES.saturating_add(1);
        let criteria = [command_criterion(&format!("head -c {bytes} /dev/zero"))];
        let reports = run_criteria_with(&sandbox.checkout(), &criteria, &sandbox.options());
        assert_eq!(reports[0].status, CriterionStatus::Failed);
        assert_eq!(
            reports[0].outcome,
            CriterionOutcome::Command(CommandOutcome::OutputTooLarge)
        );
    }

    #[test]
    fn a_timeout_above_the_maximum_is_rejected_and_the_default_is_separate() {
        let over = COMMAND_TIMEOUT_MAX_MS.saturating_add(1);
        assert_eq!(
            VerifyOptions::new(over, None).unwrap_err(),
            TimeoutAboveMaximum { requested_ms: over }
        );
        let at_max = VerifyOptions::new(COMMAND_TIMEOUT_MAX_MS, None).unwrap();
        assert_eq!(at_max.command_timeout_ms, COMMAND_TIMEOUT_MAX_MS);
        assert_eq!(
            VerifyOptions::default().command_timeout_ms,
            COMMAND_TIMEOUT_DEFAULT_MS
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Liveness {
        Running(String),
        /// Killed, not yet reaped by whichever process inherited it.
        Zombie,
        Gone,
    }

    /// `ps -o stat= -p <pid>` decoded: a `Z` state is a killed process awaiting its
    /// reaper, any other state is running, and no row with empty stderr is gone.
    /// Anything else means the probe could not answer, which fails the test.
    fn probe_process(pid: u32) -> Liveness {
        let output = Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|error| panic!("ps -p {pid} could not run: {error}"));
        let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() && state.starts_with('Z') {
            return Liveness::Zombie;
        }
        if output.status.success() && !state.is_empty() {
            return Liveness::Running(state);
        }
        assert!(
            state.is_empty() && stderr.trim().is_empty(),
            "ps -p {pid} could not answer: {} {state:?} {stderr}",
            output.status
        );
        Liveness::Gone
    }

    fn killed(liveness: &Liveness) -> bool {
        matches!(liveness, Liveness::Zombie | Liveness::Gone)
    }

    fn wait_until_killed(pid: u32) -> Liveness {
        for _ in 0..KILLED_POLLS_MAX {
            let liveness = probe_process(pid);
            if killed(&liveness) {
                return liveness;
            }
            thread::sleep(POLL_INTERVAL);
        }
        probe_process(pid)
    }

    #[test]
    fn a_timed_out_command_is_killed_and_its_child_is_gone() {
        let sandbox = Sandbox::empty();
        let options = sandbox.options_with_timeout(200);
        let started = Instant::now();
        let (outcome, detail, pid) = run_command(&sandbox.checkout(), 0, "sleep 2", &options);
        let elapsed = started.elapsed();
        assert_eq!(outcome, CommandOutcome::TimedOut, "{detail}");
        assert!(
            elapsed < Duration::from_secs(1),
            "took {elapsed:?}: {detail}"
        );
        assert!(detail.contains("group kill exit status: 0"), "{detail}");
        let pid = pid.expect("a timed-out command reports its pid");
        assert_eq!(probe_process(pid), Liveness::Gone, "{detail}");
    }

    fn read_recorded_pid(path: &Path) -> u32 {
        let text = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("{}: no recorded pid: {error}", path.display()));
        text.trim()
            .parse()
            .unwrap_or_else(|error| panic!("{}: {text:?} is not a pid: {error}", path.display()))
    }

    /// Without the group kill, `Child::kill` takes only the shell and the
    /// backgrounded `sleep 30` outlives the timeout; this test then fails.
    #[test]
    fn a_timeout_kills_the_whole_process_group_including_a_backgrounded_grandchild() {
        let sandbox = Sandbox::empty();
        let pid_file = sandbox.root.path().join("grandchild.pid");
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join(GRANDCHILD_FIXTURE);
        let command = format!("sh {} {}", script.display(), pid_file.display());
        assert_eq!(command.split_whitespace().count(), 3, "{command}");
        let options = sandbox.options_with_timeout(500);
        let started = Instant::now();
        let (outcome, detail, _pid) = run_command(&sandbox.checkout(), 0, &command, &options);
        let elapsed = started.elapsed();
        assert_eq!(outcome, CommandOutcome::TimedOut, "{detail}");
        assert!(
            elapsed < Duration::from_secs(2),
            "took {elapsed:?}: {detail}"
        );
        let grandchild = read_recorded_pid(&pid_file);
        let liveness = wait_until_killed(grandchild);
        assert!(killed(&liveness), "{liveness:?}: {detail}");
    }

    #[test]
    fn a_group_kill_that_cannot_run_is_reported_not_hidden() {
        let mut child = Command::new("sleep").arg("5").spawn().unwrap();
        let report = kill_group("tycho-harness-nonexistent-kill", child.id());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(report.starts_with("group kill could not run:"), "{report}");
    }

    #[test]
    fn the_checkout_stays_clean_after_running_a_command_criterion() {
        let sandbox = Sandbox::built();
        let criteria = [command_criterion(
            "cargo test --offline --quiet tests::has_tag_is_false_when_unknown -- --exact",
        )];
        let reports = run_criteria_with(&sandbox.checkout(), &criteria, &sandbox.options());
        assert_eq!(reports[0].status, CriterionStatus::Passed);
        let status = repository::status_porcelain(&sandbox.checkout()).unwrap();
        assert!(status.is_empty(), "git status --porcelain: {status}");
    }

    #[test]
    fn default_options_write_logs_inside_the_checkouts_target_not_beside_it() {
        let sandbox = Sandbox::built();
        let reports = run_criteria(&sandbox.checkout(), &[command_criterion("echo logged")]);
        assert_eq!(reports[0].status, CriterionStatus::Passed, "{reports:?}");
        let siblings: Vec<_> = fs::read_dir(sandbox.root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(siblings, ["checkout"], "beside the checkout: {siblings:?}");
        let log = sandbox
            .checkout()
            .join(DEFAULT_LOG_SUBDIRECTORY)
            .join("criterion-0.log");
        assert_eq!(fs::read_to_string(log).unwrap(), "logged\n");
        let status = repository::status_porcelain(&sandbox.checkout()).unwrap();
        assert!(status.is_empty(), "git status --porcelain: {status}");
    }

    #[test]
    fn file_present_and_absent_criteria_read_the_checkout() {
        let sandbox = Sandbox::built();
        let criteria = [
            DoneCriterion::FilePresent {
                path: tycho_types::task_packet::RelativePath::parse("Cargo.toml").unwrap(),
            },
            DoneCriterion::FileAbsent {
                path: tycho_types::task_packet::RelativePath::parse("does-not-exist").unwrap(),
            },
        ];
        let reports = run_criteria_with(&sandbox.checkout(), &criteria, &sandbox.options());
        assert_eq!(reports[0].status, CriterionStatus::Passed);
        assert_eq!(reports[1].status, CriterionStatus::Passed);
    }
}

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

/// Default wall clock given to one `Command` criterion before it is killed.
pub const COMMAND_TIMEOUT_MAX_MS: u64 = 60_000;
/// Captured stdout and stderr, combined, larger than this is a failure, not a truncation.
pub const CRITERION_OUTPUT_MAX_BYTES: usize = 65_536;
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// `log_dir` defaults to a sibling of the checkout, so criterion output never
/// dirties the tree being verified.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub command_timeout_ms: u64,
    pub log_dir: Option<PathBuf>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            command_timeout_ms: COMMAND_TIMEOUT_MAX_MS,
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

/// Runs the done criteria of one work unit against a checkout, with the default options.
#[must_use]
pub fn verify_unit(checkout: &Path, unit: &WorkUnit) -> Vec<CriterionReport> {
    run_criteria(checkout, &unit.packet.done_criteria)
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

/// A sibling of the checkout, so criterion logs never land inside the tree being verified.
fn default_log_dir(checkout: &Path) -> PathBuf {
    let name = checkout.file_name().map_or_else(
        || "checkout".to_string(),
        |value| value.to_string_lossy().into_owned(),
    );
    let parent = checkout.parent().unwrap_or(checkout);
    parent.join(format!("{name}.criterion-logs"))
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
        .unwrap_or_else(|| default_log_dir(checkout));
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

#[cfg(unix)]
fn kill_group(pid: u32) {
    let group = format!("-{pid}");
    drop(Command::new("kill").args(["-KILL", &group]).status());
}

#[cfg(not(unix))]
fn kill_group(_pid: u32) {}

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
            kill_group(pid);
            drop(child.wait());
            (
                CommandOutcome::TimedOut,
                "exceeded its timeout".to_string(),
                Some(pid),
            )
        }
        WaitOutcome::PollFailed => {
            kill_group(pid);
            drop(child.wait());
            (
                CommandOutcome::WaitFailed,
                "could not poll the child process".to_string(),
                Some(pid),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository;
    use crate::work_units::{self, FixtureError};

    fn built_checkout() -> tempfile::TempDir {
        let checkout = tempfile::tempdir().unwrap();
        repository::build(checkout.path()).unwrap();
        checkout
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
        let checkout = built_checkout();
        let unit = unit_by_key("trivial").unwrap();

        let before = verify_unit(checkout.path(), &unit);
        assert!(!unit_passed(unit.pass_condition, &before));
        assert_named_test_failed(&before, "tests::answer_is_42");

        repository::apply_patch(
            checkout.path(),
            include_bytes!("../fixtures/patches/trivial.patch"),
        )
        .unwrap();
        let after = verify_unit(checkout.path(), &unit);
        assert!(unit_passed(unit.pass_condition, &after));
    }

    #[test]
    fn the_downstream_unit_depends_only_on_the_trivial_patch() {
        let checkout = built_checkout();
        let unit = unit_by_key("downstream-dependent").unwrap();

        let before = verify_unit(checkout.path(), &unit);
        assert!(!unit_passed(unit.pass_condition, &before));
        assert_named_test_failed(&before, "tests::answer_times_two_is_84");

        repository::apply_patch(
            checkout.path(),
            include_bytes!("../fixtures/patches/trivial.patch"),
        )
        .unwrap();
        let after = verify_unit(checkout.path(), &unit);
        assert!(unit_passed(unit.pass_condition, &after));
    }

    #[test]
    fn the_ambiguous_unit_fails_fresh_then_passes_after_its_own_patch() {
        let checkout = built_checkout();
        let unit = unit_by_key("moderate-and-ambiguous").unwrap();

        let before = verify_unit(checkout.path(), &unit);
        assert!(!unit_passed(unit.pass_condition, &before));
        assert_named_test_failed(&before, "tests::greeting_contains_hello");

        repository::apply_patch(
            checkout.path(),
            include_bytes!("../fixtures/patches/moderate.patch"),
        )
        .unwrap();
        let after = verify_unit(checkout.path(), &unit);
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
            let checkout = built_checkout();
            let unit = unit_by_key(key).unwrap();
            assert!(unit.packet.done_criteria.is_empty(), "{key}");
            let reports = verify_unit(checkout.path(), &unit);
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
        let checkout = built_checkout();
        let criteria = [command_criterion("tycho-harness-nonexistent-binary")];
        let reports = run_criteria(checkout.path(), &criteria);
        assert_eq!(reports[0].status, CriterionStatus::Failed);
        assert_eq!(
            reports[0].outcome,
            CriterionOutcome::Command(CommandOutcome::SpawnFailed)
        );
    }

    #[test]
    fn output_over_the_cap_fails_as_output_too_large_not_a_truncation() {
        let checkout = built_checkout();
        let bytes = CRITERION_OUTPUT_MAX_BYTES.saturating_add(1);
        let criteria = [command_criterion(&format!("head -c {bytes} /dev/zero"))];
        let reports = run_criteria(checkout.path(), &criteria);
        assert_eq!(reports[0].status, CriterionStatus::Failed);
        assert_eq!(
            reports[0].outcome,
            CriterionOutcome::Command(CommandOutcome::OutputTooLarge)
        );
    }

    #[test]
    fn a_timed_out_command_is_killed_and_its_child_is_gone() {
        let checkout = built_checkout();
        let logs = tempfile::tempdir().unwrap();
        let options = VerifyOptions {
            command_timeout_ms: 200,
            log_dir: Some(logs.path().to_path_buf()),
        };
        let (outcome, _detail, pid) = run_command(checkout.path(), 0, "sleep 2", &options);
        assert_eq!(outcome, CommandOutcome::TimedOut);
        let pid = pid.expect("a timed-out command reports its pid");
        let still_alive = Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        assert!(!still_alive, "the killed process should no longer exist");
    }

    #[test]
    fn the_checkout_stays_clean_after_running_a_command_criterion() {
        let checkout = built_checkout();
        let criteria = [command_criterion(
            "cargo test --offline --quiet tests::has_tag_is_false_when_unknown -- --exact",
        )];
        let reports = run_criteria(checkout.path(), &criteria);
        assert_eq!(reports[0].status, CriterionStatus::Passed);
        let status = repository::status_porcelain(checkout.path()).unwrap();
        assert!(status.is_empty(), "git status --porcelain: {status}");
    }

    #[test]
    fn file_present_and_absent_criteria_read_the_checkout() {
        let checkout = built_checkout();
        let criteria = [
            DoneCriterion::FilePresent {
                path: tycho_types::task_packet::RelativePath::parse("Cargo.toml").unwrap(),
            },
            DoneCriterion::FileAbsent {
                path: tycho_types::task_packet::RelativePath::parse("does-not-exist").unwrap(),
            },
        ];
        let reports = run_criteria(checkout.path(), &criteria);
        assert_eq!(reports[0].status, CriterionStatus::Passed);
        assert_eq!(reports[1].status, CriterionStatus::Passed);
    }
}

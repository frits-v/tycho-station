//! Runs a work unit's done criteria against a checkout.
//!
//! Reports a bounded, enumerated outcome per criterion. A criterion that
//! cannot run (it times out, its output is oversized, or the command cannot
//! even spawn) fails; there is no status distinct from failure for that.

use std::fs;
use std::io;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

use tycho_types::task_packet::DoneCriterion;

use crate::work_units::{PassCondition, WorkUnit};

/// Wall clock given to one `Command` criterion before it is killed.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
/// Captured stdout and stderr, combined, larger than this is a failure, not a truncation.
pub const CRITERION_OUTPUT_MAX_BYTES: usize = 65_536;
const POLL_INTERVAL: Duration = Duration::from_millis(50);

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathObservation {
    Present,
    Absent,
    Unreadable,
}

/// Runs every criterion in order; the index into this slice is carried in the report.
#[must_use]
pub fn run_criteria(checkout: &Path, criteria: &[DoneCriterion]) -> Vec<CriterionReport> {
    criteria
        .iter()
        .enumerate()
        .map(|(index, criterion)| run_criterion(checkout, index, criterion))
        .collect()
}

/// Runs the done criteria of one work unit against a checkout.
#[must_use]
pub fn verify_unit(checkout: &Path, unit: &WorkUnit) -> Vec<CriterionReport> {
    run_criteria(checkout, &unit.packet.done_criteria)
}

/// Whether a unit passed: `EscalationRaised` never does here; `CriteriaPass` needs all reports passing and at least one.
#[must_use]
pub fn unit_passed(unit: &WorkUnit, reports: &[CriterionReport]) -> bool {
    match unit.pass_condition {
        PassCondition::CriteriaPass => {
            !reports.is_empty()
                && reports
                    .iter()
                    .all(|report| report.status == CriterionStatus::Passed)
        }
        PassCondition::EscalationRaised => false,
    }
}

fn run_criterion(checkout: &Path, index: usize, criterion: &DoneCriterion) -> CriterionReport {
    match criterion {
        DoneCriterion::Command {
            command,
            expected_exit,
        } => evaluate_command(checkout, index, command.as_str(), *expected_exit),
        DoneCriterion::FilePresent { path } => evaluate_path(checkout, index, path.as_str(), true),
        DoneCriterion::FileAbsent { path } => evaluate_path(checkout, index, path.as_str(), false),
    }
}

fn observe_path(checkout: &Path, relative: &str) -> PathObservation {
    match fs::symlink_metadata(checkout.join(relative)) {
        Ok(_) => PathObservation::Present,
        Err(error) if error.kind() == io::ErrorKind::NotFound => PathObservation::Absent,
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
) -> CriterionReport {
    let (outcome, detail) = run_command(checkout, index, command);
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
) -> Result<(Child, std::path::PathBuf), String> {
    let mut parts = command.split_whitespace();
    let Some(program) = parts.next() else {
        return Err("command is empty".to_string());
    };
    let scratch_dir = checkout.join(".tycho-harness");
    fs::create_dir_all(&scratch_dir).map_err(|error| error.to_string())?;
    let output_path = scratch_dir.join(format!("criterion-{index}.log"));
    let output_file = fs::File::create(&output_path).map_err(|error| error.to_string())?;
    let error_file = output_file.try_clone().map_err(|error| error.to_string())?;
    let child = Command::new(program)
        .args(parts)
        .current_dir(checkout)
        .env("CARGO_TARGET_DIR", checkout.join("target"))
        .stdin(Stdio::null())
        .stdout(output_file)
        .stderr(error_file)
        .spawn()
        .map_err(|error| error.to_string())?;
    Ok((child, output_path))
}

/// Polls in bounded steps so a runaway process is killed rather than waited on forever.
fn wait_bounded(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let polls = timeout
        .as_millis()
        .checked_div(POLL_INTERVAL.as_millis())
        .unwrap_or(1)
        .max(1);
    for _ in 0..polls {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        thread::sleep(POLL_INTERVAL);
    }
    None
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

fn read_capped(path: &Path) -> Result<String, usize> {
    let bytes = fs::read(path).unwrap_or_default();
    if bytes.len() > CRITERION_OUTPUT_MAX_BYTES {
        return Err(bytes.len());
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn run_command(checkout: &Path, index: usize, command: &str) -> (CommandOutcome, String) {
    let (mut child, output_path) = match spawn_command(checkout, index, command) {
        Ok(spawned) => spawned,
        Err(detail) => return (CommandOutcome::SpawnFailed, detail),
    };
    let Some(status) = wait_bounded(&mut child, COMMAND_TIMEOUT) else {
        drop(child.kill());
        drop(child.wait());
        return (CommandOutcome::TimedOut, "exceeded its timeout".to_string());
    };
    match read_capped(&output_path) {
        Ok(detail) => (classify_exit(status), detail),
        Err(actual_bytes) => (
            CommandOutcome::OutputTooLarge,
            format!("output was {actual_bytes} bytes; maximum is {CRITERION_OUTPUT_MAX_BYTES}"),
        ),
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
        assert!(!unit_passed(&unit, &before));

        repository::apply_patch(
            checkout.path(),
            include_bytes!("../fixtures/patches/trivial.patch"),
        )
        .unwrap();
        let after = verify_unit(checkout.path(), &unit);
        assert!(unit_passed(&unit, &after));
    }

    #[test]
    fn the_downstream_unit_depends_only_on_the_trivial_patch() {
        let checkout = built_checkout();
        let unit = unit_by_key("downstream-dependent").unwrap();

        let before = verify_unit(checkout.path(), &unit);
        assert!(!unit_passed(&unit, &before));

        repository::apply_patch(
            checkout.path(),
            include_bytes!("../fixtures/patches/trivial.patch"),
        )
        .unwrap();
        let after = verify_unit(checkout.path(), &unit);
        assert!(unit_passed(&unit, &after));
    }

    #[test]
    fn the_ambiguous_unit_fails_on_the_fresh_repository() {
        let checkout = built_checkout();
        let unit = unit_by_key("moderate-and-ambiguous").unwrap();
        let reports = verify_unit(checkout.path(), &unit);
        assert!(!unit_passed(&unit, &reports));
    }

    #[test]
    fn forced_units_never_pass_by_criteria_even_with_nothing_to_check() {
        for key in ["forced-escalation", "forced-council-split"] {
            let checkout = built_checkout();
            let unit = unit_by_key(key).unwrap();
            assert!(unit.packet.done_criteria.is_empty(), "{key}");
            let reports = verify_unit(checkout.path(), &unit);
            assert!(reports.is_empty());
            assert!(!unit_passed(&unit, &reports), "{key}");
        }
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

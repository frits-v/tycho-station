//! The ci test step: `mbx test --workspace --no-fail-fast` without colour, with cargo's and
//! the test harness's output merged, decoded into one result per test binary, each reported
//! with its resolved path and counts.

use std::fmt;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::process::{Exit, run_bounded_merged};

const TEST_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const BINARIES_MAX: usize = 512;
/// Cargo right-aligns its status verbs in twelve columns.
const RUNNING_PREFIX: &str = "     Running ";
const DOC_TESTS_PREFIX: &str = "   Doc-tests ";
const RESULT_PREFIX: &str = "test result: ";
/// Cargo's line after a binary that failed; with no result before it, the binary crashed.
const BINARY_FAILED_PREFIX: &str = "error: test failed, to rerun pass ";

/// One line of merged `cargo test` output.
#[derive(Debug, PartialEq, Eq)]
pub enum TestLine {
    /// Cargo starts a test binary: `Running unittests src/main.rs (target/debug/deps/x-1)`.
    Running { source: String, binary: String },
    /// Cargo starts a crate's documentation tests: `Doc-tests tycho_types`.
    DocTests { package: String },
    /// The harness's last line for one binary.
    Result(Counts),
    /// Cargo reports that a binary failed and names how to rerun it.
    BinaryFailed,
    /// A `test result:` line whose counts do not parse.
    Unrecognised(String),
    /// Anything else: test names, panics, compiler and mbx lines.
    Other,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub passed: usize,
    pub failed: usize,
    pub ignored: usize,
}

/// One test binary or documentation test run and what it counted.
#[derive(Debug, PartialEq, Eq)]
pub struct BinaryRun {
    pub label: String,
    pub binary: Option<String>,
    pub counts: Counts,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub binaries: usize,
    pub counts: Counts,
}

impl fmt::Display for Totals {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} binaries, {} passed, {} failed, {} ignored",
            self.binaries, self.counts.passed, self.counts.failed, self.counts.ignored
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TestOutcome {
    Passed(Vec<BinaryRun>),
    Failed(Vec<BinaryRun>),
    Unrecognised(String),
}

fn count_before(text: &str, word: &str) -> Option<usize> {
    text.split("; ")
        .find_map(|part| part.trim().strip_suffix(word))
        .and_then(|number| number.trim().parse().ok())
}

fn result_counts(rest: &str) -> Option<Counts> {
    let (_, counted) = rest.split_once(". ")?;
    Some(Counts {
        passed: count_before(counted, " passed")?,
        failed: count_before(counted, " failed")?,
        ignored: count_before(counted, " ignored")?,
    })
}

/// Decodes one line by its exact prefix, the indentation included, so text a test prints
/// matches only when it reproduces cargo's or the harness's layout.
pub fn decode_line(line: &str) -> TestLine {
    if let Some(rest) = line.strip_prefix(RESULT_PREFIX) {
        return result_counts(rest.trim_end()).map_or_else(
            || TestLine::Unrecognised(format!("unreadable result: {line}")),
            TestLine::Result,
        );
    }
    if line.starts_with(BINARY_FAILED_PREFIX) {
        return TestLine::BinaryFailed;
    }
    if let Some(package) = line.strip_prefix(DOC_TESTS_PREFIX) {
        return TestLine::DocTests {
            package: package.trim_end().to_string(),
        };
    }
    let started = line
        .strip_prefix(RUNNING_PREFIX)
        .map(str::trim_end)
        .and_then(|rest| rest.strip_suffix(')'))
        .and_then(|rest| rest.rsplit_once(" ("));
    match started {
        Some((source, binary)) => TestLine::Running {
            source: source.to_string(),
            binary: binary.to_string(),
        },
        None => TestLine::Other,
    }
}

const fn add(total: Counts, more: Counts) -> Counts {
    Counts {
        passed: total.passed.saturating_add(more.passed),
        failed: total.failed.saturating_add(more.failed),
        ignored: total.ignored.saturating_add(more.ignored),
    }
}

pub fn totals(runs: &[BinaryRun]) -> Totals {
    Totals {
        binaries: runs.len(),
        counts: runs
            .iter()
            .fold(Counts::default(), |total, run| add(total, run.counts)),
    }
}

type Open = Option<(String, Option<String>)>;

/// Pairs each binary cargo starts with the one result its harness prints. A header is taken
/// only while no binary is open, and a result only while one is, so a test's own output in
/// between is never read as either. A binary that cargo reports failed before it printed a
/// result (it crashed), a result with no binary open, output that ends with a binary open,
/// no binary, no passed test, or an exit that disagrees with the results is unrecognised.
pub fn decode(exit: &Exit, output: &str) -> TestOutcome {
    if *exit == Exit::OutputStillOpen {
        return TestOutcome::Unrecognised("output still open after cargo exited".to_string());
    }
    let mut runs: Vec<BinaryRun> = Vec::new();
    let mut open: Open = None;
    for line in output.lines() {
        match (decode_line(line), open.take()) {
            (TestLine::Running { source, binary }, None) => open = Some((source, Some(binary))),
            (TestLine::DocTests { package }, None) => {
                open = Some((format!("doc-tests {package}"), None));
            }
            (TestLine::Result(counts), Some((label, binary))) => {
                if runs.len() >= BINARIES_MAX {
                    return TestOutcome::Unrecognised(format!(
                        "more than {BINARIES_MAX} test binaries"
                    ));
                }
                runs.push(BinaryRun {
                    label,
                    binary,
                    counts,
                });
            }
            (TestLine::Result(_), None) => {
                return TestOutcome::Unrecognised(format!("a result with no binary: {line}"));
            }
            (TestLine::BinaryFailed, Some((label, _))) => {
                return TestOutcome::Unrecognised(format!("{label} failed without a test result"));
            }
            (TestLine::Unrecognised(reason), _) => return TestOutcome::Unrecognised(reason),
            (_, still_open) => open = still_open,
        }
    }
    if let Some((label, _)) = open {
        return TestOutcome::Unrecognised(format!("{label} printed no test result"));
    }
    judge(exit, runs)
}

fn judge(exit: &Exit, runs: Vec<BinaryRun>) -> TestOutcome {
    let counts = totals(&runs).counts;
    match (exit, counts.failed) {
        _ if runs.is_empty() => {
            TestOutcome::Unrecognised(format!("no test binary ran; cargo ended {exit:?}"))
        }
        (Exit::Code(0), 0) if counts.passed > 0 => TestOutcome::Passed(runs),
        (Exit::Code(0), 0) => TestOutcome::Unrecognised("no test passed".to_string()),
        (Exit::Code(101), failed) if failed > 0 => TestOutcome::Failed(runs),
        (exit, failed) => TestOutcome::Unrecognised(format!(
            "cargo ended {exit:?} with {failed} failed tests over {} binaries",
            runs.len()
        )),
    }
}

/// The binary as a resolved path, which names the checkout's own target directory even when
/// `target` is a link into a managed one.
#[expect(
    clippy::disallowed_methods,
    reason = "the resolved path is only printed, never opened"
)]
fn resolved(binary: &str) -> String {
    fs::canonicalize(Path::new(binary))
        .map_or_else(|_| binary.to_string(), |path| path.display().to_string())
}

fn report(runs: &[BinaryRun]) {
    for run in runs {
        let counts = run.counts;
        let place = run.binary.as_deref().map_or_else(
            || run.label.clone(),
            |binary| format!("{} ({})", resolved(binary), run.label),
        );
        println!(
            "xtask test: {} passed, {} failed, {} ignored in {place}",
            counts.passed, counts.failed, counts.ignored
        );
    }
}

/// A test step that did not pass, with the totals when every binary was accounted for.
#[derive(Debug)]
pub struct Failure {
    pub reason: String,
    pub totals: Option<Totals>,
}

pub fn test() -> Result<Totals, Failure> {
    let captured = run_bounded_merged(
        Command::new("mbx").args([
            "test",
            "--workspace",
            "--no-fail-fast",
            "--color",
            "never",
            "--",
            "--color",
            "never",
        ]),
        TEST_TIMEOUT,
    );
    match decode(&captured.exit, &captured.stdout) {
        TestOutcome::Passed(runs) => {
            report(&runs);
            Ok(totals(&runs))
        }
        TestOutcome::Failed(runs) => {
            report(&runs);
            let counted = totals(&runs);
            Err(Failure {
                reason: counted.to_string(),
                totals: Some(counted),
            })
        }
        TestOutcome::Unrecognised(reason) => Err(Failure {
            reason,
            totals: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING_LIB: &str =
        "     Running unittests src/lib.rs (target/debug/deps/tycho-c5ec9ac53cd74569)";
    const RUNNING_XTASK: &str =
        "     Running unittests src/main.rs (target/debug/deps/xtask-33413bc30263db20)";
    const DOC_TESTS: &str = "   Doc-tests tycho_types";
    const PASSED: &str = "test result: ok. 452 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.22s";
    const PASSED_XTASK: &str = "test result: ok. 138 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.87s";
    const NONE_RAN: &str = "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s";
    const FAILED: &str = "test result: FAILED. 138 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.87s";

    fn lines(parts: &[&str]) -> String {
        parts.join("\n")
    }

    #[test]
    fn decodes_each_line_shape() {
        assert_eq!(
            decode_line(RUNNING_XTASK),
            TestLine::Running {
                source: "unittests src/main.rs".to_string(),
                binary: "target/debug/deps/xtask-33413bc30263db20".to_string(),
            }
        );
        assert_eq!(
            decode_line(DOC_TESTS),
            TestLine::DocTests {
                package: "tycho_types".to_string()
            }
        );
        assert_eq!(
            decode_line(FAILED),
            TestLine::Result(Counts {
                passed: 138,
                failed: 1,
                ignored: 0
            })
        );
        assert!(matches!(
            decode_line("test result: ok. many passed"),
            TestLine::Unrecognised(_)
        ));
        assert_eq!(decode_line("running 138 tests"), TestLine::Other);
        assert_eq!(
            decode_line("error: test failed, to rerun pass `-p xtask --bin xtask`"),
            TestLine::BinaryFailed
        );
        assert_eq!(
            decode_line("Running unittests src/main.rs (target/debug/deps/x-1)"),
            TestLine::Other
        );
    }

    #[test]
    fn a_passing_run_names_every_binary_and_counts_its_tests() {
        let output = lines(&[
            RUNNING_LIB,
            "running 452 tests",
            PASSED,
            RUNNING_XTASK,
            "test checkout::tests::x ... ok",
            PASSED_XTASK,
            DOC_TESTS,
            NONE_RAN,
        ]);
        let TestOutcome::Passed(runs) = decode(&Exit::Code(0), &output) else {
            panic!("expected a pass");
        };
        assert_eq!(
            runs.get(1).and_then(|run| run.binary.as_deref()),
            Some("target/debug/deps/xtask-33413bc30263db20")
        );
        assert_eq!(
            totals(&runs).to_string(),
            "3 binaries, 590 passed, 0 failed, 2 ignored"
        );
    }

    #[test]
    fn a_failing_binary_fails_the_step_and_later_binaries_still_count() {
        let output = lines(&[RUNNING_LIB, FAILED, RUNNING_XTASK, PASSED_XTASK]);
        let TestOutcome::Failed(runs) = decode(&Exit::Code(101), &output) else {
            panic!("expected a failure");
        };
        assert_eq!(totals(&runs).binaries, 2);
        assert_eq!(totals(&runs).counts.failed, 1);
    }

    #[test]
    fn a_header_printed_by_a_test_while_its_binary_is_open_is_not_a_new_binary() {
        let output = lines(&[
            RUNNING_XTASK,
            "---- tests::x stdout ----",
            RUNNING_LIB,
            DOC_TESTS,
            PASSED_XTASK,
        ]);
        let TestOutcome::Passed(runs) = decode(&Exit::Code(0), &output) else {
            panic!("expected a pass");
        };
        assert_eq!(totals(&runs).binaries, 1);
        assert_eq!(runs.first().map(|run| run.counts.passed), Some(138));
    }

    #[test]
    fn output_that_does_not_account_for_every_binary_is_unrecognised() {
        let crashed = lines(&[
            RUNNING_LIB,
            "error: test failed, to rerun pass `-p tycho --lib`",
            RUNNING_XTASK,
            PASSED_XTASK,
        ]);
        let orphan = lines(&[PASSED, RUNNING_XTASK, PASSED_XTASK]);
        let unfinished = lines(&[RUNNING_LIB, PASSED, RUNNING_XTASK]);
        for output in [crashed, orphan, unfinished] {
            assert!(matches!(
                decode(&Exit::Code(101), &output),
                TestOutcome::Unrecognised(_)
            ));
        }
    }

    #[test]
    fn output_held_open_after_cargo_exited_is_named() {
        assert_eq!(
            decode(&Exit::OutputStillOpen, ""),
            TestOutcome::Unrecognised("output still open after cargo exited".to_string())
        );
    }

    #[test]
    fn an_exit_that_disagrees_with_the_results_or_an_empty_run_is_unrecognised() {
        let failed = lines(&[RUNNING_XTASK, FAILED]);
        let passed = lines(&[RUNNING_XTASK, PASSED_XTASK]);
        let empty = lines(&[RUNNING_XTASK, NONE_RAN]);
        for (exit, output) in [
            (Exit::Code(0), failed.as_str()),
            (Exit::Code(101), passed.as_str()),
            (Exit::TimedOut, passed.as_str()),
            (Exit::Code(0), empty.as_str()),
            (Exit::Code(101), "error: could not compile `xtask`"),
            (Exit::Code(0), ""),
            (Exit::OutputStillOpen, ""),
        ] {
            assert!(
                matches!(decode(&exit, output), TestOutcome::Unrecognised(_)),
                "{exit:?} {output}"
            );
        }
    }
}

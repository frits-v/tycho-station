//! The evaluation metric table from `docs/design.html` section 17.
//!
//! Plus the two baselines slice zero introduces (journal size, index build
//! time), measured by the chaos suite's first-merge test. The
//! zero-work-units-green rule lives here too: a run where nothing passed
//! verification fails the gate.

/// A metric's recorded value, or the reason it has none yet; never absent without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasuredValue {
    Recorded(&'static str),
    NotYetMeasured { reason: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metric {
    pub name: &'static str,
    pub definition: &'static str,
    pub measured_at: &'static str,
    pub target: &'static str,
    pub measured_value: MeasuredValue,
}

const NOT_MEASURED_SLICE_ZERO: MeasuredValue = MeasuredValue::NotYetMeasured {
    reason: "no work unit has run through the merge gate yet",
};

/// The design's ten metric rows, followed by the two slice-zero baselines.
pub const METRIC_TABLE: [Metric; 12] = [
    Metric {
        name: "Human interrupts per work unit",
        definition: "inbox items with severity blocks, per merged unit",
        measured_at: "store",
        target: "at most 0.2 on the synthetic epic",
        measured_value: NOT_MEASURED_SLICE_ZERO,
    },
    Metric {
        name: "Escalation depth",
        definition: "distribution of the level that ruled",
        measured_at: "cases",
        target: "most rulings at L1",
        measured_value: NOT_MEASURED_SLICE_ZERO,
    },
    Metric {
        name: "Cost per work unit",
        definition: "seat capacity consumed plus metered dollars, and wall clock",
        measured_at: "worker runs",
        target: "baseline from the first run, then relative",
        measured_value: NOT_MEASURED_SLICE_ZERO,
    },
    Metric {
        name: "Merge gate failure rate",
        definition: "units that failed verification at least once",
        measured_at: "events",
        target: "baseline relative",
        measured_value: NOT_MEASURED_SLICE_ZERO,
    },
    Metric {
        name: "Case law hit rate",
        definition: "escalations resolved by citing a case",
        measured_at: "cases",
        target: "rising across runs",
        measured_value: NOT_MEASURED_SLICE_ZERO,
    },
    Metric {
        name: "Restart recovery",
        definition: "killed sessions that resumed with no lost state and no duplicate spawn",
        measured_at: "chaos tests",
        target: "100 percent, hard gate",
        measured_value: MeasuredValue::Recorded(
            "4 of 4 cases held on state and one session per attempt; the launcher case leaves attempt 1's vendor running (issue 66)",
        ),
    },
    Metric {
        name: "Gate negative tests",
        definition: "canonical repo write, hooks edit, default branch push by the agent user",
        measured_at: "slice zero",
        target: "all refused, hard gate",
        measured_value: NOT_MEASURED_SLICE_ZERO,
    },
    Metric {
        name: "Packet resolution time",
        definition: "seconds from claim to ruling by a cold reader",
        measured_at: "verdicts",
        target: "median under 300",
        measured_value: NOT_MEASURED_SLICE_ZERO,
    },
    Metric {
        name: "Rollover fidelity",
        definition:
            "rollovers per unit, and sessions that repeat a dead end listed in the handoff note",
        measured_at: "session state, worker runs",
        target: "zero repeats, hard gate",
        measured_value: NOT_MEASURED_SLICE_ZERO,
    },
    Metric {
        name: "Rule citation ledger",
        definition:
            "per mandate article, case and mechanism: citations, firings, last cited, by whom",
        measured_at: "store",
        target: "no article unmeasured; dormant rules listed, each with a petition or a reason",
        measured_value: NOT_MEASURED_SLICE_ZERO,
    },
    Metric {
        name: "Journal size per unit",
        definition: "bytes the journal holds for one merged work unit",
        measured_at: "store",
        target: "baseline, recorded in slice zero",
        measured_value: MeasuredValue::Recorded(
            "16462 bytes over 100 entries for a one-task unit through a fixed gate, summed from sys_journal.raw_length across every invocation but the reconciler's and status reads",
        ),
    },
    Metric {
        name: "Index build time",
        definition: "wall clock to build the semantic graph index for one worktree",
        measured_at: "worktree clone",
        target: "baseline, recorded in slice zero",
        measured_value: MeasuredValue::Recorded(
            "252 to 507 ms over five cold builds of the synthetic checkout (5 files, 21 symbols) through the graph port",
        ),
    },
];

/// `|` cannot survive into a markdown table cell unescaped.
fn escape_cell(text: &str) -> String {
    text.replace('|', "\\|")
}

/// Renders the table as GitHub-flavoured markdown.
#[must_use]
pub fn render_markdown(metrics: &[Metric]) -> String {
    use std::fmt::Write as _;

    let mut table = String::from(
        "| Metric | Definition | Measured at | v1 target | Measured value |\n|---|---|---|---|---|\n",
    );
    for metric in metrics {
        let value = match metric.measured_value {
            MeasuredValue::Recorded(value) => value.to_string(),
            MeasuredValue::NotYetMeasured { reason } => format!("absent: {reason}"),
        };
        writeln!(
            table,
            "| {} | {} | {} | {} | {} |",
            escape_cell(metric.name),
            escape_cell(metric.definition),
            escape_cell(metric.measured_at),
            escape_cell(metric.target),
            escape_cell(&value)
        )
        .ok();
    }
    table
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateSummary {
    pub examined: usize,
    pub passed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    NoUnitsExamined,
    NoUnitsPassed { examined: usize },
}

/// The zero-work-units-green rule: nothing examined, or nothing passed, fails the gate.
pub fn zero_work_units_green(outcomes: &[bool]) -> Result<GateSummary, GateError> {
    let examined = outcomes.len();
    if examined == 0 {
        return Err(GateError::NoUnitsExamined);
    }
    let passed = outcomes.iter().filter(|outcome| **outcome).count();
    if passed == 0 {
        return Err(GateError::NoUnitsPassed { examined });
    }
    Ok(GateSummary { examined, passed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_carries_exactly_the_design_rows_and_the_two_baselines() {
        assert_eq!(METRIC_TABLE.len(), 12);
        let names: Vec<&str> = METRIC_TABLE.iter().map(|metric| metric.name).collect();
        assert_eq!(names.first(), Some(&"Human interrupts per work unit"));
        assert_eq!(names.get(9), Some(&"Rule citation ledger"));
        assert_eq!(names.get(10), Some(&"Journal size per unit"));
        assert_eq!(names.get(11), Some(&"Index build time"));
    }

    #[test]
    fn rendering_includes_the_absence_reason() {
        let rendered = render_markdown(&METRIC_TABLE[..1]);
        assert!(rendered.contains("Human interrupts per work unit"));
        assert!(rendered.contains("absent: no work unit has run through the merge gate yet"));
        assert!(rendered.contains("v1 target"));
    }

    #[test]
    fn a_pipe_in_a_cell_is_escaped_not_left_to_break_the_table() {
        let metric = Metric {
            name: "weird | name",
            definition: "d",
            measured_at: "m",
            target: "t",
            measured_value: MeasuredValue::Recorded("v"),
        };
        let rendered = render_markdown(std::slice::from_ref(&metric));
        assert!(rendered.contains("weird \\| name"));
    }

    fn by_name(name: &str) -> &'static Metric {
        METRIC_TABLE
            .iter()
            .find(|metric| metric.name == name)
            .unwrap()
    }

    /// The step 4 kill cases the chaos catalogue names as runnable.
    fn kill_cases() -> usize {
        let step_four = crate::chaos::SLICE_ZERO_EXIT_TESTS
            .iter()
            .find(|test| test.name == "kill tests (step 4)")
            .unwrap();
        match step_four.readiness {
            crate::chaos::Readiness::Runnable { test } => test.split(", ").count(),
            crate::chaos::Readiness::NotYetRunnable { .. } => 0,
        }
    }

    #[test]
    fn the_baselines_and_restart_recovery_are_recorded() {
        for name in ["Journal size per unit", "Index build time"] {
            assert!(matches!(
                by_name(name).measured_value,
                MeasuredValue::Recorded(_)
            ));
        }
        let cases = kill_cases();
        assert_eq!(cases, 4);
        let MeasuredValue::Recorded(value) = by_name("Restart recovery").measured_value else {
            panic!("restart recovery is not recorded");
        };
        assert!(
            value.starts_with(&format!("{cases} of {cases} cases")),
            "{value}"
        );
    }

    #[test]
    fn a_run_with_at_least_one_pass_is_green() {
        let summary = zero_work_units_green(&[false, true, false]).unwrap();
        assert_eq!(
            summary,
            GateSummary {
                examined: 3,
                passed: 1
            }
        );
    }

    #[test]
    fn zero_examined_fails_the_gate() {
        assert_eq!(zero_work_units_green(&[]), Err(GateError::NoUnitsExamined));
    }

    #[test]
    fn all_failed_fails_the_gate_rather_than_passing_over_nothing() {
        assert_eq!(
            zero_work_units_green(&[false, false]),
            Err(GateError::NoUnitsPassed { examined: 2 })
        );
    }
}

//! The chaos test catalogue (`docs/design.html` section 17).
//!
//! Each entry carries its pass condition as data, and either the test that
//! runs it or what it waits on.

/// Chaos and exit tests run from `crates/tycho/tests/chaos` with `mise run chaos-tests`.
pub const CHAOS_SUITE: &str = "crates/tycho/tests/chaos";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Runs as this test in the chaos suite.
    Runnable {
        test: &'static str,
    },
    NotYetRunnable {
        reason: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChaosTest {
    pub name: &'static str,
    pub pass_condition: &'static str,
    pub readiness: Readiness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceZeroExitTest {
    pub name: &'static str,
    pub pass_condition: &'static str,
    pub readiness: Readiness,
}

pub const CHAOS_CATALOGUE: [ChaosTest; 4] = [
    ChaosTest {
        name: "terminal app killed",
        pass_condition:
            "the unit resumes from its last step with nothing lost and no second session spawned",
        readiness: Readiness::Runnable {
            test: "terminal_app_killed_leaves_the_session_core_and_unit_running",
        },
    },
    ChaosTest {
        name: "control session killed",
        pass_condition:
            "the control session's work resumes with no lost state and no duplicate session",
        readiness: Readiness::NotYetRunnable {
            reason: "waits on the interactive control session adapter and a real vendor to kill",
        },
    },
    ChaosTest {
        name: "checkpoint corrupted",
        pass_condition:
            "the reconciler detects the corruption and replays from the last valid checkpoint",
        readiness: Readiness::NotYetRunnable {
            reason: "waits on worker checkpoints, which a real vendor writes from slice one",
        },
    },
    ChaosTest {
        name: "budget exhausted",
        pass_condition:
            "the unit stops, reports the exhaustion, and raises nothing beyond its own budget",
        readiness: Readiness::NotYetRunnable {
            reason:
                "waits on a real vendor whose usage can run out; the doubles report fixed usage",
        },
    },
];

/// Slice zero's exit tests (`docs/slices.md`).
pub const SLICE_ZERO_EXIT_TESTS: [SliceZeroExitTest; 5] = [
    SliceZeroExitTest {
        name: "kill tests (step 4)",
        pass_condition: "killing the terminal app, the Restate server between worker exit and resolve, the endpoint, and the launcher before its exit trap each leaves nothing lost and spawns no duplicate session",
        readiness: Readiness::Runnable {
            test: "terminal_app_killed_leaves_the_session_core_and_unit_running, restate_killed_between_worker_exit_and_resolve_resolves_on_the_same_attempt, endpoint_killed_between_tasks_replays_without_dispatching_twice, launcher_killed_before_its_trap_requeues_as_attempt_two",
        },
    },
    SliceZeroExitTest {
        name: "boundary tests (step 5)",
        pass_condition: "the agent user's reads of the developer's keychain and config directories, its write to its own settings file, and its reach to the Restate admin port, the canonical repository, its hooks and the default branch are all refused",
        readiness: Readiness::NotYetRunnable {
            reason: "waits on the agent user and the local merge gate's canonical repository",
        },
    },
    SliceZeroExitTest {
        name: "escalation test (step 7)",
        pass_condition: "a planted contradiction makes the worker reject its awaitable with a certified question; the packet lands in a directory and a verdict typed into a file resumes the unit",
        readiness: Readiness::NotYetRunnable {
            reason: "waits on a headless worker adapter that reads the planted contradiction",
        },
    },
    SliceZeroExitTest {
        name: "first merge",
        pass_condition: "a work unit merges end to end through the local merge gate's verify and fast-forward",
        readiness: Readiness::NotYetRunnable {
            reason: "waits on the local merge gate's fast-forward (issue 15)",
        },
    },
    SliceZeroExitTest {
        name: "first baselines",
        pass_condition: "journal size per unit and index build time are recorded as the first baselines",
        readiness: Readiness::Runnable {
            test: "a_unit_merges_end_to_end_and_records_the_baselines",
        },
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalogue_has_exactly_the_four_design_entries() {
        let names: Vec<&str> = CHAOS_CATALOGUE.iter().map(|test| test.name).collect();
        assert_eq!(
            names,
            [
                "terminal app killed",
                "control session killed",
                "checkpoint corrupted",
                "budget exhausted",
            ]
        );
    }

    /// The test function names of the chaos suite, read from its sources.
    fn suite_tests() -> String {
        let suite = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(CHAOS_SUITE);
        let mut sources = String::new();
        for entry in std::fs::read_dir(suite).unwrap() {
            sources.push_str(&std::fs::read_to_string(entry.unwrap().path()).unwrap());
        }
        sources
    }

    fn runnable_names(readiness: Readiness) -> Vec<&'static str> {
        match readiness {
            Readiness::Runnable { test } => test.split(", ").collect(),
            Readiness::NotYetRunnable { .. } => Vec::new(),
        }
    }

    #[test]
    fn only_the_terminal_app_kill_is_runnable_and_its_test_exists() {
        let sources = suite_tests();
        let runnable: Vec<&str> = CHAOS_CATALOGUE
            .iter()
            .filter(|test| matches!(test.readiness, Readiness::Runnable { .. }))
            .map(|test| test.name)
            .collect();
        assert_eq!(runnable, ["terminal app killed"]);
        for test in &CHAOS_CATALOGUE {
            for name in runnable_names(test.readiness) {
                assert!(sources.contains(&format!("fn {name}()")), "{name}");
            }
        }
    }

    #[test]
    fn a_not_runnable_entry_says_what_it_waits_on() {
        let waiting = CHAOS_CATALOGUE
            .iter()
            .map(|test| test.readiness)
            .chain(SLICE_ZERO_EXIT_TESTS.iter().map(|test| test.readiness))
            .filter_map(|readiness| match readiness {
                Readiness::NotYetRunnable { reason } => Some(reason),
                Readiness::Runnable { .. } => None,
            });
        let mut examined = 0_usize;
        for reason in waiting {
            assert!(reason.starts_with("waits on"), "{reason}");
            examined = examined.saturating_add(1);
        }
        assert_eq!(examined, 6);
    }

    #[test]
    fn slice_zero_step_four_and_the_baselines_name_tests_that_exist() {
        assert_eq!(SLICE_ZERO_EXIT_TESTS.len(), 5);
        let sources = suite_tests();
        let runnable: Vec<&str> = SLICE_ZERO_EXIT_TESTS
            .iter()
            .filter(|test| matches!(test.readiness, Readiness::Runnable { .. }))
            .map(|test| test.name)
            .collect();
        assert_eq!(runnable, ["kill tests (step 4)", "first baselines"]);
        let names: Vec<&str> = SLICE_ZERO_EXIT_TESTS
            .iter()
            .flat_map(|test| runnable_names(test.readiness))
            .collect();
        assert_eq!(names.len(), 5);
        for name in names {
            assert!(sources.contains(&format!("fn {name}()")), "{name}");
        }
    }

    #[test]
    fn step_five_names_the_keychain_and_config_reads() {
        let step_five = SLICE_ZERO_EXIT_TESTS
            .iter()
            .find(|test| test.name == "boundary tests (step 5)")
            .unwrap();
        assert!(step_five.pass_condition.contains("keychain"));
        assert!(step_five.pass_condition.contains("config"));
    }

    #[test]
    fn step_seven_names_the_packet_and_the_verdict_file_resume() {
        let step_seven = SLICE_ZERO_EXIT_TESTS
            .iter()
            .find(|test| test.name == "escalation test (step 7)")
            .unwrap();
        assert!(step_seven.pass_condition.contains("packet"));
        assert!(step_seven.pass_condition.contains("verdict"));
    }
}

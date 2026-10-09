//! The chaos test catalogue (`docs/design.html` section 17).
//!
//! Nothing here is executable yet: the spine the tests would kill does not
//! exist. Each entry carries its pass condition as data so a later issue
//! wires in the probe.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    NotYetRunnable { reason: &'static str },
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

const NO_SPINE: Readiness = Readiness::NotYetRunnable {
    reason: "the spine this test would kill does not exist yet",
};

pub const CHAOS_CATALOGUE: [ChaosTest; 4] = [
    ChaosTest {
        name: "terminal app killed",
        pass_condition:
            "the unit resumes from its last step with nothing lost and no second session spawned",
        readiness: NO_SPINE,
    },
    ChaosTest {
        name: "control session killed",
        pass_condition:
            "the control session's work resumes with no lost state and no duplicate session",
        readiness: NO_SPINE,
    },
    ChaosTest {
        name: "checkpoint corrupted",
        pass_condition:
            "the reconciler detects the corruption and replays from the last valid checkpoint",
        readiness: NO_SPINE,
    },
    ChaosTest {
        name: "budget exhausted",
        pass_condition:
            "the unit stops, reports the exhaustion, and raises nothing beyond its own budget",
        readiness: NO_SPINE,
    },
];

/// Slice zero's exit tests (`docs/slices.md`).
pub const SLICE_ZERO_EXIT_TESTS: [SliceZeroExitTest; 4] = [
    SliceZeroExitTest {
        name: "kill tests (step 4)",
        pass_condition: "killing the terminal app, the Restate server between worker exit and resolve, the endpoint, and the launcher before its exit trap each leaves nothing lost and spawns no duplicate session",
        readiness: NO_SPINE,
    },
    SliceZeroExitTest {
        name: "boundary tests (step 5)",
        pass_condition: "the agent user's reads of the developer's keychain and config directories, its write to its own settings file, and its reach to the Restate admin port, the canonical repository, its hooks and the default branch are all refused",
        readiness: NO_SPINE,
    },
    SliceZeroExitTest {
        name: "escalation test (step 7)",
        pass_condition: "a planted contradiction makes the worker reject its awaitable with a certified question; the packet lands in a directory and a verdict typed into a file resumes the unit",
        readiness: NO_SPINE,
    },
    SliceZeroExitTest {
        name: "first merge and baselines",
        pass_condition: "a work unit merges end to end; journal size per unit and index build time are recorded as the first baselines",
        readiness: NO_SPINE,
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

    #[test]
    fn no_chaos_entry_is_runnable_yet() {
        for test in &CHAOS_CATALOGUE {
            assert!(matches!(test.readiness, Readiness::NotYetRunnable { .. }));
        }
    }

    #[test]
    fn slice_zero_lists_its_four_exit_tests_none_runnable_yet() {
        assert_eq!(SLICE_ZERO_EXIT_TESTS.len(), 4);
        for test in &SLICE_ZERO_EXIT_TESTS {
            assert!(matches!(test.readiness, Readiness::NotYetRunnable { .. }));
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

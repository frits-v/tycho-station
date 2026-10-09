//! The chaos test catalogue (`docs/design.html` section 17).
//!
//! Nothing here is executable yet: the spine the tests would kill does not
//! exist. Each entry carries its pass condition as data so a later issue
//! wires in the probe.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChaosReadiness {
    NotYetRunnable { reason: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChaosTest {
    pub name: &'static str,
    pub pass_condition: &'static str,
    pub readiness: ChaosReadiness,
}

const NO_SPINE: ChaosReadiness = ChaosReadiness::NotYetRunnable {
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
pub const SLICE_ZERO_EXIT_TESTS: [&str; 4] = [
    "kill tests (step 4): nothing lost, no duplicate session spawned",
    "boundary tests (step 5): every agent-user write and the admin port read are refused",
    "escalation test (step 7): a planted contradiction raises a certified question",
    "a work unit merges end to end; journal size per unit and index build time are recorded",
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
    fn no_entry_is_runnable_yet() {
        for test in &CHAOS_CATALOGUE {
            assert!(matches!(
                test.readiness,
                ChaosReadiness::NotYetRunnable { .. }
            ));
        }
    }

    #[test]
    fn slice_zero_lists_its_exit_tests() {
        assert_eq!(SLICE_ZERO_EXIT_TESTS.len(), 4);
    }
}

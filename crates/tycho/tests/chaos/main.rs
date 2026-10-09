//! Chaos tests for slice zero step 4: a real work unit runs through the operator path on a
//! throwaway core while the terminal app, the Restate server, the endpoint and the launcher are
//! killed at the moments the design names; each case checks that nothing was lost and no second
//! session was spawned for an attempt. macOS only, run by `mise run chaos-tests`.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the evidence lines are the test's report for the pull request"
)]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers fail the test by panicking"
)]

mod cases_launcher;
mod cases_replay;
mod launcher_spawner;
mod support;

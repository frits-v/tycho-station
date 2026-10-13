//! Evaluation harness baseline for slice zero.
//!
//! The synthetic epic repository, the five work units, programmatic
//! verification, the metric table and the chaos test catalogue
//! (`docs/design.html` section 17, `docs/slices.md`).
#![allow(
    clippy::missing_errors_doc,
    reason = "each error type is an enumerated decoder; its variants are the documentation"
)]

pub mod chaos;
pub mod content;
pub mod metrics;
pub mod repository;
pub mod tool_prefix;
pub mod verify;
pub mod work_units;

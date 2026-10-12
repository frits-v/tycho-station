//! The contract shared by the launcher, the Restate services, the vendor
//! adapters and the xtask: service keys, session names, the lease file, the
//! launcher's environment, and the message envelope with its decoder states.
#![allow(
    clippy::missing_errors_doc,
    reason = "each error type is an enumerated decoder; its variants are the documentation"
)]

pub mod agent_call;
pub mod envelope;
pub mod exit;
pub mod git_environment;
pub mod launcher;
pub mod lease;
pub mod rejection;
pub mod service;
pub mod session;
pub mod task_packet;
pub mod token;

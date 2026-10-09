//! The station's library: the Restate endpoint, core session supervision and the watchdog.
#![allow(
    clippy::missing_errors_doc,
    reason = "each error type is an enumerated state; its variants are the documentation"
)]

pub mod command;
pub mod config;
pub mod core;
pub mod endpoint;
pub mod health;
pub mod http;
pub mod launchd;
pub mod private_dir;
pub mod probe;
pub mod watchdog;
pub mod zmx;

//! The station's library: the Restate endpoint, core session supervision and the watchdog.
#![allow(
    clippy::missing_errors_doc,
    reason = "each error type is an enumerated state; its variants are the documentation"
)]

pub mod agent_files;
pub mod code_graph;
pub mod command;
pub mod config;
pub mod config_store;
pub mod core;
pub mod endpoint;
pub mod entire_graph;
pub mod epic_command;
pub mod exit_decode;
pub mod health;
pub mod http;
pub mod kill;
pub mod launch_probe;
pub mod launch_spec;
pub mod launchd;
pub mod launcher;
pub mod packets;
pub mod private_dir;
pub mod probe;
pub mod process;
pub mod relay;
pub mod repositories;
pub mod services;
pub mod spawn;
pub mod spool;
pub mod vendors;
pub mod verdicts;
pub mod watchdog;
pub mod zmx;

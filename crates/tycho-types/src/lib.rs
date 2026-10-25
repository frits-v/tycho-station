//! The contract shared by the launcher, the Restate services, the vendor
//! adapters and the xtask: service keys, session names, the lease file, the
//! launcher's environment, and the message envelope with its decoder states.
#![allow(
    clippy::missing_errors_doc,
    reason = "each error type is an enumerated decoder; its variants are the documentation"
)]

pub mod agent_call;
pub mod agent_switch;
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

#[cfg(test)]
mod tests {
    /// nono turns on serde_json's `preserve_order`, and cargo turns a feature on for every
    /// crate of a build, so this crate names it itself: a build of one crate and of the whole
    /// workspace then order a JSON object's keys the same way, as they were inserted.
    #[test]
    fn a_json_object_keeps_its_keys_in_insertion_order() {
        let value = serde_json::json!({"zeta": 1, "alpha": 2});
        assert_eq!(value.to_string(), r#"{"zeta":1,"alpha":2}"#);
    }
}

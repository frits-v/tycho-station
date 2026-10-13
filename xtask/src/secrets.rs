//! The secrets the xtask reads from its environment, taken out of the process environment
//! before any command runs: no child the xtask starts inherits one, and a child that needs a
//! secret gets it set on its own command.

use std::collections::BTreeMap;
use std::env;
use std::sync::OnceLock;

use crate::anthropic_token::{REQUEST_TOKEN_VARIABLE, REQUEST_URL_VARIABLE};
use crate::app_token::{RELEASE, REVIEW};

/// Every variable that holds a secret the xtask uses itself. The Actions OIDC request URL is
/// listed with its token: the pair together mints tokens for the job.
pub const SECRET_VARIABLES: [&str; 5] = [
    RELEASE.key_variable,
    REVIEW.key_variable,
    "LANGFUSE_SECRET_KEY",
    REQUEST_TOKEN_VARIABLE,
    REQUEST_URL_VARIABLE,
];

static TAKEN: OnceLock<BTreeMap<&'static str, String>> = OnceLock::new();

/// Moves each secret variable from the process environment into the store. `main` calls it
/// first, while the process has one thread: `env::remove_var` is not thread-safe.
pub fn take_from_environment() {
    TAKEN.get_or_init(|| {
        let mut taken = BTreeMap::new();
        for name in SECRET_VARIABLES {
            if let Ok(value) = env::var(name) {
                taken.insert(name, value);
            }
            env::remove_var(name);
        }
        taken
    });
}

/// The value a secret variable held when the xtask started; `None` when it was unset or is
/// not a listed secret.
pub fn read(name: &str) -> Option<String> {
    TAKEN.get()?.get(name).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const CHILD: &str = "secrets::tests::a_started_xtask_holds_no_secret_in_its_environment";

    /// Runs only in a child process that `secrets_never_reach_a_child_process` starts with
    /// every secret variable set: the startup take, then a child of its own.
    #[test]
    #[ignore = "run by secrets_never_reach_a_child_process in a child process"]
    fn a_started_xtask_holds_no_secret_in_its_environment() {
        for name in SECRET_VARIABLES {
            assert!(env::var_os(name).is_some(), "the parent sets {name}");
        }
        take_from_environment();
        let listing = Command::new("env").output().unwrap();
        let listing = String::from_utf8_lossy(&listing.stdout);
        for name in SECRET_VARIABLES {
            assert_eq!(env::var_os(name), None, "{name}");
            assert!(
                !listing.contains(&format!("{name}=")),
                "{name} reached a child"
            );
            assert_eq!(read(name), Some(format!("value of {name}")));
        }
        assert!(listing.contains("XTASK_PLAIN_VARIABLE=kept"), "{listing}");
    }

    #[test]
    fn secrets_never_reach_a_child_process() {
        let mut command = Command::new(env::current_exe().unwrap());
        command
            .args(["--ignored", "--exact", CHILD])
            .env("XTASK_PLAIN_VARIABLE", "kept");
        for name in SECRET_VARIABLES {
            command.env(name, format!("value of {name}"));
        }
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}{stderr}");
        assert!(
            stdout.contains("test result: ok. 1 passed"),
            "the child must run exactly one test: {stdout}"
        );
    }

    #[test]
    fn every_secret_variable_the_xtask_reads_is_listed() {
        for name in [
            "TYCHO_RELEASE_APP_PRIVATE_KEY",
            "FRITS_CODE_REVIEW_APP_PRIVATE_KEY",
            "LANGFUSE_SECRET_KEY",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
        ] {
            assert!(SECRET_VARIABLES.contains(&name), "{name}");
        }
    }

    #[test]
    fn a_variable_outside_the_list_is_never_read_from_the_store() {
        assert_eq!(read("PATH"), None);
    }
}

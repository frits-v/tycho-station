//! The variables git exports to its hooks and that point a git child at another repository.
//!
//! A hook runs with `GIT_DIR` and its relatives naming the repository that started it, and
//! every process the hook starts inherits them. A `git init` or `git commit` in such a
//! process acts on that repository whatever directory it is given with `-C`, so every git
//! child of the station removes them first.

use std::env;
use std::ffi::{OsStr, OsString};
use std::process::Command;

/// The names `git rev-parse --local-env-vars` lists, and the namespace, discovery and
/// quarantine variables that also reach a hook.
pub const GIT_ENVIRONMENT_REMOVED: [&str; 19] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_PREFIX",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_QUARANTINE_PATH",
    "GIT_GRAFT_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
];

/// `git -c` and `GIT_CONFIG_COUNT` pass configuration as numbered pairs.
pub const GIT_ENVIRONMENT_REMOVED_PREFIXES: [&str; 2] = ["GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"];

/// Whether a variable is one a git child must not inherit.
#[must_use]
pub fn is_git_environment(name: &OsStr) -> bool {
    let Some(text) = name.to_str() else {
        return false;
    };
    GIT_ENVIRONMENT_REMOVED.contains(&text)
        || GIT_ENVIRONMENT_REMOVED_PREFIXES
            .iter()
            .any(|prefix| text.starts_with(prefix))
}

/// Every listed name, and each numbered configuration variable in this process's
/// environment, for a runner that takes the names to remove.
#[must_use]
pub fn git_environment_removed() -> Vec<OsString> {
    let mut removed: Vec<OsString> = GIT_ENVIRONMENT_REMOVED.iter().map(OsString::from).collect();
    let numbered: Vec<OsString> = env::vars_os()
        .map(|(name, _)| name)
        .filter(|name| is_git_environment(name) && !removed.contains(name))
        .collect();
    removed.extend(numbered);
    removed
}

/// Removes the git hook environment from what `command` inherits; variables the caller sets
/// on `command` afterwards still reach the child.
pub fn scrub_git_environment(command: &mut Command) -> &mut Command {
    for name in git_environment_removed() {
        command.env_remove(name);
    }
    command
}

/// `git` with the hook environment removed.
#[must_use]
pub fn git_command() -> Command {
    let mut command = Command::new("git");
    scrub_git_environment(&mut command);
    command
}

/// The git hook variables named in `env` output, one `NAME=value` per line; the runner tests
/// of each crate read their child's environment with it.
#[must_use]
pub fn git_environment_in(listing: &str) -> Vec<&str> {
    listing
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name))
        .filter(|name| is_git_environment(OsStr::new(name)))
        .collect()
}

/// Why a test that spawns git must not run in this process, when `GIT_DIR` is set.
#[must_use]
pub fn hook_environment_refusal() -> Option<String> {
    refusal_in(|name| env::var_os(name))
}

fn refusal_in(variable: impl Fn(&str) -> Option<OsString>) -> Option<String> {
    let git_dir = variable("GIT_DIR")?;
    let hook = if variable("GIT_INDEX_FILE").is_some() {
        "a pre-commit or commit-msg hook"
    } else {
        "a pre-push hook"
    };
    Some(format!(
        "GIT_DIR is {} in this test process, which probably runs under {hook}; a git child \
         would act on that repository. Run the tests through `cargo run -p xtask -- test`, \
         which removes git's hook environment, or unset GIT_DIR.",
        git_dir.to_string_lossy()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INHERITED_CHILD: &str =
        "git_environment::tests::a_scrubbed_command_under_an_inherited_hook_environment";

    #[test]
    fn the_hook_variables_and_numbered_configuration_are_git_environment() {
        for name in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_COMMON_DIR",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_12",
        ] {
            assert!(is_git_environment(OsStr::new(name)), "{name}");
        }
        for name in [
            "GIT_CONFIG_GLOBAL",
            "GIT_AUTHOR_NAME",
            "GIT_TERMINAL_PROMPT",
            "PATH",
            "GIT_DIRECTORY",
        ] {
            assert!(!is_git_environment(OsStr::new(name)), "{name}");
        }
    }

    #[test]
    fn an_env_listing_names_its_git_hook_variables() {
        let listing =
            "PATH=/bin\nGIT_DIR=/r/.git\nGIT_CONFIG_GLOBAL=/dev/null\nGIT_CONFIG_KEY_0=a=b\n";
        assert_eq!(git_environment_in(listing), ["GIT_DIR", "GIT_CONFIG_KEY_0"]);
        assert_eq!(git_environment_in("PATH=/bin\n"), Vec::<&str>::new());
    }

    #[test]
    fn a_set_git_dir_is_refused_and_names_the_likely_hook() {
        let push = |name: &str| (name == "GIT_DIR").then(|| OsString::from("/repo/.git"));
        let refusal = refusal_in(push).unwrap();
        assert!(refusal.contains("/repo/.git"), "{refusal}");
        assert!(refusal.contains("pre-push"), "{refusal}");
        let commit = |name: &str| {
            ["GIT_DIR", "GIT_INDEX_FILE"]
                .contains(&name)
                .then(|| OsString::from("/repo/.git"))
        };
        assert!(refusal_in(commit).unwrap().contains("pre-commit"));
        assert_eq!(refusal_in(|_| None), None);
    }

    /// Runs only in a child process that `a_scrubbed_command_hides_the_inherited_hook_environment`
    /// starts with the hook environment set, so no test mutates this process's environment.
    #[test]
    #[ignore = "run by a_scrubbed_command_hides_the_inherited_hook_environment in a child process"]
    fn a_scrubbed_command_under_an_inherited_hook_environment() {
        assert!(env::var_os("GIT_DIR").is_some(), "the parent sets GIT_DIR");
        let output = scrub_git_environment(&mut Command::new("env"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(output.status.success());
        let listing = String::from_utf8(output.stdout).unwrap();
        assert!(listing.contains("\nPATH=") || listing.starts_with("PATH="));
        assert!(listing.contains("GIT_CONFIG_GLOBAL=/dev/null"), "{listing}");
        assert_eq!(git_environment_in(&listing), Vec::<&str>::new());
    }

    #[test]
    fn a_scrubbed_command_hides_the_inherited_hook_environment() {
        let output = Command::new(env::current_exe().unwrap())
            .args(["--ignored", "--exact", INHERITED_CHILD])
            .env("GIT_DIR", "/nonexistent/hook/.git")
            .env("GIT_WORK_TREE", "/nonexistent/hook")
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "core.bare")
            .env("GIT_CONFIG_VALUE_0", "true")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}{stderr}");
        assert!(
            stdout.contains("test result: ok. 1 passed"),
            "the child must run exactly one test: {stdout}"
        );
    }
}

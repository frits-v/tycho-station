#![expect(
    clippy::disallowed_methods,
    reason = "the scratch directory is private to the test"
)]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers fail the test by panicking"
)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tycho_types::git_environment::{git_command, hook_environment_refusal};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}

fn git(arguments: &[&str]) -> String {
    if let Some(refusal) = hook_environment_refusal() {
        panic!("{refusal}");
    }
    let output = git_command().args(arguments).output().unwrap();
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// A hook hands the xtask `GIT_DIR` naming a bare repository; the xtask's git must list the
/// checkout it runs in, and the hook's repository must stay as it was.
#[test]
fn a_command_started_by_a_hook_runs_git_on_its_own_checkout() {
    let root = env::temp_dir().join(format!("xtask-hook-environment-{}", std::process::id()));
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    let scratch = Scratch(root);
    let checkout = scratch.0.join("checkout");
    let hook_repository = scratch.0.join("hook.git");
    fs::create_dir_all(&checkout).unwrap();
    git(&["init", "-q", text(&checkout)]);
    fs::write(checkout.join("listed.txt"), "plain text\n").unwrap();
    git(&["init", "-q", "--bare", text(&hook_repository)]);
    let config = fs::read(hook_repository.join("config")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("check-credentials")
        .current_dir(&checkout)
        .env("GIT_DIR", &hook_repository)
        .env("GIT_WORK_TREE", &hook_repository)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
    assert!(stdout.contains("examined 1 files"), "{stdout}");
    assert_eq!(fs::read(hook_repository.join("config")).unwrap(), config);
    assert_eq!(
        git(&["--git-dir", text(&hook_repository), "for-each-ref"]),
        ""
    );
}

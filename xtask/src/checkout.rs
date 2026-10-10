//! The checkout `xtask ci` tests: the one it was built from, which must be the one it runs in.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::process::{run_bounded, Exit};

const GIT_TIMEOUT: Duration = Duration::from_secs(60);
/// SHA-1 and SHA-256 object names.
const COMMIT_LENGTHS: [usize; 2] = [40, 64];

/// The nearest directory at or above `path` that holds `.git`, a directory in the main
/// checkout and a file in a linked worktree.
fn checkout_root(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|dir| dir.join(".git").exists())
        .map(Path::to_path_buf)
}

#[expect(
    clippy::disallowed_methods,
    reason = "resolved paths are compared, never opened"
)]
fn resolve(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path).map_err(|error| format!("cannot resolve {}: {error}", path.display()))
}

/// The checkout both paths belong to, or a refusal naming both when they differ. A nested
/// worktree is its own checkout, so `.worktrees/x` is not the checkout above it.
pub fn same_checkout(built_from: &Path, current: &Path) -> Result<PathBuf, String> {
    let built = resolve(built_from)?;
    let here = resolve(current)?;
    let Some(built_root) = checkout_root(&built) else {
        return Err(format!("{} is in no git checkout", built.display()));
    };
    let Some(here_root) = checkout_root(&here) else {
        return Err(format!("{} is in no git checkout", here.display()));
    };
    if built_root == here_root {
        return Ok(here_root);
    }
    Err(format!(
        "this xtask was built from {} (CARGO_MANIFEST_DIR) but runs in {}; \
         run `cargo run -p xtask -- ci` from the checkout under test",
        built.display(),
        here.display()
    ))
}

/// The checkout this xtask was built from, asserted to be the current directory's.
pub fn running_checkout() -> Result<PathBuf, String> {
    let current = env::current_dir()
        .map_err(|error| format!("cannot read the current directory: {error}"))?;
    same_checkout(Path::new(env!("CARGO_MANIFEST_DIR")), &current)
}

fn decode_commit(exit: &Exit, stdout: &str) -> Result<String, String> {
    let commit = stdout.trim();
    let well_formed = COMMIT_LENGTHS.contains(&commit.len())
        && commit
            .chars()
            .all(|character| character.is_ascii_hexdigit());
    match exit {
        Exit::Code(0) if well_formed => Ok(commit.to_string()),
        Exit::Code(0) => Err(format!("git rev-parse HEAD printed `{commit}`")),
        other => Err(format!("git rev-parse HEAD ended {other:?}")),
    }
}

/// The commit checked out at `root`.
pub fn head_commit(root: &Path) -> Result<String, String> {
    let captured = run_bounded(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"]),
        GIT_TIMEOUT,
    );
    decode_commit(&captured.exit, &captured.stdout)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::disallowed_methods,
        reason = "fixtures live in a scratch directory no other user can write"
    )]

    use super::*;

    /// A main checkout with a linked worktree under `.worktrees`, as the station lays them out.
    fn layout(name: &str) -> PathBuf {
        let root =
            env::temp_dir().join(format!("xtask-checkout-test-{}-{name}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        let main = root.join("station");
        for dir in [".git", "xtask", "crates/tycho", ".worktrees/branch/xtask"] {
            fs::create_dir_all(main.join(dir)).unwrap();
        }
        fs::write(
            main.join(".worktrees/branch/.git"),
            "gitdir: ../../.git/worktrees/branch\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("loose/xtask")).unwrap();
        root
    }

    #[test]
    fn an_xtask_run_inside_its_own_checkout_is_accepted() {
        let root = layout("accepted");
        let main = root.join("station");
        let found = same_checkout(&main.join("xtask"), &main.join("crates/tycho"));
        assert_eq!(found, Ok(resolve(&main).unwrap()));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_xtask_from_another_checkout_is_refused_with_both_paths() {
        let root = layout("refused");
        let main = root.join("station");
        let worktree = main.join(".worktrees/branch");
        for (built, current) in [
            (worktree.join("xtask"), main.clone()),
            (main.join("xtask"), worktree.clone()),
        ] {
            let refusal = same_checkout(&built, &current).unwrap_err();
            let built_shown = resolve(&built).unwrap().display().to_string();
            let current_shown = resolve(&current).unwrap().display().to_string();
            assert!(refusal.contains(&built_shown), "{refusal}");
            assert!(refusal.contains(&current_shown), "{refusal}");
        }
        assert!(same_checkout(&root.join("loose/xtask"), &main).is_err());
        assert!(same_checkout(&main.join("absent"), &main).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn this_test_binary_runs_in_the_checkout_it_was_built_from() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let found = running_checkout().unwrap();
        assert_eq!(Some(found.as_path()), resolve(manifest).unwrap().parent());
    }

    #[test]
    fn only_a_full_object_name_from_a_clean_exit_is_a_commit() {
        let sha1 = "511cf42a".repeat(5);
        assert_eq!(
            decode_commit(&Exit::Code(0), &format!("{sha1}\n")),
            Ok(sha1)
        );
        assert!(decode_commit(&Exit::Code(0), "HEAD\n").is_err());
        assert!(decode_commit(&Exit::Code(0), "").is_err());
        assert!(decode_commit(&Exit::Code(128), "").is_err());
        assert!(decode_commit(&Exit::TimedOut, &"a".repeat(40)).is_err());
    }
}

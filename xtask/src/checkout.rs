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
    let both = format!(
        "this xtask was built from {} (CARGO_MANIFEST_DIR) and runs in {}",
        built.display(),
        here.display()
    );
    let Some(built_root) = checkout_root(&built) else {
        return Err(format!("{both}; the first is in no git checkout"));
    };
    let Some(here_root) = checkout_root(&here) else {
        return Err(format!("{both}; the second is in no git checkout"));
    };
    if built_root == here_root {
        return Ok(here_root);
    }
    Err(format!(
        "{both}, another checkout; run `cargo run -p xtask -- ci` from the checkout under test"
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

/// The number of paths `git status --porcelain` lists: changed, staged or untracked.
fn decode_status(exit: &Exit, stdout: &str) -> Result<usize, String> {
    match exit {
        Exit::Code(0) => Ok(stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()),
        other => Err(format!("git status --porcelain ended {other:?}")),
    }
}

/// The commit with the number of uncommitted changes when there are any, so a dirty tree is
/// never named by its commit alone.
fn describe_revision(commit: &str, uncommitted: usize) -> String {
    if uncommitted == 0 {
        commit.to_string()
    } else {
        format!("{commit} with {uncommitted} uncommitted changes")
    }
}

/// The commit checked out at `root` and whether the tree differs from it.
pub fn revision(root: &Path) -> Result<String, String> {
    let head = run_bounded(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"]),
        GIT_TIMEOUT,
    );
    let commit = decode_commit(&head.exit, &head.stdout)?;
    let status = run_bounded(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["status", "--porcelain"]),
        GIT_TIMEOUT,
    );
    let uncommitted = decode_status(&status.exit, &status.stdout)?;
    Ok(describe_revision(&commit, uncommitted))
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
        for (built, current) in [
            (root.join("loose/xtask"), main.clone()),
            (main.join("xtask"), root.join("loose")),
        ] {
            let refusal = same_checkout(&built, &current).unwrap_err();
            assert!(refusal.contains("is in no git checkout"), "{refusal}");
            for path in [&built, &current] {
                let shown = resolve(path).unwrap().display().to_string();
                assert!(refusal.contains(&shown), "{refusal}");
            }
        }
        assert!(same_checkout(&main.join("absent"), &main).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn this_test_binary_runs_in_the_checkout_it_was_built_from() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let found = running_checkout().unwrap();
        assert_eq!(Some(found.as_path()), resolve(manifest).unwrap().parent());
    }

    fn git(root: &Path, arguments: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["-c", "user.name=xtask", "-c", "user.email=xtask@localhost"])
            .args(["-c", "commit.gpgsign=false"])
            .args(arguments)
            .status()
            .unwrap();
        assert!(status.success(), "git {arguments:?}");
    }

    #[test]
    fn a_tree_with_uncommitted_changes_is_never_named_by_its_commit_alone() {
        let root = env::temp_dir().join(format!("xtask-revision-test-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q"]);
        fs::write(root.join("a.txt"), "one\n").unwrap();
        git(&root, &["add", "a.txt"]);
        git(&root, &["commit", "-q", "-m", "one"]);
        let clean = revision(&root).unwrap();
        assert!(decode_commit(&Exit::Code(0), &clean).is_ok(), "{clean}");
        fs::write(root.join("a.txt"), "two\n").unwrap();
        fs::write(root.join("b.txt"), "new\n").unwrap();
        let dirty = revision(&root).unwrap();
        assert_eq!(dirty, format!("{clean} with 2 uncommitted changes"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn status_lines_count_as_uncommitted_changes_and_a_failed_status_is_an_error() {
        assert_eq!(decode_status(&Exit::Code(0), ""), Ok(0));
        assert_eq!(decode_status(&Exit::Code(0), " M a.txt\n?? b.txt\n"), Ok(2));
        assert!(decode_status(&Exit::Code(128), "").is_err());
        assert!(decode_status(&Exit::TimedOut, "").is_err());
        assert_eq!(describe_revision("511cf42", 0), "511cf42");
        assert_eq!(
            describe_revision("511cf42", 1),
            "511cf42 with 1 uncommitted changes"
        );
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

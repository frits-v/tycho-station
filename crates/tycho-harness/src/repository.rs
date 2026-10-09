//! Builds the synthetic epic repository.
//!
//! A tiny Rust target project with one intentionally failing test per work
//! unit, committed with a fixed author, date and default branch so the head
//! commit hashes the same everywhere.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tycho_types::envelope::CommitSha;
use tycho_types::token::TokenError;

use crate::content;

/// A patch fixture larger than this is rejected rather than applied.
pub const PATCH_MAX_BYTES: usize = 65_536;

const AUTHOR_NAME: &str = "Tycho Synthetic";
const AUTHOR_EMAIL: &str = "synthetic@tycho.station";
/// Base timestamp for the first commit, fixed so the head commit hashes the same everywhere.
const COMMIT_EPOCH_SECONDS: i64 = 1_700_000_000;

#[derive(Debug)]
pub struct BuiltRepository {
    pub root: PathBuf,
    pub head_sha: CommitSha,
}

#[derive(Debug)]
pub enum RepositoryError {
    TargetNotEmpty,
    PatchTooLarge { bytes: usize },
    Io(io::Error),
    Git { args: Vec<String>, stderr: String },
    Sha(TokenError),
}

impl std::fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetNotEmpty => write!(formatter, "target directory is not empty"),
            Self::PatchTooLarge { bytes } => {
                write!(
                    formatter,
                    "patch is {bytes} bytes; maximum is {PATCH_MAX_BYTES}"
                )
            }
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Git { args, stderr } => {
                write!(formatter, "git {}: {stderr}", args.join(" "))
            }
            Self::Sha(error) => write!(formatter, "head commit: {error}"),
        }
    }
}

impl std::error::Error for RepositoryError {}

struct CommitSpec {
    message: &'static str,
    files: &'static [(&'static str, &'static [u8])],
    offset_minutes: i64,
}

const WIDGET_CARGO_TOML: &[u8] = b"[package]\nname = \"widget\"\nversion = \"0.1.0\"\nedition = \"2021\"\npublish = false\n\n[workspace]\n";
const WIDGET_GITIGNORE: &[u8] = b"/target\nCargo.lock\n";
const WIDGET_LIB_RS_INITIAL: &[u8] = include_bytes!("../fixtures/widget/src/lib_initial.rs");
const WIDGET_LIB_RS_FINAL: &[u8] = include_bytes!("../fixtures/widget/src/lib.rs");
const WIDGET_ROUTING_JSON: &[u8] = include_bytes!("../fixtures/widget/config/routing.json");

const COMMITS: [CommitSpec; 4] = [
    CommitSpec {
        message: "chore: scaffold the widget project",
        files: &[
            ("Cargo.toml", WIDGET_CARGO_TOML),
            (".gitignore", WIDGET_GITIGNORE),
        ],
        offset_minutes: 0,
    },
    CommitSpec {
        message: "test: add the widget source and its tests",
        files: &[("src/lib.rs", WIDGET_LIB_RS_INITIAL)],
        offset_minutes: 1,
    },
    CommitSpec {
        message: "docs: add the budget ceiling policy",
        files: &[("POLICY.md", content::POLICY_BUDGET_CEILING)],
        offset_minutes: 2,
    },
    CommitSpec {
        message: "feat: add the routing ceiling and two lookup shapes",
        files: &[
            ("config/routing.json", WIDGET_ROUTING_JSON),
            ("src/lib.rs", WIDGET_LIB_RS_FINAL),
        ],
        offset_minutes: 3,
    },
];

fn commit_date(offset_minutes: i64) -> String {
    let seconds = COMMIT_EPOCH_SECONDS.saturating_add(offset_minutes.saturating_mul(60));
    format!("{seconds} +0000")
}

fn ensure_empty_directory(path: &Path) -> Result<(), RepositoryError> {
    let mut entries = fs::read_dir(path).map_err(RepositoryError::Io)?;
    if entries.next().is_some() {
        return Err(RepositoryError::TargetNotEmpty);
    }
    Ok(())
}

/// A bare `git` invocation with every inherited environment variable dropped
/// except `PATH`, so a caller's `GIT_DIR` or similar never reaches the child.
fn base_command(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command.env_clear();
    if let Ok(path) = std::env::var("PATH") {
        command.env("PATH", path);
    }
    command.current_dir(dir).args(args);
    command
}

/// Isolates every git invocation from the host's global and system config.
fn run_git(dir: &Path, author_date: &str, args: &[&str]) -> Result<Output, RepositoryError> {
    base_command(dir, args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", AUTHOR_NAME)
        .env("GIT_AUTHOR_EMAIL", AUTHOR_EMAIL)
        .env("GIT_COMMITTER_NAME", AUTHOR_NAME)
        .env("GIT_COMMITTER_EMAIL", AUTHOR_EMAIL)
        .env("GIT_AUTHOR_DATE", author_date)
        .env("GIT_COMMITTER_DATE", author_date)
        .output()
        .map_err(RepositoryError::Io)
}

fn checked_git(dir: &Path, author_date: &str, args: &[&str]) -> Result<Output, RepositoryError> {
    let output = run_git(dir, author_date, args)?;
    if output.status.success() {
        return Ok(output);
    }
    Err(RepositoryError::Git {
        args: args.iter().map(ToString::to_string).collect(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[expect(
    clippy::disallowed_methods,
    reason = "the synthetic repository is built in a directory of the test"
)]
fn apply_commit(target_dir: &Path, commit: &CommitSpec) -> Result<(), RepositoryError> {
    for (relative, bytes) in commit.files {
        let path = target_dir.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(RepositoryError::Io)?;
        }
        fs::write(&path, bytes).map_err(RepositoryError::Io)?;
    }
    let date = commit_date(commit.offset_minutes);
    checked_git(target_dir, &date, &["add", "-A"])?;
    checked_git(target_dir, &date, &["commit", "-q", "-m", commit.message])?;
    Ok(())
}

/// Builds the synthetic epic into `target_dir`, which must exist and be empty.
pub fn build(target_dir: &Path) -> Result<BuiltRepository, RepositoryError> {
    ensure_empty_directory(target_dir)?;
    checked_git(
        target_dir,
        &commit_date(0),
        &["-c", "init.defaultBranch=main", "init", "-q"],
    )?;
    for commit in &COMMITS {
        apply_commit(target_dir, commit)?;
    }
    let head = checked_git(target_dir, &commit_date(0), &["rev-parse", "HEAD"])?;
    let raw_sha = String::from_utf8_lossy(&head.stdout).trim().to_string();
    let head_sha = CommitSha::parse(&raw_sha).map_err(RepositoryError::Sha)?;
    Ok(BuiltRepository {
        root: target_dir.to_path_buf(),
        head_sha,
    })
}

/// Applies a reference change to the working tree without committing it.
pub fn apply_patch(checkout: &Path, patch: &[u8]) -> Result<(), RepositoryError> {
    if patch.len() > PATCH_MAX_BYTES {
        return Err(RepositoryError::PatchTooLarge { bytes: patch.len() });
    }
    let mut child = base_command(checkout, &["apply", "-"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(RepositoryError::Io)?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| RepositoryError::Io(io::Error::other("git apply did not accept stdin")))?;
    stdin.write_all(patch).map_err(RepositoryError::Io)?;
    drop(stdin);
    let output = child.wait_with_output().map_err(RepositoryError::Io)?;
    if output.status.success() {
        return Ok(());
    }
    Err(RepositoryError::Git {
        args: vec!["apply".to_string(), "-".to_string()],
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Used by the verification tests to confirm a checkout stays clean after a run.
#[cfg(test)]
pub(crate) fn status_porcelain(dir: &Path) -> Result<String, RepositoryError> {
    let output = checked_git(dir, &commit_date(0), &["status", "--porcelain"])?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_HEAD_SHA: &str = "3711d61ebf71d9117a6d46772eb40fc05d86f03a";

    const BOGUS_GIT_DIR: &str = "/nonexistent-should-be-ignored";
    const INHERITED_GIT_DIR_CHILD: &str =
        "repository::tests::build_under_an_inherited_git_dir_in_a_child_process";

    #[test]
    fn build_produces_a_stable_head_sha() {
        let checkout = tempfile::tempdir().unwrap();
        let built = build(checkout.path()).unwrap();
        assert_eq!(built.head_sha.as_str(), EXPECTED_HEAD_SHA);
    }

    /// Runs only in a child process that `build_ignores_an_inherited_git_dir`
    /// starts with `GIT_DIR` set, so no test mutates this process's environment.
    #[test]
    #[ignore = "run by build_ignores_an_inherited_git_dir in a child process"]
    fn build_under_an_inherited_git_dir_in_a_child_process() {
        assert_eq!(std::env::var("GIT_DIR").unwrap(), BOGUS_GIT_DIR);
        let checkout = tempfile::tempdir().unwrap();
        let built = build(checkout.path()).unwrap();
        assert_eq!(built.head_sha.as_str(), EXPECTED_HEAD_SHA);
    }

    #[test]
    fn build_ignores_an_inherited_git_dir() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", INHERITED_GIT_DIR_CHILD])
            .env("GIT_DIR", BOGUS_GIT_DIR)
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

    #[test]
    fn build_rejects_a_non_empty_target() {
        let checkout = tempfile::tempdir().unwrap();
        fs::write(checkout.path().join("already-here"), b"x").unwrap();
        assert!(matches!(
            build(checkout.path()),
            Err(RepositoryError::TargetNotEmpty)
        ));
    }

    #[test]
    fn apply_patch_rejects_an_oversized_patch() {
        let checkout = tempfile::tempdir().unwrap();
        build(checkout.path()).unwrap();
        let big = vec![b'a'; PATCH_MAX_BYTES.saturating_add(1)];
        assert!(matches!(
            apply_patch(checkout.path(), &big),
            Err(RepositoryError::PatchTooLarge { .. })
        ));
    }
}

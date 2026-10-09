//! Per-project canonical bare repositories under the core home, the worktree each work unit
//! attempt clones from one, and the pin refs that keep a worker's commit.
//!
//! Every git call runs through `command` with a timeout, an output cap, and the host's global
//! and system configuration shut out.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tycho_types::envelope::{BranchName, CommitSha};
use tycho_types::service::{Attempt, EpicId, WorkUnitId};
use tycho_types::session::SessionName;
use tycho_types::token::check_slug;

use crate::agent_files::current_uid;
use crate::agent_tree::{self, Bounds, Owners, TreeError, TreeRefusal};
use crate::command::{run_status_capped, Captured};
use crate::config::COMMAND_OUTPUT_MAX_BYTES;
use crate::private_dir;

pub const REPOSITORIES_DIR: &str = "repositories";
pub const BRIEFS_DIR: &str = "briefs";
pub const PIN_REF_PREFIX: &str = "refs/factory/checkpoints";
pub const PROJECT_NAME_MAX_BYTES: usize = 64;
/// A clone or fetch of a large repository over the local file system.
pub const GIT_TIMEOUT: Duration = Duration::from_secs(300);
/// The identity of commits made in a worktree; the worktree never signs.
pub const WORKER_NAME: &str = "Tycho Worker";
pub const WORKER_EMAIL: &str = "worker@tycho.invalid";
/// A worktree's `origin` push URL: a path that cannot exist, so a push from the worktree fails.
pub const PUSH_DISABLED: &str = "/dev/null/push-disabled";
/// Levels below a worktree a removal enters; each level holds one descriptor open.
pub const WORKTREE_DEPTH_MAX: usize = 64;
/// Entries a removal deletes: a large checkout with its `.git` and build output fits.
pub const WORKTREE_ENTRIES_MAX: usize = 2_000_000;
const WORKTREE_BOUNDS: Bounds = Bounds {
    depth: WORKTREE_DEPTH_MAX,
    entries: WORKTREE_ENTRIES_MAX,
};
const GIT_ENVIRONMENT: [(&str, &str); 3] = [
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_TERMINAL_PROMPT", "0"),
];
const GIT_REMOVED: [&str; 4] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryError {
    Input(String),
    Io(String),
    /// A path under the worktree root is a symlink, a stranger's, or past a bound.
    Refused(String, TreeRefusal),
    /// git could not start, timed out or overran its output cap: worth a retry.
    CouldNotRun(String),
    /// git ran and refused: the command and its report.
    Git(String),
    /// The worker's head is not on the branch the fetch brought in.
    NotFetched(String),
    Unrecognised(String),
}

impl RepositoryError {
    /// Only a git that could not run, or a file system error, is worth another try.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        match self {
            Self::Io(_) | Self::CouldNotRun(_) => true,
            Self::Input(_)
            | Self::Refused(..)
            | Self::Git(_)
            | Self::NotFetched(_)
            | Self::Unrecognised(_) => false,
        }
    }
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(reason) => write!(formatter, "repository input: {reason}"),
            Self::Io(reason) => write!(formatter, "repository file system: {reason}"),
            Self::Refused(path, refusal) => write!(formatter, "refused: {path} {refusal}"),
            Self::CouldNotRun(reason) => write!(formatter, "git could not run: {reason}"),
            Self::Git(reason) => write!(formatter, "git {reason}"),
            Self::NotFetched(reason) => write!(formatter, "not from the fetched branch: {reason}"),
            Self::Unrecognised(reason) => write!(formatter, "git output not recognised: {reason}"),
        }
    }
}

impl std::error::Error for RepositoryError {}

impl From<TreeError> for RepositoryError {
    fn from(error: TreeError) -> Self {
        match error {
            TreeError::Refused(path, refusal) => Self::Refused(text(&path), refusal),
            TreeError::Io(path, reason) => Self::Io(format!("{}: {reason}", path.display())),
        }
    }
}

/// A project's name: the canonical repository is `<name>.git`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProjectName(String);

impl ProjectName {
    pub fn parse(text: &str) -> Result<Self, RepositoryError> {
        check_slug(text, PROJECT_NAME_MAX_BYTES)
            .map_err(|error| RepositoryError::Input(format!("project {text:?}: {error}")))?;
        Ok(Self(text.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProjectName {
    type Error = RepositoryError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ProjectName> for String {
    fn from(value: ProjectName) -> Self {
        value.0
    }
}

/// A unit attempt's clone: where it is, the branch the worker commits on, and its base.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Worktree {
    pub path: PathBuf,
    pub branch: BranchName,
    pub base: CommitSha,
}

/// What `rev-parse` printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShaRead {
    Sha(CommitSha),
    Unrecognised(String),
}

#[must_use]
pub fn decode_sha(stdout: &str) -> ShaRead {
    let line = stdout.trim_end_matches('\n');
    CommitSha::parse(line).map_or_else(
        |_| ShaRead::Unrecognised(line.chars().take(80).collect()),
        ShaRead::Sha,
    )
}

/// What `rev-parse --is-bare-repository` printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BareRead {
    Bare,
    NotBare,
    Unrecognised(String),
}

#[must_use]
pub fn decode_bare(stdout: &str) -> BareRead {
    match stdout.trim_end_matches('\n') {
        "true" => BareRead::Bare,
        "false" => BareRead::NotBare,
        other => BareRead::Unrecognised(other.chars().take(80).collect()),
    }
}

/// `refs/factory/checkpoints/<unit>/<sequence>`.
#[must_use]
pub fn pin_ref(unit: &WorkUnitId, sequence: u32) -> String {
    format!("{PIN_REF_PREFIX}/{unit}/{sequence}")
}

/// `<unit>/a<attempt>`, the branch a unit attempt's worker commits on.
pub fn unit_branch(unit: &WorkUnitId, attempt: Attempt) -> Result<BranchName, RepositoryError> {
    BranchName::parse(&format!("{unit}/a{}", attempt.get()))
        .map_err(|error| RepositoryError::Input(error.to_string()))
}

fn absolute(what: &str, path: &Path) -> Result<(), RepositoryError> {
    let parent = path
        .components()
        .any(|part| part == std::path::Component::ParentDir);
    if !path.is_absolute() || parent || path.to_str().is_none() {
        return Err(RepositoryError::Input(format!(
            "{what} {} is not an absolute UTF-8 path",
            path.display()
        )));
    }
    Ok(())
}

fn text(path: &Path) -> String {
    path.display().to_string()
}

/// The canonical repositories and the directory worktrees are cloned into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repositories {
    git: PathBuf,
    core_home: PathBuf,
    worktree_root: PathBuf,
    owners: Owners,
}

impl Repositories {
    pub fn new(
        git: PathBuf,
        core_home: PathBuf,
        worktree_root: PathBuf,
    ) -> Result<Self, RepositoryError> {
        absolute("core home", &core_home)?;
        absolute("worktree root", &worktree_root)?;
        let core = current_uid();
        Ok(Self {
            git,
            core_home,
            worktree_root,
            owners: Owners { core, agent: core },
        })
    }

    /// Admits directories under the worktree root owned by `uid` as well as by the core.
    #[must_use]
    pub const fn with_agent_uid(mut self, uid: u32) -> Self {
        self.owners.agent = uid;
        self
    }

    #[must_use]
    pub fn canonical(&self, project: &ProjectName) -> PathBuf {
        self.core_home
            .join(REPOSITORIES_DIR)
            .join(format!("{}.git", project.as_str()))
    }

    #[must_use]
    pub fn worktree_root(&self) -> &Path {
        &self.worktree_root
    }

    /// `<root>/<epic>/<unit>/a<attempt>`.
    #[must_use]
    pub fn worktree_path(&self, epic: &EpicId, unit: &WorkUnitId, attempt: Attempt) -> PathBuf {
        self.worktree_root
            .join(epic.as_str())
            .join(unit.as_str())
            .join(format!("a{}", attempt.get()))
    }

    /// Beside the worktrees, never inside one, where it would be an untracked file.
    #[must_use]
    pub fn brief_path(&self, session: &SessionName) -> PathBuf {
        self.worktree_root
            .join(BRIEFS_DIR)
            .join(format!("{session}.md"))
    }

    /// Creates the briefs directory under the worktree root, refusing a symlink at any level.
    pub fn ensure_briefs_dir(&self) -> Result<PathBuf, RepositoryError> {
        let dir = self.worktree_root.join(BRIEFS_DIR);
        drop(agent_tree::ensure_dirs(
            &self.worktree_root,
            &dir,
            self.owners,
        )?);
        Ok(dir)
    }

    /// Runs git and returns whatever exit status it ends with.
    fn git_status(&self, arguments: &[&str]) -> Result<Captured, RepositoryError> {
        let removed: Vec<OsString> = GIT_REMOVED.iter().map(OsString::from).collect();
        run_status_capped(
            &self.git,
            arguments,
            &GIT_ENVIRONMENT,
            &removed,
            GIT_TIMEOUT,
            COMMAND_OUTPUT_MAX_BYTES,
        )
        .map_err(|error| RepositoryError::CouldNotRun(format!("{}: {error}", arguments.join(" "))))
    }

    fn git(&self, arguments: &[&str]) -> Result<Captured, RepositoryError> {
        let captured = self.git_status(arguments)?;
        if !captured.status.success() {
            return Err(RepositoryError::Git(format!(
                "{} exited with {}: {}",
                arguments.join(" "),
                captured.status,
                captured.stderr.trim()
            )));
        }
        Ok(captured)
    }

    fn rev_parse(&self, repository: &Path, revision: &str) -> Result<CommitSha, RepositoryError> {
        let captured = self.git(&[
            "-C",
            &text(repository),
            "rev-parse",
            "--verify",
            "--end-of-options",
            revision,
        ])?;
        match decode_sha(&captured.stdout) {
            ShaRead::Sha(sha) => Ok(sha),
            ShaRead::Unrecognised(line) => Err(RepositoryError::Unrecognised(line)),
        }
    }

    /// Creates the project's bare repository from `source`, or accepts an existing bare one;
    /// returns its HEAD.
    pub fn create_canonical(
        &self,
        project: &ProjectName,
        source: &Path,
    ) -> Result<CommitSha, RepositoryError> {
        let canonical = self.canonical(project);
        let root = self.core_home.join(REPOSITORIES_DIR);
        private_dir::ensure(&[self.core_home.clone(), root])
            .map_err(|error| RepositoryError::Io(error.to_string()))?;
        if canonical.exists() {
            let captured =
                self.git(&["-C", &text(&canonical), "rev-parse", "--is-bare-repository"])?;
            match decode_bare(&captured.stdout) {
                BareRead::Bare => {}
                BareRead::NotBare => {
                    return Err(RepositoryError::Input(format!(
                        "{} is not bare",
                        canonical.display()
                    )))
                }
                BareRead::Unrecognised(line) => return Err(RepositoryError::Unrecognised(line)),
            }
        } else {
            self.git(&[
                "clone",
                "--bare",
                "--quiet",
                "--no-hardlinks",
                "--template=",
                &text(source),
                &text(&canonical),
            ])?;
        }
        self.rev_parse(&canonical, "HEAD")
    }

    /// Clones the canonical repository into `path` on a new `branch`, with a local identity
    /// that does not sign; a directory left by an interrupted clone is removed first.
    pub fn clone_worktree(
        &self,
        project: &ProjectName,
        path: &Path,
        branch: &BranchName,
    ) -> Result<Worktree, RepositoryError> {
        absolute("worktree", path)?;
        if !path.starts_with(&self.worktree_root) || path == self.worktree_root {
            return Err(RepositoryError::Input(format!(
                "{} is outside {}",
                path.display(),
                self.worktree_root.display()
            )));
        }
        self.prepare_clone_target(path)?;
        let canonical = self.canonical(project);
        self.git(&[
            "clone",
            "--quiet",
            "--no-hardlinks",
            "--template=",
            &text(&canonical),
            &text(path),
        ])?;
        let worktree = text(path);
        for arguments in [
            ["checkout", "-q", "-b", branch.as_str()],
            // Only the core moves work out of a worktree, by fetching from it.
            ["config", "remote.origin.pushurl", PUSH_DISABLED, ""],
            ["config", "commit.gpgsign", "false", ""],
            ["config", "user.name", WORKER_NAME, ""],
            ["config", "user.email", WORKER_EMAIL, ""],
        ] {
            let mut words = vec!["-C", worktree.as_str()];
            words.extend(arguments.iter().filter(|word| !word.is_empty()));
            self.git(&words)?;
        }
        let base = self.rev_parse(path, "HEAD")?;
        Ok(Worktree {
            path: self.resolved_inside_root(path)?,
            branch: branch.clone(),
            base,
        })
    }

    /// Ensures the levels down to `path`'s parent, then removes what an interrupted clone left.
    fn prepare_clone_target(&self, path: &Path) -> Result<(), RepositoryError> {
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(RepositoryError::Input(format!(
                "{} has no parent",
                path.display()
            )));
        };
        let directory = agent_tree::ensure_dirs(&self.worktree_root, parent, self.owners)?;
        agent_tree::remove_dir(
            directory.as_fd(),
            parent,
            name,
            self.owners,
            WORKTREE_BOUNDS,
        )?;
        Ok(())
    }

    /// The resolved `path`, which must be the resolved root joined with the same names.
    fn resolved_inside_root(&self, path: &Path) -> Result<PathBuf, RepositoryError> {
        let io =
            |error: std::io::Error| RepositoryError::Io(format!("{}: {error}", path.display()));
        let root = fs::canonicalize(&self.worktree_root).map_err(io)?;
        let relative = path
            .strip_prefix(&self.worktree_root)
            .map_err(|_| RepositoryError::Refused(text(path), TreeRefusal::OutsideRoot))?;
        let expected = root.join(relative);
        if fs::canonicalize(path).map_err(io)? != expected {
            return Err(RepositoryError::Refused(text(path), TreeRefusal::Symlink));
        }
        Ok(expected)
    }

    /// Fetches the worktree's branch into the canonical repository and points `pin` at
    /// `head`, which must be that fetch's commit or one before it.
    pub fn pin(
        &self,
        project: &ProjectName,
        worktree: &Worktree,
        head: &CommitSha,
        pin: &str,
    ) -> Result<(), RepositoryError> {
        let canonical = text(&self.canonical(project));
        let refspec = format!("refs/heads/{}", worktree.branch);
        self.git(&[
            "-C",
            &canonical,
            "fetch",
            "--quiet",
            "--no-tags",
            &text(&worktree.path),
            &refspec,
        ])?;
        self.check_fetched(&canonical, head)?;
        self.git(&["-C", &canonical, "update-ref", pin, head.as_str()])?;
        let pinned = self.rev_parse(Path::new(&canonical), pin)?;
        if pinned != *head {
            return Err(RepositoryError::Unrecognised(format!(
                "{pin} points at {pinned}, not {head}"
            )));
        }
        Ok(())
    }

    /// `merge-base --is-ancestor <head> FETCH_HEAD`: exit 0 is on the branch, 1 is not, and
    /// anything else is unrecognised.
    fn check_fetched(&self, canonical: &str, head: &CommitSha) -> Result<(), RepositoryError> {
        let captured = self.git_status(&[
            "-C",
            canonical,
            "merge-base",
            "--is-ancestor",
            head.as_str(),
            "FETCH_HEAD",
        ])?;
        match captured.status.code() {
            Some(0) => Ok(()),
            Some(1) => Err(RepositoryError::NotFetched(head.to_string())),
            other => Err(RepositoryError::Unrecognised(format!(
                "merge-base exited {other:?}: {}",
                captured.stderr.trim()
            ))),
        }
    }

    /// The commit a ref of the canonical repository points at.
    pub fn resolve(
        &self,
        project: &ProjectName,
        revision: &str,
    ) -> Result<CommitSha, RepositoryError> {
        self.rev_parse(&self.canonical(project), revision)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::process::Command;

    #[derive(Debug)]
    pub struct Scratch(pub PathBuf);

    impl Scratch {
        pub fn new(test: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("tycho-repositories-{test}-{}", std::process::id()));
            if dir.exists() {
                fs::remove_dir_all(&dir).unwrap();
            }
            fs::create_dir_all(&dir).unwrap();
            Self(fs::canonicalize(&dir).unwrap())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.0));
        }
    }

    fn git(dir: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .args(["-C", &text(dir)])
            .args(arguments)
            .envs(GIT_ENVIRONMENT)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    /// A source repository with one commit on `trunk`, and the repositories rooted in scratch.
    pub fn fixture(scratch: &Scratch) -> (Repositories, ProjectName) {
        let source = scratch.0.join("source");
        fs::create_dir_all(&source).unwrap();
        git(&source, &["init", "-q", "-b", "trunk"]);
        fs::write(source.join("README"), "widget\n").unwrap();
        git(&source, &["add", "README"]);
        git(&source, &["commit", "-q", "-m", "init"]);
        let repositories = Repositories::new(
            PathBuf::from("git"),
            scratch.0.join("home"),
            scratch.0.join("worktrees"),
        )
        .unwrap();
        let project = ProjectName::parse("widget").unwrap();
        repositories.create_canonical(&project, &source).unwrap();
        (repositories, project)
    }

    fn unit() -> WorkUnitId {
        WorkUnitId::parse("wu01").unwrap()
    }

    #[test]
    fn decoders_enumerate_their_states() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            decode_sha(&format!("{sha}\n")),
            ShaRead::Sha(CommitSha::parse(sha).unwrap())
        );
        assert!(matches!(decode_sha(""), ShaRead::Unrecognised(_)));
        assert!(matches!(decode_sha("HEAD\n"), ShaRead::Unrecognised(_)));
        assert!(matches!(
            decode_sha(&format!("{sha}\n{sha}\n")),
            ShaRead::Unrecognised(_)
        ));
        assert_eq!(decode_bare("true\n"), BareRead::Bare);
        assert_eq!(decode_bare("false\n"), BareRead::NotBare);
        assert!(matches!(decode_bare("yes\n"), BareRead::Unrecognised(_)));
    }

    #[test]
    fn names_have_exact_text() {
        assert_eq!(pin_ref(&unit(), 3), "refs/factory/checkpoints/wu01/3");
        let attempt = Attempt::new(2).unwrap();
        assert_eq!(unit_branch(&unit(), attempt).unwrap().as_str(), "wu01/a2");
        let repositories =
            Repositories::new(PathBuf::from("git"), "/core".into(), "/agent/wt".into()).unwrap();
        let epic = EpicId::parse("cf7a").unwrap();
        assert_eq!(
            repositories.worktree_path(&epic, &unit(), attempt),
            PathBuf::from("/agent/wt/cf7a/wu01/a2")
        );
        let project = ProjectName::parse("widget").unwrap();
        assert_eq!(
            repositories.canonical(&project),
            PathBuf::from("/core/repositories/widget.git")
        );
        let session = SessionName::parse("cf7a.wu01.wrk.claude.a1f3").unwrap();
        assert_eq!(
            repositories.brief_path(&session),
            PathBuf::from("/agent/wt/briefs/cf7a.wu01.wrk.claude.a1f3.md")
        );
        assert!(ProjectName::parse("Widget").is_err());
        assert!(ProjectName::parse("../x").is_err());
        assert!(Repositories::new(PathBuf::from("git"), "core".into(), "/w".into()).is_err());
    }

    #[test]
    fn a_worktree_is_a_clone_of_the_canonical_repository_on_its_own_branch() {
        let scratch = Scratch::new("clone");
        let (repositories, project) = fixture(&scratch);
        let canonical = repositories.canonical(&project);
        assert_eq!(
            git(&canonical, &["rev-parse", "--is-bare-repository"]),
            "true\n"
        );
        let path = scratch.0.join("worktrees/cf7a/wu01/a1");
        let branch = unit_branch(&unit(), Attempt::FIRST).unwrap();
        let worktree = repositories
            .clone_worktree(&project, &path, &branch)
            .unwrap();
        assert_eq!(worktree.path, path);
        assert_eq!(
            git(&path, &["remote", "get-url", "origin"]).trim(),
            text(&canonical)
        );
        assert_eq!(git(&path, &["branch", "--show-current"]).trim(), "wu01/a1");
        assert_eq!(git(&path, &["config", "commit.gpgsign"]).trim(), "false");
        assert_eq!(
            git(&path, &["config", "remote.origin.pushurl"]).trim(),
            PUSH_DISABLED
        );
        let push = Command::new("git")
            .args([
                "-C",
                &text(&path),
                "push",
                "-q",
                "origin",
                "HEAD:refs/heads/escape",
            ])
            .envs(GIT_ENVIRONMENT)
            .output()
            .unwrap();
        assert!(
            !push.status.success(),
            "a push from the worktree reached origin"
        );
        assert_eq!(
            git(&path, &["rev-parse", "HEAD"]).trim(),
            worktree.base.as_str()
        );
        assert!(!path
            .join(".git/hooks")
            .read_dir()
            .is_ok_and(|mut entries| entries.next().is_some()));
        let again = repositories
            .clone_worktree(&project, &path, &branch)
            .unwrap();
        assert_eq!(
            again, worktree,
            "a repeated clone starts over in the same place"
        );
        assert!(repositories
            .clone_worktree(&project, &scratch.0.join("elsewhere"), &branch)
            .is_err());
        assert!(repositories
            .create_canonical(&project, Path::new("/nonexistent"))
            .is_ok());
    }

    #[test]
    fn a_symlinked_worktree_directory_is_refused_and_its_target_survives() {
        let scratch = Scratch::new("linked-worktree");
        let (repositories, project) = fixture(&scratch);
        let victim = scratch.0.join("victim");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("keep"), "untouched").unwrap();
        fs::create_dir_all(scratch.0.join("worktrees/cf7a/wu01")).unwrap();
        let path = scratch.0.join("worktrees/cf7a/wu01/a1");
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        let branch = unit_branch(&unit(), Attempt::FIRST).unwrap();
        let refused = repositories.clone_worktree(&project, &path, &branch);
        assert_eq!(
            refused,
            Err(RepositoryError::Refused(text(&path), TreeRefusal::Symlink))
        );
        assert!(!refused.unwrap_err().is_transient());
        assert_eq!(
            fs::read_to_string(victim.join("keep")).unwrap(),
            "untouched"
        );
    }

    #[test]
    fn a_symlinked_ancestor_is_refused_on_create() {
        let scratch = Scratch::new("linked-ancestor");
        let (repositories, project) = fixture(&scratch);
        let elsewhere = scratch.0.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(scratch.0.join("worktrees")).unwrap();
        let epic = scratch.0.join("worktrees/cf7a");
        std::os::unix::fs::symlink(&elsewhere, &epic).unwrap();
        let branch = unit_branch(&unit(), Attempt::FIRST).unwrap();
        assert_eq!(
            repositories.clone_worktree(&project, &epic.join("wu01/a1"), &branch),
            Err(RepositoryError::Refused(text(&epic), TreeRefusal::Symlink))
        );
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
        fs::remove_file(&epic).unwrap();
        let briefs = scratch.0.join("worktrees/briefs");
        std::os::unix::fs::symlink(&elsewhere, &briefs).unwrap();
        assert_eq!(
            repositories.ensure_briefs_dir(),
            Err(RepositoryError::Refused(
                text(&briefs),
                TreeRefusal::Symlink
            ))
        );
    }

    #[test]
    fn a_symlink_inside_a_worktree_is_removed_without_following_it() {
        let scratch = Scratch::new("inner-link");
        let (repositories, project) = fixture(&scratch);
        let path = scratch.0.join("worktrees/cf7a/wu01/a1");
        let branch = unit_branch(&unit(), Attempt::FIRST).unwrap();
        let first = repositories
            .clone_worktree(&project, &path, &branch)
            .unwrap();
        let victim = scratch.0.join("victim");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("keep"), "untouched").unwrap();
        std::os::unix::fs::symlink(&victim, path.join("escape")).unwrap();
        std::os::unix::fs::symlink(victim.join("keep"), path.join(".git/escape")).unwrap();
        let again = repositories
            .clone_worktree(&project, &path, &branch)
            .unwrap();
        assert_eq!(again, first);
        assert!(fs::symlink_metadata(path.join("escape")).is_err());
        assert_eq!(
            fs::read_to_string(victim.join("keep")).unwrap(),
            "untouched"
        );
        assert_eq!(fs::read_dir(&victim).unwrap().count(), 1);
    }

    #[test]
    fn a_pin_ref_holds_the_workers_commit_in_the_canonical_repository() {
        let scratch = Scratch::new("pin");
        let (repositories, project) = fixture(&scratch);
        let path = scratch.0.join("worktrees/cf7a/wu01/a1");
        let branch = unit_branch(&unit(), Attempt::FIRST).unwrap();
        let worktree = repositories
            .clone_worktree(&project, &path, &branch)
            .unwrap();
        fs::write(path.join("answer"), "42\n").unwrap();
        git(&path, &["add", "answer"]);
        git(&path, &["commit", "-q", "-m", "answer"]);
        let head = CommitSha::parse(git(&path, &["rev-parse", "HEAD"]).trim()).unwrap();
        let pin = pin_ref(&unit(), 1);
        repositories.pin(&project, &worktree, &head, &pin).unwrap();
        assert_eq!(repositories.resolve(&project, &pin).unwrap(), head);
        let missing = CommitSha::parse("1123456789abcdef0123456789abcdef01234567").unwrap();
        assert!(repositories
            .pin(&project, &worktree, &missing, &pin_ref(&unit(), 2))
            .is_err());
        let canonical = repositories.canonical(&project);
        let stranger = scratch.0.join("stranger");
        fs::create_dir_all(&stranger).unwrap();
        git(&stranger, &["init", "-q", "-b", "x"]);
        git(
            &stranger,
            &["commit", "-q", "--allow-empty", "-m", "unrelated"],
        );
        git(
            &canonical,
            &["fetch", "-q", &text(&stranger), "x:refs/heads/stranger"],
        );
        let unrelated =
            CommitSha::parse(git(&canonical, &["rev-parse", "stranger"]).trim()).unwrap();
        assert_eq!(
            repositories.pin(&project, &worktree, &unrelated, &pin_ref(&unit(), 3)),
            Err(RepositoryError::NotFetched(unrelated.to_string()))
        );
        assert!(repositories
            .resolve(&project, &pin_ref(&unit(), 3))
            .is_err());
    }
}

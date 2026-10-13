//! What a review run starts from: its commits, its credentials, the Claude binary and its own
//! directory, for each mode.

use std::env;
use std::fs;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::{git_in, langfuse, pull_request, scrubbed, Context, GitHub, Mode};
use crate::anthropic_token::{self, AccessToken};
use crate::app_token::{self, REVIEW};
use crate::checkout;
use crate::github_api::Client;
use crate::process::{run_bounded, Exit};

const EVENT_MAX_BYTES: u64 = 1 << 20;
const GIT_TIMEOUT: Duration = Duration::from_secs(120);
const MISE_TIMEOUT: Duration = Duration::from_secs(60);
const RUN_TIME_MAX: Duration = Duration::from_secs(30 * 60);
/// Left unused at the end of the access token's life, so no run starts on a token about to lapse.
const TOKEN_MARGIN: Duration = Duration::from_secs(120);
const RUN_TIME_MIN: Duration = Duration::from_secs(10 * 60);
const DRY_RUN_BASE: &str = "origin/main";
/// The diff, the earlier findings and one instructions file per pass.
const FILES_MAX: usize = 64;
const PATH_MAX_BYTES: usize = 4096;
/// The App's reviews one pull request takes; past it a run refuses, so no exchange of
/// comments and reviews goes on without end.
const REVIEWS_PER_PULL_REQUEST_MAX: usize = 20;

pub fn context(mode: &Mode) -> Result<Context, String> {
    match mode {
        Mode::DryRun => dry_run_context(),
        Mode::Post { checkout } => post_context(checkout),
    }
}

fn required(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is unset; the review job sets it"))
}

fn read_trigger() -> Result<pull_request::Trigger, String> {
    let name = required("GITHUB_EVENT_NAME")?;
    let path = required("GITHUB_EVENT_PATH")?;
    let size = fs::metadata(&path)
        .map_err(|error| format!("cannot read the event file: {error}"))?
        .len();
    if size > EVENT_MAX_BYTES {
        return Err(format!("the event file is over {EVENT_MAX_BYTES} bytes"));
    }
    let text = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read the event file: {error}"))?;
    pull_request::decode_trigger(&name, &text)
}

fn current_user() -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .ok()
        .flatten()
        .map(|user| user.name)
}

/// The run time the access token leaves, after the margin, capped at [`RUN_TIME_MAX`].
pub fn run_time_for(expires_in_seconds: u64) -> Result<Duration, String> {
    let usable = Duration::from_secs(expires_in_seconds).saturating_sub(TOKEN_MARGIN);
    if usable < RUN_TIME_MIN {
        return Err(format!(
            "the access token lasts {expires_in_seconds} s; the review needs at least {} s",
            RUN_TIME_MIN.saturating_add(TOKEN_MARGIN).as_secs()
        ));
    }
    Ok(usable.min(RUN_TIME_MAX))
}

/// An Anthropic access token by workload identity federation when the federation rule is
/// set, else none: the CLI then uses the developer's own login.
fn anthropic_access(required_here: bool) -> Result<Option<AccessToken>, String> {
    let rule = env::var(anthropic_token::FEDERATION_RULE_VARIABLE).ok();
    if rule.as_deref().is_none_or(|rule| rule.trim().is_empty()) && !required_here {
        return Ok(None);
    }
    let federation = anthropic_token::read_federation(
        rule,
        env::var(anthropic_token::ORGANIZATION_VARIABLE).ok(),
        env::var(anthropic_token::SERVICE_ACCOUNT_VARIABLE).ok(),
        env::var(anthropic_token::WORKSPACE_VARIABLE).ok(),
    )?;
    let oidc = anthropic_token::read_oidc_request(
        env::var(anthropic_token::REQUEST_URL_VARIABLE).ok(),
        env::var(anthropic_token::REQUEST_TOKEN_VARIABLE).ok(),
    )?;
    anthropic_token::mint(&federation, &oidc).map(Some)
}

fn read_langfuse() -> Result<Option<langfuse::Langfuse>, String> {
    langfuse::read(
        env::var(langfuse::BASE_URL_VARIABLE).ok(),
        env::var(langfuse::PUBLIC_KEY_VARIABLE).ok(),
        env::var(langfuse::SECRET_KEY_VARIABLE).ok(),
    )
}

fn run_time(access_token: Option<&AccessToken>) -> Result<Duration, String> {
    access_token.map_or(Ok(RUN_TIME_MAX), |token| {
        run_time_for(token.expires_in_seconds)
    })
}

fn head_commit(dir: &Path) -> Result<String, String> {
    let captured = run_bounded(git_in(dir).args(["rev-parse", "HEAD"]), GIT_TIMEOUT);
    let commit = captured.stdout.trim();
    match captured.exit {
        Exit::Code(0) if pull_request::commit_sha(commit) => Ok(commit.to_string()),
        other => Err(format!(
            "git rev-parse HEAD in {} ended {other:?}",
            dir.display()
        )),
    }
}

fn uncommitted(dir: &Path) -> Result<usize, String> {
    let captured = run_bounded(git_in(dir).args(["status", "--porcelain"]), GIT_TIMEOUT);
    match captured.exit {
        Exit::Code(0) => Ok(captured
            .stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()),
        other => Err(format!("git status --porcelain ended {other:?}")),
    }
}

/// The commits a dry run reviews: `origin/main` against a clean `HEAD`, the branch the run
/// was started on.
fn dry_run_commits(root: &Path) -> Result<(String, String, String), String> {
    let changes = uncommitted(root)?;
    if changes > 0 {
        return Err(format!(
            "{changes} uncommitted changes: the model reads the working tree, so commit first"
        ));
    }
    let head = head_commit(root)?;
    let merge_base = run_bounded(
        git_in(root).args(["merge-base", DRY_RUN_BASE, "HEAD"]),
        GIT_TIMEOUT,
    );
    let base = merge_base.stdout.trim().to_string();
    if merge_base.exit != Exit::Code(0) || !pull_request::commit_sha(&base) {
        return Err(format!(
            "git merge-base {DRY_RUN_BASE} HEAD ended {:?}",
            merge_base.exit
        ));
    }
    let session = format!("dry-run:{}", super::short(&head));
    Ok((base, head, session))
}

fn dry_run_context() -> Result<Context, String> {
    let root = checkout::running_checkout()?;
    let (base, head, session) = dry_run_commits(&root)?;
    let langfuse = read_langfuse()?;
    let access_token = anthropic_access(false)?;
    Ok(Context {
        tag: "dry-run",
        checkout: root,
        base,
        head,
        claude: PathBuf::from("claude"),
        run_time: run_time(access_token.as_ref())?,
        access_token,
        github: None,
        session,
        fork: false,
        posted: Vec::new(),
        user: current_user(),
        langfuse,
        files: create_files()?,
    })
}

/// `mise which claude` printed one absolute path to a file.
fn decode_which(exit: &Exit, stdout: &str) -> Result<PathBuf, String> {
    let path = stdout.trim();
    match exit {
        Exit::Code(0)
            if path.starts_with('/')
                && path.len() <= PATH_MAX_BYTES
                && !path.contains('\n')
                && Path::new(path).is_file() =>
        {
            Ok(PathBuf::from(path))
        }
        Exit::Code(0) => Err(format!("mise which claude printed `{path}`")),
        other => Err(format!("mise which claude ended {other:?}")),
    }
}

/// The Claude binary the base checkout's `mise.toml` pins, by absolute path: a mise shim run
/// with its working directory in the pull request's checkout would take that checkout's pin.
fn resolve_claude(root: &Path) -> Result<PathBuf, String> {
    let captured = run_bounded(
        scrubbed(&mut Command::new("mise"))
            .args(["which", "claude"])
            .current_dir(root),
        MISE_TIMEOUT,
    );
    decode_which(&captured.exit, &captured.stdout)
}

/// What a posting run reads before it mints the App's token: none of it needs one.
#[derive(Debug)]
struct Request {
    repository: app_token::Repository,
    trigger: pull_request::Trigger,
    credentials: app_token::AppCredentials,
    langfuse: Option<langfuse::Langfuse>,
    claude: PathBuf,
}

fn read_request() -> Result<Request, String> {
    let root = checkout::running_checkout()?;
    Ok(Request {
        repository: app_token::read_repository(env::var("GITHUB_REPOSITORY").ok())?,
        trigger: read_trigger()?,
        credentials: app_token::read_credentials(
            &REVIEW,
            env::var(REVIEW.client_id_variable).ok(),
            env::var(REVIEW.app_id_variable).ok(),
            env::var(REVIEW.key_variable).ok(),
        )?,
        langfuse: read_langfuse()?,
        claude: resolve_claude(&root)?,
    })
}

/// With the App's token: the pull request, checked against the checkout, and what the App
/// posted on it before, within the cap.
fn read_pull_request(
    request: &Request,
    token: &str,
    bot: &str,
    checkout_dir: &Path,
) -> Result<(pull_request::PullRequest, pull_request::Earlier, PathBuf), String> {
    let client = Client::github();
    let full_name = request.repository.full_name();
    let pull_request = match &request.trigger {
        pull_request::Trigger::Ready(pull_request) => pull_request.clone(),
        pull_request::Trigger::Asked { number } => {
            pull_request::fetch(&client, token, &full_name, *number)?
        }
    };
    let checked_out = head_commit(checkout_dir)?;
    if checked_out != pull_request.head {
        return Err(format!(
            "{} is at {checked_out}, not the pull request's head {}; it moved since the run \
             started, so ask again",
            checkout_dir.display(),
            pull_request.head
        ));
    }
    let earlier = pull_request::earlier(&client, token, &full_name, pull_request.number, bot)?;
    if earlier.reviews >= REVIEWS_PER_PULL_REQUEST_MAX {
        return Err(format!(
            "the App has posted {} reviews on this pull request, the most one takes",
            earlier.reviews
        ));
    }
    Ok((pull_request, earlier, create_files()?))
}

fn post_context(checkout_dir: &Path) -> Result<Context, String> {
    let request = read_request()?;
    let access_token = anthropic_access(true)?;
    let run_time = run_time(access_token.as_ref())?;
    let bot = app_token::bot_login(&request.credentials)?;
    let token = app_token::mint(&request.credentials, &request.repository)?;
    let (pull_request, earlier, files) =
        match read_pull_request(&request, token.expose(), &bot, checkout_dir) {
            Ok(read) => read,
            Err(reason) => {
                return Err(match app_token::revoke(&token) {
                    Ok(()) => reason,
                    Err(revocation) => format!("{reason}; {revocation}"),
                })
            }
        };
    let full_name = request.repository.full_name();
    Ok(Context {
        tag: "post",
        checkout: checkout_dir.to_path_buf(),
        base: pull_request.base.clone(),
        head: pull_request.head.clone(),
        claude: request.claude,
        access_token,
        session: format!("{full_name}#{}", pull_request.number),
        fork: is_fork(&pull_request, &full_name),
        github: Some(GitHub {
            token,
            repository: full_name,
            pull_request,
        }),
        posted: earlier.posted,
        run_time,
        user: current_user(),
        langfuse: request.langfuse,
        files,
    })
}

/// A pull request whose head lives in another repository; the App never approves one.
fn is_fork(pull_request: &pull_request::PullRequest, repository: &str) -> bool {
    pull_request.head_repository != repository
}

/// A new 0700 directory under the runner's temporary directory, or the system's outside
/// Actions; one left by an earlier run with the same pid is an error, not reused.
fn create_files() -> Result<PathBuf, String> {
    let base = env::var_os("RUNNER_TEMP")
        .filter(|value| !value.is_empty())
        .map_or_else(env::temp_dir, PathBuf::from);
    let dir = base.join(format!("tycho-review-{}", std::process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
    Ok(dir)
}

/// Removes the files this run wrote and their directory; a failure is reported, not fatal.
pub fn remove_files(dir: &Path) {
    let removed = fs::read_dir(dir).and_then(|entries| {
        for entry in entries.take(FILES_MAX) {
            fs::remove_file(entry?.path())?;
        }
        fs::remove_dir(dir)
    });
    if let Err(error) = removed {
        eprintln!("xtask review: cannot remove {}: {error}", dir.display());
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::review::pull_request::PullRequest;

    /// A posting context for a pull request of `o/r`, with the given earlier findings and an
    /// installation token value.
    pub fn context(posted: Vec<pull_request::Posted>, token: &str) -> Context {
        Context {
            tag: "post",
            checkout: PathBuf::from("/r/pull-request"),
            base: "b".repeat(40),
            head: "a".repeat(40),
            claude: PathBuf::from("/opt/claude"),
            access_token: None,
            github: Some(GitHub {
                token: app_token::InstallationToken::for_tests(token),
                repository: "o/r".to_string(),
                pull_request: PullRequest {
                    number: 1,
                    base: "b".repeat(40),
                    head: "a".repeat(40),
                    head_repository: "o/r".to_string(),
                },
            }),
            session: "o/r#1".to_string(),
            fork: false,
            posted,
            run_time: RUN_TIME_MAX,
            user: None,
            langfuse: None,
            files: PathBuf::from("/t/tycho-review-1"),
        }
    }

    #[test]
    fn no_git_or_mise_child_sees_a_secret_of_the_run() {
        let git = git_in(Path::new("/r"));
        let mut mise = Command::new("mise");
        scrubbed(&mut mise);
        for command in [&git, &mise] {
            let removed: Vec<&std::ffi::OsStr> = command
                .get_envs()
                .filter(|(_, value)| value.is_none())
                .map(|(name, _)| name)
                .collect();
            for name in crate::review::SECRET_VARIABLES {
                assert!(removed.contains(&std::ffi::OsStr::new(name)), "{name}");
            }
        }
        for name in [
            "FRITS_CODE_REVIEW_APP_PRIVATE_KEY",
            "LANGFUSE_SECRET_KEY",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        ] {
            assert!(crate::review::SECRET_VARIABLES.contains(&name), "{name}");
        }
    }

    #[test]
    fn a_head_in_another_repository_is_a_fork() {
        let mut pull_request = PullRequest {
            number: 1,
            base: "b".repeat(40),
            head: "a".repeat(40),
            head_repository: "o/r".to_string(),
        };
        assert!(!is_fork(&pull_request, "o/r"));
        pull_request.head_repository = "someone/r".to_string();
        assert!(is_fork(&pull_request, "o/r"));
    }

    #[test]
    fn the_run_time_stays_inside_the_token_lifetime_and_the_cap() {
        assert_eq!(run_time_for(3600), Ok(RUN_TIME_MAX));
        assert_eq!(
            run_time_for(900),
            Ok(Duration::from_secs(900).saturating_sub(TOKEN_MARGIN))
        );
        assert!(run_time_for(600).unwrap_err().contains("at least 720 s"));
    }

    #[test]
    fn only_an_absolute_path_to_a_file_is_the_claude_binary() {
        let file = env::current_exe().unwrap();
        let printed = format!("{}\n", file.display());
        assert_eq!(decode_which(&Exit::Code(0), &printed), Ok(file));
        assert!(decode_which(&Exit::Code(0), "claude\n").is_err());
        assert!(decode_which(&Exit::Code(0), "/no/such/claude\n").is_err());
        assert!(decode_which(&Exit::Code(1), "").is_err());
    }

    #[test]
    fn a_files_directory_is_private_and_removed_with_its_files() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = create_files().unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        fs::write(dir.join("diff.patch"), "x").unwrap();
        assert!(create_files().is_err());
        remove_files(&dir);
        assert!(!dir.exists());
    }
}

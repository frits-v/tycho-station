//! `xtask review`: a code review of a pull request by the Claude CLI, with a verdict.
//!
//! A find pass reports candidate findings against the diff; each candidate then gets a verify
//! pass in a fresh session that tries to refute it. A rule over the confirmed findings decides
//! the verdict; the other checks on the head commit are waited for and reported, never weighed.
//! `--post` runs from the base branch's checkout, reviews a pull request checked out beside it
//! as data, and posts the verdict as the review App; `--dry-run` reviews the checkout it runs
//! in and posts nothing. The model reads only inside the reviewed checkout and the run's own
//! directory, and never holds a GitHub credential. Each run is traced to Langfuse when it is
//! configured.

mod checks;
mod claude_run;
mod diff;
mod findings;
mod langfuse;
mod passes;
mod pull_request;
mod report;
mod setup;
mod verdict;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use crate::anthropic_token::AccessToken;
use crate::app_token::{self, InstallationToken};
use langfuse::{Generation, Langfuse, Trace};
use pull_request::{Posted, PullRequest};
use verdict::Event;

/// Generated or derived files: a review of them restates their sources.
const EXCLUDED_PATHSPECS: [&str; 3] = [
    ":(exclude)Cargo.lock",
    ":(exclude)config/export",
    ":(exclude)docs/figures",
];
const VERIFIED_MAX: usize = 12;
/// How long after the review starts the other checks are waited for; the App's token lasts
/// an hour from the start.
const CHECKS_WAIT: Duration = Duration::from_secs(45 * 60);
const SHORT_COMMIT_CHARS: usize = 12;
/// What a review run holds that no child it starts may see: the App key, the Langfuse secret
/// key, the Actions OIDC request and runtime tokens and a job token. The Claude CLI gets an
/// allowlist instead.
const SECRET_VARIABLES: [&str; 6] = [
    app_token::REVIEW.key_variable,
    langfuse::SECRET_KEY_VARIABLE,
    crate::anthropic_token::REQUEST_TOKEN_VARIABLE,
    crate::anthropic_token::REQUEST_URL_VARIABLE,
    "ACTIONS_RUNTIME_TOKEN",
    "GITHUB_TOKEN",
];

/// `command` without the run's secrets in its environment.
fn scrubbed(command: &mut Command) -> &mut Command {
    for name in SECRET_VARIABLES {
        command.env_remove(name);
    }
    command
}

/// git in `dir`, without the hook environment or the run's secrets.
fn git_in(dir: &Path) -> Command {
    let mut command = tycho_types::git_environment::git_command();
    scrubbed(command.arg("-C").arg(dir));
    command
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    DryRun,
    /// The pull request's head, checked out at this path, is reviewed and never run.
    Post {
        checkout: PathBuf,
    },
}

/// Where a posting run reads and writes on GitHub, as the review App.
#[derive(Debug)]
struct GitHub {
    token: InstallationToken,
    repository: String,
    pull_request: PullRequest,
}

#[derive(Debug)]
struct Context {
    tag: &'static str,
    /// The tree the model reads and the diff is taken in.
    checkout: PathBuf,
    base: String,
    head: String,
    claude: PathBuf,
    access_token: Option<AccessToken>,
    github: Option<GitHub>,
    /// `owner/name#number` in Actions; Langfuse groups a pull request's runs by it.
    session: String,
    fork: bool,
    posted: Vec<Posted>,
    run_time: Duration,
    user: Option<String>,
    langfuse: Option<Langfuse>,
    /// A directory private to this run, outside the checkout: the CLI refuses reads of
    /// gitignored paths under `dontAsk`, so `target/` cannot hold what the model reads.
    files: PathBuf,
}

#[derive(Debug, Default)]
struct Tally {
    files: usize,
    hunks: usize,
    candidates: usize,
    confirmed: usize,
    refuted: usize,
    unverified: usize,
    unjudged_blocking: usize,
    still_holding: usize,
    withheld: usize,
    inline: usize,
    outside: usize,
    failed: Vec<String>,
    cost: u64,
    generations: Vec<Generation>,
}

/// `xtask review --dry-run` or `xtask review --post <pull request checkout>`.
pub fn command(arguments: &[String]) -> i32 {
    let mode = match arguments {
        [flag] if flag == "--dry-run" => Mode::DryRun,
        [flag, checkout] if flag == "--post" => Mode::Post {
            checkout: PathBuf::from(checkout),
        },
        _ => {
            eprintln!("usage: xtask review --dry-run | --post <pull request checkout>");
            return 2;
        }
    };
    let context = match setup::context(&mode) {
        Ok(context) => context,
        Err(reason) => {
            eprintln!("xtask review: {reason}");
            return 1;
        }
    };
    let started = SystemTime::now();
    let mut tally = Tally::default();
    let reviewed = review(&context, &mut tally);
    setup::remove_files(&context.files);
    finish(&context, started, &tally, &reviewed)
}

fn review(context: &Context, tally: &mut Tally) -> Result<(Event, String), String> {
    let started = Instant::now();
    let deadline = started
        .checked_add(context.run_time)
        .ok_or("the run deadline overflows")?;
    let map = diff::parse_diff(&passes::prepare(context)?)?;
    if map.commentable.is_empty() {
        return Err(format!(
            "the diff {}...{} has no file with head-side lines to review once {} are excluded",
            short(&context.base),
            short(&context.head),
            EXCLUDED_PATHSPECS.join(", ")
        ));
    }
    tally.files = map.files;
    tally.hunks = map.hunks;
    let candidates = passes::find(context, deadline, tally)?;
    let confirmed = passes::verify(context, &candidates, deadline, tally);
    let checks = context
        .github
        .as_ref()
        .map_or_else(checks::Seen::default, |github| {
            checks::wait(
                &crate::github_api::Client::github(),
                github.token.expose(),
                &github.repository,
                &context.head,
                started.checked_add(CHECKS_WAIT).unwrap_or(started),
            )
        });
    let (event, reason) = verdict::decide(&verdict::Evidence {
        confirmed: &confirmed,
        unjudged_blocking: tally.unjudged_blocking,
        fork: context.fork,
    });
    report::publish(context, &map, &confirmed, &checks, (event, &reason), tally)?;
    Ok((event, reason))
}

fn short(commit: &str) -> &str {
    commit.get(..SHORT_COMMIT_CHARS).unwrap_or(commit)
}

fn trace(
    context: &Context,
    started: SystemTime,
    tally: &Tally,
    reviewed: &Result<(Event, String), String>,
) -> Trace {
    let output = match reviewed {
        Ok((event, reason)) => format!("{}: {reason}", event.label()),
        Err(reason) => format!("no verdict: {reason}"),
    };
    let verdict = reviewed.as_ref().map_or("none", |(event, _)| event.label());
    Trace {
        name: "code-review".to_string(),
        session: context.session.clone(),
        tags: vec![context.tag.to_string()],
        started,
        ended: SystemTime::now(),
        input: format!("{}...{}", context.base, context.head),
        output,
        metadata: vec![
            ("verdict".to_string(), verdict.to_string()),
            ("head".to_string(), context.head.clone()),
            ("counts".to_string(), report::counts(tally)),
        ],
        generations: tally.generations.clone(),
    }
}

/// Exports the trace and revokes the App's token; any failure on the way is the exit code.
fn finish(
    context: &Context,
    started: SystemTime,
    tally: &Tally,
    reviewed: &Result<(Event, String), String>,
) -> i32 {
    if let Err(reason) = reviewed {
        eprintln!("xtask review: {reason}");
    }
    for failure in &tally.failed {
        eprintln!("xtask review: a verify pass gave no verdict: {failure}");
    }
    let traced = context.langfuse.as_ref().map_or_else(
        || {
            println!("xtask review: Langfuse is not configured; no trace sent");
            true
        },
        |langfuse| {
            langfuse::export(langfuse, &trace(context, started, tally, reviewed))
                .map_err(|reason| eprintln!("xtask review: {reason}"))
                .is_ok()
        },
    );
    let revoked = context.github.as_ref().is_none_or(|github| {
        app_token::revoke(&github.token)
            .map_err(|reason| eprintln!("xtask review: {reason}"))
            .is_ok()
    });
    i32::from(reviewed.is_err() || !tally.failed.is_empty() || !traced || !revoked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_arguments_choose_the_mode_and_anything_else_is_a_usage_error() {
        assert_eq!(command(&[]), 2);
        assert_eq!(command(&["--post".to_string()]), 2);
        assert_eq!(command(&["--dry-run".to_string(), "x".to_string()]), 2);
    }

    fn step_running(workflow: &str, needle: &str) -> Option<String> {
        let lines: Vec<&str> = workflow.lines().collect();
        let at = lines.iter().position(|line| line.contains(needle))?;
        lines
            .get(..at)?
            .iter()
            .rev()
            .find(|line| line.contains("run:"))
            .map(|line| line.trim().to_string())
    }

    #[test]
    fn the_trusted_review_starts_only_on_ready_or_a_comment_and_runs_the_base_xtask() {
        let workflow = include_str!("../../.github/workflows/review.yml");
        let triggers: Vec<&str> = workflow
            .lines()
            .skip_while(|line| !line.starts_with("on:"))
            .skip(1)
            .take_while(|line| line.starts_with(' ') || line.starts_with('#'))
            .filter(|line| line.starts_with("  ") && !line.starts_with("    "))
            .map(str::trim)
            .collect();
        assert_eq!(
            triggers,
            [
                "# The workflow and the xtask come from the base branch; the pull request's head is checked",
                "# out as data the model reads and is never built or run.",
                "pull_request_target: # zizmor: ignore[dangerous-triggers]",
                "issue_comment:",
            ]
        );
        assert!(workflow.contains("    types: [ready_for_review]\n"));
        assert!(workflow.contains("    types: [created]\n"));
        assert_eq!(
            step_running(workflow, "secrets.FRITS_CODE_REVIEW_APP_PRIVATE_KEY").as_deref(),
            Some("- run: target/debug/xtask review --post pull-request")
        );
        assert_eq!(
            workflow
                .matches("secrets.FRITS_CODE_REVIEW_APP_PRIVATE_KEY")
                .count(),
            1
        );
        let build = workflow
            .find("- run: cargo build --locked -p xtask")
            .unwrap();
        let review = workflow
            .find("- run: target/debug/xtask review --post")
            .unwrap();
        assert!(build < review);
        assert!(workflow.contains("          path: pull-request\n"));
        assert_eq!(workflow.matches("persist-credentials: false").count(), 2);
        assert!(!workflow.contains("working-directory"));
        assert_eq!(workflow.matches("- run:").count(), 2);
        assert!(workflow.contains("    environment: review\n"));
    }

    #[test]
    fn the_dry_run_is_started_by_hand_and_never_holds_the_app_key() {
        let workflow = include_str!("../../.github/workflows/review-dry-run.yml");
        assert!(workflow.contains("on:\n  workflow_dispatch:\n"));
        assert!(!workflow.contains("pull_request"));
        assert!(!workflow.contains("FRITS_CODE_REVIEW"));
        assert!(!workflow.contains("pull-requests: write"));
        assert!(workflow.contains("- run: target/debug/xtask review --dry-run"));
        assert!(workflow.contains("    environment: review-dry-run\n"));
    }

    #[test]
    fn the_trace_names_the_verdict_or_why_there_is_none() {
        let context = setup::tests::context(Vec::new(), "t");
        let tally = Tally::default();
        let started = SystemTime::now();
        let approved = trace(
            &context,
            started,
            &tally,
            &Ok((
                Event::Approve,
                "no confirmed high or medium findings".to_string(),
            )),
        );
        assert_eq!(approved.session, "o/r#1");
        assert_eq!(approved.tags, ["post"]);
        assert!(approved.output.starts_with("approve: "));
        let failed = trace(
            &context,
            started,
            &tally,
            &Err("the find pass ended".into()),
        );
        assert!(failed.output.starts_with("no verdict: "));
        assert!(failed
            .metadata
            .contains(&("verdict".to_string(), "none".to_string())));
    }
}

//! `xtask review`: a code review of a pull request by the Claude CLI, posted as one review.
//!
//! A find pass reports candidate findings against the diff; each candidate then gets a verify
//! pass in a fresh session that tries to refute it. The xtask anchors what survives to lines
//! the diff shows, drops what earlier runs posted, and posts one `COMMENT` review. The model
//! reads only inside the checkout and never holds a GitHub credential.

mod claude_run;
mod diff;
mod findings;
mod pull_request;

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tycho_types::git_environment::git_command;

use crate::anthropic_token::{self, AccessToken};
use crate::app_token;
use crate::checkout;
use crate::github_api::Client;
use crate::process::{run_bounded, Exit};
use claude_run::{Limits, RunOutcome};
use diff::DiffMap;
use findings::{Finding, Verdict};
use pull_request::{PostOutcome, Posted, PullRequest};

const REVIEW_DIR: &str = "target/review";
const FIND_SCHEMA: &str = include_str!("../../config/export/schema/review_findings.json");
const VERDICT_SCHEMA: &str = include_str!("../../config/export/schema/review_verdict.json");
const FIND_INSTRUCTIONS: &str = include_str!("../prompts/review-find.md");
const VERIFY_INSTRUCTIONS: &str = include_str!("../prompts/review-verify.md");
/// Generated or derived files: a review of them restates their sources.
const EXCLUDED_PATHSPECS: [&str; 3] = [
    ":(exclude)Cargo.lock",
    ":(exclude)config/export",
    ":(exclude)docs/figures",
];
const DIFF_MAX_BYTES: usize = 512 * 1024;
const EVENT_MAX_BYTES: u64 = 1 << 20;
const GIT_TIMEOUT: Duration = Duration::from_secs(120);
const FIND_LIMITS: Limits = Limits {
    max_turns: 80,
    max_budget_usd: 10,
};
const VERIFY_LIMITS: Limits = Limits {
    max_turns: 30,
    max_budget_usd: 2,
};
const VERIFIED_MAX: usize = 12;
const VERIFY_PARALLEL: usize = 4;
const RUN_TIME_MAX: Duration = Duration::from_secs(30 * 60);
/// Left unused at the end of the access token's life, so no run starts on a token about to lapse.
const TOKEN_MARGIN: Duration = Duration::from_secs(120);
const RUN_TIME_MIN: Duration = Duration::from_secs(10 * 60);
const ONE_RUN_MIN: Duration = Duration::from_secs(60);
const DRY_RUN_BASE: &str = "origin/main";
const SHORT_COMMIT_CHARS: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Post,
    DryRun,
}

/// Where a posting run sends its review.
#[derive(Debug)]
struct Destination {
    token: String,
    repository: String,
    pull_request: PullRequest,
}

#[derive(Debug)]
struct Context {
    root: PathBuf,
    base: String,
    head: String,
    access_token: Option<AccessToken>,
    destination: Option<Destination>,
    posted: Vec<Posted>,
    run_time: Duration,
    user: Option<String>,
}

#[derive(Debug, Default)]
struct Tally {
    files: usize,
    hunks: usize,
    candidates: usize,
    verified: usize,
    confirmed: usize,
    refuted: usize,
    unverified: usize,
    already_posted: usize,
    withheld: usize,
    inline: usize,
    outside: usize,
    failed: Vec<String>,
    cost: u64,
}

/// `xtask review [--dry-run]`.
pub fn command(argument: Option<&str>) -> i32 {
    match argument {
        None => review(Mode::Post),
        Some("--dry-run") => review(Mode::DryRun),
        Some(other) => {
            eprintln!("usage: xtask review [--dry-run]; got {other}");
            2
        }
    }
}

fn review(mode: Mode) -> i32 {
    match run(mode) {
        Ok(code) => code,
        Err(reason) => {
            eprintln!("xtask review: {reason}");
            1
        }
    }
}

fn run(mode: Mode) -> Result<i32, String> {
    let root = checkout::running_checkout()?;
    let context = match mode {
        Mode::Post => post_context(root)?,
        Mode::DryRun => dry_run_context(root)?,
    };
    let started = Instant::now();
    let deadline = started
        .checked_add(context.run_time)
        .ok_or("the run deadline overflows")?;
    let map = diff::parse_diff(&prepare(&context)?)?;
    if map.commentable.is_empty() {
        return Err(format!(
            "the diff {}...{} has no file with head-side lines to review once {} are excluded",
            short(&context.base),
            short(&context.head),
            EXCLUDED_PATHSPECS.join(", ")
        ));
    }
    let mut tally = Tally {
        files: map.files,
        hunks: map.hunks,
        ..Tally::default()
    };
    let candidates = find(&context, deadline, &mut tally)?;
    let confirmed = verify(&context, candidates, deadline, &mut tally);
    publish(&context, &map, confirmed, &mut tally)
}

fn required(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is unset; the review job sets it"))
}

fn read_event() -> Result<PullRequest, String> {
    let path = required("GITHUB_EVENT_PATH")?;
    let size = fs::metadata(&path)
        .map_err(|error| format!("cannot read the event file: {error}"))?
        .len();
    if size > EVENT_MAX_BYTES {
        return Err(format!("the event file is over {EVENT_MAX_BYTES} bytes"));
    }
    let text = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read the event file: {error}"))?;
    pull_request::decode_event(&text)
}

fn current_user() -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .ok()
        .flatten()
        .map(|user| user.name)
}

/// The run time the access token leaves, after the margin, capped at [`RUN_TIME_MAX`].
fn run_time_for(expires_in_seconds: u64) -> Result<Duration, String> {
    let usable = Duration::from_secs(expires_in_seconds).saturating_sub(TOKEN_MARGIN);
    if usable < RUN_TIME_MIN {
        return Err(format!(
            "the access token lasts {expires_in_seconds} s; the review needs at least {} s",
            RUN_TIME_MIN.saturating_add(TOKEN_MARGIN).as_secs()
        ));
    }
    Ok(usable.min(RUN_TIME_MAX))
}

fn post_context(root: PathBuf) -> Result<Context, String> {
    let repository = app_token::read_repository(env::var("GITHUB_REPOSITORY").ok())?.full_name();
    let event = read_event()?;
    if event.head_repository != repository {
        return Err(format!(
            "the pull request's head is in {}, not {repository}; a fork is not reviewed",
            event.head_repository
        ));
    }
    let checked_out = checkout::head_commit(&root)?;
    if checked_out != event.head {
        return Err(format!(
            "the checkout is at {checked_out}, not the pull request's head {}",
            event.head
        ));
    }
    let federation = anthropic_token::read_federation(
        env::var(anthropic_token::FEDERATION_RULE_VARIABLE).ok(),
        env::var(anthropic_token::ORGANIZATION_VARIABLE).ok(),
        env::var(anthropic_token::SERVICE_ACCOUNT_VARIABLE).ok(),
        env::var(anthropic_token::WORKSPACE_VARIABLE).ok(),
    )?;
    let oidc = anthropic_token::read_oidc_request(
        env::var(anthropic_token::REQUEST_URL_VARIABLE).ok(),
        env::var(anthropic_token::REQUEST_TOKEN_VARIABLE).ok(),
    )?;
    let token = required("GITHUB_TOKEN")?;
    let posted =
        pull_request::posted_findings(&Client::github(), &token, &repository, event.number)?;
    let access_token = anthropic_token::mint(&federation, &oidc)?;
    Ok(Context {
        root,
        base: event.base.clone(),
        head: event.head.clone(),
        run_time: run_time_for(access_token.expires_in_seconds)?,
        access_token: Some(access_token),
        destination: Some(Destination {
            token,
            repository,
            pull_request: event,
        }),
        posted,
        user: current_user(),
    })
}

fn dry_run_context(root: PathBuf) -> Result<Context, String> {
    let changes = checkout::uncommitted(&root)?;
    if changes > 0 {
        return Err(format!(
            "{changes} uncommitted changes: the model reads the working tree, so commit first"
        ));
    }
    let head = checkout::head_commit(&root)?;
    let merge_base = run_bounded(
        git_command()
            .arg("-C")
            .arg(&root)
            .args(["merge-base", DRY_RUN_BASE, "HEAD"]),
        GIT_TIMEOUT,
    );
    let base = merge_base.stdout.trim().to_string();
    if merge_base.exit != Exit::Code(0) || !pull_request::commit_sha(&base) {
        return Err(format!(
            "git merge-base {DRY_RUN_BASE} HEAD ended {:?}",
            merge_base.exit
        ));
    }
    Ok(Context {
        root,
        base,
        head,
        access_token: None,
        destination: None,
        posted: Vec::new(),
        run_time: RUN_TIME_MAX,
        user: current_user(),
    })
}

fn short(commit: &str) -> &str {
    commit.get(..SHORT_COMMIT_CHARS).unwrap_or(commit)
}

fn review_dir(context: &Context) -> PathBuf {
    context.root.join(REVIEW_DIR)
}

fn write_file(path: &Path, text: &str) -> Result<(), String> {
    fs::write(path, text).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// The diff, written where the model can read it with the earlier findings beside it.
fn prepare(context: &Context) -> Result<String, String> {
    let range = format!("{}...{}", context.base, context.head);
    let captured = run_bounded(
        git_command()
            .arg("-C")
            .arg(&context.root)
            .args(["-c", "core.quotePath=false", "diff", "--no-color"])
            .args(["--no-ext-diff", "--no-textconv", "-M", "--unified=3"])
            .args([range.as_str(), "--", "."])
            .args(EXCLUDED_PATHSPECS),
        GIT_TIMEOUT,
    );
    if captured.exit != Exit::Code(0) {
        return Err(format!("git diff {range} ended {:?}", captured.exit));
    }
    if captured.stdout.len() > DIFF_MAX_BYTES {
        return Err(format!(
            "the diff is {} bytes; the review takes at most {DIFF_MAX_BYTES}",
            captured.stdout.len()
        ));
    }
    let dir = review_dir(context);
    match fs::create_dir(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("cannot create {}: {error}", dir.display())),
    }
    write_file(&dir.join("diff.patch"), &captured.stdout)?;
    write_file(&dir.join("posted.json"), &posted_listing(&context.posted))?;
    Ok(captured.stdout)
}

fn posted_listing(posted: &[Posted]) -> String {
    let entries: Vec<Value> = posted
        .iter()
        .map(|entry| Value::from(entry.excerpt.as_str()))
        .collect();
    Value::Array(entries).to_string()
}

fn render(template: &str, context: &Context, finding: Option<&Finding>) -> String {
    let finding = finding
        .and_then(|finding| serde_json::to_string_pretty(finding).ok())
        .unwrap_or_default();
    template
        .replace("{{head}}", &context.head)
        .replace("{{base}}", &context.base)
        .replace("{{diff}}", &format!("{REVIEW_DIR}/diff.patch"))
        .replace("{{posted}}", &format!("{REVIEW_DIR}/posted.json"))
        .replace("{{finding}}", &finding)
}

fn minified(schema: &str) -> Result<String, String> {
    serde_json::from_str::<Value>(schema)
        .map(|value| value.to_string())
        .map_err(|_| "an exported review schema is not JSON; run `mise run config-export`".into())
}

fn run_claude(
    context: &Context,
    instructions: &Path,
    schema: &str,
    limits: Limits,
    deadline: Instant,
) -> RunOutcome {
    let Some(remaining) = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| *remaining >= ONE_RUN_MIN)
    else {
        return RunOutcome::Ended(Exit::TimedOut);
    };
    let environment = claude_run::environment(
        env::vars_os(),
        context.user.as_deref(),
        context
            .access_token
            .as_ref()
            .map(|token| token.value.expose()),
    );
    let mut command = claude_run::command(instructions, schema, limits, environment);
    command.current_dir(&context.root);
    let captured = run_bounded(&mut command, remaining);
    claude_run::decode(captured.exit, &captured.stdout)
}

fn find(context: &Context, deadline: Instant, tally: &mut Tally) -> Result<Vec<Finding>, String> {
    let instructions = review_dir(context).join("find.md");
    write_file(&instructions, &render(FIND_INSTRUCTIONS, context, None))?;
    let outcome = run_claude(
        context,
        &instructions,
        &minified(FIND_SCHEMA)?,
        FIND_LIMITS,
        deadline,
    );
    tally.cost = tally.cost.saturating_add(outcome.cost());
    match outcome {
        RunOutcome::Answered { output, .. } => {
            let candidates = findings::decode_findings(&output)?;
            tally.candidates = candidates.len();
            Ok(candidates)
        }
        other => Err(format!("the find pass ended {other:?}")),
    }
}

/// One verify pass; `Ok` carries the verdict, `Err` why the pass gave none.
fn verify_one(
    context: &Context,
    index: usize,
    finding: &Finding,
    schema: &str,
    deadline: Instant,
) -> (Result<Verdict, String>, u64) {
    let instructions = review_dir(context).join(format!("verify-{index}.md"));
    if let Err(reason) = write_file(
        &instructions,
        &render(VERIFY_INSTRUCTIONS, context, Some(finding)),
    ) {
        return (Err(reason), 0);
    }
    let outcome = run_claude(context, &instructions, schema, VERIFY_LIMITS, deadline);
    let cost = outcome.cost();
    let verdict = match outcome {
        RunOutcome::Answered { output, .. } => {
            findings::decode_verdict(&output).map(|(verdict, reasoning)| {
                println!(
                    "xtask review: {}:{} {verdict:?}: {reasoning}",
                    finding.path, finding.line
                );
                verdict
            })
        }
        other => Err(format!("{other:?}")),
    };
    (verdict, cost)
}

/// Verifies the most severe candidates, a few sessions at a time, and keeps the confirmed.
fn verify(
    context: &Context,
    candidates: Vec<Finding>,
    deadline: Instant,
    tally: &mut Tally,
) -> Vec<Finding> {
    let schema = match minified(VERDICT_SCHEMA) {
        Ok(schema) => schema,
        Err(reason) => {
            tally.failed.push(reason);
            return Vec::new();
        }
    };
    tally.unverified = candidates.len().saturating_sub(VERIFIED_MAX);
    let checked: Vec<Finding> = candidates.into_iter().take(VERIFIED_MAX).collect();
    let mut confirmed = Vec::new();
    for (batch, chunk) in checked.chunks(VERIFY_PARALLEL).enumerate() {
        #[allow(
            clippy::needless_collect,
            reason = "every pass in the chunk starts before the first is joined"
        )]
        let results: Vec<(Result<Verdict, String>, u64)> = thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .enumerate()
                .map(|(offset, finding)| {
                    let index = batch.saturating_mul(VERIFY_PARALLEL).saturating_add(offset);
                    let schema = schema.as_str();
                    scope.spawn(move || verify_one(context, index, finding, schema, deadline))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| (Err("the verify thread panicked".into()), 0))
                })
                .collect()
        });
        for (finding, (verdict, cost)) in chunk.iter().zip(results) {
            tally.cost = tally.cost.saturating_add(cost);
            match verdict {
                Ok(Verdict::Confirmed) => confirmed.push(finding.clone()),
                Ok(Verdict::Refuted) => tally.refuted = tally.refuted.saturating_add(1),
                Err(reason) => tally
                    .failed
                    .push(format!("{}:{}: {reason}", finding.path, finding.line)),
            }
        }
    }
    tally.verified = checked.len().saturating_sub(tally.failed.len());
    tally.confirmed = confirmed.len();
    confirmed
}

/// The confirmed findings that are new and safe to post, split by whether the diff shows
/// their line.
fn select(
    context: &Context,
    map: &DiffMap,
    confirmed: Vec<Finding>,
    tally: &mut Tally,
) -> Result<(Vec<Finding>, Vec<Finding>), String> {
    let secrets: Vec<&str> = [
        context
            .access_token
            .as_ref()
            .map(|token| token.value.expose()),
        context
            .destination
            .as_ref()
            .map(|destination| destination.token.as_str()),
    ]
    .into_iter()
    .flatten()
    .collect();
    let posted: BTreeSet<&str> = context
        .posted
        .iter()
        .map(|entry| entry.fingerprint.as_str())
        .collect();
    let mut inline = Vec::new();
    let mut outside = Vec::new();
    for finding in confirmed {
        if findings::names_secret(&finding, &secrets) {
            return Err(
                "a confirmed finding holds the run's own credential; nothing is posted".into(),
            );
        }
        if findings::carries_credential_prefix(&finding) {
            tally.withheld = tally.withheld.saturating_add(1);
        } else if posted.contains(findings::fingerprint(&finding).as_str()) {
            tally.already_posted = tally.already_posted.saturating_add(1);
        } else if map.anchors(&finding.path, finding.line) {
            inline.push(finding);
        } else {
            outside.push(finding);
        }
    }
    tally.inline = inline.len();
    tally.outside = outside.len();
    Ok((inline, outside))
}

fn counts(tally: &Tally) -> String {
    format!(
        "examined {} files and {} hunks; {} candidates, {} verified, {} confirmed, {} refuted, \
         {} not verified (over the cap of {VERIFIED_MAX}), {} already posted, {} withheld; \
         {} inline, {} outside the diff; cost ${}.{:02}",
        tally.files,
        tally.hunks,
        tally.candidates,
        tally.verified,
        tally.confirmed,
        tally.refuted,
        tally.unverified,
        tally.already_posted,
        tally.withheld,
        tally.inline,
        tally.outside,
        tally.cost / 1_000_000,
        (tally.cost % 1_000_000) / 10_000
    )
}

fn review_body(context: &Context, outside: &[Finding], tally: &Tally) -> String {
    let mut body = format!(
        "Claude review (`{}`) of {}: {} new findings, {} inline below.\n",
        claude_run::MODEL,
        short(&context.head),
        tally.inline.saturating_add(tally.outside),
        tally.inline
    );
    if !outside.is_empty() {
        body.push_str("\nOn lines the diff does not show:\n\n");
        for finding in outside {
            body.push_str(&findings::outside_entry(finding));
            body.push('\n');
        }
    }
    body.push_str("\nThe review ");
    body.push_str(&counts(tally));
    body.push_str(".\n");
    body
}

fn write_step_summary(text: &str) {
    let Ok(path) = env::var("GITHUB_STEP_SUMMARY") else {
        return;
    };
    let written = fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .and_then(|mut file| writeln!(file, "{text}"));
    if let Err(error) = written {
        eprintln!("xtask review: cannot write the step summary: {error}");
    }
}

fn post(
    context: &Context,
    inline: &[Finding],
    outside: &[Finding],
    tally: &Tally,
) -> Result<(), String> {
    let Some(destination) = &context.destination else {
        for finding in inline.iter().chain(outside) {
            println!(
                "\n{}:{}\n{}",
                finding.path,
                finding.line,
                findings::inline_body(finding)
            );
        }
        return Ok(());
    };
    if inline.is_empty() && outside.is_empty() {
        println!("xtask review: no new findings; nothing posted");
        return Ok(());
    }
    let comments: Vec<(String, u32, String)> = inline
        .iter()
        .map(|finding| {
            (
                finding.path.clone(),
                finding.line,
                findings::inline_body(finding),
            )
        })
        .collect();
    match pull_request::post_review(
        &Client::github(),
        &destination.token,
        &destination.repository,
        &destination.pull_request,
        &review_body(context, outside, tally),
        &comments,
    ) {
        PostOutcome::Posted { url } => {
            println!("xtask review: posted {url}");
            Ok(())
        }
        other => Err(format!("posting the review ended {other:?}")),
    }
}

fn publish(
    context: &Context,
    map: &DiffMap,
    confirmed: Vec<Finding>,
    tally: &mut Tally,
) -> Result<i32, String> {
    let (inline, outside) = select(context, map, confirmed, tally)?;
    post(context, &inline, &outside, tally)?;
    let summary = format!("xtask review: {}", counts(tally));
    println!("{summary}");
    write_step_summary(&summary);
    if tally.failed.is_empty() {
        return Ok(0);
    }
    for failure in &tally.failed {
        eprintln!("xtask review: a verify pass gave no verdict: {failure}");
    }
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn the_exported_schemas_are_json_and_the_prompts_name_every_placeholder() {
        assert!(minified(FIND_SCHEMA).is_ok());
        assert!(minified(VERDICT_SCHEMA).is_ok());
        for placeholder in ["{{head}}", "{{base}}", "{{diff}}", "{{posted}}"] {
            assert!(FIND_INSTRUCTIONS.contains(placeholder), "{placeholder}");
        }
        for placeholder in ["{{head}}", "{{base}}", "{{diff}}", "{{finding}}"] {
            assert!(VERIFY_INSTRUCTIONS.contains(placeholder), "{placeholder}");
        }
    }

    #[test]
    fn the_step_holding_the_tokens_runs_a_built_binary_not_a_build() {
        let workflow = include_str!("../../.github/workflows/review.yml");
        let lines: Vec<&str> = workflow.lines().collect();
        let token_line = lines
            .iter()
            .position(|line| line.contains("${{ github.token }}"))
            .unwrap();
        let step_run = lines
            .get(..token_line)
            .and_then(|before| before.iter().rev().find(|line| line.contains("run:")))
            .map(|line| line.trim());
        assert_eq!(step_run, Some("- run: target/debug/xtask review"));
        assert_eq!(workflow.matches("${{ github.token }}").count(), 1);
        let build = workflow
            .find("- run: cargo build --locked -p xtask")
            .unwrap();
        let review = workflow.find("- run: target/debug/xtask review").unwrap();
        assert!(build < review);
        assert!(workflow.contains("ref: ${{ github.event.pull_request.head.sha }}"));
        assert!(!workflow.contains("pull_request_target"));
    }
}

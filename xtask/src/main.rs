#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    reason = "xtask is a command line tool; its output and exit code are its interface"
)]

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

mod anthropic_token;
mod app_token;
mod checkout;
mod clippy;
mod code_scanning;
mod codeql;
mod config;
mod credentials;
mod figures;
mod github_api;
mod ledger;
mod opengrep;
mod prefix_install;
mod prefix_manifest;
mod process;
mod provision;
mod pull_request_hook;
mod release;
mod review;
mod sarif;
mod secrets;
mod setup;
mod test_step;
mod tool_prefix;
mod workflows;

use sarif::{Finding, Rule};
use tycho_types::git_environment::git_environment_removed;

const TYPES: [&str; 11] = [
    "feat", "fix", "docs", "chore", "refactor", "test", "build", "ci", "perf", "style", "revert",
];
const SUBJECT_MAX: usize = 72;
const FMT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const HOOK_INPUT_MAX_BYTES: u64 = 1 << 20;
const HOOK_REPORT_MAX_LINES: usize = 40;
const WALK_MAX_FILES: usize = 4096;
const WALK_MAX_DEPTH: usize = 16;
const SOURCE_DIRS: [&str; 2] = ["xtask", "crates"];
const DOC_DIRS: [&str; 1] = ["docs"];
const RULES_DIR: &str = ".claude/rules";
const RULE_MAX_LINES: usize = 24;
const COMMANDS: [(&str, &str); 27] = [
    (
        "ci",
        "format check, clippy, tests, workflow audits, opengrep, repository checks, PR title",
    ),
    ("fmt", "cargo fmt --check over the workspace"),
    (
        "clippy",
        "clippy over every target with the workspace lints",
    ),
    (
        "test",
        "every test binary, each reported with its path and counts",
    ),
    (
        "opengrep",
        "the opengrep rules against their fixtures, then over the Rust sources",
    ),
    (
        "workflows [--offline]",
        "zizmor and jactionlint over the workflows at pedantic; online unless --offline",
    ),
    (
        "codeql",
        "CodeQL's Actions security queries over the workflows (pre-push on .github changes)",
    ),
    (
        "sarif-upload",
        "upload target/sarif/*.sarif to code scanning (the code-scanning ci job)",
    ),
    (
        "check-commit-msg <file>",
        "one commit message against the conventional grammar",
    ),
    (
        "check-pr-title [title]",
        "a pull request title, from the argument or the CI event",
    ),
    ("check-names", "no abbreviated identifiers in Rust sources"),
    (
        "check-comments",
        "no narration or history in Rust comments and documents",
    ),
    (
        "check-rules",
        "rule files carry paths frontmatter and stay short",
    ),
    (
        "check-ledger",
        "every function a ledger row cites as enforcement exists in the sources",
    ),
    (
        "check-credentials",
        "no user token named in any file git tracks",
    ),
    (
        "render-figures",
        "export figures/ with cue, render with stencil into docs/figures",
    ),
    (
        "check-figures",
        "re-render the figures; fail when docs/figures or the design drift",
    ),
    (
        "check-config",
        "cue vet, then a fresh export compared with config/export",
    ),
    (
        "config-export",
        "cue vet, then export config and JSON Schema to config/export",
    ),
    (
        "release-pr [--dry-run]",
        "open the release pull request; --dry-run shows it locally",
    ),
    (
        "release",
        "tag a merged release pull request, create its GitHub release",
    ),
    (
        "release-binaries [tag]",
        "build this host's archives with dist, upload to the release",
    ),
    (
        "review --dry-run | --post <dir>",
        "Claude reviews a pull request; --post posts the App's verdict, --dry-run prints it",
    ),
    (
        "hook post-tool-use",
        "after an edit: format and lint Rust, check documents and CUE",
    ),
    (
        "hook pre-tool-use",
        "before gh pr create or edit: a draft, and a title that passes the subject check",
    ),
    (
        "setup",
        "operator preconditions for running the factory on this machine",
    ),
    (
        "provision-agent [--print]",
        "create the agent user, groups, socket directories and tool prefix setup checks",
    ),
];
const ABBREVIATIONS: [&str; 5] = ["tmp", "ctx", "obj", "arr", "cfg"];
const NARRATION_MARKERS: [&str; 10] = [
    "previously",
    "used to ",
    "no longer",
    "replaced ",
    "let me",
    "we tried",
    "important to note",
    "in summary",
    "now does",
    "legacy",
];
/// Markers that opengrep's `rust-history-trace-comment` rule covers in Rust comments; this
/// check still applies them to documents.
const MARKERS_IN_OPENGREP: [&str; 3] = ["previously", "used to ", "now does"];
const NAMES_RULES: [Rule<'static>; 1] = [Rule {
    id: "check-names/abbreviation",
    description: "An identifier is an abbreviation (tmp, ctx, obj, arr, cfg) no framework imposes",
}];
const COMMENTS_RULES: [Rule<'static>; 2] = [
    Rule {
        id: "check-comments/narration",
        description: "A comment or document narrates history or process",
    },
    Rule {
        id: "check-comments/ticket-reference",
        description: "A Rust comment names a ticket or issue number",
    },
];
const LEDGER_RULES: [Rule<'static>; 2] = [
    Rule {
        id: "check-ledger/undefined",
        description: "A ledger row cites a function or module nothing in the sources defines",
    },
    Rule {
        id: "check-ledger/stale-exception",
        description: "A name listed as defined elsewhere is no longer cited, or is defined here",
    },
];
const RULES_RULES: [Rule<'static>; 2] = [
    Rule {
        id: "check-rules/frontmatter",
        description: "A rule file has no `paths` frontmatter",
    },
    Rule {
        id: "check-rules/length",
        description: "A rule file is longer than the limit",
    },
];

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Ok,
    MissingColon,
    UnknownType(String),
    BadScope(String),
    EmptySubject,
    UppercaseSubject,
    TrailingPeriod,
    TooLong(usize),
}

fn check_subject(line: &str) -> Verdict {
    let Some((head, subject)) = line.split_once(": ") else {
        return Verdict::MissingColon;
    };
    let head = head.strip_suffix('!').unwrap_or(head);
    let (kind, scope) = match head.split_once('(') {
        Some((kind, rest)) => match rest.strip_suffix(')') {
            Some(scope) => (kind, Some(scope)),
            None => return Verdict::BadScope(rest.to_string()),
        },
        None => (head, None),
    };
    if !TYPES.contains(&kind) {
        return Verdict::UnknownType(kind.to_string());
    }
    if let Some(scope) = scope {
        let valid = !scope.is_empty()
            && scope
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c));
        if !valid {
            return Verdict::BadScope(scope.to_string());
        }
    }
    let subject = subject.trim();
    if subject.is_empty() {
        return Verdict::EmptySubject;
    }
    if subject.chars().next().is_some_and(char::is_uppercase) {
        return Verdict::UppercaseSubject;
    }
    if subject.ends_with('.') {
        return Verdict::TrailingPeriod;
    }
    if line.chars().count() > SUBJECT_MAX {
        return Verdict::TooLong(line.chars().count());
    }
    Verdict::Ok
}

fn explain(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Ok => "ok".to_string(),
        Verdict::MissingColon => "expected `type(scope): subject` or `type: subject`".to_string(),
        Verdict::UnknownType(t) => format!("unknown type `{t}`; allowed: {}", TYPES.join(", ")),
        Verdict::BadScope(s) => {
            format!("scope `{s}` must be lowercase letters, digits, `.`, `_` or `-`")
        }
        Verdict::EmptySubject => "subject is empty".to_string(),
        Verdict::UppercaseSubject => "subject starts with an uppercase letter".to_string(),
        Verdict::TrailingPeriod => "subject ends with a period".to_string(),
        Verdict::TooLong(n) => format!("subject line is {n} characters; limit is {SUBJECT_MAX}"),
    }
}

fn first_non_comment_line(text: &str) -> &str {
    text.lines()
        .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .unwrap_or("")
}

fn check_commit_msg(path: &str) -> i32 {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("xtask: cannot read {path}: {e}");
            return 2;
        }
    };
    let line = first_non_comment_line(&text);
    report("commit message", line, &check_subject(line))
}

fn pr_title_from_event() -> Option<String> {
    let path = env::var("GITHUB_EVENT_PATH").ok()?;
    let text = fs::read_to_string(path).ok()?;
    let event: serde_json::Value = serde_json::from_str(&text).ok()?;
    event
        .get("pull_request")?
        .get("title")?
        .as_str()
        .map(str::to_string)
}

fn check_pr_title(title: Option<String>) -> i32 {
    title.map_or_else(
        || {
            println!("xtask: no pull request title available; skipping the title check");
            0
        },
        |t| report("pull request title", &t, &check_subject(&t)),
    )
}

fn report(what: &str, line: &str, verdict: &Verdict) -> i32 {
    if *verdict == Verdict::Ok {
        println!("xtask: {what} ok: {line}");
        0
    } else {
        eprintln!("xtask: {what} rejected: {line}\n  {}", explain(verdict));
        1
    }
}

fn step_passed(name: &str, outcome: Result<String, String>) -> bool {
    match outcome {
        Ok(summary) => {
            println!("xtask {summary}");
            true
        }
        Err(reason) => {
            eprintln!("xtask {name}: {reason}");
            false
        }
    }
}

type Check = fn() -> i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Passed,
    Failed,
    Skipped,
}

const fn step(passed: bool) -> Step {
    if passed {
        Step::Passed
    } else {
        Step::Failed
    }
}

/// The title check in ci: skipped, and named as skipped, when the run has no pull request.
fn pr_title_step(title: Option<String>) -> Step {
    title.map_or_else(
        || {
            println!("xtask: no pull request title available; skipping the title check");
            Step::Skipped
        },
        |t| step(report("pull request title", &t, &check_subject(&t)) == 0),
    )
}

/// The checkout, its commit, its uncommitted change count and a clean SARIF directory, or
/// the reason ci cannot start.
fn ci_start() -> Result<(PathBuf, String, usize), String> {
    let checkout = checkout::running_checkout()?;
    let commit = checkout::head_commit(&checkout)?;
    let uncommitted = checkout::uncommitted(&checkout)?;
    sarif::clear()?;
    Ok((checkout, commit, uncommitted))
}

/// Runs every step even after one fails, so one run reports all findings and writes all
/// SARIF. A cargo build started here finds rustup's cargo on `PATH`, not the mise wrapper
/// that routes it through the mbx cache, so builds start `mbx` with the cargo subcommand.
fn ci() -> i32 {
    let (checkout, commit, uncommitted_before) = match ci_start() {
        Ok(started) => started,
        Err(reason) => {
            eprintln!("xtask ci: {reason}");
            return 1;
        }
    };
    let formatted = format_checked();
    let linted = step_passed("clippy", clippy::clippy());
    let (tested, tests) = tested();
    let mut steps: Vec<(&str, Step)> = vec![
        ("fmt", step(formatted)),
        ("clippy", step(linted)),
        ("test", step(tested)),
        (
            "workflows",
            step(workflows::workflows(workflows::Network::Online) == 0),
        ),
        ("opengrep", step(opengrep::opengrep() == 0)),
    ];
    let checks: [(&str, Check); 7] = [
        ("check-names", check_names),
        ("check-comments", check_comments),
        ("check-rules", check_rules),
        ("check-ledger", check_ledger),
        ("check-credentials", credentials::check_credentials),
        ("check-figures", figures::check_figures),
        ("check-config", config::check_config),
    ];
    for (name, check) in checks {
        steps.push((name, step(check() == 0)));
    }
    steps.push(("check-pr-title", pr_title_step(pr_title_from_event())));
    let after = checkout::uncommitted(&checkout);
    let revision =
        checkout::closing_revision(&commit, uncommitted_before, after).unwrap_or_else(|reason| {
            eprintln!("xtask ci: recounting uncommitted changes: {reason}");
            steps.push(("recount-uncommitted", Step::Failed));
            checkout::describe_revision(&commit, uncommitted_before)
        });
    let (code, line) = ci_summary(&steps, tests, &checkout, &revision);
    if code == 0 {
        println!("{line}");
    } else {
        eprintln!("{line}");
    }
    code
}

/// `cargo fmt --check` with its diff echoed as it arrives, bounded like every other step.
fn format_checked() -> bool {
    let captured = process::run_bounded_merged(
        Command::new("cargo").args(["fmt", "--all", "--", "--check"]),
        FMT_TIMEOUT,
    );
    match captured.exit {
        process::Exit::Code(0) => true,
        process::Exit::Code(_) => false,
        other => {
            eprintln!("xtask fmt: cargo fmt ended {other:?}");
            false
        }
    }
}

/// Whether every test passed, with the counts when every binary was accounted for.
fn tested() -> (bool, Option<test_step::Counts>) {
    match test_step::test() {
        Ok(totals) => {
            println!("xtask test: {totals}");
            (true, Some(totals.counts))
        }
        Err(failure) => {
            eprintln!("xtask test: {}", failure.reason);
            (false, failure.totals.map(|totals| totals.counts))
        }
    }
}

/// git hands its repository to a hook as `GIT_DIR` and its relatives, and every command the
/// hook starts inherits them; a test that runs `git init` or `git commit` would act on that
/// repository. They are removed before any command runs, so no child of the xtask sees them.
#[expect(
    clippy::disallowed_methods,
    reason = "runs first in main, while the process has one thread"
)]
fn scrub_git_hook_environment() {
    for name in git_environment_removed() {
        env::remove_var(name);
    }
}

const fn exit_code(passed: bool) -> i32 {
    if passed {
        0
    } else {
        1
    }
}

fn steps_in<'name>(steps: &[(&'name str, Step)], wanted: Step) -> Vec<&'name str> {
    steps
        .iter()
        .filter(|(_, state)| *state == wanted)
        .map(|(name, _)| *name)
        .collect()
}

/// The exit code and the closing line: 0 exactly when no step failed. The line names the
/// skipped steps, the tests counted, the checkout and the revision, so a log identifies the
/// tree it came from.
fn ci_summary(
    steps: &[(&str, Step)],
    tests: Option<test_step::Counts>,
    checkout: &Path,
    revision: &str,
) -> (i32, String) {
    let failed = steps_in(steps, Step::Failed);
    let skipped = steps_in(steps, Step::Skipped);
    let passed = steps_in(steps, Step::Passed);
    let skipped_clause = format!("{} skipped ({})", skipped.len(), skipped.join(", "));
    let (skipped, failed_skipped) = if skipped.is_empty() {
        (String::new(), String::new())
    } else {
        (format!(", {skipped_clause}"), format!("; {skipped_clause}"))
    };
    let tests = tests.map_or_else(
        || "tests not counted".to_string(),
        |counts| format!("{} tests passed, {} failed", counts.passed, counts.failed),
    );
    let place = format!("in {} at {revision}", checkout.display());
    if failed.is_empty() {
        let line = format!(
            "xtask ci: {} steps passed{skipped}, {tests}, {place}",
            passed.len()
        );
        (0, line)
    } else {
        let line = format!(
            "xtask ci: {} of {} steps failed: {}{failed_skipped}; {tests}; {place}",
            failed.len(),
            steps.len(),
            failed.join(", ")
        );
        (1, line)
    }
}

fn walk(dirs: &[&str], extension: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = dirs.iter().map(|d| (PathBuf::from(d), 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        if depth > WALK_MAX_DEPTH || found.len() >= WALK_MAX_FILES {
            break;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten().take(WALK_MAX_FILES) {
            let path = entry.path();
            if path.is_dir() {
                stack.push((path, depth.saturating_add(1)));
            } else if path.extension() == Some(OsStr::new(extension)) {
                found.push(path);
            }
        }
    }
    found
}

fn outside_strings(line: &str) -> String {
    let mut kept = String::with_capacity(line.len());
    let mut inside = false;
    let mut escaped = false;
    for c in line.chars() {
        let toggles = c == '"' && !escaped;
        escaped = inside && c == '\\' && !escaped;
        if toggles {
            inside = !inside;
        }
        kept.push(if inside || toggles { ' ' } else { c });
    }
    kept
}

/// Each identifier outside string literals with its one-based character column.
fn identifiers(line: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut current = String::new();
    let mut start = 0_usize;
    for (index, character) in outside_strings(line).chars().enumerate() {
        if character.is_ascii_alphanumeric() || character == '_' {
            if current.is_empty() {
                start = index.saturating_add(1);
            }
            current.push(character);
        } else if !current.is_empty() {
            found.push((start, std::mem::take(&mut current)));
        }
    }
    if !current.is_empty() {
        found.push((start, current));
    }
    found
}

fn abbreviation_defects(path: &Path, text: &str) -> Vec<Finding> {
    let mut defects = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("#[") {
            continue;
        }
        for (column, token) in identifiers(line) {
            let framework = token == "cfg" && (line.contains("cfg(") || line.contains("cfg!"));
            if ABBREVIATIONS.contains(&token.as_str()) && !framework {
                defects.push(Finding::at(
                    path,
                    index.saturating_add(1),
                    column,
                    "check-names/abbreviation",
                    format!("identifier `{token}`"),
                ));
            }
        }
    }
    defects
}

/// A `#` immediately followed by a digit, the shape of a tracker reference.
fn has_hash_digit(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes
        .iter()
        .zip(bytes.iter().skip(1))
        .any(|(byte, next)| *byte == b'#' && next.is_ascii_digit())
}

/// `#<digits>`, `issue <digits>` or `issue #<digits>`; `issue` must start a word, so
/// "tissue 3" and "an issue with" do not match. Expects lowercase text.
fn has_ticket_reference(lower: &str) -> bool {
    let issue_number = lower.match_indices("issue ").any(|(start, marker)| {
        let starts_word = lower
            .get(..start)
            .and_then(|before| before.chars().next_back())
            .is_none_or(|previous| !previous.is_alphanumeric());
        let rest = lower
            .get(start.saturating_add(marker.len())..)
            .unwrap_or("");
        let number = rest.strip_prefix('#').unwrap_or(rest);
        starts_word && number.starts_with(|character: char| character.is_ascii_digit())
    });
    issue_number || has_hash_digit(lower)
}

/// The line from the first `//` outside a double-quoted string, so a trailing comment
/// after code is checked and a `//` inside a string literal is not.
fn comment_text(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        if *byte == b'"' {
            in_string = true;
        } else if *byte == b'/' && bytes.get(index.saturating_add(1)) == Some(&b'/') {
            return line.get(index..);
        }
    }
    None
}

/// In Rust sources (`comments_only`) the markers opengrep covers are left to it.
fn narration_defects(path: &Path, text: &str, comments_only: bool) -> Vec<Finding> {
    let mut defects = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let scanned = if comments_only {
            match comment_text(line) {
                Some(comment) => comment,
                None => continue,
            }
        } else {
            line
        };
        let offset = line.len().saturating_sub(scanned.len());
        let lower = scanned.to_ascii_lowercase();
        let line_number = index.saturating_add(1);
        for marker in NARRATION_MARKERS {
            if comments_only && MARKERS_IN_OPENGREP.contains(&marker) {
                continue;
            }
            if let Some(found) = lower.find(marker) {
                defects.push(Finding::at(
                    path,
                    line_number,
                    offset.saturating_add(found).saturating_add(1),
                    "check-comments/narration",
                    format!("`{marker}`"),
                ));
            }
        }
        if comments_only && has_ticket_reference(&lower) {
            defects.push(Finding::at(
                path,
                line_number,
                offset.saturating_add(1),
                "check-comments/ticket-reference",
                "ticket reference".to_string(),
            ));
        }
    }
    defects
}

fn rule_defects(path: &Path, text: &str) -> Vec<Finding> {
    let mut defects = Vec::new();
    let has_paths = text.starts_with("---\n") && text.contains("\npaths:");
    if !has_paths {
        defects.push(Finding::at(
            path,
            1,
            1,
            "check-rules/frontmatter",
            "missing `paths` frontmatter".to_string(),
        ));
    }
    let lines = text.lines().count();
    if lines > RULE_MAX_LINES {
        defects.push(Finding::at(
            path,
            RULE_MAX_LINES.saturating_add(1),
            1,
            "check-rules/length",
            format!("{lines} lines; limit is {RULE_MAX_LINES}"),
        ));
    }
    defects
}

fn finish(name: &str, examined: usize, defects: &[String]) -> i32 {
    finish_with_note(name, examined, "", defects)
}

/// `note` follows the examined count in the summary, for what a check counted but skipped.
fn finish_with_note(name: &str, examined: usize, note: &str, defects: &[String]) -> i32 {
    if examined == 0 {
        eprintln!("xtask {name}: examined 0 files{note}; a check over nothing is a failure");
        return 1;
    }
    if defects.is_empty() {
        println!("xtask {name}: examined {examined} files{note}, no defects");
        return 0;
    }
    eprintln!(
        "xtask {name}: examined {examined} files{note}, {} defects",
        defects.len()
    );
    for defect in defects.iter().take(HOOK_REPORT_MAX_LINES) {
        eprintln!("  {defect}");
    }
    1
}

/// Writes a file-and-line check's findings to `target/sarif/xtask-<name>.sarif`, one
/// category per check, then reports them as `finish_with_note` does.
fn finish_findings(
    name: &str,
    rules: &[Rule<'_>],
    examined: usize,
    note: &str,
    findings: &[Finding],
) -> i32 {
    let document = sarif::document("xtask", &format!("xtask-{name}"), rules, findings);
    if let Err(reason) = sarif::write(&format!("xtask-{name}"), &document) {
        eprintln!("xtask {name}: {reason}");
        return 1;
    }
    let defects: Vec<String> = findings.iter().map(ToString::to_string).collect();
    finish_with_note(name, examined, note, &defects)
}

fn check_names() -> i32 {
    let files = walk(&SOURCE_DIRS, "rs");
    let defects: Vec<Finding> = files
        .iter()
        .filter_map(|p| {
            fs::read_to_string(p)
                .ok()
                .map(|t| abbreviation_defects(p, &t))
        })
        .flatten()
        .collect();
    finish_findings("check-names", &NAMES_RULES, files.len(), "", &defects)
}

fn check_comments() -> i32 {
    let sources = walk(&SOURCE_DIRS, "rs");
    let docs = walk(&DOC_DIRS, "md");
    let mut defects = Vec::new();
    for path in &sources {
        if let Ok(text) = fs::read_to_string(path) {
            defects.extend(narration_defects(path, &text, true));
        }
    }
    for path in &docs {
        if let Ok(text) = fs::read_to_string(path) {
            defects.extend(narration_defects(path, &text, false));
        }
    }
    finish_findings(
        "check-comments",
        &COMMENTS_RULES,
        sources.len().saturating_add(docs.len()),
        "",
        &defects,
    )
}

fn check_rules() -> i32 {
    let files = walk(&[RULES_DIR], "md");
    let defects: Vec<Finding> = files
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok().map(|t| rule_defects(p, &t)))
        .flatten()
        .collect();
    finish_findings("check-rules", &RULES_RULES, files.len(), "", &defects)
}

/// Reads a file the check needs whole, refusing one over the bound rather than reading part.
fn read_bounded_text(path: &Path) -> Result<String, String> {
    let size = fs::metadata(path)
        .map_err(|error| format!("{}: {error}", path.display()))?
        .len();
    if size > ledger::LEDGER_MAX_BYTES {
        return Err(format!(
            "{} is {size} bytes; the limit is {}",
            path.display(),
            ledger::LEDGER_MAX_BYTES
        ));
    }
    fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn check_ledger() -> i32 {
    let texts = read_bounded_text(Path::new(ledger::LEDGER)).and_then(|ledger_text| {
        read_bounded_text(Path::new(ledger::ELSEWHERE)).map(|listed| (ledger_text, listed))
    });
    let (ledger_text, listed) = match texts {
        Ok(texts) => texts,
        Err(why) => {
            eprintln!("xtask check-ledger: {why}");
            return 1;
        }
    };
    let cited = ledger::cited_names(&ledger_text);
    if cited.is_empty() {
        eprintln!("xtask check-ledger: examined 0 cited names; a check over nothing is a failure");
        return 1;
    }
    let sources = walk(&SOURCE_DIRS, "rs");
    let mut defined = std::collections::BTreeSet::new();
    for path in &sources {
        if let Some(stem) = path.file_stem().and_then(OsStr::to_str) {
            defined.insert(stem.to_string());
        }
        if let Ok(text) = fs::read_to_string(path) {
            defined.extend(ledger::defined_names(&text));
        }
    }
    let defects = ledger::ledger_defects(&cited, &defined, &ledger::elsewhere_names(&listed));
    let note = format!(" for {} cited names", cited.len());
    finish_findings(
        "check-ledger",
        &LEDGER_RULES,
        sources.len(),
        &note,
        &defects,
    )
}

fn capture(program: &str, args: &[&str]) -> Option<Output> {
    Command::new(program).args(args).output().ok()
}

fn edited_file() -> Option<String> {
    let mut text = String::new();
    io::stdin()
        .take(HOOK_INPUT_MAX_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    let event: serde_json::Value = serde_json::from_str(&text).ok()?;
    event
        .get("tool_input")?
        .get("file_path")?
        .as_str()
        .map(str::to_string)
}

fn hook_post_tool_use() -> i32 {
    let Some(path) = edited_file() else {
        return 0;
    };
    credentials::check_credentials();
    let extension = Path::new(&path).extension().and_then(OsStr::to_str);
    match extension {
        Some("rs") => hook_rust(&path),
        Some("cue") => {
            figures::check_figures();
            config::check_config();
            0
        }
        Some("md") => {
            check_comments();
            check_rules();
            check_ledger();
            0
        }
        _ => 0,
    }
}

fn hook_rust(path: &str) -> i32 {
    capture("cargo", &["fmt", "--", path]);
    let Some(output) = capture(
        "mbx",
        &[
            "clippy",
            "-q",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    ) else {
        println!("xtask hook: clippy could not run");
        return 0;
    };
    if output.status.success() {
        println!("xtask hook: {path} formatted, clippy clean");
        check_names();
        check_comments();
        return 0;
    }
    let report = String::from_utf8_lossy(&output.stderr);
    println!("xtask hook: clippy findings after editing {path}");
    for line in report.lines().take(HOOK_REPORT_MAX_LINES) {
        println!("{line}");
    }
    check_names();
    check_comments();
    0
}

fn help() -> i32 {
    println!("xtask <command>\n");
    for (name, what) in COMMANDS {
        println!("  {name:<26} {what}");
    }
    0
}

/// What the process environment holds before any command runs: no git hook variable, and no
/// secret, which the secret store keeps instead.
fn prepare_environment() {
    scrub_git_hook_environment();
    secrets::take_from_environment();
}

fn main() {
    prepare_environment();
    let args: Vec<String> = env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("check-commit-msg") => args.get(1).map_or_else(
            || {
                eprintln!("usage: xtask check-commit-msg <file>");
                2
            },
            |path| check_commit_msg(path),
        ),
        Some("check-pr-title") => check_pr_title(args.get(1).cloned().or_else(pr_title_from_event)),
        Some("ci") => ci(),
        Some("fmt") => exit_code(format_checked()),
        Some("clippy") => exit_code(step_passed("clippy", clippy::clippy())),
        Some("test") => exit_code(tested().0),
        Some("opengrep") => opengrep::opengrep(),
        Some("workflows") => workflows::command(args.get(1).map(String::as_str)),
        Some("sarif-upload") => code_scanning::sarif_upload(),
        Some("codeql") => codeql::codeql(),
        Some("check-names") => check_names(),
        Some("check-comments") => check_comments(),
        Some("check-rules") => check_rules(),
        Some("check-ledger") => check_ledger(),
        Some("check-credentials") => credentials::check_credentials(),
        Some("render-figures") => figures::render_figures(),
        Some("check-figures") => figures::check_figures(),
        Some("check-config") => config::check_config(),
        Some("config-export") => config::config_export(),
        Some("release-pr") => match args.get(1).map(String::as_str) {
            None => release::release_pr(false),
            Some("--dry-run") => release::release_pr(true),
            Some(other) => {
                eprintln!("usage: xtask release-pr [--dry-run]; got {other}");
                2
            }
        },
        Some("release") => release::release(),
        Some("release-binaries") => release::release_binaries(args.get(1).cloned()),
        Some("review") => review::command(args.get(1..).unwrap_or_default()),
        Some("hook") if args.get(1).map(String::as_str) == Some("post-tool-use") => {
            hook_post_tool_use()
        }
        Some("hook") if args.get(1).map(String::as_str) == Some("pre-tool-use") => {
            pull_request_hook::hook_pre_tool_use()
        }
        Some("hook") => {
            eprintln!("usage: xtask hook post-tool-use | pre-tool-use");
            2
        }
        Some("setup") => setup::run(),
        Some("provision-agent") => provision::run(args.get(1..).unwrap_or_default()),
        Some("help") | None => help(),
        _ => {
            help();
            2
        }
    };
    std::process::exit(code);
}

/// Every test that spawns git calls it first.
///
/// # Panics
///
/// When this test process inherited a git hook's environment.
#[cfg(test)]
pub fn refuse_hook_environment() {
    if let Some(refusal) = tycho_types::git_environment::hook_environment_refusal() {
        panic!("{refusal}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tycho_types::git_environment::{git_environment_in, scrub_git_environment};

    const INHERITED_CHILD: &str = "tests::git_children_under_an_inherited_hook_environment";
    const ENV_TIMEOUT: Duration = Duration::from_secs(60);

    fn env_listing(command: &mut Command) -> String {
        let captured = process::run_bounded(command, ENV_TIMEOUT);
        assert_eq!(captured.exit, process::Exit::Code(0));
        captured.stdout
    }

    /// Runs only in a child process that `git_children_never_see_the_hook_environment` starts
    /// with the hook environment set: first the runner git goes through, then the startup
    /// scrub, each with `env` in place of git.
    #[test]
    #[ignore = "run by git_children_never_see_the_hook_environment in a child process"]
    fn git_children_under_an_inherited_hook_environment() {
        assert!(env::var_os("GIT_DIR").is_some(), "the parent sets GIT_DIR");
        let plain = env_listing(&mut Command::new("env"));
        assert!(git_environment_in(&plain).contains(&"GIT_DIR"), "{plain}");
        let scrubbed = env_listing(scrub_git_environment(&mut Command::new("env")));
        assert_eq!(git_environment_in(&scrubbed), Vec::<&str>::new());
        scrub_git_hook_environment();
        assert_eq!(env::var_os("GIT_DIR"), None);
        let after_startup = env_listing(&mut Command::new("env"));
        assert_eq!(git_environment_in(&after_startup), Vec::<&str>::new());
    }

    #[test]
    fn git_children_never_see_the_hook_environment() {
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

    #[test]
    fn accepts_conventional_subjects() {
        for line in [
            "feat: add the thing",
            "fix(core): handle empty input",
            "refactor(sync-step)!: drop the old path",
            "ci: lint pull request titles as conventional commits",
        ] {
            assert_eq!(check_subject(line), Verdict::Ok, "{line}");
        }
    }

    #[test]
    fn rejects_each_defect() {
        assert_eq!(check_subject("add the thing"), Verdict::MissingColon);
        assert_eq!(
            check_subject("feature: add"),
            Verdict::UnknownType("feature".into())
        );
        assert_eq!(
            check_subject("fix(Core): x"),
            Verdict::BadScope("Core".into())
        );
        assert_eq!(
            check_subject("fix(core: x"),
            Verdict::BadScope("core".into())
        );
        assert_eq!(check_subject("fix: "), Verdict::EmptySubject);
        assert_eq!(check_subject("fix: Capitalised"), Verdict::UppercaseSubject);
        assert_eq!(
            check_subject("fix: ends with period."),
            Verdict::TrailingPeriod
        );
        let long = format!("fix: {}", "x".repeat(80));
        assert!(matches!(check_subject(&long), Verdict::TooLong(_)));
    }

    #[test]
    fn flags_abbreviations_but_not_framework_cfg() {
        let text = "let tmp = 1;\n#[cfg(test)]\nif cfg!(unix) {}\nlet s = \"tmp ctx\";\n";
        let defects = abbreviation_defects(Path::new("a.rs"), text);
        assert_eq!(defects.len(), 1);
        assert!(defects.first().is_some_and(
            |d| d.to_string() == "a.rs:1:5: check-names/abbreviation: identifier `tmp`"
        ));
    }

    #[test]
    fn flags_narration_in_comments_only_for_sources() {
        let text = "// we tried this loop\nlet legacy = 1;\n";
        assert_eq!(narration_defects(Path::new("a.rs"), text, true).len(), 1);
        assert_eq!(narration_defects(Path::new("a.md"), text, false).len(), 2);
    }

    #[test]
    fn flags_ticket_and_issue_references_in_comments() {
        let text = "// see issue 19 for background\n// fixed in #42\n// tracked as issue #7\nlet count = 1;\n";
        let defects = narration_defects(Path::new("a.rs"), text, true);
        assert_eq!(defects.len(), 3, "{defects:?}");
    }

    #[test]
    fn does_not_flag_a_plain_comment_without_a_ticket_reference() {
        let text = "// this stays bounded by the caller\nlet count = 1;\n";
        assert!(narration_defects(Path::new("a.rs"), text, true).is_empty());
    }

    #[test]
    fn does_not_flag_the_word_issue_in_ordinary_prose() {
        let text = "// an issue with the splitter: tissue 3 is not a ticket\nlet count = 1;\n";
        let defects = narration_defects(Path::new("a.rs"), text, true);
        assert!(defects.is_empty(), "{defects:?}");
    }

    #[test]
    fn flags_a_ticket_reference_in_a_trailing_comment_but_not_inside_a_string() {
        let text = "let count = 1; // see issue 19\nlet url = \"https://host/#1\";\n";
        let defects = narration_defects(Path::new("a.rs"), text, true);
        assert_eq!(defects.len(), 1, "{defects:?}");
        assert!(defects
            .first()
            .is_some_and(|defect| defect.to_string().starts_with("a.rs:1:16:")));
    }

    #[test]
    fn rule_files_need_paths_frontmatter_and_stay_short() {
        let good = "---\npaths:\n  - \"**/*.rs\"\n---\nshort\n";
        assert!(rule_defects(Path::new("r.md"), good).is_empty());
        let unscoped = "no frontmatter\n";
        assert_eq!(rule_defects(Path::new("r.md"), unscoped).len(), 1);
        let long = format!("{good}{}", "x\n".repeat(RULE_MAX_LINES));
        assert_eq!(rule_defects(Path::new("r.md"), &long).len(), 1);
    }

    #[test]
    fn the_ci_exit_code_is_zero_exactly_when_no_step_failed() {
        let checkout = Path::new("/station");
        let counted = test_step::Counts {
            passed: 590,
            failed: 0,
            ignored: 2,
        };
        let passing = [
            ("fmt", Step::Passed),
            ("test", Step::Passed),
            ("check-pr-title", Step::Passed),
        ];
        let (code, line) = ci_summary(&passing, Some(counted), checkout, "511cf42");
        assert_eq!(code, 0);
        assert_eq!(
            line,
            "xtask ci: 3 steps passed, 590 tests passed, 0 failed, in /station at 511cf42"
        );
        let one_failed = test_step::Counts {
            failed: 1,
            ..counted
        };
        let failing = [
            ("fmt", Step::Passed),
            ("test", Step::Failed),
            ("check-pr-title", Step::Skipped),
        ];
        let (code, line) = ci_summary(&failing, Some(one_failed), checkout, "511cf42");
        assert_eq!(code, 1);
        assert_eq!(
            line,
            "xtask ci: 1 of 3 steps failed: test; 1 skipped (check-pr-title); 590 tests passed, 1 failed; in /station at 511cf42"
        );
        let (code, line) = ci_summary(&failing, None, checkout, "511cf42");
        assert_eq!(code, 1);
        assert!(line.contains("tests not counted"), "{line}");
        let last_failing = [("fmt", Step::Passed), ("check-pr-title", Step::Failed)];
        let (code, line) = ci_summary(&last_failing, Some(counted), checkout, "511cf42");
        assert_eq!(code, 1);
        assert!(!line.contains("steps passed"), "{line}");
    }

    #[test]
    fn a_skipped_step_is_named_and_not_counted_as_passed() {
        let steps = [
            ("fmt", Step::Passed),
            ("test", Step::Passed),
            ("check-pr-title", Step::Skipped),
        ];
        let counted = test_step::Counts {
            passed: 590,
            failed: 0,
            ignored: 0,
        };
        let (code, line) = ci_summary(
            &steps,
            Some(counted),
            Path::new("/station"),
            "511cf42 with 2 uncommitted changes",
        );
        assert_eq!(code, 0);
        assert_eq!(
            line,
            "xtask ci: 2 steps passed, 1 skipped (check-pr-title), 590 tests passed, 0 failed, in /station at 511cf42 with 2 uncommitted changes"
        );
        assert_eq!(pr_title_step(None), Step::Skipped);
        assert_eq!(
            pr_title_step(Some("fix: a title".to_string())),
            Step::Passed
        );
        assert_eq!(pr_title_step(Some("Fix a title".to_string())), Step::Failed);
    }

    #[test]
    fn skips_comment_lines_in_message_files() {
        let text = "# Please enter the commit message\n\nfeat: real subject\n";
        assert_eq!(first_non_comment_line(text), "feat: real subject");
    }
}

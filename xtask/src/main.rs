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
use std::process::{Command, ExitStatus, Output};

mod app_token;
mod clippy;
mod code_scanning;
mod config;
mod credentials;
mod figures;
mod github_api;
mod opengrep;
mod process;
mod provision;
mod release;
mod sarif;
mod setup;
mod workflows;

use sarif::{Finding, Rule};

const TYPES: [&str; 11] = [
    "feat", "fix", "docs", "chore", "refactor", "test", "build", "ci", "perf", "style", "revert",
];
const SUBJECT_MAX: usize = 72;
const HOOK_INPUT_MAX_BYTES: u64 = 1 << 20;
const HOOK_REPORT_MAX_LINES: usize = 40;
const WALK_MAX_FILES: usize = 4096;
const WALK_MAX_DEPTH: usize = 16;
const SOURCE_DIRS: [&str; 2] = ["xtask", "crates"];
const DOC_DIRS: [&str; 1] = ["docs"];
const RULES_DIR: &str = ".claude/rules";
const RULE_MAX_LINES: usize = 24;
const COMMANDS: [(&str, &str); 20] = [
    (
        "ci",
        "format check, clippy, tests, workflow audits, opengrep, repository checks, PR title",
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
        "hook post-tool-use",
        "after an edit: format and lint Rust, check documents and CUE",
    ),
    (
        "setup",
        "operator preconditions for running the factory on this machine",
    ),
    (
        "provision-agent [--print]",
        "create the agent user, groups and socket directories setup checks",
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

fn run(program: &str, args: &[&str]) -> ExitStatus {
    println!("xtask: {program} {}", args.join(" "));
    Command::new(program)
        .args(args)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("xtask: failed to start {program}: {e}");
            std::process::exit(2)
        })
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

/// Runs every step even after one fails, so one run reports all findings and writes all
/// SARIF. A cargo build started here finds rustup's cargo on `PATH`, not the mise wrapper
/// that routes it through the mbx cache, so builds start `mbx` with the cargo subcommand.
fn ci() -> i32 {
    if let Err(reason) = sarif::clear() {
        eprintln!("xtask ci: {reason}");
        return 1;
    }
    let mut steps: Vec<(&str, bool)> = vec![
        (
            "fmt",
            run("cargo", &["fmt", "--all", "--", "--check"]).success(),
        ),
        ("clippy", step_passed("clippy", clippy::clippy())),
        ("test", run("mbx", &["test", "--workspace"]).success()),
        (
            "workflows",
            workflows::workflows(workflows::Network::Online) == 0,
        ),
        ("opengrep", opengrep::opengrep() == 0),
    ];
    let checks: [(&str, Check); 6] = [
        ("check-names", check_names),
        ("check-comments", check_comments),
        ("check-rules", check_rules),
        ("check-credentials", credentials::check_credentials),
        ("check-figures", figures::check_figures),
        ("check-config", config::check_config),
    ];
    for (name, check) in checks {
        steps.push((name, check() == 0));
    }
    steps.push(("check-pr-title", check_pr_title(pr_title_from_event()) == 0));
    let failed: Vec<&str> = steps
        .iter()
        .filter(|(_, passed)| !passed)
        .map(|(name, _)| *name)
        .collect();
    if failed.is_empty() {
        println!("xtask ci: {} steps passed", steps.len());
        0
    } else {
        eprintln!(
            "xtask ci: {} of {} steps failed: {}",
            failed.len(),
            steps.len(),
            failed.join(", ")
        );
        1
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

fn main() {
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
        Some("opengrep") => opengrep::opengrep(),
        Some("workflows") => match args.get(1).map(String::as_str) {
            None => workflows::workflows(workflows::Network::Online),
            Some("--offline") => workflows::workflows(workflows::Network::Offline),
            Some(other) => {
                eprintln!("usage: xtask workflows [--offline]; got {other}");
                2
            }
        },
        Some("sarif-upload") => code_scanning::sarif_upload(),
        Some("check-names") => check_names(),
        Some("check-comments") => check_comments(),
        Some("check-rules") => check_rules(),
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
        Some("hook") if args.get(1).map(String::as_str) == Some("post-tool-use") => {
            hook_post_tool_use()
        }
        Some("hook") => {
            eprintln!("usage: xtask hook post-tool-use");
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn skips_comment_lines_in_message_files() {
        let text = "# Please enter the commit message\n\nfeat: real subject\n";
        assert_eq!(first_non_comment_line(text), "feat: real subject");
    }
}

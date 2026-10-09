use std::env;
use std::fs;
use std::process::{self, Command, ExitStatus};

const TYPES: [&str; 11] = [
    "feat", "fix", "docs", "chore", "refactor", "test", "build", "ci", "perf", "style", "revert",
];
const SUBJECT_MAX: usize = 72;

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
    if subject.chars().next().is_some_and(|c| c.is_uppercase()) {
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
    report("commit message", line, check_subject(line))
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
    match title {
        Some(t) => report("pull request title", &t, check_subject(&t)),
        None => {
            println!("xtask: no pull request title available; skipping the title check");
            0
        }
    }
}

fn report(what: &str, line: &str, verdict: Verdict) -> i32 {
    if verdict == Verdict::Ok {
        println!("xtask: {what} ok: {line}");
        0
    } else {
        eprintln!("xtask: {what} rejected: {line}\n  {}", explain(&verdict));
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
            process::exit(2)
        })
}

fn ci() -> i32 {
    let steps: [(&str, &[&str]); 3] = [
        ("cargo", &["fmt", "--all", "--", "--check"]),
        (
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
        ),
        ("cargo", &["test", "--workspace"]),
    ];
    for (program, args) in steps {
        if !run(program, args).success() {
            return 1;
        }
    }
    check_pr_title(pr_title_from_event())
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("check-commit-msg") => match args.get(1) {
            Some(path) => check_commit_msg(path),
            None => {
                eprintln!("usage: xtask check-commit-msg <file>");
                2
            }
        },
        Some("check-pr-title") => check_pr_title(args.get(1).cloned().or_else(pr_title_from_event)),
        Some("ci") => ci(),
        _ => {
            eprintln!("usage: xtask <check-commit-msg <file> | check-pr-title [title] | ci>");
            2
        }
    };
    process::exit(code);
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
    fn skips_comment_lines_in_message_files() {
        let text = "# Please enter the commit message\n\nfeat: real subject\n";
        assert_eq!(first_non_comment_line(text), "feat: real subject");
    }
}

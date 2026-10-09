//! Release commands: release pull requests and tags through release-plz, binaries through dist.

use std::env;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const RELEASE_PLZ_TIMEOUT: Duration = Duration::from_secs(600);
const DIST_TIMEOUT: Duration = Duration::from_secs(1800);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(600);
const GIT_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const READER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
const OUTPUT_MAX_BYTES: u64 = 4 << 20;
const REPORT_MAX_LINES: usize = 80;
const ARTIFACTS_MAX: usize = 32;
const TAG_MAX_CHARS: usize = 32;
const RELEASED_PACKAGE: &str = "tycho";
const RELEASE_TOKEN_VARIABLE: &str = "RELEASE_PLZ_TOKEN";
const DRY_RUN_DIR: &str = "target/release-dry-run";
const DISTRIB_DIR: &str = "target/distrib";
const MACOS_TARGETS: [&str; 2] = ["aarch64-apple-darwin", "x86_64-apple-darwin"];
const LINUX_TARGETS: [&str; 1] = ["x86_64-unknown-linux-gnu"];

/// How a bounded child process ended.
#[derive(Debug, PartialEq, Eq)]
enum Exit {
    Code(i32),
    Signal,
    TimedOut,
    OutputTooLarge,
    OutputUnreadable,
    NotStarted(String),
}

#[derive(Debug)]
struct Captured {
    exit: Exit,
    stdout: String,
}

#[derive(Debug, PartialEq, Eq)]
enum ReleasePrOutcome {
    Opened { number: u64, url: String },
    NothingToRelease,
    Failed(Exit),
    Unrecognised(String),
}

#[derive(Debug, PartialEq, Eq)]
enum ReleaseOutcome {
    Released { tag: String, version: String },
    NothingToRelease,
    Failed(Exit),
    Unrecognised(String),
}

#[derive(Debug, PartialEq, Eq)]
enum DryRunOutcome {
    Proposed(Vec<String>),
    NothingToRelease,
    Failed(Exit),
    Unrecognised(String),
}

#[derive(Debug, PartialEq, Eq)]
enum DistOutcome {
    Built(Vec<String>),
    Failed(Exit),
    Unrecognised(String),
}

#[derive(Debug, PartialEq, Eq)]
enum UploadOutcome {
    Uploaded(usize),
    Failed(Exit),
}

/// Runs a command with stdin closed, stderr inherited and stdout captured up to the cap.
fn run_bounded(command: &mut Command, timeout: Duration) -> Captured {
    println!("xtask: {}", describe(command));
    let spawned = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            return Captured {
                exit: Exit::NotStarted(error.to_string()),
                stdout: String::new(),
            }
        }
    };
    let (sender, receiver) = mpsc::channel();
    if let Some(pipe) = child.stdout.take() {
        thread::spawn(move || {
            let mut kept = Vec::new();
            let mut limited = pipe.take(OUTPUT_MAX_BYTES.saturating_add(1));
            let read = limited.read_to_end(&mut kept);
            let mut rest = limited.into_inner();
            // Draining past the cap keeps the child from blocking on a full pipe.
            let drained = std::io::copy(&mut rest, &mut std::io::sink());
            let state = if read.is_err() || drained.is_err() {
                Some(Exit::OutputUnreadable)
            } else if u64::try_from(kept.len()).map_or(true, |n| n > OUTPUT_MAX_BYTES) {
                Some(Exit::OutputTooLarge)
            } else {
                None
            };
            if sender.send((kept, state)).is_err() {
                eprintln!("xtask: stdout arrived after the reader deadline");
            }
        });
    }
    let exit = wait_with_deadline(&mut child, timeout);
    let Ok((kept, reader_state)) = receiver.recv_timeout(READER_JOIN_TIMEOUT) else {
        let exit = if exit == Exit::Code(0) {
            Exit::OutputUnreadable
        } else {
            exit
        };
        return Captured {
            exit,
            stdout: String::new(),
        };
    };
    let stdout = String::from_utf8_lossy(&kept).into_owned();
    let exit = reader_state.unwrap_or(exit);
    Captured { exit, stdout }
}

fn wait_with_deadline(child: &mut std::process::Child, timeout: Duration) -> Exit {
    let polls = timeout
        .as_millis()
        .checked_div(POLL_INTERVAL.as_millis())
        .unwrap_or(0);
    for _ in 0..polls {
        match child.try_wait() {
            Ok(Some(status)) => return status.code().map_or(Exit::Signal, Exit::Code),
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => return Exit::NotStarted(error.to_string()),
        }
    }
    if let Err(error) = child.kill() {
        eprintln!("xtask: could not kill the timed out process: {error}");
    }
    if let Err(error) = child.wait() {
        eprintln!("xtask: could not reap the timed out process: {error}");
    }
    Exit::TimedOut
}

/// The program and its arguments; environment values, where tokens live, are never shown.
fn describe(command: &Command) -> String {
    let mut parts = vec![command.get_program().to_string_lossy().into_owned()];
    parts.extend(command.get_args().map(|a| a.to_string_lossy().into_owned()));
    parts.join(" ")
}

fn print_capped(text: &str) {
    for line in text.lines().take(REPORT_MAX_LINES) {
        println!("  {line}");
    }
    let total = text.lines().count();
    if total > REPORT_MAX_LINES {
        println!(
            "  ... {} more lines",
            total.saturating_sub(REPORT_MAX_LINES)
        );
    }
}

/// Reads stdout as one JSON document, or failing that its last line that opens an object.
fn parse_json(stdout: &str) -> Result<serde_json::Value, String> {
    if let Ok(value) = serde_json::from_str(stdout.trim()) {
        return Ok(value);
    }
    let line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| "no JSON object on stdout".to_string())?;
    serde_json::from_str(line).map_err(|e| format!("stdout is not JSON: {e}"))
}

fn decode_release_pr(exit: Exit, stdout: &str) -> ReleasePrOutcome {
    if exit != Exit::Code(0) {
        return ReleasePrOutcome::Failed(exit);
    }
    let value = match parse_json(stdout) {
        Ok(value) => value,
        Err(reason) => return ReleasePrOutcome::Unrecognised(reason),
    };
    let Some(prs) = value.get("prs").and_then(serde_json::Value::as_array) else {
        return ReleasePrOutcome::Unrecognised("no `prs` array".to_string());
    };
    match prs.as_slice() {
        [] => ReleasePrOutcome::NothingToRelease,
        [pr] => {
            let number = pr.get("number").and_then(serde_json::Value::as_u64);
            let url = pr.get("html_url").and_then(serde_json::Value::as_str);
            match (number, url) {
                (Some(number), Some(url)) => ReleasePrOutcome::Opened {
                    number,
                    url: url.to_string(),
                },
                _ => ReleasePrOutcome::Unrecognised("pull request without number or url".into()),
            }
        }
        _ => ReleasePrOutcome::Unrecognised(format!("{} release pull requests", prs.len())),
    }
}

fn decode_release(exit: Exit, stdout: &str) -> ReleaseOutcome {
    if exit != Exit::Code(0) {
        return ReleaseOutcome::Failed(exit);
    }
    let value = match parse_json(stdout) {
        Ok(value) => value,
        Err(reason) => return ReleaseOutcome::Unrecognised(reason),
    };
    let Some(releases) = value.get("releases").and_then(serde_json::Value::as_array) else {
        return ReleaseOutcome::Unrecognised("no `releases` array".to_string());
    };
    match releases.as_slice() {
        [] => ReleaseOutcome::NothingToRelease,
        [release] => {
            let field = |name: &str| release.get(name).and_then(serde_json::Value::as_str);
            match (field("package_name"), field("tag"), field("version")) {
                (Some(RELEASED_PACKAGE), Some(tag), Some(version)) if valid_tag(tag) => {
                    ReleaseOutcome::Released {
                        tag: tag.to_string(),
                        version: version.to_string(),
                    }
                }
                _ => ReleaseOutcome::Unrecognised(format!("unexpected release entry: {release}")),
            }
        }
        _ => ReleaseOutcome::Unrecognised(format!("{} releases; only tycho", releases.len())),
    }
}

fn decode_dry_run(exit: Exit, porcelain: &str) -> DryRunOutcome {
    if exit != Exit::Code(0) {
        return DryRunOutcome::Failed(exit);
    }
    let mut files = Vec::new();
    for line in porcelain.lines() {
        match line.get(3..) {
            Some(path) if line.len() > 3 => files.push(path.to_string()),
            _ => return DryRunOutcome::Unrecognised(format!("status line `{line}`")),
        }
    }
    if files.is_empty() {
        DryRunOutcome::NothingToRelease
    } else {
        DryRunOutcome::Proposed(files)
    }
}

fn decode_dist(exit: Exit, stdout: &str) -> DistOutcome {
    if exit != Exit::Code(0) {
        return DistOutcome::Failed(exit);
    }
    let value = match parse_json(stdout) {
        Ok(value) => value,
        Err(reason) => return DistOutcome::Unrecognised(reason),
    };
    let Some(artifacts) = value
        .get("artifacts")
        .and_then(serde_json::Value::as_object)
    else {
        return DistOutcome::Unrecognised("no `artifacts` object".to_string());
    };
    let names: Vec<String> = artifacts.keys().cloned().collect();
    let safe = names
        .iter()
        .all(|n| n.starts_with("tycho-") && !n.contains('/') && !n.contains(".."));
    if names.is_empty() || names.len() > ARTIFACTS_MAX || !safe {
        return DistOutcome::Unrecognised(format!("artifact list {names:?}"));
    }
    DistOutcome::Built(names)
}

fn decode_upload(exit: Exit, count: usize) -> UploadOutcome {
    if exit == Exit::Code(0) {
        UploadOutcome::Uploaded(count)
    } else {
        UploadOutcome::Failed(exit)
    }
}

/// A release tag is `v` and a semantic version of digits and dots, bounded in length.
fn valid_tag(tag: &str) -> bool {
    let Some(version) = tag.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = version.split('.').collect();
    tag.len() <= TAG_MAX_CHARS
        && parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

fn release_pr_token(value: Option<String>) -> Result<String, String> {
    match value {
        Some(token) if !token.trim().is_empty() => Ok(token),
        _ => Err(format!(
            "{RELEASE_TOKEN_VARIABLE} is not set. The release pull request needs a token whose \
             pull requests trigger ci: create a fine-grained token for this repository with \
             Contents and Pull requests read and write, and store it as the repository secret \
             {RELEASE_TOKEN_VARIABLE}"
        )),
    }
}

/// `xtask release-pr`: opens or updates the release pull request.
pub fn release_pr(dry_run: bool) -> i32 {
    if dry_run {
        return release_pr_dry_run();
    }
    let token = match release_pr_token(env::var(RELEASE_TOKEN_VARIABLE).ok()) {
        Ok(token) => token,
        Err(reason) => {
            eprintln!("xtask release-pr: {reason}");
            return 1;
        }
    };
    let captured = run_bounded(
        Command::new("release-plz")
            .args(["release-pr", "--output", "json"])
            .env("GIT_TOKEN", token),
        RELEASE_PLZ_TIMEOUT,
    );
    match decode_release_pr(captured.exit, &captured.stdout) {
        ReleasePrOutcome::Opened { number, url } => {
            println!("xtask release-pr: release pull request #{number} at {url}");
            0
        }
        ReleasePrOutcome::NothingToRelease => {
            println!("xtask release-pr: no releasable commits since the last tag");
            0
        }
        outcome => {
            eprintln!("xtask release-pr: {outcome:?}");
            print_capped(&captured.stdout);
            1
        }
    }
}

fn git_in(dir: &Path, args: &[&str]) -> Captured {
    run_bounded(Command::new("git").current_dir(dir).args(args), GIT_TIMEOUT)
}

fn remove_dry_run_worktree(root: &Path) {
    let scratch = root.join(DRY_RUN_DIR);
    if scratch.exists() {
        let path = scratch.to_string_lossy().into_owned();
        git_in(root, &["worktree", "remove", "--force", &path]);
    }
}

/// Runs `release-plz update` in a detached scratch worktree at HEAD and shows what it would change.
fn release_pr_dry_run() -> i32 {
    let root = PathBuf::from(".");
    remove_dry_run_worktree(&root);
    let added = git_in(
        &root,
        &[
            "worktree",
            "add",
            "--force",
            "--detach",
            DRY_RUN_DIR,
            "HEAD",
        ],
    );
    if added.exit != Exit::Code(0) {
        eprintln!(
            "xtask release-pr --dry-run: worktree add ended {:?}",
            added.exit
        );
        return 1;
    }
    let scratch = root.join(DRY_RUN_DIR);
    let code = dry_run_in(&scratch);
    remove_dry_run_worktree(&root);
    code
}

fn dry_run_in(scratch: &Path) -> i32 {
    let mut update = Command::new("release-plz");
    update.current_dir(scratch).arg("update");
    let token = env::var(RELEASE_TOKEN_VARIABLE).or_else(|_| env::var("GITHUB_TOKEN"));
    if let Ok(token) = token {
        update.env("GIT_TOKEN", token);
    }
    let updated = run_bounded(&mut update, RELEASE_PLZ_TIMEOUT);
    print_capped(&updated.stdout);
    let exit = if updated.exit == Exit::Code(0) {
        git_in(scratch, &["add", "--intent-to-add", "--all"]);
        let status = git_in(scratch, &["status", "--porcelain"]);
        let outcome = decode_dry_run(status.exit, &status.stdout);
        if let DryRunOutcome::Proposed(_) = outcome {
            print_capped(&git_in(scratch, &["diff"]).stdout);
        }
        outcome
    } else {
        DryRunOutcome::Failed(updated.exit)
    };
    match exit {
        DryRunOutcome::Proposed(files) => {
            println!(
                "xtask release-pr --dry-run: would change {} files",
                files.len()
            );
            0
        }
        DryRunOutcome::NothingToRelease => {
            println!("xtask release-pr --dry-run: nothing to release");
            0
        }
        outcome => {
            eprintln!("xtask release-pr --dry-run: {outcome:?}");
            1
        }
    }
}

/// `xtask release`: tags a merged release pull request and creates its GitHub release.
pub fn release() -> i32 {
    let Some(token) = env::var("GITHUB_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty())
    else {
        eprintln!(
            "xtask release: GITHUB_TOKEN is not set; release-plz needs it to tag and release"
        );
        return 1;
    };
    let captured = run_bounded(
        Command::new("release-plz")
            .args(["release", "--output", "json"])
            .env("GIT_TOKEN", token),
        RELEASE_PLZ_TIMEOUT,
    );
    match decode_release(captured.exit, &captured.stdout) {
        ReleaseOutcome::Released { tag, version } => {
            println!("xtask release: released {RELEASED_PACKAGE} {version} as {tag}");
            write_step_output("tag", &tag)
        }
        ReleaseOutcome::NothingToRelease => {
            println!("xtask release: this commit is not a merged release pull request");
            0
        }
        outcome => {
            eprintln!("xtask release: {outcome:?}");
            print_capped(&captured.stdout);
            1
        }
    }
}

fn write_step_output(name: &str, value: &str) -> i32 {
    let Ok(path) = env::var("GITHUB_OUTPUT") else {
        println!("xtask: {name}={value} (no GITHUB_OUTPUT outside Actions)");
        return 0;
    };
    let written = OpenOptions::new()
        .append(true)
        .open(&path)
        .and_then(|mut file| writeln!(file, "{name}={value}"));
    match written {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("xtask: cannot write step output to {path}: {error}");
            1
        }
    }
}

const fn host_targets() -> &'static [&'static str] {
    if cfg!(target_os = "macos") {
        &MACOS_TARGETS
    } else {
        &LINUX_TARGETS
    }
}

/// `xtask release-binaries <tag>`: builds this host's archives with dist and uploads them.
pub fn release_binaries(tag: Option<String>) -> i32 {
    let tag = match tag.or_else(|| env::var("RELEASE_TAG").ok()) {
        Some(tag) if valid_tag(&tag) => tag,
        other => {
            eprintln!("xtask release-binaries: expected a tag like v1.2.3, got {other:?}");
            return 2;
        }
    };
    let mut dist = Command::new("dist");
    dist.args([
        "build",
        "--tag",
        &tag,
        "--artifacts",
        "local",
        "--no-local-paths",
    ]);
    dist.args(["--output-format", "json"]);
    for target in host_targets() {
        dist.args(["--target", target]);
    }
    let built = run_bounded(&mut dist, DIST_TIMEOUT);
    let names = match decode_dist(built.exit, &built.stdout) {
        DistOutcome::Built(names) => names,
        outcome => {
            eprintln!("xtask release-binaries: dist {outcome:?}");
            return 1;
        }
    };
    upload(&tag, &names)
}

fn upload(tag: &str, names: &[String]) -> i32 {
    let paths: Vec<PathBuf> = names
        .iter()
        .map(|n| Path::new(DISTRIB_DIR).join(n))
        .collect();
    if let Some(missing) = paths.iter().find(|p| !p.is_file()) {
        eprintln!(
            "xtask release-binaries: dist reported {} but it is not on disk",
            missing.display()
        );
        return 1;
    }
    let mut command = Command::new("gh");
    command
        .args(["release", "upload", tag, "--clobber"])
        .args(&paths);
    if let Ok(token) = env::var("GITHUB_TOKEN") {
        command.env("GH_TOKEN", token);
    }
    let captured = run_bounded(&mut command, UPLOAD_TIMEOUT);
    match decode_upload(captured.exit, paths.len()) {
        UploadOutcome::Uploaded(count) => {
            println!("xtask release-binaries: uploaded {count} files to {tag}");
            0
        }
        UploadOutcome::Failed(exit) => {
            eprintln!("xtask release-binaries: gh release upload ended {exit:?}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_pr_decoder_covers_each_state() {
        let opened = r#"{"prs":[{"head_branch":"release-plz-x","base_branch":"main","html_url":"https://github.com/o/r/pull/7","number":7,"releases":[]}]}"#;
        assert_eq!(
            decode_release_pr(Exit::Code(0), opened),
            ReleasePrOutcome::Opened {
                number: 7,
                url: "https://github.com/o/r/pull/7".into()
            }
        );
        assert_eq!(
            decode_release_pr(Exit::Code(0), "log line\n{\"prs\":[]}\n"),
            ReleasePrOutcome::NothingToRelease
        );
        assert_eq!(
            decode_release_pr(Exit::Code(1), ""),
            ReleasePrOutcome::Failed(Exit::Code(1))
        );
        assert_eq!(
            decode_release_pr(Exit::TimedOut, ""),
            ReleasePrOutcome::Failed(Exit::TimedOut)
        );
        for unrecognised in [
            "",
            "not json",
            "{\"prs\":{}}",
            "{\"prs\":[{}]}",
            "{\"prs\":[{},{}]}",
        ] {
            assert!(
                matches!(
                    decode_release_pr(Exit::Code(0), unrecognised),
                    ReleasePrOutcome::Unrecognised(_)
                ),
                "{unrecognised}"
            );
        }
    }

    #[test]
    fn release_decoder_covers_each_state() {
        let released =
            r#"{"releases":[{"package_name":"tycho","prs":[],"tag":"v0.1.0","version":"0.1.0"}]}"#;
        assert_eq!(
            decode_release(Exit::Code(0), released),
            ReleaseOutcome::Released {
                tag: "v0.1.0".into(),
                version: "0.1.0".into()
            }
        );
        assert_eq!(
            decode_release(Exit::Code(0), "{\"releases\":[]}"),
            ReleaseOutcome::NothingToRelease
        );
        assert_eq!(
            decode_release(Exit::Signal, ""),
            ReleaseOutcome::Failed(Exit::Signal)
        );
        let other_package =
            r#"{"releases":[{"package_name":"xtask","tag":"v0.1.0","version":"0.1.0"}]}"#;
        let bad_tag = r#"{"releases":[{"package_name":"tycho","tag":"v1;rm","version":"1"}]}"#;
        for unrecognised in ["", "{}", other_package, bad_tag] {
            assert!(
                matches!(
                    decode_release(Exit::Code(0), unrecognised),
                    ReleaseOutcome::Unrecognised(_)
                ),
                "{unrecognised}"
            );
        }
    }

    #[test]
    fn dry_run_decoder_reads_porcelain_status() {
        assert_eq!(
            decode_dry_run(
                Exit::Code(0),
                " A crates/tycho/CHANGELOG.md\n M Cargo.lock\n"
            ),
            DryRunOutcome::Proposed(vec![
                "crates/tycho/CHANGELOG.md".into(),
                "Cargo.lock".into()
            ])
        );
        assert_eq!(
            decode_dry_run(Exit::Code(0), ""),
            DryRunOutcome::NothingToRelease
        );
        assert_eq!(
            decode_dry_run(Exit::Code(128), ""),
            DryRunOutcome::Failed(Exit::Code(128))
        );
        assert!(matches!(
            decode_dry_run(Exit::Code(0), "?"),
            DryRunOutcome::Unrecognised(_)
        ));
    }

    #[test]
    fn dist_decoder_requires_safe_artifact_names() {
        let built = "{\n  \"artifacts\": {\n    \"tycho-aarch64-apple-darwin.tar.xz\": {},\n    \"tycho-aarch64-apple-darwin.tar.xz.sha256\": {}\n  }\n}\n";
        assert!(matches!(
            decode_dist(Exit::Code(0), built),
            DistOutcome::Built(names) if names.len() == 2
        ));
        assert_eq!(
            decode_dist(Exit::Code(255), ""),
            DistOutcome::Failed(Exit::Code(255))
        );
        let empty = r#"{"artifacts":{}}"#;
        let escaping = r#"{"artifacts":{"tycho-../../etc":{}}}"#;
        let foreign = r#"{"artifacts":{"other.tar.xz":{}}}"#;
        for unrecognised in ["", "{}", empty, escaping, foreign] {
            assert!(
                matches!(
                    decode_dist(Exit::Code(0), unrecognised),
                    DistOutcome::Unrecognised(_)
                ),
                "{unrecognised}"
            );
        }
    }

    #[test]
    fn upload_decoder_counts_only_on_success() {
        assert_eq!(decode_upload(Exit::Code(0), 4), UploadOutcome::Uploaded(4));
        assert_eq!(
            decode_upload(Exit::Code(1), 4),
            UploadOutcome::Failed(Exit::Code(1))
        );
    }

    #[test]
    fn tags_are_versions_only() {
        assert!(valid_tag("v0.1.0"));
        assert!(valid_tag("v12.0.31"));
        for bad in [
            "0.1.0",
            "v0.1",
            "v0.1.0-rc1",
            "v0.1.0;x",
            "v..",
            "tycho-v0.1.0",
            "",
        ] {
            assert!(!valid_tag(bad), "{bad}");
        }
    }

    #[test]
    fn release_pr_refuses_a_missing_token() {
        assert!(release_pr_token(None).is_err());
        assert!(release_pr_token(Some("  ".into())).is_err());
        assert_eq!(release_pr_token(Some("t".into())), Ok("t".into()));
    }

    #[test]
    fn described_commands_never_show_the_token() {
        let mut command = Command::new("release-plz");
        command
            .args(["release-pr", "--output", "json"])
            .env("GIT_TOKEN", "secret-value");
        let shown = describe(&command);
        assert_eq!(shown, "release-plz release-pr --output json");
        assert!(!shown.contains("secret-value"));
    }

    #[test]
    fn bounded_run_times_out_and_captures_stdout() {
        let quick = run_bounded(Command::new("sh").args(["-c", "echo hello"]), GIT_TIMEOUT);
        assert_eq!(quick.exit, Exit::Code(0));
        assert_eq!(quick.stdout.trim(), "hello");
        let slow = run_bounded(
            Command::new("sh").args(["-c", "sleep 5"]),
            Duration::from_millis(400),
        );
        assert_eq!(slow.exit, Exit::TimedOut);
        let flood = format!("head -c {} /dev/zero", OUTPUT_MAX_BYTES.saturating_add(10));
        let large = run_bounded(Command::new("sh").args(["-c", &flood]), GIT_TIMEOUT);
        assert_eq!(large.exit, Exit::OutputTooLarge);
        let missing = run_bounded(&mut Command::new("no-such-program-xtask"), GIT_TIMEOUT);
        assert!(matches!(missing.exit, Exit::NotStarted(_)));
    }
}

//! Release commands: release pull requests and tags through release-plz, binaries through dist.

use std::env;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::app_token::{self, AppCredentials, Repository, APP_ID_VARIABLE, APP_KEY_VARIABLE};
use crate::process::{run_bounded, Captured, Exit};
use std::time::Duration;

const RELEASE_PLZ_TIMEOUT: Duration = Duration::from_secs(600);
const DIST_TIMEOUT: Duration = Duration::from_secs(1800);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(600);
const GIT_TIMEOUT: Duration = Duration::from_secs(120);
const RUSTUP_TIMEOUT: Duration = Duration::from_secs(600);
const REPORT_MAX_LINES: usize = 80;
const ARTIFACTS_MAX: usize = 32;
const TAG_MAX_CHARS: usize = 32;
const RELEASED_PACKAGE: &str = "tycho";
const DRY_RUN_DIR: &str = "target/release-dry-run";
const DISTRIB_DIR: &str = "target/distrib";
const MACOS_TARGETS: [&str; 2] = ["aarch64-apple-darwin", "x86_64-apple-darwin"];
const LINUX_TARGETS: [&str; 1] = ["x86_64-unknown-linux-gnu"];

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
enum HeadTag {
    Tagged(String),
    Untagged,
    Failed(Exit),
    Unrecognised(String),
}

/// The exit code fully partitions the states: zero uploaded every file, anything else failed.
#[derive(Debug, PartialEq, Eq)]
enum UploadOutcome {
    Uploaded(usize),
    Failed(Exit),
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

fn decode_head_tags(exit: Exit, stdout: &str) -> HeadTag {
    if exit != Exit::Code(0) {
        return HeadTag::Failed(exit);
    }
    let versions: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|t| valid_tag(t))
        .collect();
    match versions.as_slice() {
        [] => HeadTag::Untagged,
        [tag] => HeadTag::Tagged((*tag).to_string()),
        _ => HeadTag::Unrecognised(format!("several version tags at HEAD: {versions:?}")),
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

fn release_pr_inputs() -> Result<(AppCredentials, Repository), String> {
    let credentials = app_token::read_credentials(
        env::var(APP_ID_VARIABLE).ok(),
        env::var(APP_KEY_VARIABLE).ok(),
    )?;
    let repository = app_token::read_repository(env::var("GITHUB_REPOSITORY").ok())?;
    Ok((credentials, repository))
}

/// `xtask release-pr`: opens or updates the release pull request with an App installation token.
pub fn release_pr(dry_run: bool) -> i32 {
    if dry_run {
        return release_pr_dry_run();
    }
    let token = match release_pr_inputs()
        .and_then(|(credentials, repository)| app_token::mint(&credentials, &repository))
    {
        Ok(token) => token,
        Err(reason) => {
            eprintln!("xtask release-pr: {reason}");
            return 1;
        }
    };
    let captured = run_bounded(
        release_plz_command(&["release-pr", "--output", "json"], env::vars_os())
            .env("GIT_TOKEN", token.expose()),
        RELEASE_PLZ_TIMEOUT,
    );
    let code = report_release_pr(captured);
    match app_token::revoke(&token) {
        Ok(()) => code,
        Err(reason) => {
            eprintln!("xtask release-pr: {reason}");
            1
        }
    }
}

/// release-plz and the cargo and git processes it starts never see the App id or key.
fn release_plz_command(
    args: &[&str],
    parent: impl IntoIterator<Item = (OsString, OsString)>,
) -> Command {
    let mut command = Command::new("release-plz");
    command
        .args(args)
        .env_clear()
        .envs(app_token::without_app_credentials(parent));
    command
}

fn report_release_pr(captured: Captured) -> i32 {
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

fn remove_dry_run_worktree(root: &Path) -> bool {
    let scratch = root.join(DRY_RUN_DIR);
    if !scratch.exists() {
        return true;
    }
    let path = scratch.to_string_lossy().into_owned();
    let removed = git_in(root, &["worktree", "remove", "--force", &path]);
    if removed.exit != Exit::Code(0) {
        eprintln!(
            "xtask release-pr --dry-run: could not remove {path}: {:?}",
            removed.exit
        );
        return false;
    }
    true
}

/// Runs `release-plz update` in a detached scratch worktree at HEAD and shows what it would change.
fn release_pr_dry_run() -> i32 {
    let root = PathBuf::from(".");
    if !remove_dry_run_worktree(&root) {
        return 1;
    }
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
    if remove_dry_run_worktree(&root) {
        code
    } else {
        1
    }
}

fn dry_run_in(scratch: &Path) -> i32 {
    let mut update = release_plz_command(&["update"], env::vars_os());
    update.current_dir(scratch);
    if let Ok(token) = env::var("GITHUB_TOKEN") {
        update.env("GIT_TOKEN", token);
    }
    let updated = run_bounded(&mut update, RELEASE_PLZ_TIMEOUT);
    print_capped(&updated.stdout);
    let outcome = if updated.exit == Exit::Code(0) {
        proposed_changes(scratch)
    } else {
        DryRunOutcome::Failed(updated.exit)
    };
    match outcome {
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

fn proposed_changes(scratch: &Path) -> DryRunOutcome {
    let staged = git_in(scratch, &["add", "--intent-to-add", "--all"]);
    if staged.exit != Exit::Code(0) {
        return DryRunOutcome::Failed(staged.exit);
    }
    let status = git_in(scratch, &["status", "--porcelain"]);
    let outcome = decode_dry_run(status.exit, &status.stdout);
    if let DryRunOutcome::Proposed(_) = outcome {
        let diff = git_in(scratch, &["diff"]);
        if diff.exit != Exit::Code(0) {
            return DryRunOutcome::Failed(diff.exit);
        }
        print_capped(&diff.stdout);
    }
    outcome
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
        ReleaseOutcome::NothingToRelease => existing_release_at_head(),
        outcome => {
            eprintln!("xtask release: {outcome:?}");
            print_capped(&captured.stdout);
            1
        }
    }
}

/// A rerun of a release commit finds its tag already made; the binaries are rebuilt for it.
fn existing_release_at_head() -> i32 {
    let tags = git_in(Path::new("."), &["tag", "--points-at", "HEAD"]);
    match decode_head_tags(tags.exit, &tags.stdout) {
        HeadTag::Tagged(tag) => {
            println!("xtask release: {tag} already points at this commit; binaries rebuild for it");
            write_step_output("tag", &tag)
        }
        HeadTag::Untagged => {
            println!("xtask release: this commit is not a merged release pull request");
            0
        }
        outcome => {
            eprintln!("xtask release: tags at HEAD {outcome:?}");
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
    if !add_host_targets() {
        return 1;
    }
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

fn add_host_targets() -> bool {
    for target in host_targets() {
        let added = run_bounded(
            Command::new("rustup").args(["target", "add", target]),
            RUSTUP_TIMEOUT,
        );
        if added.exit != Exit::Code(0) {
            eprintln!(
                "xtask release-binaries: rustup target add {target} ended {:?}",
                added.exit
            );
            return false;
        }
    }
    true
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
    fn head_tag_decoder_picks_the_single_version_tag() {
        assert_eq!(
            decode_head_tags(Exit::Code(0), "v0.1.0\n"),
            HeadTag::Tagged("v0.1.0".into())
        );
        assert_eq!(
            decode_head_tags(Exit::Code(0), "checkpoint-1\nv0.2.0\n"),
            HeadTag::Tagged("v0.2.0".into())
        );
        assert_eq!(decode_head_tags(Exit::Code(0), ""), HeadTag::Untagged);
        assert_eq!(
            decode_head_tags(Exit::Code(0), "not-a-version\n"),
            HeadTag::Untagged
        );
        assert_eq!(
            decode_head_tags(Exit::Code(128), ""),
            HeadTag::Failed(Exit::Code(128))
        );
        assert!(matches!(
            decode_head_tags(Exit::Code(0), "v0.1.0\nv0.1.1\n"),
            HeadTag::Unrecognised(_)
        ));
    }

    #[test]
    fn release_plz_never_receives_the_app_credentials() {
        let parent: Vec<(OsString, OsString)> = [
            ("PATH", "/usr/bin"),
            (APP_ID_VARIABLE, "1"),
            (APP_KEY_VARIABLE, "key-material"),
        ]
        .into_iter()
        .map(|(name, value)| (name.into(), value.into()))
        .collect();
        let command = release_plz_command(&["release-pr"], parent);
        let names: Vec<&std::ffi::OsStr> = command.get_envs().map(|(name, _)| name).collect();
        assert_eq!(names, [std::ffi::OsStr::new("PATH")]);
    }

    #[test]
    fn the_step_holding_the_app_key_runs_a_built_binary_not_a_build() {
        let workflow = include_str!("../../.github/workflows/release.yml");
        let lines: Vec<&str> = workflow.lines().collect();
        let key_lines: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.contains(&format!("secrets.{APP_KEY_VARIABLE}")))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(key_lines.len(), 1, "{key_lines:?}");
        let step_run = key_lines
            .first()
            .and_then(|key| lines.get(..*key))
            .and_then(|before| before.iter().rev().find(|line| line.contains("run:")))
            .map(|line| line.trim());
        assert_eq!(step_run, Some("- run: target/debug/xtask release-pr"));
        assert!(workflow.contains("- run: cargo build --locked -p xtask"));
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
}

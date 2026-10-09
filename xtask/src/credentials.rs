//! `xtask check-credentials`: no user token is named in any file git tracks or would track.
//! This file holds the marker list and its fixtures and is not scanned.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::finish;
use crate::process::{run_bounded, Exit};

const MARKERS: [&str; 10] = [
    "personal access token",
    "fine-grained token",
    "classic token",
    "gh auth token",
    "ghp_",
    "gho_",
    "ghu_",
    "ghr_",
    "github_pat_",
    "release_plz_token",
];
const EXCLUDED_PATHS: [&str; 1] = ["xtask/src/credentials.rs"];
const STYLE_PATH: &str = "docs/style.md";
/// The style document's row for this rule names the markers it bans; only that row is exempt.
const STYLE_ROW_PREFIX: &str =
    "| No personal access tokens; a credential is the shortest-lived and narrowest";
const MANDATE_PATH: &str = "docs/mandate.md";
/// Mandate clause 7.4 states the rule in its own words; only these three consecutive lines,
/// exactly as written, are exempt.
const MANDATE_CLAUSE: [&str; 3] = [
    "7.4 Where options differ in security, the station takes the most secure one that does the",
    "work and names the trade-off. No personal access token is used; a credential is the",
    "shortest-lived and narrowest the task allows, issued to the station's own identity.",
];
const LISTED_FILES_MAX: usize = 4096;
const SCANNED_FILE_MAX_BYTES: u64 = 4 << 20;
const GIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Every file git tracks or would track under `base` (ignored files excluded), relative to
/// `base`. A listing over the bound or a git that cannot run is an error, never an empty scan.
fn listed_files(base: &Path) -> Result<Vec<PathBuf>, String> {
    let listed = run_bounded(
        Command::new("git").current_dir(base).args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ]),
        GIT_TIMEOUT,
    );
    if listed.exit != Exit::Code(0) {
        return Err(format!("git ls-files ended {:?}", listed.exit));
    }
    let files: Vec<PathBuf> = listed
        .stdout
        .split('\0')
        .filter(|name| !name.is_empty())
        .map(PathBuf::from)
        .collect();
    if files.len() > LISTED_FILES_MAX {
        return Err(format!(
            "git lists {} files; the limit is {LISTED_FILES_MAX}",
            files.len()
        ));
    }
    Ok(files)
}

/// Lowercased text with each run of whitespace, no-break spaces and `&nbsp;` as one space, and
/// for each byte kept the line it came from, so a marker wrapped across lines still matches.
fn normalized(text: &str) -> (String, Vec<usize>) {
    let lower = text.to_ascii_lowercase().replace("&nbsp;", "\u{a0}");
    let mut kept = String::with_capacity(lower.len());
    let mut lines = Vec::with_capacity(lower.len());
    let mut line = 1_usize;
    let mut in_space = false;
    for character in lower.chars() {
        let source_line = line;
        if character == '\n' {
            line = line.saturating_add(1);
        }
        if character.is_whitespace() {
            if in_space {
                continue;
            }
            in_space = true;
            kept.push(' ');
            lines.push(source_line);
            continue;
        }
        in_space = false;
        kept.push(character);
        for _ in 0..character.len_utf8() {
            lines.push(source_line);
        }
    }
    (kept, lines)
}

/// The one-based line numbers of every place `passage` appears as consecutive whole lines.
fn passage_lines(text: &str, passage: &[&str]) -> Vec<usize> {
    let lines: Vec<&str> = text.lines().collect();
    let mut exempt = Vec::new();
    for (start, window) in lines.windows(passage.len()).enumerate() {
        if window == passage {
            exempt.extend((1..=passage.len()).map(|offset| start.saturating_add(offset)));
        }
    }
    exempt
}

fn credential_defects(path: &Path, text: &str) -> Vec<String> {
    let style = path == Path::new(STYLE_PATH);
    let mandate_exempt = if path == Path::new(MANDATE_PATH) {
        passage_lines(text, &MANDATE_CLAUSE)
    } else {
        Vec::new()
    };
    let exempt_line = |line: usize| {
        let style_row = style
            && text
                .lines()
                .nth(line.saturating_sub(1))
                .is_some_and(|row| row.starts_with(STYLE_ROW_PREFIX));
        style_row || mandate_exempt.contains(&line)
    };
    let (kept, lines) = normalized(text);
    let mut defects = Vec::new();
    for marker in MARKERS {
        for (offset, _) in kept.match_indices(marker) {
            let line = lines.get(offset).copied().unwrap_or(0);
            if !exempt_line(line) {
                defects.push(format!("{}:{line}: `{marker}`", path.display()));
            }
        }
    }
    defects
}

/// Reads a scanned file as text; `None` for a binary file, which carries no prose to check, or a
/// tracked file deleted from the working tree.
fn scanned_text(path: &Path) -> Result<Option<String>, String> {
    let size = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    if size > SCANNED_FILE_MAX_BYTES {
        return Err(format!(
            "{} is larger than {SCANNED_FILE_MAX_BYTES} bytes",
            path.display()
        ));
    }
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(String::from_utf8(bytes).ok())
}

/// The number of text files examined and the defects found under `base`.
fn scan(base: &Path) -> Result<(usize, Vec<String>), String> {
    let files = listed_files(base)?;
    let mut examined = 0_usize;
    let mut defects = Vec::new();
    let scanned = files.iter().filter(|path| {
        !EXCLUDED_PATHS
            .iter()
            .any(|excluded| path.as_path() == Path::new(excluded))
    });
    for relative in scanned {
        match scanned_text(&base.join(relative)) {
            Ok(Some(text)) => {
                examined = examined.saturating_add(1);
                defects.extend(credential_defects(relative, &text));
            }
            Ok(None) => {}
            Err(reason) => defects.push(reason),
        }
    }
    Ok((examined, defects))
}

pub fn check_credentials() -> i32 {
    match scan(Path::new(".")) {
        Ok((examined, defects)) => finish("check-credentials", examined, &defects),
        Err(reason) => {
            eprintln!("xtask check-credentials: {reason}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STYLE_ROW: &str = "| No personal access tokens; a credential is the shortest-lived and narrowest the task allows | `xtask check-credentials` |";

    fn markers_found(path: &str, text: &str) -> Vec<String> {
        credential_defects(Path::new(path), text)
    }

    #[test]
    fn flags_each_marker_in_any_case() {
        let text = "env:\n  TOKEN: ghp_abc\n  OTHER: GITHUB_PAT_11AB\nuse a Personal Access Token\na Fine-Grained Token\nRELEASE_PLZ_TOKEN: x\noauth gho_x user ghu_x refresh ghr_x\na Classic Token\nrun `GH AUTH TOKEN`\n";
        let defects = markers_found(".github/workflows/x.yml", text);
        assert_eq!(defects.len(), 10, "{defects:?}");
        assert!(defects
            .iter()
            .any(|defect| defect.contains("x.yml:2: `ghp_`")));
        assert!(defects
            .iter()
            .any(|defect| defect.contains("x.yml:9: `gh auth token`")));
    }

    #[test]
    fn flags_a_marker_wrapped_across_lines_or_split_by_no_break_spaces() {
        let wrapped = "store a personal\n  access token as a secret\n";
        assert_eq!(
            markers_found("README.md", wrapped),
            ["README.md:1: `personal access token`"]
        );
        let entity = "<td>personal&nbsp;access&NBSP;token</td>\n";
        assert_eq!(markers_found("docs/design.html", entity).len(), 1);
        let no_break = "a fine-grained\u{a0}token\n";
        assert_eq!(markers_found("notes/ledger.md", no_break).len(), 1);
    }

    #[test]
    fn passes_text_that_names_only_app_credentials() {
        let text = "TYCHO_RELEASE_APP_PRIVATE_KEY: ${{ secrets.TYCHO_RELEASE_APP_PRIVATE_KEY }}\nan installation token, ghs_ prefixed\nthe personal\n\naccess list\n";
        assert!(markers_found("docs/process.md", text).is_empty());
    }

    #[test]
    fn exempts_only_the_exact_style_row() {
        let text =
            format!("{STYLE_ROW}\n| store a personal access token | `xtask check-credentials` |\n");
        let defects = markers_found(STYLE_PATH, &text);
        assert_eq!(defects, ["docs/style.md:2: `personal access token`"]);
        assert_eq!(markers_found("docs/process.md", &text).len(), 2);
    }

    #[test]
    fn exempts_only_the_exact_mandate_clause() {
        let clause = MANDATE_CLAUSE.join("\n");
        let mandate =
            format!("7.3 Nothing leaves the agent domain.\n\n{clause}\n\n## 8. Case law\n");
        assert_eq!(markers_found(MANDATE_PATH, &mandate), Vec::<String>::new());
        let elsewhere = format!(
            "{mandate}\n8.9 No personal access token is used; a credential is the shortest-lived.\n"
        );
        assert_eq!(
            markers_found(MANDATE_PATH, &elsewhere),
            ["docs/mandate.md:9: `personal access token`"]
        );
        let middle_line_alone = format!("{}\n", MANDATE_CLAUSE[1]);
        assert_eq!(markers_found(MANDATE_PATH, &middle_line_alone).len(), 1);
        let reworded = clause.replace("is used", "is ever used");
        assert_eq!(markers_found(MANDATE_PATH, &reworded).len(), 1);
        assert_eq!(markers_found("docs/process.md", &mandate).len(), 1);
    }

    fn repository_root() -> &'static Path {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
    }

    #[test]
    fn the_repository_scan_lists_every_tracked_file_and_skips_only_this_one() {
        let files = listed_files(repository_root()).unwrap();
        for expected in [
            "README.md",
            "CLAUDE.md",
            "notes/ledger.md",
            "Cargo.toml",
            "release-plz.toml",
            "lefthook.json",
            ".github/workflows/release.yml",
            "docs/design.html",
            "xtask/src/credentials.rs",
        ] {
            assert!(
                files.iter().any(|path| path == Path::new(expected)),
                "{expected}"
            );
        }
        assert!(!files.iter().any(|path| path.starts_with("target")));
        let (examined, defects) = scan(repository_root()).unwrap();
        assert!(examined > 0);
        assert_eq!(defects, Vec::<String>::new());
    }

    #[test]
    fn a_listing_git_cannot_produce_is_an_error_not_an_empty_scan() {
        assert!(listed_files(Path::new("/no-such-directory-xtask")).is_err());
    }
}

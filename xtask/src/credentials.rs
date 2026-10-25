//! `xtask check-credentials`: no user token is named in any file git tracks or would track.
//! This file holds the marker list and its fixtures and is not scanned.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tycho_types::git_environment::git_command;

use crate::finish_findings;
use crate::process::{Exit, run_bounded};
use crate::sarif::{Finding, Rule};

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
/// Credential prefixes a review comment must never carry onto a pull request: Anthropic keys
/// and OAuth tokens, GitHub installation, user and refresh tokens. Kept here, the one file
/// the scan skips.
pub const POSTED_TEXT_PREFIXES: [&str; 7] = [
    "sk-ant-",
    "ghs_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghr_",
    "github_pat_",
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
/// Characters that render as nothing or as a gap and can split a marker: zero-width space,
/// non-joiner and joiner, word joiner, byte order mark, soft hyphen, and the replacement
/// character a non-UTF-8 byte such as a Latin-1 no-break space decodes to.
const INVISIBLE_SEPARATORS: [char; 7] = [
    '\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}', '\u{ad}', '\u{fffd}',
];
/// HTML spellings of a no-break space, lowercased.
const SPACE_ENTITIES: [&str; 3] = ["&nbsp;", "&#160;", "&#xa0;"];
const RULES: [Rule<'static>; 2] = [
    Rule {
        id: "check-credentials/marker",
        description: "A file names a user token or a personal credential",
    },
    Rule {
        id: "check-credentials/unreadable",
        description: "A listed file could not be read for the credential scan",
    },
];
const LISTED_FILES_MAX: usize = 4096;
const SCANNED_FILE_MAX_BYTES: u64 = 4 << 20;
const GIT_TIMEOUT: Duration = Duration::from_mins(1);

/// Every file git tracks or would track under `base` (ignored files excluded), relative to
/// `base`. A listing over the bound or a git that cannot run is an error, never an empty scan.
fn listed_files(base: &Path) -> Result<Vec<PathBuf>, String> {
    let listed = run_bounded(
        git_command().current_dir(base).args([
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

/// Lowercased text with every whitespace character, invisible separator and HTML no-break
/// space removed, and for each byte kept the line it came from. Markers are compared in the same
/// compact form, so a marker wrapped across lines or split by any separator still matches.
fn compacted(text: &str) -> (String, Vec<usize>) {
    let mut lower = text.to_ascii_lowercase();
    for entity in SPACE_ENTITIES {
        lower = lower.replace(entity, " ");
    }
    let mut kept = String::with_capacity(lower.len());
    let mut lines = Vec::with_capacity(lower.len());
    let mut line = 1_usize;
    for character in lower.chars() {
        let source_line = line;
        if character == '\n' {
            line = line.saturating_add(1);
        }
        if character.is_whitespace() || INVISIBLE_SEPARATORS.contains(&character) {
            continue;
        }
        kept.push(character);
        for _ in 0..character.len_utf8() {
            lines.push(source_line);
        }
    }
    (kept, lines)
}

fn compact_marker(marker: &str) -> String {
    marker.chars().filter(|c| !c.is_whitespace()).collect()
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

/// The one-based column of `marker` on `line` when it appears there unsplit; 1 otherwise,
/// since a marker split across lines or separators has no single column.
fn marker_column(text: &str, line: usize, marker: &str) -> usize {
    text.lines()
        .nth(line.saturating_sub(1))
        .and_then(|row| row.to_ascii_lowercase().find(marker))
        .map_or(1, |index| index.saturating_add(1))
}

fn credential_defects(path: &Path, text: &str) -> Vec<Finding> {
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
    let (kept, lines) = compacted(text);
    let mut defects = Vec::new();
    for marker in MARKERS {
        for (offset, _) in kept.match_indices(compact_marker(marker).as_str()) {
            let line = lines.get(offset).copied().unwrap_or(0);
            if !exempt_line(line) {
                defects.push(Finding::at(
                    path,
                    line,
                    marker_column(text, line, marker),
                    "check-credentials/marker",
                    format!("`{marker}`"),
                ));
            }
        }
    }
    defects
}

/// What a listed file holds for the scan.
#[derive(Debug, PartialEq, Eq)]
enum Scanned {
    Text(String),
    /// Bytes with a NUL: an image or other binary, counted in the summary.
    Binary,
    /// A tracked file deleted from the working tree, or not a regular file.
    Absent,
}

/// Text for any bytes without a NUL; a byte that is not UTF-8 becomes U+FFFD, which the
/// compaction removes, so one stray byte cannot hide a file.
fn decoded(bytes: &[u8]) -> Scanned {
    if bytes.contains(&0) {
        Scanned::Binary
    } else {
        Scanned::Text(String::from_utf8_lossy(bytes).into_owned())
    }
}

fn scanned_text(path: &Path) -> Result<Scanned, String> {
    let size = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => return Ok(Scanned::Absent),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Scanned::Absent),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    if size > SCANNED_FILE_MAX_BYTES {
        return Err(format!(
            "{} is larger than {SCANNED_FILE_MAX_BYTES} bytes",
            path.display()
        ));
    }
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(decoded(&bytes))
}

#[derive(Debug, Default)]
struct ScanReport {
    examined: usize,
    binary: usize,
    defects: Vec<Finding>,
}

fn scan(base: &Path) -> Result<ScanReport, String> {
    let files = listed_files(base)?;
    let mut report = ScanReport::default();
    let scanned = files.iter().filter(|path| {
        !EXCLUDED_PATHS
            .iter()
            .any(|excluded| path.as_path() == Path::new(excluded))
    });
    for relative in scanned {
        match scanned_text(&base.join(relative)) {
            Ok(Scanned::Text(text)) => {
                report.examined = report.examined.saturating_add(1);
                report.defects.extend(credential_defects(relative, &text));
            }
            Ok(Scanned::Binary) => report.binary = report.binary.saturating_add(1),
            Ok(Scanned::Absent) => {}
            Err(reason) => report.defects.push(Finding::at(
                relative,
                1,
                1,
                "check-credentials/unreadable",
                reason,
            )),
        }
    }
    Ok(report)
}

pub fn check_credentials() -> i32 {
    match scan(Path::new(".")) {
        Ok(report) => finish_findings(
            "check-credentials",
            &RULES,
            report.examined,
            &format!(", skipped {} binary files", report.binary),
            &report.defects,
        ),
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
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn flags_each_marker_in_any_case() {
        let text = "env:\n  TOKEN: ghp_abc\n  OTHER: GITHUB_PAT_11AB\nuse a Personal Access Token\na Fine-Grained Token\nRELEASE_PLZ_TOKEN: x\noauth gho_x user ghu_x refresh ghr_x\na Classic Token\nrun `GH AUTH TOKEN`\n";
        let defects = markers_found(".github/workflows/x.yml", text);
        assert_eq!(defects.len(), 10, "{defects:?}");
        assert!(
            defects
                .iter()
                .any(|defect| defect.contains("x.yml:2:10: check-credentials/marker: `ghp_`"))
        );
        assert!(
            defects
                .iter()
                .any(|defect| defect
                    .contains("x.yml:9:6: check-credentials/marker: `gh auth token`"))
        );
    }

    #[test]
    fn flags_a_marker_wrapped_across_lines_or_split_by_no_break_spaces() {
        let wrapped = "store a personal\n  access token as a secret\n";
        assert_eq!(
            markers_found("README.md", wrapped),
            ["README.md:1:1: check-credentials/marker: `personal access token`"]
        );
        let entity = "<td>personal&nbsp;access&NBSP;token</td>\n";
        assert_eq!(markers_found("docs/design.html", entity).len(), 1);
        let no_break = "a fine-grained\u{a0}token\n";
        assert_eq!(markers_found("notes/ledger.md", no_break).len(), 1);
    }

    #[test]
    fn flags_a_marker_split_by_each_invisible_separator_or_entity() {
        for separator in INVISIBLE_SEPARATORS {
            let text = format!("gh{separator}p_abc and personal{separator}access token\n");
            assert_eq!(markers_found("README.md", &text).len(), 2, "{separator:?}");
        }
        for entity in ["&nbsp;", "&#160;", "&#xa0;", "&#XA0;"] {
            let text = format!("<td>fine-grained{entity}token</td>\n");
            assert_eq!(
                markers_found("docs/design.html", &text).len(),
                1,
                "{entity}"
            );
        }
    }

    #[test]
    fn a_latin_1_byte_does_not_hide_a_file() {
        let latin_1 = b"use a\xa0ghp_abc token\nand a personal\xa0access token\n";
        let Scanned::Text(text) = decoded(latin_1) else {
            panic!("a Latin-1 file is text");
        };
        assert_eq!(
            markers_found("notes/ledger.md", &text),
            [
                "notes/ledger.md:2:1: check-credentials/marker: `personal access token`",
                "notes/ledger.md:1:9: check-credentials/marker: `ghp_`"
            ]
        );
        assert_eq!(decoded(b"\x89PNG\r\n\x1a\n\0\0"), Scanned::Binary);
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
        assert_eq!(
            defects,
            ["docs/style.md:2:11: check-credentials/marker: `personal access token`"]
        );
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
            ["docs/mandate.md:9:8: check-credentials/marker: `personal access token`"]
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
        crate::refuse_hook_environment();
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
        let report = scan(repository_root()).unwrap();
        assert!(report.examined > 0);
        assert!(report.binary > 0, "the committed figure PNGs are binary");
        assert_eq!(report.defects, Vec::<Finding>::new());
    }

    #[test]
    fn a_listing_git_cannot_produce_is_an_error_not_an_empty_scan() {
        assert!(listed_files(Path::new("/no-such-directory-xtask")).is_err());
    }
}

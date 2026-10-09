//! `xtask check-credentials`: no user token is named anywhere the station's code, configuration
//! or documents live. This file holds the marker list and its fixtures and is not scanned.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{finish, WALK_MAX_DEPTH, WALK_MAX_FILES};

const SCAN_ROOTS: [&str; 5] = [".github", "docs", "mise.toml", "xtask/src", "crates"];
const MARKERS: [&str; 5] = [
    "personal access token",
    "fine-grained token",
    "ghp_",
    "github_pat_",
    "release_plz_token",
];
const SELF_PATH: &str = "xtask/src/credentials.rs";
const STYLE_PATH: &str = "docs/style.md";
/// The style document's row for this rule names the markers it bans.
const STYLE_ROW_MARKER: &str = "check-credentials";
const SCANNED_FILE_MAX_BYTES: u64 = 4 << 20;

/// Every regular file under `roots`, which may name files or directories relative to `base`;
/// paths come back relative to `base`. Exceeding a bound is an error, never a truncation.
fn listed_files(base: &Path, roots: &[&str]) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = roots.iter().map(|r| (PathBuf::from(r), 0)).collect();
    while let Some((relative, depth)) = stack.pop() {
        let path = base.join(&relative);
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            return Err(format!("{} cannot be read", relative.display()));
        };
        if metadata.is_file() {
            found.push(relative);
        } else if metadata.is_dir() {
            if depth >= WALK_MAX_DEPTH {
                return Err(format!(
                    "{} is deeper than {WALK_MAX_DEPTH}",
                    relative.display()
                ));
            }
            let entries =
                fs::read_dir(&path).map_err(|e| format!("{}: {e}", relative.display()))?;
            for entry in entries {
                let entry = entry.map_err(|e| format!("{}: {e}", relative.display()))?;
                stack.push((relative.join(entry.file_name()), depth.saturating_add(1)));
                if stack.len().saturating_add(found.len()) > WALK_MAX_FILES {
                    return Err(format!("more than {WALK_MAX_FILES} entries to scan"));
                }
            }
        }
    }
    Ok(found)
}

fn credential_defects(path: &Path, text: &str) -> Vec<String> {
    let style = path == Path::new(STYLE_PATH);
    let mut defects = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        if style && lower.contains(STYLE_ROW_MARKER) {
            continue;
        }
        for marker in MARKERS {
            if lower.contains(marker) {
                defects.push(format!(
                    "{}:{}: `{marker}`",
                    path.display(),
                    index.saturating_add(1)
                ));
            }
        }
    }
    defects
}

/// Reads a scanned file as text; `None` for a binary file, which carries no prose to check.
fn scanned_text(path: &Path) -> Result<Option<String>, String> {
    let size = fs::metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .len();
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
    let files = listed_files(base, &SCAN_ROOTS)?;
    let mut examined = 0_usize;
    let mut defects = Vec::new();
    for relative in files.iter().filter(|p| p.as_path() != Path::new(SELF_PATH)) {
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

    #[test]
    fn flags_each_marker_in_any_case() {
        let text = "env:\n  TOKEN: ghp_abc\n  OTHER: GITHUB_PAT_11AB\nuse a Personal Access Token\na Fine-Grained Token\nRELEASE_PLZ_TOKEN: x\n";
        let defects = credential_defects(Path::new(".github/workflows/x.yml"), text);
        assert_eq!(defects.len(), 5, "{defects:?}");
        assert!(defects
            .first()
            .is_some_and(|defect| defect.contains("x.yml:2:")));
    }

    #[test]
    fn passes_text_that_names_only_app_credentials() {
        let text = "TYCHO_RELEASE_APP_PRIVATE_KEY: ${{ secrets.TYCHO_RELEASE_APP_PRIVATE_KEY }}\nan installation token, ghs_ prefixed\n";
        assert!(credential_defects(Path::new("docs/process.md"), text).is_empty());
    }

    #[test]
    fn exempts_only_the_style_row_that_names_this_check() {
        let text = "| No personal access tokens | `xtask check-credentials` |\n| store a personal access token | review |\n";
        let defects = credential_defects(Path::new(STYLE_PATH), text);
        assert_eq!(defects.len(), 1, "{defects:?}");
        assert!(defects
            .first()
            .is_some_and(|defect| defect.contains("style.md:2:")));
        let elsewhere = credential_defects(Path::new("docs/process.md"), text);
        assert_eq!(elsewhere.len(), 2, "{elsewhere:?}");
    }

    fn repository_root() -> &'static Path {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
    }

    #[test]
    fn the_repository_scan_covers_every_root_and_skips_only_this_file() {
        let files = listed_files(repository_root(), &SCAN_ROOTS).unwrap();
        for root in SCAN_ROOTS {
            assert!(files.iter().any(|path| path.starts_with(root)), "{root}");
        }
        assert!(files.iter().any(|path| path == Path::new(SELF_PATH)));
        let (examined, defects) = scan(repository_root()).unwrap();
        assert!(examined > 0);
        assert_eq!(defects, Vec::<String>::new());
    }

    #[test]
    fn a_missing_root_is_an_error_not_an_empty_scan() {
        assert!(listed_files(repository_root(), &["no-such-directory-xtask"]).is_err());
    }
}

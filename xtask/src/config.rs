//! `config-export` and `check-config`: the CUE under `config/` and `schemas/`, vetted and
//! exported to `config/export`, with a content hash beside each value export.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::process::{run_bounded, Exit};

const CONFIG_DIR: &str = "config";
const CONFIG_SCHEMA: &str = "config/schema.cue";
const MANDATE_DOC: &str = "docs/mandate.md";
const EXPORT_DIR: &str = "config/export";
const SCHEMA_EXPORT_SUBDIR: &str = "schema";
const SCHEMAS_DIR: &str = "schemas";
const CHECK_DIR: &str = "target/check-config";
const VALUES: [&str; 4] = ["adapters", "mandate", "routing", "thresholds"];
const SCHEMAS: [(&str, &str); 3] = [
    ("envelope", "#Envelope"),
    ("task_packet", "#TaskPacketPayload"),
    ("exit_state", "#ExitState"),
];
const CUE_TIMEOUT: Duration = Duration::from_secs(120);
const EXPORT_DIR_MAX_FILES: usize = 256;
const EXPORT_DIR_MAX_DEPTH: usize = 4;
const SCHEMA_SOURCES_MAX: usize = 64;

/// What one `cue` invocation came to; anything outside the known shapes is unrecognised.
#[derive(Debug, PartialEq, Eq)]
pub enum CueOutcome {
    Clean(Vec<u8>),
    /// cue printed its report on stderr, which the runner passes through.
    Rejected,
    CouldNotRun(String),
    Unrecognised(String),
}

impl CueOutcome {
    fn describe(&self) -> String {
        match self {
            Self::Clean(_) => "clean".to_string(),
            Self::Rejected => "rejected; the report is above".to_string(),
            Self::CouldNotRun(reason) => format!("could not run: {reason}"),
            Self::Unrecognised(what) => format!("unrecognised result: {what}"),
        }
    }
}

/// `cue` exits 0 when clean and 1 with a report when it refuses.
pub fn decode(exit: &Exit, stdout: String) -> CueOutcome {
    match exit {
        Exit::Code(0) => CueOutcome::Clean(stdout.into_bytes()),
        Exit::Code(1) => CueOutcome::Rejected,
        Exit::NotStarted(reason) => CueOutcome::CouldNotRun(reason.clone()),
        other => CueOutcome::Unrecognised(format!("{other:?}")),
    }
}

fn cue(args: &[&str]) -> CueOutcome {
    let captured = run_bounded(Command::new("cue").args(args), CUE_TIMEOUT);
    decode(&captured.exit, captured.stdout)
}

fn cue_clean(args: &[&str]) -> Result<Vec<u8>, String> {
    match cue(args) {
        CueOutcome::Clean(stdout) => Ok(stdout),
        other => Err(format!("cue {}: {}", args.join(" "), other.describe())),
    }
}

fn schema_sources() -> Result<Vec<String>, String> {
    let entries =
        fs::read_dir(SCHEMAS_DIR).map_err(|error| format!("cannot list {SCHEMAS_DIR}: {error}"))?;
    let mut sources: Vec<String> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "cue"))
        .take(SCHEMA_SOURCES_MAX.saturating_add(1))
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    sources.sort();
    if sources.is_empty() || sources.len() > SCHEMA_SOURCES_MAX {
        return Err(format!(
            "{} .cue files in {SCHEMAS_DIR}; expected 1..={SCHEMA_SOURCES_MAX}",
            sources.len()
        ));
    }
    Ok(sources)
}

#[must_use]
pub fn sha256_line(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut line = Vec::with_capacity(digest.len().saturating_mul(2).saturating_add(1));
    for byte in digest {
        line.extend(
            [byte >> 4, byte & 0x0f]
                .iter()
                .filter_map(|nibble| HEX.get(usize::from(*nibble))),
        );
    }
    line.push(b'\n');
    line
}

/// One exported file, by its path under the export directory.
#[derive(Debug)]
struct Export {
    relative: PathBuf,
    bytes: Vec<u8>,
}

fn value_exports() -> Result<Vec<Export>, String> {
    let mut exports = Vec::new();
    for name in VALUES {
        let source = format!("config/{name}.cue");
        cue_clean(&["vet", "-c", CONFIG_SCHEMA, &source])?;
        let json = cue_clean(&[
            "export",
            CONFIG_SCHEMA,
            &source,
            "-e",
            name,
            "--out",
            "json",
        ])?;
        exports.push(Export {
            relative: PathBuf::from(format!("{name}.sha256")),
            bytes: sha256_line(&json),
        });
        exports.push(Export {
            relative: PathBuf::from(format!("{name}.json")),
            bytes: json,
        });
    }
    Ok(exports)
}

fn schema_exports() -> Result<Vec<Export>, String> {
    let sources = schema_sources()?;
    let mut vet: Vec<&str> = vec!["vet"];
    vet.extend(sources.iter().map(String::as_str));
    cue_clean(&vet)?;
    let mut exports = Vec::new();
    for (name, definition) in SCHEMAS {
        let mut args: Vec<&str> = vec!["def", "--out", "jsonschema", "-e", definition];
        args.extend(sources.iter().map(String::as_str));
        exports.push(Export {
            relative: Path::new(SCHEMA_EXPORT_SUBDIR).join(format!("{name}.json")),
            bytes: cue_clean(&args)?,
        });
    }
    Ok(exports)
}

fn render() -> Result<Vec<Export>, String> {
    let mut exports = value_exports()?;
    exports.extend(schema_exports()?);
    Ok(exports)
}

#[expect(
    clippy::disallowed_methods,
    reason = "exports are written inside the developer's checkout"
)]
fn write_all(root: &Path, exports: &[Export]) -> Result<(), String> {
    for export in exports {
        let path = root.join(&export.relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        fs::write(&path, &export.bytes)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    }
    Ok(())
}

pub fn config_export() -> i32 {
    let written = render().and_then(|exports| {
        write_all(Path::new(EXPORT_DIR), &exports)?;
        Ok(exports.len())
    });
    match written {
        Ok(count) => {
            println!("xtask config-export: wrote {count} files under {EXPORT_DIR}");
            i32::from(count == 0)
        }
        Err(error) => {
            eprintln!("xtask config-export: {error}");
            1
        }
    }
}

/// Every entry under the export directory, as a path relative to it; a directory is walked
/// with an explicit bounded stack, anything that is neither file nor directory is a defect.
fn checked_in_files() -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    let mut stack = vec![(PathBuf::new(), 0_usize)];
    while let Some((relative, depth)) = stack.pop() {
        let dir = Path::new(EXPORT_DIR).join(&relative);
        let entries = fs::read_dir(&dir)
            .map_err(|error| format!("cannot list {}: {error}", dir.display()))?;
        for entry in entries.flatten() {
            if found.len() >= EXPORT_DIR_MAX_FILES {
                return Err(format!(
                    "more than {EXPORT_DIR_MAX_FILES} entries under {EXPORT_DIR}"
                ));
            }
            let path = relative.join(entry.file_name());
            let kind = entry
                .file_type()
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if kind.is_dir() && depth < EXPORT_DIR_MAX_DEPTH {
                stack.push((path, depth.saturating_add(1)));
            } else {
                found.push(path);
            }
        }
    }
    Ok(found)
}

/// `.cue` files under `config/` that neither the schema nor a value export accounts for.
fn stray_sources(names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter(|name| {
            let path = Path::new(name.as_str());
            let is_cue = path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("cue"));
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("");
            is_cue && stem != "schema" && !VALUES.contains(&stem)
        })
        .map(|name| format!("config/{name} is neither schema.cue nor a value file"))
        .collect()
}

fn config_sources() -> Result<Vec<String>, String> {
    let entries =
        fs::read_dir(CONFIG_DIR).map_err(|error| format!("cannot list {CONFIG_DIR}: {error}"))?;
    let names: Vec<String> = entries
        .flatten()
        .take(EXPORT_DIR_MAX_FILES.saturating_add(1))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    if names.len() > EXPORT_DIR_MAX_FILES {
        return Err(format!(
            "more than {EXPORT_DIR_MAX_FILES} entries in {CONFIG_DIR}"
        ));
    }
    Ok(names)
}

/// The numbered clauses of the mandate: lines that start with `<article>.<clause> `.
fn clause_ids_in(text: &str) -> Vec<String> {
    let mut ids: Vec<String> = text
        .lines()
        .filter_map(|line| line.split_once(' ').map(|(head, _)| head))
        .filter(|head| {
            head.split_once('.').is_some_and(|(article, clause)| {
                !article.is_empty()
                    && !clause.is_empty()
                    && article.bytes().all(|b| b.is_ascii_digit())
                    && clause.bytes().all(|b| b.is_ascii_digit())
            })
        })
        .map(str::to_string)
        .collect();
    ids.sort();
    ids
}

fn clause_defects(mandate_export: &[u8]) -> Vec<String> {
    let document = match fs::read_to_string(MANDATE_DOC) {
        Ok(text) => clause_ids_in(&text),
        Err(error) => return vec![format!("cannot read {MANDATE_DOC}: {error}")],
    };
    let mut mapped: Vec<String> = serde_json::from_slice::<serde_json::Value>(mandate_export)
        .ok()
        .and_then(|value| {
            value
                .get("clauses")?
                .as_object()
                .map(|clauses| clauses.keys().cloned().collect())
        })
        .unwrap_or_default();
    mapped.sort();
    if document.is_empty() || document != mapped {
        return vec![format!(
            "{MANDATE_DOC} numbers {} clauses and config/mandate.cue maps {}; the ids must match",
            document.len(),
            mapped.len()
        )];
    }
    Vec::new()
}

fn drift(fresh: &Path, exports: &[Export]) -> Vec<String> {
    let mut defects = Vec::new();
    for export in exports {
        let checked_in = Path::new(EXPORT_DIR).join(&export.relative);
        let regenerated = fs::read(fresh.join(&export.relative)).ok();
        match fs::read(&checked_in) {
            Ok(bytes) if Some(&bytes) == regenerated.as_ref() => {}
            Ok(_) => defects.push(format!(
                "{} differs from a fresh export; run `cargo run -q -p xtask -- config-export`",
                checked_in.display()
            )),
            Err(error) => defects.push(format!("{}: {error}", checked_in.display())),
        }
    }
    let checked_in = match checked_in_files() {
        Ok(files) => files,
        Err(error) => {
            defects.push(error);
            Vec::new()
        }
    };
    match config_sources() {
        Ok(names) => defects.extend(stray_sources(&names)),
        Err(error) => defects.push(error),
    }
    if let Some(mandate) = exports
        .iter()
        .find(|export| export.relative == Path::new("mandate.json"))
    {
        defects.extend(clause_defects(&mandate.bytes));
    }
    for relative in checked_in {
        if !exports.iter().any(|export| export.relative == relative) {
            defects.push(format!(
                "{} is not produced by any export",
                Path::new(EXPORT_DIR).join(relative).display()
            ));
        }
    }
    defects
}

pub fn check_config() -> i32 {
    let fresh = Path::new(CHECK_DIR);
    let exports = match render().and_then(|exports| {
        write_all(fresh, &exports)?;
        Ok(exports)
    }) {
        Ok(exports) => exports,
        Err(error) => {
            eprintln!("xtask check-config: {error}");
            return 1;
        }
    };
    super::finish("check-config", exports.len(), &drift(fresh, &exports))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEF_EXIT_STATE: &str = include_str!("../fixtures/cue_def_exit_state.json");

    #[test]
    fn decodes_a_captured_export_as_clean() {
        let outcome = decode(&Exit::Code(0), DEF_EXIT_STATE.to_string());
        assert_eq!(
            outcome,
            CueOutcome::Clean(DEF_EXIT_STATE.as_bytes().to_vec())
        );
    }

    #[test]
    fn decodes_exit_one_as_rejected_and_a_failed_start_as_could_not_run() {
        assert_eq!(decode(&Exit::Code(1), String::new()), CueOutcome::Rejected);
        assert!(matches!(
            decode(&Exit::NotStarted("no cue".to_string()), String::new()),
            CueOutcome::CouldNotRun(_)
        ));
    }

    #[test]
    fn every_other_end_is_unrecognised() {
        for exit in [
            Exit::Code(2),
            Exit::Signal,
            Exit::TimedOut,
            Exit::OutputTooLarge,
            Exit::OutputUnreadable,
            Exit::OutputStillOpen,
        ] {
            let outcome = decode(&exit, DEF_EXIT_STATE.to_string());
            assert!(
                matches!(outcome, CueOutcome::Unrecognised(_)),
                "{exit:?}: {outcome:?}"
            );
        }
    }

    #[test]
    fn a_cue_file_outside_the_schema_and_the_values_is_stray() {
        let names: Vec<String> = [
            "schema.cue",
            "routing.cue",
            "export",
            "notes.cue",
            "old.cue.bak",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(
            stray_sources(&names),
            vec!["config/notes.cue is neither schema.cue nor a value file".to_string()]
        );
    }

    #[test]
    fn clause_ids_come_from_numbered_lines_only() {
        let text = "## 14. Amendment\n\n14.5 Thresholds are set.\nsee 1.2 above\n15.4 A check.\n";
        assert_eq!(
            clause_ids_in(text),
            vec!["14.5".to_string(), "15.4".to_string()]
        );
    }

    #[test]
    fn hash_line_is_lowercase_hex_and_a_newline() {
        let line = sha256_line(b"");
        assert_eq!(
            line,
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        );
    }
}

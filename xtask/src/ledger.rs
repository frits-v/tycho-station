//! `check-ledger`: the ledger's digest and its monthly archives agree, and every function a
//! row of either names as its enforcement exists in the sources.
//!
//! `notes/ledger.md` is the digest: one row per rule, each linking the full rows it stands
//! for in `notes/ledger/<year>-<month>.md`. A link is `[<text>][<year>-<month>]`, a reference
//! to that month's file, and resolves when its text opens the Rule cell of exactly one row of
//! that file and ends at a word boundary there. Every archive row is the target of exactly one
//! link, the first link of a digest row targets a row of the digest row's date, and every
//! archive row is dated in its file's month. Every backticked span of a digest row's Enforced
//! by cell is a span, or a whole run of `::` segments of a span, in the Enforced by cell of a
//! full row it links, so a rename corrected in the full row cannot leave
//! the digest naming what is gone. What the check cannot see is whether the digest's
//! rule says what the full row says; that is for review. The digest is refused past
//! `DIGEST_MAX_BYTES`, so it stays a digest.
//!
//! A name is a backticked span whose last `::` segment is snake case, longer than twelve
//! characters and holds an underscore, taken when the span is a Rust path (every segment snake
//! case, not starting with `std`) or, bare, when it holds at least three underscores. Test
//! names here read as sentences of four words or more; a bare span with fewer is in practice a
//! wire value, a lint, a GitHub event or a token claim, which names nothing in the sources. A
//! name resolves to a `fn` or `mod` of that name, or a `.rs` file of that stem, under `crates/`
//! or `xtask/`. A name the ledger cites that lives outside the repository, or that a row names
//! because it was deleted, is listed with its reason in `notes/ledger-names-elsewhere.txt`; an
//! entry there that no row of the digest or an archive cites, or that the sources define, is
//! itself a defect.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::sarif::Finding;

pub const LEDGER: &str = "notes/ledger.md";
pub const ARCHIVE_DIR: &str = "notes/ledger";
pub const ELSEWHERE: &str = "notes/ledger-names-elsewhere.txt";
/// Files larger than this are refused rather than read in part.
pub const LEDGER_MAX_BYTES: u64 = 1024 * 1024;
/// The digest is loaded into every session; past this it is a defect, and rows that state one
/// rule are merged into one digest row before the bound is raised.
pub const DIGEST_MAX_BYTES: usize = 24 * 1024;
/// More entries than this in the archive directory is an error, not a partial read.
pub const ARCHIVE_ENTRIES_MAX: usize = 240;
const NAME_MIN_CHARS: usize = 13;
const BARE_UNDERSCORES_MIN: usize = 3;
const DIGEST_COLUMNS: usize = 4;
const ARCHIVE_COLUMNS: usize = 3;
/// The most archive rows one digest row links.
const LINKS_MAX: usize = 16;

/// A ledger file and its text, named by its path from the repository root.
#[derive(Debug, Clone)]
pub struct Source {
    pub path: String,
    pub text: String,
}

/// A name a row cites, where it is cited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Citation {
    pub path: String,
    pub line: usize,
    pub name: String,
}

/// What the check read in one ledger file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Examined {
    pub path: String,
    pub rows: usize,
    pub names: usize,
}

fn snake(word: &str) -> bool {
    let mut characters = word.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && characters.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The name a backticked span cites, if it cites one.
#[must_use]
pub fn cited_name(span: &str) -> Option<&str> {
    let segments: Vec<&str> = span.split("::").collect();
    let (last, path) = segments.split_last()?;
    if !snake(last) || last.len() < NAME_MIN_CHARS || !last.contains('_') {
        return None;
    }
    let taken = if path.is_empty() {
        last.matches('_').count() >= BARE_UNDERSCORES_MIN
    } else {
        path.first() != Some(&"std") && path.iter().all(|segment| snake(segment))
    };
    taken.then_some(last)
}

/// Every name a ledger file cites, with its line, in order.
#[must_use]
pub fn cited_names(source: &Source) -> Vec<Citation> {
    let mut found = Vec::new();
    for (index, line) in source.text.lines().enumerate() {
        for (position, span) in line.split('`').enumerate() {
            if position % 2 == 1
                && let Some(name) = cited_name(span)
            {
                found.push(Citation {
                    path: source.path.clone(),
                    line: index.saturating_add(1),
                    name: name.to_string(),
                });
            }
        }
    }
    found
}

/// The `fn` and `mod` names a Rust source defines.
#[must_use]
pub fn defined_names(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in source.lines() {
        let words: Vec<&str> = line
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|word| !word.is_empty())
            .collect();
        for pair in words.windows(2) {
            if let [keyword, name] = pair
                && (*keyword == "fn" || *keyword == "mod")
            {
                names.insert((*name).to_string());
            }
        }
    }
    names
}

/// The names `notes/ledger-names-elsewhere.txt` lists, one per line before `#`.
#[must_use]
pub fn elsewhere_names(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let name = line.split('#').next().unwrap_or("").trim();
            (!name.is_empty()).then(|| (index.saturating_add(1), name.to_string()))
        })
        .collect()
}

/// The defects: cited names nothing defines and the list does not hold, and listed names
/// that no row cites or that the sources define.
#[must_use]
pub fn name_defects(
    cited: &[Citation],
    defined: &BTreeSet<String>,
    elsewhere: &[(usize, String)],
) -> Vec<Finding> {
    let listed: BTreeSet<&str> = elsewhere.iter().map(|(_, name)| name.as_str()).collect();
    let mut defects: Vec<Finding> = cited
        .iter()
        .filter(|citation| {
            !defined.contains(&citation.name) && !listed.contains(citation.name.as_str())
        })
        .map(|citation| {
            Finding::at(
                Path::new(&citation.path),
                citation.line,
                1,
                "check-ledger/undefined",
                format!(
                    "`{}` is cited as enforcement, but no fn, mod or file defines it",
                    citation.name
                ),
            )
        })
        .collect();
    let cited_set: BTreeSet<&str> = cited
        .iter()
        .map(|citation| citation.name.as_str())
        .collect();
    for (line, name) in elsewhere {
        let why = if !cited_set.contains(name.as_str()) {
            Some("no ledger row cites it")
        } else if defined.contains(name) {
            Some("the sources define it")
        } else {
            None
        };
        if let Some(why) = why {
            defects.push(Finding::at(
                Path::new(ELSEWHERE),
                *line,
                1,
                "check-ledger/stale-exception",
                format!("`{name}` is listed as defined elsewhere, but {why}"),
            ));
        }
    }
    defects
}

/// A dated row of a ledger table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row<'a> {
    pub line: usize,
    pub date: &'a str,
    /// The cells after the date.
    pub cells: Vec<&'a str>,
}

/// One line of a ledger file, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableLine<'a> {
    /// A line that does not start with `|`: a heading, prose, a link definition or a blank.
    Outside,
    Header,
    Separator,
    Row(Row<'a>),
    /// A line that starts with `|` and is none of the above; never usable.
    Unrecognised,
}

fn is_date(text: &str) -> bool {
    text.len() == 10
        && text.char_indices().all(|(position, c)| {
            if position == 4 || position == 7 {
                c == '-'
            } else {
                c.is_ascii_digit()
            }
        })
}

/// Decodes one line of a table with `columns` columns, the date first.
#[must_use]
pub fn table_line(index: usize, line: &str, columns: usize) -> TableLine<'_> {
    if !line.starts_with('|') {
        return TableLine::Outside;
    }
    let Some(inner) = line
        .strip_prefix("| ")
        .and_then(|rest| rest.strip_suffix(" |"))
    else {
        return if line.starts_with("|-") && line.chars().all(|c| c == '|' || c == '-') {
            TableLine::Separator
        } else {
            TableLine::Unrecognised
        };
    };
    let cells: Vec<&str> = inner.split(" | ").collect();
    if cells.len() != columns {
        return TableLine::Unrecognised;
    }
    match cells.split_first() {
        Some((&"Date", _)) => TableLine::Header,
        Some((date, rest)) if is_date(date) => TableLine::Row(Row {
            line: index.saturating_add(1),
            date,
            cells: rest.to_vec(),
        }),
        _ => TableLine::Unrecognised,
    }
}

fn shape(path: &str, line: usize, message: String) -> Finding {
    Finding::at(Path::new(path), line, 1, "check-ledger/shape", message)
}

/// The dated rows of a ledger file, and a defect for each table line that is not one.
fn table_rows(source: &Source, columns: usize) -> (Vec<Row<'_>>, Vec<Finding>) {
    let mut rows = Vec::new();
    let mut defects = Vec::new();
    for (index, line) in source.text.lines().enumerate() {
        match table_line(index, line, columns) {
            TableLine::Row(row) => rows.push(row),
            TableLine::Unrecognised => defects.push(shape(
                &source.path,
                index.saturating_add(1),
                format!("a table line that is not a {columns}-column dated row"),
            )),
            TableLine::Outside | TableLine::Header | TableLine::Separator => {}
        }
    }
    (rows, defects)
}

/// A digest row's link to an archive row: its text and the month file it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link<'a> {
    pub text: &'a str,
    pub month: &'a str,
}

/// The links of an Archive cell, `[text][month]` separated by `, `; `None` when the cell
/// holds anything else or more than `LINKS_MAX` links.
#[must_use]
pub fn links(cell: &str) -> Option<Vec<Link<'_>>> {
    let mut found = Vec::new();
    let mut rest = cell;
    for _ in 0..LINKS_MAX {
        if rest.is_empty() {
            break;
        }
        if !found.is_empty() {
            rest = rest.strip_prefix(", ")?;
        }
        let (text, after) = rest.strip_prefix('[')?.split_once("][")?;
        let (month, after) = after.split_once(']')?;
        if text.is_empty() || text.contains('[') || text.contains(']') {
            return None;
        }
        found.push(Link { text, month });
        rest = after;
    }
    rest.is_empty().then_some(found)
}

/// The month an archive file is for, from a name `<year>-<month>.md`.
#[must_use]
pub fn archive_month(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    let month = name.strip_suffix(".md")?;
    (month.len() == 7 && is_date(&format!("{month}-01"))).then_some(month)
}

/// Whether `text` opens `rule` and ends there at a word boundary.
#[must_use]
pub fn opens(rule: &str, text: &str) -> bool {
    rule.strip_prefix(text)
        .is_some_and(|rest| !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
}

/// An archive file's rows, keyed by its month.
struct Archive<'a> {
    path: &'a str,
    rows: Vec<Row<'a>>,
}

fn definition_defects(digest: &Source, months: &BTreeMap<&str, Archive<'_>>) -> Vec<Finding> {
    let mut defined = BTreeSet::new();
    let mut defects = Vec::new();
    for (index, line) in digest.text.lines().enumerate() {
        let Some((label, target)) = line
            .strip_prefix('[')
            .and_then(|rest| rest.split_once("]: "))
        else {
            continue;
        };
        if target == format!("ledger/{label}.md") && months.contains_key(label) {
            defined.insert(label.to_string());
        } else {
            defects.push(shape(
                &digest.path,
                index.saturating_add(1),
                format!(
                    "`[{label}]: {target}` does not name an archive file as `ledger/{label}.md`"
                ),
            ));
        }
    }
    for month in months.keys() {
        if !defined.contains(*month) {
            defects.push(shape(
                &digest.path,
                1,
                format!("no definition `[{month}]: ledger/{month}.md` for the {month} archive"),
            ));
        }
    }
    defects
}

fn link_defect(path: &str, line: usize, message: String) -> Finding {
    Finding::at(Path::new(path), line, 1, "check-ledger/link", message)
}

/// Resolves one link of the digest row at `row`; on success, the archive row's index.
fn resolve(
    digest: &Source,
    row: &Row<'_>,
    link: &Link<'_>,
    months: &BTreeMap<&str, Archive<'_>>,
) -> Result<(String, usize), Finding> {
    let Some(archive) = months.get(link.month) else {
        return Err(link_defect(
            &digest.path,
            row.line,
            format!("`[{}][{}]` names no archive file", link.text, link.month),
        ));
    };
    let matched: Vec<usize> = archive
        .rows
        .iter()
        .enumerate()
        .filter(|(_, target)| {
            target
                .cells
                .first()
                .is_some_and(|rule| opens(rule, link.text))
        })
        .map(|(index, _)| index)
        .collect();
    match matched.as_slice() {
        [index] => Ok((link.month.to_string(), *index)),
        [] => Err(link_defect(
            &digest.path,
            row.line,
            format!("`{}` opens no row of {}", link.text, archive.path),
        )),
        several => Err(link_defect(
            &digest.path,
            row.line,
            format!(
                "`{}` opens {} rows of {}; a link names one",
                link.text,
                several.len(),
                archive.path
            ),
        )),
    }
}

/// The digest lines that link each archive row, keyed by month and the row's index.
type Linked = BTreeMap<(String, usize), Vec<usize>>;

/// Each archive row's digest lines, and the defects of the digest's links.
fn digest_links(
    digest: &Source,
    rows: &[Row<'_>],
    months: &BTreeMap<&str, Archive<'_>>,
) -> (Linked, Vec<Finding>) {
    let mut linked = Linked::new();
    let mut defects = Vec::new();
    for row in rows {
        let cell = row.cells.last().copied().unwrap_or("");
        let Some(found) = links(cell).filter(|found| !found.is_empty()) else {
            defects.push(link_defect(
                &digest.path,
                row.line,
                format!(
                    "an Archive cell that is not 1 to {LINKS_MAX} links `[text][<year>-<month>]`"
                ),
            ));
            continue;
        };
        let mut targets = Vec::new();
        for (position, link) in found.iter().enumerate() {
            match resolve(digest, row, link, months) {
                Ok(key) => {
                    let target = months
                        .get(key.0.as_str())
                        .and_then(|archive| archive.rows.get(key.1));
                    targets.extend(target.and_then(|target| target.cells.get(1).copied()));
                    let target_date = target.map(|target| target.date);
                    if position == 0 && target_date != Some(row.date) {
                        defects.push(link_defect(
                            &digest.path,
                            row.line,
                            format!(
                                "dated {} but its first link opens a row dated {}",
                                row.date,
                                target_date.unwrap_or("nothing")
                            ),
                        ));
                    }
                    linked.entry(key).or_default().push(row.line);
                }
                Err(defect) => defects.push(defect),
            }
        }
        if !targets.is_empty() {
            defects.extend(enforcement_defects(digest, row, &targets));
        }
    }
    (linked, defects)
}

/// The backticked spans of a cell.
fn spans(cell: &str) -> impl Iterator<Item = &str> {
    cell.split('`').skip(1).step_by(2)
}

/// Whether a full row's span holds a digest span: the same span, or its `::` segments as a
/// whole run of the full span's segments (`work_unit::ruling_promise` in
/// `services::work_unit::ruling_promise`, `kill` in `kill::tests::...`, never `verify` in
/// `verification`).
#[must_use]
pub fn span_holds(full: &str, digest: &str) -> bool {
    let full: Vec<&str> = full.split("::").collect();
    let digest: Vec<&str> = digest.split("::").collect();
    !digest.is_empty()
        && full
            .windows(digest.len())
            .any(|run| run == digest.as_slice())
}

/// A backticked span of a digest row's Enforced by cell that no span of the Enforced by cells
/// of the full rows it links holds: a renamed or removed mechanism the full row was corrected
/// for and the digest was not.
fn enforcement_defects(digest: &Source, row: &Row<'_>, targets: &[&str]) -> Vec<Finding> {
    let cell = row.cells.get(1).copied().unwrap_or("");
    spans(cell)
        .filter(|span| {
            !targets
                .iter()
                .flat_map(|target| spans(target))
                .any(|full| span_holds(full, span))
        })
        .map(|span| {
            Finding::at(
                Path::new(&digest.path),
                row.line,
                1,
                "check-ledger/enforcement",
                format!("`{span}` is in no Enforced by cell of a full row this digest row links"),
            )
        })
        .collect()
}

fn coverage_defects(months: &BTreeMap<&str, Archive<'_>>, linked: &Linked) -> Vec<Finding> {
    let mut defects = Vec::new();
    for (month, archive) in months {
        for (index, row) in archive.rows.iter().enumerate() {
            if !row.date.starts_with(month) {
                defects.push(shape(
                    archive.path,
                    row.line,
                    format!("a row dated {} in the {month} archive", row.date),
                ));
            }
            let lines = linked.get(&((*month).to_string(), index));
            match lines.map(Vec::as_slice) {
                Some([_]) => {}
                None | Some([]) => defects.push(Finding::at(
                    Path::new(archive.path),
                    row.line,
                    1,
                    "check-ledger/unlinked",
                    format!("the {} row has no digest row in {LEDGER}", row.date),
                )),
                Some(several) => defects.push(link_defect(
                    archive.path,
                    row.line,
                    format!(
                        "the {} row is linked from digest lines {several:?}",
                        row.date
                    ),
                )),
            }
        }
    }
    defects
}

/// The defects of the digest and the archives as a pair, and what was read in each.
#[must_use]
pub fn pairing_defects(digest: &Source, archives: &[Source]) -> (Vec<Finding>, Vec<Examined>) {
    let mut defects = Vec::new();
    if digest.text.len() > DIGEST_MAX_BYTES {
        defects.push(Finding::at(
            Path::new(&digest.path),
            1,
            1,
            "check-ledger/size",
            format!(
                "the digest is {} bytes; its bound is {DIGEST_MAX_BYTES}: merge rows that state one rule",
                digest.text.len()
            ),
        ));
    }
    let (digest_rows, digest_shape) = table_rows(digest, DIGEST_COLUMNS);
    defects.extend(digest_shape);
    let mut examined = vec![Examined {
        path: digest.path.clone(),
        rows: digest_rows.len(),
        names: cited_names(digest).len(),
    }];
    let mut months = BTreeMap::new();
    for archive in archives {
        let (rows, archive_shape) = table_rows(archive, ARCHIVE_COLUMNS);
        defects.extend(archive_shape);
        examined.push(Examined {
            path: archive.path.clone(),
            rows: rows.len(),
            names: cited_names(archive).len(),
        });
        match archive_month(&archive.path) {
            Some(month) if !rows.is_empty() => {
                months.insert(
                    month,
                    Archive {
                        path: &archive.path,
                        rows,
                    },
                );
            }
            Some(_) => defects.push(shape(
                &archive.path,
                1,
                "an archive with no rows".to_string(),
            )),
            None => defects.push(shape(
                &archive.path,
                1,
                "an archive file is named `<year>-<month>.md`".to_string(),
            )),
        }
    }
    defects.extend(definition_defects(digest, &months));
    let (linked, link_defects) = digest_links(digest, &digest_rows, &months);
    defects.extend(link_defects);
    defects.extend(coverage_defects(&months, &linked));
    (defects, examined)
}

/// The names of the entries in the archive directory, sorted; more than
/// `ARCHIVE_ENTRIES_MAX` is an error.
///
/// # Errors
///
/// When the directory cannot be read or holds too many entries.
pub fn archive_names(dir: &Path) -> Result<Vec<String>, String> {
    let entries = fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let mut names = Vec::new();
    for entry in entries.take(ARCHIVE_ENTRIES_MAX.saturating_add(1)) {
        let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
        if names.len() >= ARCHIVE_ENTRIES_MAX {
            return Err(format!(
                "{} holds more than {ARCHIVE_ENTRIES_MAX} entries",
                dir.display()
            ));
        }
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

/// Reads a ledger file under `root` whole, refusing one over `LEDGER_MAX_BYTES` rather than
/// reading part; the source keeps `path` as its name.
fn read_source(root: &Path, path: &str) -> Result<Source, String> {
    let full = root.join(path);
    let size = fs::metadata(&full)
        .map_err(|error| format!("{path}: {error}"))?
        .len();
    if size > LEDGER_MAX_BYTES {
        return Err(format!(
            "{path} is {size} bytes; the limit is {LEDGER_MAX_BYTES}"
        ));
    }
    let text = fs::read_to_string(&full).map_err(|error| format!("{path}: {error}"))?;
    Ok(Source {
        path: path.to_string(),
        text,
    })
}

/// The digest, every archive file and the names-elsewhere list under `root`, each read whole.
///
/// # Errors
///
/// When a file cannot be read whole, or the archive directory holds no file: a check over
/// no archive is a failure.
pub fn read_sources(root: &Path) -> Result<(Source, Vec<Source>, String), String> {
    let digest = read_source(root, LEDGER)?;
    let archives = archive_names(&root.join(ARCHIVE_DIR))?
        .iter()
        .map(|name| read_source(root, &format!("{ARCHIVE_DIR}/{name}")))
        .collect::<Result<Vec<_>, _>>()?;
    if archives.is_empty() {
        return Err(format!(
            "examined 0 archive files in {ARCHIVE_DIR}; a check over nothing is a failure"
        ));
    }
    let listed = read_source(root, ELSEWHERE)?.text;
    Ok((digest, archives, listed))
}

/// Every name the digest and the archives cite.
///
/// # Errors
///
/// When they cite none: a check over no name is a failure.
pub fn citations(digest: &Source, archives: &[Source]) -> Result<Vec<Citation>, String> {
    let cited: Vec<Citation> = std::iter::once(digest)
        .chain(archives)
        .flat_map(cited_names)
        .collect();
    if cited.is_empty() {
        return Err("examined 0 cited names; a check over nothing is a failure".to_string());
    }
    Ok(cited)
}

#[cfg(test)]
mod tests;

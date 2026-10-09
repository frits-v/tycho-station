//! The `CodeGraph` port: a per-checkout index of definitions, callers and change impact that
//! workers and reviewers query before reading files.
//!
//! The core calls it only inside journaled steps, on the checkout path after a clone and
//! after each worker commit, never from a worker. It is never the source of truth for
//! lifecycle state.

use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use tycho_types::service::WorkUnitId;

pub const STEP_KEY_MAX_BYTES: usize = 128;
pub const GRAPH_PATH_MAX_BYTES: usize = 1024;
pub const GRAPH_SYMBOL_MAX_BYTES: usize = 256;
pub const GRAPH_REVISION_MAX_BYTES: usize = 128;
pub const IMPACT_PATHS_MAX_ITEMS: usize = 64;
pub const GRAPH_RESULTS_MAX_ITEMS: usize = 50;
pub const IMPACT_ENTITIES_MAX_ITEMS: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    Empty(&'static str),
    TooLong(&'static str, usize),
    TooMany(&'static str, usize),
    LeadingDash(&'static str),
    Character(&'static str, char),
    NotAbsolute(PathBuf),
    NotRelative(String),
    ParentComponent(String),
    Range(String),
    NotUtf8(PathBuf),
    NotCanonical(PathBuf),
    Unresolvable(PathBuf, String),
}

impl fmt::Display for InputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(what) => write!(formatter, "{what} is empty"),
            Self::TooLong(what, length) => write!(formatter, "{what} is {length} bytes long"),
            Self::TooMany(what, count) => write!(formatter, "{count} {what} is over the bound"),
            Self::LeadingDash(what) => write!(formatter, "{what} starts with a dash"),
            Self::Character(what, c) => write!(formatter, "{what} contains {c:?}"),
            Self::NotAbsolute(path) => write!(formatter, "{} is not absolute", path.display()),
            Self::NotRelative(path) => write!(formatter, "{path} is not a relative path"),
            Self::ParentComponent(path) => write!(formatter, "{path} contains `..`"),
            Self::Range(text) => write!(formatter, "{text} is a range, not a revision"),
            Self::NotUtf8(path) => write!(formatter, "{} is not UTF-8", path.display()),
            Self::NotCanonical(path) => {
                write!(formatter, "{} is not a canonical path", path.display())
            }
            Self::Unresolvable(path, error) => {
                write!(formatter, "cannot resolve {}: {error}", path.display())
            }
        }
    }
}

fn bounded_text(what: &'static str, text: &str, max_bytes: usize) -> Result<(), InputError> {
    if text.is_empty() {
        return Err(InputError::Empty(what));
    }
    if text.len() > max_bytes {
        return Err(InputError::TooLong(what, text.len()));
    }
    if text.starts_with('-') {
        return Err(InputError::LeadingDash(what));
    }
    refuse_characters(what, text, |c| !(c.is_control() || c.is_whitespace()))
}

fn refuse_characters(
    what: &'static str,
    text: &str,
    allowed: impl Fn(char) -> bool,
) -> Result<(), InputError> {
    text.chars()
        .find(|c| !allowed(*c))
        .map_or(Ok(()), |c| Err(InputError::Character(what, c)))
}

/// The journaled step's idempotency key, recorded in every report the port returns.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StepKey(String);

impl StepKey {
    pub fn parse(text: &str) -> Result<Self, InputError> {
        bounded_text("step key", text, STEP_KEY_MAX_BYTES)?;
        refuse_characters("step key", text, |c| {
            c.is_ascii_alphanumeric() || "._:-".contains(c)
        })?;
        Ok(Self(text.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A canonical checkout path: absolute, no symlinks, and UTF-8 because it is passed to the
/// tool as an argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkout(PathBuf);

impl Checkout {
    #[expect(
        clippy::disallowed_methods,
        reason = "the resolved path is compared; only a path already in its resolved spelling is kept"
    )]
    pub fn parse(path: &Path) -> Result<Self, InputError> {
        let text = path
            .to_str()
            .ok_or_else(|| InputError::NotUtf8(path.to_path_buf()))?;
        bounded_text("checkout path", text, GRAPH_PATH_MAX_BYTES)?;
        if !path.is_absolute() {
            return Err(InputError::NotAbsolute(path.to_path_buf()));
        }
        if path.components().any(|part| part == Component::ParentDir) {
            return Err(InputError::ParentComponent(text.to_string()));
        }
        let canonical = fs::canonicalize(path)
            .map_err(|error| InputError::Unresolvable(path.to_path_buf(), error.to_string()))?;
        if canonical != path {
            return Err(InputError::NotCanonical(path.to_path_buf()));
        }
        Ok(Self(canonical))
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.to_str().unwrap_or_default()
    }
}

/// A symbol name or a `<file>:<line>` selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol(String);

impl Symbol {
    pub fn parse(text: &str) -> Result<Self, InputError> {
        bounded_text("symbol", text, GRAPH_SYMBOL_MAX_BYTES)?;
        Ok(Self(text.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A git revision the impact query compares the checkout's HEAD against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision(String);

impl Revision {
    pub fn parse(text: &str) -> Result<Self, InputError> {
        bounded_text("revision", text, GRAPH_REVISION_MAX_BYTES)?;
        if text.contains("..") {
            return Err(InputError::Range(text.to_string()));
        }
        refuse_characters("revision", text, |c| {
            c.is_ascii_alphanumeric() || "._/~^-".contains(c)
        })?;
        Ok(Self(text.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A path relative to the checkout root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoPath(String);

impl RepoPath {
    pub fn parse(text: &str) -> Result<Self, InputError> {
        bounded_text("repository path", text, GRAPH_PATH_MAX_BYTES)?;
        let path = Path::new(text);
        if path.is_absolute() {
            return Err(InputError::NotRelative(text.to_string()));
        }
        if path.components().any(|part| part == Component::ParentDir) {
            return Err(InputError::ParentComponent(text.to_string()));
        }
        Ok(Self(text.to_string()))
    }

    pub fn parse_all(texts: &[&str]) -> Result<Vec<Self>, InputError> {
        if texts.is_empty() {
            return Err(InputError::Empty("impact paths"));
        }
        if texts.len() > IMPACT_PATHS_MAX_ITEMS {
            return Err(InputError::TooMany("impact paths", texts.len()));
        }
        texts.iter().map(|text| Self::parse(text)).collect()
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphCounts {
    pub files: u64,
    pub parsed_files: u64,
    pub symbols: u64,
    pub relations: u64,
    pub partial_failures: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completeness {
    Complete,
    /// Some files failed to parse; the index holds the rest.
    Degraded,
}

/// The index build time per unit, as the evaluation harness stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexTime {
    pub step_key: String,
    pub work_unit: WorkUnitId,
    pub checkout: String,
    pub commit: String,
    pub wall_clock_ms: u64,
    pub tool_latency_ms: u64,
    pub cache_hit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildReport {
    pub key: StepKey,
    pub work_unit: WorkUnitId,
    pub checkout: Checkout,
    pub index_dir: PathBuf,
    pub plugin_version: String,
    pub commit: String,
    pub wall_clock: Duration,
    pub tool_latency_ms: u64,
    pub cache_hit: bool,
    pub counts: GraphCounts,
    pub completeness: Completeness,
}

impl BuildReport {
    #[must_use]
    pub fn index_time(&self) -> IndexTime {
        IndexTime {
            step_key: self.key.as_str().to_string(),
            work_unit: self.work_unit.clone(),
            checkout: self.checkout.as_str().to_string(),
            commit: self.commit.clone(),
            wall_clock_ms: u64::try_from(self.wall_clock.as_millis()).unwrap_or(u64::MAX),
            tool_latency_ms: self.tool_latency_ms,
            cache_hit: self.cache_hit,
        }
    }
}

impl fmt::Display for BuildReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let time = self.index_time();
        writeln!(formatter, "step key: {}", self.key.as_str())?;
        writeln!(formatter, "work unit: {}", self.work_unit)?;
        writeln!(formatter, "checkout: {}", self.checkout.as_str())?;
        writeln!(formatter, "commit: {}", self.commit)?;
        writeln!(formatter, "index: {}", self.index_dir.display())?;
        writeln!(formatter, "plugin: {}", self.plugin_version)?;
        writeln!(
            formatter,
            "build: {} ms wall clock, {} ms reported by the tool, cache hit {}",
            time.wall_clock_ms, time.tool_latency_ms, time.cache_hit
        )?;
        writeln!(
            formatter,
            "counts: {} files ({} parsed), {} symbols, {} relations, {} partial failures, {:?}",
            self.counts.files,
            self.counts.parsed_files,
            self.counts.symbols,
            self.counts.relations,
            self.counts.partial_failures,
            self.completeness
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub qualified_name: String,
    pub kind: String,
    pub file_path: String,
    pub line: u64,
}

impl fmt::Display for Location {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} {}:{}",
            self.kind, self.qualified_name, self.file_path, self.line
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Definitions {
    Found {
        declarations: Vec<Location>,
        truncated: bool,
    },
    /// The tool fell back to a fuzzy match; these are near names, not the symbol.
    NotFound { nearest: Vec<Location> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Callers {
    Found {
        callers: Vec<Location>,
        truncated: bool,
    },
    /// The name has several definitions; rerun with a `<file>:<line>` selector.
    Ambiguous {
        candidates: Vec<Location>,
    },
    NotFound {
        nearest: Vec<Location>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Removed,
    Renamed,
    SignatureChanged,
    BodyChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedEntity {
    pub file_path: String,
    pub change: ChangeKind,
    pub kind: String,
    pub name: String,
    pub dependents: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Impact {
    Complete(Vec<ChangedEntity>),
    /// The analysis stopped at its time budget; the list is what it reached.
    Partial(Vec<ChangedEntity>),
}

/// The tree a query answered about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revisions {
    Commit(String),
    Range { base: String, head: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryReport<T> {
    pub key: StepKey,
    pub revisions: Revisions,
    /// False when the query found no cached index and built one itself.
    pub index_cache_hit: Option<bool>,
    pub answer: T,
}

fn write_locations(
    formatter: &mut fmt::Formatter<'_>,
    heading: &str,
    locations: &[Location],
) -> fmt::Result {
    writeln!(formatter, "{heading}: {}", locations.len())?;
    for location in locations {
        writeln!(formatter, "  {location}")?;
    }
    Ok(())
}

impl fmt::Display for Definitions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Found {
                declarations,
                truncated,
            } => {
                write_locations(formatter, "declarations", declarations)?;
                writeln!(formatter, "truncated: {truncated}")
            }
            Self::NotFound { nearest } => write_locations(formatter, "not found; nearest", nearest),
        }
    }
}

impl fmt::Display for Callers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Found { callers, truncated } => {
                write_locations(formatter, "callers", callers)?;
                writeln!(formatter, "truncated: {truncated}")
            }
            Self::Ambiguous { candidates } => {
                write_locations(formatter, "ambiguous; candidates", candidates)
            }
            Self::NotFound { nearest } => write_locations(formatter, "not found; nearest", nearest),
        }
    }
}

impl fmt::Display for Impact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (heading, entities) = match self {
            Self::Complete(entities) => ("changed entities", entities),
            Self::Partial(entities) => ("changed entities, partial at the time budget", entities),
        };
        writeln!(formatter, "{heading}: {}", entities.len())?;
        for entity in entities {
            writeln!(
                formatter,
                "  {:?} {} {} in {}, {} dependents",
                entity.change, entity.kind, entity.name, entity.file_path, entity.dependents
            )?;
        }
        Ok(())
    }
}

impl<T: fmt::Display> fmt::Display for QueryReport<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "step key: {}", self.key.as_str())?;
        match &self.revisions {
            Revisions::Commit(commit) => writeln!(formatter, "commit: {commit}")?,
            Revisions::Range { base, head } => writeln!(formatter, "range: {base}..{head}")?,
        }
        match self.index_cache_hit {
            Some(hit) => writeln!(formatter, "index cache hit: {hit}")?,
            None => writeln!(formatter, "index cache hit: not reported")?,
        }
        write!(formatter, "{}", self.answer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    Input(InputError),
    /// The plugin version is not the pinned one, or the plugin is absent.
    VersionRefused(String),
    EgressNotRuledOut(String),
    IndexInsideCheckout(PathBuf),
    CannotPrepare(PathBuf, String),
    Command(&'static str, String),
    NotARepository(String),
    Failed(&'static str, String),
    EmptyIndex,
    TooManyResults(&'static str, usize),
    Unrecognised(&'static str, String),
}

impl fmt::Display for GraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => write!(formatter, "{error}"),
            Self::VersionRefused(reason) => write!(formatter, "graph plugin refused: {reason}"),
            Self::EgressNotRuledOut(reason) => {
                write!(
                    formatter,
                    "graph plugin does not confirm no egress: {reason}"
                )
            }
            Self::IndexInsideCheckout(path) => {
                write!(formatter, "index {} is inside the checkout", path.display())
            }
            Self::CannotPrepare(path, error) => {
                write!(formatter, "cannot prepare {}: {error}", path.display())
            }
            Self::Command(command, error) => write!(formatter, "graph {command}: {error}"),
            Self::NotARepository(message) => write!(formatter, "not a repository: {message}"),
            Self::Failed(command, message) => {
                write!(formatter, "graph {command} failed: {message}")
            }
            Self::EmptyIndex => formatter.write_str("graph index holds no files or no symbols"),
            Self::TooManyResults(command, count) => {
                write!(
                    formatter,
                    "graph {command} returned {count} results; over the bound"
                )
            }
            Self::Unrecognised(command, reason) => {
                write!(formatter, "graph {command} output not recognised: {reason}")
            }
        }
    }
}

impl From<InputError> for GraphError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

/// Builds and queries the code graph of one checkout; services hold it across threads.
pub trait CodeGraph: Send + Sync {
    /// After a worktree clone.
    fn build(
        &self,
        key: &StepKey,
        unit: &WorkUnitId,
        checkout: &Checkout,
    ) -> Result<BuildReport, GraphError>;

    /// After a worker commit. The index has no incremental mode, so this is a full build.
    fn rebuild(
        &self,
        key: &StepKey,
        unit: &WorkUnitId,
        checkout: &Checkout,
    ) -> Result<BuildReport, GraphError>;

    fn definitions(
        &self,
        key: &StepKey,
        checkout: &Checkout,
        symbol: &Symbol,
    ) -> Result<QueryReport<Definitions>, GraphError>;

    fn callers(
        &self,
        key: &StepKey,
        checkout: &Checkout,
        symbol: &Symbol,
    ) -> Result<QueryReport<Callers>, GraphError>;

    /// Entities changed under `paths` between `base` and HEAD, each with its dependent count.
    fn impact(
        &self,
        key: &StepKey,
        checkout: &Checkout,
        base: &Revision,
        paths: &[RepoPath],
    ) -> Result<QueryReport<Impact>, GraphError>;
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;

    #[test]
    fn accepts_inputs_within_bounds() {
        assert!(StepKey::parse("wu03.graph:7").is_ok());
        let canonical = fs::canonicalize(env!("CARGO_MANIFEST_DIR")).unwrap();
        assert!(Checkout::parse(&canonical).is_ok());
        assert!(Symbol::parse("crates/tycho/src/zmx.rs:42").is_ok());
        assert!(Revision::parse("HEAD~1").is_ok());
        assert!(RepoPath::parse_all(&["crates/tycho/src/zmx.rs"]).is_ok());
    }

    #[test]
    fn rejects_a_symbol_over_the_bound() {
        let symbol = "s".repeat(GRAPH_SYMBOL_MAX_BYTES + 1);
        assert_eq!(
            Symbol::parse(&symbol),
            Err(InputError::TooLong("symbol", GRAPH_SYMBOL_MAX_BYTES + 1))
        );
        assert!(Symbol::parse(&"s".repeat(GRAPH_SYMBOL_MAX_BYTES)).is_ok());
    }

    #[test]
    fn rejects_a_symbol_that_reads_as_a_flag() {
        assert_eq!(
            Symbol::parse("--repo=/etc"),
            Err(InputError::LeadingDash("symbol"))
        );
        assert_eq!(
            Symbol::parse("a b"),
            Err(InputError::Character("symbol", ' '))
        );
        assert_eq!(Symbol::parse(""), Err(InputError::Empty("symbol")));
    }

    #[test]
    fn rejects_a_path_over_the_bound() {
        let long = format!("/{}", "p".repeat(GRAPH_PATH_MAX_BYTES));
        assert!(matches!(
            Checkout::parse(Path::new(&long)),
            Err(InputError::TooLong("checkout path", _))
        ));
        let relative = "p".repeat(GRAPH_PATH_MAX_BYTES + 1);
        assert!(matches!(
            RepoPath::parse(&relative),
            Err(InputError::TooLong("repository path", _))
        ));
    }

    #[test]
    fn rejects_a_checkout_that_is_relative_or_climbs() {
        assert!(matches!(
            Checkout::parse(Path::new("wt/wu03")),
            Err(InputError::NotAbsolute(_))
        ));
        assert!(matches!(
            Checkout::parse(Path::new("/Users/someone/../other")),
            Err(InputError::ParentComponent(_))
        ));
    }

    #[test]
    fn rejects_a_checkout_through_a_symlink_or_missing() {
        let base = fs::canonicalize(env!("CARGO_MANIFEST_DIR"))
            .unwrap()
            .join("../../target")
            .join(format!("checkout-symlink-{}", std::process::id()));
        fs::create_dir_all(base.join("real")).unwrap();
        let base = fs::canonicalize(base).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
        let through_link = Checkout::parse(&base.join("link"));
        let direct = Checkout::parse(&base.join("real"));
        let missing = Checkout::parse(&base.join("missing"));
        fs::remove_dir_all(&base).unwrap();
        assert!(matches!(through_link, Err(InputError::NotCanonical(_))));
        assert!(direct.is_ok());
        assert!(matches!(missing, Err(InputError::Unresolvable(_, _))));
    }

    #[test]
    fn rejects_repository_paths_outside_the_checkout() {
        assert!(matches!(
            RepoPath::parse("/etc/passwd"),
            Err(InputError::NotRelative(_))
        ));
        assert!(matches!(
            RepoPath::parse("src/../../etc"),
            Err(InputError::ParentComponent(_))
        ));
    }

    #[test]
    fn rejects_too_many_or_no_impact_paths() {
        let paths = vec!["a.rs"; IMPACT_PATHS_MAX_ITEMS + 1];
        assert_eq!(
            RepoPath::parse_all(&paths),
            Err(InputError::TooMany(
                "impact paths",
                IMPACT_PATHS_MAX_ITEMS + 1
            ))
        );
        assert_eq!(
            RepoPath::parse_all(&[]),
            Err(InputError::Empty("impact paths"))
        );
    }

    #[test]
    fn rejects_a_revision_with_option_or_range_syntax() {
        assert_eq!(
            Revision::parse("-p"),
            Err(InputError::LeadingDash("revision"))
        );
        assert_eq!(
            Revision::parse("main..HEAD"),
            Err(InputError::Range("main..HEAD".to_string()))
        );
        assert_eq!(
            Revision::parse("HEAD:x"),
            Err(InputError::Character("revision", ':'))
        );
        let long = "r".repeat(GRAPH_REVISION_MAX_BYTES + 1);
        assert!(matches!(
            Revision::parse(&long),
            Err(InputError::TooLong("revision", _))
        ));
    }

    #[test]
    fn rejects_a_step_key_over_the_bound_or_with_odd_characters() {
        let long = "k".repeat(STEP_KEY_MAX_BYTES + 1);
        assert!(matches!(
            StepKey::parse(&long),
            Err(InputError::TooLong("step key", _))
        ));
        assert_eq!(
            StepKey::parse("wu03/graph"),
            Err(InputError::Character("step key", '/'))
        );
    }
}

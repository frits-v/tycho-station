//! The `CodeGraph` adapter over entire.io's semantic graph plugin, pinned to one version.
//!
//! The plugin binary is run directly, never through `entire graph`: the entire CLI checks a
//! public API for a new version once a day with no switch to turn it off, and the plugin
//! itself makes no network or model calls (`doctor --json` reports `no_egress`, checked when
//! the adapter opens). Each checkout gets its own index directory under the core's home,
//! passed as `ENTIRE_PLUGIN_DATA_DIR`, because the plugin's cache is keyed on the checkout
//! path and queries take no cache flag of their own.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;

use tycho_types::service::WorkUnitId;

use crate::code_graph::{
    BuildReport, Callers, ChangeKind, ChangedEntity, Checkout, CodeGraph, Completeness,
    Definitions, GraphCounts, GraphError, Impact, Location, QueryReport, RepoPath, Revision,
    Revisions, StepKey, Symbol, GRAPH_RESULTS_MAX_ITEMS, IMPACT_ENTITIES_MAX_ITEMS,
};
use crate::command::{self, Captured, CommandError};
use crate::config::{
    COMMAND_OUTPUT_MAX_BYTES, COMMAND_TIMEOUT, ENTIRE_GRAPH_PINNED_VERSION, GRAPH_BUILD_TIMEOUT,
    GRAPH_DIFF_BUDGET_SECONDS, GRAPH_OUTPUT_MAX_BYTES, GRAPH_QUERY_TIMEOUT, MISE_NO_INSTALL,
};
use crate::private_dir;

pub const PROVIDER: &str = "entire-graph";
pub const DATA_DIR_ENV: &str = "ENTIRE_PLUGIN_DATA_DIR";
/// The parsing depth both `index` and the relation queries use, so they share a cache entry.
const PROFILE: &str = "full";
const MESSAGE_MAX_BYTES: usize = 512;
const INDEX_NAME_MAX_BYTES: usize = 64;
const BUDGET_EXCEEDED: &str = "W_ANALYSIS_BUDGET_EXCEEDED";
/// The `format_version` of the `index`, `def` and `neighbors` captures; `version`, `doctor`
/// and `diff` carry none.
const FORMAT_VERSION: u64 = 1;
const ENTIRE_PREFIX: &str = "ENTIRE_";

/// One `type` value of a `diff` change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeType {
    Known(ChangeKind),
    Unrecognised(String),
}

#[must_use]
pub fn decode_change_type(text: &str) -> ChangeType {
    match text {
        "added" => ChangeType::Known(ChangeKind::Added),
        "removed" => ChangeType::Known(ChangeKind::Removed),
        "renamed" => ChangeType::Known(ChangeKind::Renamed),
        "signature_changed" => ChangeType::Known(ChangeKind::SignatureChanged),
        "body_changed" => ChangeType::Known(ChangeKind::BodyChanged),
        other => ChangeType::Unrecognised(excerpt(other)),
    }
}

/// `version --json`, or the absence of the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionState {
    Pinned,
    Other(String),
    Absent,
    Unrecognised(String),
}

/// `doctor --json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressState {
    NoEgress,
    Egress(String),
    Unrecognised(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexSummary {
    pub provider_version: String,
    pub commit: String,
    pub cache_hit: bool,
    pub latency_ms: u64,
    pub counts: GraphCounts,
    pub completeness: Completeness,
}

/// `index --format json`, with its exit status and stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexOutcome {
    Built(IndexSummary),
    Empty,
    NotARepository(String),
    Failed(String),
    Unrecognised(String),
}

/// A query's output: the port's answer, or why there is none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded<T> {
    Answer {
        answer: T,
        revisions: Revisions,
        index_cache_hit: Option<bool>,
    },
    Failed(String),
    TooMany(usize),
    Unrecognised(String),
}

fn excerpt(text: &str) -> String {
    let trimmed = text.trim();
    let mut end = trimmed.len().min(MESSAGE_MAX_BYTES);
    while !trimmed.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    trimmed.get(..end).unwrap_or_default().to_string()
}

fn parse_object(stdout: &str) -> Result<Value, String> {
    match serde_json::from_str::<Value>(stdout) {
        Ok(value) if value.is_object() => Ok(value),
        Ok(_) => Err(format!("not a JSON object: {}", excerpt(stdout))),
        Err(error) => Err(format!("{error}: {}", excerpt(stdout))),
    }
}

fn check_format(value: &Value, expected: Option<u64>) -> Result<(), String> {
    match (value.get("format_version"), expected) {
        (None, None) => Ok(()),
        (Some(found), Some(expected)) if found.as_u64() == Some(expected) => Ok(()),
        (found, _) => Err(format!("format_version {found:?}, expected {expected:?}")),
    }
}

fn parse_versioned(stdout: &str, expected: Option<u64>) -> Result<Value, String> {
    let value = parse_object(stdout)?;
    check_format(&value, expected)?;
    Ok(value)
}

fn text_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn number_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn flag_field(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

#[must_use]
pub fn decode_version(result: &Result<Captured, CommandError>) -> VersionState {
    let captured = match result {
        Ok(captured) if captured.status.success() => captured,
        Ok(captured) => return VersionState::Unrecognised(excerpt(&captured.stderr)),
        Err(CommandError::Spawn(_, error)) if error.kind() == io::ErrorKind::NotFound => {
            return VersionState::Absent
        }
        Err(error) => return VersionState::Unrecognised(error.to_string()),
    };
    let value = match parse_versioned(&captured.stdout, None) {
        Ok(value) => value,
        Err(reason) => return VersionState::Unrecognised(reason),
    };
    match (
        text_field(&value, "provider"),
        text_field(&value, "version"),
    ) {
        (Some(PROVIDER), Some(ENTIRE_GRAPH_PINNED_VERSION)) => VersionState::Pinned,
        (Some(PROVIDER), Some(version)) if version.starts_with('v') => {
            VersionState::Other(excerpt(version))
        }
        _ => VersionState::Unrecognised(excerpt(&captured.stdout)),
    }
}

#[must_use]
pub fn decode_doctor(stdout: &str) -> EgressState {
    let value = match parse_versioned(stdout, None) {
        Ok(value) => value,
        Err(reason) => return EgressState::Unrecognised(reason),
    };
    let Some(local) = value.get("phase_1_local_only").and_then(Value::as_object) else {
        return EgressState::Unrecognised("no phase_1_local_only object".to_string());
    };
    if local.is_empty() {
        return EgressState::Unrecognised("phase_1_local_only is empty".to_string());
    }
    let mut remote = Vec::new();
    for (name, setting) in local {
        match setting.as_bool() {
            Some(false) => {}
            Some(true) => remote.push(name.clone()),
            None => return EgressState::Unrecognised(format!("{name} is not a boolean")),
        }
    }
    match (flag_field(&value, "no_egress"), remote.is_empty()) {
        (Some(true), true) => EgressState::NoEgress,
        (Some(_), _) => EgressState::Egress(remote.join(", ")),
        (None, _) => EgressState::Unrecognised("no no_egress flag".to_string()),
    }
}

fn decode_counts(value: &Value) -> Option<(GraphCounts, Option<Completeness>)> {
    let counts = value.get("counts")?;
    let decoded = GraphCounts {
        files: number_field(counts, "files")?,
        parsed_files: number_field(counts, "parsed_files")?,
        symbols: number_field(counts, "symbols")?,
        relations: number_field(counts, "relations")?,
        partial_failures: number_field(counts, "partial_failures")?,
    };
    let completeness = match text_field(counts, "completeness_level")? {
        "ok" => Some(Completeness::Complete),
        "degraded" => Some(Completeness::Degraded),
        _ => None,
    };
    Some((decoded, completeness))
}

fn decode_index_summary(value: &Value) -> Result<IndexSummary, String> {
    check_format(value, Some(FORMAT_VERSION))?;
    let provider = text_field(value, "provider");
    let version = text_field(value, "provider_version");
    if provider != Some(PROVIDER) || version != Some(ENTIRE_GRAPH_PINNED_VERSION) {
        return Err(format!("provider {provider:?} version {version:?}"));
    }
    let (counts, completeness) = decode_counts(value).ok_or("counts missing or malformed")?;
    let completeness = completeness.ok_or("completeness level not recognised")?;
    Ok(IndexSummary {
        provider_version: ENTIRE_GRAPH_PINNED_VERSION.to_string(),
        commit: text_field(value, "commit").ok_or("no commit")?.to_string(),
        cache_hit: flag_field(value, "index_cache_hit").ok_or("no index_cache_hit")?,
        latency_ms: number_field(value, "index_latency_ms").ok_or("no index_latency_ms")?,
        counts,
        completeness,
    })
}

#[must_use]
pub fn decode_index(success: bool, stdout: &str, stderr: &str) -> IndexOutcome {
    if !success {
        if stderr.contains("not a git repository") {
            return IndexOutcome::NotARepository(excerpt(stderr));
        }
        return IndexOutcome::Failed(excerpt(stderr));
    }
    let summary = match parse_object(stdout).and_then(|value| decode_index_summary(&value)) {
        Ok(summary) => summary,
        Err(reason) => return IndexOutcome::Unrecognised(reason),
    };
    if summary.counts.files == 0 || summary.counts.symbols == 0 {
        return IndexOutcome::Empty;
    }
    IndexOutcome::Built(summary)
}

fn decode_location(value: &Value) -> Option<Location> {
    Some(Location {
        qualified_name: text_field(value, "qualified_name")?.to_string(),
        kind: text_field(value, "kind")?.to_string(),
        file_path: text_field(value, "file_path")?.to_string(),
        line: number_field(value, "start_line")?,
    })
}

/// Locations at `pointer` inside each element of `items`; `None` when any is malformed.
fn decode_locations(items: &[Value], pointer: &str) -> Option<Vec<Location>> {
    items
        .iter()
        .map(|item| item.pointer(pointer).and_then(decode_location))
        .collect()
}

fn array_field<'a>(value: &'a Value, key: &str) -> Option<&'a [Value]> {
    value.get(key).and_then(Value::as_array).map(Vec::as_slice)
}

fn query_object<T>(
    success: bool,
    stdout: &str,
    stderr: &str,
    format: Option<u64>,
) -> Result<Value, Decoded<T>> {
    if !success {
        return Err(Decoded::Failed(excerpt(stderr)));
    }
    parse_versioned(stdout, format).map_err(Decoded::Unrecognised)
}

/// A fuzzy fallback match, which names near symbols rather than the one asked for.
fn fuzzy(value: &Value) -> Result<bool, String> {
    let flagged = match value.get("fuzzy_match") {
        None => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => return Err("fuzzy_match is not a boolean".to_string()),
    };
    Ok(flagged || value.get("fuzzy_match_kind").is_some())
}

fn commit(value: &Value) -> Result<Revisions, String> {
    text_field(value, "commit")
        .map(|commit| Revisions::Commit(commit.to_string()))
        .ok_or_else(|| "no commit".to_string())
}

#[must_use]
pub fn decode_definitions(success: bool, stdout: &str, stderr: &str) -> Decoded<Definitions> {
    let value = match query_object(success, stdout, stderr, Some(FORMAT_VERSION)) {
        Ok(value) => value,
        Err(decoded) => return decoded,
    };
    let (revisions, fuzzy) =
        match commit(&value).and_then(|revisions| Ok((revisions, fuzzy(&value)?))) {
            Ok(decoded) => decoded,
            Err(reason) => return Decoded::Unrecognised(reason),
        };
    let Some(items) = array_field(&value, "declarations") else {
        return Decoded::Unrecognised("no declarations array".to_string());
    };
    if items.len() > GRAPH_RESULTS_MAX_ITEMS {
        return Decoded::TooMany(items.len());
    }
    let Some(locations) = decode_locations(items, "") else {
        return Decoded::Unrecognised("a declaration is malformed".to_string());
    };
    let answer = match (fuzzy, flag_field(&value, "truncated")) {
        (true, _) => Definitions::NotFound { nearest: locations },
        (false, _) if locations.is_empty() => Definitions::NotFound { nearest: locations },
        (false, Some(truncated)) => Definitions::Found {
            declarations: locations,
            truncated,
        },
        (false, None) => return Decoded::Unrecognised("no truncated flag".to_string()),
    };
    Decoded::Answer {
        answer,
        revisions,
        index_cache_hit: flag_field(&value, "index_cache_hit"),
    }
}

fn decode_callers_answer(value: &Value, matches: &[Value]) -> Result<Callers, String> {
    let fuzzy = fuzzy(value)?;
    let ambiguous = flag_field(value, "disambiguation_required").ok_or("no disambiguation flag")?;
    let candidates = decode_locations(matches, "/symbol").ok_or("a match is malformed")?;
    if fuzzy || matches.is_empty() {
        return Ok(Callers::NotFound {
            nearest: candidates,
        });
    }
    if ambiguous {
        return Ok(Callers::Ambiguous { candidates });
    }
    let [focus] = matches else {
        return Err(format!("{} matches without ambiguity", matches.len()));
    };
    let incoming = array_field(focus, "incoming").ok_or("no incoming array")?;
    if incoming.len() > GRAPH_RESULTS_MAX_ITEMS {
        return Err(format!("{} callers over the bound", incoming.len()));
    }
    Ok(Callers::Found {
        callers: decode_locations(incoming, "/endpoint").ok_or("a caller is malformed")?,
        truncated: flag_field(value, "truncated").ok_or("no truncated flag")?,
    })
}

#[must_use]
pub fn decode_callers(success: bool, stdout: &str, stderr: &str) -> Decoded<Callers> {
    let value = match query_object(success, stdout, stderr, Some(FORMAT_VERSION)) {
        Ok(value) => value,
        Err(decoded) => return decoded,
    };
    let revisions = match commit(&value) {
        Ok(revisions) => revisions,
        Err(reason) => return Decoded::Unrecognised(reason),
    };
    let Some(matches) = array_field(&value, "matches") else {
        return Decoded::Unrecognised("no matches array".to_string());
    };
    if matches.len() > GRAPH_RESULTS_MAX_ITEMS {
        return Decoded::TooMany(matches.len());
    }
    match decode_callers_answer(&value, matches) {
        Ok(answer) => Decoded::Answer {
            answer,
            revisions,
            index_cache_hit: flag_field(&value, "index_cache_hit"),
        },
        Err(reason) => Decoded::Unrecognised(reason),
    }
}

fn decode_change(path: &str, change: &Value) -> Result<ChangedEntity, String> {
    let kind = match decode_change_type(text_field(change, "type").ok_or("a change has no type")?) {
        ChangeType::Known(kind) => kind,
        ChangeType::Unrecognised(text) => return Err(format!("change type {text}")),
    };
    Ok(ChangedEntity {
        file_path: path.to_string(),
        change: kind,
        kind: text_field(change, "kind")
            .ok_or("a change has no kind")?
            .to_string(),
        name: text_field(change, "name")
            .ok_or("a change has no name")?
            .to_string(),
        dependents: number_field(change, "dependents_count")
            .ok_or("a change has no dependents_count")?,
    })
}

fn decode_file_changes(file: &Value) -> Result<Vec<ChangedEntity>, String> {
    let path = text_field(file, "path").ok_or("a file has no path")?;
    let changes = match file.get("changes") {
        Some(Value::Null) => &[][..],
        Some(Value::Array(changes)) => changes.as_slice(),
        _ => return Err(format!("{path} has no changes list")),
    };
    changes
        .iter()
        .map(|change| decode_change(path, change))
        .collect()
}

fn range(value: &Value) -> Result<Revisions, String> {
    match (text_field(value, "base"), text_field(value, "head")) {
        (Some(base), Some(head)) => Ok(Revisions::Range {
            base: base.to_string(),
            head: head.to_string(),
        }),
        _ => Err("no base or head".to_string()),
    }
}

fn budget_exceeded(value: &Value) -> Option<bool> {
    match value.get("warnings") {
        None | Some(Value::Null) => Some(false),
        Some(Value::Array(warnings)) => Some(
            warnings
                .iter()
                .any(|warning| warning.to_string().contains(BUDGET_EXCEEDED)),
        ),
        Some(_) => None,
    }
}

/// `diff --json`, which has no format version and writes `null` for an empty file list.
#[must_use]
pub fn decode_impact(success: bool, stdout: &str, stderr: &str) -> Decoded<Impact> {
    let value = match query_object(success, stdout, stderr, None) {
        Ok(value) => value,
        Err(decoded) => return decoded,
    };
    let revisions = match range(&value) {
        Ok(revisions) => revisions,
        Err(reason) => return Decoded::Unrecognised(reason),
    };
    let files = match value.get("files") {
        Some(Value::Null) => &[][..],
        Some(Value::Array(files)) => files.as_slice(),
        _ => return Decoded::Unrecognised("no files list".to_string()),
    };
    let mut entities = Vec::new();
    for file in files {
        let changes = match decode_file_changes(file) {
            Ok(changes) => changes,
            Err(reason) => return Decoded::Unrecognised(reason),
        };
        entities.extend(changes);
        if entities.len() > IMPACT_ENTITIES_MAX_ITEMS {
            return Decoded::TooMany(entities.len());
        }
    }
    let answer = match budget_exceeded(&value) {
        Some(false) => Impact::Complete(entities),
        Some(true) => Impact::Partial(entities),
        None => return Decoded::Unrecognised("warnings is not a list".to_string()),
    };
    Decoded::Answer {
        answer,
        revisions,
        index_cache_hit: None,
    }
}

/// Stable across runs and releases, unlike the standard library's hasher.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The checkout's directory name, for a reader, and a hash of its whole path.
#[must_use]
pub fn index_name(checkout: &Checkout) -> String {
    let base: String = checkout
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("root")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c))
        .take(INDEX_NAME_MAX_BYTES)
        .collect();
    format!("{base}-{:016x}", fnv1a(checkout.as_str().as_bytes()))
}

/// Inherited `ENTIRE_*` variables, removed from the plugin's environment so only the ones
/// the adapter sets reach it.
#[must_use]
pub fn entire_variables(names: impl Iterator<Item = OsString>) -> Vec<OsString> {
    names
        .filter(|name| {
            name.to_str()
                .is_none_or(|text| text.starts_with(ENTIRE_PREFIX))
        })
        .collect()
}

fn run_plugin(
    binary: &Path,
    arguments: &[&str],
    data_dir: Option<&str>,
    timeout: Duration,
    output_max_bytes: usize,
) -> Result<Captured, CommandError> {
    let mut environment = MISE_NO_INSTALL.to_vec();
    if let Some(data_dir) = data_dir {
        environment.push((DATA_DIR_ENV, data_dir));
    }
    let removed = entire_variables(env::vars_os().map(|(name, _)| name));
    command::run_status_capped(
        binary,
        arguments,
        &environment,
        &removed,
        timeout,
        output_max_bytes,
    )
}

/// The adapter, opened only when the plugin is the pinned version and reports no egress.
#[derive(Debug, Clone)]
pub struct EntireGraph {
    binary: PathBuf,
    index_root: PathBuf,
}

impl EntireGraph {
    pub fn open(binary: &Path, index_root: &Path) -> Result<Self, GraphError> {
        let version = run_plugin(
            binary,
            &["version", "--json"],
            None,
            COMMAND_TIMEOUT,
            COMMAND_OUTPUT_MAX_BYTES,
        );
        match decode_version(&version) {
            VersionState::Pinned => {}
            VersionState::Other(found) => {
                return Err(GraphError::VersionRefused(format!(
                    "found {found}, pinned {ENTIRE_GRAPH_PINNED_VERSION}"
                )))
            }
            VersionState::Absent => {
                return Err(GraphError::VersionRefused(format!(
                    "{} is absent; install with `entire plugin install graph --pin {}`",
                    binary.display(),
                    ENTIRE_GRAPH_PINNED_VERSION
                )))
            }
            VersionState::Unrecognised(reason) => return Err(GraphError::VersionRefused(reason)),
        }
        let doctor = run_plugin(
            binary,
            &["doctor", "--json"],
            None,
            COMMAND_TIMEOUT,
            COMMAND_OUTPUT_MAX_BYTES,
        )
        .map_err(|error| GraphError::Command("doctor", error.to_string()))?;
        if !doctor.status.success() {
            return Err(GraphError::Failed("doctor", excerpt(&doctor.stderr)));
        }
        match decode_doctor(&doctor.stdout) {
            EgressState::NoEgress => {}
            EgressState::Egress(reason) | EgressState::Unrecognised(reason) => {
                return Err(GraphError::EgressNotRuledOut(reason))
            }
        }
        Ok(Self {
            binary: binary.to_path_buf(),
            index_root: canonical_root(index_root)?,
        })
    }

    #[must_use]
    pub fn index_root(&self) -> &Path {
        &self.index_root
    }

    #[must_use]
    pub fn index_dir(&self, checkout: &Checkout) -> PathBuf {
        self.index_root.join(index_name(checkout))
    }

    /// The index directory must sit outside the checkout, where a worker cannot reach it.
    fn prepare(&self, checkout: &Checkout) -> Result<PathBuf, GraphError> {
        let index_dir = self.index_dir(checkout);
        if index_dir.starts_with(checkout.path()) {
            return Err(GraphError::IndexInsideCheckout(index_dir));
        }
        private_dir::ensure(&[self.index_root.clone(), index_dir.clone()])
            .map_err(|error| GraphError::CannotPrepare(index_dir.clone(), error.to_string()))?;
        Ok(index_dir)
    }

    fn run(
        &self,
        command: &'static str,
        arguments: &[&str],
        index_dir: &Path,
        timeout: Duration,
    ) -> Result<Captured, GraphError> {
        let data_dir = index_dir.to_str().ok_or_else(|| {
            GraphError::CannotPrepare(index_dir.to_path_buf(), "not UTF-8".to_string())
        })?;
        run_plugin(
            &self.binary,
            arguments,
            Some(data_dir),
            timeout,
            GRAPH_OUTPUT_MAX_BYTES,
        )
        .map_err(|error| GraphError::Command(command, error.to_string()))
    }

    fn index(
        &self,
        key: &StepKey,
        unit: &WorkUnitId,
        checkout: &Checkout,
    ) -> Result<BuildReport, GraphError> {
        let index_dir = self.prepare(checkout)?;
        let arguments = [
            "index",
            "--repo",
            checkout.as_str(),
            "--profile",
            PROFILE,
            "--format",
            "json",
        ];
        let started = Instant::now();
        let captured = self.run("index", &arguments, &index_dir, GRAPH_BUILD_TIMEOUT)?;
        let wall_clock = started.elapsed();
        let summary = match decode_index(
            captured.status.success(),
            &captured.stdout,
            &captured.stderr,
        ) {
            IndexOutcome::Built(summary) => summary,
            IndexOutcome::Empty => return Err(GraphError::EmptyIndex),
            IndexOutcome::NotARepository(message) => {
                return Err(GraphError::NotARepository(message))
            }
            IndexOutcome::Failed(message) => return Err(GraphError::Failed("index", message)),
            IndexOutcome::Unrecognised(reason) => {
                return Err(GraphError::Unrecognised("index", reason))
            }
        };
        Ok(BuildReport {
            key: key.clone(),
            work_unit: unit.clone(),
            checkout: checkout.clone(),
            index_dir,
            plugin_version: summary.provider_version,
            commit: summary.commit,
            wall_clock,
            tool_latency_ms: summary.latency_ms,
            cache_hit: summary.cache_hit,
            counts: summary.counts,
            completeness: summary.completeness,
        })
    }

    fn query<T>(
        &self,
        command: &'static str,
        key: &StepKey,
        checkout: &Checkout,
        arguments: &[&str],
        decode: fn(bool, &str, &str) -> Decoded<T>,
    ) -> Result<QueryReport<T>, GraphError> {
        let index_dir = self.prepare(checkout)?;
        let captured = self.run(command, arguments, &index_dir, GRAPH_QUERY_TIMEOUT)?;
        match decode(
            captured.status.success(),
            &captured.stdout,
            &captured.stderr,
        ) {
            Decoded::Answer {
                answer,
                revisions,
                index_cache_hit,
            } => Ok(QueryReport {
                key: key.clone(),
                revisions,
                index_cache_hit,
                answer,
            }),
            Decoded::Failed(message) => Err(GraphError::Failed(command, message)),
            Decoded::TooMany(count) => Err(GraphError::TooManyResults(command, count)),
            Decoded::Unrecognised(reason) => Err(GraphError::Unrecognised(command, reason)),
        }
    }
}

impl CodeGraph for EntireGraph {
    fn build(
        &self,
        key: &StepKey,
        unit: &WorkUnitId,
        checkout: &Checkout,
    ) -> Result<BuildReport, GraphError> {
        self.index(key, unit, checkout)
    }

    fn rebuild(
        &self,
        key: &StepKey,
        unit: &WorkUnitId,
        checkout: &Checkout,
    ) -> Result<BuildReport, GraphError> {
        self.index(key, unit, checkout)
    }

    fn definitions(
        &self,
        key: &StepKey,
        checkout: &Checkout,
        symbol: &Symbol,
    ) -> Result<QueryReport<Definitions>, GraphError> {
        let limit = GRAPH_RESULTS_MAX_ITEMS.to_string();
        let arguments = [
            "def",
            symbol.as_str(),
            "--repo",
            checkout.as_str(),
            "--head",
            "--members",
            &limit,
            "--format",
            "json",
        ];
        self.query("def", key, checkout, &arguments, decode_definitions)
    }

    fn callers(
        &self,
        key: &StepKey,
        checkout: &Checkout,
        symbol: &Symbol,
    ) -> Result<QueryReport<Callers>, GraphError> {
        let limit = GRAPH_RESULTS_MAX_ITEMS.to_string();
        let arguments = [
            "neighbors",
            "--symbol",
            symbol.as_str(),
            "--repo",
            checkout.as_str(),
            "--relation",
            "CALLS",
            "--direction",
            "in",
            "--depth",
            "1",
            "--limit",
            &limit,
            "--head",
            "--profile",
            PROFILE,
            "--format",
            "json",
        ];
        self.query("neighbors", key, checkout, &arguments, decode_callers)
    }

    fn impact(
        &self,
        key: &StepKey,
        checkout: &Checkout,
        base: &Revision,
        paths: &[RepoPath],
    ) -> Result<QueryReport<Impact>, GraphError> {
        let budget = GRAPH_DIFF_BUDGET_SECONDS.to_string();
        let mut arguments = vec![
            "diff",
            "--base",
            base.as_str(),
            "--head",
            "HEAD",
            "--json",
            "--max-seconds",
            &budget,
            "--repo",
            checkout.as_str(),
            "--",
        ];
        arguments.extend(paths.iter().map(RepoPath::as_str));
        self.query("diff", key, checkout, &arguments, decode_impact)
    }
}

/// Creates the root if missing and resolves it, so the inside-the-checkout check compares
/// real paths, not spellings.
#[expect(
    clippy::disallowed_methods,
    reason = "the index root is private to the core and resolved for comparison"
)]
fn canonical_root(index_root: &Path) -> Result<PathBuf, GraphError> {
    private_dir::ensure(&[index_root.to_path_buf()])
        .map_err(|error| GraphError::CannotPrepare(index_root.to_path_buf(), error.to_string()))?;
    fs::canonicalize(index_root)
        .map_err(|error| GraphError::CannotPrepare(index_root.to_path_buf(), error.to_string()))
}

#[cfg(test)]
mod tests;

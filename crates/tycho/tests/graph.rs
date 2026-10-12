//! Builds the semantic graph index of a copy of this repository in a temporary directory,
//! rebuilds it after a commit, queries it, and records the index build time. Needs the
//! pinned plugin installed; run by `mise run graph-tests`.
#![allow(
    clippy::disallowed_methods,
    reason = "fixtures live in throwaway directories no other user can write"
)]
#![allow(
    clippy::print_stdout,
    reason = "the evidence lines are the test's report for the pull request"
)]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers fail the test by panicking"
)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tycho_types::git_environment::git_command;

use tycho::code_graph::{
    BuildReport, Callers, Checkout, CodeGraph, Definitions, Impact, RepoPath, Revision, StepKey,
    Symbol,
};
use tycho::config;
use tycho::entire_graph::EntireGraph;
use tycho_types::service::WorkUnitId;

const PROBE_FILE: &str = "crates/tycho/src/graph_probe.rs";
const PROBE_SYMBOL: &str = "graph_probe_marker";

/// Removes the temporary tree even when an assertion fails.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}

fn git(checkout: &Path, arguments: &[&str]) {
    let status = git_command()
        .arg("-C")
        .arg(checkout)
        .args([
            "-c",
            "user.name=graph test",
            "-c",
            "user.email=graph@test.invalid",
        ])
        .args(["-c", "commit.gpgsign=false"])
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?} failed");
}

fn scratch() -> Scratch {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = env::temp_dir().join(format!("tycho-graph-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    Scratch(root.canonicalize().unwrap())
}

fn record(label: &str, report: &BuildReport) {
    let time = report.index_time();
    println!(
        "{label}: wall clock {} ms, tool {} ms, cache hit {}, commit {}, {} files, {} symbols, {} relations",
        time.wall_clock_ms,
        time.tool_latency_ms,
        time.cache_hit,
        time.commit,
        report.counts.files,
        report.counts.symbols,
        report.counts.relations
    );
}

fn default_cache_entries() -> Option<usize> {
    let home = env::var_os("HOME")?;
    let cache = Path::new(&home).join("Library/Caches/entire-graph");
    fs::read_dir(cache).ok().map(Iterator::count)
}

fn clone_this_repository(scratch: &Scratch, name: &str) -> Checkout {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let checkout_path = scratch.0.join(name);
    let status = git_command()
        .args(["clone", "--quiet", "--no-hardlinks"])
        .arg(&source)
        .arg(&checkout_path)
        .status()
        .unwrap();
    assert!(status.success());
    Checkout::parse(&checkout_path).unwrap()
}

fn key(text: &str) -> StepKey {
    StepKey::parse(text).unwrap()
}

/// A query on a checkout with no index builds one on the caller's path; the report says so.
fn query_unbuilt(graph: &EntireGraph, scratch: &Scratch) {
    let unbuilt = clone_this_repository(scratch, "unbuilt");
    let symbol = Symbol::parse("run_bounded").unwrap();
    let report = graph
        .definitions(&key("graph-test.unbuilt"), &unbuilt, &symbol)
        .unwrap();
    assert_eq!(report.index_cache_hit, Some(false));
    println!(
        "query on an unbuilt checkout: index cache hit {:?}",
        report.index_cache_hit
    );
}

fn query_known_symbol(graph: &EntireGraph, checkout: &Checkout) {
    let symbol = Symbol::parse("run_bounded").unwrap();
    let definitions = graph
        .definitions(&key("graph-test.def"), checkout, &symbol)
        .unwrap();
    assert!(matches!(definitions.answer, Definitions::Found { .. }));
    assert_eq!(definitions.index_cache_hit, Some(true));
    let callers = graph
        .callers(&key("graph-test.callers"), checkout, &symbol)
        .unwrap();
    let Callers::Found { callers, .. } = callers.answer else {
        panic!("no callers of run_bounded");
    };
    assert!(!callers.is_empty());
}

fn commit_probe(checkout: &Checkout) {
    fs::write(
        checkout.path().join(PROBE_FILE),
        format!("pub fn {PROBE_SYMBOL}() {{}}\n"),
    )
    .unwrap();
    git(checkout.path(), &["add", PROBE_FILE]);
    git(
        checkout.path(),
        &["commit", "--quiet", "-m", "test: graph probe"],
    );
}

fn query_probe(graph: &EntireGraph, checkout: &Checkout) {
    let probe = Symbol::parse(PROBE_SYMBOL).unwrap();
    let found = graph
        .definitions(&key("graph-test.probe"), checkout, &probe)
        .unwrap();
    assert!(
        matches!(found.answer, Definitions::Found { .. }),
        "{found:?}"
    );
    let base = Revision::parse("HEAD~1").unwrap();
    let paths = RepoPath::parse_all(&[PROBE_FILE]).unwrap();
    let impact = graph
        .impact(&key("graph-test.impact"), checkout, &base, &paths)
        .unwrap();
    let Impact::Complete(entities) = impact.answer else {
        panic!("impact is partial");
    };
    assert!(entities.iter().any(|entity| entity.name == PROBE_SYMBOL));
}

#[test]
#[ignore = "needs the pinned entire graph plugin; run by `mise run graph-tests`"]
fn builds_rebuilds_and_queries_this_repository() {
    let default_cache_before = default_cache_entries();
    let scratch = scratch();
    let checkout = clone_this_repository(&scratch, "checkout");
    let unit = WorkUnitId::parse("wu-graph-test").unwrap();
    let binary = config::entire_graph_path().unwrap();
    let graph = EntireGraph::open(&binary, &scratch.0.join("index")).unwrap();

    let built = graph
        .build(&key("graph-test.build"), &unit, &checkout)
        .unwrap();
    record("index build after clone", &built);
    assert!(!built.cache_hit);
    assert!(built.counts.files > 0 && built.counts.symbols > 0);
    assert!(built.index_dir.starts_with(&scratch.0));
    assert_eq!(built.key.as_str(), "graph-test.build");
    assert_eq!(built.index_time().work_unit, unit);

    let unchanged = graph
        .rebuild(&key("graph-test.same"), &unit, &checkout)
        .unwrap();
    record("rebuild with no commit", &unchanged);
    assert!(unchanged.cache_hit);
    query_known_symbol(&graph, &checkout);

    commit_probe(&checkout);
    let rebuilt = graph
        .rebuild(&key("graph-test.rebuild"), &unit, &checkout)
        .unwrap();
    record("rebuild after a commit", &rebuilt);
    assert!(!rebuilt.cache_hit);
    assert_ne!(rebuilt.commit, built.commit);
    query_probe(&graph, &checkout);
    query_unbuilt(&graph, &scratch);

    let index_files = fs::read_dir(&built.index_dir).unwrap().count();
    assert!(index_files > 0, "nothing written to the index directory");
    let default_cache_after = default_cache_entries();
    assert_eq!(default_cache_after, default_cache_before);
    println!(
        "index directory {} holds {index_files} entries",
        built.index_dir.display()
    );
    println!(
        "default cache entries before {default_cache_before:?}, after {default_cache_after:?}"
    );
}

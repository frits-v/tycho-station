//! `tycho graph`: builds and queries a checkout's semantic graph index for local inspection.

use std::fs;
use std::path::Path;
use std::process;

use tycho::code_graph::{Checkout, CodeGraph, RepoPath, Revision, StepKey, Symbol};
use tycho::config::{self, GRAPH_INDEX_DIR};
use tycho::entire_graph::EntireGraph;
use tycho::private_dir;
use tycho_types::service::WorkUnitId;

/// The commit a worker most recently added, which is what a reviewer asks about.
const IMPACT_BASE: &str = "HEAD~1";

#[expect(
    clippy::disallowed_methods,
    reason = "the command line names a developer checkout, resolved to the one spelling the plugin keys on"
)]
fn open(checkout: &str) -> Result<(EntireGraph, StepKey, Checkout), String> {
    let home = config::core_home().map_err(|error| error.to_string())?;
    let index_root = home.join(GRAPH_INDEX_DIR);
    private_dir::ensure(&[home]).map_err(|error| error.to_string())?;
    let binary = config::entire_graph_path().map_err(|error| error.to_string())?;
    let graph = EntireGraph::open(&binary, &index_root).map_err(|error| error.to_string())?;
    // The plugin keys its cache on the checkout path, so one checkout gets one spelling.
    let resolved = fs::canonicalize(Path::new(checkout))
        .map_err(|error| format!("cannot resolve {checkout}: {error}"))?;
    let checkout = Checkout::parse(&resolved).map_err(|error| error.to_string())?;
    let key =
        StepKey::parse(&format!("cli.{}", process::id())).map_err(|error| error.to_string())?;
    Ok((graph, key, checkout))
}

pub fn build(checkout: &str, unit: &str) -> Result<String, String> {
    let unit = WorkUnitId::parse(unit).map_err(|error| format!("work unit {unit}: {error}"))?;
    let (graph, key, checkout) = open(checkout)?;
    graph
        .build(&key, &unit, &checkout)
        .map(|report| report.to_string())
        .map_err(|error| error.to_string())
}

pub fn query(checkout: &str, kind: &str, argument: &str) -> Result<String, String> {
    let (graph, key, checkout) = open(checkout)?;
    let report = match kind {
        "definitions" => {
            let symbol = Symbol::parse(argument).map_err(|error| error.to_string())?;
            graph
                .definitions(&key, &checkout, &symbol)
                .map(|report| report.to_string())
        }
        "callers" => {
            let symbol = Symbol::parse(argument).map_err(|error| error.to_string())?;
            graph
                .callers(&key, &checkout, &symbol)
                .map(|report| report.to_string())
        }
        "impact" => {
            let base = Revision::parse(IMPACT_BASE).map_err(|error| error.to_string())?;
            let paths = RepoPath::parse_all(&[argument]).map_err(|error| error.to_string())?;
            graph
                .impact(&key, &checkout, &base, &paths)
                .map(|report| report.to_string())
        }
        _ => {
            return Err(format!(
                "unknown query {kind}; use definitions, callers or impact"
            ));
        }
    };
    report.map_err(|error| error.to_string())
}

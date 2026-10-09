#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    reason = "the binary is a command line tool; its output and exit code are its interface"
)]

use std::env;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::thread;

use tycho::config::{self, CoreConfig, ENDPOINT_PORT, PROBE_TIMEOUT, WATCHDOG_INTERVAL};
use tycho::epic_command::{self, OperatorAnswer};
use tycho::http::Http;
use tycho::launchd::Agent;
use tycho::services::merge_gate::NoGate;
use tycho::services::spawner::NoLauncher;
use tycho::services::{Ports, Timing};
use tycho::watchdog::{self, LoopEnd, Supervisor};
use tycho::{core, endpoint};

mod graph;

const USAGE: &str = "usage: tycho <command>
  endpoint                    serve the Restate services on the loopback port
  core start|stop|status      the restate-server and endpoint zmx sessions
  watchdog once|run           probe both sessions and restart what is missing
  watchdog install|uninstall  the launchd user agent that runs `watchdog run`
  graph build <checkout> <work-unit>   build the semantic graph index of a checkout
  graph query <checkout> definitions|callers <symbol>
  graph query <checkout> impact <path>   entities changed under the path since HEAD~1
  epic start <id> <goal>      start an epic through the operator service
  epic add-unit <id> <unit>   add a work unit to an epic through the operator service
  epic dispatch <id> <unit> <plan.json>   start a listed unit's run with a dispatch plan";

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let code = match words.as_slice() {
        ["endpoint"] => serve_endpoint(),
        ["core", "start"] => with_config(|config, supervisor| {
            let report = core::start(supervisor, config);
            finish(&report, report.succeeded(), config)
        }),
        ["core", "stop"] => with_config(|config, supervisor| {
            let report = core::stop(supervisor);
            finish(&report, report.succeeded(), config)
        }),
        ["core", "status"] => with_config(|config, supervisor| {
            let report = core::status(supervisor);
            finish(&report, report.succeeded(), config)
        }),
        ["watchdog", "once"] => with_config(|config, supervisor| {
            let report = supervisor.once();
            finish(&report, report.succeeded(), config)
        }),
        ["watchdog", "run"] => with_config(run_watchdog),
        ["epic", "start", epic, goal] => with_config(|config, _| {
            operator_call(|http| epic_command::start(config, http, epic, goal))
        }),
        ["epic", "dispatch", epic, unit, plan] => with_config(|config, _| {
            operator_call(|http| epic_command::dispatch(config, http, epic, unit, Path::new(plan)))
        }),
        ["epic", "add-unit", epic, unit] => with_config(|config, _| {
            operator_call(|http| epic_command::add_unit(config, http, epic, unit))
        }),
        ["watchdog", "install"] => with_config(|config, _| {
            report_result(
                Agent::for_default_label()
                    .and_then(|agent| agent.install(config))
                    .map_err(|error| error.to_string()),
            )
        }),
        ["watchdog", "uninstall"] => report_result(
            Agent::for_default_label()
                .and_then(|agent| agent.uninstall())
                .map_err(|error| error.to_string()),
        ),
        ["graph", "build", checkout, unit] => report_result(graph::build(checkout, unit)),
        ["graph", "query", checkout, kind, argument] => {
            report_result(graph::query(checkout, kind, argument))
        }
        _ => {
            eprintln!("{USAGE}");
            2
        }
    };
    process::exit(code);
}

fn serve_endpoint() -> i32 {
    let ports = Ports {
        spawner: Arc::new(NoLauncher),
        merge_gate: Arc::new(NoGate),
        timing: Timing::default(),
        operator_secret: env::var_os(config::HOME_ENV)
            .map(|home| PathBuf::from(home).join(config::OPERATOR_SECRET_FILE)),
    };
    match endpoint::serve(config::loopback(ENDPOINT_PORT), &ports) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("tycho: endpoint: {error}");
            1
        }
    }
}

fn with_config(action: impl FnOnce(&CoreConfig, &Supervisor) -> i32) -> i32 {
    let config = match CoreConfig::from_environment() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("tycho: {error}");
            return 2;
        }
    };
    let http = match Http::new(PROBE_TIMEOUT) {
        Ok(http) => http,
        Err(error) => {
            eprintln!("tycho: cannot build the HTTP client: {error}");
            return 2;
        }
    };
    match Supervisor::new(config.clone(), http) {
        Ok(supervisor) => action(&config, &supervisor),
        Err(error) => {
            eprintln!("tycho: refusing to start: {error}");
            2
        }
    }
}

fn finish(report: &impl Display, succeeded: bool, config: &CoreConfig) -> i32 {
    print!("{report}");
    println!("core home: {}", config.home.display());
    i32::from(!succeeded)
}

/// launchd restarts the watchdog only after an unsuccessful exit (`KeepAlive` with
/// `SuccessfulExit` false), so reaching the tick bound must exit non-zero and the stop file
/// exits zero.
const EXIT_TICKS_EXHAUSTED: i32 = 3;

fn run_watchdog(config: &CoreConfig, supervisor: &Supervisor) -> i32 {
    let stop_file = config.stop_file();
    let end = watchdog::run_bounded(
        config::WATCHDOG_ITERATIONS_MAX,
        WATCHDOG_INTERVAL,
        || stop_file.exists(),
        |iteration| println!("tick {iteration}\n{}", supervisor.once()),
        thread::sleep,
    );
    println!("watchdog run ended: {end:?}");
    match end {
        LoopEnd::StopFile(_) => 0,
        LoopEnd::IterationsExhausted(_) => EXIT_TICKS_EXHAUSTED,
    }
}

fn operator_call(action: impl FnOnce(&Http) -> Result<OperatorAnswer, String>) -> i32 {
    let answer = Http::new(config::COMMAND_TIMEOUT)
        .map_err(|error| format!("cannot build the HTTP client: {error}"))
        .and_then(|http| action(&http));
    match answer {
        Ok(OperatorAnswer::Done(body)) => {
            println!("{body}");
            0
        }
        Ok(other) => {
            eprintln!("tycho: {other}");
            1
        }
        Err(error) => {
            eprintln!("tycho: {error}");
            2
        }
    }
}

fn report_result(result: Result<String, String>) -> i32 {
    match result {
        Ok(done) => {
            println!("{done}");
            0
        }
        Err(error) => {
            eprintln!("tycho: {error}");
            1
        }
    }
}

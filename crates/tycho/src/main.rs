#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    reason = "the binary is a command line tool; its output and exit code are its interface"
)]

use std::env;
use std::fmt::Display;
use std::process;
use std::thread;

use tycho::config::{self, CoreConfig, ENDPOINT_PORT, PROBE_TIMEOUT, WATCHDOG_INTERVAL};
use tycho::http::Http;
use tycho::launchd::Agent;
use tycho::watchdog::{self, Supervisor};
use tycho::{core, endpoint};

const USAGE: &str = "usage: tycho <command>
  endpoint                    serve the Restate services on the loopback port
  core start|stop|status      the restate-server and endpoint zmx sessions
  watchdog once|run           probe both sessions and restart what is missing
  watchdog install|uninstall  the launchd user agent that runs `watchdog run`";

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let code = match words.as_slice() {
        ["endpoint"] => serve_endpoint(),
        ["core", "start"] => with_config(|config, supervisor| {
            let report = core::start(supervisor);
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
        _ => {
            eprintln!("{USAGE}");
            2
        }
    };
    process::exit(code);
}

fn serve_endpoint() -> i32 {
    match endpoint::serve(config::loopback(ENDPOINT_PORT)) {
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
    action(&config, &Supervisor::new(config.clone(), http))
}

fn finish(report: &impl Display, succeeded: bool, config: &CoreConfig) -> i32 {
    print!("{report}");
    println!("core home: {}", config.home.display());
    i32::from(!succeeded)
}

/// Exits after a bounded number of ticks; launchd's `KeepAlive` starts the next run.
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
    0
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

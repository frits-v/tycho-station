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

use tycho::config::{
    self, CoreConfig, ENDPOINT_PORT, PROBE_TIMEOUT, VERDICT_INTERVAL, VERDICT_ITERATIONS_MAX,
    WATCHDOG_INTERVAL,
};
use tycho::config_store::{self, FactoryConfig, CONFIG_DIR_ENV};
use tycho::epic_command::{self, OperatorAnswer};
use tycho::http::Http;
use tycho::launchd::Agent;
use tycho::launcher;
use tycho::services::merge_gate::NoGate;
use tycho::services::operator::read_secret_file;
use tycho::services::spawner::NoLauncher;
use tycho::services::{Ports, Timing};
use tycho::watchdog::{self, LoopEnd, Supervisor};
use tycho::{agent_files, core, endpoint, verdicts};

mod graph;

const USAGE: &str = "usage: tycho <command>
  endpoint                    serve the Restate services on the loopback port
  core start|stop|status      the restate-server and endpoint zmx sessions
  watchdog once|run           probe both sessions and restart what is missing
  watchdog install|uninstall  the launchd user agent that runs `watchdog run`
  verdicts once|run           apply the verdict files typed beside decision packets
  graph build <checkout> <work-unit>   build the semantic graph index of a checkout
  graph query <checkout> definitions|callers <symbol>
  graph query <checkout> impact <path>   entities changed under the path since HEAD~1
  epic start <id> <goal>      start an epic through the operator service
  epic add-unit <id> <unit>   add a work unit to an epic through the operator service
  epic dispatch <id> <unit> <plan.json>   start a listed unit's run with a dispatch plan
  launch --spec <spec file> [--tier <tier>]   run a vendor session: lease, heartbeat, spool, resolve
  launch --replay <spool file>    deliver a spooled result that was never acknowledged
  worker --vendor <vendor> ...    run one headless worker inside a launcher session";

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let code = match words.as_slice() {
        ["endpoint"] => serve_endpoint(),
        ["core", "start"] => with_config(|config, supervisor| {
            if let Err(error) = factory_config(Some(&config.home)) {
                eprintln!("tycho: refusing to start: {error}");
                return 2;
            }
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
        ["verdicts", mode @ ("once" | "run")] => with_config(|config, _| verdicts(config, mode)),
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
        ["launch", "--replay", spool] => replay(spool),
        ["launch", "--spec", spec] => launch(spec, None),
        ["launch", "--spec", spec, "--tier", tier] => launch(spec, Some(tier)),
        ["worker", ..] => worker(arguments.get(1..).unwrap_or_default()),
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

const LAUNCH_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn launch_http() -> Result<Http, i32> {
    Http::new(LAUNCH_HTTP_TIMEOUT).map_err(|error| {
        eprintln!("tycho: cannot build the HTTP client: {error}");
        launcher::EXIT_REFUSED_TO_START
    })
}

/// Fails closed before anything runs: no lease, no vendor, no ingress call.
fn launch(spec: &str, tier: Option<&str>) -> i32 {
    let taken = launcher::core_uid_from_environment().and_then(|core_uid| {
        let tier = tier.map(launcher::check_tier).transpose()?;
        let (settings, vendor) = launcher::take_spec(Path::new(spec), core_uid)?;
        Ok((launcher::LauncherSettings { tier, ..settings }, vendor))
    });
    let (settings, vendor) = match taken {
        Ok(taken) => taken,
        Err(error) => {
            eprintln!("tycho: launch refused: {error}");
            return launcher::EXIT_REFUSED_TO_START;
        }
    };
    let http = match launch_http() {
        Ok(http) => http,
        Err(code) => return code,
    };
    match launcher::launch(&settings, &vendor, &http) {
        Ok(end) => {
            println!("{end}");
            end.exit_code()
        }
        Err(error) => {
            eprintln!("tycho: launch: lease not written: {error}");
            launcher::EXIT_REFUSED_TO_START
        }
    }
}

/// The launcher's vendor command for a headless worker; the event stream goes to stdout.
fn worker(words: &[String]) -> i32 {
    let environment = env::vars().collect();
    let mut stdout = std::io::stdout();
    match tycho::vendors::worker_process::run(words, &environment, &mut stdout) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("tycho: worker refused: {error}");
            tycho::vendors::worker_process::EXIT_REFUSED
        }
    }
}

fn replay(spool: &str) -> i32 {
    let http = match launch_http() {
        Ok(http) => http,
        Err(code) => return code,
    };
    let owner = match config::agent_uid() {
        Ok(owner) => owner,
        Err(error) => {
            eprintln!("tycho: replay refused: {error}");
            return launcher::EXIT_REFUSED_TO_START;
        }
    };
    match tycho::spool::replay(&http, Path::new(spool), owner, &mut thread::sleep) {
        Ok(delivery) => {
            println!("{delivery:?}");
            i32::from(!delivery.acknowledged())
        }
        Err(error) => {
            eprintln!("tycho: replay refused: {error}");
            launcher::EXIT_REFUSED_TO_START
        }
    }
}

/// Loads the configuration from `TYCHO_CONFIG_DIR`, `<home>/config` or the embedded export.
fn factory_config(home: Option<&Path>) -> Result<FactoryConfig, String> {
    let source = config_store::resolve_source(env::var_os(CONFIG_DIR_ENV), home)
        .map_err(|error| error.to_string())?;
    let loaded = config_store::load(&source).map_err(|error| error.to_string())?;
    let hashes = loaded.hashes();
    println!(
        "configuration: {source} (routing {}, thresholds {})",
        hashes.routing, hashes.thresholds
    );
    Ok(loaded)
}

fn serve_endpoint() -> i32 {
    let home = env::var_os(config::HOME_ENV).map(PathBuf::from);
    let factory = match factory_config(home.as_deref()) {
        Ok(factory) => factory,
        Err(error) => {
            eprintln!("tycho: endpoint: {error}");
            return 1;
        }
    };
    let ports = Ports {
        spawner: Arc::new(NoLauncher),
        merge_gate: Arc::new(NoGate),
        timing: Timing::from_thresholds(&factory.thresholds.value),
        config: Arc::new(factory),
        operator_secret: home
            .as_ref()
            .map(|home| home.join(config::OPERATOR_SECRET_FILE)),
        packet_dir: home.map(|home| home.join(config::PACKET_DIR)),
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

fn verdicts(config: &CoreConfig, mode: &str) -> i32 {
    if mode == "run" {
        run_verdicts(config)
    } else {
        verdicts_once(config)
    }
}

/// One pass; a pass that could not run, or that the operator refused, exits non-zero.
fn verdicts_once(config: &CoreConfig) -> i32 {
    let secret = match read_secret_file(&config.operator_secret_file()) {
        Ok(secret) => secret,
        Err(error) => {
            eprintln!("tycho: verdicts: {error}");
            return 2;
        }
    };
    let http = match Http::new(config::COMMAND_TIMEOUT) {
        Ok(http) => http,
        Err(error) => {
            eprintln!("tycho: verdicts: cannot build the HTTP client: {error}");
            return 2;
        }
    };
    let report = verdicts::pass(
        &config.packet_dir(),
        agent_files::current_uid(),
        &mut |request| verdicts::rule_through_operator(&http, secret.expose(), request),
    );
    print!("{report}");
    i32::from(!report.succeeded())
}

fn run_verdicts(config: &CoreConfig) -> i32 {
    let stop_file = config.stop_file();
    let end = watchdog::run_bounded(
        VERDICT_ITERATIONS_MAX,
        VERDICT_INTERVAL,
        || stop_file.exists(),
        |_| {
            verdicts_once(config);
        },
        thread::sleep,
    );
    println!("verdicts run ended: {end:?}");
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

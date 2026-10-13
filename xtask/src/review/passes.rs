//! The two kinds of Claude pass: one find pass over the diff, then a verify pass per
//! candidate, each in a fresh session, with what each one spent recorded for the trace.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;

use super::claude_run::{self, Limits, RunOutcome};
use super::findings::{self, Finding, Verdict};
use super::langfuse::Generation;
use super::pull_request::Posted;
use super::verdict::blocks;
use super::{git_in, Context, Tally, EXCLUDED_PATHSPECS, VERIFIED_MAX};
use crate::process::{run_bounded, Exit};

const FIND_SCHEMA: &str = include_str!("../../../config/export/schema/review_findings.json");
const VERDICT_SCHEMA: &str = include_str!("../../../config/export/schema/review_verdict.json");
const FIND_INSTRUCTIONS: &str = include_str!("../../prompts/review-find.md");
const VERIFY_INSTRUCTIONS: &str = include_str!("../../prompts/review-verify.md");
const DIFF_MAX_BYTES: usize = 512 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(120);
const FIND_LIMITS: Limits = Limits {
    max_turns: 80,
    max_budget_usd: 10,
};
const VERIFY_LIMITS: Limits = Limits {
    max_turns: 30,
    max_budget_usd: 2,
};
const VERIFY_PARALLEL: usize = 4;
const ONE_RUN_MIN: Duration = Duration::from_secs(60);

fn write_file(path: &Path, text: &str) -> Result<(), String> {
    fs::write(path, text).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// The diff of the reviewed checkout, through git without the run's secrets: it runs inside
/// the pull request's checkout.
fn diff_command(context: &Context) -> Command {
    let mut command = git_in(&context.checkout);
    command
        .args(["-c", "core.quotePath=false", "diff", "--no-color"])
        .args(["--no-ext-diff", "--no-textconv", "-M", "--unified=3"])
        .arg(format!("{}...{}", context.base, context.head))
        .args(["--", "."])
        .args(EXCLUDED_PATHSPECS);
    command
}

/// The diff, written where the model can read it with the earlier findings beside it.
pub fn prepare(context: &Context) -> Result<String, String> {
    let range = format!("{}...{}", context.base, context.head);
    let captured = run_bounded(&mut diff_command(context), GIT_TIMEOUT);
    if captured.exit != Exit::Code(0) {
        return Err(format!("git diff {range} ended {:?}", captured.exit));
    }
    if captured.stdout.len() > DIFF_MAX_BYTES {
        return Err(format!(
            "the diff is {} bytes; the review takes at most {DIFF_MAX_BYTES}",
            captured.stdout.len()
        ));
    }
    write_file(&context.files.join("diff.patch"), &captured.stdout)?;
    write_file(
        &context.files.join("posted.json"),
        &posted_listing(&context.posted),
    )?;
    Ok(captured.stdout)
}

fn posted_listing(posted: &[Posted]) -> String {
    let entries: Vec<Value> = posted
        .iter()
        .map(|entry| Value::from(entry.excerpt.as_str()))
        .collect();
    Value::Array(entries).to_string()
}

fn render(template: &str, context: &Context, finding: Option<&Finding>) -> String {
    let finding = finding
        .and_then(|finding| serde_json::to_string_pretty(finding).ok())
        .unwrap_or_default();
    let in_files = |name: &str| context.files.join(name).display().to_string();
    template
        .replace("{{head}}", &context.head)
        .replace("{{base}}", &context.base)
        .replace("{{files}}", &context.files.display().to_string())
        .replace("{{diff}}", &in_files("diff.patch"))
        .replace("{{posted}}", &in_files("posted.json"))
        .replace("{{finding}}", &finding)
}

/// The exported schema on one line without its `$schema` dialect: the CLI's validator refuses
/// the draft 2020-12 URI cue writes, and reads `$defs` and patterns without it.
pub fn minified(schema: &str) -> Result<String, String> {
    let mut value = serde_json::from_str::<Value>(schema)
        .map_err(|_| "an exported review schema is not JSON; run `mise run config-export`")?;
    value
        .as_object_mut()
        .ok_or("an exported review schema is not a JSON object")?
        .remove("$schema");
    Ok(value.to_string())
}

/// One pass: the instructions written to the run's directory, the CLI run under the
/// deadline, and the generation the trace records.
fn run_claude(
    context: &Context,
    name: &str,
    instructions: &str,
    schema: &str,
    limits: Limits,
    deadline: Instant,
) -> (RunOutcome, Generation) {
    let started = SystemTime::now();
    let path = context.files.join(format!("{name}.md"));
    let outcome = match (
        write_file(&path, instructions),
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| *remaining >= ONE_RUN_MIN),
    ) {
        (Err(reason), _) => RunOutcome::Unrecognised(reason),
        (Ok(()), None) => RunOutcome::Ended(Exit::TimedOut),
        (Ok(()), Some(remaining)) => {
            let environment = claude_run::environment(
                std::env::vars_os(),
                context.user.as_deref(),
                context
                    .access_token
                    .as_ref()
                    .map(|token| token.value.expose()),
            );
            let mut command = claude_run::command(
                &context.claude,
                &path,
                &context.files,
                schema,
                limits,
                environment,
            );
            command.current_dir(&context.checkout);
            let captured = run_bounded(&mut command, remaining);
            claude_run::decode(captured.exit, &captured.stdout)
        }
    };
    let generation = Generation {
        name: name.to_string(),
        model: claude_run::MODEL,
        started,
        ended: SystemTime::now(),
        input: instructions.to_string(),
        output: match &outcome {
            RunOutcome::Answered { output, .. } => output.to_string(),
            other => other.label(),
        },
        outcome: outcome.label(),
        usage: outcome.usage(),
    };
    (outcome, generation)
}

pub fn find(
    context: &Context,
    deadline: Instant,
    tally: &mut Tally,
) -> Result<Vec<Finding>, String> {
    let instructions = render(FIND_INSTRUCTIONS, context, None);
    let (outcome, generation) = run_claude(
        context,
        "find",
        &instructions,
        &minified(FIND_SCHEMA)?,
        FIND_LIMITS,
        deadline,
    );
    tally.cost = tally.cost.saturating_add(generation.usage.cost);
    tally.generations.push(generation);
    match outcome {
        RunOutcome::Answered { output, .. } => {
            let candidates = findings::decode_findings(&output)?;
            tally.candidates = candidates.len();
            Ok(candidates)
        }
        other => Err(format!("the find pass ended {}", other.label())),
    }
}

/// One verify pass; `Ok` carries the verdict, `Err` why the pass gave none.
fn verify_one(
    context: &Context,
    index: usize,
    finding: &Finding,
    schema: &str,
    deadline: Instant,
) -> (Result<Verdict, String>, Generation) {
    let instructions = render(VERIFY_INSTRUCTIONS, context, Some(finding));
    let name = format!("verify-{index}");
    let (outcome, generation) = run_claude(
        context,
        &name,
        &instructions,
        schema,
        VERIFY_LIMITS,
        deadline,
    );
    let verdict = match outcome {
        RunOutcome::Answered { output, .. } => {
            findings::decode_verdict(&output).map(|(verdict, reasoning)| {
                println!(
                    "xtask review: {}:{} {verdict:?}: {reasoning}",
                    finding.path, finding.line
                );
                verdict
            })
        }
        other => Err(other.label()),
    };
    (verdict, generation)
}

fn verify_chunk(
    context: &Context,
    first_index: usize,
    chunk: &[Finding],
    schema: &str,
    deadline: Instant,
) -> Vec<(Result<Verdict, String>, Option<Generation>)> {
    #[allow(
        clippy::needless_collect,
        reason = "every pass in the chunk starts before the first is joined"
    )]
    thread::scope(|scope| {
        let handles: Vec<_> = chunk
            .iter()
            .enumerate()
            .map(|(offset, finding)| {
                let index = first_index.saturating_add(offset);
                scope.spawn(move || verify_one(context, index, finding, schema, deadline))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| match handle.join() {
                Ok((verdict, generation)) => (verdict, Some(generation)),
                Err(_) => (Err("the verify thread panicked".to_string()), None),
            })
            .collect()
    })
}

/// Verifies the most severe candidates, a few sessions at a time, and keeps the confirmed.
/// A blocking candidate over the cap or without a verdict is counted as unjudged.
pub fn verify(
    context: &Context,
    candidates: &[Finding],
    deadline: Instant,
    tally: &mut Tally,
) -> Vec<Finding> {
    let schema = match minified(VERDICT_SCHEMA) {
        Ok(schema) => schema,
        Err(reason) => {
            tally.failed.push(reason);
            tally.unjudged_blocking = candidates.iter().filter(|finding| blocks(finding)).count();
            return Vec::new();
        }
    };
    let over_cap = candidates.get(VERIFIED_MAX..).unwrap_or_default();
    tally.unverified = over_cap.len();
    tally.unjudged_blocking = over_cap.iter().filter(|finding| blocks(finding)).count();
    let checked = candidates.get(..VERIFIED_MAX).unwrap_or(candidates);
    let mut confirmed = Vec::new();
    for (batch, chunk) in checked.chunks(VERIFY_PARALLEL).enumerate() {
        let first = batch.saturating_mul(VERIFY_PARALLEL);
        let results = verify_chunk(context, first, chunk, &schema, deadline);
        for (finding, (verdict, generation)) in chunk.iter().zip(results) {
            if let Some(generation) = generation {
                tally.cost = tally.cost.saturating_add(generation.usage.cost);
                tally.generations.push(generation);
            }
            match verdict {
                Ok(Verdict::Confirmed) => confirmed.push(finding.clone()),
                Ok(Verdict::Refuted) => tally.refuted = tally.refuted.saturating_add(1),
                Err(reason) => {
                    if blocks(finding) {
                        tally.unjudged_blocking = tally.unjudged_blocking.saturating_add(1);
                    }
                    tally
                        .failed
                        .push(format!("{}:{}: {reason}", finding.path, finding.line));
                }
            }
        }
    }
    tally.confirmed = confirmed.len();
    confirmed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schemas_handed_to_the_cli_name_no_dialect_and_the_prompts_name_every_placeholder() {
        for schema in [FIND_SCHEMA, VERDICT_SCHEMA] {
            assert!(schema.contains("\"$schema\""));
            let handed = minified(schema).unwrap();
            assert!(!handed.contains("$schema"), "{handed}");
            assert!(handed.contains("\"$defs\""));
        }
        for placeholder in [
            "{{head}}",
            "{{base}}",
            "{{files}}",
            "{{diff}}",
            "{{posted}}",
        ] {
            assert!(FIND_INSTRUCTIONS.contains(placeholder), "{placeholder}");
        }
        for placeholder in [
            "{{head}}",
            "{{base}}",
            "{{files}}",
            "{{diff}}",
            "{{finding}}",
        ] {
            assert!(VERIFY_INSTRUCTIONS.contains(placeholder), "{placeholder}");
        }
    }

    #[test]
    fn the_diff_runs_in_the_reviewed_checkout_without_the_runs_secrets() {
        let context = crate::review::setup::tests::context(Vec::new(), "t");
        let command = diff_command(&context);
        let removed: Vec<&std::ffi::OsStr> = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name)
            .collect();
        for name in crate::review::SECRET_VARIABLES {
            assert!(removed.contains(&std::ffi::OsStr::new(name)), "{name}");
        }
        let words: Vec<String> = command
            .get_args()
            .map(|word| word.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            words.get(..2),
            Some(["-C".to_string(), "/r/pull-request".to_string()].as_slice())
        );
        assert!(words.contains(&"--no-ext-diff".to_string()));
        assert!(words.contains(&"--no-textconv".to_string()));
    }

    #[test]
    fn a_rendered_prompt_names_the_runs_own_files() {
        let context = crate::review::setup::tests::context(Vec::new(), "t");
        let rendered = render(FIND_INSTRUCTIONS, &context, None);
        assert!(rendered.contains("/t/tycho-review-1/diff.patch"));
        assert!(rendered.contains("/t/tycho-review-1/posted.json"));
        assert!(!rendered.contains("{{"));
    }

    #[test]
    fn a_pass_past_its_deadline_never_starts_and_is_recorded() {
        let context = crate::review::setup::tests::context(Vec::new(), "t");
        let dir = std::env::temp_dir().join(format!("tycho-review-pass-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let context = Context {
            files: dir.clone(),
            ..context
        };
        let (outcome, generation) =
            run_claude(&context, "find", "text", "{}", FIND_LIMITS, Instant::now());
        assert_eq!(outcome, RunOutcome::Ended(Exit::TimedOut));
        assert_eq!(generation.name, "find");
        assert_eq!(generation.input, "text");
        assert_eq!(generation.outcome, "ended TimedOut");
        fs::remove_file(dir.join("find.md")).unwrap();
        fs::remove_dir(&dir).unwrap();
    }
}

//! The decision packet of design section 9 in its markdown form.
//!
//! A blocker is rendered as a choice and written 0600 under
//! `<core home>/packets/<epic>/<unit>-<attempt>.md`, beside the verdict path the human types into.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use tycho_types::envelope::{
    CommitSha, ContentRef, EscalationOption, EscalationPayload, OPTIONS_MAX_ITEMS, QuestionType,
    Reversibility,
};
use tycho_types::service::{Attempt, EpicId, WorkUnitId};
use tycho_types::session::Level;

use crate::agent_files;

/// No payload within the envelope's bounds plus bounded findings reaches this.
pub const PACKET_MAX_BYTES: usize = 32_768;
/// Findings the packet lists under what was tried, and the bytes each keeps.
pub const FINDINGS_MAX_ITEMS: usize = 16;
pub const FINDING_MAX_BYTES: usize = 512;
/// The verdict file's optional second line; the packet states it to the reader.
pub const RATIONALE_MAX_BYTES: usize = 280;
pub const PACKET_EXTENSION: &str = "md";
pub const VERDICT_EXTENSION: &str = "verdict";

const OPTION_LETTERS: [&str; 4] = ["A", "B", "C", "D"];
const _: () = assert!(OPTION_LETTERS.len() == OPTIONS_MAX_ITEMS);
/// Mandate 10.2: a row the payload cannot fill is shown as missing, never dropped.
const NOT_SUPPLIED: &str = "not supplied by the worker";

/// Why the unit is escalated: a worker's certified question, or the unit's own give-up rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocker {
    Certified(EscalationPayload),
    Uncertified { reason: String },
}

/// The unit around the blocker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketContext {
    pub epic: EpicId,
    pub unit: WorkUnitId,
    pub attempt: Attempt,
    pub head_sha: Option<CommitSha>,
    /// No checkpoint exists before slice one; the packet says none.
    pub checkpoint: Option<CommitSha>,
    pub findings: Vec<String>,
}

#[derive(Debug)]
pub enum PacketError {
    TooLarge { bytes: usize, max: usize },
    Io(PathBuf, io::Error),
}

impl fmt::Display for PacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes, max } => {
                write!(formatter, "the packet is {bytes} bytes; maximum is {max}")
            }
            Self::Io(path, error) => write!(formatter, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for PacketError {}

/// `<packet dir>/<epic>/<unit>-<attempt>.<extension>`.
#[must_use]
pub fn unit_path(
    packet_dir: &Path,
    epic: &EpicId,
    unit: &WorkUnitId,
    attempt: Attempt,
    extension: &str,
) -> PathBuf {
    packet_dir
        .join(epic.as_str())
        .join(format!("{unit}-{}.{extension}", attempt.get()))
}

/// Renders, then replaces the packet atomically, so a replayed step writes the same file.
pub fn write(
    packet_dir: &Path,
    blocker: &Blocker,
    context: &PacketContext,
) -> Result<PathBuf, PacketError> {
    let epic_dir = packet_dir.join(context.epic.as_str());
    for dir in [packet_dir, epic_dir.as_path()] {
        agent_files::ensure_private_dir(dir)
            .map_err(|error| PacketError::Io(dir.to_path_buf(), error))?;
    }
    let packet = unit_path(
        packet_dir,
        &context.epic,
        &context.unit,
        context.attempt,
        PACKET_EXTENSION,
    );
    let verdict = packet.with_extension(VERDICT_EXTENSION);
    // Slice zero has no content store, so no reference is verified.
    let text = render(blocker, context, &verdict, &|_| false, PACKET_MAX_BYTES)?;
    agent_files::write_durable(&packet, text.as_bytes())
        .map_err(|error| PacketError::Io(packet.clone(), error))?;
    Ok(packet)
}

/// The packet text; a reference `verified` refuses counts as an unverified claim.
pub fn render(
    blocker: &Blocker,
    context: &PacketContext,
    verdict: &Path,
    verified: &dyn Fn(&ContentRef) -> bool,
    max: usize,
) -> Result<String, PacketError> {
    let mut text = String::new();
    header(&mut text, context);
    let (unverified, lettered) = match blocker {
        Blocker::Certified(payload) => (
            certified(&mut text, payload, verified),
            !payload.options.is_empty(),
        ),
        Blocker::Uncertified { reason } => {
            uncertified(&mut text, reason, context.attempt);
            (0, false)
        }
    };
    tried(&mut text, context);
    cases(&mut text, blocker);
    verdict_section(&mut text, verdict, context.attempt, lettered);
    line(&mut text, &format!("Unverified claims: {unverified}"));
    if text.len() > max {
        return Err(PacketError::TooLarge {
            bytes: text.len(),
            max,
        });
    }
    Ok(text)
}

fn line(text: &mut String, value: &str) {
    text.push_str(value);
    text.push('\n');
}

fn heading(text: &mut String, value: &str) {
    line(text, "");
    line(text, value);
    line(text, "");
}

fn header(text: &mut String, context: &PacketContext) {
    let sha = |value: Option<&CommitSha>| value.map_or("none", CommitSha::as_str).to_string();
    line(
        text,
        &format!(
            "# Decision packet: {}, attempt {}",
            context.unit,
            context.attempt.get()
        ),
    );
    line(text, "");
    for (label, value) in [
        ("Epic", context.epic.to_string()),
        ("Work unit", context.unit.to_string()),
        ("Attempt", context.attempt.get().to_string()),
        ("Head", sha(context.head_sha.as_ref())),
        ("Checkpoint", sha(context.checkpoint.as_ref())),
        ("Blocks", "yes; the unit waits for this verdict".to_string()),
        ("Default", "none".to_string()),
    ] {
        line(text, &format!("- {label}: {value}"));
    }
}

/// Writes the question, options, recommendation and evidence; returns the unverified count.
fn certified(
    text: &mut String,
    payload: &EscalationPayload,
    verified: &dyn Fn(&ContentRef) -> bool,
) -> usize {
    heading(text, "## Question");
    let lettered: Vec<(&str, &EscalationOption)> =
        OPTION_LETTERS.into_iter().zip(&payload.options).collect();
    if !lettered.is_empty() {
        let choices: Vec<String> = lettered
            .iter()
            .map(|(letter, option)| format!("{letter}, {}", option.label))
            .collect();
        line(text, &format!("Choose one: {}.", choices.join("; ")));
        line(text, "");
    }
    line(
        text,
        &format!("The worker stopped because {}.", payload.give_up_reason),
    );
    line(text, "");
    line(
        text,
        &format!(
            "Type: {}, raised at the {} level. Full question: {}",
            question_type(payload.question_type),
            level(payload.level_reached),
            payload.question
        ),
    );
    heading(text, "## Options");
    if lettered.is_empty() {
        line(text, &format!("None: {NOT_SUPPLIED}."));
    }
    for (index, (letter, option)) in lettered.iter().enumerate() {
        if index > 0 {
            line(text, "");
        }
        let blast_radius = option.blast_radius.to_string();
        option_rows(
            text,
            &format!("{letter}: {}", option.label),
            [
                NOT_SUPPLIED,
                NOT_SUPPLIED,
                &blast_radius,
                reversibility(option.reversibility),
            ],
        );
    }
    let ruling = payload.proposed_ruling.as_ref().map(ToString::to_string);
    recommendation(text, ruling.as_deref().unwrap_or(NOT_SUPPLIED));
    evidence(text, payload, verified)
}

/// Lists the evidence and returns how many distinct references are unverified.
fn evidence(
    text: &mut String,
    payload: &EscalationPayload,
    verified: &dyn Fn(&ContentRef) -> bool,
) -> usize {
    heading(text, "## Evidence");
    if payload.evidence.is_empty() {
        line(text, &format!("None: {NOT_SUPPLIED}."));
    }
    for reference in &payload.evidence {
        line(text, &format!("- {reference}"));
    }
    let claims: BTreeSet<&ContentRef> = payload
        .evidence
        .iter()
        .chain(&payload.proposed_ruling)
        .collect();
    claims
        .into_iter()
        .filter(|reference| !verified(reference))
        .count()
}

/// One option: gains, accepting that, blast radius, reversibility, each on its own row.
fn option_rows(text: &mut String, title: &str, rows: [&str; 4]) {
    line(text, &format!("### {title}"));
    line(text, "");
    let labels = ["Gains", "Accepting that", "Blast radius", "Reversibility"];
    for (label, value) in labels.into_iter().zip(rows) {
        line(text, &format!("- {label}: {value}"));
    }
}

fn recommendation(text: &mut String, ruling: &str) {
    heading(text, "## Recommendation");
    for (label, value) in [
        ("Proposed ruling", ruling),
        ("Confidence", NOT_SUPPLIED),
        ("Strongest dissent", NOT_SUPPLIED),
    ] {
        line(text, &format!("- {label}: {value}"));
    }
}

fn uncertified(text: &mut String, reason: &str, attempt: Attempt) {
    let next = attempt.get().saturating_add(1);
    heading(text, "## Question");
    line(
        text,
        &format!("Continue with attempt {next}, or abandon the unit?"),
    );
    line(text, "");
    line(text, &format!("The unit stopped because {reason}."));
    heading(text, "## Options");
    let budget = format!("attempt {next} spends another attempt's budget");
    option_rows(
        text,
        "Continue",
        [
            "another attempt at the done criteria",
            &budget,
            "this unit only",
            "two-way",
        ],
    );
    line(text, "");
    option_rows(
        text,
        "Abandon",
        [
            "no further budget spent on this unit",
            "the unit ends unmerged",
            "this unit only",
            "costly: the unit must be dispatched again",
        ],
    );
    recommendation(
        text,
        "not supplied; the unit's own give-up rule raised this blocker",
    );
}

fn tried(text: &mut String, context: &PacketContext) {
    heading(text, "## Already tried");
    let earlier = context.attempt.get().saturating_sub(1);
    line(text, &format!("Earlier attempts: {earlier}."));
    for finding in context.findings.iter().take(FINDINGS_MAX_ITEMS) {
        if finding.len() > FINDING_MAX_BYTES {
            line(
                text,
                &format!(
                    "- A finding of {} bytes, over the {FINDING_MAX_BYTES}-byte bound; the unit's view holds it.",
                    finding.len()
                ),
            );
        } else {
            line(text, &format!("- {finding}"));
        }
    }
    let more = context.findings.len().saturating_sub(FINDINGS_MAX_ITEMS);
    if more > 0 {
        line(
            text,
            &format!("- {more} more findings; the unit's view holds them."),
        );
    }
}

fn cases(text: &mut String, blocker: &Blocker) {
    heading(text, "## Cases consulted");
    let consulted = match blocker {
        Blocker::Certified(payload) => payload.cases_consulted.as_slice(),
        Blocker::Uncertified { .. } => &[],
    };
    if consulted.is_empty() {
        line(text, "None.");
    }
    for case in consulted {
        line(text, &format!("- {case}"));
    }
}

fn verdict_section(text: &mut String, verdict: &Path, attempt: Attempt, lettered: bool) {
    let next = attempt.get().saturating_add(1);
    heading(text, "## Verdict");
    let letter = if lettered {
        " Begin the rationale with the letter of the option you choose, as in `B: ask the \
         council`; `continue` records it as the chosen option."
    } else {
        ""
    };
    let body = format!(
        "Write `{}` with one line, `continue` or `abandon`. `continue` starts attempt {next}; \
         `abandon` ends the unit. An optional second line is the rationale, at most \
         {RATIONALE_MAX_BYTES} bytes; for `abandon` it is the reason the unit records.{letter} \
         Any other content is rejected and the unit stays escalated.",
        verdict.display()
    );
    line(text, &body);
    line(text, "");
}

const fn question_type(value: QuestionType) -> &'static str {
    match value {
        QuestionType::Empirical => "empirical",
        QuestionType::Judgment => "judgment",
        QuestionType::Authority => "authority",
    }
}

const fn level(value: Level) -> &'static str {
    match value {
        Level::Root => "root",
        Level::Control => "control",
        Level::Worker => "worker",
    }
}

const fn reversibility(value: Reversibility) -> &'static str {
    match value {
        Reversibility::TwoWay => "two-way",
        Reversibility::Costly => "costly",
        Reversibility::OneWay => "one-way",
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tycho_types::envelope::ShortText;

    fn reference(fill: char) -> ContentRef {
        ContentRef::parse(&format!("sha256:{}", fill.to_string().repeat(64))).unwrap()
    }

    fn text(value: &str) -> ShortText {
        ShortText::parse(value).unwrap()
    }

    fn payload() -> EscalationPayload {
        EscalationPayload {
            level_reached: Level::Worker,
            give_up_reason: text(
                "the objective edits a budget ceiling that POLICY.md reserves for a council ruling",
            ),
            question: reference('a'),
            question_type: QuestionType::Authority,
            options: vec![
                EscalationOption {
                    label: text("raise the ceiling as the objective asks"),
                    reversibility: Reversibility::Costly,
                    blast_radius: text("every unit in the epic runs under the new ceiling"),
                },
                EscalationOption {
                    label: text("leave the ceiling and ask for a council ruling"),
                    reversibility: Reversibility::TwoWay,
                    blast_radius: text("the trivial unit stays constrained until the ruling"),
                },
            ],
            proposed_ruling: Some(reference('b')),
            evidence: vec![reference('c'), reference('d')],
            cases_consulted: Vec::new(),
            blocking: true,
        }
    }

    fn context() -> PacketContext {
        PacketContext {
            epic: EpicId::parse("cf7a").unwrap(),
            unit: WorkUnitId::parse("wu01").unwrap(),
            attempt: Attempt::FIRST,
            head_sha: None,
            checkpoint: None,
            findings: Vec::new(),
        }
    }

    const EXPECTED: &str = include_str!("fixtures/packet.md");

    #[test]
    fn a_certified_question_renders_in_the_section_nine_shape() {
        let verdict = Path::new("/home/packets/cf7a/wu01-1.verdict");
        let rendered = render(
            &Blocker::Certified(payload()),
            &context(),
            verdict,
            &|_| false,
            PACKET_MAX_BYTES,
        )
        .unwrap();
        assert_eq!(rendered, EXPECTED);
    }

    #[test]
    fn a_packet_over_its_bound_is_an_error_not_a_truncation() {
        let verdict = Path::new("/v");
        let blocker = Blocker::Certified(payload());
        let full = render(&blocker, &context(), verdict, &|_| false, PACKET_MAX_BYTES).unwrap();
        let exact = render(&blocker, &context(), verdict, &|_| false, full.len());
        assert_eq!(exact.unwrap(), full);
        let over = render(&blocker, &context(), verdict, &|_| false, full.len() - 1);
        assert!(
            matches!(over, Err(PacketError::TooLarge { bytes, .. }) if bytes == full.len()),
            "{over:?}"
        );
    }

    #[test]
    fn every_unresolved_reference_counts_as_an_unverified_claim() {
        let verdict = Path::new("/v");
        let blocker = Blocker::Certified(payload());
        let count = |verified: &dyn Fn(&ContentRef) -> bool| {
            let rendered =
                render(&blocker, &context(), verdict, verified, PACKET_MAX_BYTES).unwrap();
            rendered.lines().last().unwrap().to_string()
        };
        assert_eq!(count(&|_| false), "Unverified claims: 3");
        assert_eq!(
            count(&|candidate| *candidate == reference('c')),
            "Unverified claims: 2"
        );
        assert_eq!(count(&|_| true), "Unverified claims: 0");
        let mut bare = payload();
        bare.proposed_ruling = None;
        bare.evidence.clear();
        let rendered = render(
            &Blocker::Certified(bare),
            &context(),
            verdict,
            &|_| false,
            PACKET_MAX_BYTES,
        )
        .unwrap();
        assert!(
            rendered.contains("- Proposed ruling: not supplied by the worker"),
            "{rendered}"
        );
        assert!(rendered.contains("None: not supplied by the worker."));
        assert!(rendered.ends_with("Unverified claims: 0\n"), "{rendered}");
    }

    #[test]
    fn an_uncertified_blocker_asks_continue_or_abandon_and_bounds_its_findings() {
        let mut unit = context();
        unit.attempt = Attempt::new(5).unwrap();
        unit.findings = vec!["criterion 0 failed".to_string(); FINDINGS_MAX_ITEMS + 2];
        unit.findings[1] = "x".repeat(FINDING_MAX_BYTES + 1);
        let blocker = Blocker::Uncertified {
            reason: "the attempt cap was reached".to_string(),
        };
        let rendered = render(
            &blocker,
            &unit,
            Path::new("/v"),
            &|_| false,
            PACKET_MAX_BYTES,
        )
        .unwrap();
        assert!(
            rendered.contains("Continue with attempt 6, or abandon the unit?"),
            "{rendered}"
        );
        assert!(rendered.contains("The unit stopped because the attempt cap was reached."));
        assert!(rendered.contains("Earlier attempts: 4."));
        assert!(rendered.contains("- 2 more findings; the unit's view holds them."));
        assert!(
            !rendered.contains(&"x".repeat(FINDING_MAX_BYTES)),
            "never truncated into the text"
        );
        assert!(rendered.contains("A finding of 513 bytes"));
    }

    #[test]
    fn the_written_packet_is_0600_in_0700_directories_and_a_replay_replaces_it() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("packets-write-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let packet_dir = base.join("packets");
        let blocker = Blocker::Certified(payload());
        let first = write(&packet_dir, &blocker, &context()).unwrap();
        let again = write(&packet_dir, &blocker, &context()).unwrap();
        let mode = |path: &Path| fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777;
        let modes = (
            mode(&packet_dir),
            mode(&packet_dir.join("cf7a")),
            mode(&first),
        );
        let text = fs::read_to_string(&first).unwrap();
        let entries = fs::read_dir(packet_dir.join("cf7a")).unwrap().count();
        fs::remove_dir_all(&base).unwrap();
        assert_eq!(first, packet_dir.join("cf7a").join("wu01-1.md"));
        assert_eq!(again, first);
        assert_eq!(modes, (0o700, 0o700, 0o600));
        assert_eq!(entries, 1, "no staging file left behind");
        assert!(text.contains(&format!(
            "`{}`",
            packet_dir.join("cf7a").join("wu01-1.verdict").display()
        )));
    }

    #[test]
    fn a_reference_cited_twice_counts_once() {
        let mut twice = payload();
        twice.proposed_ruling = Some(reference('c'));
        let rendered = render(
            &Blocker::Certified(twice),
            &context(),
            Path::new("/v"),
            &|_| false,
            PACKET_MAX_BYTES,
        )
        .unwrap();
        assert!(rendered.ends_with("Unverified claims: 2\n"), "{rendered}");
    }

    #[test]
    fn a_payload_at_every_bound_stays_under_the_packet_bound() {
        use tycho_types::envelope::{REFS_MAX_ITEMS, RecordId, TEXT_MAX_BYTES};
        let long = text(&"t".repeat(TEXT_MAX_BYTES));
        let mut widest = payload();
        widest.give_up_reason = long.clone();
        widest.options = vec![
            EscalationOption {
                label: long.clone(),
                reversibility: Reversibility::OneWay,
                blast_radius: long,
            };
            OPTIONS_MAX_ITEMS
        ];
        widest.evidence = vec![reference('e'); REFS_MAX_ITEMS];
        widest.cases_consulted = vec![RecordId::parse(&"c".repeat(64)).unwrap(); REFS_MAX_ITEMS];
        let mut unit = context();
        unit.attempt = Attempt::new(9).unwrap();
        unit.findings = vec!["f".repeat(FINDING_MAX_BYTES); FINDINGS_MAX_ITEMS];
        let verdict = PathBuf::from("/").join("v".repeat(1024));
        let rendered = render(
            &Blocker::Certified(widest),
            &unit,
            &verdict,
            &|_| false,
            PACKET_MAX_BYTES,
        )
        .unwrap();
        assert!(
            rendered.len() < PACKET_MAX_BYTES,
            "{} bytes",
            rendered.len()
        );
    }
}

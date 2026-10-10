//! `tycho verdicts once|run`: reads the verdict files typed beside decision packets, rules
//! through the Operator, and renames each file `.applied` or `.rejected` so it is read once.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::OFlag;
use tycho_types::envelope::ShortText;
use tycho_types::service::{handler, Attempt, EpicId, WorkUnitId};

use crate::agent_files;
use crate::config::CorePorts;
use crate::epic_command::{self, OperatorAnswer, OPERATOR_SERVICE};
use crate::http::Http;
use crate::packets::{RATIONALE_MAX_BYTES, VERDICT_EXTENSION};
use crate::services::operator::RuleUnitCall;
use crate::services::work_unit::{RuleCall, Ruling, RulingVerdict};

/// A verdict line, a newline and a rationale fit well inside this.
pub const VERDICT_MAX_BYTES: usize = 512;
pub const VERDICT_FILES_PER_PASS_MAX: usize = 32;
pub const EPIC_DIRS_MAX: usize = 64;
pub const DIR_ENTRIES_MAX: usize = 1024;
const APPLIED: &str = "applied";
const REJECTED: &str = "rejected";
const REASON: &str = "reason";

/// What a verdict file says; anything but the two words and an optional rationale is unrecognised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerdictText {
    Ruled {
        verdict: RulingVerdict,
        rationale: Option<ShortText>,
    },
    /// Never applied; the reason never quotes the file.
    Unrecognised(String),
}

#[must_use]
pub fn decode(bytes: &[u8]) -> VerdictText {
    let unrecognised = |reason: &str| VerdictText::Unrecognised(reason.to_string());
    let Ok(text) = std::str::from_utf8(bytes) else {
        return unrecognised("the file is not UTF-8");
    };
    let mut lines: Vec<&str> = text.split('\n').map(str::trim).collect();
    while lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    let (first, second) = match lines.as_slice() {
        [] => return unrecognised("the file is empty"),
        [first] => (*first, None),
        [first, second] => (*first, Some(*second)),
        _ => return unrecognised("the file has more than two lines"),
    };
    let verdict = match first {
        "continue" => RulingVerdict::Continue,
        "abandon" => RulingVerdict::Abandon,
        _ => return unrecognised("the first line is neither `continue` nor `abandon`"),
    };
    let rationale = match second.filter(|line| !line.is_empty()) {
        None => None,
        Some(line) if line.len() > RATIONALE_MAX_BYTES => {
            return VerdictText::Unrecognised(format!(
                "the rationale is {} bytes; maximum is {RATIONALE_MAX_BYTES}",
                line.len()
            ));
        }
        Some(line) => match ShortText::parse(line) {
            Ok(rationale) => Some(rationale),
            Err(_) => return unrecognised("the rationale holds a control character"),
        },
    };
    VerdictText::Ruled { verdict, rationale }
}

/// `<unit>-<attempt>.verdict`; a unit id may itself hold dashes.
#[must_use]
pub fn parse_name(file_name: &str) -> Option<(WorkUnitId, Attempt)> {
    let stem = file_name.strip_suffix(&format!(".{VERDICT_EXTENSION}"))?;
    let (unit, number) = stem.rsplit_once('-')?;
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let attempt = Attempt::new(number.parse().ok()?).ok()?;
    Some((WorkUnitId::parse(unit).ok()?, attempt))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileRefusal {
    NotRegular,
    Owner {
        found: u32,
        expected: u32,
    },
    TooLarge {
        bytes: u64,
        max: usize,
    },
    Unreadable(String),
    /// The descriptor could not be stat'ed; the file waits for the next pass.
    Stat(String),
}

impl fmt::Display for FileRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRegular => formatter.write_str("not a regular file"),
            Self::Owner { found, expected } => {
                write!(formatter, "owned by uid {found}, expected uid {expected}")
            }
            Self::TooLarge { bytes, max } => {
                write!(formatter, "{bytes} bytes; maximum is {max}")
            }
            Self::Unreadable(reason) => write!(formatter, "cannot open: {reason}"),
            Self::Stat(reason) => write!(formatter, "cannot stat: {reason}"),
        }
    }
}

/// The verdict on an opened file, from its descriptor's metadata.
pub fn judge(
    is_file: bool,
    owner: u32,
    length: u64,
    expected_owner: u32,
    max: usize,
) -> Result<(), FileRefusal> {
    if !is_file {
        return Err(FileRefusal::NotRegular);
    }
    if owner != expected_owner {
        return Err(FileRefusal::Owner {
            found: owner,
            expected: expected_owner,
        });
    }
    if length > u64::try_from(max).unwrap_or(u64::MAX) {
        return Err(FileRefusal::TooLarge { bytes: length, max });
    }
    Ok(())
}

/// A verdict file's bytes and the identity of the descriptor they were read through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictFile {
    pub bytes: Vec<u8>,
    /// Inode, modification seconds and nanoseconds: a file typed again gets a new identity.
    pub identity: (u64, i64, i64),
}

/// Never follows a symlink and never blocks on a FIFO; the descriptor is judged before reading.
pub fn read_verdict(path: &Path, expected_owner: u32) -> Result<VerdictFile, FileRefusal> {
    let unreadable = |error: io::Error| FileRefusal::Unreadable(error.to_string());
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(unreadable)?;
    let metadata = file
        .metadata()
        .map_err(|error| FileRefusal::Stat(error.to_string()))?;
    judge(
        metadata.file_type().is_file(),
        metadata.uid(),
        metadata.len(),
        expected_owner,
        VERDICT_MAX_BYTES,
    )?;
    let limit = u64::try_from(VERDICT_MAX_BYTES).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() > VERDICT_MAX_BYTES {
        return Err(FileRefusal::TooLarge {
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            max: VERDICT_MAX_BYTES,
        });
    }
    Ok(VerdictFile {
        bytes,
        identity: (metadata.ino(), metadata.mtime(), metadata.mtime_nsec()),
    })
}

/// How the Operator answered one ruling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAnswer {
    Applied,
    /// A 400 for a bad request or the wrong epic, or a 409 for an attempt that is not current.
    Refused(String),
    /// The core's own operator secret was refused; the verdict is not at fault.
    Unauthorized(String),
    /// Unreachable, another 4xx such as 404, 408 or 429, or an answer no one enumerated; the
    /// file waits for the next pass.
    Unavailable(String),
}

/// Only 400 and 409 condemn the verdict itself; every other refusal may pass on a later try.
#[must_use]
pub fn rule_answer(answer: OperatorAnswer) -> RuleAnswer {
    match answer {
        OperatorAnswer::Done(_) => RuleAnswer::Applied,
        OperatorAnswer::Rejected(status @ (400 | 409), body) => {
            RuleAnswer::Refused(format!("{status}: {body}"))
        }
        OperatorAnswer::Rejected(status, body) => {
            RuleAnswer::Unavailable(format!("{status}: {body}"))
        }
        OperatorAnswer::Unauthorized(body) => RuleAnswer::Unauthorized(body),
        OperatorAnswer::Unreachable(reason) | OperatorAnswer::Unrecognised(reason) => {
            RuleAnswer::Unavailable(reason)
        }
    }
}

/// One ruling to send: the unit, the call, and the idempotency key of this file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRequest {
    pub unit: WorkUnitId,
    pub call: RuleCall,
    pub idempotency_key: String,
}

/// `Operator/rule_unit` through ingress; a replay of the same file reuses its key.
#[must_use]
pub fn rule_through_operator(
    http: &Http,
    ports: CorePorts,
    secret: &str,
    request: &RuleRequest,
) -> RuleAnswer {
    let call = RuleUnitCall {
        secret: secret.to_string(),
        unit: request.unit.clone(),
        rule: request.call.clone(),
    };
    let body = match serde_json::to_string(&call) {
        Ok(body) => body,
        Err(error) => return RuleAnswer::Unavailable(error.to_string()),
    };
    let url = ports.ingress_url(&format!(
        "/{OPERATOR_SERVICE}/{}",
        handler::OPERATOR_RULE_UNIT
    ));
    let headers = [("idempotency-key", request.idempotency_key.as_str())];
    rule_answer(epic_command::decode(http.post(
        &url,
        "application/json",
        &headers,
        body,
    )))
}

/// What one pass did with one verdict file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Applied,
    Rejected(String),
    /// Left in place for the next pass.
    Deferred(String),
    /// The Operator could not be reached or answered for now; the pass stops here.
    Unavailable(String),
    /// Renamed rejected, since a retry under the same key returns the same refusal, and the
    /// pass fails: the core refused its own secret.
    CoreRefused(String),
    /// Left in place; the pass fails, since the fault is the core's.
    Failed(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassReport {
    pub examined: Vec<(PathBuf, Disposition)>,
    /// Verdict files over the per-pass bound, left for the next pass.
    pub left: usize,
    /// Problems with the directories themselves.
    pub errors: Vec<String>,
}

impl PassReport {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.errors.is_empty()
            && !self.examined.iter().any(|(_, disposition)| {
                matches!(
                    disposition,
                    Disposition::Failed(_) | Disposition::CoreRefused(_)
                )
            })
    }

    fn count(&self, wanted: fn(&Disposition) -> bool) -> usize {
        self.examined
            .iter()
            .filter(|(_, disposition)| wanted(disposition))
            .count()
    }
}

impl fmt::Display for PassReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "verdicts: examined {}, applied {}, rejected {}, deferred {}, failed {}, left {}",
            self.examined.len(),
            self.count(|disposition| matches!(disposition, Disposition::Applied)),
            self.count(|disposition| matches!(disposition, Disposition::Rejected(_))),
            self.count(|disposition| {
                matches!(
                    disposition,
                    Disposition::Deferred(_) | Disposition::Unavailable(_)
                )
            }),
            self.count(|disposition| {
                matches!(
                    disposition,
                    Disposition::Failed(_) | Disposition::CoreRefused(_)
                )
            }),
            self.left
        )?;
        for (path, disposition) in &self.examined {
            writeln!(formatter, "  {}: {disposition:?}", path.display())?;
        }
        for error in &self.errors {
            writeln!(formatter, "  error: {error}")?;
        }
        Ok(())
    }
}

/// The entries of a directory, failing past `max` rather than reading a prefix.
fn bounded_entries(dir: &Path, max: usize) -> Result<Vec<(String, PathBuf)>, String> {
    let mut entries = Vec::new();
    let listing = fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    for entry in listing {
        let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
        if entries.len() >= max {
            return Err(format!("{} holds more than {max} entries", dir.display()));
        }
        if let Some(name) = entry.file_name().to_str() {
            entries.push((name.to_string(), entry.path()));
        }
    }
    entries.sort();
    Ok(entries)
}

/// The verdict files under each epic directory, sorted, at most `max` of them.
fn verdict_files(packet_dir: &Path, report: &mut PassReport, max: usize) -> Vec<(EpicId, PathBuf)> {
    let epics = match bounded_entries(packet_dir, EPIC_DIRS_MAX) {
        Ok(epics) => epics,
        Err(error) => {
            report.errors.push(error);
            return Vec::new();
        }
    };
    let mut found = Vec::new();
    for (name, epic_dir) in epics {
        let is_dir = fs::symlink_metadata(&epic_dir).is_ok_and(|metadata| metadata.is_dir());
        let Ok(epic) = EpicId::parse(&name) else {
            continue;
        };
        if !is_dir {
            continue;
        }
        match bounded_entries(&epic_dir, DIR_ENTRIES_MAX) {
            Ok(entries) => found.extend(
                entries
                    .into_iter()
                    .filter(|(file, _)| file.ends_with(&format!(".{VERDICT_EXTENSION}")))
                    .map(|(_, path)| (epic.clone(), path)),
            ),
            Err(error) => report.errors.push(error),
        }
    }
    report.left = found.len().saturating_sub(max);
    found.truncate(max);
    found
}

/// One pass over `<packet dir>/<epic>/*.verdict`, at most `VERDICT_FILES_PER_PASS_MAX` files.
pub fn pass(
    packet_dir: &Path,
    owner: u32,
    rule: &mut dyn FnMut(&RuleRequest) -> RuleAnswer,
) -> PassReport {
    let mut report = PassReport::default();
    if let Err(error) = agent_files::ensure_private_dir(packet_dir) {
        report
            .errors
            .push(format!("{}: {error}", packet_dir.display()));
        return report;
    }
    let files = verdict_files(packet_dir, &mut report, VERDICT_FILES_PER_PASS_MAX);
    let total = files.len();
    for (epic, path) in files {
        let disposition = consider(&epic, &path, owner, rule);
        let disposition = match dispose(&path, &disposition) {
            Ok(()) => disposition,
            Err(error) => Disposition::Failed(format!("{disposition:?}, then {error}")),
        };
        let stop = matches!(disposition, Disposition::Unavailable(_));
        report.examined.push((path, disposition));
        if stop {
            let rest = total.saturating_sub(report.examined.len());
            report.left = report.left.saturating_add(rest);
            break;
        }
    }
    report
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{suffix}"));
    PathBuf::from(name)
}

/// Decides one file without touching it.
fn consider(
    epic: &EpicId,
    path: &Path,
    owner: u32,
    rule: &mut dyn FnMut(&RuleRequest) -> RuleAnswer,
) -> Disposition {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let Some((unit, attempt)) = parse_name(name) else {
        return Disposition::Rejected("the name is not <unit>-<attempt>.verdict".to_string());
    };
    if fs::symlink_metadata(sibling(path, APPLIED)).is_ok() {
        return Disposition::Rejected("a verdict for this attempt was already applied".to_string());
    }
    let file = match read_verdict(path, owner) {
        Ok(file) => file,
        Err(refusal @ FileRefusal::Stat(_)) => return Disposition::Deferred(refusal.to_string()),
        Err(refusal) => return Disposition::Rejected(refusal.to_string()),
    };
    let (verdict, rationale) = match decode(&file.bytes) {
        VerdictText::Ruled { verdict, rationale } => (verdict, rationale),
        VerdictText::Unrecognised(reason) => return Disposition::Rejected(reason),
    };
    let Some(reason) = rationale.or_else(|| default_reason(verdict)) else {
        return Disposition::Failed("the default rationale does not parse".to_string());
    };
    let request = RuleRequest {
        unit,
        call: RuleCall {
            epic: epic.clone(),
            attempt: attempt.get(),
            ruling: Ruling { verdict, reason },
        },
        idempotency_key: idempotency_key(epic, name, file.identity),
    };
    match rule(&request) {
        RuleAnswer::Applied => Disposition::Applied,
        RuleAnswer::Refused(reason) => Disposition::Rejected(reason),
        RuleAnswer::Unauthorized(reason) => Disposition::CoreRefused(format!(
            "the core's own operator secret was refused ({reason}); fix the core, then type the \
             verdict again"
        )),
        RuleAnswer::Unavailable(reason) => Disposition::Unavailable(reason),
    }
}

fn default_reason(verdict: RulingVerdict) -> Option<ShortText> {
    let text = match verdict {
        RulingVerdict::Continue => "continue, no rationale given",
        RulingVerdict::Abandon => "abandoned, no rationale given",
    };
    ShortText::parse(text).ok()
}

/// The same file keeps its key across passes; a file typed again gets a new one.
fn idempotency_key(epic: &EpicId, name: &str, identity: (u64, i64, i64)) -> String {
    format!(
        "verdict:{epic}:{name}:{}:{}:{}",
        identity.0, identity.1, identity.2
    )
}

/// Renames onto a checked target, so an applied verdict is never read again.
fn dispose(path: &Path, disposition: &Disposition) -> io::Result<()> {
    match disposition {
        Disposition::Applied => {
            let applied = sibling(path, APPLIED);
            agent_files::check_replaceable(&applied)?;
            fs::rename(path, applied)
        }
        Disposition::Rejected(reason) | Disposition::CoreRefused(reason) => {
            let rejected = sibling(path, REJECTED);
            agent_files::check_replaceable(&rejected)?;
            fs::rename(path, rejected)?;
            agent_files::write_durable(&sibling(path, REASON), format!("{reason}\n").as_bytes())
        }
        Disposition::Deferred(_) | Disposition::Unavailable(_) | Disposition::Failed(_) => Ok(()),
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("verdicts-{name}-{}", std::process::id()));
        if base.exists() {
            fs::remove_dir_all(&base).unwrap();
        }
        let epic = base.join("packets").join("cf7a");
        fs::create_dir_all(&epic).unwrap();
        for dir in [base.join("packets"), epic] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        base
    }

    fn ruled(verdict: RulingVerdict, rationale: Option<&str>) -> VerdictText {
        VerdictText::Ruled {
            verdict,
            rationale: rationale.map(|text| ShortText::parse(text).unwrap()),
        }
    }

    #[test]
    fn each_verdict_decodes_to_its_state() {
        assert_eq!(decode(b"continue\n"), ruled(RulingVerdict::Continue, None));
        assert_eq!(decode(b"abandon"), ruled(RulingVerdict::Abandon, None));
        assert_eq!(
            decode(b"abandon\nthe policy forbids it\n\n"),
            ruled(RulingVerdict::Abandon, Some("the policy forbids it"))
        );
        assert_eq!(
            decode(b"  continue \r\n choose B \r\n"),
            ruled(RulingVerdict::Continue, Some("choose B"))
        );
        assert_eq!(
            decode(b"continue\n\n"),
            ruled(RulingVerdict::Continue, None)
        );
    }

    #[test]
    fn garbage_is_unrecognised_and_never_quoted() {
        let rationale = format!("abandon\n{}", "r".repeat(RATIONALE_MAX_BYTES + 1));
        let exact = format!("abandon\n{}", "r".repeat(RATIONALE_MAX_BYTES));
        assert!(matches!(
            decode(exact.as_bytes()),
            VerdictText::Ruled { .. }
        ));
        for garbage in [
            &b""[..],
            b"\n\n",
            b"maybe",
            b"Continue",
            b"continue please",
            b"continue\none\ntwo",
            b"\xff\xfe",
            b"abandon\nbell \x07 here",
            rationale.as_bytes(),
        ] {
            match decode(garbage) {
                VerdictText::Unrecognised(reason) => {
                    assert!(
                        !reason.contains("maybe") && !reason.contains("rrrr"),
                        "{reason}"
                    );
                }
                other @ VerdictText::Ruled { .. } => panic!("{garbage:?} decoded as {other:?}"),
            }
        }
    }

    #[test]
    fn names_carry_the_unit_and_attempt() {
        let parsed = parse_name("wu-orders-split-12.verdict").unwrap();
        assert_eq!(parsed.0.as_str(), "wu-orders-split");
        assert_eq!(parsed.1.get(), 12);
        assert_eq!(parse_name("wu01-1.verdict").unwrap().1, Attempt::FIRST);
        for bad in [
            "wu01.verdict",
            "wu01-0.verdict",
            "wu01-x.verdict",
            "wu01-+1.verdict",
            "wu01-1.verdict.applied",
            "wu01-.verdict",
            "-1.verdict",
        ] {
            assert_eq!(parse_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_file_judgment_refuses_type_owner_and_size() {
        assert_eq!(judge(true, 501, 10, 501, 512), Ok(()));
        assert_eq!(
            judge(false, 501, 10, 501, 512),
            Err(FileRefusal::NotRegular)
        );
        assert_eq!(
            judge(true, 502, 10, 501, 512),
            Err(FileRefusal::Owner {
                found: 502,
                expected: 501
            })
        );
        assert_eq!(judge(true, 501, 512, 501, 512), Ok(()));
        assert_eq!(
            judge(true, 501, 513, 501, 512),
            Err(FileRefusal::TooLarge {
                bytes: 513,
                max: 512
            })
        );
    }

    #[test]
    fn a_symlink_a_fifo_an_oversized_file_and_another_owner_are_refused() {
        let base = scratch("files");
        let me = agent_files::current_uid();
        let target = base.join("target");
        fs::write(&target, "continue\n").unwrap();
        let link = base.join("link.verdict");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let fifo = base.join("fifo.verdict");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let big = base.join("big.verdict");
        fs::write(&big, vec![b'a'; VERDICT_MAX_BYTES + 1]).unwrap();
        let outcomes = (
            read_verdict(&link, me),
            read_verdict(&fifo, me),
            read_verdict(&big, me),
            read_verdict(&target, me.saturating_add(1)),
            read_verdict(&target, me),
        );
        fs::remove_dir_all(&base).unwrap();
        assert!(
            matches!(outcomes.0, Err(FileRefusal::Unreadable(_))),
            "{:?}",
            outcomes.0
        );
        assert_eq!(outcomes.1, Err(FileRefusal::NotRegular));
        assert!(matches!(outcomes.2, Err(FileRefusal::TooLarge { .. })));
        assert!(matches!(outcomes.3, Err(FileRefusal::Owner { .. })));
        assert_eq!(outcomes.4.unwrap().bytes, b"continue\n".to_vec());
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut found: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        found.sort();
        found
    }

    #[test]
    fn a_verdict_is_applied_once_and_then_refused() {
        let base = scratch("once");
        let packets = base.join("packets");
        let epic = packets.join("cf7a");
        let verdict = epic.join("wu01-1.verdict");
        fs::write(&verdict, "abandon\nthe policy forbids it\n").unwrap();
        let calls = Cell::new(0_u32);
        let mut seen = Vec::new();
        let mut rule = |request: &RuleRequest| {
            calls.set(calls.get() + 1);
            seen.push(request.clone());
            RuleAnswer::Applied
        };
        let me = agent_files::current_uid();
        let first = pass(&packets, me, &mut rule);
        fs::write(&verdict, "continue\n").unwrap();
        let second = pass(&packets, me, &mut rule);
        let listing = names(&epic);
        let reason = fs::read_to_string(epic.join("wu01-1.verdict.reason")).unwrap();
        fs::remove_dir_all(&base).unwrap();
        assert!(first.succeeded() && second.succeeded(), "{first}{second}");
        assert_eq!(first.examined, vec![(verdict, Disposition::Applied)]);
        assert_eq!(calls.get(), 1, "the second file never reached the operator");
        assert_eq!(seen[0].unit.as_str(), "wu01");
        assert_eq!(
            seen[0].call.epic.as_str(),
            "cf7a",
            "the epic is the directory's"
        );
        assert!(seen[0]
            .idempotency_key
            .starts_with("verdict:cf7a:wu01-1.verdict:"));
        assert_eq!(seen[0].call.attempt, 1);
        assert_eq!(seen[0].call.ruling.verdict, RulingVerdict::Abandon);
        assert_eq!(seen[0].call.ruling.reason.as_str(), "the policy forbids it");
        assert!(
            matches!(&second.examined[0].1, Disposition::Rejected(why) if why.contains("already applied"))
        );
        assert_eq!(
            listing,
            [
                "wu01-1.verdict.applied",
                "wu01-1.verdict.reason",
                "wu01-1.verdict.rejected"
            ]
        );
        assert!(reason.contains("already applied"));
    }

    #[test]
    fn each_operator_answer_has_its_disposition() {
        let base = scratch("answers");
        let packets = base.join("packets");
        let epic = packets.join("cf7a");
        for unit in ["wa", "wb", "wc", "wd", "we"] {
            fs::write(epic.join(format!("{unit}-2.verdict")), "continue\n").unwrap();
        }
        fs::write(epic.join("bad-name.verdict"), "continue\n").unwrap();
        let mut rule = |request: &RuleRequest| match request.unit.as_str() {
            "wa" => RuleAnswer::Applied,
            "wb" => RuleAnswer::Refused("409: attempt 2 is not the current attempt".to_string()),
            "wc" => RuleAnswer::Unauthorized("operator secret missing or wrong".to_string()),
            "wd" => RuleAnswer::Unavailable("connection refused".to_string()),
            _ => panic!("the pass went on after the operator was unavailable"),
        };
        let report = pass(&packets, agent_files::current_uid(), &mut rule);
        let listing = names(&epic);
        fs::remove_dir_all(&base).unwrap();
        assert_answers(&report, &listing);
    }

    fn assert_answers(report: &PassReport, listing: &[String]) {
        let kinds: Vec<&str> = report
            .examined
            .iter()
            .map(|(_, disposition)| match disposition {
                Disposition::Applied => "applied",
                Disposition::Rejected(why) if why.contains("not <unit>") => "bad name",
                Disposition::Rejected(why) if why.starts_with("409") => "conflict",
                Disposition::Rejected(_) => "rejected",
                Disposition::CoreRefused(why) if why.contains("type the verdict again") => {
                    "core refused"
                }
                Disposition::CoreRefused(_) => "core refused without the instruction",
                Disposition::Deferred(_) => "deferred",
                Disposition::Unavailable(_) => "unavailable",
                Disposition::Failed(_) => "failed",
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "bad name",
                "applied",
                "conflict",
                "core refused",
                "unavailable"
            ]
        );
        assert_eq!(
            report.left, 1,
            "the pass stopped at the unavailable operator"
        );
        assert!(!report.succeeded(), "a refused core secret fails the pass");
        let expected = [
            "bad-name.verdict.reason",
            "bad-name.verdict.rejected",
            "wa-2.verdict.applied",
            "wb-2.verdict.reason",
            "wb-2.verdict.rejected",
            "wc-2.verdict.reason",
            "wc-2.verdict.rejected",
            "wd-2.verdict",
            "we-2.verdict",
        ];
        assert_eq!(
            listing, expected,
            "unavailable and unread files stay in place"
        );
    }

    #[test]
    fn a_pass_reads_at_most_its_bound_and_leaves_the_rest() {
        let base = scratch("bound");
        let packets = base.join("packets");
        for index in 1..=VERDICT_FILES_PER_PASS_MAX + 3 {
            fs::write(
                packets.join("cf7a").join(format!("wu01-{index}.verdict")),
                "maybe",
            )
            .unwrap();
        }
        let mut rule = |_: &RuleRequest| RuleAnswer::Applied;
        let report = pass(&packets, agent_files::current_uid(), &mut rule);
        fs::remove_dir_all(&base).unwrap();
        assert_eq!(report.examined.len(), VERDICT_FILES_PER_PASS_MAX);
        assert_eq!(report.left, 3);
    }

    #[test]
    fn a_packet_directory_open_to_others_fails_the_pass() {
        let base = scratch("open");
        let packets = base.join("packets");
        fs::write(packets.join("cf7a").join("wu01-1.verdict"), "continue\n").unwrap();
        fs::set_permissions(&packets, fs::Permissions::from_mode(0o755)).unwrap();
        let calls = Cell::new(0_u32);
        let mut rule = |_: &RuleRequest| {
            calls.set(calls.get() + 1);
            RuleAnswer::Applied
        };
        let report = pass(&packets, agent_files::current_uid(), &mut rule);
        fs::remove_dir_all(&base).unwrap();
        assert!(!report.succeeded(), "{report}");
        assert!(report.examined.is_empty());
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn operator_answers_decode() {
        assert_eq!(
            rule_answer(OperatorAnswer::Done(String::new())),
            RuleAnswer::Applied
        );
        assert!(matches!(
            rule_answer(OperatorAnswer::Rejected(409, "stale".to_string())),
            RuleAnswer::Refused(reason) if reason == "409: stale"
        ));
        assert!(matches!(
            rule_answer(OperatorAnswer::Unauthorized(String::new())),
            RuleAnswer::Unauthorized(_)
        ));
        assert!(matches!(
            rule_answer(OperatorAnswer::Rejected(400, "wrong epic".to_string())),
            RuleAnswer::Refused(_)
        ));
        for unavailable in [
            OperatorAnswer::Unreachable(String::new()),
            OperatorAnswer::Unrecognised(String::new()),
            OperatorAnswer::Rejected(404, String::new()),
            OperatorAnswer::Rejected(408, String::new()),
            OperatorAnswer::Rejected(429, String::new()),
            OperatorAnswer::Rejected(418, String::new()),
        ] {
            assert!(matches!(
                rule_answer(unavailable),
                RuleAnswer::Unavailable(_)
            ));
        }
    }
}

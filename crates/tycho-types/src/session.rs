//! The zmx session name grammar: `<epic>.<unit>.<ctl|wrk>.<vendor>[.<suffix>]`,
//! and `<epic>.root.<vendor>[.<suffix>]` for the root control session.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::service::{Attempt, EpicId, TaskId, WorkUnitId, ROOT_SEGMENT};
use crate::token::{check_slug, checked_string, TokenError};

/// `sun_path` is 104 bytes on macOS with its NUL; zmx names the socket after the session.
pub const SOCKET_PATH_MAX_BYTES: usize = 103;
/// Leaves 38 bytes of `SOCKET_PATH_MAX_BYTES` for the socket directory and its separator.
pub const SESSION_NAME_MAX_BYTES: usize = 64;
pub const SUFFIX_MAX_BYTES: usize = 13;
const TASK_HASH_HEX_DIGITS: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionKind {
    Control,
    Worker,
}

impl SessionKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "ctl",
            Self::Worker => "wrk",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "ctl" => Some(Self::Control),
            "wrk" => Some(Self::Worker),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Vendor {
    Claude,
    Codex,
    Antigravity,
    Amp,
    OpenCode,
}

impl Vendor {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Antigravity => "antigravity",
            Self::Amp => "amp",
            Self::OpenCode => "opencode",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "claude" => Some(Self::Claude),
            "codex" => Some(Self::Codex),
            "antigravity" => Some(Self::Antigravity),
            "amp" => Some(Self::Amp),
            "opencode" => Some(Self::OpenCode),
            _ => None,
        }
    }
}

fn check_suffix(value: &str) -> Result<(), TokenError> {
    check_slug(value, SUFFIX_MAX_BYTES)
}

checked_string!(
    /// The attempt or short id that keeps successive sessions of one key apart.
    Suffix,
    check_suffix
);

fn fnv1a_64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash: u64, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

impl Suffix {
    /// `<first 10 hex digits of FNV-1a 64 of the task id>a<attempt>`, such as `3f1c0a9b2ea2`.
    #[must_use]
    pub fn for_task(task: &TaskId, attempt: Attempt) -> Self {
        Self::for_key(task.as_str(), attempt)
    }

    /// The same shape from any run key, such as a worker run key that carries a unit attempt.
    #[must_use]
    pub fn for_key(key: &str, attempt: Attempt) -> Self {
        let hash = format!("{:016x}", fnv1a_64(key.as_bytes()));
        let prefix: String = hash.chars().take(TASK_HASH_HEX_DIGITS).collect();
        Self(format!("{prefix}a{}", attempt.get()))
    }
}

/// The level a session runs at, derived from its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Root,
    Control,
    Worker,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionName {
    epic: EpicId,
    unit: Option<WorkUnitId>,
    kind: SessionKind,
    vendor: Vendor,
    suffix: Option<Suffix>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionNameError {
    TooLong(usize),
    SegmentCount,
    Epic(TokenError),
    Unit(TokenError),
    Kind,
    Vendor,
    Suffix(TokenError),
    SocketPathTooLong(usize),
}

impl fmt::Display for SessionNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong(length) => write!(
                formatter,
                "session name is {length} bytes; maximum is {SESSION_NAME_MAX_BYTES}"
            ),
            Self::SegmentCount => write!(
                formatter,
                "expected `<epic>.<unit>.<ctl|wrk>.<vendor>[.<suffix>]` or `<epic>.root.<vendor>[.<suffix>]`"
            ),
            Self::Epic(error) => write!(formatter, "epic id: {error}"),
            Self::Unit(error) => write!(formatter, "work unit id: {error}"),
            Self::Kind => write!(formatter, "kind is neither `ctl` nor `wrk`"),
            Self::Vendor => write!(formatter, "unknown vendor"),
            Self::Suffix(error) => write!(formatter, "suffix: {error}"),
            Self::SocketPathTooLong(length) => write!(
                formatter,
                "socket path is {length} bytes; maximum is {SOCKET_PATH_MAX_BYTES}"
            ),
        }
    }
}

impl std::error::Error for SessionNameError {}

impl SessionName {
    /// Infallible: the longest combination of bounded components fits `SESSION_NAME_MAX_BYTES`.
    #[must_use]
    pub const fn unit(
        epic: EpicId,
        unit: WorkUnitId,
        kind: SessionKind,
        vendor: Vendor,
        suffix: Option<Suffix>,
    ) -> Self {
        Self {
            epic,
            unit: Some(unit),
            kind,
            vendor,
            suffix,
        }
    }

    #[must_use]
    pub const fn root(epic: EpicId, vendor: Vendor, suffix: Option<Suffix>) -> Self {
        Self {
            epic,
            unit: None,
            kind: SessionKind::Control,
            vendor,
            suffix,
        }
    }

    pub fn parse(value: &str) -> Result<Self, SessionNameError> {
        if value.len() > SESSION_NAME_MAX_BYTES {
            return Err(SessionNameError::TooLong(value.len()));
        }
        let mut segments = value.split('.');
        let epic =
            EpicId::parse(segments.next().unwrap_or_default()).map_err(SessionNameError::Epic)?;
        let second = segments.next().ok_or(SessionNameError::SegmentCount)?;
        let (unit, kind) = if second == ROOT_SEGMENT {
            (None, SessionKind::Control)
        } else {
            let unit = WorkUnitId::parse(second).map_err(SessionNameError::Unit)?;
            let kind = segments.next().ok_or(SessionNameError::SegmentCount)?;
            (
                Some(unit),
                SessionKind::parse(kind).ok_or(SessionNameError::Kind)?,
            )
        };
        let vendor = segments.next().ok_or(SessionNameError::SegmentCount)?;
        let vendor = Vendor::parse(vendor).ok_or(SessionNameError::Vendor)?;
        let suffix = segments
            .next()
            .map(Suffix::parse)
            .transpose()
            .map_err(SessionNameError::Suffix)?;
        if segments.next().is_some() {
            return Err(SessionNameError::SegmentCount);
        }
        Ok(Self {
            epic,
            unit,
            kind,
            vendor,
            suffix,
        })
    }

    /// The socket zmx creates for this session, refused over the platform limit.
    pub fn socket_path(&self, socket_dir: &Path) -> Result<PathBuf, SessionNameError> {
        let path = socket_dir.join(self.to_string());
        let length = path.as_os_str().len();
        if length > SOCKET_PATH_MAX_BYTES {
            return Err(SessionNameError::SocketPathTooLong(length));
        }
        Ok(path)
    }

    #[must_use]
    pub const fn epic(&self) -> &EpicId {
        &self.epic
    }

    #[must_use]
    pub const fn work_unit(&self) -> Option<&WorkUnitId> {
        self.unit.as_ref()
    }

    #[must_use]
    pub const fn kind(&self) -> SessionKind {
        self.kind
    }

    #[must_use]
    pub const fn vendor(&self) -> Vendor {
        self.vendor
    }

    #[must_use]
    pub const fn suffix(&self) -> Option<&Suffix> {
        self.suffix.as_ref()
    }

    #[must_use]
    pub const fn level(&self) -> Level {
        match (&self.unit, self.kind) {
            (None, _) => Level::Root,
            (Some(_), SessionKind::Control) => Level::Control,
            (Some(_), SessionKind::Worker) => Level::Worker,
        }
    }
}

impl fmt::Display for SessionName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.unit {
            Some(unit) => write!(
                formatter,
                "{}.{unit}.{}.{}",
                self.epic,
                self.kind.as_str(),
                self.vendor.as_str()
            )?,
            None => write!(
                formatter,
                "{}.{ROOT_SEGMENT}.{}",
                self.epic,
                self.vendor.as_str()
            )?,
        }
        if let Some(suffix) = &self.suffix {
            write!(formatter, ".{suffix}")?;
        }
        Ok(())
    }
}

impl TryFrom<String> for SessionName {
    type Error = SessionNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<SessionName> for String {
    fn from(value: SessionName) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> SessionName {
        SessionName::parse(value).unwrap()
    }

    #[test]
    fn parses_design_examples() {
        for example in [
            "cf7a.wu03.ctl.codex",
            "cf7a.wu03.wrk.claude.a1f3",
            "cf7a.root.claude",
            "cf7a.wu-orders-split.ctl.claude",
        ] {
            assert_eq!(name(example).to_string(), example);
        }
        let worker = name("cf7a.wu03.wrk.claude.a1f3");
        assert_eq!(worker.level(), Level::Worker);
        assert_eq!(worker.vendor(), Vendor::Claude);
        assert_eq!(worker.suffix().map(Suffix::as_str), Some("a1f3"));
        assert_eq!(name("cf7a.root.claude").level(), Level::Root);
        assert_eq!(name("cf7a.wu03.ctl.codex").level(), Level::Control);
    }

    #[test]
    fn rejects_each_defect() {
        let long = format!("cf7a.wu03.wrk.claude.{}", "a".repeat(50));
        assert!(long.len() > SESSION_NAME_MAX_BYTES);
        assert!(matches!(
            SessionName::parse(&long),
            Err(SessionNameError::TooLong(_))
        ));
        assert_eq!(
            SessionName::parse("cf7a.wu03.ctl"),
            Err(SessionNameError::SegmentCount)
        );
        assert_eq!(
            SessionName::parse("cf7a.wu03.wrk.claude.a1.b2"),
            Err(SessionNameError::SegmentCount)
        );
        assert_eq!(
            SessionName::parse("cf7a.wu03.run.claude"),
            Err(SessionNameError::Kind)
        );
        assert_eq!(
            SessionName::parse("cf7a.wu03.wrk.gemini"),
            Err(SessionNameError::Vendor)
        );
        assert!(matches!(
            SessionName::parse("-d.wu03.wrk.claude"),
            Err(SessionNameError::Epic(_))
        ));
        assert!(matches!(
            SessionName::parse("cf7a..wrk.claude"),
            Err(SessionNameError::Unit(TokenError::Empty))
        ));
        assert!(matches!(
            SessionName::parse("cf7a.wu03.wrk.claude.suffixtoolong1"),
            Err(SessionNameError::Suffix(_))
        ));
        assert!(SessionName::parse("").is_err());
    }

    #[test]
    fn rejects_a_suffix_over_its_maximum() {
        let suffix = format!(
            "cf7a.wu03.wrk.claude.{}",
            "s".repeat(SUFFIX_MAX_BYTES.saturating_add(1))
        );
        assert!(matches!(
            SessionName::parse(&suffix),
            Err(SessionNameError::Suffix(TokenError::TooLong { .. }))
        ));
    }

    #[test]
    fn longest_name_fits_the_maximum() {
        let epic = EpicId::parse(&"e".repeat(crate::service::ID_MAX_BYTES)).unwrap();
        let unit = WorkUnitId::parse(&"u".repeat(crate::service::ID_MAX_BYTES)).unwrap();
        let suffix = Suffix::parse(&"s".repeat(SUFFIX_MAX_BYTES)).unwrap();
        let longest = SessionName::unit(
            epic,
            unit,
            SessionKind::Control,
            Vendor::Antigravity,
            Some(suffix),
        );
        let text = longest.to_string();
        assert!(text.len() <= SESSION_NAME_MAX_BYTES, "{}", text.len());
        assert_eq!(SessionName::parse(&text), Ok(longest));
    }

    #[test]
    fn socket_path_is_bounded() {
        let session = name("cf7a.wu03.wrk.claude.a1f3");
        let short = session.socket_path(Path::new("/Users/dev/.zmx"));
        assert_eq!(
            short.map(|p| p.display().to_string()),
            Ok("/Users/dev/.zmx/cf7a.wu03.wrk.claude.a1f3".to_string())
        );
        let name_length = session.to_string().len();
        let fits = format!(
            "/{}",
            "d".repeat(SOCKET_PATH_MAX_BYTES.saturating_sub(name_length.saturating_add(2)))
        );
        assert!(session.socket_path(Path::new(&fits)).is_ok());
        let deep = format!("{fits}d");
        assert_eq!(
            session.socket_path(Path::new(&deep)),
            Err(SessionNameError::SocketPathTooLong(
                SOCKET_PATH_MAX_BYTES.saturating_add(1)
            ))
        );
    }

    #[test]
    fn task_suffix_is_stable_and_separates_attempts() {
        let task = TaskId::parse("cf7a-wu03-t07").unwrap();
        let first = Suffix::for_task(&task, Attempt::FIRST);
        assert_eq!(first, Suffix::for_task(&task, Attempt::FIRST));
        assert!(first.as_str().ends_with("a1"));
        assert_eq!(Suffix::parse(first.as_str()), Ok(first.clone()));
        let second = Suffix::for_task(&task, Attempt::new(2).unwrap());
        assert_ne!(first, second);
        let other = TaskId::parse("cf7a-wu03-t08").unwrap();
        assert_ne!(first, Suffix::for_task(&other, Attempt::FIRST));
        assert_ne!(
            Suffix::for_key("cf7a-wu03-t07.u2", Attempt::FIRST),
            Suffix::for_key("cf7a-wu03-t07-u2", Attempt::FIRST)
        );
        let last = Suffix::for_task(&task, Attempt::new(crate::service::ATTEMPT_MAX).unwrap());
        assert!(last.as_str().len() <= SUFFIX_MAX_BYTES);
    }

    #[test]
    fn serializes_as_a_string() {
        let session = name("cf7a.wu03.wrk.codex");
        let json = serde_json::to_string(&session).unwrap();
        assert_eq!(json, "\"cf7a.wu03.wrk.codex\"");
        let rejected: Result<SessionName, _> = serde_json::from_str("\"cf7a.wu03\"");
        assert!(rejected.is_err());
    }
}

//! The vendor credentials the core holds for the agent's sessions: one file per vendor under
//! `<core home>/credentials`, mode 0600 in a 0700 directory of the core's user.
//!
//! A value enters only through stdin, is checked against its vendor's shape and bound, and
//! leaves only through the launcher hand-off. No `Debug`, `Display` or error carries it.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use tycho_types::session::Vendor;

use crate::agent_files::{current_uid, write_durable};
use crate::private_dir::{self, DirError};

pub const CREDENTIALS_DIR: &str = "credentials";
/// A `claude setup-token` token is about 110 bytes.
pub const CLAUDE_TOKEN_MAX_BYTES: usize = 512;
/// A Codex `auth.json` with a plan login is about 4 KiB.
pub const CODEX_AUTH_MAX_BYTES: usize = 16 * 1024;
/// The variable Claude Code reads a `setup-token` token from.
pub const CLAUDE_TOKEN_ENV: &str = "CLAUDE_CODE_OAUTH_TOKEN";
/// The directory Codex reads `auth.json` from.
pub const CODEX_HOME_ENV: &str = "CODEX_HOME";
pub const CODEX_AUTH_FILE: &str = "auth.json";
/// The prefix the pinned Claude CLI gives a long-lived OAuth token.
const CLAUDE_TOKEN_PREFIX: &str = "sk-ant-oat";
const GROUP_AND_OTHER_BITS: u32 = 0o077;
const STORE_DIR_MODE: u32 = 0o700;
const STORE_FILE_MODE: u32 = 0o600;
const SECONDS_PER_DAY: u64 = 86_400;

/// A vendor whose sessions authenticate with a credential the core hands over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialVendor {
    Claude,
    Codex,
}

impl CredentialVendor {
    pub const ALL: [Self; 2] = [Self::Claude, Self::Codex];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|vendor| vendor.as_str() == value)
    }

    #[must_use]
    pub const fn max_bytes(self) -> usize {
        match self {
            Self::Claude => CLAUDE_TOKEN_MAX_BYTES,
            Self::Codex => CODEX_AUTH_MAX_BYTES,
        }
    }

    /// The credential a session of this vendor needs; `None` for a vendor the station does
    /// not hand one to.
    #[must_use]
    pub const fn for_session(vendor: Vendor) -> Option<Self> {
        match vendor {
            Vendor::Claude => Some(Self::Claude),
            Vendor::Codex => Some(Self::Codex),
            Vendor::Antigravity | Vendor::Amp | Vendor::OpenCode => None,
        }
    }
}

impl fmt::Display for CredentialVendor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Why a value or a stored file was refused; never the value itself.
#[derive(Debug)]
pub enum CredentialError {
    Empty(CredentialVendor),
    TooLarge(CredentialVendor),
    NotUtf8(CredentialVendor),
    Shape(CredentialVendor, &'static str),
    Absent(CredentialVendor, PathBuf),
    Store(DirError),
    Io(PathBuf, io::Error),
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(vendor) => write!(formatter, "the {vendor} credential is empty"),
            Self::TooLarge(vendor) => write!(
                formatter,
                "the {vendor} credential exceeds {} bytes",
                vendor.max_bytes()
            ),
            Self::NotUtf8(vendor) => write!(formatter, "the {vendor} credential is not UTF-8"),
            Self::Shape(vendor, why) => write!(formatter, "the {vendor} credential {why}"),
            Self::Absent(vendor, path) => write!(
                formatter,
                "no {vendor} credential at {}; store one with `tycho credentials set {vendor}`",
                path.display()
            ),
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Io(path, error) => write!(formatter, "{}: {error}", path.display()),
        }
    }
}

/// One vendor's credential in memory; its `Debug` names the vendor only.
pub struct Credential {
    vendor: CredentialVendor,
    value: String,
}

impl Credential {
    /// Checks the bytes against the vendor's bound and shape.
    pub fn parse(vendor: CredentialVendor, bytes: &[u8]) -> Result<Self, CredentialError> {
        if bytes.len() > vendor.max_bytes() {
            return Err(CredentialError::TooLarge(vendor));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| CredentialError::NotUtf8(vendor))?;
        let value = text.trim();
        if value.is_empty() {
            return Err(CredentialError::Empty(vendor));
        }
        match vendor {
            CredentialVendor::Claude => check_claude_token(value)?,
            CredentialVendor::Codex => check_codex_auth(value)?,
        }
        Ok(Self {
            vendor,
            value: value.to_string(),
        })
    }

    #[must_use]
    pub const fn vendor(&self) -> CredentialVendor {
        self.vendor
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.value
    }
}

impl Clone for Credential {
    fn clone(&self) -> Self {
        Self {
            vendor: self.vendor,
            value: self.value.clone(),
        }
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Credential({}, redacted)", self.vendor)
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        wipe(std::mem::take(&mut self.value).into_bytes());
    }
}

/// Zeroes bytes that held a credential before they are freed.
pub fn wipe(mut bytes: Vec<u8>) {
    bytes.fill(0);
    // Keeps the zeroing from being removed as a dead store.
    std::hint::black_box(&bytes);
}

/// One line of printable ASCII with the prefix the pinned CLI gives a long-lived token.
fn check_claude_token(value: &str) -> Result<(), CredentialError> {
    let vendor = CredentialVendor::Claude;
    if !value.starts_with(CLAUDE_TOKEN_PREFIX) {
        return Err(CredentialError::Shape(
            vendor,
            "does not start with the long-lived token prefix sk-ant-oat",
        ));
    }
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_';
    if !value.bytes().all(allowed) {
        return Err(CredentialError::Shape(
            vendor,
            "holds a character other than letters, digits, '-' and '_'",
        ));
    }
    Ok(())
}

/// A JSON object with either a token bundle holding a refresh token or an API key.
fn check_codex_auth(value: &str) -> Result<(), CredentialError> {
    let vendor = CredentialVendor::Codex;
    let parsed: serde_json::Value =
        serde_json::from_str(value).map_err(|_| CredentialError::Shape(vendor, "is not JSON"))?;
    let object = parsed
        .as_object()
        .ok_or(CredentialError::Shape(vendor, "is not a JSON object"))?;
    let refresh = object
        .get("tokens")
        .and_then(|tokens| tokens.get("refresh_token"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|token| !token.is_empty());
    let api_key = object
        .get("OPENAI_API_KEY")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|key| !key.is_empty());
    if refresh || api_key {
        Ok(())
    } else {
        Err(CredentialError::Shape(
            vendor,
            "holds neither tokens.refresh_token nor OPENAI_API_KEY",
        ))
    }
}

#[must_use]
pub fn store_dir(core_home: &Path) -> PathBuf {
    core_home.join(CREDENTIALS_DIR)
}

#[must_use]
pub fn store_path(core_home: &Path, vendor: CredentialVendor) -> PathBuf {
    store_dir(core_home).join(vendor.as_str())
}

/// Reads at most one byte past the vendor's bound, so an oversized input is refused whole.
pub fn read_input(
    reader: impl Read,
    vendor: CredentialVendor,
) -> Result<Credential, CredentialError> {
    let limit = u64::try_from(vendor.max_bytes())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    let read = reader.take(limit).read_to_end(&mut bytes);
    let parsed = read
        .map_err(|error| CredentialError::Io(PathBuf::from("stdin"), error))
        .and_then(|_| Credential::parse(vendor, &bytes));
    bytes.fill(0);
    parsed
}

/// Creates the core home and the store one level at a time, each 0700 and the core's.
pub fn ensure_store(core_home: &Path) -> Result<PathBuf, CredentialError> {
    let dir = store_dir(core_home);
    private_dir::ensure(&[core_home.to_path_buf(), dir.clone()]).map_err(CredentialError::Store)?;
    Ok(dir)
}

/// Replaces the vendor's file atomically: a new 0600 file beside it, renamed over it.
pub fn store(core_home: &Path, credential: &Credential) -> Result<PathBuf, CredentialError> {
    ensure_store(core_home)?;
    let path = store_path(core_home, credential.vendor());
    write_durable(&path, credential.expose().as_bytes())
        .map_err(|error| CredentialError::Io(path.clone(), error))?;
    Ok(path)
}

/// Reads the vendor's file only from a private store of the core: the directory and the
/// file the current user's, closed to group and other.
pub fn load(core_home: &Path, vendor: CredentialVendor) -> Result<Credential, CredentialError> {
    let dir = store_dir(core_home);
    let metadata = match fs::symlink_metadata(&dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(CredentialError::Absent(
                vendor,
                store_path(core_home, vendor),
            ));
        }
        Err(error) => return Err(CredentialError::Io(dir, error)),
    };
    private_dir::judge(
        private_dir::Policy::Private,
        metadata.file_type().is_dir(),
        metadata.uid(),
        metadata.mode(),
        current_uid(),
    )
    .map_err(|refusal| CredentialError::Store(DirError::Refused(dir.clone(), refusal)))?;
    let path = store_path(core_home, vendor);
    if matches!(fs::symlink_metadata(&path), Err(error) if error.kind() == io::ErrorKind::NotFound)
    {
        return Err(CredentialError::Absent(vendor, path));
    }
    let mut bytes = private_dir::read_private_file(&path, vendor.max_bytes())
        .map_err(CredentialError::Store)?;
    let parsed = Credential::parse(vendor, &bytes);
    bytes.fill(0);
    parsed
}

/// What `status` found for one entry, from its own metadata; contents are never read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryState {
    Absent,
    Present {
        owner: u32,
        mode: u32,
        bytes: u64,
        age_days: Option<u64>,
        kind: EntryKind,
    },
    Unreadable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    File,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryStatus {
    pub path: PathBuf,
    pub state: EntryState,
    /// `None` when the entry is as it must be; otherwise what is wrong.
    pub problem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreStatus {
    pub dir: EntryStatus,
    pub vendors: Vec<(CredentialVendor, EntryStatus)>,
}

impl StoreStatus {
    /// The store and every vendor's file are present and as they must be.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.dir.problem.is_none()
            && self
                .vendors
                .iter()
                .all(|(_, entry)| entry.problem.is_none())
    }
}

fn entry_state(path: &Path, now: SystemTime) -> EntryState {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => EntryState::Absent,
        Err(error) => EntryState::Unreadable(error.to_string()),
        Ok(metadata) => {
            let kind = if metadata.file_type().is_dir() {
                EntryKind::Directory
            } else if metadata.file_type().is_file() {
                EntryKind::File
            } else {
                EntryKind::Other
            };
            let age_days = metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .map(|age| age.as_secs() / SECONDS_PER_DAY);
            EntryState::Present {
                owner: metadata.uid(),
                mode: metadata.mode() & 0o7777,
                bytes: metadata.len(),
                age_days,
                kind,
            }
        }
    }
}

/// What is wrong with an entry that must be the core's, of `kind`, with exactly `mode`.
fn entry_problem(state: &EntryState, kind: EntryKind, mode: u32, core_uid: u32) -> Option<String> {
    match state {
        EntryState::Absent => Some("absent".to_string()),
        EntryState::Unreadable(why) => Some(format!("cannot inspect: {why}")),
        EntryState::Present {
            kind: found, owner, ..
        } if *found != kind || *owner != core_uid => Some(format!(
            "must be a {kind:?} of uid {core_uid}, found a {found:?} of uid {owner}"
        )),
        EntryState::Present { mode: found, .. } if found & GROUP_AND_OTHER_BITS != 0 => Some(
            format!("mode {found:04o} lets group or other in; wanted {mode:04o}"),
        ),
        EntryState::Present { mode: found, .. } if *found != mode => {
            Some(format!("mode {found:04o}; wanted {mode:04o}"))
        }
        EntryState::Present { .. } => None,
    }
}

/// Presence, owner, mode and age of the store and each vendor's file, read without opening
/// any of them.
#[must_use]
pub fn status(core_home: &Path, core_uid: u32, now: SystemTime) -> StoreStatus {
    let dir_path = store_dir(core_home);
    let dir_state = entry_state(&dir_path, now);
    let dir = EntryStatus {
        problem: entry_problem(&dir_state, EntryKind::Directory, STORE_DIR_MODE, core_uid),
        path: dir_path,
        state: dir_state,
    };
    let vendors = CredentialVendor::ALL
        .into_iter()
        .map(|vendor| {
            let path = store_path(core_home, vendor);
            let state = entry_state(&path, now);
            let problem = entry_problem(&state, EntryKind::File, STORE_FILE_MODE, core_uid);
            (
                vendor,
                EntryStatus {
                    path,
                    state,
                    problem,
                },
            )
        })
        .collect();
    StoreStatus { dir, vendors }
}

impl fmt::Display for EntryStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: ", self.path.display())?;
        match &self.state {
            EntryState::Absent => write!(formatter, "absent")?,
            EntryState::Unreadable(why) => write!(formatter, "cannot inspect ({why})")?,
            EntryState::Present {
                owner,
                mode,
                bytes,
                age_days,
                kind,
            } => {
                write!(formatter, "present, uid {owner}, mode {mode:04o}")?;
                if *kind == EntryKind::File {
                    write!(formatter, ", {bytes} bytes")?;
                    if let Some(days) = age_days {
                        write!(formatter, ", set {days} days ago")?;
                    }
                }
            }
        }
        match &self.problem {
            None => write!(formatter, "; ok"),
            Some(problem) => write!(formatter, "; not ready: {problem}"),
        }
    }
}

impl fmt::Display for StoreStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "store {}", self.dir)?;
        for (vendor, entry) in &self.vendors {
            writeln!(formatter, "{vendor} {entry}")?;
        }
        let ready = self
            .vendors
            .iter()
            .filter(|(_, entry)| entry.problem.is_none())
            .count();
        write!(
            formatter,
            "{ready} of {} vendor credentials ready",
            self.vendors.len()
        )
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
pub mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The shape of a long-lived token, never a real one.
    pub const CLAUDE_TOKEN: &str = "sk-ant-oat01-test-credential-AAAAbbbbCCCCdddd0123456789";
    pub const CODEX_AUTH: &str = r#"{"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{"id_token":"test-id","access_token":"test-access-credential","refresh_token":"test-refresh-credential","account_id":"test-account"},"last_refresh":"2026-10-12T00:00:00Z"}"#;

    fn scratch(test: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tycho-credentials-{test}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        dir
    }

    #[test]
    fn each_vendor_shape_is_checked_and_nothing_prints_the_value() {
        let claude = Credential::parse(
            CredentialVendor::Claude,
            format!("{CLAUDE_TOKEN}\n").as_bytes(),
        )
        .unwrap();
        assert_eq!(claude.expose(), CLAUDE_TOKEN);
        assert!(!format!("{claude:?}").contains(CLAUDE_TOKEN));
        let codex = Credential::parse(CredentialVendor::Codex, CODEX_AUTH.as_bytes()).unwrap();
        assert!(!format!("{codex:?}").contains("test-refresh-credential"));
        let refused: [(CredentialVendor, &[u8]); 7] = [
            (CredentialVendor::Claude, b"   \n"),
            (
                CredentialVendor::Claude,
                b"sk-ant-api03-not-a-subscription-token",
            ),
            (CredentialVendor::Claude, b"sk-ant-oat01-has space"),
            (CredentialVendor::Claude, &[0xff, 0xfe]),
            (CredentialVendor::Codex, b"not json"),
            (CredentialVendor::Codex, b"[1]"),
            (
                CredentialVendor::Codex,
                br#"{"tokens":{"refresh_token":""},"OPENAI_API_KEY":null}"#,
            ),
        ];
        for (vendor, bytes) in refused {
            let error = Credential::parse(vendor, bytes).unwrap_err().to_string();
            assert!(
                !error.contains("has space") && !error.contains("api03"),
                "{error}"
            );
        }
        let api_key = br#"{"OPENAI_API_KEY":"sk-test"}"#;
        assert!(Credential::parse(CredentialVendor::Codex, api_key).is_ok());
    }

    #[test]
    fn input_over_the_bound_is_refused_whole() {
        let long = format!("{CLAUDE_TOKEN}{}", "a".repeat(CLAUDE_TOKEN_MAX_BYTES));
        assert!(matches!(
            read_input(long.as_bytes(), CredentialVendor::Claude),
            Err(CredentialError::TooLarge(CredentialVendor::Claude))
        ));
        let big = format!(
            "{{\"OPENAI_API_KEY\":\"{}\"}}",
            "k".repeat(CODEX_AUTH_MAX_BYTES)
        );
        assert!(matches!(
            read_input(big.as_bytes(), CredentialVendor::Codex),
            Err(CredentialError::TooLarge(CredentialVendor::Codex))
        ));
        assert!(read_input(CLAUDE_TOKEN.as_bytes(), CredentialVendor::Claude).is_ok());
    }

    #[test]
    fn a_stored_credential_is_private_and_reads_back() {
        let home = scratch("store");
        let credential =
            Credential::parse(CredentialVendor::Claude, CLAUDE_TOKEN.as_bytes()).unwrap();
        let path = store(&home, &credential).unwrap();
        let mode = |path: &Path| fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&store_dir(&home)), 0o700);
        assert_eq!(mode(&home), 0o700);
        let loaded = load(&home, CredentialVendor::Claude).unwrap();
        assert_eq!(loaded.expose(), CLAUDE_TOKEN);
        let replaced =
            Credential::parse(CredentialVendor::Claude, b"sk-ant-oat01-rotated").unwrap();
        store(&home, &replaced).unwrap();
        assert_eq!(
            load(&home, CredentialVendor::Claude).unwrap().expose(),
            "sk-ant-oat01-rotated"
        );
        assert!(matches!(
            load(&home, CredentialVendor::Codex),
            Err(CredentialError::Absent(CredentialVendor::Codex, _))
        ));
        fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn an_open_store_or_file_is_refused_on_load() {
        let home = scratch("open");
        let credential =
            Credential::parse(CredentialVendor::Claude, CLAUDE_TOKEN.as_bytes()).unwrap();
        let path = store(&home, &credential).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let refusal = load(&home, CredentialVendor::Claude)
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("group and other bits"), "{refusal}");
        assert!(!refusal.contains(CLAUDE_TOKEN));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(store_dir(&home), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            load(&home, CredentialVendor::Claude),
            Err(CredentialError::Store(_))
        ));
        fs::set_permissions(store_dir(&home), fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(home.join("elsewhere"), &path).unwrap();
        assert!(load(&home, CredentialVendor::Claude).is_err());
        fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn status_reports_owner_mode_and_age_without_the_value() {
        let home = scratch("status");
        let empty = status(&home, current_uid(), SystemTime::now());
        assert!(!empty.ready());
        assert_eq!(empty.dir.problem.as_deref(), Some("absent"));
        for vendor in CredentialVendor::ALL {
            let value = match vendor {
                CredentialVendor::Claude => CLAUDE_TOKEN,
                CredentialVendor::Codex => CODEX_AUTH,
            };
            store(&home, &Credential::parse(vendor, value.as_bytes()).unwrap()).unwrap();
        }
        let later = SystemTime::now() + std::time::Duration::from_secs(3 * SECONDS_PER_DAY);
        let ready = status(&home, current_uid(), later);
        assert!(ready.ready(), "{ready}");
        let text = ready.to_string();
        assert!(
            text.contains("mode 0600") && text.contains("set 3 days ago"),
            "{text}"
        );
        assert!(text.ends_with("2 of 2 vendor credentials ready"), "{text}");
        assert!(!text.contains(CLAUDE_TOKEN) && !text.contains("test-refresh-credential"));
        let codex = store_path(&home, CredentialVendor::Codex);
        fs::set_permissions(&codex, fs::Permissions::from_mode(0o644)).unwrap();
        let open = status(&home, current_uid(), SystemTime::now());
        assert!(!open.ready());
        assert!(
            open.to_string().contains("lets group or other in"),
            "{open}"
        );
        let other = status(&home, current_uid().wrapping_add(1), SystemTime::now());
        assert!(other
            .dir
            .problem
            .unwrap()
            .contains("must be a Directory of uid"));
        fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn sessions_of_claude_and_codex_need_a_credential_and_no_other_vendor_does() {
        assert_eq!(
            CredentialVendor::for_session(Vendor::Claude),
            Some(CredentialVendor::Claude)
        );
        assert_eq!(
            CredentialVendor::for_session(Vendor::Codex),
            Some(CredentialVendor::Codex)
        );
        assert_eq!(CredentialVendor::for_session(Vendor::Amp), None);
        assert_eq!(
            CredentialVendor::parse("codex"),
            Some(CredentialVendor::Codex)
        );
        assert_eq!(CredentialVendor::parse("gemini"), None);
    }
}

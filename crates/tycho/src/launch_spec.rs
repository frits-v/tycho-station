//! What the launcher is handed: the launch spec file, its checks, and the settings parsed
//! from it, including the environment the vendor may see.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tycho_types::launcher::{EnvError, LauncherEnv, ENV_SESSION_NAME, ENV_VALUE_MAX_BYTES};
use tycho_types::service::Service;

use crate::agent_files::{read_checked, shred};
use crate::config::{AgentDirs, AGENT_DIR_ENV, ZMX_ENV};

pub const HEARTBEAT_TARGET_ENV: &str = "TYCHO_HEARTBEAT_TARGET";
pub const CORE_UID_ENV: &str = "TYCHO_CORE_UID";
pub const PROGRESS_FILE_ENV: &str = "TYCHO_PROGRESS_FILE";
pub const RESULT_FILE_ENV: &str = "TYCHO_RESULT_FILE";
pub const TIER_FLAG: &str = "--tier";
pub const TIER_ENV: &str = "TYCHO_TIER";
pub const TIER_MAX_BYTES: usize = 32;
pub const VENDOR_ARGS_MAX: usize = 64;
pub const VENDOR_ARG_MAX_BYTES: usize = 4096;
pub const SPEC_FILE_MAX_BYTES: usize = 65_536;
pub const SPEC_ENV_MAX: usize = 64;
pub const SPEC_SCHEMA_VERSION: u32 = 1;
pub const WALL_CLOCK_MAX: Duration = Duration::from_secs(86_400);
pub const OUTPUT_FILE_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Telemetry off in every agent environment. Claude Code documents the first three; the two
/// entire variables are names found in the pinned entire binary.
pub const AGENT_TELEMETRY_ENV: [(&str, &str); 5] = [
    ("DISABLE_TELEMETRY", "1"),
    ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
    ("DO_NOT_TRACK", "1"),
    ("ENTIRE_TELEMETRY_OPTOUT", "1"),
    ("ENTIRE_NO_AUTO_UPDATE", "1"),
];
/// Claude Code reads its sandbox from settings, not the environment; the vendor adapter
/// passes this JSON with `--settings`, which also overrides looser repository settings.
pub const VENDOR_SANDBOX_SETTINGS_ENV: &str = "TYCHO_VENDOR_SANDBOX_SETTINGS";
/// The names of the spec's environment that reach the vendor; everything else stays with
/// the launcher.
const VENDOR_SPEC_ENV: [&str; 2] = [ENV_SESSION_NAME, VENDOR_SANDBOX_SETTINGS_ENV];
/// What the vendor inherits from the launcher's own environment.
const VENDOR_PROCESS_ENV: [&str; 2] = ["HOME", "PATH"];
const GROUP_AND_OTHER_WRITE_BITS: u32 = 0o022;
const STICKY_BIT: u32 = 0o1000;

/// Where heartbeats go; any other name is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatTarget {
    Session,
}

impl HeartbeatTarget {
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Session => "session",
        }
    }

    #[must_use]
    pub const fn service(self) -> &'static str {
        match self {
            Self::Session => Service::Session.name(),
        }
    }

    fn parse(value: Option<&str>) -> Result<Self, SettingsError> {
        match value {
            None | Some("session") => Ok(Self::Session),
            Some(_) => Err(SettingsError::HeartbeatTarget),
        }
    }
}

#[derive(Debug)]
pub enum SettingsError {
    Env(EnvError),
    Missing(&'static str),
    TooLong(&'static str),
    NotAbsolute(&'static str),
    HeartbeatTarget,
    VendorArguments(String),
    Spec(String),
    Tier(String),
    CoreUid,
}

impl fmt::Display for SettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(error) => write!(formatter, "{error}"),
            Self::Missing(name) => write!(formatter, "{name} is not set"),
            Self::TooLong(name) => {
                write!(formatter, "{name} exceeds {ENV_VALUE_MAX_BYTES} bytes")
            }
            Self::NotAbsolute(name) => write!(formatter, "{name} is not an absolute path"),
            Self::HeartbeatTarget => write!(formatter, "{HEARTBEAT_TARGET_ENV} is not known"),
            Self::VendorArguments(reason) => write!(formatter, "vendor command: {reason}"),
            Self::Spec(reason) => write!(formatter, "launch spec: {reason}"),
            Self::Tier(tier) => write!(
                formatter,
                "tier {tier:?} is not 1..={TIER_MAX_BYTES} bytes of [A-Za-z0-9._-]"
            ),
            Self::CoreUid => write!(formatter, "{CORE_UID_ENV} is not a uid"),
        }
    }
}

/// Everything the launcher reads before it runs anything.
#[derive(Debug, Clone)]
pub struct LauncherSettings {
    pub env: LauncherEnv,
    pub dirs: AgentDirs,
    pub zmx: PathBuf,
    pub heartbeat: HeartbeatTarget,
    /// The spec pairs on the vendor allowlist; never the awaitable id or the secret.
    pub vendor_env: Vec<(String, String)>,
    /// The routing tier from `--tier`, handed to the vendor as `TYCHO_TIER`.
    pub tier: Option<String>,
    pub wall_clock: Duration,
    pub output_max_bytes: u64,
}

/// A tier is 1 to 32 bytes of letters, digits, `.`, `_` and `-`.
pub fn check_tier(tier: &str) -> Result<String, SettingsError> {
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || b"._-".contains(&byte);
    if tier.is_empty() || tier.len() > TIER_MAX_BYTES || !tier.bytes().all(allowed) {
        return Err(SettingsError::Tier(
            tier.chars().take(TIER_MAX_BYTES).collect(),
        ));
    }
    Ok(tier.to_string())
}

/// The core's uid from `TYCHO_CORE_UID`, which the core types into the launch command.
pub fn core_uid_from_environment() -> Result<u32, SettingsError> {
    std::env::var(CORE_UID_ENV)
        .map_err(|_| SettingsError::Missing(CORE_UID_ENV))?
        .parse()
        .map_err(|_| SettingsError::CoreUid)
}

fn absolute(
    environment: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<PathBuf, SettingsError> {
    let value = environment.get(name).ok_or(SettingsError::Missing(name))?;
    if value.len() > ENV_VALUE_MAX_BYTES {
        return Err(SettingsError::TooLong(name));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(SettingsError::NotAbsolute(name));
    }
    Ok(path)
}

impl LauncherSettings {
    pub fn from_map(environment: &BTreeMap<String, String>) -> Result<Self, SettingsError> {
        let env = LauncherEnv::from_map(environment).map_err(SettingsError::Env)?;
        let dirs = AgentDirs::new(absolute(environment, AGENT_DIR_ENV)?)
            .map_err(|_| SettingsError::NotAbsolute(AGENT_DIR_ENV))?;
        let zmx = absolute(environment, ZMX_ENV)?;
        let heartbeat =
            HeartbeatTarget::parse(environment.get(HEARTBEAT_TARGET_ENV).map(String::as_str))?;
        let allowed = |name: &str| {
            VENDOR_SPEC_ENV.contains(&name)
                || AGENT_TELEMETRY_ENV
                    .iter()
                    .any(|(listed, _)| *listed == name)
        };
        let vendor_env = environment
            .iter()
            .filter(|(name, _)| allowed(name))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        Ok(Self {
            env,
            dirs,
            zmx,
            heartbeat,
            vendor_env,
            tier: None,
            wall_clock: WALL_CLOCK_MAX,
            output_max_bytes: OUTPUT_FILE_MAX_BYTES,
        })
    }

    /// The vendor's whole environment: the allowlisted spec pairs, `HOME` and `PATH` from the
    /// launcher, the tier, and the two files the vendor may write.
    #[must_use]
    pub fn vendor_environment(&self, progress: &Path, result: &Path) -> Vec<(String, String)> {
        let mut pairs = self.vendor_env.clone();
        for name in VENDOR_PROCESS_ENV {
            if let Ok(value) = std::env::var(name) {
                pairs.push((name.to_string(), value));
            }
        }
        if let Some(tier) = &self.tier {
            pairs.push((TIER_ENV.to_string(), tier.clone()));
        }
        pairs.push((
            PROGRESS_FILE_ENV.to_string(),
            progress.display().to_string(),
        ));
        pairs.push((RESULT_FILE_ENV.to_string(), result.display().to_string()));
        pairs
    }
}

/// The spawn step's hand-off, through a file because a typed line is cut at 1024 bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSpec {
    pub schema_version: u32,
    pub environment: BTreeMap<String, String>,
    pub vendor: Vec<String>,
}

impl fmt::Debug for LaunchSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchSpec")
            .field("environment", &self.environment.keys().collect::<Vec<_>>())
            .field("vendor", &self.vendor)
            .finish_non_exhaustive()
    }
}

impl LaunchSpec {
    /// Checks every bound and parses the settings; the spec file is never trusted unchecked.
    pub fn settings(&self) -> Result<LauncherSettings, SettingsError> {
        if self.schema_version != SPEC_SCHEMA_VERSION {
            return Err(SettingsError::Spec(format!(
                "schema version {}",
                self.schema_version
            )));
        }
        if self.environment.len() > SPEC_ENV_MAX {
            return Err(SettingsError::Spec(format!(
                "{} environment entries; maximum is {SPEC_ENV_MAX}",
                self.environment.len()
            )));
        }
        if let Some((name, _)) = self.environment.iter().find(|(name, value)| {
            name.len() > ENV_VALUE_MAX_BYTES || value.len() > ENV_VALUE_MAX_BYTES
        }) {
            return Err(SettingsError::Spec(format!(
                "{name} exceeds {ENV_VALUE_MAX_BYTES} bytes"
            )));
        }
        check_vendor(&self.vendor)?;
        LauncherSettings::from_map(&self.environment)
    }
}

/// The spec's directory must belong to the core and be writable by nobody else, or be sticky.
fn check_spec_dir(path: &Path, core_uid: u32) -> Result<(), SettingsError> {
    let dir = path
        .parent()
        .ok_or_else(|| SettingsError::Spec(format!("{} has no directory", path.display())))?;
    let metadata = fs::symlink_metadata(dir)
        .map_err(|error| SettingsError::Spec(format!("{}: {error}", dir.display())))?;
    if !metadata.file_type().is_dir() || metadata.uid() != core_uid {
        return Err(SettingsError::Spec(format!(
            "{} is not a directory of uid {core_uid} (owner uid {})",
            dir.display(),
            metadata.uid()
        )));
    }
    let mode = metadata.mode();
    if mode & GROUP_AND_OTHER_WRITE_BITS != 0 && mode & STICKY_BIT == 0 {
        return Err(SettingsError::Spec(format!(
            "{} has mode {:o}; only the core may write it unless it is sticky",
            dir.display(),
            mode & 0o7777
        )));
    }
    Ok(())
}

/// Reads a spec the core wrote, checks it, and removes it; a spec refused for its content is
/// zeroed and removed, one refused for its owner or place is left alone.
pub fn take_spec(
    path: &Path,
    core_uid: u32,
) -> Result<(LauncherSettings, Vec<String>), SettingsError> {
    check_spec_dir(path, core_uid)?;
    let bytes = read_checked(path, SPEC_FILE_MAX_BYTES, Some(core_uid))
        .map_err(|error| SettingsError::Spec(error.to_string()))?
        .ok_or_else(|| SettingsError::Spec(format!("{} does not exist", path.display())))?;
    let checked = serde_json::from_slice::<LaunchSpec>(&bytes)
        .map_err(|error| SettingsError::Spec(error.to_string()))
        .and_then(|spec| spec.settings().map(|settings| (settings, spec.vendor)));
    // Across users the core removes the spec once the lease appears; a failure here is fine.
    drop(shred(path));
    checked
}

pub fn check_vendor(vendor: &[String]) -> Result<(), SettingsError> {
    if vendor.is_empty() || vendor.len() > VENDOR_ARGS_MAX {
        return Err(SettingsError::VendorArguments(format!(
            "{} arguments; expected 1..={VENDOR_ARGS_MAX}",
            vendor.len()
        )));
    }
    if let Some(long) = vendor.iter().find(|word| word.len() > VENDOR_ARG_MAX_BYTES) {
        return Err(SettingsError::VendorArguments(format!(
            "an argument of {} bytes exceeds {VENDOR_ARG_MAX_BYTES}",
            long.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::agent_files::current_uid;
    use std::os::unix::fs::PermissionsExt;
    use tycho_types::launcher::{ENV_AWAITABLE_ID, ENV_SESSION_SECRET};

    pub const NAME: &str = "cf7a.wu03.wrk.claude.a1f3";
    pub const SECRET: &str = "0123456789abcdef0123456789abcdef";

    #[must_use]
    pub fn environment(agent_dir: &Path) -> BTreeMap<String, String> {
        let mut environment = BTreeMap::from([
            (ENV_AWAITABLE_ID.to_string(), "sign_1abc".to_string()),
            (ENV_SESSION_SECRET.to_string(), SECRET.to_string()),
            (ENV_SESSION_NAME.to_string(), NAME.to_string()),
            (AGENT_DIR_ENV.to_string(), agent_dir.display().to_string()),
            (ZMX_ENV.to_string(), "/usr/bin/true".to_string()),
            ("ZMX_DIR".to_string(), agent_dir.display().to_string()),
            (HEARTBEAT_TARGET_ENV.to_string(), "session".to_string()),
            (VENDOR_SANDBOX_SETTINGS_ENV.to_string(), "{}".to_string()),
        ]);
        for (name, value) in AGENT_TELEMETRY_ENV {
            environment.insert(name.to_string(), value.to_string());
        }
        environment
    }

    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tycho-spec-{test}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
        dir
    }

    fn spec(dir: &Path) -> LaunchSpec {
        LaunchSpec {
            schema_version: SPEC_SCHEMA_VERSION,
            environment: environment(dir),
            vendor: vec!["/bin/true".to_string()],
        }
    }

    #[test]
    fn settings_fail_closed() {
        let dir = Path::new("/agent");
        assert!(LauncherSettings::from_map(&environment(dir)).is_ok());
        let mut missing = environment(dir);
        missing.remove(AGENT_DIR_ENV);
        assert!(matches!(
            LauncherSettings::from_map(&missing),
            Err(SettingsError::Missing(AGENT_DIR_ENV))
        ));
        let mut relative = environment(dir);
        relative.insert(ZMX_ENV.to_string(), "zmx".to_string());
        assert!(matches!(
            LauncherSettings::from_map(&relative),
            Err(SettingsError::NotAbsolute(ZMX_ENV))
        ));
        let mut long = environment(dir);
        long.insert(
            ZMX_ENV.to_string(),
            format!("/{}", "z".repeat(ENV_VALUE_MAX_BYTES)),
        );
        assert!(matches!(
            LauncherSettings::from_map(&long),
            Err(SettingsError::TooLong(ZMX_ENV))
        ));
        let mut target = environment(dir);
        target.insert(HEARTBEAT_TARGET_ENV.to_string(), "Session".to_string());
        assert!(matches!(
            LauncherSettings::from_map(&target),
            Err(SettingsError::HeartbeatTarget)
        ));
        let mut secret = environment(dir);
        secret.remove(ENV_SESSION_SECRET);
        assert!(matches!(
            LauncherSettings::from_map(&secret),
            Err(SettingsError::Env(_))
        ));
    }

    #[test]
    fn vendor_arguments_and_tiers_are_bounded() {
        assert!(check_vendor(&[]).is_err());
        assert_eq!(check_tier("t2-fast").unwrap(), "t2-fast");
        for tier in ["", "a b", "t;rm", &"t".repeat(TIER_MAX_BYTES + 1)] {
            assert!(
                matches!(check_tier(tier), Err(SettingsError::Tier(_))),
                "{tier}"
            );
        }
        assert!(check_vendor(&["x".repeat(VENDOR_ARG_MAX_BYTES + 1)]).is_err());
        assert!(check_vendor(&vec!["x".to_string(); VENDOR_ARGS_MAX + 1]).is_err());
    }

    #[test]
    fn the_vendor_environment_is_exactly_the_allowlist() {
        let mut settings = LauncherSettings::from_map(&environment(Path::new("/agent"))).unwrap();
        settings.tier = Some("t2".to_string());
        let pairs =
            settings.vendor_environment(Path::new("/s/progress.json"), Path::new("/s/result.json"));
        let mut names: Vec<&str> = pairs.iter().map(|(name, _)| name.as_str()).collect();
        names.sort_unstable();
        let mut expected = vec![
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
            "DISABLE_TELEMETRY",
            "DO_NOT_TRACK",
            "ENTIRE_NO_AUTO_UPDATE",
            "ENTIRE_TELEMETRY_OPTOUT",
            "HOME",
            "PATH",
            "TYCHO_PROGRESS_FILE",
            "TYCHO_RESULT_FILE",
            "TYCHO_SESSION_NAME",
            "TYCHO_TIER",
            "TYCHO_VENDOR_SANDBOX_SETTINGS",
        ];
        expected.sort_unstable();
        assert_eq!(names, expected);
        assert!(!pairs
            .iter()
            .any(|(_, value)| value == SECRET || value == "sign_1abc"));
    }

    #[test]
    fn a_spec_is_checked_zeroed_and_removed() {
        let dir = scratch("spec");
        let path = dir.join("s.json");
        assert!(matches!(
            take_spec(&path, current_uid()),
            Err(SettingsError::Spec(_))
        ));
        fs::write(&path, serde_json::to_vec(&spec(&dir)).unwrap()).unwrap();
        let (_, vendor) = take_spec(&path, current_uid()).unwrap();
        assert_eq!(vendor, spec(&dir).vendor);
        assert!(!path.exists(), "the spec outlived its read");
        assert!(!format!("{:?}", spec(&dir)).contains(SECRET));
        let mut wide = spec(&dir);
        for index in 0..=SPEC_ENV_MAX {
            wide.environment
                .insert(format!("EXTRA_{index}"), "x".to_string());
        }
        let mut versioned = spec(&dir);
        versioned.schema_version = 2;
        let mut no_vendor = spec(&dir);
        no_vendor.vendor.clear();
        for refused in [wide, versioned, no_vendor] {
            fs::write(&path, serde_json::to_vec(&refused).unwrap()).unwrap();
            assert!(take_spec(&path, current_uid()).is_err());
            assert!(!path.exists(), "a refused spec is zeroed and removed");
        }
        fs::write(&path, "x".repeat(SPEC_FILE_MAX_BYTES + 1)).unwrap();
        assert!(take_spec(&path, current_uid()).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_spec_of_another_owner_or_in_an_open_directory_is_refused_and_left() {
        let dir = scratch("owner");
        let path = dir.join("s.json");
        fs::write(&path, serde_json::to_vec(&spec(&dir)).unwrap()).unwrap();
        let other = current_uid().wrapping_add(1);
        let refusal = take_spec(&path, other).unwrap_err().to_string();
        assert!(refusal.contains(&format!("uid {other}")), "{refusal}");
        assert!(
            refusal.contains(&format!("owner uid {}", current_uid())),
            "{refusal}"
        );
        assert!(path.exists(), "a spec refused for its owner is left alone");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o770)).unwrap();
        let refusal = take_spec(&path, current_uid()).unwrap_err().to_string();
        assert!(refusal.contains("only the core may write it"), "{refusal}");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o1770)).unwrap();
        assert!(
            take_spec(&path, current_uid()).is_ok(),
            "a sticky directory is accepted"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}

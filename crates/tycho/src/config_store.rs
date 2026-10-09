//! The exported factory configuration under `config/export`: JSON files, each read only when
//! it matches the SHA-256 in its sibling `.sha256`, decoded into closed typed structs.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tycho_types::task_packet::{Effort, RoutingName};

pub const CONFIG_DIR_ENV: &str = "TYCHO_CONFIG_DIR";
/// Under the core home, so only the core's user can change what the services read.
pub const CONFIG_SUBDIR: &str = "config";
pub const CONFIG_FILE_MAX_BYTES: u64 = 64 * 1024;
pub const CLASSES_MAX_ITEMS: usize = 32;
pub const TIERS_MAX_ITEMS: usize = 8;
pub const MODEL_MAX_BYTES: usize = 64;
const HASH_HEX_DIGITS: usize = 64;
const ROUTING: &str = "routing";
const THRESHOLDS: &str = "thresholds";

/// A decoded file and the SHA-256 of the bytes it was decoded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentHashed<T> {
    pub hash: String,
    pub value: T,
}

#[derive(Debug)]
pub enum StoreError {
    Read(PathBuf, io::Error),
    TooLarge(String, u64),
    HashLine(String),
    HashMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    Decode(String, serde_json::Error),
    Unrecognised(String, String),
    Invalid(String, String),
    RelativeDir(PathBuf),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(path, error) => write!(formatter, "cannot read {}: {error}", path.display()),
            Self::TooLarge(name, length) => write!(
                formatter,
                "{name} is {length} bytes; limit is {CONFIG_FILE_MAX_BYTES}"
            ),
            Self::HashLine(name) => {
                write!(
                    formatter,
                    "{name}.sha256 is not 64 lowercase hex digits and a newline"
                )
            }
            Self::HashMismatch {
                name,
                expected,
                actual,
            } => write!(
                formatter,
                "{name}.json hashes to {actual}; {name}.sha256 says {expected}"
            ),
            Self::Decode(name, error) => write!(formatter, "{name}.json: {error}"),
            Self::Unrecognised(name, what) => {
                write!(formatter, "{name}.json: unrecognised value at {what}")
            }
            Self::Invalid(name, what) => write!(formatter, "{name}.json: {what}"),
            Self::RelativeDir(path) => {
                write!(
                    formatter,
                    "{CONFIG_DIR_ENV}={} is not absolute",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for StoreError {}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(HASH_HEX_DIGITS);
    for byte in Sha256::digest(bytes) {
        for nibble in [byte >> 4, byte & 0x0f] {
            if let Some(digit) = HEX.get(usize::from(nibble)) {
                text.push(char::from(*digit));
            }
        }
    }
    text
}

fn parse_hash_line(name: &str, line: &[u8]) -> Result<String, StoreError> {
    let digits = line
        .strip_suffix(b"\n")
        .filter(|digits| digits.len() == HASH_HEX_DIGITS)
        .filter(|digits| {
            digits
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        })
        .ok_or_else(|| StoreError::HashLine(name.to_string()))?;
    Ok(String::from_utf8_lossy(digits).into_owned())
}

/// Decodes `bytes` only when they hash to the digest in `hash_line`.
pub fn decode<T: DeserializeOwned>(
    name: &str,
    bytes: &[u8],
    hash_line: &[u8],
) -> Result<ContentHashed<T>, StoreError> {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if length > CONFIG_FILE_MAX_BYTES {
        return Err(StoreError::TooLarge(name.to_string(), length));
    }
    let expected = parse_hash_line(name, hash_line)?;
    let actual = sha256_hex(bytes);
    if actual != expected {
        return Err(StoreError::HashMismatch {
            name: name.to_string(),
            expected,
            actual,
        });
    }
    let value = serde_json::from_slice(bytes)
        .map_err(|error| StoreError::Decode(name.to_string(), error))?;
    Ok(ContentHashed {
        hash: actual,
        value,
    })
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, StoreError> {
    let file = File::open(path).map_err(|error| StoreError::Read(path.to_path_buf(), error))?;
    let mut bytes = Vec::new();
    file.take(CONFIG_FILE_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| StoreError::Read(path.to_path_buf(), error))?;
    Ok(bytes)
}

fn read_file<T: DeserializeOwned>(dir: &Path, name: &str) -> Result<ContentHashed<T>, StoreError> {
    let bytes = read_bounded(&dir.join(format!("{name}.json")))?;
    let hash_line = read_bounded(&dir.join(format!("{name}.sha256")))?;
    decode(name, &bytes, &hash_line)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfiguredEffort {
    Minimal,
    Low,
    Medium,
    High,
    Max,
    #[serde(other)]
    Unrecognised,
}

impl ConfiguredEffort {
    /// `None` for the unrecognised state, which is never usable.
    #[must_use]
    pub const fn effort(self) -> Option<Effort> {
        match self {
            Self::Minimal => Some(Effort::Minimal),
            Self::Low => Some(Effort::Low),
            Self::Medium => Some(Effort::Medium),
            Self::High => Some(Effort::High),
            Self::Max => Some(Effort::Max),
            Self::Unrecognised => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Class {
    pub minimum_tier: RoutingName,
    pub effort: ConfiguredEffort,
    pub attempt_cap: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Models {
    pub claude: String,
    pub codex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tier {
    pub models: Models,
    pub fallback: Option<RoutingName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingTables {
    pub classes: BTreeMap<RoutingName, Class>,
    pub attempt_cap_default: u16,
    pub tiers: BTreeMap<RoutingName, Tier>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stall {
    pub silence_seconds: u64,
    pub progress_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotCounts {
    pub control: u16,
    pub worker: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retry {
    pub backoff_initial_seconds: u64,
    pub backoff_max_seconds: u64,
    pub backoff_factor: u32,
    pub port_step_attempts_max: u32,
    pub slot_retry_delay_seconds: u64,
    pub unit_attempt_cap: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTimes {
    pub heartbeat_interval_seconds: u64,
    pub lease_fresh_seconds: u64,
    pub spawn_grace_seconds: u64,
    pub reconciler_interval_seconds: u64,
    pub rollover_fraction: f64,
}

/// Article 14.3 to 15.3 thresholds; `None` until the operator sets them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MandateThresholds {
    pub convention_citations_min: Option<u32>,
    pub petition_repeat_count: Option<u32>,
    pub convention_held_period_days: Option<u32>,
    pub review_period_days: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    pub stall: Stall,
    pub slots: SlotCounts,
    pub retry: Retry,
    pub session: SessionTimes,
    pub mandate: MandateThresholds,
}

fn check_routing(routing: &RoutingTables) -> Result<(), String> {
    if routing.classes.is_empty() || routing.classes.len() > CLASSES_MAX_ITEMS {
        return Err(format!(
            "{} classes; expected 1..={CLASSES_MAX_ITEMS}",
            routing.classes.len()
        ));
    }
    if routing.tiers.is_empty() || routing.tiers.len() > TIERS_MAX_ITEMS {
        return Err(format!(
            "{} tiers; expected 1..={TIERS_MAX_ITEMS}",
            routing.tiers.len()
        ));
    }
    for (name, class) in &routing.classes {
        if !routing.tiers.contains_key(&class.minimum_tier) {
            return Err(format!("class {name} names a missing tier"));
        }
        if class.attempt_cap == 0 {
            return Err(format!("class {name} has an attempt cap of zero"));
        }
    }
    for (name, tier) in &routing.tiers {
        let models = [&tier.models.claude, &tier.models.codex];
        if models
            .iter()
            .any(|model| model.is_empty() || model.len() > MODEL_MAX_BYTES)
        {
            return Err(format!(
                "tier {name} has a model name outside 1..={MODEL_MAX_BYTES} bytes"
            ));
        }
        if tier
            .fallback
            .as_ref()
            .is_some_and(|fallback| !routing.tiers.contains_key(fallback))
        {
            return Err(format!("tier {name} falls back to a missing tier"));
        }
    }
    if routing.attempt_cap_default == 0 {
        return Err("attempt_cap_default is zero".to_string());
    }
    Ok(())
}

fn check_thresholds(thresholds: &Thresholds) -> Result<(), String> {
    let stall = thresholds.stall;
    let retry = thresholds.retry;
    let session = thresholds.session;
    let positive = [
        stall.silence_seconds,
        retry.backoff_initial_seconds,
        retry.slot_retry_delay_seconds,
        session.heartbeat_interval_seconds,
        session.spawn_grace_seconds,
        session.reconciler_interval_seconds,
        u64::from(thresholds.slots.control),
        u64::from(thresholds.slots.worker),
        u64::from(retry.port_step_attempts_max),
        u64::from(retry.unit_attempt_cap),
    ];
    if positive.contains(&0) {
        return Err("a duration, slot count or attempt cap is zero".to_string());
    }
    if stall.progress_seconds <= stall.silence_seconds
        || retry.backoff_max_seconds < retry.backoff_initial_seconds
        || session.lease_fresh_seconds <= session.heartbeat_interval_seconds
    {
        return Err(
            "T2 must exceed T1, the backoff cap its start, the lease the heartbeat".to_string(),
        );
    }
    if retry.backoff_factor != 2 {
        return Err("backoff_factor must be 2; the spine implements doubling".to_string());
    }
    if !(session.rollover_fraction > 0.0 && session.rollover_fraction < 1.0) {
        return Err("rollover_fraction is outside (0, 1)".to_string());
    }
    Ok(())
}

/// The content hashes a work unit records at its start.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigHashes {
    pub routing: String,
    pub thresholds: String,
}

/// The configuration the services run with.
#[derive(Debug, Clone, PartialEq)]
pub struct FactoryConfig {
    pub routing: ContentHashed<RoutingTables>,
    pub thresholds: ContentHashed<Thresholds>,
}

impl FactoryConfig {
    pub fn load(dir: &Path) -> Result<Self, StoreError> {
        Self::checked(read_file(dir, ROUTING)?, read_file(dir, THRESHOLDS)?)
    }

    /// The export this binary was built with.
    pub fn embedded() -> Result<Self, StoreError> {
        Self::checked(
            decode(
                ROUTING,
                include_bytes!("../../../config/export/routing.json"),
                include_bytes!("../../../config/export/routing.sha256"),
            )?,
            decode(
                THRESHOLDS,
                include_bytes!("../../../config/export/thresholds.json"),
                include_bytes!("../../../config/export/thresholds.sha256"),
            )?,
        )
    }

    fn checked(
        routing: ContentHashed<RoutingTables>,
        thresholds: ContentHashed<Thresholds>,
    ) -> Result<Self, StoreError> {
        if let Some((name, _)) = routing
            .value
            .classes
            .iter()
            .find(|(_, class)| class.effort.effort().is_none())
        {
            return Err(StoreError::Unrecognised(
                ROUTING.to_string(),
                format!("classes.{name}.effort"),
            ));
        }
        check_routing(&routing.value)
            .map_err(|what| StoreError::Invalid(ROUTING.to_string(), what))?;
        check_thresholds(&thresholds.value)
            .map_err(|what| StoreError::Invalid(THRESHOLDS.to_string(), what))?;
        Ok(Self {
            routing,
            thresholds,
        })
    }

    #[must_use]
    pub fn hashes(&self) -> ConfigHashes {
        ConfigHashes {
            routing: self.routing.hash.clone(),
            thresholds: self.thresholds.hash.clone(),
        }
    }

    /// The attempt cap of a task class, or the table's default for a class it does not list.
    #[must_use]
    pub fn attempt_cap(&self, class: &RoutingName) -> u16 {
        let routing = &self.routing.value;
        routing
            .classes
            .get(class)
            .map_or(routing.attempt_cap_default, |listed| listed.attempt_cap)
    }
}

/// Where the configuration comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    Dir(PathBuf),
    Embedded,
}

impl fmt::Display for ConfigSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dir(dir) => write!(formatter, "{}", dir.display()),
            Self::Embedded => formatter.write_str("the export embedded in the binary"),
        }
    }
}

/// `TYCHO_CONFIG_DIR` when set, else `<core home>/config` when it exists, else the embedded export.
pub fn resolve_source(
    variable: Option<OsString>,
    home: Option<&Path>,
) -> Result<ConfigSource, StoreError> {
    if let Some(dir) = variable.map(PathBuf::from) {
        if !dir.is_absolute() {
            return Err(StoreError::RelativeDir(dir));
        }
        return Ok(ConfigSource::Dir(dir));
    }
    match home.map(|home| home.join(CONFIG_SUBDIR)) {
        Some(dir) if dir.is_dir() => Ok(ConfigSource::Dir(dir)),
        _ => Ok(ConfigSource::Embedded),
    }
}

pub fn load(source: &ConfigSource) -> Result<FactoryConfig, StoreError> {
    match source {
        ConfigSource::Dir(dir) => FactoryConfig::load(dir),
        ConfigSource::Embedded => FactoryConfig::embedded(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTING_JSON: &[u8] = include_bytes!("../../../config/export/routing.json");
    const ROUTING_HASH: &[u8] = include_bytes!("../../../config/export/routing.sha256");

    #[test]
    fn the_embedded_export_loads_and_equals_the_spine_numbers() {
        let config = FactoryConfig::embedded().unwrap();
        let thresholds = config.thresholds.value;
        assert_eq!(thresholds.stall.silence_seconds, 300);
        assert_eq!(thresholds.stall.progress_seconds, 900);
        assert_eq!(thresholds.retry.backoff_initial_seconds, 10);
        assert_eq!(thresholds.retry.backoff_max_seconds, 300);
        assert_eq!(thresholds.retry.port_step_attempts_max, 12);
        assert_eq!(thresholds.retry.slot_retry_delay_seconds, 10);
        assert_eq!(thresholds.retry.unit_attempt_cap, 3);
        assert_eq!(
            thresholds.slots,
            SlotCounts {
                control: 2,
                worker: 2
            }
        );
        assert_eq!(thresholds.session.lease_fresh_seconds, 30);
        assert_eq!(thresholds.session.spawn_grace_seconds, 60);
        assert_eq!(thresholds.session.reconciler_interval_seconds, 30);
        assert_eq!(config.hashes().routing, sha256_hex(ROUTING_JSON));
    }

    #[test]
    fn a_listed_class_takes_its_cap_and_an_unlisted_one_the_default() {
        let config = FactoryConfig::embedded().unwrap();
        assert_eq!(
            config.attempt_cap(&RoutingName::parse("implement").unwrap()),
            3
        );
        assert_eq!(
            config.attempt_cap(&RoutingName::parse("unlisted").unwrap()),
            3
        );
    }

    #[test]
    fn refuses_bytes_that_do_not_match_their_hash() {
        let mut edited = ROUTING_JSON.to_vec();
        edited.push(b' ');
        let refused = decode::<RoutingTables>("routing", &edited, ROUTING_HASH);
        assert!(
            matches!(refused, Err(StoreError::HashMismatch { .. })),
            "{refused:?}"
        );
    }

    #[test]
    fn refuses_a_malformed_hash_line() {
        for line in [
            &b""[..],
            b"abc\n",
            &ROUTING_HASH[..64],
            b"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\n",
        ] {
            assert!(matches!(
                decode::<RoutingTables>("routing", ROUTING_JSON, line),
                Err(StoreError::HashLine(_))
            ));
        }
    }

    fn hashed(text: &str) -> (Vec<u8>, Vec<u8>) {
        let bytes = text.as_bytes().to_vec();
        let line = format!("{}\n", sha256_hex(&bytes)).into_bytes();
        (bytes, line)
    }

    #[test]
    fn refuses_unknown_fields_and_oversized_files() {
        let text = String::from_utf8_lossy(ROUTING_JSON).replace(
            "\"attempt_cap_default\"",
            "\"extra\": 1, \"attempt_cap_default\"",
        );
        let (bytes, line) = hashed(&text);
        assert!(matches!(
            decode::<RoutingTables>("routing", &bytes, &line),
            Err(StoreError::Decode(..))
        ));
        let limit = usize::try_from(CONFIG_FILE_MAX_BYTES).unwrap();
        let (bytes, line) = hashed(&" ".repeat(limit.saturating_add(1)));
        assert!(matches!(
            decode::<RoutingTables>("routing", &bytes, &line),
            Err(StoreError::TooLarge(..))
        ));
    }

    #[test]
    fn an_unrecognised_effort_is_never_usable() {
        let text = String::from_utf8_lossy(ROUTING_JSON).replacen("\"low\"", "\"extreme\"", 1);
        let (bytes, line) = hashed(&text);
        let routing = decode::<RoutingTables>("routing", &bytes, &line).unwrap();
        let embedded = FactoryConfig::embedded().unwrap();
        let refused = FactoryConfig::checked(routing, embedded.thresholds);
        assert!(
            matches!(refused, Err(StoreError::Unrecognised(..))),
            "{refused:?}"
        );
    }

    #[test]
    fn refuses_a_class_naming_a_missing_tier_and_inverted_timers() {
        let text = String::from_utf8_lossy(ROUTING_JSON).replacen(
            "\"minimum_tier\": \"light\"",
            "\"minimum_tier\": \"tiny\"",
            1,
        );
        let (bytes, line) = hashed(&text);
        let routing = decode::<RoutingTables>("routing", &bytes, &line).unwrap();
        let embedded = FactoryConfig::embedded().unwrap();
        assert!(matches!(
            FactoryConfig::checked(routing, embedded.thresholds.clone()),
            Err(StoreError::Invalid(..))
        ));
        let mut thresholds = embedded.thresholds.clone();
        thresholds.value.stall.progress_seconds = thresholds.value.stall.silence_seconds;
        assert!(matches!(
            FactoryConfig::checked(embedded.routing, thresholds),
            Err(StoreError::Invalid(..))
        ));
    }

    #[test]
    fn source_prefers_the_variable_then_the_home_then_the_embedded_export() {
        let home = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert_eq!(
            resolve_source(Some(OsString::from("/etc/tycho")), Some(&home)).unwrap(),
            ConfigSource::Dir(PathBuf::from("/etc/tycho"))
        );
        assert!(matches!(
            resolve_source(Some(OsString::from("relative")), None),
            Err(StoreError::RelativeDir(_))
        ));
        assert_eq!(
            resolve_source(None, Some(&home)).unwrap(),
            ConfigSource::Dir(home.join("config"))
        );
        assert_eq!(
            resolve_source(None, Some(Path::new("/nonexistent"))).unwrap(),
            ConfigSource::Embedded
        );
        assert_eq!(resolve_source(None, None).unwrap(), ConfigSource::Embedded);
    }

    #[test]
    fn loads_the_checked_in_export_directory() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/export");
        assert_eq!(
            FactoryConfig::load(&dir).unwrap(),
            FactoryConfig::embedded().unwrap()
        );
    }
}

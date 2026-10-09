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

use crate::private_dir;

mod bounds;

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
    Dir(String),
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
            Self::Dir(error) => write!(formatter, "configuration directory: {error}"),
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigHashes {
    pub routing: String,
    pub thresholds: String,
}

/// What a work unit journals at its start and runs with from then on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitConfig {
    pub hashes: ConfigHashes,
    pub unit_attempt_cap: u16,
}

/// What a worker run journals at its start: its class's attempt cap and the tiers it climbs,
/// starting with the requested one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub hashes: ConfigHashes,
    pub attempt_cap: u16,
    pub tiers: Vec<RoutingName>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    UnknownClass(RoutingName),
    UnknownTier(RoutingName),
    BelowMinimum {
        tier: RoutingName,
        minimum: RoutingName,
    },
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownClass(class) => {
                write!(formatter, "class {class} is not in the routing table")
            }
            Self::UnknownTier(tier) => write!(formatter, "tier {tier} is not in the routing table"),
            Self::BelowMinimum { tier, minimum } => {
                write!(
                    formatter,
                    "tier {tier} is below the class minimum {minimum}"
                )
            }
        }
    }
}

impl std::error::Error for RouteError {}

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
        bounds::check_routing(&routing.value)
            .map_err(|what| StoreError::Invalid(ROUTING.to_string(), what))?;
        bounds::check_thresholds(&thresholds.value)
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

    #[must_use]
    pub fn unit_config(&self) -> UnitConfig {
        UnitConfig {
            hashes: self.hashes(),
            unit_attempt_cap: self.thresholds.value.retry.unit_attempt_cap,
        }
    }

    /// Refuses a class the table does not list and a tier below the class minimum.
    pub fn route(&self, class: &RoutingName, tier: &RoutingName) -> Result<Route, RouteError> {
        let routing = &self.routing.value;
        let listed = routing
            .classes
            .get(class)
            .ok_or_else(|| RouteError::UnknownClass(class.clone()))?;
        if !routing.tiers.contains_key(tier) {
            return Err(RouteError::UnknownTier(tier.clone()));
        }
        let ladder = self.ladder(&listed.minimum_tier);
        let position = ladder.iter().position(|name| name == tier).ok_or_else(|| {
            RouteError::BelowMinimum {
                tier: tier.clone(),
                minimum: listed.minimum_tier.clone(),
            }
        })?;
        Ok(Route {
            hashes: self.hashes(),
            attempt_cap: listed.attempt_cap,
            tiers: ladder.into_iter().skip(position).collect(),
        })
    }

    /// The tier and its fallbacks in order, stopping at the top or at a tier seen before.
    fn ladder(&self, from: &RoutingName) -> Vec<RoutingName> {
        let mut ladder: Vec<RoutingName> = Vec::new();
        let mut current = Some(from.clone());
        for _ in 0..TIERS_MAX_ITEMS {
            let Some(name) = current.take() else {
                break;
            };
            if ladder.contains(&name) {
                break;
            }
            current = self
                .routing
                .value
                .tiers
                .get(&name)
                .and_then(|tier| tier.fallback.clone());
            ladder.push(name);
        }
        ladder
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

/// A directory is read only when it is the user's own and not writable by others.
pub fn load(source: &ConfigSource) -> Result<FactoryConfig, StoreError> {
    match source {
        ConfigSource::Dir(dir) => {
            if !dir.is_dir() {
                return Err(StoreError::Dir(format!(
                    "{} is not a directory",
                    dir.display()
                )));
            }
            private_dir::ensure_owned(dir).map_err(|error| StoreError::Dir(error.to_string()))?;
            FactoryConfig::load(dir)
        }
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

    fn name(text: &str) -> RoutingName {
        RoutingName::parse(text).unwrap()
    }

    #[test]
    fn a_route_climbs_from_the_requested_tier_to_the_top() {
        let config = FactoryConfig::embedded().unwrap();
        let route = config.route(&name("implement"), &name("standard")).unwrap();
        assert_eq!(route.attempt_cap, 3);
        assert_eq!(route.tiers, vec![name("standard"), name("strong")]);
        assert_eq!(route.hashes, config.hashes());
        let top = config.route(&name("implement"), &name("strong")).unwrap();
        assert_eq!(top.tiers, vec![name("strong")]);
    }

    #[test]
    fn a_route_refuses_an_unlisted_class_an_unknown_tier_and_a_tier_below_the_minimum() {
        let config = FactoryConfig::embedded().unwrap();
        assert_eq!(
            config.route(&name("unlisted"), &name("standard")),
            Err(RouteError::UnknownClass(name("unlisted")))
        );
        assert_eq!(
            config.route(&name("implement"), &name("huge")),
            Err(RouteError::UnknownTier(name("huge")))
        );
        assert_eq!(
            config.route(&name("implement"), &name("light")),
            Err(RouteError::BelowMinimum {
                tier: name("light"),
                minimum: name("standard")
            })
        );
    }

    #[test]
    fn a_fallback_cycle_ends_the_ladder() {
        let mut config = FactoryConfig::embedded().unwrap();
        config
            .routing
            .value
            .tiers
            .get_mut(&name("strong"))
            .unwrap()
            .fallback = Some(name("standard"));
        let route = config.route(&name("implement"), &name("standard")).unwrap();
        assert_eq!(route.tiers, vec![name("standard"), name("strong")]);
    }

    #[test]
    fn a_directory_open_to_others_is_refused_before_any_file_is_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("config-store-open-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let refused = load(&ConfigSource::Dir(dir.clone()));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let empty = load(&ConfigSource::Dir(dir.clone()));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(matches!(refused, Err(StoreError::Dir(_))), "{refused:?}");
        assert!(matches!(empty, Err(StoreError::Read(..))), "{empty:?}");
        assert!(matches!(
            load(&ConfigSource::Dir(PathBuf::from("/nonexistent-config"))),
            Err(StoreError::Dir(_))
        ));
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
        let text =
            String::from_utf8_lossy(ROUTING_JSON).replace("\"tiers\"", "\"extra\": 1, \"tiers\"");
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

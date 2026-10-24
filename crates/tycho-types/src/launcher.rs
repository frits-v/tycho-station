//! The environment a spawn step hands the launcher, and the idempotency keys the
//! launcher's ingress calls carry.

use std::collections::BTreeMap;
use std::fmt;

use crate::session::{SessionName, SessionNameError};

use crate::token::{TokenError, check_opaque, checked_string};

pub const ENV_AWAITABLE_ID: &str = "TYCHO_AWAITABLE_ID";
pub const ENV_SESSION_SECRET: &str = "TYCHO_SESSION_SECRET";
pub const ENV_SESSION_NAME: &str = "TYCHO_SESSION_NAME";
pub const ENV_VALUE_MAX_BYTES: usize = 512;
pub const AWAITABLE_ID_MAX_BYTES: usize = 256;
pub const SESSION_SECRET_MIN_BYTES: usize = 32;
pub const SESSION_SECRET_MAX_BYTES: usize = 128;
pub const SEQUENCE_MAX: u64 = u32::MAX as u64;

fn check_awaitable_id(value: &str) -> Result<(), TokenError> {
    check_opaque(value, AWAITABLE_ID_MAX_BYTES)
}

checked_string!(
    /// The id of the awaitable the launcher resolves or rejects on exit.
    AwaitableId,
    check_awaitable_id
);

fn check_awaitable_digest(value: &str) -> Result<(), TokenError> {
    crate::token::check_hex(value, &[AWAITABLE_DIGEST_HEX_DIGITS])
}

pub const AWAITABLE_DIGEST_HEX_DIGITS: usize = 64;

checked_string!(
    /// SHA-256 of an awaitable id in lowercase hex: names the awaitable without granting it.
    AwaitableDigest,
    check_awaitable_digest
);

impl AwaitableDigest {
    #[must_use]
    pub fn of(awaitable: &AwaitableId) -> Self {
        use sha2::{Digest, Sha256};
        use std::fmt::Write;
        let mut hex = String::with_capacity(AWAITABLE_DIGEST_HEX_DIGITS);
        for byte in Sha256::digest(awaitable.as_str().as_bytes()) {
            if write!(hex, "{byte:02x}").is_err() {
                break;
            }
        }
        Self(hex)
    }
}

/// The per-session heartbeat secret; it has no serialization and a redacted `Debug`.
#[derive(Clone)]
pub struct SessionSecret(String);

impl SessionSecret {
    pub fn parse(value: &str) -> Result<Self, TokenError> {
        check_opaque(value, SESSION_SECRET_MAX_BYTES)?;
        if value.len() < SESSION_SECRET_MIN_BYTES {
            return Err(TokenError::TooShort {
                length: value.len(),
                min: SESSION_SECRET_MIN_BYTES,
            });
        }
        Ok(Self(value.to_string()))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Compares in time independent of where the bytes differ; only the length can leak.
    #[must_use]
    pub fn verify(&self, candidate: &str) -> bool {
        let expected = self.0.as_bytes();
        let candidate = candidate.as_bytes();
        if expected.len() != candidate.len() {
            return false;
        }
        let difference = expected
            .iter()
            .zip(candidate)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            });
        difference == 0
    }
}

impl fmt::Debug for SessionSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionSecret(redacted)")
    }
}

#[derive(Debug, Clone)]
pub struct LauncherEnv {
    pub awaitable_id: AwaitableId,
    pub session_secret: SessionSecret,
    pub session_name: SessionName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvError {
    Missing(&'static str),
    TooLong {
        name: &'static str,
        length: usize,
    },
    Invalid {
        name: &'static str,
        reason: TokenError,
    },
    SessionName(SessionNameError),
}

impl fmt::Display for EnvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(formatter, "{name} is not set"),
            Self::TooLong { name, length } => write!(
                formatter,
                "{name} is {length} bytes; maximum is {ENV_VALUE_MAX_BYTES}"
            ),
            Self::Invalid { name, reason } => write!(formatter, "{name}: {reason}"),
            Self::SessionName(error) => write!(formatter, "{ENV_SESSION_NAME}: {error}"),
        }
    }
}

impl std::error::Error for EnvError {}

fn read<'a>(
    environment: &'a BTreeMap<String, String>,
    name: &'static str,
) -> Result<&'a str, EnvError> {
    let value = environment.get(name).ok_or(EnvError::Missing(name))?;
    if value.len() > ENV_VALUE_MAX_BYTES {
        return Err(EnvError::TooLong {
            name,
            length: value.len(),
        });
    }
    Ok(value)
}

impl LauncherEnv {
    pub fn from_map(environment: &BTreeMap<String, String>) -> Result<Self, EnvError> {
        let awaitable_id =
            AwaitableId::parse(read(environment, ENV_AWAITABLE_ID)?).map_err(|reason| {
                EnvError::Invalid {
                    name: ENV_AWAITABLE_ID,
                    reason,
                }
            })?;
        let session_secret =
            SessionSecret::parse(read(environment, ENV_SESSION_SECRET)?).map_err(|reason| {
                EnvError::Invalid {
                    name: ENV_SESSION_SECRET,
                    reason,
                }
            })?;
        let session_name = SessionName::parse(read(environment, ENV_SESSION_NAME)?)
            .map_err(EnvError::SessionName)?;
        Ok(Self {
            awaitable_id,
            session_secret,
            session_name,
        })
    }

    /// The pairs a spawn step sets on the launcher's process.
    #[must_use]
    pub fn to_pairs(&self) -> [(&'static str, String); 3] {
        [
            (ENV_AWAITABLE_ID, self.awaitable_id.to_string()),
            (ENV_SESSION_SECRET, self.session_secret.expose().to_string()),
            (ENV_SESSION_NAME, self.session_name.to_string()),
        ]
    }
}

pub const IDEMPOTENCY_KEY_MAX_BYTES: usize = 96;

/// Key of a launcher ingress call: the session name, a colon and a sequence number.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotencyKeyError {
    Sequence(u64),
    TooLong(usize),
}

impl fmt::Display for IdempotencyKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sequence(sequence) => {
                write!(formatter, "sequence {sequence} exceeds {SEQUENCE_MAX}")
            }
            Self::TooLong(length) => write!(
                formatter,
                "idempotency key is {length} bytes; maximum is {IDEMPOTENCY_KEY_MAX_BYTES}"
            ),
        }
    }
}

impl std::error::Error for IdempotencyKeyError {}

impl IdempotencyKey {
    pub fn new(session: &SessionName, sequence: u64) -> Result<Self, IdempotencyKeyError> {
        if sequence > SEQUENCE_MAX {
            return Err(IdempotencyKeyError::Sequence(sequence));
        }
        Self::bounded(format!("{session}:{sequence}"))
    }

    /// Unreachable from `new` while `SESSION_NAME_MAX_BYTES` and `SEQUENCE_MAX` fit the maximum.
    fn bounded(key: String) -> Result<Self, IdempotencyKeyError> {
        if key.len() > IDEMPOTENCY_KEY_MAX_BYTES {
            return Err(IdempotencyKeyError::TooLong(key.len()));
        }
        Ok(Self(key))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SESSION_NAME_MAX_BYTES;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn environment() -> BTreeMap<String, String> {
        BTreeMap::from([
            (ENV_AWAITABLE_ID.to_string(), "sign_1abc".to_string()),
            (ENV_SESSION_SECRET.to_string(), SECRET.to_string()),
            (
                ENV_SESSION_NAME.to_string(),
                "cf7a.wu03.wrk.claude.a1f3".to_string(),
            ),
        ])
    }

    #[test]
    fn reads_the_contract_and_writes_it_back() {
        let env = LauncherEnv::from_map(&environment()).unwrap();
        assert_eq!(env.awaitable_id.as_str(), "sign_1abc");
        assert_eq!(env.session_secret.expose(), SECRET);
        let round_trip: BTreeMap<String, String> = env
            .to_pairs()
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect();
        assert_eq!(round_trip, environment());
    }

    #[test]
    fn rejects_missing_and_overlong_values() {
        let mut missing = environment();
        missing.remove(ENV_SESSION_SECRET);
        assert!(matches!(
            LauncherEnv::from_map(&missing),
            Err(EnvError::Missing(ENV_SESSION_SECRET))
        ));
        let mut long = environment();
        long.insert(
            ENV_AWAITABLE_ID.to_string(),
            "a".repeat(ENV_VALUE_MAX_BYTES.saturating_add(1)),
        );
        assert!(matches!(
            LauncherEnv::from_map(&long),
            Err(EnvError::TooLong { .. })
        ));
        let mut wide = environment();
        wide.insert(
            ENV_AWAITABLE_ID.to_string(),
            "a".repeat(AWAITABLE_ID_MAX_BYTES.saturating_add(1)),
        );
        assert!(matches!(
            LauncherEnv::from_map(&wide),
            Err(EnvError::Invalid { .. })
        ));
    }

    #[test]
    fn rejects_short_secrets_and_bad_names() {
        let mut short = environment();
        short.insert(ENV_SESSION_SECRET.to_string(), "short".to_string());
        assert!(matches!(
            LauncherEnv::from_map(&short),
            Err(EnvError::Invalid {
                reason: TokenError::TooShort { .. },
                ..
            })
        ));
        let mut name = environment();
        name.insert(ENV_SESSION_NAME.to_string(), "cf7a".to_string());
        assert!(matches!(
            LauncherEnv::from_map(&name),
            Err(EnvError::SessionName(_))
        ));
    }

    #[test]
    fn rejects_overlong_secrets() {
        let mut long = environment();
        long.insert(
            ENV_SESSION_SECRET.to_string(),
            "s".repeat(SESSION_SECRET_MAX_BYTES.saturating_add(1)),
        );
        assert!(matches!(
            LauncherEnv::from_map(&long),
            Err(EnvError::Invalid {
                name: ENV_SESSION_SECRET,
                reason: TokenError::TooLong { .. },
            })
        ));
    }

    #[test]
    fn secret_verifies_only_an_exact_match() {
        let secret = SessionSecret::parse(SECRET).unwrap();
        assert!(secret.verify(SECRET));
        assert!(!secret.verify(&SECRET.replace('0', "1")));
        assert!(!secret.verify(&SECRET[1..]));
        assert!(!secret.verify(""));
    }

    #[test]
    fn digest_is_lowercase_sha256_and_parses_back() {
        let digest = AwaitableDigest::of(&AwaitableId::parse("abc").unwrap());
        assert_eq!(
            digest.as_str(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(AwaitableDigest::parse(digest.as_str()).unwrap(), digest);
        assert!(AwaitableDigest::parse("sign_1abc").is_err());
        assert!(AwaitableDigest::parse(&digest.as_str().to_uppercase()).is_err());
    }

    #[test]
    fn secret_never_prints() {
        let env = LauncherEnv::from_map(&environment()).unwrap();
        let printed = format!("{env:?}");
        assert!(!printed.contains(SECRET));
        assert!(printed.contains("redacted"));
    }

    #[test]
    fn idempotency_key_is_bounded() {
        let session = SessionName::parse("cf7a.wu03.wrk.claude.a1f3").unwrap();
        let key = IdempotencyKey::new(&session, 7).unwrap();
        assert_eq!(key.as_str(), "cf7a.wu03.wrk.claude.a1f3:7");
        let largest = IdempotencyKey::new(&session, SEQUENCE_MAX).unwrap();
        assert!(largest.as_str().len() <= IDEMPOTENCY_KEY_MAX_BYTES);
        assert_eq!(
            IdempotencyKey::new(&session, SEQUENCE_MAX.saturating_add(1)),
            Err(IdempotencyKeyError::Sequence(
                SEQUENCE_MAX.saturating_add(1)
            ))
        );
        let longest = format!(
            "{}.{}.ctl.antigravity.{}",
            "e".repeat(16),
            "u".repeat(16),
            "s".repeat(13)
        );
        let longest = SessionName::parse(&longest).unwrap();
        assert!(IdempotencyKey::new(&longest, SEQUENCE_MAX).is_ok());
        assert!(SESSION_NAME_MAX_BYTES.saturating_add(11) <= IDEMPOTENCY_KEY_MAX_BYTES);
    }

    #[test]
    fn idempotency_key_rejects_its_maximum_plus_one() {
        assert!(IdempotencyKey::bounded("k".repeat(IDEMPOTENCY_KEY_MAX_BYTES)).is_ok());
        let over = IDEMPOTENCY_KEY_MAX_BYTES.saturating_add(1);
        assert_eq!(
            IdempotencyKey::bounded("k".repeat(over)),
            Err(IdempotencyKeyError::TooLong(over))
        );
    }
}

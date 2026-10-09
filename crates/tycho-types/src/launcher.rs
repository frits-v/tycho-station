//! The environment a spawn step hands the launcher, and the idempotency keys the
//! launcher's ingress calls carry.

use std::collections::BTreeMap;
use std::fmt;

use crate::session::{SessionName, SessionNameError, SESSION_NAME_MAX_BYTES};
use crate::token::{check_opaque, checked_string, TokenError};

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

/// The per-session secret for heartbeat calls. Neither `Debug` nor any
/// serialization prints it, so it cannot leak into a log, a lease or a payload.
#[derive(Clone, PartialEq, Eq)]
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
}

impl fmt::Debug for SessionSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionSecret(redacted)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

pub const IDEMPOTENCY_KEY_MAX_BYTES: usize = SESSION_NAME_MAX_BYTES + 1 + 10;

/// Idempotency key of a launcher ingress call: the session name plus a sequence
/// number, so a retried call deduplicates and the next call does not.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceError(pub u64);

impl fmt::Display for SequenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sequence {} exceeds {SEQUENCE_MAX}", self.0)
    }
}

impl std::error::Error for SequenceError {}

impl IdempotencyKey {
    pub fn new(session: &SessionName, sequence: u64) -> Result<Self, SequenceError> {
        if sequence > SEQUENCE_MAX {
            return Err(SequenceError(sequence));
        }
        Ok(Self(format!("{session}:{sequence}")))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            LauncherEnv::from_map(&missing),
            Err(EnvError::Missing(ENV_SESSION_SECRET))
        );
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
            Err(SequenceError(SEQUENCE_MAX.saturating_add(1)))
        );
    }
}

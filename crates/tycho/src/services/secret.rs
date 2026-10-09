//! Per-session heartbeat secrets: generated inside a journaled step, checked in constant time.

use std::fs::File;
use std::io::{self, Read};

use tycho_types::launcher::SessionSecret;

const SECRET_BYTES: usize = 32;
const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// 32 bytes from the kernel as 64 lowercase hex digits.
pub fn generate() -> io::Result<SessionSecret> {
    let mut bytes = [0_u8; SECRET_BYTES];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let hex: String = bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .filter_map(|nibble| {
            DIGITS
                .get(usize::from(nibble))
                .map(|digit| char::from(*digit))
        })
        .collect();
    SessionSecret::parse(&hex).map_err(|error| io::Error::other(error.to_string()))
}

/// False for a wrong candidate and for a stored value that is not a valid secret.
#[must_use]
pub fn matches(stored: &str, candidate: &str) -> bool {
    SessionSecret::parse(stored).is_ok_and(|secret| secret.verify(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_distinct_valid_secrets() {
        let first = generate().unwrap();
        let second = generate().unwrap();
        assert_eq!(first.expose().len(), SECRET_BYTES * 2);
        assert_ne!(first.expose(), second.expose());
    }

    #[test]
    fn accepts_the_right_secret() {
        let secret = generate().unwrap();
        assert!(matches(secret.expose(), secret.expose()));
    }

    #[test]
    fn rejects_a_wrong_secret() {
        let secret = generate().unwrap();
        let other = generate().unwrap();
        assert!(!matches(secret.expose(), other.expose()));
        assert!(!matches(secret.expose(), ""));
        assert!(!matches(secret.expose(), &secret.expose()[1..]));
    }

    #[test]
    fn rejects_when_the_stored_value_is_not_a_secret() {
        assert!(!matches("short", "short"));
    }
}

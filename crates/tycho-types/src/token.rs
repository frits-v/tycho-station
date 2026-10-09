//! Validation for the string types that cross a process or trust boundary.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    Empty,
    TooShort { length: usize, min: usize },
    TooLong { length: usize, max: usize },
    InvalidCharacter { position: usize },
    Reserved,
}

impl fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(formatter, "empty"),
            Self::TooShort { length, min } => {
                write!(formatter, "{length} bytes; minimum is {min}")
            }
            Self::TooLong { length, max } => write!(formatter, "{length} bytes; maximum is {max}"),
            Self::InvalidCharacter { position } => {
                write!(formatter, "invalid character at byte {position}")
            }
            Self::Reserved => write!(formatter, "reserved word"),
        }
    }
}

impl std::error::Error for TokenError {}

const fn check_length(value: &str, max: usize) -> Result<(), TokenError> {
    if value.is_empty() {
        return Err(TokenError::Empty);
    }
    if value.len() > max {
        return Err(TokenError::TooLong {
            length: value.len(),
            max,
        });
    }
    Ok(())
}

fn first_invalid(value: &str, allowed: impl Fn(u8) -> bool) -> Result<(), TokenError> {
    if let Some(position) = value.bytes().position(|byte| !allowed(byte)) {
        return Err(TokenError::InvalidCharacter { position });
    }
    Ok(())
}

/// Lowercase letters, digits and `-`, starting with a letter or digit so that a
/// session name built from it is never read as a command line flag.
pub fn check_slug(value: &str, max: usize) -> Result<(), TokenError> {
    check_length(value, max)?;
    if value.starts_with('-') {
        return Err(TokenError::InvalidCharacter { position: 0 });
    }
    first_invalid(value, |byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
    })
}

/// Visible ASCII without whitespace: the shape of opaque ids and secrets.
pub fn check_opaque(value: &str, max: usize) -> Result<(), TokenError> {
    check_length(value, max)?;
    first_invalid(value, |byte| byte.is_ascii_graphic())
}

/// Letters, digits, `-` and `_`: record ids such as ULIDs.
pub fn check_record_id(value: &str, max: usize) -> Result<(), TokenError> {
    check_length(value, max)?;
    first_invalid(value, |byte| {
        byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
    })
}

/// Lowercase hexadecimal of exactly one of the given lengths.
pub fn check_hex(value: &str, lengths: &[usize]) -> Result<(), TokenError> {
    let max = lengths.iter().copied().max().unwrap_or(0);
    check_length(value, max)?;
    if !lengths.contains(&value.len()) {
        return Err(TokenError::TooShort {
            length: value.len(),
            min: max,
        });
    }
    first_invalid(value, |byte| {
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
    })
}

/// Printable text without control characters, so a summary cannot carry
/// terminal escape sequences into a pane or the inbox.
pub fn check_text(value: &str, max: usize) -> Result<(), TokenError> {
    check_length(value, max)?;
    if let Some((position, _)) = value.char_indices().find(|(_, c)| c.is_control()) {
        return Err(TokenError::InvalidCharacter { position });
    }
    Ok(())
}

/// Defines a string newtype whose only constructor runs `check`, and which
/// serializes as a plain JSON string validated on the way in.
macro_rules! checked_string {
    ($(#[$meta:meta])* $name:ident, $check:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: &str) -> Result<Self, $crate::token::TokenError> {
                let check: fn(&str) -> Result<(), $crate::token::TokenError> = $check;
                check(value)?;
                Ok(Self(value.to_string()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $name {
            type Error = $crate::token::TokenError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(&value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

pub(crate) use checked_string;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_accepts_lowercase_digits_and_dash() {
        assert_eq!(check_slug("wu-orders-split", 16), Ok(()));
        assert_eq!(check_slug("cf7a", 16), Ok(()));
    }

    #[test]
    fn slug_rejects_each_defect() {
        assert_eq!(check_slug("", 16), Err(TokenError::Empty));
        assert_eq!(
            check_slug("abcdefghijklmnopq", 16),
            Err(TokenError::TooLong {
                length: 17,
                max: 16
            })
        );
        assert_eq!(
            check_slug("-d", 16),
            Err(TokenError::InvalidCharacter { position: 0 })
        );
        assert_eq!(
            check_slug("wu.03", 16),
            Err(TokenError::InvalidCharacter { position: 2 })
        );
        assert_eq!(
            check_slug("WU03", 16),
            Err(TokenError::InvalidCharacter { position: 0 })
        );
    }

    #[test]
    fn opaque_rejects_whitespace() {
        assert_eq!(check_opaque("sign_1abc", 64), Ok(()));
        assert_eq!(
            check_opaque("a b", 64),
            Err(TokenError::InvalidCharacter { position: 1 })
        );
    }

    #[test]
    fn hex_requires_an_allowed_length_and_lowercase() {
        let sha = "a".repeat(40);
        assert_eq!(check_hex(&sha, &[40, 64]), Ok(()));
        assert!(check_hex(&"a".repeat(41), &[40, 64]).is_err());
        assert!(check_hex(&"A".repeat(40), &[40, 64]).is_err());
        assert!(check_hex(&"a".repeat(65), &[40, 64]).is_err());
    }

    #[test]
    fn text_rejects_control_characters() {
        assert_eq!(check_text("tests pass", 32), Ok(()));
        assert_eq!(
            check_text("red\u{1b}[31m", 32),
            Err(TokenError::InvalidCharacter { position: 3 })
        );
        assert!(check_text(&"x".repeat(33), 32).is_err());
    }
}

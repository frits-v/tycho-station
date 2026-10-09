//! Fixture content for the synthetic epic, addressed by the `sha256` of its bytes.
//! Embedding with `include_bytes!` keeps the harness free of a runtime fetch.

use std::fmt;

use sha2::{Digest, Sha256};
use tycho_types::envelope::ContentRef;
use tycho_types::token::TokenError;

/// A fixture content file larger than this is rejected rather than hashed and truncated.
pub const CONTENT_MAX_BYTES: usize = 8192;

pub const OBJECTIVE_TRIVIAL: &[u8] = include_bytes!("../fixtures/content/objective-trivial.md");
pub const OBJECTIVE_MODERATE: &[u8] = include_bytes!("../fixtures/content/objective-moderate.md");
pub const OBJECTIVE_FORCED_ESCALATION: &[u8] =
    include_bytes!("../fixtures/content/objective-forced-escalation.md");
pub const OBJECTIVE_FORCED_COUNCIL: &[u8] =
    include_bytes!("../fixtures/content/objective-forced-council.md");
pub const OBJECTIVE_DOWNSTREAM: &[u8] =
    include_bytes!("../fixtures/content/objective-downstream.md");
/// Committed as `POLICY.md`; referenced from the forced escalation unit's inputs.
pub const POLICY_BUDGET_CEILING: &[u8] =
    include_bytes!("../fixtures/content/policy-budget-ceiling.md");
pub const RESULT_SCHEMA: &[u8] = include_bytes!("../fixtures/content/result-schema.md");

#[derive(Debug, PartialEq, Eq)]
pub enum ContentError {
    TooLarge { bytes: usize },
    Token(TokenError),
}

impl fmt::Display for ContentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes } => {
                write!(formatter, "{bytes} bytes; maximum is {CONTENT_MAX_BYTES}")
            }
            Self::Token(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ContentError {}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from_digit(u32::from(nibble), 10).unwrap_or('0'),
        _ => char::from_digit(u32::from(nibble), 16).unwrap_or('f'),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        hex.push(hex_digit(byte >> 4));
        hex.push(hex_digit(byte & 0x0f));
    }
    hex
}

/// Hashes fixture content into the `sha256:<hex>` form a `ContentRef` requires.
pub fn content_ref(bytes: &[u8]) -> Result<ContentRef, ContentError> {
    if bytes.len() > CONTENT_MAX_BYTES {
        return Err(ContentError::TooLarge { bytes: bytes.len() });
    }
    let digest = Sha256::digest(bytes);
    let reference = format!("sha256:{}", to_hex(&digest));
    ContentRef::parse(&reference).map_err(ContentError::Token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_match_the_literals_the_fixtures_were_pinned_with() {
        let known = [
            (
                OBJECTIVE_TRIVIAL,
                "sha256:7e3c0e3b34e15fbeb0e7e0573f11580e255f41792c5acee0a4d02fbb8eea1a25",
            ),
            (
                OBJECTIVE_MODERATE,
                "sha256:a4b947b54f86cdfa2a8fe38ae1863a9c2504d7ef88517c8b17c16c78715d408d",
            ),
            (
                OBJECTIVE_FORCED_ESCALATION,
                "sha256:04034684accc4cf760f9728274b4f48554b0f9caa90784591fdde4aa8e362fa4",
            ),
            (
                OBJECTIVE_FORCED_COUNCIL,
                "sha256:9a0f8c15dddd215e17cc3ca437c4ec92fd2b53074539d16ec1942a46d457784c",
            ),
            (
                OBJECTIVE_DOWNSTREAM,
                "sha256:2117b73d0c7475fa835ce61e0107c380689a9aea27b388af73a16a963576d42e",
            ),
            (
                POLICY_BUDGET_CEILING,
                "sha256:8eb939cc037d95e92bb9e3018e62986843202c782bd5a0d9f688efbb1422d09a",
            ),
            (
                RESULT_SCHEMA,
                "sha256:2fdaa039597af9108edd356a3a6e72e34f85e4eae7a34ac7a7137494ca786477",
            ),
        ];
        assert_eq!(known.len(), 7, "every fixture content file is covered here");
        for (bytes, expected) in known {
            assert_eq!(content_ref(bytes).unwrap().as_str(), expected);
        }
    }

    #[test]
    fn oversized_content_is_rejected_not_truncated() {
        let big = vec![b'a'; CONTENT_MAX_BYTES.saturating_add(1)];
        assert_eq!(
            content_ref(&big),
            Err(ContentError::TooLarge {
                bytes: CONTENT_MAX_BYTES.saturating_add(1)
            })
        );
    }
}

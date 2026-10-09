//! The port offset of a test core: zero for the production core, else one of
//! `PORT_OFFSET_SLOTS` multiples of the stride from `PORT_OFFSET_BASE` to `PORT_OFFSET_MAX`.

use std::ffi::OsString;
use std::fmt;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Set by a test suite to the offset of its test home; never set for the production core.
pub const PORT_OFFSET_ENV: &str = "TYCHO_PORT_OFFSET";
/// No two production ports differ by a multiple of the stride, so cores whose offsets differ
/// by one never share a port; `config` tests it over the whole range.
pub const PORT_OFFSET_STRIDE: u16 = 32;
/// The lowest test offset, a multiple of the stride.
pub const PORT_OFFSET_BASE: u16 = 1024;
pub const PORT_OFFSET_SLOTS: u16 = 900;
/// `PORT_OFFSET_BASE` plus 899 strides; the highest shifted port stays below 49152, where the
/// macOS ephemeral range starts.
pub const PORT_OFFSET_MAX: u16 = 29_792;
/// Five decimal digits hold every `u16`.
pub const PORT_OFFSET_TEXT_MAX_BYTES: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortOffsetError {
    /// The variable is set while no test home is.
    NoTestHome,
    NotDecimal(String),
    OutOfRange(u32),
    OffStride(u32),
}

impl fmt::Display for PortOffsetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTestHome => write!(
                formatter,
                "{PORT_OFFSET_ENV} is set without a test home; the production core keeps its ports"
            ),
            Self::NotDecimal(text) => write!(
                formatter,
                "{PORT_OFFSET_ENV}={text:?} is not 1..={PORT_OFFSET_TEXT_MAX_BYTES} decimal digits"
            ),
            Self::OutOfRange(value) => write!(
                formatter,
                "{PORT_OFFSET_ENV}={value} is outside {PORT_OFFSET_BASE}..={PORT_OFFSET_MAX}"
            ),
            Self::OffStride(value) => write!(
                formatter,
                "{PORT_OFFSET_ENV}={value} is not {PORT_OFFSET_BASE} plus a multiple of {PORT_OFFSET_STRIDE}"
            ),
        }
    }
}

impl std::error::Error for PortOffsetError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortOffset(u16);

impl PortOffset {
    pub const PRODUCTION: Self = Self(0);

    /// A test offset: `PORT_OFFSET_BASE` plus a multiple of the stride, at most `PORT_OFFSET_MAX`.
    pub fn new(value: u32) -> Result<Self, PortOffsetError> {
        let base = u32::from(PORT_OFFSET_BASE);
        if !(base..=u32::from(PORT_OFFSET_MAX)).contains(&value) {
            return Err(PortOffsetError::OutOfRange(value));
        }
        let above_base = value.saturating_sub(base);
        if above_base.checked_rem(u32::from(PORT_OFFSET_STRIDE)) != Some(0) {
            return Err(PortOffsetError::OffStride(value));
        }
        u16::try_from(value)
            .map(Self)
            .map_err(|_| PortOffsetError::OutOfRange(value))
    }

    /// The offset of slot `hash` modulo `PORT_OFFSET_SLOTS`; defined for every `u64`.
    #[must_use]
    pub fn for_hash(hash: u64) -> Self {
        let slot = hash.checked_rem(u64::from(PORT_OFFSET_SLOTS)).unwrap_or(0);
        let offset = slot
            .checked_mul(u64::from(PORT_OFFSET_STRIDE))
            .and_then(|strides| strides.checked_add(u64::from(PORT_OFFSET_BASE)))
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(PORT_OFFSET_BASE);
        Self(offset)
    }

    /// The first eight bytes of the SHA-256 of the home's path, so every process that is
    /// handed the same home derives the same offset.
    #[must_use]
    pub fn for_test_home(home: &Path) -> Self {
        let digest = Sha256::digest(home.as_os_str().as_encoded_bytes());
        let mut prefix = [0_u8; 8];
        for (slot, byte) in prefix.iter_mut().zip(digest.iter()) {
            *slot = *byte;
        }
        Self::for_hash(u64::from_be_bytes(prefix))
    }

    /// Decodes the variable's text; zero is refused, since it is the production core's.
    pub fn parse(text: &str) -> Result<Self, PortOffsetError> {
        let decimal = !text.is_empty()
            && text.len() <= PORT_OFFSET_TEXT_MAX_BYTES
            && text.bytes().all(|byte| byte.is_ascii_digit());
        if !decimal {
            return Err(PortOffsetError::NotDecimal(
                text.chars().take(PORT_OFFSET_TEXT_MAX_BYTES).collect(),
            ));
        }
        let value = text
            .parse::<u32>()
            .map_err(|_| PortOffsetError::NotDecimal(text.to_string()))?;
        Self::new(value)
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn is_production(self) -> bool {
        self.0 == 0
    }

    /// Never saturates: the highest port plus `PORT_OFFSET_MAX` is below `u16::MAX`.
    #[must_use]
    pub const fn shift(self, port: u16) -> u16 {
        port.saturating_add(self.0)
    }
}

impl fmt::Display for PortOffset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// `TYCHO_PORT_OFFSET` when set beside a test home, else the production ports.
pub fn resolve_port_offset(
    variable: Option<OsString>,
    test_home: bool,
) -> Result<PortOffset, PortOffsetError> {
    let Some(variable) = variable else {
        return Ok(PortOffset::PRODUCTION);
    };
    if !test_home {
        return Err(PortOffsetError::NoTestHome);
    }
    let text = variable
        .into_string()
        .map_err(|raw| PortOffsetError::NotDecimal(raw.to_string_lossy().into_owned()))?;
    PortOffset::parse(&text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn the_max_is_the_last_slot() {
        let last = u32::from(PORT_OFFSET_SLOTS - 1) * u32::from(PORT_OFFSET_STRIDE)
            + u32::from(PORT_OFFSET_BASE);
        assert_eq!(last, u32::from(PORT_OFFSET_MAX));
        assert_eq!(PORT_OFFSET_BASE % PORT_OFFSET_STRIDE, 0);
    }

    #[test]
    fn every_hash_lands_in_the_range_on_a_stride() {
        let slots = u64::from(PORT_OFFSET_SLOTS);
        for hash in [0, 1, slots - 1, slots, slots + 1, u64::MAX - 1, u64::MAX] {
            let offset = PortOffset::for_hash(hash);
            assert_eq!(PortOffset::new(u32::from(offset.get())), Ok(offset));
        }
        assert_eq!(PortOffset::for_hash(0).get(), PORT_OFFSET_BASE);
        assert_eq!(PortOffset::for_hash(slots - 1).get(), PORT_OFFSET_MAX);
        assert_eq!(PortOffset::for_hash(slots).get(), PORT_OFFSET_BASE);
    }

    #[test]
    fn a_home_always_derives_the_same_test_offset() {
        let home = PathBuf::from("/Users/someone/.tycho-spine-cancel-4242");
        let offset = PortOffset::for_test_home(&home);
        assert_eq!(PortOffset::for_test_home(&home), offset);
        assert!(!offset.is_production());
        assert!(!PortOffset::for_test_home(Path::new("")).is_production());
        assert_ne!(
            PortOffset::for_test_home(Path::new("/Users/someone/.tycho-spine-cancel-4243")),
            offset
        );
    }

    #[test]
    fn decodes_the_edges_of_the_range() {
        assert_eq!(
            PortOffset::parse("1024").map(PortOffset::get),
            Ok(PORT_OFFSET_BASE)
        );
        assert_eq!(
            PortOffset::parse("29792").map(PortOffset::get),
            Ok(PORT_OFFSET_MAX)
        );
        assert_eq!(PortOffset::parse("1056").map(PortOffset::get), Ok(1056));
    }

    #[test]
    fn refuses_an_offset_that_leaves_the_range() {
        for value in ["0", "992", "1023", "29793", "29824", "65535", "99999"] {
            assert!(
                matches!(
                    PortOffset::parse(value),
                    Err(PortOffsetError::OutOfRange(_))
                ),
                "{value}"
            );
        }
        assert_eq!(
            PortOffset::new(u32::MAX),
            Err(PortOffsetError::OutOfRange(u32::MAX))
        );
    }

    #[test]
    fn refuses_an_offset_off_the_stride() {
        for value in ["1025", "1055", "29791"] {
            assert!(
                matches!(PortOffset::parse(value), Err(PortOffsetError::OffStride(_))),
                "{value}"
            );
        }
    }

    #[test]
    fn refuses_text_that_is_not_a_short_decimal() {
        for text in [
            "",
            " 1024",
            "1024 ",
            "+1024",
            "-1024",
            "0x400",
            "102400",
            "１０２４",
        ] {
            assert!(
                matches!(PortOffset::parse(text), Err(PortOffsetError::NotDecimal(_))),
                "{text:?}"
            );
        }
    }

    #[test]
    fn resolves_production_without_the_variable_and_refuses_it_without_a_test_home() {
        assert_eq!(resolve_port_offset(None, false), Ok(PortOffset::PRODUCTION));
        assert_eq!(resolve_port_offset(None, true), Ok(PortOffset::PRODUCTION));
        assert_eq!(
            resolve_port_offset(Some(OsString::from("1024")), false),
            Err(PortOffsetError::NoTestHome)
        );
        assert_eq!(
            resolve_port_offset(Some(OsString::from("1024")), true).map(PortOffset::get),
            Ok(1024)
        );
    }

    #[test]
    fn shifting_the_highest_port_by_the_max_does_not_saturate() {
        let max = PortOffset::new(u32::from(PORT_OFFSET_MAX)).unwrap();
        assert!(u32::from(u16::MAX) > u32::from(19_081_u16) + u32::from(PORT_OFFSET_MAX));
        assert_eq!(max.shift(19_081), 48_873);
    }
}

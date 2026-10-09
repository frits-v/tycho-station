//! A test core's claim on a port offset slot: an exclusive lock on the slot's file, held for
//! the core's life, so no two live test cores of this user share an offset.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg, OFlag};

use super::{user_home, CorePorts};
use crate::config_store::{PortOffset, PORT_OFFSET_SLOTS};
use crate::private_dir;

/// Under the user's home, so every worktree and suite of the user shares one set of slots.
pub const PORT_SLOT_DIR: &str = ".tycho-port-slots";
const SLOT_FILE_MODE: u32 = 0o600;

#[derive(Debug)]
pub enum ClaimError {
    Dir(String),
    Open(PathBuf, io::Error),
    Lock(PathBuf, Errno),
    /// Every slot tried was held by another live test core.
    Exhausted(u16),
    /// The slot was free among test cores, but a process outside them holds one of its ports.
    Taken {
        home: PathBuf,
        offset: PortOffset,
        detail: String,
    },
}

impl fmt::Display for ClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dir(error) => write!(formatter, "port slot directory: {error}"),
            Self::Open(path, error) => write!(formatter, "cannot open {}: {error}", path.display()),
            Self::Lock(path, errno) => write!(formatter, "cannot lock {}: {errno}", path.display()),
            Self::Exhausted(tried) => write!(formatter, "all {tried} port slots tried are held"),
            Self::Taken {
                home,
                offset,
                detail,
            } => write!(
                formatter,
                "port collision: {} at port offset {offset}: {detail}",
                home.display()
            ),
        }
    }
}

impl std::error::Error for ClaimError {}

/// Dropping the claim releases the slot, so it lives as long as the core it was taken for.
pub struct PortClaim {
    pub home: PathBuf,
    pub ports: CorePorts,
    _lock: Flock<File>,
}

impl fmt::Debug for PortClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortClaim")
            .field("home", &self.home)
            .field("ports", &self.ports)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for PortClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ports = self.ports;
        write!(
            formatter,
            "{} at port offset {}, free: admin {}, ingress {}, node {}, endpoint {}, test endpoint {}",
            self.home.display(),
            ports.offset,
            ports.admin().port(),
            ports.ingress().port(),
            ports.node().port(),
            ports.endpoint().port(),
            ports.test_endpoint().port(),
        )
    }
}

impl CorePorts {
    /// Locks the first slot no other test core holds, starting at the home's own, then checks
    /// the five ports against processes outside the test cores.
    pub fn claim(home: &Path) -> Result<PortClaim, ClaimError> {
        let user_home = user_home().map_err(|error| ClaimError::Dir(error.to_string()))?;
        let claim = claim_in(&user_home.join(PORT_SLOT_DIR), home, PORT_OFFSET_SLOTS)?;
        match claim.ports.first_taken() {
            Some(detail) => Err(ClaimError::Taken {
                home: claim.home,
                offset: claim.ports.offset,
                detail,
            }),
            None => Ok(claim),
        }
    }
}

/// Tries at most `attempts` slots, never more than there are, from the home's own slot on.
pub fn claim_in(dir: &Path, home: &Path, attempts: u16) -> Result<PortClaim, ClaimError> {
    let start = PortOffset::for_test_home(home).slot().unwrap_or(0);
    claim_from(dir, home, start, attempts)
}

fn claim_from(dir: &Path, home: &Path, start: u16, attempts: u16) -> Result<PortClaim, ClaimError> {
    private_dir::ensure(&[dir.to_path_buf()])
        .map_err(|error| ClaimError::Dir(error.to_string()))?;
    let tries = attempts.min(PORT_OFFSET_SLOTS);
    for step in 0..tries {
        let offset = PortOffset::for_slot(u32::from(start).saturating_add(u32::from(step)));
        let path = dir.join(offset.slot().unwrap_or(0).to_string());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(SLOT_FILE_MODE)
            .custom_flags(OFlag::O_NOFOLLOW.bits())
            .open(&path)
            .map_err(|error| ClaimError::Open(path.clone(), error))?;
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => {
                return Ok(PortClaim {
                    home: home.to_path_buf(),
                    ports: CorePorts::at(offset),
                    _lock: lock,
                })
            }
            Err((_, Errno::EWOULDBLOCK)) => {}
            Err((_, errno)) => return Err(ClaimError::Lock(path, errno)),
        }
    }
    Err(ClaimError::Exhausted(tries))
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use crate::config_store::PORT_OFFSET_MAX;
    use std::fs;

    fn scratch(test: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("port-slots-{test}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        dir
    }

    #[test]
    fn two_claims_from_homes_on_the_same_slot_get_different_offsets() {
        let dir = scratch("same");
        let home = Path::new("/Users/someone/.tycho-spine-unit-42");
        let first = claim_in(&dir, home, PORT_OFFSET_SLOTS).unwrap();
        let second = claim_in(&dir, home, PORT_OFFSET_SLOTS).unwrap();
        assert_eq!(first.ports.offset, PortOffset::for_test_home(home));
        assert_ne!(first.ports.offset, second.ports.offset);
        let first_slot = first.ports.offset.slot().unwrap();
        assert_eq!(
            second.ports.offset,
            PortOffset::for_slot(u32::from(first_slot) + 1)
        );
        drop(first);
        let again = claim_in(&dir, home, PORT_OFFSET_SLOTS).unwrap();
        assert_eq!(again.ports.offset, PortOffset::for_test_home(home));
        drop((second, again));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_last_slot_wraps_to_the_first() {
        let dir = scratch("wrap");
        let home = Path::new("/h");
        let last = claim_from(&dir, home, PORT_OFFSET_SLOTS - 1, 2).unwrap();
        assert_eq!(last.ports.offset.get(), PORT_OFFSET_MAX);
        let wrapped = claim_from(&dir, home, PORT_OFFSET_SLOTS - 1, 2).unwrap();
        assert_eq!(wrapped.ports.offset.slot(), Some(0));
        drop((last, wrapped));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn claims_stop_at_their_bound_when_every_slot_tried_is_held() {
        let dir = scratch("bound");
        let home = Path::new("/h");
        let held = [
            claim_from(&dir, home, 7, 2).unwrap(),
            claim_from(&dir, home, 7, 2).unwrap(),
        ];
        assert!(matches!(
            claim_from(&dir, home, 7, 2),
            Err(ClaimError::Exhausted(2))
        ));
        assert!(matches!(
            claim_from(&dir, home, 7, u16::MAX),
            Ok(claim) if claim.ports.offset.slot() == Some(9)
        ));
        drop(held);
        fs::remove_dir_all(&dir).unwrap();
    }
}

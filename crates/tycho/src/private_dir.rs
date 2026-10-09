//! Creates the core's directories and refuses any that another user could have planted or
//! can reach.

use std::fmt;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use nix::unistd::Uid;

pub const PRIVATE_DIR_MODE: u32 = 0o700;
const GROUP_AND_OTHER_BITS: u32 = 0o077;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NotADirectory,
    OwnedBy(u32),
    OpenToOthers(u32),
}

#[derive(Debug)]
pub enum DirError {
    Create(PathBuf, io::Error),
    Inspect(PathBuf, io::Error),
    Refused(PathBuf, Refusal),
}

impl fmt::Display for DirError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create(path, error) => {
                write!(formatter, "cannot create {}: {error}", path.display())
            }
            Self::Inspect(path, error) => {
                write!(formatter, "cannot inspect {}: {error}", path.display())
            }
            Self::Refused(path, Refusal::NotADirectory) => {
                write!(
                    formatter,
                    "{} is not a real directory (a symlink or a file)",
                    path.display()
                )
            }
            Self::Refused(path, Refusal::OwnedBy(uid)) => {
                write!(
                    formatter,
                    "{} is owned by uid {uid}, not the current user",
                    path.display()
                )
            }
            Self::Refused(path, Refusal::OpenToOthers(mode)) => write!(
                formatter,
                "{} has mode {mode:o}; group and other bits must be clear",
                path.display()
            ),
        }
    }
}

/// The verdict on an existing path, from its own metadata, never a symlink's target.
pub const fn judge(is_dir: bool, owner: u32, mode: u32, current_uid: u32) -> Result<(), Refusal> {
    if !is_dir {
        return Err(Refusal::NotADirectory);
    }
    if owner != current_uid {
        return Err(Refusal::OwnedBy(owner));
    }
    if mode & GROUP_AND_OTHER_BITS != 0 {
        return Err(Refusal::OpenToOthers(mode & 0o777));
    }
    Ok(())
}

/// Creates each missing directory alone with mode 0700, parents first, then judges each.
pub fn ensure(dirs: &[PathBuf]) -> Result<(), DirError> {
    let current_uid = Uid::current().as_raw();
    for dir in dirs {
        ensure_one(dir, current_uid)?;
    }
    Ok(())
}

fn ensure_one(dir: &Path, current_uid: u32) -> Result<(), DirError> {
    match fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            DirBuilder::new()
                .mode(PRIVATE_DIR_MODE)
                .create(dir)
                .map_err(|error| DirError::Create(dir.to_path_buf(), error))?;
        }
        Err(error) => return Err(DirError::Inspect(dir.to_path_buf(), error)),
    }
    let metadata =
        fs::symlink_metadata(dir).map_err(|error| DirError::Inspect(dir.to_path_buf(), error))?;
    judge(
        metadata.file_type().is_dir(),
        metadata.uid(),
        metadata.mode(),
        current_uid,
    )
    .map_err(|refusal| DirError::Refused(dir.to_path_buf(), refusal))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: u32 = 501;

    #[test]
    fn accepts_a_private_directory() {
        assert_eq!(judge(true, ME, 0o40700, ME), Ok(()));
    }

    #[test]
    fn refuses_a_symlink_or_file() {
        assert_eq!(judge(false, ME, 0o120_700, ME), Err(Refusal::NotADirectory));
    }

    #[test]
    fn refuses_another_owner() {
        assert_eq!(judge(true, 0, 0o40700, ME), Err(Refusal::OwnedBy(0)));
    }

    fn scratch(name: &str) -> PathBuf {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("private-dir-{name}-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn creates_a_missing_directory_private() {
        let base = scratch("create");
        let dir = base.join("core");
        let result = ensure(std::slice::from_ref(&dir));
        let mode = fs::symlink_metadata(&dir).unwrap().mode() & 0o777;
        fs::remove_dir_all(&base).unwrap();
        assert!(result.is_ok());
        assert_eq!(mode, PRIVATE_DIR_MODE);
    }

    #[test]
    fn refuses_a_planted_symlink() {
        let base = scratch("symlink");
        let target = base.join("elsewhere");
        fs::create_dir(&target).unwrap();
        let link = base.join("core");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let result = ensure(&[link]);
        fs::remove_dir_all(&base).unwrap();
        assert!(matches!(
            result,
            Err(DirError::Refused(_, Refusal::NotADirectory))
        ));
    }

    #[test]
    fn refuses_group_or_other_bits() {
        assert_eq!(
            judge(true, ME, 0o40750, ME),
            Err(Refusal::OpenToOthers(0o750))
        );
        assert_eq!(
            judge(true, ME, 0o41777, ME),
            Err(Refusal::OpenToOthers(0o777))
        );
    }
}

//! Creates the core's directories and refuses any that another user could have planted or
//! can reach.

use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nix::unistd::Uid;

pub const PRIVATE_DIR_MODE: u32 = 0o700;
pub const PRIVATE_FILE_MODE: u32 = 0o600;
const GROUP_AND_OTHER_BITS: u32 = 0o077;
const GROUP_AND_OTHER_WRITE_BITS: u32 = 0o022;

/// How strict the mode check is; ownership and real-directory checks always apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Private,
    /// For a directory macOS creates 0755 and other programs read, such as
    /// `~/Library/LaunchAgents`: readable is fine, writable by others is not.
    OwnedNotWritableByOthers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NotADirectory,
    NotARegularFile,
    OwnedBy(u32),
    OpenToOthers(u32),
    TooLarge(usize),
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
            Self::Refused(path, Refusal::NotARegularFile) => {
                write!(
                    formatter,
                    "{} is not a regular file (a symlink or a directory)",
                    path.display()
                )
            }
            Self::Refused(path, Refusal::TooLarge(length)) => {
                write!(formatter, "{} is {length} bytes; too large", path.display())
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
pub const fn judge(
    policy: Policy,
    is_dir: bool,
    owner: u32,
    mode: u32,
    current_uid: u32,
) -> Result<(), Refusal> {
    if !is_dir {
        return Err(Refusal::NotADirectory);
    }
    if owner != current_uid {
        return Err(Refusal::OwnedBy(owner));
    }
    let forbidden = match policy {
        Policy::Private => GROUP_AND_OTHER_BITS,
        Policy::OwnedNotWritableByOthers => GROUP_AND_OTHER_WRITE_BITS,
    };
    if mode & forbidden != 0 {
        return Err(Refusal::OpenToOthers(mode & 0o777));
    }
    Ok(())
}

/// Creates each missing directory alone with mode 0700, parents first, then judges each.
pub fn ensure(dirs: &[PathBuf]) -> Result<(), DirError> {
    let current_uid = Uid::current().as_raw();
    for dir in dirs {
        ensure_one(dir, current_uid, Policy::Private)?;
    }
    Ok(())
}

/// Creates the directory 0700 if missing; an existing one must be the user's own and not
/// writable by others.
pub fn ensure_owned(dir: &Path) -> Result<(), DirError> {
    ensure_one(
        dir,
        Uid::current().as_raw(),
        Policy::OwnedNotWritableByOthers,
    )
}

fn ensure_one(dir: &Path, current_uid: u32, policy: Policy) -> Result<(), DirError> {
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
        policy,
        metadata.file_type().is_dir(),
        metadata.uid(),
        metadata.mode(),
        current_uid,
    )
    .map_err(|refusal| DirError::Refused(dir.to_path_buf(), refusal))
}

/// Creates the file 0600 with the given contents unless it exists; never follows a symlink.
pub fn create_private_file(path: &Path, contents: &[u8]) -> Result<bool, DirError> {
    let create = |error| DirError::Create(path.to_path_buf(), error);
    if fs::symlink_metadata(path).is_ok() {
        return Ok(false);
    }
    let staging = staging_path(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&staging)
        .map_err(create)?;
    let written = file.write_all(contents).and_then(|()| file.sync_all());
    drop(file);
    // A hard link never replaces an existing name, so a concurrent writer keeps its file.
    let linked = written.and_then(|()| fs::hard_link(&staging, path));
    let removed = fs::remove_file(&staging);
    match linked {
        Ok(()) => removed.map(|()| true).map_err(create),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(create(error)),
    }
}

/// A sibling name only this process uses: `.<name>.<pid>.staging`.
fn staging_path(path: &Path) -> Result<PathBuf, DirError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            DirError::Create(
                path.to_path_buf(),
                io::Error::new(io::ErrorKind::InvalidInput, "no file name"),
            )
        })?;
    Ok(path.with_file_name(format!(".{name}.{}.staging", std::process::id())))
}

/// Reads a regular file the current user owns with no group or other bits, up to `max` bytes.
pub fn read_private_file(path: &Path, max: usize) -> Result<Vec<u8>, DirError> {
    let inspect = |error| DirError::Inspect(path.to_path_buf(), error);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .map_err(inspect)?;
    let metadata = file.metadata().map_err(inspect)?;
    let refuse = |refusal| DirError::Refused(path.to_path_buf(), refusal);
    if !metadata.file_type().is_file() {
        return Err(refuse(Refusal::NotARegularFile));
    }
    if metadata.uid() != Uid::current().as_raw() {
        return Err(refuse(Refusal::OwnedBy(metadata.uid())));
    }
    if metadata.mode() & GROUP_AND_OTHER_BITS != 0 {
        return Err(refuse(Refusal::OpenToOthers(metadata.mode() & 0o777)));
    }
    let limit = u64::try_from(max).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(inspect)?;
    if bytes.len() > max {
        return Err(refuse(Refusal::TooLarge(bytes.len())));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: u32 = 501;

    #[test]
    fn accepts_a_private_directory() {
        assert_eq!(judge(Policy::Private, true, ME, 0o40700, ME), Ok(()));
    }

    #[test]
    fn refuses_a_symlink_or_file() {
        assert_eq!(
            judge(Policy::Private, false, ME, 0o120_700, ME),
            Err(Refusal::NotADirectory)
        );
    }

    #[test]
    fn refuses_another_owner() {
        assert_eq!(
            judge(Policy::Private, true, 0, 0o40700, ME),
            Err(Refusal::OwnedBy(0))
        );
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
    fn accepts_a_readable_launch_agents_directory() {
        let policy = Policy::OwnedNotWritableByOthers;
        assert_eq!(judge(policy, true, ME, 0o40755, ME), Ok(()));
        assert_eq!(
            judge(policy, true, ME, 0o40775, ME),
            Err(Refusal::OpenToOthers(0o775))
        );
        assert_eq!(
            judge(policy, true, 0, 0o40755, ME),
            Err(Refusal::OwnedBy(0))
        );
        assert_eq!(
            judge(policy, false, ME, 0o40755, ME),
            Err(Refusal::NotADirectory)
        );
    }

    #[test]
    fn refuses_group_or_other_bits() {
        assert_eq!(
            judge(Policy::Private, true, ME, 0o40750, ME),
            Err(Refusal::OpenToOthers(0o750))
        );
        assert_eq!(
            judge(Policy::Private, true, ME, 0o41777, ME),
            Err(Refusal::OpenToOthers(0o777))
        );
    }

    #[test]
    fn creates_a_private_file_once_and_reads_it_back() {
        let base = scratch("file");
        let path = base.join("operator.secret");
        let first = create_private_file(&path, b"abc");
        let second = create_private_file(&path, b"other");
        let mode = fs::symlink_metadata(&path).unwrap().mode() & 0o777;
        let read = read_private_file(&path, 16);
        let entries = fs::read_dir(&base).unwrap().count();
        fs::remove_dir_all(&base).unwrap();
        assert_eq!(entries, 1, "no staging file left beside the secret");
        assert!(matches!(first, Ok(true)));
        assert!(matches!(second, Ok(false)));
        assert_eq!(mode, PRIVATE_FILE_MODE);
        assert_eq!(read.unwrap(), b"abc");
    }

    #[test]
    fn refuses_a_file_open_to_others_or_over_its_maximum() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch("open-file");
        let path = base.join("operator.secret");
        create_private_file(&path, b"abcdef").unwrap();
        let too_large = read_private_file(&path, 3);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let open = read_private_file(&path, 16);
        fs::remove_dir_all(&base).unwrap();
        assert!(matches!(
            too_large,
            Err(DirError::Refused(_, Refusal::TooLarge(_)))
        ));
        assert!(matches!(
            open,
            Err(DirError::Refused(_, Refusal::OpenToOthers(0o644)))
        ));
    }

    #[test]
    fn refuses_a_symlinked_file() {
        let base = scratch("link-file");
        let target = base.join("target");
        create_private_file(&target, b"abc").unwrap();
        let link = base.join("operator.secret");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let read = read_private_file(&link, 16);
        let created = create_private_file(&link, b"x");
        fs::remove_dir_all(&base).unwrap();
        assert!(read.is_err());
        assert!(created.is_err() || matches!(created, Ok(false)));
    }
}

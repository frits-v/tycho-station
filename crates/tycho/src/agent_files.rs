//! File access in directories the agent user can write, where any path may hold a planted
//! symlink.
//!
//! Every open refuses to follow a symlink, a new file is created with `create_new`, a rename
//! goes only onto a path checked just before, and a read checks the file's type, owner and size
//! first.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use nix::fcntl::OFlag;
use nix::unistd::Uid;

pub const PRIVATE_FILE_MODE: u32 = 0o600;
pub const PRIVATE_DIR_MODE: u32 = 0o700;
const GROUP_AND_OTHER_BITS: u32 = 0o077;

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

fn refused(path: &Path, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{}: {reason}", path.display()),
    )
}

/// Opens a file that must not exist yet, mode 0600, never through a symlink.
pub fn create_new(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(OFlag::O_NOFOLLOW.bits())
        .open(path)
}

/// Opens for appending, creating it 0600 if missing, never through a symlink.
pub fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(OFlag::O_NOFOLLOW.bits())
        .open(path)
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| refused(path, "no parent directory"))?;
    File::open(parent)?.sync_all()
}

/// Writes a file that must not exist yet and syncs it and its directory.
pub fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = create_new(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    sync_parent(path)
}

/// Absent, or a regular file of the current user: the only targets a rename may replace.
pub fn check_replaceable(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(metadata) if !metadata.file_type().is_file() => Err(refused(path, "not a regular file")),
        Ok(metadata) if metadata.uid() != Uid::current().as_raw() => {
            Err(refused(path, "owned by another user"))
        }
        Ok(_) => Ok(()),
    }
}

/// Stages a new file beside the target, syncs it, renames it over the checked target and
/// syncs the directory, so a reader sees the old bytes or the new ones.
pub fn write_durable(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| refused(path, "no file name"))?;
    let count = STAGING_COUNTER.fetch_add(1, Ordering::SeqCst);
    let staging = path.with_file_name(format!(
        ".{file_name}.staging-{}-{count}",
        std::process::id()
    ));
    let mut file = create_new(&staging)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let renamed = written
        .and_then(|()| check_replaceable(path))
        .and_then(|()| fs::rename(&staging, path));
    if let Err(error) = renamed {
        drop(fs::remove_file(&staging));
        return Err(error);
    }
    sync_parent(path)
}

/// Creates the directory 0700 if missing; it must be a real directory of the current user
/// with no group or other bits.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(PRIVATE_DIR_MODE).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(refused(path, "not a real directory"));
    }
    if metadata.uid() != Uid::current().as_raw() {
        return Err(refused(path, "owned by another user"));
    }
    if metadata.mode() & GROUP_AND_OTHER_BITS != 0 {
        return Err(refused(path, "open to group or others"));
    }
    Ok(())
}

/// Reads a regular file of `owner` (any owner when `None`) of at most `max_bytes`; a missing
/// file is `None`, a symlink, another owner or a larger file an error.
pub fn read_checked(
    path: &Path,
    max_bytes: usize,
    owner: Option<u32>,
) -> io::Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() {
        return Err(refused(path, "not a regular file"));
    }
    if owner.is_some_and(|owner| owner != metadata.uid()) {
        return Err(refused(path, "not owned by the expected user"));
    }
    let limit = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    if metadata.len() > limit {
        return Err(too_large(path, max_bytes));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(OFlag::O_NOFOLLOW.bits())
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(too_large(path, max_bytes));
    }
    Ok(Some(bytes))
}

fn too_large(path: &Path, max_bytes: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{} exceeds {max_bytes} bytes", path.display()),
    )
}

/// The current user's uid, as the owner a launcher's own files must have.
#[must_use]
pub fn current_uid() -> u32 {
    Uid::current().as_raw()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    fn scratch(test: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tycho-agent-files-{test}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_planted_symlink_is_never_written_through() {
        let dir = scratch("symlink");
        let victim = dir.join("victim");
        fs::write(&victim, "untouched").unwrap();
        let planted = dir.join("planted");
        symlink(&victim, &planted).unwrap();
        assert!(write_new(&planted, b"x").is_err());
        assert!(open_append(&planted).is_err());
        assert!(write_durable(&planted, b"x").is_err());
        assert!(read_checked(&planted, 64, None).is_err());
        assert_eq!(fs::read_to_string(&victim).unwrap(), "untouched");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_pre_existing_file_is_refused_by_create_new() {
        let dir = scratch("existing");
        let path = dir.join("spool");
        fs::write(&path, "planted").unwrap();
        assert_eq!(
            write_new(&path, b"x").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "planted");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn durable_writes_replace_only_a_checked_target_and_leave_no_staging() {
        let dir = scratch("durable");
        let path = dir.join("lease");
        write_durable(&path, b"one").unwrap();
        write_durable(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        let not_a_file = dir.join("dir");
        fs::create_dir(&not_a_file).unwrap();
        assert!(write_durable(&not_a_file, b"x").is_err());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_check_type_owner_and_size() {
        let dir = scratch("read");
        let path = dir.join("file");
        assert_eq!(read_checked(&path, 8, None).unwrap(), None);
        fs::write(&path, "123456789").unwrap();
        assert!(read_checked(&path, 8, None).is_err());
        assert_eq!(
            read_checked(&path, 9, Some(current_uid()))
                .unwrap()
                .unwrap()
                .len(),
            9
        );
        assert!(read_checked(&path, 9, Some(current_uid().wrapping_add(1))).is_err());
        assert!(read_checked(&dir, 9, None).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_private_dir_must_be_real_owned_and_closed() {
        let dir = scratch("private");
        let private = dir.join("private");
        ensure_private_dir(&private).unwrap();
        ensure_private_dir(&private).unwrap();
        let open = dir.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, std::os::unix::fs::PermissionsExt::from_mode(0o770)).unwrap();
        assert!(ensure_private_dir(&open).is_err());
        let link = dir.join("link");
        symlink(&private, &link).unwrap();
        assert!(ensure_private_dir(&link).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}

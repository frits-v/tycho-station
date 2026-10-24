//! Directories created and removed under a root the agent user can write.
//!
//! Every level is opened relative to its parent's descriptor with `O_NOFOLLOW`, so a symlink
//! planted at any level is refused instead of followed, and swapping a checked directory for
//! a link afterwards changes nothing: the descriptor still names the directory that was checked.

use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use nix::NixPath;
use nix::dir::{Dir, Type};
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat, renameat};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat, mkdirat};
use nix::unistd::{UnlinkatFlags, fsync, unlinkat};

/// Names listed per pass over a directory; a pass removes what it listed, then lists again.
const SWEEP_BATCH: usize = 4096;

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeRefusal {
    Symlink,
    NotADirectory,
    NotARegularFile,
    OwnedBy(u32),
    OutsideRoot,
    TooDeep(usize),
    TooManyEntries(usize),
    NotAName,
    OtherFilesystem,
}

impl fmt::Display for TreeRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Symlink => formatter.write_str("is a symlink"),
            Self::NotADirectory => formatter.write_str("is not a directory"),
            Self::NotARegularFile => formatter.write_str("is not a regular file"),
            Self::OwnedBy(uid) => write!(formatter, "is owned by uid {uid}"),
            Self::OutsideRoot => formatter.write_str("is not below the root"),
            Self::TooDeep(depth) => write!(formatter, "is nested deeper than {depth} levels"),
            Self::TooManyEntries(entries) => write!(formatter, "holds more than {entries} entries"),
            Self::NotAName => formatter.write_str("is not a single plain name"),
            Self::OtherFilesystem => formatter.write_str(
                "is on another filesystem than the core home: the agent worktree root must share it",
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
    Refused(PathBuf, TreeRefusal),
    Io(PathBuf, String),
}

impl fmt::Display for TreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(path, refusal) => write!(formatter, "{} {refusal}", path.display()),
            Self::Io(path, error) => write!(formatter, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for TreeError {}

/// The uids a directory under the root may belong to: the core's, and the agent user's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owners {
    pub core: u32,
    pub agent: u32,
}

impl Owners {
    const fn admit(self, uid: u32) -> bool {
        uid == self.core || uid == self.agent
    }
}

/// How far a removal may go: levels below the removed directory, and entries removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub depth: usize,
    pub entries: usize,
}

fn refused(path: &Path, refusal: TreeRefusal) -> TreeError {
    TreeError::Refused(path.to_path_buf(), refusal)
}

fn failed(path: &Path, error: impl fmt::Display) -> TreeError {
    TreeError::Io(path.to_path_buf(), error.to_string())
}

fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

/// The mode `create_dir` uses; the umask narrows it.
fn directory_mode() -> Mode {
    Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO
}

fn kind(stat: &FileStat) -> SFlag {
    SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT
}

/// The plain names leading from `root` to `path`; any other component is outside the root.
fn relative_names<'a>(root: &Path, path: &'a Path) -> Result<Vec<&'a OsStr>, TreeError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| refused(path, TreeRefusal::OutsideRoot))?;
    let mut names = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => names.push(name),
            _ => return Err(refused(path, TreeRefusal::OutsideRoot)),
        }
    }
    Ok(names)
}

/// Exactly one plain name: no separator, no `.` or `..`, not empty.
fn check_name(name: &OsStr, path: &Path) -> Result<(), TreeError> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(only)), None) if only == name => Ok(()),
        _ => Err(refused(path, TreeRefusal::NotAName)),
    }
}

fn check_owner(path: &Path, directory: &OwnedFd, owners: Owners) -> Result<(), TreeError> {
    let stat = fstat(directory).map_err(|errno| failed(path, errno))?;
    if owners.admit(stat.st_uid) {
        Ok(())
    } else {
        Err(refused(path, TreeRefusal::OwnedBy(stat.st_uid)))
    }
}

/// Opens the root, creating it if missing; its ancestors are the core's, outside the agent's reach.
#[expect(
    clippy::disallowed_methods,
    reason = "the root's ancestors belong to the core and are outside the agent's reach"
)]
fn open_root(root: &Path, owners: Owners) -> Result<OwnedFd, TreeError> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(root).map_err(|error| failed(root, error))?;
        }
        Err(error) => return Err(failed(root, error)),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(refused(root, TreeRefusal::Symlink));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(refused(root, TreeRefusal::NotADirectory));
        }
        Ok(_) => {}
    }
    let directory = open(root, directory_flags(), Mode::empty()).map_err(|errno| match errno {
        Errno::ELOOP => refused(root, TreeRefusal::Symlink),
        Errno::ENOTDIR => refused(root, TreeRefusal::NotADirectory),
        other => failed(root, other),
    })?;
    check_owner(root, &directory, owners)?;
    Ok(directory)
}

/// Why `name` in `parent` could not be opened as a directory, from its own metadata.
fn classify<N: ?Sized + NixPath>(
    parent: BorrowedFd<'_>,
    name: &N,
    path: &Path,
    errno: Errno,
) -> TreeError {
    match fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) if kind(&stat) == SFlag::S_IFLNK => refused(path, TreeRefusal::Symlink),
        Ok(stat) if kind(&stat) != SFlag::S_IFDIR => refused(path, TreeRefusal::NotADirectory),
        Ok(_) | Err(_) => failed(path, errno),
    }
}

/// Opens `name` in `parent` as a real directory of one of `owners`, never through a symlink.
fn open_child<N: ?Sized + NixPath>(
    parent: BorrowedFd<'_>,
    name: &N,
    path: &Path,
    owners: Owners,
) -> Result<OwnedFd, TreeError> {
    let child = openat(parent, name, directory_flags(), Mode::empty())
        .map_err(|errno| classify(parent, name, path, errno))?;
    check_owner(path, &child, owners)?;
    Ok(child)
}

/// Opens every level from `root` down to `path`, creating missing ones one at a time.
pub fn ensure_dirs(root: &Path, path: &Path, owners: Owners) -> Result<OwnedFd, TreeError> {
    walk(root, path, owners, true)
}

/// Opens every level from `root` down to `path`, all of which must exist.
pub fn open_dirs(root: &Path, path: &Path, owners: Owners) -> Result<OwnedFd, TreeError> {
    walk(root, path, owners, false)
}

fn walk(root: &Path, path: &Path, owners: Owners, create: bool) -> Result<OwnedFd, TreeError> {
    let names = relative_names(root, path)?;
    let mut current = open_root(root, owners)?;
    let mut reached = root.to_path_buf();
    for name in names {
        reached.push(name);
        if create {
            match mkdirat(current.as_fd(), name, directory_mode()) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(errno) => return Err(failed(&reached, errno)),
            }
        }
        current = open_child(current.as_fd(), name, &reached, owners)?;
    }
    Ok(current)
}

/// Replaces `name` in `directory` with a 0600 file of `bytes`, never onto a link.
pub fn replace_file(
    directory: &OwnedFd,
    directory_path: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), TreeError> {
    let path = directory_path.join(name);
    check_name(OsStr::new(name), &path)?;
    let count = STAGING_COUNTER.fetch_add(1, Ordering::SeqCst);
    let staging = format!(".{name}.staging-{}-{count}", std::process::id());
    let flags =
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let created = openat(
        directory,
        staging.as_str(),
        flags,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|errno| failed(&directory_path.join(&staging), errno))?;
    let mut file = File::from(created);
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| failed(&path, error));
    drop(file);
    let renamed = written
        .and_then(|()| check_replaceable(directory, name, &path))
        .and_then(|()| {
            renameat(directory, staging.as_str(), directory, name)
                .map_err(|errno| failed(&path, errno))
        });
    if let Err(error) = renamed {
        // The rename's error is the one reported; a staging name left behind is harmless.
        let _staging_left =
            unlinkat(directory, staging.as_str(), UnlinkatFlags::NoRemoveDir).is_err();
        return Err(error);
    }
    fsync(directory).map_err(|errno| failed(directory_path, errno))
}

/// Absent or a regular file: the only targets a rename may replace.
fn check_replaceable(directory: &OwnedFd, name: &str, path: &Path) -> Result<(), TreeError> {
    match fstatat(directory, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Err(Errno::ENOENT) => Ok(()),
        Err(errno) => Err(failed(path, errno)),
        Ok(stat) if kind(&stat) == SFlag::S_IFLNK => Err(refused(path, TreeRefusal::Symlink)),
        Ok(stat) if kind(&stat) != SFlag::S_IFREG => {
            Err(refused(path, TreeRefusal::NotARegularFile))
        }
        Ok(_) => Ok(()),
    }
}

/// Removes the directory `name` in `parent` and everything in it; absent is fine.
pub fn remove_dir(
    parent: BorrowedFd<'_>,
    parent_path: &Path,
    name: &OsStr,
    owners: Owners,
    bounds: Bounds,
) -> Result<(), TreeError> {
    let path = parent_path.join(name);
    check_name(name, &path)?;
    match fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Err(Errno::ENOENT) => return Ok(()),
        Err(errno) => return Err(failed(&path, errno)),
        Ok(stat) if kind(&stat) == SFlag::S_IFLNK => {
            return Err(refused(&path, TreeRefusal::Symlink));
        }
        Ok(stat) if kind(&stat) != SFlag::S_IFDIR => {
            return Err(refused(&path, TreeRefusal::NotADirectory));
        }
        Ok(_) => {}
    }
    let top = open_child(parent, name, &path, owners)?;
    empty_tree(top, &path, owners, bounds)?;
    unlinkat(parent, name, UnlinkatFlags::RemoveDir).map_err(|errno| failed(&path, errno))
}

/// Renames the directory `from_name` in `from` to `to_name` in `to`, both by descriptor.
pub fn move_dir(
    from: BorrowedFd<'_>,
    from_name: &OsStr,
    to: BorrowedFd<'_>,
    to_path: &Path,
    to_name: &OsStr,
) -> Result<(), TreeError> {
    let path = to_path.join(to_name);
    check_name(from_name, Path::new(from_name))?;
    check_name(to_name, &path)?;
    match renameat(from, from_name, to, to_name) {
        Ok(()) => fsync(to).map_err(|errno| failed(to_path, errno)),
        Err(Errno::EXDEV) => Err(refused(&path, TreeRefusal::OtherFilesystem)),
        Err(errno) => Err(failed(&path, errno)),
    }
}

struct Frame {
    directory: OwnedFd,
    name: CString,
    path: PathBuf,
}

enum Step {
    Descend(CString),
    Emptied,
    Swept,
}

/// Empties `top` depth first with an explicit stack; links and files are unlinked, never followed.
fn empty_tree(top: OwnedFd, path: &Path, owners: Owners, bounds: Bounds) -> Result<(), TreeError> {
    let mut stack = vec![Frame {
        directory: top,
        name: CString::default(),
        path: path.to_path_buf(),
    }];
    let mut removed: usize = 0;
    // Each step descends, removes at least one entry, or leaves an emptied directory.
    let steps = bounds.entries.saturating_mul(3).saturating_add(2);
    for _ in 0..steps {
        let Some(frame) = stack.last() else {
            return Ok(());
        };
        match sweep(frame, &mut removed, bounds)? {
            Step::Swept => {}
            Step::Descend(name) => {
                if stack.len() > bounds.depth {
                    return Err(refused(&frame.path, TreeRefusal::TooDeep(bounds.depth)));
                }
                let child_path = frame.path.join(OsStr::from_bytes(name.as_bytes()));
                let directory = open_child(
                    frame.directory.as_fd(),
                    name.as_c_str(),
                    &child_path,
                    owners,
                )?;
                stack.push(Frame {
                    directory,
                    name,
                    path: child_path,
                });
            }
            Step::Emptied => pop_emptied(&mut stack, &mut removed, bounds)?,
        }
    }
    Err(refused(path, TreeRefusal::TooManyEntries(bounds.entries)))
}

/// Removes the emptied directory on top of the stack from its parent; the top frame stays.
fn pop_emptied(
    stack: &mut Vec<Frame>,
    removed: &mut usize,
    bounds: Bounds,
) -> Result<(), TreeError> {
    let Some(emptied) = stack.pop() else {
        return Ok(());
    };
    let Some(parent) = stack.last() else {
        return Ok(());
    };
    count(removed, bounds, &emptied.path)?;
    unlinkat(
        parent.directory.as_fd(),
        emptied.name.as_c_str(),
        UnlinkatFlags::RemoveDir,
    )
    .map_err(|errno| failed(&emptied.path, errno))
}

fn count(removed: &mut usize, bounds: Bounds, path: &Path) -> Result<(), TreeError> {
    *removed = removed.saturating_add(1);
    if *removed > bounds.entries {
        return Err(refused(path, TreeRefusal::TooManyEntries(bounds.entries)));
    }
    Ok(())
}

/// One pass over a directory: unlinks what is not a directory, or names a directory to enter.
fn sweep(frame: &Frame, removed: &mut usize, bounds: Bounds) -> Result<Step, TreeError> {
    let names = list(frame)?;
    if names.is_empty() {
        return Ok(Step::Emptied);
    }
    for (name, entry_type) in names {
        let entry_path = frame.path.join(OsStr::from_bytes(name.as_bytes()));
        let is_directory = match entry_type {
            Some(entry_type) => entry_type == Type::Directory,
            None => fstatat(
                &frame.directory,
                name.as_c_str(),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map(|stat| kind(&stat) == SFlag::S_IFDIR)
            .map_err(|errno| failed(&entry_path, errno))?,
        };
        if is_directory {
            return Ok(Step::Descend(name));
        }
        count(removed, bounds, &entry_path)?;
        unlinkat(
            &frame.directory,
            name.as_c_str(),
            UnlinkatFlags::NoRemoveDir,
        )
        .map_err(|errno| failed(&entry_path, errno))?;
    }
    Ok(Step::Swept)
}

/// Up to `SWEEP_BATCH` entries of the frame's directory, from a fresh descriptor of it.
fn list(frame: &Frame) -> Result<Vec<(CString, Option<Type>)>, TreeError> {
    let fail = |errno| failed(&frame.path, errno);
    let mut directory = Dir::openat(
        &frame.directory,
        c".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(fail)?;
    let mut names = Vec::new();
    for entry in directory.iter() {
        let entry = entry.map_err(fail)?;
        let name: &CStr = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        names.push((name.to_owned(), entry.file_type()));
        if names.len() >= SWEEP_BATCH {
            break;
        }
    }
    Ok(names)
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use crate::agent_files::current_uid;
    use std::os::unix::fs::symlink;

    const WIDE: Bounds = Bounds {
        depth: 8,
        entries: 64,
    };

    fn scratch(test: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tycho-agent-tree-{test}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        fs::create_dir_all(&dir).unwrap();
        fs::canonicalize(&dir).unwrap()
    }

    fn me() -> Owners {
        Owners {
            core: current_uid(),
            agent: current_uid(),
        }
    }

    fn remove(root: &Path, name: &str, bounds: Bounds) -> Result<(), TreeError> {
        let parent = ensure_dirs(root, root, me()).unwrap();
        remove_dir(parent.as_fd(), root, OsStr::new(name), me(), bounds)
    }

    #[test]
    fn a_tree_is_removed_and_an_absent_one_is_fine() {
        let root = scratch("ordinary");
        let deepest = root.join("a1/x/y");
        drop(ensure_dirs(&root, &deepest, me()).unwrap());
        fs::write(deepest.join("file"), "x").unwrap();
        fs::write(root.join("a1/top"), "x").unwrap();
        assert_eq!(remove(&root, "a1", WIDE), Ok(()));
        assert!(!root.join("a1").exists());
        assert_eq!(remove(&root, "a1", WIDE), Ok(()));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_symlink_inside_the_tree_is_unlinked_not_followed() {
        let root = scratch("inner-link");
        let victim = root.join("victim");
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("keep"), "untouched").unwrap();
        fs::create_dir_all(root.join("a1/sub")).unwrap();
        symlink(&victim, root.join("a1/escape")).unwrap();
        symlink(victim.join("keep"), root.join("a1/sub/file-link")).unwrap();
        assert_eq!(remove(&root, "a1", WIDE), Ok(()));
        assert!(!root.join("a1").exists());
        assert_eq!(
            fs::read_to_string(victim.join("keep")).unwrap(),
            "untouched"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_symlinked_directory_is_refused_and_its_target_survives() {
        let root = scratch("top-link");
        let victim = root.join("victim");
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("keep"), "untouched").unwrap();
        symlink(&victim, root.join("a1")).unwrap();
        assert_eq!(
            remove(&root, "a1", WIDE),
            Err(TreeError::Refused(root.join("a1"), TreeRefusal::Symlink))
        );
        assert_eq!(
            fs::read_to_string(victim.join("keep")).unwrap(),
            "untouched"
        );
        fs::write(root.join("file"), "x").unwrap();
        assert_eq!(
            remove(&root, "file", WIDE),
            Err(TreeError::Refused(
                root.join("file"),
                TreeRefusal::NotADirectory
            ))
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_symlinked_level_is_refused_on_create() {
        let root = scratch("level-link");
        let elsewhere = root.join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let tree = root.join("tree");
        fs::create_dir(&tree).unwrap();
        symlink(&elsewhere, tree.join("cf7a")).unwrap();
        assert_eq!(
            ensure_dirs(&tree, &tree.join("cf7a/wu01"), me()).err(),
            Some(TreeError::Refused(tree.join("cf7a"), TreeRefusal::Symlink))
        );
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
        let linked_root = root.join("linked-root");
        symlink(&tree, &linked_root).unwrap();
        assert_eq!(
            ensure_dirs(&linked_root, &linked_root.join("x"), me()).err(),
            Some(TreeError::Refused(linked_root, TreeRefusal::Symlink))
        );
        assert_eq!(
            ensure_dirs(&tree, &root.join("other"), me()).err(),
            Some(TreeError::Refused(
                root.join("other"),
                TreeRefusal::OutsideRoot
            ))
        );
        assert_eq!(
            ensure_dirs(&tree, &tree.join("a/../b"), me()).err(),
            Some(TreeError::Refused(
                tree.join("a/../b"),
                TreeRefusal::OutsideRoot
            ))
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_directory_of_another_owner_is_refused() {
        let root = scratch("owner");
        let strangers = Owners {
            core: current_uid().wrapping_add(1),
            agent: current_uid().wrapping_add(2),
        };
        assert_eq!(
            ensure_dirs(&root, &root.join("a1"), strangers).err(),
            Some(TreeError::Refused(
                root.clone(),
                TreeRefusal::OwnedBy(current_uid())
            ))
        );
        let agent_only = Owners {
            core: current_uid().wrapping_add(1),
            agent: current_uid(),
        };
        assert!(ensure_dirs(&root, &root.join("a1"), agent_only).is_ok());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_file_is_replaced_only_through_its_directory_and_never_onto_a_link() {
        let root = scratch("replace");
        let briefs = root.join("briefs");
        let directory = ensure_dirs(&root, &briefs, me()).unwrap();
        replace_file(&directory, &briefs, "one.md", b"first").unwrap();
        replace_file(&directory, &briefs, "one.md", b"second").unwrap();
        assert_eq!(fs::read_to_string(briefs.join("one.md")).unwrap(), "second");
        let victim = root.join("victim");
        fs::write(&victim, "untouched").unwrap();
        symlink(&victim, briefs.join("two.md")).unwrap();
        assert_eq!(
            replace_file(&directory, &briefs, "two.md", b"x"),
            Err(TreeError::Refused(
                briefs.join("two.md"),
                TreeRefusal::Symlink
            ))
        );
        fs::create_dir(briefs.join("three.md")).unwrap();
        assert_eq!(
            replace_file(&directory, &briefs, "three.md", b"x"),
            Err(TreeError::Refused(
                briefs.join("three.md"),
                TreeRefusal::NotARegularFile
            ))
        );
        assert_eq!(fs::read_to_string(&victim).unwrap(), "untouched");
        assert_eq!(
            fs::read_dir(&briefs).unwrap().count(),
            3,
            "no staging file left"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_name_that_is_not_one_plain_component_is_refused() {
        let root = scratch("names");
        let directory = ensure_dirs(&root, &root, me()).unwrap();
        fs::create_dir(root.join("kept")).unwrap();
        for name in ["", ".", "..", "../kept", "kept/inner", "a/", "/kept"] {
            assert_eq!(
                replace_file(&directory, &root, name, b"x"),
                Err(TreeError::Refused(root.join(name), TreeRefusal::NotAName)),
                "{name:?}"
            );
            assert_eq!(
                remove_dir(directory.as_fd(), &root, OsStr::new(name), me(), WIDE),
                Err(TreeError::Refused(root.join(name), TreeRefusal::NotAName)),
                "{name:?}"
            );
            assert_eq!(
                move_dir(
                    directory.as_fd(),
                    OsStr::new("kept"),
                    directory.as_fd(),
                    &root,
                    OsStr::new(name)
                ),
                Err(TreeError::Refused(root.join(name), TreeRefusal::NotAName)),
                "{name:?}"
            );
        }
        assert!(root.join("kept").is_dir());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        assert_eq!(
            move_dir(
                directory.as_fd(),
                OsStr::new("kept"),
                directory.as_fd(),
                &root,
                OsStr::new("moved")
            ),
            Ok(())
        );
        assert!(root.join("moved").is_dir());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn removal_stops_at_its_depth_and_entry_bounds() {
        let root = scratch("bounds");
        fs::create_dir_all(root.join("deep/x/y/z")).unwrap();
        assert_eq!(
            remove(
                &root,
                "deep",
                Bounds {
                    depth: 2,
                    entries: 64
                }
            ),
            Err(TreeError::Refused(
                root.join("deep/x/y"),
                TreeRefusal::TooDeep(2)
            ))
        );
        assert_eq!(
            remove(
                &root,
                "deep",
                Bounds {
                    depth: 3,
                    entries: 64
                }
            ),
            Ok(())
        );
        fs::create_dir(root.join("wide")).unwrap();
        for index in 0..4 {
            fs::write(root.join(format!("wide/f{index}")), "x").unwrap();
        }
        assert!(matches!(
            remove(
                &root,
                "wide",
                Bounds {
                    depth: 1,
                    entries: 3
                }
            ),
            Err(TreeError::Refused(_, TreeRefusal::TooManyEntries(3)))
        ));
        assert_eq!(
            remove(
                &root,
                "wide",
                Bounds {
                    depth: 1,
                    entries: 1
                }
            ),
            Ok(())
        );
        fs::remove_dir_all(&root).unwrap();
    }
}

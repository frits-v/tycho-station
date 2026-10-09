//! The instruction relay, for an inbox socket that admits only the vendor's own user.
//!
//! The core leaves an instruction in a directory it owns and the agent user's group can read;
//! the session's launcher, running as the agent user, posts it to the socket. The directory is
//! sticky and group-writable, so the launcher can add its outcome markers (`<name>.posted`,
//! `<name>.failed`) but can neither replace nor remove the core's files. Each file names its
//! session and key, so a file linked into another session's directory or under another name is
//! refused on its content.

use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::OFlag;
use nix::unistd::Uid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tycho_types::envelope::ShortText;
use tycho_types::session::SessionName;

use crate::agent_files::{current_uid, write_new, write_new_mode};
use crate::config::AgentDirs;
use crate::vendors::claude_control::post;
use crate::vendors::control::{bounded, Delivery};

pub const RELAY_DIR: &str = "instructions";
/// Group-writable for the launcher's markers, sticky so it cannot touch the core's files.
pub const RELAY_DIR_MODE: u32 = 0o1770;
/// Readable by the agent user's group, writable by the core alone.
pub const RELAY_FILE_MODE: u32 = 0o640;
pub const RELAY_FILE_MAX_BYTES: usize = 4096;
/// Unposted instructions one directory may hold; markers do not count.
pub const RELAY_PENDING_MAX: usize = 256;
/// Entries one listing reads, markers included; a directory over it is an error.
pub const RELAY_LISTING_MAX: usize = 8192;
/// Instructions one poll posts; the rest wait for the next poll a second later.
pub const RELAY_POSTS_PER_POLL_MAX: usize = 8;
pub const POSTED_SUFFIX: &str = "posted";
pub const FAILED_SUFFIX: &str = "failed";
const GROUP_AND_OTHER_WRITE_BITS: u32 = 0o022;
const PERMISSION_BITS: u32 = 0o7777;
const STICKY_BIT: u32 = 0o1000;
const KEY_DIGEST_HEX: usize = 16;

/// The session's relay directory under the agent directory.
#[must_use]
pub fn relay_dir(dirs: &AgentDirs, session: &SessionName) -> PathBuf {
    dirs.socket_dir.join(RELAY_DIR).join(session.to_string())
}

/// The file name for an idempotency key: the same key always names the same file.
#[must_use]
pub fn relay_file_name(key: &ShortText) -> String {
    let digest = Sha256::digest(key.as_str().as_bytes());
    let hex: String = digest
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .take(KEY_DIGEST_HEX)
        .map(|nibble| char::from_digit(u32::from(nibble), 16).unwrap_or('0'))
        .collect();
    format!("{hex}.json")
}

/// One relay file: the session and key it was written for, and the line the vendor reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayEnvelope {
    session: String,
    key: String,
    message: serde_json::Value,
}

/// The file line for an instruction line: the envelope with the session and key.
fn envelope_line(session: &SessionName, key: &ShortText, line: &str) -> Result<String, String> {
    let message: serde_json::Value =
        serde_json::from_str(line.trim_end()).map_err(|error| bounded(&error.to_string()))?;
    let envelope = RelayEnvelope {
        session: session.to_string(),
        key: key.to_string(),
        message,
    };
    let text = serde_json::to_string(&envelope).map_err(|error| error.to_string())?;
    Ok(format!("{text}\n"))
}

fn ensure_relay_dir(dir: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(RELAY_DIR_MODE).create(dir) {
        Ok(()) => fs::set_permissions(dir, fs::Permissions::from_mode(RELAY_DIR_MODE))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(dir)?;
    if !metadata.file_type().is_dir() || metadata.uid() != Uid::current().as_raw() {
        return Err(io::Error::other(format!(
            "{} is not a directory of this user",
            dir.display()
        )));
    }
    Ok(())
}

/// The relay file's own checks, on the metadata of the opened descriptor.
fn check_relay_file(path: &Path, metadata: &fs::Metadata, owner: u32) -> Result<(), String> {
    let limit = u64::try_from(RELAY_FILE_MAX_BYTES).unwrap_or(u64::MAX);
    let mode = metadata.mode() & PERMISSION_BITS;
    let refusal = if !metadata.file_type().is_file() {
        "not a regular file".to_string()
    } else if metadata.uid() != owner {
        format!("owned by uid {}, expected uid {owner}", metadata.uid())
    } else if mode & !RELAY_FILE_MODE != 0 {
        format!("mode {mode:o} is wider than {RELAY_FILE_MODE:o}")
    } else if metadata.nlink() != 1 {
        // A second link is a copy under another name or session, which would replay it.
        format!("{} links, expected 1", metadata.nlink())
    } else if metadata.len() > limit {
        format!("exceeds {RELAY_FILE_MAX_BYTES} bytes")
    } else {
        return Ok(());
    };
    Err(format!("{}: {refusal}", path.display()))
}

/// Opens without following a link, checks the descriptor, and reads the file within its bound.
fn read_relay_file(path: &Path, owner: u32) -> Result<Vec<u8>, String> {
    // O_NONBLOCK keeps a planted FIFO from blocking the open; the descriptor check refuses it.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(|error| format!("{}: cannot open: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    check_relay_file(path, &metadata, owner)?;
    let limit = u64::try_from(RELAY_FILE_MAX_BYTES).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if bytes.len() > RELAY_FILE_MAX_BYTES {
        return Err(format!(
            "{}: exceeds {RELAY_FILE_MAX_BYTES} bytes",
            path.display()
        ));
    }
    Ok(bytes)
}

/// Leaves one instruction for the launcher; an existing file for the key counts as relayed
/// only when it is the core's own single-linked file holding the same envelope.
pub fn write_instruction(
    dirs: &AgentDirs,
    session: &SessionName,
    key: &ShortText,
    line: &str,
) -> Result<String, String> {
    if line.len() > RELAY_FILE_MAX_BYTES {
        return Err(format!(
            "an instruction of {} bytes exceeds {RELAY_FILE_MAX_BYTES}",
            line.len()
        ));
    }
    let line = envelope_line(session, key, line)?;
    if line.len() > RELAY_FILE_MAX_BYTES {
        return Err(format!(
            "an instruction of {} bytes exceeds {RELAY_FILE_MAX_BYTES}",
            line.len()
        ));
    }
    let dir = relay_dir(dirs, session);
    for each in [dirs.socket_dir.join(RELAY_DIR), dir.clone()] {
        ensure_relay_dir(&each).map_err(|error| format!("{}: {error}", each.display()))?;
    }
    let name = relay_file_name(key);
    let path = dir.join(&name);
    match write_new_mode(&path, line.as_bytes(), RELAY_FILE_MODE) {
        Ok(()) => Ok(name),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing = read_relay_file(&path, current_uid())?;
            if existing != line.as_bytes() {
                return Err(format!(
                    "{}: holds another instruction for the key",
                    path.display()
                ));
            }
            Ok(name)
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// The directory must belong to the core and be sticky or closed to group writes.
pub fn check_relay_dir(dir: &Path, core_uid: u32) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let mode = metadata.mode();
    let open = mode & GROUP_AND_OTHER_WRITE_BITS != 0 && mode & STICKY_BIT == 0;
    if !metadata.file_type().is_dir() || metadata.uid() != core_uid || open {
        return Err(format!(
            "{} is not a directory of uid {core_uid} closed to other writers",
            dir.display()
        ));
    }
    Ok(())
}

fn marker(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

/// The directory's entry names within the listing bound; a missing directory has none.
fn list_names(dir: &Path) -> Result<BTreeSet<String>, String> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => return Err(format!("{}: {error}", dir.display())),
    };
    let mut names = BTreeSet::new();
    for (count, entry) in entries.enumerate() {
        if count >= RELAY_LISTING_MAX {
            return Err(format!(
                "{} holds more than {RELAY_LISTING_MAX} entries",
                dir.display()
            ));
        }
        let name = entry.map_err(|error| error.to_string())?.file_name();
        // The core names every file in ASCII; any other name is not one of its instructions.
        if let Some(name) = name.to_str() {
            names.insert(name.to_string());
        }
    }
    Ok(names)
}

fn is_instruction(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("json")
}

/// Instruction files without an outcome marker, oldest first; over the bound is an error.
pub fn pending(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let names = list_names(dir)?;
    let marked = |name: &str| {
        [POSTED_SUFFIX, FAILED_SUFFIX]
            .iter()
            .any(|suffix| names.contains(&format!("{name}.{suffix}")))
    };
    let mut files = Vec::new();
    for name in names
        .iter()
        .filter(|name| is_instruction(name) && !marked(name))
    {
        if files.len() >= RELAY_PENDING_MAX {
            return Err(format!(
                "{} holds more than {RELAY_PENDING_MAX} unposted instructions",
                dir.display()
            ));
        }
        let path = dir.join(name);
        let modified = fs::symlink_metadata(&path)
            .and_then(|metadata| metadata.modified())
            .map_err(|error| format!("{}: {error}", path.display()))?;
        files.push((modified, path));
    }
    files.sort();
    Ok(files.into_iter().map(|(_, path)| path).collect())
}

/// Reads one instruction file of the core (regular, at most 0640, one link) and returns the
/// vendor line when the file names this session, is named for its key, and is not yet posted.
pub fn read_instruction(
    path: &Path,
    core_uid: u32,
    session: &SessionName,
) -> Result<String, String> {
    let bytes = read_relay_file(path, core_uid)?;
    let line = String::from_utf8(bytes).map_err(|error| error.to_string())?;
    if !(line.ends_with('\n') && line.matches('\n').count() == 1) {
        return Err("not one line".to_string());
    }
    let envelope: RelayEnvelope =
        serde_json::from_str(line.trim_end()).map_err(|error| bounded(&error.to_string()))?;
    if envelope.session != session.to_string() {
        return Err(format!(
            "written for session {}, not {session}",
            bounded(&envelope.session)
        ));
    }
    let key = ShortText::parse(&envelope.key).map_err(|error| error.to_string())?;
    let name = relay_file_name(&key);
    if path.file_name().and_then(|name| name.to_str()) != Some(name.as_str()) {
        return Err(format!("the key names {name}, not this file"));
    }
    if marker(path, POSTED_SUFFIX).exists() {
        return Err(format!("the key {key} was already posted"));
    }
    if envelope
        .message
        .get("type")
        .and_then(serde_json::Value::as_str)
        != Some("user")
    {
        return Err("not a user message".to_string());
    }
    let message = serde_json::to_string(&envelope.message).map_err(|error| error.to_string())?;
    Ok(format!("{message}\n"))
}

/// One poll: posts pending instructions up to the bound and marks each posted or failed.
pub fn relay_once(
    dir: &Path,
    core_uid: u32,
    session: &SessionName,
    socket: &Path,
) -> Result<Vec<Delivery>, String> {
    check_relay_dir(dir, core_uid)?;
    let mut outcomes = Vec::new();
    for path in pending(dir)?.into_iter().take(RELAY_POSTS_PER_POLL_MAX) {
        let delivery = match read_instruction(&path, core_uid, session) {
            Ok(line) => post(socket, &line, current_uid()),
            Err(reason) => Delivery::Unrecognised { reason },
        };
        let suffix = if delivery.written() {
            POSTED_SUFFIX
        } else {
            FAILED_SUFFIX
        };
        let record = serde_json::to_vec(&delivery).map_err(|error| error.to_string())?;
        write_new(&marker(&path, suffix), &record)
            .map_err(|error| format!("{}: {error}", marker(&path, suffix).display()))?;
        outcomes.push(delivery);
    }
    Ok(outcomes)
}

/// Unlinks an ended session's relay directory and its entries; a missing one is removed.
#[expect(
    clippy::disallowed_methods,
    reason = "checked above as this user's directory; std removes a symlink at the top as a link and opens descendants without following links"
)]
pub fn remove_relay_dir(dirs: &AgentDirs, session: &SessionName) -> Result<(), String> {
    let dir = relay_dir(dirs, session);
    match fs::symlink_metadata(&dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", dir.display())),
        Ok(metadata) if !metadata.file_type().is_dir() || metadata.uid() != current_uid() => {
            return Err(format!("{} is not a directory of this user", dir.display()))
        }
        Ok(_) => {}
    }
    // Only names are unlinked, never a file opened or written: a planted hard link may share
    // its inode with any file of the core. A link of an instruction left elsewhere names this
    // session, which no other launcher posts.
    fs::remove_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use crate::agent_files::current_uid;
    use crate::vendors::claude_control::instruction_line;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;
    use std::thread;

    fn scratch(test: &str) -> AgentDirs {
        let dir = std::env::temp_dir().join(format!("trl-{test}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }
        fs::create_dir_all(&dir).unwrap();
        AgentDirs::new(dir).unwrap()
    }

    fn session() -> SessionName {
        SessionName::parse("cf7a.wu03.ctl.claude").unwrap()
    }

    fn other_session() -> SessionName {
        SessionName::parse("cf7a.wu04.ctl.claude").unwrap()
    }

    fn line(text: &str) -> String {
        instruction_line(&ShortText::parse(text).unwrap())
    }

    #[test]
    fn an_instruction_is_written_once_per_key_closed_to_other_writers() {
        let dirs = scratch("write");
        let key = ShortText::parse("wu03:task_packet:1").unwrap();
        let name = write_instruction(&dirs, &session(), &key, &line("go")).unwrap();
        assert_eq!(name, relay_file_name(&key));
        let dir = relay_dir(&dirs, &session());
        let file = dir.join(&name);
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            RELAY_FILE_MODE
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o7777,
            RELAY_DIR_MODE
        );
        assert_eq!(
            write_instruction(&dirs, &session(), &key, &line("go")).unwrap(),
            name,
            "a replayed key is not written twice"
        );
        let other = write_instruction(&dirs, &session(), &key, &line("again")).unwrap_err();
        assert!(other.contains("another instruction"), "{other}");
        assert_eq!(
            read_instruction(&file, current_uid(), &session()).unwrap(),
            line("go")
        );
        let long = "x".repeat(RELAY_FILE_MAX_BYTES + 1);
        assert!(write_instruction(&dirs, &session(), &key, &long).is_err());
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn an_instruction_of_another_owner_or_open_to_writes_or_not_a_message_is_refused() {
        let dirs = scratch("refuse");
        let key = ShortText::parse("k").unwrap();
        let name = write_instruction(&dirs, &session(), &key, &line("go")).unwrap();
        let file = relay_dir(&dirs, &session()).join(name);
        let other = current_uid().wrapping_add(1);
        assert!(read_instruction(&file, other, &session()).is_err());
        assert!(check_relay_dir(&relay_dir(&dirs, &session()), other).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o660)).unwrap();
        assert!(read_instruction(&file, current_uid(), &session()).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        fs::remove_file(&file).unwrap();
        let auth = envelope_line(&session(), &key, "{\"type\":\"auth\"}").unwrap();
        write_new_mode(&file, auth.as_bytes(), 0o640).unwrap();
        let refused = read_instruction(&file, current_uid(), &session()).unwrap_err();
        assert!(refused.contains("not a user message"), "{refused}");
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_poll_posts_each_pending_line_and_marks_it() {
        let dirs = scratch("poll");
        let dir = relay_dir(&dirs, &session());
        let socket = dirs.socket_dir.join("i.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let mut lines = Vec::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream).read_line(&mut line).unwrap();
                lines.push(line);
            }
            lines
        });
        for (key, text) in [("k1", "first"), ("k2", "second")] {
            let key = ShortText::parse(key).unwrap();
            write_instruction(&dirs, &session(), &key, &line(text)).unwrap();
            thread::sleep(std::time::Duration::from_millis(20));
        }
        let outcomes = relay_once(&dir, current_uid(), &session(), &socket).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(Delivery::written), "{outcomes:?}");
        assert_eq!(server.join().unwrap(), [line("first"), line("second")]);
        assert!(pending(&dir).unwrap().is_empty(), "both are marked posted");
        assert!(relay_once(&dir, current_uid(), &session(), &socket)
            .unwrap()
            .is_empty());
        fs::remove_file(&socket).unwrap();
        let key = ShortText::parse("k3").unwrap();
        let name = write_instruction(&dirs, &session(), &key, &line("third")).unwrap();
        let failed = relay_once(&dir, current_uid(), &session(), &socket).unwrap();
        assert!(matches!(failed.as_slice(), [Delivery::NoSocket { .. }]));
        assert!(marker(&dir.join(name), FAILED_SUFFIX).exists());
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_hard_linked_instruction_is_refused_by_its_link_count() {
        let dirs = scratch("link");
        let key = ShortText::parse("k").unwrap();
        let name = write_instruction(&dirs, &session(), &key, &line("go")).unwrap();
        let file = relay_dir(&dirs, &session()).join(&name);
        let replay = relay_dir(&dirs, &session()).join("ffffffffffffffff.json");
        fs::hard_link(&file, &replay).unwrap();
        let refused = read_instruction(&replay, current_uid(), &session()).unwrap_err();
        assert!(refused.contains("2 links, expected 1"), "{refused}");
        assert!(read_instruction(&file, current_uid(), &session()).is_err());
        fs::remove_file(&replay).unwrap();
        assert_eq!(
            read_instruction(&file, current_uid(), &session()).unwrap(),
            line("go")
        );
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_line_linked_into_another_sessions_directory_is_refused_by_content() {
        let dirs = scratch("content");
        let key = ShortText::parse("k").unwrap();
        let name = write_instruction(&dirs, &session(), &key, &line("go")).unwrap();
        let file = relay_dir(&dirs, &session()).join(&name);
        let other_key = ShortText::parse("k2").unwrap();
        write_instruction(&dirs, &other_session(), &other_key, &line("b")).unwrap();
        let other_dir = relay_dir(&dirs, &other_session());
        let planted = other_dir.join(&name);
        fs::hard_link(&file, &planted).unwrap();
        // With the original name gone the link count is one again; only the content refuses it.
        fs::remove_file(&file).unwrap();
        let refused = read_instruction(&planted, current_uid(), &other_session()).unwrap_err();
        assert!(
            refused.contains("written for session cf7a.wu03"),
            "{refused}"
        );
        let socket = dirs.socket_dir.join("absent.sock");
        let outcomes = relay_once(&other_dir, current_uid(), &other_session(), &socket).unwrap();
        assert!(
            outcomes
                .iter()
                .any(|delivery| matches!(delivery, Delivery::Unrecognised { reason } if reason.contains("written for session"))),
            "{outcomes:?}"
        );
        assert!(marker(&planted, FAILED_SUFFIX).exists());
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_posted_key_is_refused_by_its_marker_and_a_renamed_file_by_its_key() {
        let dirs = scratch("replay");
        let dir = relay_dir(&dirs, &session());
        let key = ShortText::parse("k").unwrap();
        let name = write_instruction(&dirs, &session(), &key, &line("go")).unwrap();
        let file = dir.join(&name);
        let socket = dirs.socket_dir.join("i.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream).read_line(&mut line).unwrap();
            line
        });
        let outcomes = relay_once(&dir, current_uid(), &session(), &socket).unwrap();
        assert!(
            matches!(outcomes.as_slice(), [Delivery::Posted { .. }]),
            "{outcomes:?}"
        );
        assert_eq!(server.join().unwrap(), line("go"));
        let refused = read_instruction(&file, current_uid(), &session()).unwrap_err();
        assert!(refused.contains("already posted"), "{refused}");
        let renamed = dir.join("0123456789abcdef.json");
        fs::rename(&file, &renamed).unwrap();
        let refused = read_instruction(&renamed, current_uid(), &session()).unwrap_err();
        assert!(
            refused.contains(&format!("the key names {name}")),
            "{refused}"
        );
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_pre_existing_file_counts_as_relayed_only_when_it_is_the_cores_identical_line() {
        let dirs = scratch("existing");
        let key = ShortText::parse("k").unwrap();
        let dir = relay_dir(&dirs, &session());
        write_instruction(
            &dirs,
            &session(),
            &ShortText::parse("k0").unwrap(),
            &line("x"),
        )
        .unwrap();
        let file = dir.join(relay_file_name(&key));
        write_new_mode(&file, line("planted").as_bytes(), RELAY_FILE_MODE).unwrap();
        let refused = write_instruction(&dirs, &session(), &key, &line("go")).unwrap_err();
        assert!(refused.contains("another instruction"), "{refused}");
        fs::remove_file(&file).unwrap();
        let identical = envelope_line(&session(), &key, &line("go")).unwrap();
        write_new_mode(&file, identical.as_bytes(), RELAY_FILE_MODE).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o660)).unwrap();
        let refused = write_instruction(&dirs, &session(), &key, &line("go")).unwrap_err();
        assert!(refused.contains("wider than 640"), "{refused}");
        fs::set_permissions(&file, fs::Permissions::from_mode(RELAY_FILE_MODE)).unwrap();
        let link = dir.join("link");
        fs::hard_link(&file, &link).unwrap();
        let refused = write_instruction(&dirs, &session(), &key, &line("go")).unwrap_err();
        assert!(refused.contains("2 links"), "{refused}");
        fs::remove_file(&link).unwrap();
        assert_eq!(
            write_instruction(&dirs, &session(), &key, &line("go")).unwrap(),
            relay_file_name(&key)
        );
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn a_hard_link_to_a_core_file_outside_the_relay_survives_cleanup_with_its_content() {
        let dirs = scratch("remove");
        let name = write_instruction(
            &dirs,
            &session(),
            &ShortText::parse("k").unwrap(),
            &line("go"),
        )
        .unwrap();
        let dir = relay_dir(&dirs, &session());
        write_new(&marker(&dir.join(&name), POSTED_SUFFIX), b"{}").unwrap();
        let secret = dirs.socket_dir.join("operator-secret");
        write_new(&secret, b"0123456789abcdef").unwrap();
        fs::hard_link(&secret, dir.join("0000000000000000.json")).unwrap();
        remove_relay_dir(&dirs, &session()).unwrap();
        assert!(!dir.exists());
        assert_eq!(fs::read(&secret).unwrap(), b"0123456789abcdef");
        assert_eq!(fs::metadata(&secret).unwrap().nlink(), 1);
        remove_relay_dir(&dirs, &session()).unwrap();
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }

    #[test]
    fn the_poll_still_posts_after_more_instructions_than_the_pending_bound_were_posted() {
        let dirs = scratch("many");
        let dir = relay_dir(&dirs, &session());
        for index in 0..130 {
            let key = ShortText::parse(&format!("k{index}")).unwrap();
            let name = write_instruction(&dirs, &session(), &key, &line("old")).unwrap();
            write_new(&marker(&dir.join(name), POSTED_SUFFIX), b"{}").unwrap();
        }
        assert!(fs::read_dir(&dir).unwrap().count() > RELAY_PENDING_MAX);
        assert!(pending(&dir).unwrap().is_empty());
        let socket = dirs.socket_dir.join("i.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream).read_line(&mut line).unwrap();
            line
        });
        let key = ShortText::parse("k130").unwrap();
        write_instruction(&dirs, &session(), &key, &line("new")).unwrap();
        let outcomes = relay_once(&dir, current_uid(), &session(), &socket).unwrap();
        assert!(
            matches!(outcomes.as_slice(), [Delivery::Posted { .. }]),
            "{outcomes:?}"
        );
        assert_eq!(server.join().unwrap(), line("new"));
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }
}

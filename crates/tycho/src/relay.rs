//! The instruction relay, for an inbox socket that admits only the vendor's own user.
//!
//! The core leaves an instruction in a directory it owns and the agent user's group can read;
//! the session's launcher, running as the agent user, posts it to the socket. The directory is sticky and group-writable, so the launcher can add its outcome markers
//! (`<name>.posted`, `<name>.failed`) but can neither replace nor remove the core's files.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::unistd::Uid;
use sha2::{Digest, Sha256};
use tycho_types::envelope::ShortText;
use tycho_types::session::SessionName;

use crate::agent_files::{read_checked, write_new, write_new_mode};
use crate::config::AgentDirs;
use crate::vendors::claude_control::post;
use crate::vendors::control::{bounded, Delivery};

pub const RELAY_DIR: &str = "instructions";
/// Group-writable for the launcher's markers, sticky so it cannot touch the core's files.
pub const RELAY_DIR_MODE: u32 = 0o1770;
/// Readable by the agent user's group, writable by the core alone.
pub const RELAY_FILE_MODE: u32 = 0o640;
pub const RELAY_FILE_MAX_BYTES: usize = 4096;
pub const RELAY_ENTRIES_MAX: usize = 256;
/// Instructions one poll posts; the rest wait for the next poll a second later.
pub const RELAY_POSTS_PER_POLL_MAX: usize = 8;
pub const POSTED_SUFFIX: &str = "posted";
pub const FAILED_SUFFIX: &str = "failed";
const GROUP_AND_OTHER_WRITE_BITS: u32 = 0o022;
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

/// Leaves one instruction line for the launcher; an existing file for the key counts as relayed.
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
    let dir = relay_dir(dirs, session);
    for each in [dirs.socket_dir.join(RELAY_DIR), dir.clone()] {
        ensure_relay_dir(&each).map_err(|error| format!("{}: {error}", each.display()))?;
    }
    let name = relay_file_name(key);
    match write_new_mode(&dir.join(&name), line.as_bytes(), RELAY_FILE_MODE) {
        Ok(()) => Ok(name),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(name),
        Err(error) => Err(format!("{}: {error}", dir.join(&name).display())),
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

/// Instruction files without an outcome marker, oldest first; over the bound is an error.
pub fn pending(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("{}: {error}", dir.display())),
    };
    let mut files = Vec::new();
    for (count, entry) in entries.enumerate() {
        if count >= RELAY_ENTRIES_MAX {
            return Err(format!(
                "{} holds more than {RELAY_ENTRIES_MAX} entries",
                dir.display()
            ));
        }
        let path = entry.map_err(|error| error.to_string())?.path();
        let done = [POSTED_SUFFIX, FAILED_SUFFIX]
            .iter()
            .any(|suffix| marker(&path, suffix).exists());
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") && !done {
            let modified = fs::symlink_metadata(&path)
                .and_then(|metadata| metadata.modified())
                .map_err(|error| format!("{}: {error}", path.display()))?;
            files.push((modified, path));
        }
    }
    files.sort();
    Ok(files.into_iter().map(|(_, path)| path).collect())
}

/// Reads one instruction file of the core, closed to other writers, holding one JSON line.
pub fn read_instruction(path: &Path, core_uid: u32) -> Result<String, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.mode() & GROUP_AND_OTHER_WRITE_BITS != 0 {
        return Err(format!("{} is writable by others", path.display()));
    }
    let bytes = read_checked(path, RELAY_FILE_MAX_BYTES, Some(core_uid))
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("{} is gone", path.display()))?;
    let line = String::from_utf8(bytes).map_err(|error| error.to_string())?;
    let single = line.ends_with('\n') && line.matches('\n').count() == 1;
    let message: serde_json::Value =
        serde_json::from_str(line.trim_end()).map_err(|error| bounded(&error.to_string()))?;
    if !single || message.get("type").and_then(serde_json::Value::as_str) != Some("user") {
        return Err("not one user message line".to_string());
    }
    Ok(line)
}

/// One poll: posts pending instructions up to the bound and marks each posted or failed.
pub fn relay_once(dir: &Path, core_uid: u32, socket: &Path) -> Result<Vec<Delivery>, String> {
    check_relay_dir(dir, core_uid)?;
    let mut outcomes = Vec::new();
    for path in pending(dir)?.into_iter().take(RELAY_POSTS_PER_POLL_MAX) {
        let delivery = match read_instruction(&path, core_uid) {
            Ok(line) => post(socket, &line),
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

#[cfg(test)]
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
            write_instruction(&dirs, &session(), &key, &line("again")).unwrap(),
            name,
            "a replayed key is not written twice"
        );
        assert_eq!(read_instruction(&file, current_uid()).unwrap(), line("go"));
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
        assert!(read_instruction(&file, other).is_err());
        assert!(check_relay_dir(&relay_dir(&dirs, &session()), other).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o660)).unwrap();
        assert!(read_instruction(&file, current_uid()).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        fs::remove_file(&file).unwrap();
        write_new_mode(&file, b"{\"type\":\"auth\"}\n", 0o640).unwrap();
        assert!(read_instruction(&file, current_uid()).is_err());
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
        let outcomes = relay_once(&dir, current_uid(), &socket).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(Delivery::written), "{outcomes:?}");
        assert_eq!(server.join().unwrap(), [line("first"), line("second")]);
        assert!(pending(&dir).unwrap().is_empty(), "both are marked posted");
        assert!(relay_once(&dir, current_uid(), &socket).unwrap().is_empty());
        fs::remove_file(&socket).unwrap();
        let key = ShortText::parse("k3").unwrap();
        let name = write_instruction(&dirs, &session(), &key, &line("third")).unwrap();
        let failed = relay_once(&dir, current_uid(), &socket).unwrap();
        assert!(matches!(failed.as_slice(), [Delivery::NoSocket { .. }]));
        assert!(marker(&dir.join(name), FAILED_SUFFIX).exists());
        fs::remove_dir_all(&dirs.socket_dir).unwrap();
    }
}

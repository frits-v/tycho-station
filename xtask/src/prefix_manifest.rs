//! `station.json` in the tool prefix: what the install steps placed there, with digests. It
//! catches an accidental change, a partial install or a stale build; it does not stop
//! tampering, since whoever can replace a binary in the prefix can rewrite this file too.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub const MANIFEST_SCHEMA_VERSION: u64 = 2;
pub const MANIFEST_MAX_BYTES: u64 = 64 << 10;
/// Every file the install digest reads, each read in full.
pub const BINARY_MAX_BYTES: u64 = 512 << 20;
/// Entries one install digest examines before it refuses the install as too large.
pub const INSTALL_ENTRIES_MAX: usize = 4096;
const HEX_DIGEST_BYTES: usize = 64;
const COMMIT_HEX_BYTES: usize = 40;
const READ_CHUNK_BYTES: usize = 64 << 10;

/// The station binaries' digests and the commit they were built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationRecord {
    pub commit: String,
    pub clean: bool,
    pub xtask: String,
    pub tycho: String,
}

/// One agent tool: its pin, the absolute path a session runs, and the digest of its install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRecord {
    pub version: String,
    pub path: PathBuf,
    pub install_sha256: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    pub station: Option<StationRecord>,
    pub tools: BTreeMap<String, ToolRecord>,
}

pub fn is_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

pub fn is_commit(text: &str) -> bool {
    is_hex(text, COMMIT_HEX_BYTES)
}

impl Manifest {
    pub fn render(&self) -> String {
        let mut value = serde_json::Map::new();
        value.insert(
            "schema_version".to_string(),
            serde_json::Value::from(MANIFEST_SCHEMA_VERSION),
        );
        if let Some(station) = &self.station {
            value.insert(
                "station".to_string(),
                serde_json::json!({
                    "commit": station.commit,
                    "clean": station.clean,
                    "xtask": station.xtask,
                    "tycho": station.tycho,
                }),
            );
        }
        let tools: serde_json::Map<String, serde_json::Value> = self
            .tools
            .iter()
            .map(|(name, record)| {
                (
                    name.clone(),
                    serde_json::json!({
                        "version": record.version,
                        "path": record.path.display().to_string(),
                        "install_sha256": record.install_sha256,
                    }),
                )
            })
            .collect();
        value.insert("tools".to_string(), serde_json::Value::Object(tools));
        format!("{:#}\n", serde_json::Value::Object(value))
    }
}

fn decode_station(value: &serde_json::Value) -> Option<StationRecord> {
    let text = |name: &str| value.get(name)?.as_str().map(str::to_string);
    let record = StationRecord {
        commit: text("commit")?,
        clean: value.get("clean")?.as_bool()?,
        xtask: text("xtask")?,
        tycho: text("tycho")?,
    };
    let valid = is_commit(&record.commit)
        && is_hex(&record.xtask, HEX_DIGEST_BYTES)
        && is_hex(&record.tycho, HEX_DIGEST_BYTES);
    valid.then_some(record)
}

fn decode_tool(value: &serde_json::Value) -> Option<ToolRecord> {
    let record = ToolRecord {
        version: value.get("version")?.as_str()?.to_string(),
        path: PathBuf::from(value.get("path")?.as_str()?),
        install_sha256: value.get("install_sha256")?.as_str()?.to_string(),
    };
    let valid = !record.version.is_empty()
        && record.path.is_absolute()
        && is_hex(&record.install_sha256, HEX_DIGEST_BYTES);
    valid.then_some(record)
}

/// `None` for anything but a version 2 manifest whose every present part is well formed.
pub fn decode_manifest(text: &str) -> Option<Manifest> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    if value.get("schema_version")?.as_u64()? != MANIFEST_SCHEMA_VERSION {
        return None;
    }
    let station = match value.get("station") {
        None => None,
        Some(station) => Some(decode_station(station)?),
    };
    let mut tools = BTreeMap::new();
    if let Some(entries) = value.get("tools") {
        for (name, entry) in entries.as_object()? {
            tools.insert(name.clone(), decode_tool(entry)?);
        }
    }
    Some(Manifest { station, tools })
}

/// Reads a regular file without following a link, refusing one over `max` bytes.
pub fn read_regular(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let file = open_regular(path)?;
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > max) {
        return Err(io::Error::other(format!(
            "{} is larger than {max} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

fn open_regular(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(file)
}

/// What reading `station.json` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestRead {
    Absent,
    Present(Manifest),
    /// A file that is not a version 2 manifest, which the install steps replace.
    Unrecognised,
    Unreadable(String),
}

impl ManifestRead {
    /// The manifest to extend: an absent or unrecognised one starts empty.
    pub fn into_base(self) -> Result<Manifest, String> {
        match self {
            Self::Present(manifest) => Ok(manifest),
            Self::Absent | Self::Unrecognised => Ok(Manifest::default()),
            Self::Unreadable(why) => Err(why),
        }
    }
}

pub fn read_manifest(path: &Path) -> ManifestRead {
    match read_regular(path, MANIFEST_MAX_BYTES) {
        Ok(bytes) => decode_manifest(&String::from_utf8_lossy(&bytes))
            .map_or(ManifestRead::Unrecognised, ManifestRead::Present),
        Err(error) if error.kind() == io::ErrorKind::NotFound => ManifestRead::Absent,
        Err(error) => ManifestRead::Unreadable(format!("{}: {error}", path.display())),
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(digest: &[u8]) -> String {
    digest
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
        .collect()
}

/// A file's SHA-256, read in chunks without following a link, refusing one over the bound.
fn file_sha256(path: &Path) -> Result<String, String> {
    let shown = path.display();
    let mut file = open_regular(path).map_err(|error| format!("{shown}: {error}"))?;
    let mut hasher = Sha256::new();
    let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
    let mut total = 0_u64;
    loop {
        let count = file
            .read(&mut chunk)
            .map_err(|error| format!("{shown}: {error}"))?;
        if count == 0 {
            return Ok(hex(&hasher.finalize()));
        }
        total = total.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        if total > BINARY_MAX_BYTES {
            return Err(format!("{shown} is larger than {BINARY_MAX_BYTES} bytes"));
        }
        hasher.update(chunk.get(..count).unwrap_or_default());
    }
}

/// Every entry under `root` without following a link, sorted, bounded by
/// `INSTALL_ENTRIES_MAX`.
fn install_entries(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut stack = vec![root.to_path_buf()];
    let mut entries = Vec::new();
    while let Some(path) = stack.pop() {
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if metadata.is_dir() {
            let listing =
                fs::read_dir(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            for entry in listing {
                let entry = entry.map_err(|error| format!("{}: {error}", path.display()))?;
                if stack.len().saturating_add(entries.len()) >= INSTALL_ENTRIES_MAX {
                    return Err(format!(
                        "{} holds more than {INSTALL_ENTRIES_MAX} entries",
                        root.display()
                    ));
                }
                stack.push(entry.path());
            }
        }
        entries.push(path);
    }
    entries.sort();
    Ok(entries)
}

/// One line per entry of an install, sorted by path: its kind, path relative to the install,
/// mode, and a file's SHA-256 or a link's target. The digest of those lines names the install.
pub fn install_sha256(root: &Path) -> Result<String, String> {
    let mut lines = String::new();
    for path in install_entries(root)? {
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let mode = metadata.mode() & 0o7777;
        let file_type = metadata.file_type();
        let line = if file_type.is_symlink() {
            let target =
                fs::read_link(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            format!("link {relative} {}", target.display())
        } else if file_type.is_dir() {
            format!("dir {relative} {mode:04o}")
        } else if file_type.is_file() {
            format!("file {relative} {mode:04o} {}", file_sha256(&path)?)
        } else {
            return Err(format!(
                "{} is not a file, a directory or a link",
                path.display()
            ));
        };
        lines.push_str(&line);
        lines.push('\n');
    }
    Ok(sha256_hex(lines.as_bytes()))
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn record() -> Manifest {
        Manifest {
            station: Some(StationRecord {
                commit: "a".repeat(40),
                clean: true,
                xtask: "b".repeat(64),
                tycho: "c".repeat(64),
            }),
            tools: BTreeMap::from([(
                "claude".to_string(),
                ToolRecord {
                    version: "2.1.280".to_string(),
                    path: PathBuf::from("/p/mise/installs/claude/2.1.280/claude"),
                    install_sha256: "d".repeat(64),
                },
            )]),
        }
    }

    #[test]
    fn a_manifest_round_trips_and_a_malformed_part_is_refused() {
        let recorded = record();
        assert_eq!(decode_manifest(&recorded.render()), Some(recorded.clone()));
        assert_eq!(
            decode_manifest(&Manifest::default().render()),
            Some(Manifest::default())
        );
        let mut short = recorded.clone();
        if let Some(station) = short.station.as_mut() {
            station.commit = "abc".to_string();
        }
        assert_eq!(decode_manifest(&short.render()), None);
        let mut relative = recorded.clone();
        if let Some(tool) = relative.tools.get_mut("claude") {
            tool.path = PathBuf::from("mise/installs/claude");
        }
        assert_eq!(decode_manifest(&relative.render()), None);
        let mut upper = recorded;
        if let Some(tool) = upper.tools.get_mut("claude") {
            tool.install_sha256 = "D".repeat(64);
        }
        assert_eq!(decode_manifest(&upper.render()), None);
        assert_eq!(decode_manifest("{\"schema_version\": 1}"), None);
        assert_eq!(decode_manifest("not json"), None);
    }

    #[test]
    fn an_unrecognised_manifest_is_replaced_and_an_absent_one_starts_empty() {
        let dir = std::env::temp_dir().join(format!("xtask-manifest-{}", std::process::id()));
        drop(fs::remove_dir_all(&dir));
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("station.json");
        assert_eq!(read_manifest(&path), ManifestRead::Absent);
        fs::write(&path, "{\"schema_version\": 1, \"commit\": \"x\"}").expect("write");
        assert_eq!(read_manifest(&path), ManifestRead::Unrecognised);
        assert_eq!(read_manifest(&path).into_base(), Ok(Manifest::default()));
        fs::write(&path, record().render()).expect("write");
        assert_eq!(read_manifest(&path), ManifestRead::Present(record()));
        assert!(ManifestRead::Unreadable("x".to_string())
            .into_base()
            .is_err());
        fs::remove_dir_all(&dir).expect("clean up");
    }

    #[test]
    fn digests_are_lowercase_hex_sha256() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn an_install_digest_changes_with_any_file_mode_or_link() {
        let root = std::env::temp_dir().join(format!("xtask-install-{}", std::process::id()));
        drop(fs::remove_dir_all(&root));
        fs::create_dir_all(root.join("bin")).expect("mkdir");
        fs::write(root.join("bin/tool"), b"one").expect("write");
        std::os::unix::fs::symlink("bin/tool", root.join("latest")).expect("link");
        let first = install_sha256(&root).expect("digest");
        assert_eq!(install_sha256(&root).expect("digest"), first);
        fs::write(root.join("bin/tool"), b"two").expect("write");
        let second = install_sha256(&root).expect("digest");
        assert_ne!(second, first);
        fs::set_permissions(root.join("bin/tool"), fs::Permissions::from_mode(0o700))
            .expect("chmod");
        assert_ne!(install_sha256(&root).expect("digest"), second);
        fs::remove_file(root.join("latest")).expect("unlink");
        std::os::unix::fs::symlink("bin", root.join("latest")).expect("link");
        assert_ne!(install_sha256(&root).expect("digest"), second);
        fs::remove_dir_all(&root).expect("clean up");
    }
}

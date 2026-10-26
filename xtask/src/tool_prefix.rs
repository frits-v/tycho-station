//! The shared tool prefix, `/Users/Shared/tycho`: the pinned mise, the station's own binaries,
//! and a mise data directory holding the tools the agent runs. The developer owns every entry
//! and none is writable by group or other, so the agent executes and reads but changes nothing.
//! `/Users/Shared` is sticky, so only the developer or root can rename or remove the prefix.
//!
//! Every probe here reads what it finds and never creates anything; `prefix_install` makes the
//! prefix. A probe that cannot run is `Unreachable`, never guessed.

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use tycho_types::git_environment::git_command;

use crate::prefix_manifest::{
    BINARY_MAX_BYTES, Manifest, ManifestRead, StationRecord, ToolRecord, install_sha256, is_commit,
    read_manifest, read_regular, sha256_hex,
};
use crate::setup::{self, Capture, Check, Finding, Identity, Status};

pub const PREFIX_ROOT: &str = "/Users/Shared/tycho";
pub const PREFIX_MODE: u32 = 0o755;
/// The mise version the workflows pin; the prefix runs the same one.
pub const MISE_PINNED_VERSION: &str = "2026.9.13";
/// Entries one walk of the prefix examines before it reports the tree as too large.
pub const ENTRIES_MAX: usize = 4096;
const GROUP_OR_OTHER_WRITE: u32 = 0o022;
const STICKY: u32 = 0o1000;
/// A cold shim start reads the install's bin paths before the tool answers.
pub const TOOL_PROBE_TIMEOUT: Duration = Duration::from_secs(30);
/// The pins of the tools the agent needs, compiled from the repository's `mise.toml`, so the
/// agent's `xtask setup` needs no checkout.
const REPOSITORY_MISE_TOML: &str = include_str!("../../mise.toml");
pub const AGENT_HOME: &str = "/Users/tycho-agent";
const STATE_RELATIVE: &str = ".local/state/mise";
const DEVELOPER_STATE_RELATIVE: &str = ".local/state/tycho-prefix-mise";
const DISABLED_PROJECT_CONFIG: &str = "no-project-config";
const SYSTEM_PATH: &str = "/usr/bin:/bin";

/// The tools the agent runs from the prefix; git comes from the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentTool {
    Claude,
    Codex,
    Zmx,
}

impl AgentTool {
    pub const ALL: [Self; 3] = [Self::Claude, Self::Codex, Self::Zmx];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Zmx => "zmx",
        }
    }

    fn decode_version(self, stdout: &str) -> Option<String> {
        match self {
            Self::Claude => setup::decode_claude_version(stdout),
            Self::Codex => setup::decode_codex_version(stdout),
            Self::Zmx => setup::decode_zmx_version(stdout),
        }
    }

    /// Where the executable sits inside the install: the backends put claude and zmx at the
    /// install's root and codex under `bin`.
    pub const fn bin_relative(self) -> &'static str {
        match self {
            Self::Claude | Self::Zmx => "",
            Self::Codex => "bin",
        }
    }

    pub const fn developer_check(self) -> Check {
        match self {
            Self::Claude => Check::PrefixClaude,
            Self::Codex => Check::PrefixCodex,
            Self::Zmx => Check::PrefixZmx,
        }
    }

    pub const fn agent_check(self) -> Check {
        match self {
            Self::Claude => Check::AgentPrefixClaude,
            Self::Codex => Check::AgentPrefixCodex,
            Self::Zmx => Check::AgentPrefixZmx,
        }
    }
}

/// The station binaries installed into the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StationBinary {
    Xtask,
    Tycho,
}

impl StationBinary {
    pub const ALL: [Self; 2] = [Self::Xtask, Self::Tycho];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Xtask => "xtask",
            Self::Tycho => "tycho",
        }
    }

    pub const fn check(self) -> Check {
        match self {
            Self::Xtask => Check::PrefixStationXtask,
            Self::Tycho => Check::PrefixStationTycho,
        }
    }
}

/// One `name = "value"` line of the `[tools]` table, the only form the agent's pins take.
#[derive(Debug, PartialEq, Eq)]
enum PinLine {
    Pinned(String),
    Absent,
    Unrecognised(String),
}

fn decode_pin(text: &str, tool: &str) -> PinLine {
    let mut in_tools = false;
    let mut found = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_tools = line == "[tools]";
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !in_tools || key.trim() != tool {
            continue;
        }
        let quoted = value
            .trim()
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .filter(|inner| !inner.is_empty() && !inner.contains(['"', '\\']));
        match (quoted, &found) {
            (Some(version), None) => found = Some(version.to_string()),
            _ => return PinLine::Unrecognised(line.to_string()),
        }
    }
    found.map_or(PinLine::Absent, PinLine::Pinned)
}

/// The tool's version from the repository's `mise.toml` this binary was built with.
pub fn pinned_version(tool: AgentTool) -> Result<String, String> {
    match decode_pin(REPOSITORY_MISE_TOML, tool.name()) {
        PinLine::Pinned(version) => Ok(version),
        PinLine::Absent => Err(format!("{} is not pinned in mise.toml", tool.name())),
        PinLine::Unrecognised(line) => Err(format!(
            "unrecognised pin for {} in mise.toml: {line:?}",
            tool.name()
        )),
    }
}

/// The global configuration the prefix's shims resolve versions from: the agent's pins only.
pub fn global_config() -> Result<String, String> {
    let mut lines = vec!["[tools]".to_string()];
    for tool in AgentTool::ALL {
        lines.push(format!("{} = \"{}\"", tool.name(), pinned_version(tool)?));
    }
    lines.push(String::new());
    Ok(lines.join("\n"))
}

/// Where the prefix and its parts live; tests point it at a scratch directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    root: PathBuf,
}

impl Prefix {
    pub fn production() -> Self {
        Self {
            root: PathBuf::from(PREFIX_ROOT),
        }
    }

    #[cfg(test)]
    pub const fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn bin(&self) -> PathBuf {
        self.root.join("bin")
    }

    pub fn mise(&self) -> PathBuf {
        self.bin().join("mise")
    }

    pub fn binary(&self, binary: StationBinary) -> PathBuf {
        self.bin().join(binary.name())
    }

    pub fn data_dir(&self) -> PathBuf {
        self.root.join("mise")
    }

    /// mise's cache: the developer fills it at install and the agent only reads it, so no
    /// cached bin path the agent writes can redirect a lookup.
    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }

    /// A path that never exists, named as mise's only project configuration file name, so no
    /// `mise.toml` in a working directory or its parents is read.
    pub fn disabled_project_config(&self) -> PathBuf {
        self.root.join(DISABLED_PROJECT_CONFIG)
    }

    pub fn installs(&self, tool: AgentTool, version: &str) -> PathBuf {
        self.data_dir()
            .join("installs")
            .join(tool.name())
            .join(version)
    }

    /// The directory holding the tool's executable in its pinned install.
    pub fn tool_dir(&self, tool: AgentTool, version: &str) -> PathBuf {
        let install = self.installs(tool, version);
        match tool.bin_relative() {
            "" => install,
            relative => install.join(relative),
        }
    }

    /// The executable a session runs, by absolute path, never through a shim.
    pub fn tool_binary(&self, tool: AgentTool, version: &str) -> PathBuf {
        self.tool_dir(tool, version).join(tool.name())
    }

    pub fn global_config(&self) -> PathBuf {
        self.root.join("mise.toml")
    }

    pub fn manifest(&self) -> PathBuf {
        self.root.join("station.json")
    }

    /// The agent's `PATH`: the prefix's binaries, each pinned install's executable directory,
    /// then the system's. No shim directory is on it.
    pub fn path_value(&self) -> Result<String, String> {
        let mut parts = vec![self.bin().display().to_string()];
        for tool in AgentTool::ALL {
            parts.push(
                self.tool_dir(tool, &pinned_version(tool)?)
                    .display()
                    .to_string(),
            );
        }
        parts.push(SYSTEM_PATH.to_string());
        Ok(parts.join(":"))
    }

    /// What any mise started with the prefix reads: the prefix's installs, pins and cache, no
    /// project configuration, no network and no install of a missing version.
    pub fn mise_environment(&self) -> Vec<(&'static str, String)> {
        vec![
            ("MISE_DATA_DIR", self.data_dir().display().to_string()),
            (
                "MISE_GLOBAL_CONFIG_FILE",
                self.global_config().display().to_string(),
            ),
            ("MISE_CACHE_DIR", self.cache_dir().display().to_string()),
            (
                "MISE_OVERRIDE_CONFIG_FILENAMES",
                self.disabled_project_config().display().to_string(),
            ),
            ("MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES", "none".to_string()),
            ("MISE_OFFLINE", "1".to_string()),
            ("MISE_AUTO_INSTALL", "false".to_string()),
        ]
    }

    /// The agent's environment for its own commands, as the operator types it.
    pub fn agent_environment_words(&self) -> Result<String, String> {
        let mut words = vec![format!("PATH={}", self.path_value()?)];
        words.extend(
            self.mise_environment()
                .iter()
                .map(|(name, value)| format!("{name}={value}")),
        );
        let agent = ToolEnvironment::for_agent(Path::new(AGENT_HOME));
        words.push(format!("MISE_STATE_DIR={}", agent.state.display()));
        Ok(words.join(" "))
    }
}

/// The home and mise state a prefix command runs with; the cache is the prefix's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolEnvironment {
    pub home: PathBuf,
    pub state: PathBuf,
}

impl ToolEnvironment {
    /// The agent's state under its own home, as the operator's commands set it.
    pub fn for_agent(home: &Path) -> Self {
        Self {
            home: home.to_path_buf(),
            state: home.join(STATE_RELATIVE),
        }
    }

    /// The developer's state for the prefix, apart from the developer's own mise.
    pub fn for_developer(home: &Path) -> Self {
        Self {
            home: home.to_path_buf(),
            state: home.join(DEVELOPER_STATE_RELATIVE),
        }
    }

    /// `HOME` of this process, else the home directory services record for the user.
    pub fn current_home(identity: &Identity) -> Result<PathBuf, String> {
        match std::env::var_os("HOME") {
            Some(home) if Path::new(&home).is_absolute() => Ok(PathBuf::from(home)),
            _ => setup::resolve_home(&identity.username).map(PathBuf::from),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Offline,
    /// Only for the install step, which downloads the pins.
    Online,
}

/// A command that sees only the prefix: a cleared environment, `/` as its directory, the
/// prefix's mise variables, and the network only when `Online`.
pub fn prefix_command(
    prefix: &Prefix,
    environment: &ToolEnvironment,
    program: &Path,
    args: &[&str],
    network: Network,
) -> Command {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir("/")
        .env_clear()
        .env("PATH", format!("{}:{SYSTEM_PATH}", prefix.bin().display()))
        .env("HOME", &environment.home)
        .env("MISE_STATE_DIR", &environment.state);
    for (name, value) in prefix.mise_environment() {
        if network == Network::Online && name == "MISE_OFFLINE" {
            continue;
        }
        command.env(name, value);
    }
    if network == Network::Online {
        command.env("MISE_YES", "1");
    }
    command
}

/// A tool run by absolute path with a cleared environment from `/`: the agent's `PATH`, the
/// given home and the prefix's mise variables.
pub fn tool_command(
    prefix: &Prefix,
    environment: &ToolEnvironment,
    program: &Path,
    args: &[&str],
) -> Result<Command, String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir("/")
        .env_clear()
        .env("PATH", prefix.path_value()?)
        .env("HOME", &environment.home)
        .env("MISE_STATE_DIR", &environment.state)
        .envs(prefix.mise_environment());
    Ok(command)
}

/// The prefix directory itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryState {
    Settled,
    Missing,
    /// A real directory the developer owns, with another mode.
    WrongMode(u32),
    /// Anything no remedy here changes: a link, a file, another owner, an open ancestor.
    Foreign(String),
    Unreachable(String),
}

/// Every ancestor must be a real directory owned by root or the developer, and either closed to
/// group and other writes or sticky, so no other user can swap the prefix's entry.
fn ancestor_problem(ancestor: &Path, developer_uid: u32) -> Result<Option<String>, String> {
    let shown = ancestor.display();
    let metadata = fs::symlink_metadata(ancestor).map_err(|error| format!("{shown}: {error}"))?;
    let mode = metadata.mode();
    Ok(if metadata.file_type().is_symlink() {
        Some(format!("{shown} is a link"))
    } else if !metadata.is_dir() {
        Some(format!("{shown} is not a directory"))
    } else if metadata.uid() != 0 && metadata.uid() != developer_uid {
        Some(format!("{shown} is owned by uid {}", metadata.uid()))
    } else if mode & GROUP_OR_OTHER_WRITE != 0 && mode & STICKY == 0 {
        Some(format!(
            "{shown} has mode {:04o} without the sticky bit",
            mode & 0o7777
        ))
    } else {
        None
    })
}

/// Opens the directory without following a link and returns its descriptor's metadata, which
/// must be the inode checked by path.
fn opened_directory(path: &Path, checked: &fs::Metadata) -> Result<fs::Metadata, String> {
    let shown = path.display();
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("{shown}: {error}"))?;
    let opened = directory
        .metadata()
        .map_err(|error| format!("{shown}: {error}"))?;
    if (opened.dev(), opened.ino()) != (checked.dev(), checked.ino()) {
        return Err(format!("{shown} changed between its check and its open"));
    }
    Ok(opened)
}

pub fn directory_state(prefix: &Prefix, developer_uid: u32) -> DirectoryState {
    let root = prefix.root();
    let mut ancestors: Vec<&Path> = root.ancestors().skip(1).collect();
    ancestors.reverse();
    for ancestor in ancestors {
        match ancestor_problem(ancestor, developer_uid) {
            Ok(None) => {}
            Ok(Some(problem)) => return DirectoryState::Foreign(problem),
            Err(why) => return DirectoryState::Unreachable(why),
        }
    }
    let shown = root.display();
    let checked = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return DirectoryState::Missing,
        Err(error) => return DirectoryState::Unreachable(format!("{shown}: {error}")),
    };
    if checked.file_type().is_symlink() {
        return DirectoryState::Foreign(format!("{shown} is a link"));
    }
    if !checked.is_dir() {
        return DirectoryState::Foreign(format!("{shown} is not a directory"));
    }
    if checked.uid() != developer_uid {
        return DirectoryState::Foreign(format!("{shown} is owned by uid {}", checked.uid()));
    }
    match opened_directory(root, &checked) {
        Ok(opened) if opened.mode() & 0o7777 == PREFIX_MODE => DirectoryState::Settled,
        Ok(opened) => DirectoryState::WrongMode(opened.mode() & 0o7777),
        Err(why) => DirectoryState::Unreachable(why),
    }
}

pub const DIRECTORY_FOREIGN_HINT: &str = "inspect /Users/Shared/tycho and anything above it, remove what another user owns or what is a link, then run: mise run provision-agent";

fn directory_finding(state: &DirectoryState) -> Finding {
    let check = Check::PrefixDirectory;
    let wanted = format!("a real directory the developer owns, mode {PREFIX_MODE:04o}");
    match state {
        DirectoryState::Settled => Finding::new(check, Status::Present),
        DirectoryState::Missing => Finding::with_hint(
            check,
            Status::Missing,
            "mise run provision-agent creates it",
        ),
        DirectoryState::WrongMode(mode) => Finding::with_hint(
            check,
            Status::Wrong {
                found: format!("mode {mode:04o}"),
                wanted,
            },
            "mise run provision-agent sets the mode",
        ),
        DirectoryState::Foreign(found) => Finding::with_hint(
            check,
            Status::Wrong {
                found: found.clone(),
                wanted,
            },
            DIRECTORY_FOREIGN_HINT,
        ),
        DirectoryState::Unreachable(why) => Finding::unreachable(check, why.clone()),
    }
}

/// Everything beneath the prefix, the prefix included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeState {
    Closed { examined: usize },
    Absent,
    Open { first: String, count: usize },
    Unreachable(String),
}

/// A link's target, resolved against the link's directory by its components alone; `None`
/// when `..` would climb above `/`.
fn lexical_target(link: &Path, target: &Path) -> Option<PathBuf> {
    let joined = if target.is_absolute() {
        target.to_path_buf()
    } else {
        link.parent()?.join(target)
    };
    let mut resolved = PathBuf::from("/");
    for component in joined.components() {
        match component {
            Component::RootDir => resolved = PathBuf::from("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                if !resolved.pop() {
                    return None;
                }
            }
            Component::Normal(name) => resolved.push(name),
            Component::Prefix(_) => return None,
        }
    }
    Some(resolved)
}

fn entry_problem(root: &Path, path: &Path, metadata: &fs::Metadata, uid: u32) -> Option<String> {
    let shown = path.display();
    let file_type = metadata.file_type();
    if metadata.uid() != uid {
        return Some(format!("{shown} is owned by uid {}", metadata.uid()));
    }
    if file_type.is_symlink() {
        let Ok(target) = fs::read_link(path) else {
            return Some(format!("{shown} is a link that cannot be read"));
        };
        return match lexical_target(path, &target) {
            Some(resolved) if resolved.starts_with(root) => None,
            _ => Some(format!(
                "{shown} links outside the prefix, to {}",
                target.display()
            )),
        };
    }
    if !file_type.is_dir() && !file_type.is_file() {
        return Some(format!("{shown} is not a file, a directory or a link"));
    }
    let mode = metadata.mode() & 0o7777;
    (mode & GROUP_OR_OTHER_WRITE != 0).then(|| format!("{shown} has mode {mode:04o}"))
}

/// Visits every entry beneath `root`, `root` included, without following a link, and returns
/// how many it examined and what `visit` reported; more than `ENTRIES_MAX` is an error.
fn walk(
    root: &Path,
    mut visit: impl FnMut(&Path, &fs::Metadata) -> Result<Option<String>, String>,
) -> Result<(usize, Vec<String>), String> {
    let mut stack = vec![root.to_path_buf()];
    let mut examined = 0_usize;
    let mut problems = Vec::new();
    while let Some(path) = stack.pop() {
        examined = examined.saturating_add(1);
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if let Some(problem) = visit(&path, &metadata)? {
            problems.push(problem);
        }
        if !metadata.is_dir() {
            continue;
        }
        let entries =
            fs::read_dir(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("{}: {error}", path.display()))?;
            if stack.len().saturating_add(examined) >= ENTRIES_MAX {
                return Err(format!(
                    "more than {ENTRIES_MAX} entries beneath the prefix"
                ));
            }
            stack.push(entry.path());
        }
    }
    Ok((examined, problems))
}

/// Walks the prefix without following a link: owner, write bits and link targets of every
/// entry, bounded by `ENTRIES_MAX`; the disabled project configuration must not exist.
pub fn tree_state(prefix: &Prefix, developer_uid: u32) -> TreeState {
    let root = prefix.root();
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return TreeState::Absent,
        Err(error) => return TreeState::Unreachable(format!("{}: {error}", root.display())),
        Ok(_) => {}
    }
    let disabled = prefix.disabled_project_config();
    let walked = walk(root, |path, metadata| {
        if path == disabled {
            return Ok(Some(format!(
                "{} exists, and mise would read it as project configuration",
                path.display()
            )));
        }
        Ok(entry_problem(root, path, metadata, developer_uid))
    });
    match walked {
        Err(why) => TreeState::Unreachable(why),
        Ok((examined, problems)) => {
            problems
                .first()
                .map_or(TreeState::Closed { examined }, |first| TreeState::Open {
                    first: first.clone(),
                    count: problems.len(),
                })
        }
    }
}

const TREE_OPEN_HINT: &str = "as the developer: chmod -R go-w /Users/Shared/tycho, and remove any entry another user owns and any link that leaves the prefix";

fn tree_finding(check: Check, state: &TreeState, hint: &str) -> Finding {
    match state {
        TreeState::Closed { examined: 0 } => {
            Finding::unreachable(check, "the walk examined no entry")
        }
        TreeState::Closed { examined } => Finding::with_hint(
            check,
            Status::Present,
            format!("examined {examined} entries"),
        ),
        TreeState::Absent => Finding::with_hint(
            check,
            Status::Missing,
            "mise run provision-agent creates the prefix",
        ),
        TreeState::Open { first, count } => Finding::with_hint(
            check,
            Status::Wrong {
                found: format!("{count} entries open, first {first}"),
                wanted: "nothing beneath the prefix that the checked user can change".to_string(),
            },
            hint,
        ),
        TreeState::Unreachable(why) => Finding::unreachable(check, why.clone()),
    }
}

/// Whether this process may write an entry, asked of the kernel with `access(W_OK)`, so
/// access lists and group memberships count as well as the mode bits. A link is not asked:
/// its directory decides whether it can be replaced.
fn writable_problem(path: &Path, metadata: &fs::Metadata) -> Result<Option<String>, String> {
    if metadata.file_type().is_symlink() {
        return Ok(None);
    }
    match nix::unistd::access(path, nix::unistd::AccessFlags::W_OK) {
        Ok(()) => Ok(Some(format!("{} is writable", path.display()))),
        Err(nix::errno::Errno::EACCES | nix::errno::Errno::EPERM | nix::errno::Errno::EROFS) => {
            Ok(None)
        }
        Err(error) => Err(format!("access {}: {error}", path.display())),
    }
}

/// The agent's own walk of the prefix: nothing it can write, bounded by `ENTRIES_MAX`.
pub fn writable_state(prefix: &Prefix) -> TreeState {
    let root = prefix.root();
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return TreeState::Absent,
        Err(error) => return TreeState::Unreachable(format!("{}: {error}", root.display())),
        Ok(_) => {}
    }
    match walk(root, writable_problem) {
        Err(why) => TreeState::Unreachable(why),
        Ok((examined, problems)) => {
            problems
                .first()
                .map_or(TreeState::Closed { examined }, |first| TreeState::Open {
                    first: first.clone(),
                    count: problems.len(),
                })
        }
    }
}

/// A tool as the prefix serves it: mise itself, or a pinned install run by absolute path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolState {
    Pinned,
    Absent,
    WrongVersion(String),
    /// Runs, but from somewhere else, or not as a working program.
    WrongSource(String),
    /// The install differs from the digest `station.json` records.
    Modified(String),
    Unreachable(String),
}

fn decode_mise_version(stdout: &str) -> Option<String> {
    let version = setup::first_line(stdout).split_whitespace().next()?;
    let numeric = !version.is_empty()
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()));
    numeric.then(|| version.to_string())
}

fn regular_file(path: &Path) -> Result<bool, ToolState> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(ToolState::Absent),
        Err(error) => Err(ToolState::Unreachable(format!(
            "{}: {error}",
            path.display()
        ))),
    }
}

pub fn mise_state(prefix: &Prefix, environment: &ToolEnvironment) -> ToolState {
    let mise = prefix.mise();
    match regular_file(&mise) {
        Ok(true) => {}
        Ok(false) => {
            return ToolState::WrongSource(format!("{} is not a regular file", mise.display()));
        }
        Err(state) => return state,
    }
    let command = prefix_command(prefix, environment, &mise, &["--version"], Network::Offline);
    match setup::run_bounded_within(command, TOOL_PROBE_TIMEOUT) {
        Capture::ExecutableNotFound => ToolState::Absent,
        Capture::Unreachable(why) => ToolState::Unreachable(why),
        Capture::Ran {
            success: false,
            code,
            stderr,
            ..
        } => ToolState::WrongSource(format!(
            "mise --version exits {code:?}: {}",
            setup::first_line(&stderr)
        )),
        Capture::Ran {
            success: true,
            stdout,
            ..
        } => match decode_mise_version(&stdout) {
            Some(version) if version == MISE_PINNED_VERSION => ToolState::Pinned,
            Some(version) => ToolState::WrongVersion(version),
            None => ToolState::Unreachable(format!(
                "unrecognised mise --version output: {:?}",
                setup::first_line(&stdout)
            )),
        },
    }
}

/// What `mise which <tool>` answered.
#[derive(Debug, PartialEq, Eq)]
enum Which {
    Path(PathBuf),
    /// Installed under some version, but no configuration selects an installed one.
    NotActive,
    /// No install of the tool at all.
    NotInstalled,
    Unrecognised(String),
}

fn decode_which(success: bool, stdout: &str, stderr: &str) -> Which {
    let first_out = setup::first_line(stdout);
    let first_err = setup::first_line(stderr);
    if success {
        return if first_out.starts_with('/') && stdout.lines().count() == 1 {
            Which::Path(PathBuf::from(first_out))
        } else {
            Which::Unrecognised(first_out.to_string())
        };
    }
    if first_err.contains("is a mise bin however it is not currently active") {
        Which::NotActive
    } else if first_err.contains("is not a mise bin") {
        Which::NotInstalled
    } else {
        Which::Unrecognised(first_err.to_string())
    }
}

/// The path the prefix's mise resolves the tool to; the install step records it only when it
/// is the pinned install's executable.
pub fn which_tool(
    prefix: &Prefix,
    environment: &ToolEnvironment,
    tool: AgentTool,
    pin: &str,
) -> ToolState {
    let command = prefix_command(
        prefix,
        environment,
        &prefix.mise(),
        &["which", tool.name()],
        Network::Offline,
    );
    match setup::run_bounded_within(command, TOOL_PROBE_TIMEOUT) {
        Capture::ExecutableNotFound => ToolState::Absent,
        Capture::Unreachable(why) => ToolState::Unreachable(why),
        Capture::Ran {
            success,
            stdout,
            stderr,
            ..
        } => match decode_which(success, &stdout, &stderr) {
            Which::Path(path) if path == prefix.tool_binary(tool, pin) => ToolState::Pinned,
            Which::Path(path) => ToolState::WrongSource(path.display().to_string()),
            Which::NotActive | Which::NotInstalled => ToolState::Absent,
            Which::Unrecognised(line) => ToolState::Unreachable(format!(
                "unrecognised mise which {} result: {line:?}",
                tool.name()
            )),
        },
    }
}

fn version_state(
    prefix: &Prefix,
    environment: &ToolEnvironment,
    tool: AgentTool,
    pin: &str,
) -> ToolState {
    let binary = prefix.tool_binary(tool, pin);
    let command = match tool_command(prefix, environment, &binary, &["--version"]) {
        Ok(command) => command,
        Err(why) => return ToolState::Unreachable(why),
    };
    match setup::run_bounded_within(command, TOOL_PROBE_TIMEOUT) {
        Capture::ExecutableNotFound => ToolState::Absent,
        Capture::Unreachable(why) => ToolState::Unreachable(why),
        Capture::Ran {
            success: false,
            code,
            stderr,
            ..
        } => ToolState::WrongSource(format!(
            "{} --version exits {code:?}: {}",
            binary.display(),
            setup::first_line(&stderr)
        )),
        Capture::Ran {
            success: true,
            stdout,
            ..
        } => match tool.decode_version(&stdout) {
            Some(version) if version == pin => ToolState::Pinned,
            Some(version) => ToolState::WrongVersion(version),
            None => ToolState::Unreachable(format!(
                "unrecognised {} --version output: {:?}",
                tool.name(),
                setup::first_line(&stdout)
            )),
        },
    }
}

/// The record `station.json` holds for the tool, which must name the pinned install's
/// executable.
fn recorded_tool<'manifest>(
    prefix: &Prefix,
    manifest: &'manifest ManifestRead,
    tool: AgentTool,
    pin: &str,
) -> Result<&'manifest ToolRecord, ToolState> {
    let manifest = match manifest {
        ManifestRead::Present(manifest) => manifest,
        ManifestRead::Absent => return Err(ToolState::Absent),
        ManifestRead::Unrecognised => {
            return Err(ToolState::Modified(
                "an unrecognised station.json".to_string(),
            ));
        }
        ManifestRead::Unreadable(why) => return Err(ToolState::Unreachable(why.clone())),
    };
    let Some(record) = manifest.tools.get(tool.name()) else {
        return Err(ToolState::Absent);
    };
    let expected = prefix.tool_binary(tool, pin);
    if record.version != pin || record.path != expected {
        return Err(ToolState::WrongSource(format!(
            "station.json records {} {}",
            record.version,
            record.path.display()
        )));
    }
    Ok(record)
}

/// The install has the digest `station.json` records, and only then is its executable run,
/// by absolute path, to answer with its pin. No shim and no mise lookup is involved.
pub fn installed_tool_state(
    prefix: &Prefix,
    environment: &ToolEnvironment,
    manifest: &ManifestRead,
    tool: AgentTool,
    pin: &str,
) -> ToolState {
    let binary = prefix.tool_binary(tool, pin);
    match regular_file(&binary) {
        Ok(true) => {}
        Ok(false) => {
            return ToolState::WrongSource(format!("{} is not a regular file", binary.display()));
        }
        Err(state) => return state,
    }
    let record = match recorded_tool(prefix, manifest, tool, pin) {
        Ok(record) => record,
        Err(state) => return state,
    };
    match install_sha256(&prefix.installs(tool, pin)) {
        Ok(digest) if digest == record.install_sha256 => {}
        Ok(digest) => return ToolState::Modified(format!("install sha256 {digest}")),
        Err(why) => return ToolState::Unreachable(why),
    }
    version_state(prefix, environment, tool, pin)
}

const TOOLS_HINT: &str = "mise run provision-agent installs the pins into the prefix";

fn tool_status(state: &ToolState, wanted: &str) -> Status {
    match state {
        ToolState::Pinned => Status::Present,
        ToolState::Absent => Status::Missing,
        ToolState::WrongVersion(found)
        | ToolState::WrongSource(found)
        | ToolState::Modified(found) => Status::Wrong {
            found: found.clone(),
            wanted: wanted.to_string(),
        },
        ToolState::Unreachable(why) => Status::Unreachable { why: why.clone() },
    }
}

pub fn tool_finding(check: Check, state: &ToolState, wanted: &str) -> Finding {
    let status = tool_status(state, wanted);
    if status.is_pass() {
        Finding::new(check, status)
    } else {
        Finding::with_hint(check, status, TOOLS_HINT)
    }
}

/// The station binaries against what the install step recorded and the checkout's commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StationState {
    Current,
    Absent,
    /// The file is not the one the install step recorded.
    Modified(String),
    /// Built from another commit, or from a tree with uncommitted changes.
    Stale {
        installed: String,
        checkout: String,
    },
    Unreachable(String),
}

fn station_digest(record: &StationRecord, binary: StationBinary) -> &str {
    match binary {
        StationBinary::Xtask => &record.xtask,
        StationBinary::Tycho => &record.tycho,
    }
}

pub fn station_state(
    prefix: &Prefix,
    binary: StationBinary,
    manifest: &ManifestRead,
    checkout: &Result<String, String>,
) -> StationState {
    let path = prefix.binary(binary);
    let bytes = match read_regular(&path, BINARY_MAX_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return StationState::Absent,
        Err(error) => return StationState::Modified(format!("{}: {error}", path.display())),
    };
    let record = match manifest {
        ManifestRead::Present(Manifest {
            station: Some(record),
            ..
        }) => record,
        ManifestRead::Present(_) | ManifestRead::Absent => return StationState::Absent,
        ManifestRead::Unrecognised => {
            return StationState::Modified("an unrecognised station.json".to_string());
        }
        ManifestRead::Unreadable(why) => return StationState::Unreachable(why.clone()),
    };
    let digest = sha256_hex(&bytes);
    if digest != station_digest(record, binary) {
        return StationState::Modified(format!("sha256 {digest}"));
    }
    let head = match checkout {
        Ok(head) => head,
        Err(why) => return StationState::Unreachable(why.clone()),
    };
    if !record.clean {
        return StationState::Stale {
            installed: format!("{} with uncommitted changes", record.commit),
            checkout: head.clone(),
        };
    }
    if &record.commit == head {
        StationState::Current
    } else {
        StationState::Stale {
            installed: record.commit.clone(),
            checkout: head.clone(),
        }
    }
}

const STATION_HINT: &str = "mise run provision-agent builds and installs them from this checkout";

fn station_finding(binary: StationBinary, state: &StationState) -> Finding {
    let check = binary.check();
    let status = match state {
        StationState::Current => return Finding::new(check, Status::Present),
        StationState::Absent => Status::Missing,
        StationState::Modified(found) => Status::Wrong {
            found: found.clone(),
            wanted: "the digest recorded in station.json".to_string(),
        },
        StationState::Stale {
            installed,
            checkout,
        } => Status::Wrong {
            found: format!("built from {installed}"),
            wanted: format!("built from {checkout}"),
        },
        StationState::Unreachable(why) => return Finding::unreachable(check, why.clone()),
    };
    Finding::with_hint(check, status, STATION_HINT)
}

/// `git rev-parse HEAD` in the checkout this xtask was built from.
pub fn checkout_head() -> Result<String, String> {
    let mut command = git_command();
    command
        .args(["rev-parse", "HEAD"])
        .current_dir(setup::workspace_root());
    match setup::run_bounded_within(command, TOOL_PROBE_TIMEOUT) {
        Capture::ExecutableNotFound => Err("git is not on PATH".to_string()),
        Capture::Unreachable(why) => Err(why),
        Capture::Ran {
            success: true,
            stdout,
            ..
        } if is_commit(setup::first_line(&stdout)) => Ok(setup::first_line(&stdout).to_string()),
        Capture::Ran { stdout, stderr, .. } => Err(format!(
            "unrecognised git rev-parse HEAD result: {:?} {:?}",
            setup::first_line(&stdout),
            setup::first_line(&stderr)
        )),
    }
}

/// Everything the developer side reads of the prefix, kept so a remedy decides on the same
/// facts its finding reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub directory: DirectoryState,
    pub tree: TreeState,
    pub mise: ToolState,
    pub tools: Vec<(AgentTool, Result<String, String>, ToolState)>,
    pub station: Vec<(StationBinary, StationState)>,
}

/// The developer's view of one tool: mise resolves it to the pinned install, and the install
/// runs and matches its record.
fn developer_tool_state(
    prefix: &Prefix,
    environment: &ToolEnvironment,
    manifest: &ManifestRead,
    tool: AgentTool,
    pin: &str,
) -> ToolState {
    match which_tool(prefix, environment, tool, pin) {
        ToolState::Pinned => installed_tool_state(prefix, environment, manifest, tool, pin),
        other => other,
    }
}

impl Probe {
    pub fn read(prefix: &Prefix, identity: &Identity) -> Self {
        let uid = identity.uid;
        let environment = ToolEnvironment::current_home(identity)
            .map(|home| ToolEnvironment::for_developer(&home))
            .map_err(|why| format!("home unknown: {why}"));
        let manifest = read_manifest(&prefix.manifest());
        let mise = match &environment {
            Ok(environment) => mise_state(prefix, environment),
            Err(why) => ToolState::Unreachable(why.clone()),
        };
        let tools = AgentTool::ALL
            .iter()
            .map(|&tool| {
                let pin = pinned_version(tool);
                let state = match (&pin, &environment) {
                    (Ok(pin), Ok(environment)) => {
                        developer_tool_state(prefix, environment, &manifest, tool, pin)
                    }
                    (Err(why), _) | (_, Err(why)) => ToolState::Unreachable(why.clone()),
                };
                (tool, pin, state)
            })
            .collect();
        let head = checkout_head();
        let station = StationBinary::ALL
            .iter()
            .map(|&binary| (binary, station_state(prefix, binary, &manifest, &head)))
            .collect();
        Self {
            directory: directory_state(prefix, uid),
            tree: tree_state(prefix, uid),
            mise,
            tools,
            station,
        }
    }

    pub fn findings(&self) -> Vec<Finding> {
        let mut findings = vec![
            directory_finding(&self.directory),
            tree_finding(Check::PrefixTree, &self.tree, TREE_OPEN_HINT),
            tool_finding(Check::PrefixMise, &self.mise, MISE_PINNED_VERSION),
        ];
        findings.extend(self.tools.iter().map(|(tool, pin, state)| {
            tool_finding(
                tool.developer_check(),
                state,
                pin.as_deref().unwrap_or("the pinned version"),
            )
        }));
        findings.extend(
            self.station
                .iter()
                .map(|(binary, state)| station_finding(*binary, state)),
        );
        findings
    }
}

const AGENT_WRITABLE_HINT: &str = "as the developer: chmod -R go-w /Users/Shared/tycho and remove any access list entry that grants the agent a write (ls -le shows them)";

/// The agent's own view: nothing in the prefix it can write, the prefix's mise, and each
/// tool run by absolute path from its uid.
pub fn agent_findings(identity: &Identity) -> Vec<Finding> {
    let prefix = Prefix::production();
    let mut findings = vec![tree_finding(
        Check::AgentPrefixWritable,
        &writable_state(&prefix),
        AGENT_WRITABLE_HINT,
    )];
    let environment = match ToolEnvironment::current_home(identity) {
        Ok(home) => ToolEnvironment::for_agent(&home),
        Err(why) => {
            findings.extend(
                std::iter::once(Check::AgentPrefixMise)
                    .chain(AgentTool::ALL.iter().map(|tool| tool.agent_check()))
                    .map(|check| Finding::unreachable(check, format!("home unknown: {why}"))),
            );
            return findings;
        }
    };
    findings.push(tool_finding(
        Check::AgentPrefixMise,
        &mise_state(&prefix, &environment),
        MISE_PINNED_VERSION,
    ));
    let manifest = read_manifest(&prefix.manifest());
    for tool in AgentTool::ALL {
        let finding = match pinned_version(tool) {
            Ok(pin) => tool_finding(
                tool.agent_check(),
                &installed_tool_state(&prefix, &environment, &manifest, tool, &pin),
                &pin,
            ),
            Err(why) => Finding::unreachable(tool.agent_check(), why),
        };
        findings.push(finding);
    }
    findings
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    fn scratch(name: &str) -> PathBuf {
        let base = fs::canonicalize(std::env::temp_dir())
            .expect("resolve the temporary directory")
            .join(format!("xtask-prefix-{}-{name}", std::process::id()));
        drop(fs::remove_dir_all(&base));
        fs::DirBuilder::new()
            .mode(0o755)
            .create(&base)
            .expect("create the scratch prefix");
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).expect("chmod");
        base
    }

    fn own_uid(path: &Path) -> u32 {
        fs::symlink_metadata(path).expect("stat").uid()
    }

    #[test]
    fn the_agent_pins_come_from_the_repository_mise_toml() {
        assert_eq!(pinned_version(AgentTool::Claude), Ok("2.1.295".to_string()));
        assert_eq!(pinned_version(AgentTool::Codex), Ok("0.160.1".to_string()));
        assert_eq!(pinned_version(AgentTool::Zmx), Ok("0.8.1".to_string()));
        assert_eq!(
            global_config(),
            Ok("[tools]\nclaude = \"2.1.295\"\ncodex = \"0.160.1\"\nzmx = \"0.8.1\"\n".to_string())
        );
    }

    #[test]
    fn decodes_pin_lines_and_rejects_the_unrecognised() {
        let toml = "min_version = \"1\"\n[tools]\nzmx = \"0.8.1\"\nrust = { version = \"1.94\" }\n[tasks.ci]\nclaude = \"9\"\n";
        assert_eq!(
            decode_pin(toml, "zmx"),
            PinLine::Pinned("0.8.1".to_string())
        );
        assert_eq!(decode_pin(toml, "claude"), PinLine::Absent);
        assert!(matches!(decode_pin(toml, "rust"), PinLine::Unrecognised(_)));
        let twice = "[tools]\nzmx = \"0.8.1\"\nzmx = \"0.8.2\"\n";
        assert!(matches!(decode_pin(twice, "zmx"), PinLine::Unrecognised(_)));
        for value in ["\"\"", "0.8.1", "\"0.8\"1\""] {
            let line = format!("[tools]\nzmx = {value}\n");
            assert!(
                matches!(decode_pin(&line, "zmx"), PinLine::Unrecognised(_)),
                "{value}"
            );
        }
    }

    const AGENT_WORDS: &str = "PATH=/Users/Shared/tycho/bin:/Users/Shared/tycho/mise/installs/claude/2.1.295:/Users/Shared/tycho/mise/installs/codex/0.160.1/bin:/Users/Shared/tycho/mise/installs/zmx/0.8.1:/usr/bin:/bin MISE_DATA_DIR=/Users/Shared/tycho/mise MISE_GLOBAL_CONFIG_FILE=/Users/Shared/tycho/mise.toml MISE_CACHE_DIR=/Users/Shared/tycho/cache MISE_OVERRIDE_CONFIG_FILENAMES=/Users/Shared/tycho/no-project-config MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES=none MISE_OFFLINE=1 MISE_AUTO_INSTALL=false MISE_STATE_DIR=/Users/tycho-agent/.local/state/mise";

    #[test]
    fn the_agent_environment_puts_the_pinned_installs_on_path_and_no_shim() {
        let prefix = Prefix::production();
        assert_eq!(
            prefix.agent_environment_words(),
            Ok(AGENT_WORDS.to_string())
        );
        assert!(!AGENT_WORDS.contains("shims"));
        assert_eq!(
            prefix.tool_binary(AgentTool::Codex, "0.160.1"),
            PathBuf::from("/Users/Shared/tycho/mise/installs/codex/0.160.1/bin/codex")
        );
        assert_eq!(
            prefix.tool_binary(AgentTool::Claude, "2.1.295"),
            PathBuf::from("/Users/Shared/tycho/mise/installs/claude/2.1.295/claude")
        );
    }

    #[test]
    fn a_prefix_command_sees_only_the_prefix_from_the_root_directory() {
        let prefix = Prefix::production();
        let environment = ToolEnvironment::for_agent(Path::new("/Users/tycho-agent"));
        let command = prefix_command(
            &prefix,
            &environment,
            &prefix.mise(),
            &["--version"],
            Network::Offline,
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("/")));
        let pairs: Vec<(String, String)> = command
            .get_envs()
            .filter_map(|(name, value)| {
                Some((
                    name.to_string_lossy().into_owned(),
                    value?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        let mut names: Vec<&str> = pairs.iter().map(|(name, _)| name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "HOME",
                "MISE_AUTO_INSTALL",
                "MISE_CACHE_DIR",
                "MISE_DATA_DIR",
                "MISE_GLOBAL_CONFIG_FILE",
                "MISE_OFFLINE",
                "MISE_OVERRIDE_CONFIG_FILENAMES",
                "MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES",
                "MISE_STATE_DIR",
                "PATH"
            ]
        );
        for expected in [
            ("MISE_OFFLINE", "1"),
            ("MISE_AUTO_INSTALL", "false"),
            ("MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES", "none"),
            ("MISE_CACHE_DIR", "/Users/Shared/tycho/cache"),
        ] {
            assert!(
                pairs.contains(&(expected.0.to_string(), expected.1.to_string())),
                "{expected:?}"
            );
        }
        let online = prefix_command(&prefix, &environment, &prefix.mise(), &[], Network::Online);
        assert!(online.get_envs().all(|(name, _)| name != "MISE_OFFLINE"));
        assert!(
            online
                .get_envs()
                .any(|(name, value)| name == "MISE_AUTO_INSTALL" && value.is_some())
        );
    }

    #[test]
    fn a_settled_prefix_reads_settled_and_a_wide_one_reads_its_mode() {
        let root = scratch("settled");
        let uid = own_uid(&root);
        let prefix = Prefix::at(root.clone());
        assert_eq!(directory_state(&prefix, uid), DirectoryState::Settled);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o775)).expect("chmod");
        assert_eq!(
            directory_state(&prefix, uid),
            DirectoryState::WrongMode(0o775)
        );
        assert!(matches!(
            directory_state(&prefix, uid.wrapping_add(1)),
            DirectoryState::Foreign(_)
        ));
        let missing = Prefix::at(root.join("absent"));
        assert!(matches!(
            directory_state(&missing, uid),
            DirectoryState::Foreign(why) if why.contains("without the sticky bit")
        ));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(directory_state(&missing, uid), DirectoryState::Missing);
        fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn a_linked_prefix_or_a_linked_ancestor_is_foreign() {
        let base = scratch("linked");
        let uid = own_uid(&base);
        let real = base.join("real");
        fs::DirBuilder::new()
            .mode(0o755)
            .create(&real)
            .expect("mkdir");
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("plant the link");
        assert!(matches!(
            directory_state(&Prefix::at(link.clone()), uid),
            DirectoryState::Foreign(why) if why.contains("is a link")
        ));
        fs::DirBuilder::new()
            .mode(0o755)
            .create(real.join("inner"))
            .expect("mkdir");
        assert!(matches!(
            directory_state(&Prefix::at(link.join("inner")), uid),
            DirectoryState::Foreign(why) if why.contains("is a link")
        ));
        fs::set_permissions(&base, fs::Permissions::from_mode(0o777)).expect("chmod");
        assert!(matches!(
            directory_state(&Prefix::at(real.clone()), uid),
            DirectoryState::Foreign(why) if why.contains("without the sticky bit")
        ));
        fs::set_permissions(&base, fs::Permissions::from_mode(0o1777)).expect("chmod");
        assert_eq!(
            directory_state(&Prefix::at(real), uid),
            DirectoryState::Settled
        );
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).expect("chmod");
        fs::remove_dir_all(&base).expect("clean up");
    }

    #[test]
    fn the_walk_counts_what_it_examined_and_reports_every_open_entry() {
        let root = scratch("walk");
        let uid = own_uid(&root);
        let bin = root.join("bin");
        fs::DirBuilder::new()
            .mode(0o755)
            .create(&bin)
            .expect("mkdir");
        fs::write(bin.join("mise"), b"#!/bin/sh\n").expect("write");
        fs::set_permissions(bin.join("mise"), fs::Permissions::from_mode(0o755)).expect("chmod");
        std::os::unix::fs::symlink("bin/mise", root.join("shim")).expect("link");
        let prefix = Prefix::at(root.clone());
        assert_eq!(tree_state(&prefix, uid), TreeState::Closed { examined: 4 });

        fs::set_permissions(bin.join("mise"), fs::Permissions::from_mode(0o775)).expect("chmod");
        std::os::unix::fs::symlink("/usr/bin/true", root.join("outside")).expect("link");
        std::os::unix::fs::symlink("../../escape", bin.join("climb")).expect("link");
        match tree_state(&prefix, uid) {
            TreeState::Open { count, .. } => assert_eq!(count, 3),
            other => panic!("expected an open tree, got {other:?}"),
        }
        assert!(matches!(
            tree_state(&prefix, uid.wrapping_add(1)),
            TreeState::Open { .. }
        ));
        assert_eq!(
            tree_state(&Prefix::at(root.join("absent")), uid),
            TreeState::Absent
        );
        fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn a_walk_over_its_entry_bound_is_unreachable_not_truncated() {
        let root = scratch("bound");
        let uid = own_uid(&root);
        for index in 0..ENTRIES_MAX {
            fs::write(root.join(format!("f{index}")), b"").expect("write");
        }
        assert!(matches!(
            tree_state(&Prefix::at(root.clone()), uid),
            TreeState::Unreachable(why) if why.contains("more than")
        ));
        fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn an_empty_walk_or_an_open_tree_never_passes() {
        assert!(
            !tree_finding(
                Check::PrefixTree,
                &TreeState::Closed { examined: 0 },
                TREE_OPEN_HINT
            )
            .status
            .is_pass()
        );
        let open = TreeState::Open {
            first: "x".to_string(),
            count: 1,
        };
        assert!(
            !tree_finding(Check::PrefixTree, &open, TREE_OPEN_HINT)
                .status
                .is_pass()
        );
        let closed = tree_finding(
            Check::PrefixTree,
            &TreeState::Closed { examined: 9 },
            TREE_OPEN_HINT,
        );
        assert!(closed.status.is_pass());
        assert_eq!(closed.hint.as_deref(), Some("examined 9 entries"));
    }

    #[test]
    fn link_targets_resolve_by_their_components() {
        let link = Path::new("/p/mise/installs/claude/latest");
        assert_eq!(
            lexical_target(link, Path::new("./2.1.295")),
            Some(PathBuf::from("/p/mise/installs/claude/2.1.295"))
        );
        assert_eq!(
            lexical_target(link, Path::new("../../../../x")),
            Some(PathBuf::from("/x"))
        );
        assert_eq!(lexical_target(Path::new("/a"), Path::new("../../x")), None);
        assert_eq!(
            lexical_target(link, Path::new("/p/bin/mise")),
            Some(PathBuf::from("/p/bin/mise"))
        );
    }

    #[test]
    fn decodes_mise_versions_and_which_answers_and_rejects_the_unrecognised() {
        assert_eq!(
            decode_mise_version("2026.9.13 macos-arm64 (2026-09-24)\n"),
            Some("2026.9.13".to_string())
        );
        assert_eq!(decode_mise_version("mise WARN something\n"), None);
        assert_eq!(decode_mise_version(""), None);
        assert_eq!(
            decode_which(true, "/p/mise/installs/claude/2.1.295/claude\n", ""),
            Which::Path(PathBuf::from("/p/mise/installs/claude/2.1.295/claude"))
        );
        assert!(matches!(
            decode_which(true, "claude\n", ""),
            Which::Unrecognised(_)
        ));
        assert!(matches!(
            decode_which(true, "/a\n/b\n", ""),
            Which::Unrecognised(_)
        ));
        let inactive = "mise ERROR claude is a mise bin however it is not currently active. Use `mise use` to activate it in this directory.\nmise ERROR Version: 2026.9.13 macos-arm64 (2026-09-24)\n";
        assert_eq!(decode_which(false, "", inactive), Which::NotActive);
        let absent =
            "mise ERROR nosuchtool is not a mise bin. Perhaps you need to install it first.\n";
        assert_eq!(decode_which(false, "", absent), Which::NotInstalled);
        assert!(matches!(
            decode_which(
                false,
                "",
                "mise ERROR Config files in /x are not trusted.\n"
            ),
            Which::Unrecognised(_)
        ));
    }

    fn station(xtask: String) -> Manifest {
        Manifest {
            station: Some(StationRecord {
                commit: "a".repeat(40),
                clean: true,
                xtask,
                tycho: "c".repeat(64),
            }),
            ..Manifest::default()
        }
    }

    #[test]
    fn a_station_binary_is_current_only_at_the_recorded_digest_and_the_checkout_commit() {
        let root = scratch("station");
        fs::DirBuilder::new()
            .mode(0o755)
            .create(root.join("bin"))
            .expect("mkdir");
        let prefix = Prefix::at(root.clone());
        fs::write(prefix.binary(StationBinary::Xtask), b"xtask").expect("write");
        let recorded = station(sha256_hex(b"xtask"));
        let head = Ok("a".repeat(40));
        let state = |manifest: &Manifest, head: &Result<String, String>| {
            station_state(
                &prefix,
                StationBinary::Xtask,
                &ManifestRead::Present(manifest.clone()),
                head,
            )
        };
        assert_eq!(state(&recorded, &head), StationState::Current);
        assert!(matches!(
            state(&recorded, &Ok("d".repeat(40))),
            StationState::Stale { .. }
        ));
        let mut dirty = recorded.clone();
        if let Some(record) = dirty.station.as_mut() {
            record.clean = false;
        }
        assert!(matches!(state(&dirty, &head), StationState::Stale { .. }));
        assert!(matches!(
            state(&recorded, &Err("git is not on PATH".to_string())),
            StationState::Unreachable(_)
        ));
        assert_eq!(state(&Manifest::default(), &head), StationState::Absent);
        fs::write(prefix.binary(StationBinary::Xtask), b"replaced").expect("write");
        assert!(matches!(state(&recorded, &head), StationState::Modified(_)));
        assert_eq!(
            station_state(
                &prefix,
                StationBinary::Tycho,
                &ManifestRead::Present(recorded),
                &head
            ),
            StationState::Absent
        );
        fs::remove_dir_all(&root).expect("clean up");
    }

    /// A scratch prefix holding one tool install whose executable is a script printing the
    /// version line the real tool prints.
    fn scratch_install(name: &str, tool: AgentTool, pin: &str, answer: &str) -> Prefix {
        let root = scratch(name);
        let prefix = Prefix::at(root);
        let binary = prefix.tool_binary(tool, pin);
        fs::create_dir_all(binary.parent().expect("a parent")).expect("mkdir");
        fs::write(&binary, format!("#!/bin/sh\necho '{answer}'\n")).expect("write");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).expect("chmod");
        prefix
    }

    fn recorded(prefix: &Prefix, tool: AgentTool, pin: &str) -> Manifest {
        let mut manifest = Manifest::default();
        manifest.tools.insert(
            tool.name().to_string(),
            ToolRecord {
                version: pin.to_string(),
                path: prefix.tool_binary(tool, pin),
                install_sha256: install_sha256(&prefix.installs(tool, pin)).expect("digest"),
            },
        );
        manifest
    }

    #[test]
    fn an_install_runs_by_absolute_path_at_its_pin_and_its_recorded_digest() {
        let prefix = scratch_install("install", AgentTool::Zmx, "0.8.1", "zmx\t\t0.8.1");
        let environment = ToolEnvironment::for_agent(prefix.root());
        let manifest = ManifestRead::Present(recorded(&prefix, AgentTool::Zmx, "0.8.1"));
        let state = |manifest: &ManifestRead| {
            installed_tool_state(&prefix, &environment, manifest, AgentTool::Zmx, "0.8.1")
        };
        assert_eq!(state(&manifest), ToolState::Pinned);
        assert_eq!(state(&ManifestRead::Absent), ToolState::Absent);
        assert!(matches!(
            state(&ManifestRead::Unrecognised),
            ToolState::Modified(_)
        ));
        assert_eq!(
            state(&ManifestRead::Present(Manifest::default())),
            ToolState::Absent
        );
        let mut elsewhere = recorded(&prefix, AgentTool::Zmx, "0.8.1");
        if let Some(record) = elsewhere.tools.get_mut("zmx") {
            record.path = PathBuf::from("/usr/local/bin/zmx");
        }
        assert!(matches!(
            state(&ManifestRead::Present(elsewhere)),
            ToolState::WrongSource(_)
        ));
        let binary = prefix.tool_binary(AgentTool::Zmx, "0.8.1");
        let ran = prefix.root().join("ran");
        fs::write(
            &binary,
            format!("#!/bin/sh\ntouch {}\necho 'zmx\t\t0.8.1'\n", ran.display()),
        )
        .expect("write");
        assert!(matches!(state(&manifest), ToolState::Modified(_)));
        assert!(!ran.exists(), "a modified install must not run");
        fs::write(&binary, "#!/bin/sh\necho 'zmx\t\t0.9.0'\n").expect("write");
        let rerecorded = ManifestRead::Present(recorded(&prefix, AgentTool::Zmx, "0.8.1"));
        assert_eq!(
            state(&rerecorded),
            ToolState::WrongVersion("0.9.0".to_string())
        );
        fs::remove_dir_all(prefix.root()).expect("clean up");
    }

    #[test]
    fn a_tool_without_its_install_is_absent_before_anything_runs() {
        let root = scratch("noinstall");
        let prefix = Prefix::at(root.clone());
        let environment = ToolEnvironment::for_agent(&root);
        assert_eq!(
            installed_tool_state(
                &prefix,
                &environment,
                &ManifestRead::Absent,
                AgentTool::Claude,
                "2.1.295"
            ),
            ToolState::Absent
        );
        assert_eq!(mise_state(&prefix, &environment), ToolState::Absent);
        fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn the_agents_walk_asks_the_kernel_and_counts_what_it_examined() {
        let root = scratch("writable");
        let prefix = Prefix::at(root.clone());
        fs::write(root.join("file"), b"").expect("write");
        std::os::unix::fs::symlink("file", root.join("link")).expect("link");
        match writable_state(&prefix) {
            TreeState::Open { count, .. } => assert_eq!(count, 2, "the directory and the file"),
            other => panic!("the owner can write its scratch prefix, got {other:?}"),
        }
        fs::set_permissions(root.join("file"), fs::Permissions::from_mode(0o444)).expect("chmod");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).expect("chmod");
        assert_eq!(writable_state(&prefix), TreeState::Closed { examined: 3 });
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(
            writable_state(&Prefix::at(root.join("absent"))),
            TreeState::Absent
        );
        fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn the_disabled_project_configuration_must_not_exist() {
        let root = scratch("disabled");
        let uid = own_uid(&root);
        let prefix = Prefix::at(root.clone());
        assert_eq!(tree_state(&prefix, uid), TreeState::Closed { examined: 1 });
        fs::write(prefix.disabled_project_config(), b"[tools]\n").expect("write");
        assert!(matches!(
            tree_state(&prefix, uid),
            TreeState::Open { first, .. } if first.contains("project configuration")
        ));
        fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn every_tool_state_but_pinned_fails_its_finding() {
        for state in [
            ToolState::Absent,
            ToolState::WrongVersion("1".to_string()),
            ToolState::WrongSource("/elsewhere".to_string()),
            ToolState::Modified("sha256".to_string()),
            ToolState::Unreachable("x".to_string()),
        ] {
            assert!(
                !tool_finding(Check::PrefixClaude, &state, "2")
                    .status
                    .is_pass()
            );
        }
        assert!(
            tool_finding(Check::PrefixClaude, &ToolState::Pinned, "2")
                .status
                .is_pass()
        );
    }
}

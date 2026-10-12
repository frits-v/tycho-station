//! The shared tool prefix every session's binaries come from.
//!
//! The vendor CLIs and zmx run by the absolute paths `station.json` records for the pinned
//! installs, never through a mise shim, so no configuration file or cache entry the agent can
//! write decides what runs.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use super::{core_home, is_shell_safe, is_test_home, user_home, ConfigError};
use crate::agent_files::{current_uid, read_checked};

/// The shared tool prefix: honoured only for a test core home, like the port offset.
pub const TOOL_PREFIX_ENV: &str = "TYCHO_TOOL_PREFIX";
/// Owned by the developer, closed to group and other writes; the agent runs its binaries.
pub const TOOL_PREFIX_DEFAULT: &str = "/Users/Shared/tycho";
/// The variables `ToolPrefix::mise_environment` sets, which the launcher passes to the vendor.
pub const MISE_PREFIX_ENV: [&str; 7] = [
    "MISE_DATA_DIR",
    "MISE_GLOBAL_CONFIG_FILE",
    "MISE_CACHE_DIR",
    "MISE_OVERRIDE_CONFIG_FILENAMES",
    "MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES",
    "MISE_OFFLINE",
    "MISE_AUTO_INSTALL",
];
/// The tools a session may run from the prefix, in `PATH` order.
pub const PREFIX_TOOLS: [&str; 3] = ["claude", "codex", "zmx"];
const MANIFEST: &str = "station.json";
const MANIFEST_MAX_BYTES: usize = 64 * 1024;
/// What follows the prefix on a launcher's `PATH`.
const SYSTEM_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Where every binary a session runs lives: the station's own under `bin`, and each pinned
/// tool's executable at the path `station.json` records under `mise/installs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPrefix {
    root: PathBuf,
    tools: BTreeMap<String, PathBuf>,
}

impl ToolPrefix {
    /// A prefix with no tools recorded, for a scratch prefix in tests. The root is typed into
    /// a zmx session, so it must be absolute and shell-safe.
    pub fn new(root: PathBuf) -> Result<Self, ConfigError> {
        if !root.is_absolute() {
            return Err(ConfigError::RelativePath(TOOL_PREFIX_ENV, root));
        }
        if !is_shell_safe(&root) {
            return Err(ConfigError::UnsafePath(root));
        }
        Ok(Self {
            root,
            tools: BTreeMap::new(),
        })
    }

    /// The prefix at `root` with the tool paths its `station.json` records; the file must be
    /// a regular file of this user's, and every tool listed.
    pub fn load(root: PathBuf) -> Result<Self, ConfigError> {
        let prefix = Self::new(root)?;
        let path = prefix.root.join(MANIFEST);
        let bytes = read_checked(&path, MANIFEST_MAX_BYTES, Some(current_uid()))
            .map_err(|error| ConfigError::ToolPrefixManifest(error.to_string()))?
            .ok_or_else(|| {
                ConfigError::ToolPrefixManifest(format!(
                    "{} does not exist; run mise run provision-agent",
                    path.display()
                ))
            })?;
        prefix.with_manifest(&String::from_utf8_lossy(&bytes))
    }

    /// The tool paths from a manifest's text. Each must be the tool's executable inside the
    /// prefix's installs, shell-safe, with no `.` or `..` component.
    pub fn with_manifest(mut self, text: &str) -> Result<Self, ConfigError> {
        let refused = |why: String| ConfigError::ToolPrefixManifest(why);
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|error| refused(error.to_string()))?;
        let tools = value
            .get("tools")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| refused("station.json records no tools".to_string()))?;
        for name in PREFIX_TOOLS {
            let path = tools
                .get(name)
                .and_then(|tool| tool.get("path"))
                .and_then(serde_json::Value::as_str)
                .map(PathBuf::from)
                .ok_or_else(|| refused(format!("station.json records no path for {name}")))?;
            let installs = self.root.join("mise/installs").join(name);
            let plain = path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
            let named = path.file_name().is_some_and(|file| file == name);
            if !plain || !named || !path.starts_with(&installs) || !is_shell_safe(&path) {
                return Err(refused(format!(
                    "{} is not {name}'s executable under {}",
                    path.display(),
                    installs.display()
                )));
            }
            self.tools.insert(name.to_string(), path);
        }
        Ok(self)
    }

    /// `TYCHO_TOOL_PREFIX` for a test core home, else the production prefix; set for the
    /// production home it is refused, so no environment moves where production sessions run.
    pub fn resolve_root(
        variable: Option<OsString>,
        test_home: bool,
    ) -> Result<PathBuf, ConfigError> {
        match (variable, test_home) {
            (None, _) => Ok(PathBuf::from(TOOL_PREFIX_DEFAULT)),
            (Some(_), false) => Err(ConfigError::ProductionOverride(TOOL_PREFIX_ENV)),
            (Some(root), true) => Ok(PathBuf::from(root)),
        }
    }

    /// The prefix this process's configuration names, with its recorded tools.
    pub fn from_environment() -> Result<Self, ConfigError> {
        let variable = env::var_os(TOOL_PREFIX_ENV);
        let test_home = variable.is_some() && is_test_home(&core_home()?, &user_home()?);
        Self::load(Self::resolve_root(variable, test_home)?)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The station's own binary in the prefix, which zmx types as the launcher.
    #[must_use]
    pub fn tycho(&self) -> PathBuf {
        self.root.join("bin/tycho")
    }

    /// The absolute path of a recorded tool's executable.
    #[must_use]
    pub fn tool(&self, name: &str) -> Option<&Path> {
        self.tools.get(name).map(PathBuf::as_path)
    }

    /// The prefix's binaries, each recorded tool's directory, then the system's; no shim
    /// directory is on it.
    #[must_use]
    pub fn path(&self) -> String {
        let mut parts = vec![self.root.join("bin").display().to_string()];
        for name in PREFIX_TOOLS {
            if let Some(directory) = self.tool(name).and_then(Path::parent) {
                parts.push(directory.display().to_string());
            }
        }
        parts.push(SYSTEM_PATH.to_string());
        parts.join(":")
    }

    /// What any mise a session starts reads: the prefix's installs, pins and read-only cache,
    /// no project configuration, no network and no install of a missing version.
    #[must_use]
    pub fn mise_environment(&self) -> [(&'static str, String); 7] {
        let [data, global, cache, config_names, tool_versions, offline, auto_install] =
            MISE_PREFIX_ENV;
        [
            (data, self.root.join("mise").display().to_string()),
            (global, self.root.join("mise.toml").display().to_string()),
            (cache, self.root.join("cache").display().to_string()),
            (
                config_names,
                self.root.join("no-project-config").display().to_string(),
            ),
            (tool_versions, "none".to_string()),
            (offline, "1".to_string()),
            (auto_install, "false".to_string()),
        ]
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// The manifest `xtask provision-agent` writes for the production prefix's tools.
    pub const MANIFEST_TEXT: &str = r#"{
  "schema_version": 2,
  "tools": {
    "claude": {"version": "2.1.280", "path": "/Users/Shared/tycho/mise/installs/claude/2.1.280/claude", "install_sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
    "codex": {"version": "0.160.1", "path": "/Users/Shared/tycho/mise/installs/codex/0.160.1/bin/codex", "install_sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
    "zmx": {"version": "0.8.1", "path": "/Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx", "install_sha256": "0000000000000000000000000000000000000000000000000000000000000000"}
  }
}"#;

    /// The production prefix with its recorded tools, read from text rather than the host.
    ///
    /// # Panics
    ///
    /// When `MANIFEST_TEXT` does not decode, which its own tests rule out.
    #[must_use]
    pub fn production() -> ToolPrefix {
        ToolPrefix::new(PathBuf::from(TOOL_PREFIX_DEFAULT))
            .and_then(|prefix| prefix.with_manifest(MANIFEST_TEXT))
            .unwrap()
    }

    #[test]
    fn the_tool_prefix_moves_only_for_a_test_home_and_must_be_shell_safe() {
        assert_eq!(
            ToolPrefix::resolve_root(None, false).unwrap(),
            PathBuf::from(TOOL_PREFIX_DEFAULT)
        );
        assert!(matches!(
            ToolPrefix::resolve_root(Some(OsString::from("/tmp/prefix")), false),
            Err(ConfigError::ProductionOverride(TOOL_PREFIX_ENV))
        ));
        assert_eq!(
            ToolPrefix::resolve_root(Some(OsString::from("/tmp/prefix")), true).unwrap(),
            PathBuf::from("/tmp/prefix")
        );
        assert!(matches!(
            ToolPrefix::new(PathBuf::from("prefix")),
            Err(ConfigError::RelativePath(..))
        ));
        assert!(matches!(
            ToolPrefix::new(PathBuf::from("/tmp/a prefix")),
            Err(ConfigError::UnsafePath(_))
        ));
    }

    #[test]
    fn the_path_holds_the_recorded_install_directories_and_no_shim() {
        let prefix = production();
        assert_eq!(
            prefix.path(),
            "/Users/Shared/tycho/bin:/Users/Shared/tycho/mise/installs/claude/2.1.280:/Users/Shared/tycho/mise/installs/codex/0.160.1/bin:/Users/Shared/tycho/mise/installs/zmx/0.8.1:/usr/bin:/bin:/usr/sbin:/sbin"
        );
        assert!(!prefix.path().contains("shims"));
        assert_eq!(
            prefix.tool("claude"),
            Some(Path::new(
                "/Users/Shared/tycho/mise/installs/claude/2.1.280/claude"
            ))
        );
        let scratch = ToolPrefix::new(PathBuf::from("/tmp/prefix")).unwrap();
        assert_eq!(
            scratch.path(),
            "/tmp/prefix/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        );
    }

    #[test]
    fn a_recorded_path_outside_the_installs_or_naming_another_tool_is_refused() {
        let base = || ToolPrefix::new(PathBuf::from(TOOL_PREFIX_DEFAULT)).unwrap();
        for (from, to) in [
            (
                "/Users/Shared/tycho/mise/installs/claude/2.1.280/claude",
                "/Users/Shared/tycho/mise/shims/claude",
            ),
            (
                "/Users/Shared/tycho/mise/installs/claude/2.1.280/claude",
                "/Users/Shared/tycho/mise/installs/claude/../../../../evil/claude",
            ),
            (
                "/Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx",
                "/Users/Shared/tycho/mise/installs/zmx/0.8.1/sh",
            ),
            (
                "/Users/Shared/tycho/mise/installs/codex/0.160.1/bin/codex",
                "/Users/Shared/tycho/mise/installs/claude/2.1.280/codex",
            ),
        ] {
            let text = MANIFEST_TEXT.replace(from, to);
            assert!(
                matches!(
                    base().with_manifest(&text),
                    Err(ConfigError::ToolPrefixManifest(_))
                ),
                "{to}"
            );
        }
        let without_zmx = MANIFEST_TEXT.replace("\"zmx\"", "\"other\"");
        assert!(base().with_manifest(&without_zmx).is_err());
        assert!(base().with_manifest("not json").is_err());
    }

    #[test]
    fn mise_reads_only_the_prefix_and_never_installs() {
        let words: Vec<String> = production()
            .mise_environment()
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        assert_eq!(
            words,
            [
                "MISE_DATA_DIR=/Users/Shared/tycho/mise",
                "MISE_GLOBAL_CONFIG_FILE=/Users/Shared/tycho/mise.toml",
                "MISE_CACHE_DIR=/Users/Shared/tycho/cache",
                "MISE_OVERRIDE_CONFIG_FILENAMES=/Users/Shared/tycho/no-project-config",
                "MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES=none",
                "MISE_OFFLINE=1",
                "MISE_AUTO_INSTALL=false",
            ]
        );
    }
}

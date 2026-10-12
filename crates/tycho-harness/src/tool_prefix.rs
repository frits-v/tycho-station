//! A scratch tool prefix for the integration suites.
//!
//! It has the layout and `station.json` of the shared prefix, with the built `tycho` and the
//! developer's pinned tools linked in, so a test session starts from the prefix the way a
//! production session does without touching `/Users/Shared/tycho`.

use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

/// The version directory the scratch installs sit under.
pub const SCRATCH_VERSION: &str = "scratch";

/// Where a linked tool's executable sits in the scratch prefix.
#[must_use]
pub fn scratch_tool_path(root: &Path, name: &str) -> PathBuf {
    root.join("mise/installs")
        .join(name)
        .join(SCRATCH_VERSION)
        .join(name)
}

/// Creates `root` and its levels one at a time, links `bin/tycho` to `tycho` and each tool's
/// executable to its target, and writes the `station.json` that names them. `root` must not
/// exist yet.
pub fn link_scratch_prefix(root: &Path, tycho: &Path, tools: &[(&str, &Path)]) -> io::Result<()> {
    for level in [root.to_path_buf(), root.join("bin"), root.join("mise")] {
        fs::create_dir(level)?;
    }
    fs::create_dir(root.join("mise/installs"))?;
    symlink(tycho, root.join("bin/tycho"))?;
    let mut records = serde_json::Map::new();
    for (name, target) in tools {
        let install = root.join("mise/installs").join(name);
        fs::create_dir(&install)?;
        fs::create_dir(install.join(SCRATCH_VERSION))?;
        let path = scratch_tool_path(root, name);
        symlink(target, &path)?;
        records.insert(
            (*name).to_string(),
            serde_json::json!({
                "version": SCRATCH_VERSION,
                "path": path.display().to_string(),
                "install_sha256": "0".repeat(64),
            }),
        );
    }
    let manifest = serde_json::json!({"schema_version": 2, "tools": records});
    fs::write(root.join("station.json"), format!("{manifest:#}\n"))
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "the fixture lives in a scratch directory no other user can write"
)]
mod tests {
    use super::*;

    #[test]
    fn a_scratch_prefix_links_tycho_and_names_each_tool_in_its_manifest() {
        let root = std::env::temp_dir().join(format!("harness-prefix-{}", std::process::id()));
        drop(fs::remove_dir_all(&root));
        link_scratch_prefix(
            &root,
            Path::new("/bin/sh"),
            &[("zmx", Path::new("/bin/echo"))],
        )
        .unwrap();
        assert_eq!(
            fs::read_link(root.join("bin/tycho")).unwrap(),
            PathBuf::from("/bin/sh")
        );
        assert_eq!(
            fs::read_link(scratch_tool_path(&root, "zmx")).unwrap(),
            PathBuf::from("/bin/echo")
        );
        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(root.join("station.json")).unwrap()).unwrap();
        assert_eq!(
            manifest["tools"]["zmx"]["path"],
            scratch_tool_path(&root, "zmx").display().to_string()
        );
        assert!(link_scratch_prefix(&root, Path::new("/bin/sh"), &[]).is_err());
        fs::remove_dir_all(&root).unwrap();
    }
}

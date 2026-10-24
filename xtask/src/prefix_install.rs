//! Makes the shared tool prefix as the developer, with no root step: its directories, the
//! pinned mise downloaded and checked against a digest compiled in here and the one mise
//! publishes, the agent's tools installed by that mise, and release builds of the station's
//! binaries. Every file is written beside its final name and renamed over it, so a reader
//! sees the old file or the new one, never a partial one.

use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tycho_types::git_environment::git_command;
use ureq::Agent;
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

use crate::prefix_manifest::{
    BINARY_MAX_BYTES, Manifest, StationRecord, ToolRecord, install_sha256, read_manifest,
    read_regular, sha256_hex,
};
use crate::process::{self, Exit};
use crate::provision;
use crate::setup::{self, Identity};
use crate::tool_prefix::{
    self, AgentTool, MISE_PINNED_VERSION, Network, PREFIX_MODE, Prefix, StationBinary,
    ToolEnvironment, ToolState,
};

/// The release assets of the pinned mise and their SHA-256, recorded when the pin was set.
const MISE_ASSETS: [(&str, &str); 2] = [
    (
        "macos-arm64",
        "3977349e71eea611cf25717ddca753172cae6a92597a47bc4b9efada123b237e",
    ),
    (
        "macos-x64",
        "820bda7a3547edf75dd9e9390846cc87219583bef4fe72666f35a4935d330f47",
    ),
];
const MISE_RELEASE: &str = "https://github.com/jdx/mise/releases/download";
/// Hosts a release download may be sent to: GitHub, then its asset storage.
const DOWNLOAD_HOSTS: [&str; 3] = [
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
];
const REDIRECTS_MAX: usize = 3;
const MISE_BINARY_MAX_BYTES: u64 = 256 << 20;
const SUMS_MAX_BYTES: u64 = 64 << 10;
const SUMS_LINES_MAX: usize = 256;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);
const USER_AGENT: &str = "tycho-xtask";
/// A mise install downloads every agent tool; claude and codex are about 100 MB each.
const INSTALL_TIMEOUT: Duration = Duration::from_secs(1800);
/// A cold release build of the workspace.
const BUILD_TIMEOUT: Duration = Duration::from_secs(3600);
const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const CONFIG_MODE: u32 = 0o644;
const BINARY_MODE: u32 = 0o755;

/// The release asset name for this machine and its pinned digest.
fn mise_asset() -> Result<(String, &'static str), String> {
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "macos-arm64",
        ("macos", "x86_64") => "macos-x64",
        (os, arch) => return Err(format!("no pinned mise digest for {os} on {arch}")),
    };
    let digest = MISE_ASSETS
        .iter()
        .find(|(name, _)| *name == platform)
        .map(|(_, digest)| *digest)
        .ok_or_else(|| format!("no pinned mise digest for {platform}"))?;
    Ok((format!("mise-v{MISE_PINNED_VERSION}-{platform}"), digest))
}

/// One line of mise's `SHASUMS256.txt`: `<sha256>  ./<asset>`.
#[derive(Debug, PartialEq, Eq)]
enum SumLine {
    Listed(String),
    Absent,
    Unrecognised(String),
}

fn decode_sums(text: &str, asset: &str) -> SumLine {
    let wanted = format!("./{asset}");
    let mut found = None;
    for (index, line) in text.lines().enumerate() {
        if index >= SUMS_LINES_MAX {
            return SumLine::Unrecognised(format!("more than {SUMS_LINES_MAX} lines"));
        }
        let mut words = line.split_whitespace();
        let (Some(digest), Some(name), None) = (words.next(), words.next(), words.next()) else {
            return SumLine::Unrecognised(line.to_string());
        };
        let hex = digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit());
        if !hex {
            return SumLine::Unrecognised(line.to_string());
        }
        if name == wanted {
            if found.is_some() {
                return SumLine::Unrecognised(line.to_string());
            }
            found = Some(digest.to_ascii_lowercase());
        }
    }
    found.map_or(SumLine::Absent, SumLine::Listed)
}

/// An agent that follows no redirect itself, ignores proxy variables and refuses plain HTTP;
/// `fetch` follows a redirect only to a listed host.
fn agent() -> Agent {
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .root_certs(RootCerts::WebPki)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .build();
    Agent::config_builder()
        .tls_config(tls)
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(DOWNLOAD_TIMEOUT))
        .user_agent(USER_AGENT)
        .build()
        .into()
}

/// The host of an `https://` URL; `None` for any other scheme or an empty host.
fn https_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty() && !host.contains(['@', ':'])).then_some(host)
}

/// What one request came back with.
#[derive(Debug, PartialEq, Eq)]
enum Fetched {
    Body(Vec<u8>),
    Redirect(String),
    Status(u16),
    TooLarge,
    Failed(&'static str),
}

const fn failure(error: &ureq::Error) -> &'static str {
    match error {
        ureq::Error::Timeout(_) => "the request timed out",
        ureq::Error::Io(_) => "the connection failed",
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => "the TLS handshake failed",
        ureq::Error::RequireHttpsOnly(_) => "the URL is not HTTPS",
        _ => "the request failed",
    }
}

fn fetch_once(agent: &Agent, url: &str, max: u64) -> Fetched {
    let mut response = match agent.get(url).call() {
        Ok(response) => response,
        Err(error) => return Fetched::Failed(failure(&error)),
    };
    let status = response.status().as_u16();
    match status {
        200 => match response.body_mut().with_config().limit(max).read_to_vec() {
            Ok(bytes) => Fetched::Body(bytes),
            Err(ureq::Error::BodyExceedsLimit(_)) => Fetched::TooLarge,
            Err(error) => Fetched::Failed(failure(&error)),
        },
        301 | 302 | 303 | 307 | 308 => response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .map_or(
                Fetched::Failed("a redirect without a location"),
                |location| Fetched::Redirect(location.to_string()),
            ),
        other => Fetched::Status(other),
    }
}

/// Downloads `url` up to `max` bytes, following at most `REDIRECTS_MAX` redirects, each to a
/// listed host over HTTPS. Errors name hosts, never the signed URLs GitHub redirects to.
fn fetch(agent: &Agent, url: &str, max: u64) -> Result<Vec<u8>, String> {
    let mut current = url.to_string();
    for _ in 0..=REDIRECTS_MAX {
        let host = https_host(&current)
            .filter(|host| DOWNLOAD_HOSTS.contains(host))
            .ok_or_else(|| "a download was sent to a host outside the list".to_string())?
            .to_string();
        match fetch_once(agent, &current, max) {
            Fetched::Body(bytes) => return Ok(bytes),
            Fetched::Redirect(location) => current = location,
            Fetched::Status(status) => return Err(format!("{host} answered {status}")),
            Fetched::TooLarge => return Err(format!("{host} sent more than {max} bytes")),
            Fetched::Failed(why) => return Err(format!("{host}: {why}")),
        }
    }
    Err(format!("more than {REDIRECTS_MAX} redirects"))
}

/// Writes `bytes` beside `name` in `dir` with `mode`, flushes it, and renames it over `name`.
/// The staging name is created new without following a link; a stale one from an interrupted
/// run is unlinked first.
pub fn write_replacing(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> Result<(), String> {
    let staging = dir.join(format!(".{name}.{}.new", std::process::id()));
    let target = dir.join(name);
    match fs::symlink_metadata(&staging) {
        Ok(_) => {
            fs::remove_file(&staging).map_err(|error| format!("{}: {error}", staging.display()))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{}: {error}", staging.display())),
    }
    let written = write_new(&staging, bytes, mode)
        .and_then(|()| fs::rename(&staging, &target))
        .map_err(|error| format!("{}: {error}", target.display()));
    if written.is_err() {
        drop(fs::remove_file(&staging));
    }
    written
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.set_permissions(Permissions::from_mode(mode))?;
    file.sync_all()
}

/// The prefix, its `bin` and its mise data directory, each a real directory the developer owns
/// with mode 0755, created one level at a time and set on a descriptor.
pub fn create_directories(prefix: &Prefix, developer_uid: u32) -> Result<(), String> {
    for directory in [prefix.root().to_path_buf(), prefix.bin(), prefix.data_dir()] {
        provision::create_level(&directory, developer_uid)?;
        let opened = provision::open_own_directory(&directory, developer_uid)?;
        opened
            .set_permissions(Permissions::from_mode(PREFIX_MODE))
            .map_err(|error| format!("chmod {PREFIX_MODE:04o} {}: {error}", directory.display()))?;
    }
    Ok(())
}

/// Downloads the pinned mise, requires the published checksum and the download to match the
/// digest compiled in here, and installs it as the prefix's `bin/mise`.
pub fn install_mise(prefix: &Prefix) -> Result<(), String> {
    let (asset, pinned) = mise_asset()?;
    let agent = agent();
    let release = format!("{MISE_RELEASE}/v{MISE_PINNED_VERSION}");
    let sums = fetch(&agent, &format!("{release}/SHASUMS256.txt"), SUMS_MAX_BYTES)?;
    match decode_sums(&String::from_utf8_lossy(&sums), &asset) {
        SumLine::Listed(published) if published == pinned => {}
        SumLine::Listed(published) => {
            return Err(format!(
                "SHASUMS256.txt lists {published} for {asset}; the pinned digest is {pinned}"
            ));
        }
        SumLine::Absent => return Err(format!("SHASUMS256.txt does not list {asset}")),
        SumLine::Unrecognised(line) => {
            return Err(format!("unrecognised SHASUMS256.txt line: {line:?}"));
        }
    }
    let binary = fetch(&agent, &format!("{release}/{asset}"), MISE_BINARY_MAX_BYTES)?;
    let digest = sha256_hex(&binary);
    if digest != pinned {
        return Err(format!(
            "{asset} has sha256 {digest}; the pinned digest is {pinned}"
        ));
    }
    write_replacing(&prefix.bin(), "mise", &binary, BINARY_MODE)
}

fn exit_result(what: &str, exit: &Exit) -> Result<(), String> {
    match exit {
        Exit::Code(0) => Ok(()),
        other => Err(format!("{what} ended with {other:?}")),
    }
}

/// Sets the file creation mask for the rest of this process, so whatever mise writes is
/// closed to group and other writes whatever the developer's shell mask was.
fn close_creation_mask() {
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o022));
}

/// Writes the prefix's global configuration from the compiled pins, runs the prefix's mise
/// from `/` with a cleared environment so it installs exactly those pins, then records each
/// tool's executable, which `mise which` must resolve to the pinned install, and the digest
/// of that install in `station.json`.
pub fn install_agent_tools(prefix: &Prefix, developer: &Identity) -> Result<(), String> {
    close_creation_mask();
    let config = tool_prefix::global_config()?;
    write_replacing(prefix.root(), "mise.toml", config.as_bytes(), CONFIG_MODE)?;
    let home = ToolEnvironment::current_home(developer)?;
    let environment = ToolEnvironment::for_developer(&home);
    let mut command = tool_prefix::prefix_command(
        prefix,
        &environment,
        &prefix.mise(),
        &["install"],
        Network::Online,
    );
    exit_result(
        "mise install",
        &process::run_bounded_merged(&mut command, INSTALL_TIMEOUT).exit,
    )?;
    let mut manifest = read_manifest(&prefix.manifest()).into_base()?;
    for tool in AgentTool::ALL {
        let pin = tool_prefix::pinned_version(tool)?;
        match tool_prefix::which_tool(prefix, &environment, tool, &pin) {
            ToolState::Pinned => {}
            other => {
                return Err(format!(
                    "mise which {} does not name {}: {other:?}",
                    tool.name(),
                    prefix.tool_binary(tool, &pin).display()
                ));
            }
        }
        let install_sha256 = install_sha256(&prefix.installs(tool, &pin))?;
        manifest.tools.insert(
            tool.name().to_string(),
            ToolRecord {
                path: prefix.tool_binary(tool, &pin),
                version: pin,
                install_sha256,
            },
        );
    }
    write_manifest(prefix, &manifest)
}

fn write_manifest(prefix: &Prefix, manifest: &Manifest) -> Result<(), String> {
    write_replacing(
        prefix.root(),
        "station.json",
        manifest.render().as_bytes(),
        CONFIG_MODE,
    )
}

fn git_line(args: &[&str]) -> Result<String, String> {
    let mut command = git_command();
    command.args(args).current_dir(setup::workspace_root());
    let captured = process::run_bounded_capturing_stderr(&mut command, GIT_TIMEOUT);
    exit_result(&format!("git {}", args.join(" ")), &captured.exit)?;
    Ok(captured.stdout)
}

/// The checkout's commit and whether its tree is clean.
fn checkout_state() -> Result<(String, bool), String> {
    let commit = tool_prefix::checkout_head()?;
    let clean = git_line(&["status", "--porcelain"])?.trim().is_empty();
    Ok((commit, clean))
}

/// Builds `xtask` and `tycho` in release mode from this checkout, installs both into the
/// prefix's `bin`, and records their digests with the commit and whether the tree was clean.
/// The commit and the tree are read before and after the build, and a change between the
/// two refuses the install, so the record names what was built.
pub fn install_station(prefix: &Prefix) -> Result<(), String> {
    let before = checkout_state()?;
    let root = setup::workspace_root();
    let mut build = Command::new("mbx");
    build
        .args([
            "build",
            "--release",
            "--locked",
            "-p",
            "xtask",
            "-p",
            "tycho",
        ])
        .current_dir(root);
    exit_result(
        "mbx build",
        &process::run_bounded_merged(&mut build, BUILD_TIMEOUT).exit,
    )?;
    let after = checkout_state()?;
    if after != before {
        return Err(format!(
            "the checkout changed during the build ({} clean {} became {} clean {}); run the task again",
            before.0, before.1, after.0, after.1
        ));
    }
    let mut digests = Vec::new();
    for binary in StationBinary::ALL {
        let compiled: PathBuf = root.join("target/release").join(binary.name());
        let bytes = read_regular(&compiled, BINARY_MAX_BYTES)
            .map_err(|error| format!("{}: {error}", compiled.display()))?;
        write_replacing(&prefix.bin(), binary.name(), &bytes, BINARY_MODE)?;
        digests.push(sha256_hex(&bytes));
    }
    let [xtask, tycho] = <[String; 2]>::try_from(digests)
        .map_err(|_| "expected two station binaries".to_string())?;
    let mut manifest = read_manifest(&prefix.manifest()).into_base()?;
    manifest.station = Some(StationRecord {
        commit: before.0,
        clean: before.1,
        xtask,
        tycho,
    });
    write_manifest(prefix, &manifest)
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// Two lines of the published file, captured for the decoder; the anchor is the digest
    /// compiled into `MISE_ASSETS`, not this fixture.
    const SUMS: &str = "3977349e71eea611cf25717ddca753172cae6a92597a47bc4b9efada123b237e  ./mise-v2026.9.13-macos-arm64\n820bda7a3547edf75dd9e9390846cc87219583bef4fe72666f35a4935d330f47  ./mise-v2026.9.13-macos-x64\n";

    #[test]
    fn decodes_the_published_checksums_and_rejects_the_unrecognised() {
        assert_eq!(
            decode_sums(SUMS, "mise-v2026.9.13-macos-arm64"),
            SumLine::Listed(
                "3977349e71eea611cf25717ddca753172cae6a92597a47bc4b9efada123b237e".to_string()
            )
        );
        assert_eq!(
            decode_sums(SUMS, "mise-v2026.9.13-linux-arm64"),
            SumLine::Absent
        );
        assert!(matches!(
            decode_sums("not a sums file\n", "x"),
            SumLine::Unrecognised(_)
        ));
        let twice = format!("{SUMS}{SUMS}");
        assert!(matches!(
            decode_sums(&twice, "mise-v2026.9.13-macos-x64"),
            SumLine::Unrecognised(_)
        ));
        let long = "0".repeat(64) + "  ./x\n";
        assert!(matches!(
            decode_sums(&long.repeat(SUMS_LINES_MAX + 1), "y"),
            SumLine::Unrecognised(_)
        ));
    }

    #[test]
    fn a_download_goes_only_to_listed_https_hosts() {
        assert_eq!(
            https_host("https://github.com/jdx/mise/releases"),
            Some("github.com")
        );
        assert_eq!(
            https_host("https://release-assets.githubusercontent.com/x?sig=1"),
            Some("release-assets.githubusercontent.com")
        );
        assert_eq!(https_host("http://github.com/x"), None);
        assert_eq!(https_host("https://user@github.com/x"), None);
        assert_eq!(https_host("https://github.com:444/x"), None);
        assert_eq!(https_host("https:///x"), None);
        let refused = fetch(&agent(), "https://example.com/mise", 1);
        assert_eq!(
            refused,
            Err("a download was sent to a host outside the list".to_string())
        );
    }

    #[test]
    fn the_mise_pin_is_the_one_every_workflow_installs() {
        let workflows = setup::workspace_root().join(".github/workflows");
        let mut pins = 0_usize;
        for entry in fs::read_dir(&workflows).expect("list the workflows") {
            let text = fs::read_to_string(entry.expect("entry").path()).expect("read");
            let mut lines = text.lines();
            while let Some(line) = lines.next() {
                if !line.contains("jdx/mise-action@") {
                    continue;
                }
                let version = lines
                    .next()
                    .filter(|next| next.trim() == "with:")
                    .and_then(|_| lines.next())
                    .and_then(|next| next.trim().strip_prefix("version: "));
                assert_eq!(version, Some(MISE_PINNED_VERSION), "{line}");
                pins += 1;
            }
        }
        assert!(pins >= 2, "found {pins} mise-action steps");
    }

    #[test]
    fn a_replaced_file_has_its_mode_and_no_staging_file_is_left() {
        let dir = std::env::temp_dir().join(format!("xtask-replace-{}", std::process::id()));
        drop(fs::remove_dir_all(&dir));
        fs::create_dir(&dir).expect("mkdir");
        write_replacing(&dir, "bin", b"one", 0o755).expect("first write");
        write_replacing(&dir, "bin", b"two", 0o755).expect("second write");
        assert_eq!(fs::read(dir.join("bin")).expect("read"), b"two");
        assert_eq!(
            fs::metadata(dir.join("bin")).expect("stat").mode() & 0o7777,
            0o755
        );
        assert_eq!(fs::read_dir(&dir).expect("list").count(), 1);
        let staging = dir.join(format!(".link.{}.new", std::process::id()));
        std::os::unix::fs::symlink(dir.join("elsewhere"), &staging).expect("plant");
        write_replacing(&dir, "link", b"three", 0o644).expect("write past a stale link");
        assert!(!dir.join("elsewhere").exists());
        assert_eq!(fs::read(dir.join("link")).expect("read"), b"three");
        fs::remove_dir_all(&dir).expect("clean up");
    }
}

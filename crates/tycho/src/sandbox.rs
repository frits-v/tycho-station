//! The session sandbox: the capability set the session leader applies to the vendor's tree.
//!
//! `tycho session-leader` applies it between `setsid` and `exec` (Seatbelt on macOS, Landlock
//! on Linux). It is built from the station's system-path list in `config/sandbox.cue` and the
//! plan the launcher hands the leader.
//!
//! Every set the station builds is proxy-only: outbound TCP reaches only the session proxy's
//! loopback port, never one of the core's ports. `capability_set` is the only constructor
//! and ends in `check_proxy_only`, so a set that fails the property is never returned.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use nono::{AccessMode, CapabilitySet, NetworkMode, SignalMode, UnixSocketMode};
use serde::{Deserialize, Serialize};

use crate::config::CorePorts;
use crate::config_store::{ContentHashed, StoreError, decode};

/// The plan the launcher hands the session leader, as JSON; the leader removes it from the
/// environment before it execs the vendor.
pub const PLAN_ENV: &str = "TYCHO_SANDBOX_PLAN";
pub const PLAN_MAX_BYTES: usize = 64 * 1024;
/// Grants of one kind a plan may carry.
pub const PLAN_GRANTS_MAX: usize = 64;
pub const PATH_MAX_BYTES: usize = 1024;
/// The leader's exit code when it could not build or apply the sandbox; the vendor never ran.
pub const EXIT_SANDBOX_REFUSED: i32 = 125;
/// The exit state of a session whose sandbox could not be built, so no vendor started; it
/// decodes as unrecognised, which goes to the inbox rather than back to the queue.
pub const SANDBOX_REFUSED: &str = "vendor_sandbox_refused";
const CONFIG_NAME: &str = "sandbox";
pub const SYSTEM_PATHS_MAX: usize = 256;
pub const ALLOWED_HOSTS_MAX: usize = 16;
pub const HOST_MAX_BYTES: usize = 253;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Write,
    ReadWrite,
}

impl Access {
    const fn mode(self) -> AccessMode {
        match self {
            Self::Read => AccessMode::Read,
            Self::Write => AccessMode::Write,
            Self::ReadWrite => AccessMode::ReadWrite,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Macos,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    Aarch64,
    X86_64,
}

/// The platform and architecture this binary was built for, or `None` where the station
/// has no sandbox.
#[must_use]
pub const fn host() -> Option<(Platform, Arch)> {
    let platform = if cfg!(target_os = "macos") {
        Platform::Macos
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else {
        return None;
    };
    let arch = if cfg!(target_arch = "aarch64") {
        Arch::Aarch64
    } else if cfg!(target_arch = "x86_64") {
        Arch::X86_64
    } else {
        return None;
    };
    Some((platform, arch))
}

/// One entry of the station's system-path list.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemGrant {
    pub path: PathBuf,
    pub access: Access,
    pub platform: Platform,
    pub arch: Option<Arch>,
    pub optional: bool,
}

impl SystemGrant {
    fn applies_to(&self, platform: Platform, arch: Arch) -> bool {
        self.platform == platform && self.arch.is_none_or(|only| only == arch)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorNetwork {
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorNetworks {
    pub claude: VendorNetwork,
    pub codex: VendorNetwork,
}

/// The vendors the sandbox knows; a session of any other vendor is refused a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxVendor {
    Claude,
    Codex,
}

impl SandboxVendor {
    #[must_use]
    pub const fn for_session(vendor: tycho_types::session::Vendor) -> Option<Self> {
        use tycho_types::session::Vendor;
        match vendor {
            Vendor::Claude => Some(Self::Claude),
            Vendor::Codex => Some(Self::Codex),
            Vendor::Antigravity | Vendor::Amp | Vendor::OpenCode => None,
        }
    }
}

/// `config/export/sandbox.json`, decoded only when it matches its digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    pub system_paths: Vec<SystemGrant>,
    pub vendors: VendorNetworks,
}

impl SandboxConfig {
    /// The export this binary was built with, its bounds checked again.
    pub fn embedded() -> Result<ContentHashed<Self>, StoreError> {
        let decoded: ContentHashed<Self> = decode(
            CONFIG_NAME,
            include_bytes!("../../../config/export/sandbox.json"),
            include_bytes!("../../../config/export/sandbox.sha256"),
        )?;
        decoded
            .value
            .check()
            .map_err(|what| StoreError::Invalid(CONFIG_NAME.to_string(), what))?;
        Ok(decoded)
    }

    fn check(&self) -> Result<(), String> {
        if self.system_paths.is_empty() || self.system_paths.len() > SYSTEM_PATHS_MAX {
            return Err(format!(
                "{} system paths; expected 1..={SYSTEM_PATHS_MAX}",
                self.system_paths.len()
            ));
        }
        if let Some(grant) = self
            .system_paths
            .iter()
            .find(|grant| check_path(&grant.path).is_err())
        {
            return Err(format!(
                "{} is not a plain absolute path",
                grant.path.display()
            ));
        }
        if let Some(grant) = self
            .system_paths
            .iter()
            .find(|grant| grant.platform == Platform::Macos && grant.optional)
        {
            return Err(format!("macOS entry {} is optional", grant.path.display()));
        }
        for (name, network) in [
            ("claude", &self.vendors.claude),
            ("codex", &self.vendors.codex),
        ] {
            let hosts = &network.allowed_hosts;
            if hosts.is_empty() || hosts.len() > ALLOWED_HOSTS_MAX {
                return Err(format!(
                    "{name} has {} allowed hosts; expected 1..={ALLOWED_HOSTS_MAX}",
                    hosts.len()
                ));
            }
            if let Some(host) = hosts.iter().find(|host| !is_host(host)) {
                return Err(format!("{name} allows {host:?}, which is not a host name"));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn allowed_hosts(&self, vendor: SandboxVendor) -> &[String] {
        match vendor {
            SandboxVendor::Claude => &self.vendors.claude.allowed_hosts,
            SandboxVendor::Codex => &self.vendors.codex.allowed_hosts,
        }
    }

    /// The entries for one platform and architecture.
    pub fn system_paths_for(
        &self,
        platform: Platform,
        arch: Arch,
    ) -> impl Iterator<Item = &SystemGrant> {
        self.system_paths
            .iter()
            .filter(move |grant| grant.applies_to(platform, arch))
    }
}

/// Lowercase labels of letters, digits and `-`, at least two, the last one letters only.
fn is_host(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    let label = |text: &&str| {
        !text.is_empty()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    host.len() <= HOST_MAX_BYTES
        && labels.len() >= 2
        && labels.iter().all(label)
        && labels
            .last()
            .is_some_and(|top| top.len() >= 2 && top.bytes().all(|byte| byte.is_ascii_lowercase()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One path of the session's own, a directory and everything under it or a single file.
pub struct Grant {
    pub path: PathBuf,
    pub access: Access,
}

/// What the launcher hands the leader: the proxy's port, the core's ports the set must never
/// reach, and the session's own grants on top of the system list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPlan {
    pub proxy_port: u16,
    pub core_ports: Vec<u16>,
    pub grants: Vec<Grant>,
    /// Directories whose pathname sockets the vendor may bind and connect.
    pub socket_dirs: Vec<PathBuf>,
    /// Absent paths the vendor may stat and find absent; without this a denied `stat` answers
    /// `EPERM`, which git treats as fatal for its configuration files.
    pub absent_paths: Vec<PathBuf>,
    /// Files the vendor replaces by writing a sibling `<file>.<suffix>` and renaming it over
    /// the file, granted with those siblings: a grant of the file alone refuses the save.
    pub state_files: Vec<PathBuf>,
}

impl SandboxPlan {
    pub fn to_json(&self) -> Result<String, SandboxError> {
        self.check()?;
        serde_json::to_string(self).map_err(|error| SandboxError::Plan(error.to_string()))
    }

    pub fn from_json(text: &str) -> Result<Self, SandboxError> {
        if text.len() > PLAN_MAX_BYTES {
            return Err(SandboxError::Plan(format!(
                "{} bytes; maximum is {PLAN_MAX_BYTES}",
                text.len()
            )));
        }
        let plan: Self =
            serde_json::from_str(text).map_err(|error| SandboxError::Plan(error.to_string()))?;
        plan.check()?;
        Ok(plan)
    }

    fn check(&self) -> Result<(), SandboxError> {
        let counts = [
            ("grants", self.grants.len()),
            ("socket directories", self.socket_dirs.len()),
            ("absent paths", self.absent_paths.len()),
            ("state files", self.state_files.len()),
        ];
        if let Some((what, count)) = counts.iter().find(|(_, count)| *count > PLAN_GRANTS_MAX) {
            return Err(SandboxError::Plan(format!(
                "{count} {what}; maximum is {PLAN_GRANTS_MAX}"
            )));
        }
        let paths = self
            .grants
            .iter()
            .map(|grant| grant.path.as_path())
            .chain(self.socket_dirs.iter().map(PathBuf::as_path))
            .chain(self.absent_paths.iter().map(PathBuf::as_path))
            .chain(self.state_files.iter().map(PathBuf::as_path));
        for path in paths {
            check_path(path)?;
        }
        if let Some(path) = self.state_files.iter().find(|path| {
            path.to_str()
                .is_some_and(|text| text.contains(STATE_FILE_REFUSED_CHARACTERS))
        }) {
            return Err(SandboxError::Path(path.clone()));
        }
        Ok(())
    }

    /// The plan from the leader's environment; its absence is a refusal, never an unsandboxed
    /// run.
    pub fn from_environment() -> Result<Self, SandboxError> {
        let text = std::env::var(PLAN_ENV).map_err(|_| SandboxError::NoPlan)?;
        Self::from_json(&text)
    }
}

/// Absolute, at most `PATH_MAX_BYTES`, no empty, `.` or `..` component, and none of the
/// characters a Seatbelt string literal would have to escape.
pub fn check_path(path: &Path) -> Result<(), SandboxError> {
    let text = path
        .to_str()
        .ok_or_else(|| SandboxError::Path(path.to_path_buf()))?;
    let plain = text.starts_with('/')
        && text.len() <= PATH_MAX_BYTES
        && !text
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component == "." || component == "..")
        && !text
            .chars()
            .any(|character| character.is_control() || matches!(character, '"' | '\\'));
    if plain {
        Ok(())
    } else {
        Err(SandboxError::Path(path.to_path_buf()))
    }
}

#[derive(Debug)]
pub enum SandboxError {
    NoPlan,
    Plan(String),
    Path(PathBuf),
    Config(StoreError),
    UnsupportedPlatform,
    Grant {
        path: PathBuf,
        reason: String,
    },
    NotProxyOnly(String),
    /// The kernel could not apply the set; on Linux this includes a Landlock ABI too old to
    /// filter TCP, which nono would leave to a seccomp supervisor the station does not run.
    Apply(String),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPlan => write!(
                formatter,
                "{PLAN_ENV} is not set; no vendor runs unsandboxed"
            ),
            Self::Plan(reason) => write!(formatter, "sandbox plan: {reason}"),
            Self::Path(path) => write!(
                formatter,
                "{} is not a plain absolute path of at most {PATH_MAX_BYTES} bytes",
                path.display()
            ),
            Self::Config(error) => write!(formatter, "sandbox configuration: {error}"),
            Self::UnsupportedPlatform => write!(formatter, "no sandbox on this platform"),
            Self::Grant { path, reason } => {
                write!(formatter, "cannot grant {}: {reason}", path.display())
            }
            Self::NotProxyOnly(reason) => write!(formatter, "not a proxy-only set: {reason}"),
            Self::Apply(reason) => write!(formatter, "sandbox not applied: {reason}"),
        }
    }
}

impl std::error::Error for SandboxError {}

fn grant_path(
    set: CapabilitySet,
    path: &Path,
    access: Access,
) -> Result<CapabilitySet, SandboxError> {
    let refused = |reason: String| SandboxError::Grant {
        path: path.to_path_buf(),
        reason,
    };
    let metadata = fs::metadata(path).map_err(|error| refused(error.to_string()))?;
    let granted = if metadata.is_dir() {
        set.allow_path(path, access.mode())
    } else {
        set.allow_file(path, access.mode())
    };
    granted.map_err(|error| refused(error.to_string()))
}

/// The metadata rule for one absent path.
fn absent_path_rule(path: &Path) -> String {
    format!(
        "(allow file-read-metadata (literal \"{}\"))",
        path.display()
    )
}

/// The read and write rule for one state file and its `<file>.<suffix>` siblings. Each regex
/// metacharacter of the path becomes a one-character class; the characters a class cannot
/// hold literally (`STATE_FILE_REFUSED_CHARACTERS`, `"` and `\`) never reach here.
fn state_file_rule(path: &Path) -> String {
    let mut pattern = String::new();
    for character in path.display().to_string().chars() {
        if ".+*?(){}|$".contains(character) {
            pattern.push('[');
            pattern.push(character);
            pattern.push(']');
        } else {
            pattern.push(character);
        }
    }
    format!("(allow file-read* file-write* (regex \"^{pattern}([.][^/]+)?$\"))")
}

/// What a state file's path may not hold: `[` and `]` end or open a class, and `^` first in
/// one negates it, so `[^]` would match every character but the one meant.
pub const STATE_FILE_REFUSED_CHARACTERS: [char; 3] = ['[', ']', '^'];

/// The platform rules a set built from `plan` carries, in order: none on Linux.
fn platform_rules(plan: &SandboxPlan, platform: Platform) -> Vec<String> {
    if platform != Platform::Macos {
        return Vec::new();
    }
    plan.absent_paths
        .iter()
        .map(|path| absent_path_rule(path))
        .chain(plan.state_files.iter().map(|path| state_file_rule(path)))
        .collect()
}

/// The set for one session on the host platform: proxy-only network, the system list, the
/// plan's grants and socket directories. Any grant that fails is a refusal.
pub fn capability_set(
    plan: &SandboxPlan,
    config: &SandboxConfig,
) -> Result<CapabilitySet, SandboxError> {
    let (platform, arch) = host().ok_or(SandboxError::UnsupportedPlatform)?;
    plan.check()?;
    // Isolated still lets the vendor signal its own tool children, which share its sandbox;
    // nono's same-sandbox mode needs Landlock ABI 6 on Linux and fails closed below it. No
    // name resolves inside the sandbox on macOS: the proxy resolves the hosts it admits, and
    // the resolver's socket would otherwise carry data out in queries.
    let mut set = CapabilitySet::new()
        .proxy_only(plan.proxy_port)
        .block_dns()
        .set_signal_mode(SignalMode::Isolated);
    for grant in config.system_paths_for(platform, arch) {
        if grant.optional && fs::symlink_metadata(&grant.path).is_err() {
            continue;
        }
        set = grant_path(set, &grant.path, grant.access)?;
    }
    for grant in &plan.grants {
        set = grant_path(set, &grant.path, grant.access)?;
    }
    for dir in &plan.socket_dirs {
        set = set
            .allow_unix_socket_dir(dir, UnixSocketMode::ConnectBind)
            .map_err(|error| SandboxError::Grant {
                path: dir.clone(),
                reason: error.to_string(),
            })?;
    }
    for rule in platform_rules(plan, platform) {
        set = set
            .platform_rule(rule)
            .map_err(|error| SandboxError::Plan(error.to_string()))?;
    }
    // Landlock has no pattern rule, so on Linux a state file present is granted alone and
    // its save is refused; the ci runner runs no vendor.
    if platform == Platform::Linux {
        for path in plan.state_files.iter().filter(|path| path.is_file()) {
            set = grant_path(set, path, Access::ReadWrite)?;
        }
    }
    check_proxy_only(&set, plan)?;
    Ok(set)
}

/// The property every station set holds, or the reason it does not.
///
/// Outbound TCP only to the proxy's port, which is none of the core's; no other TCP grant; the
/// resolver blocked, which Seatbelt enforces on macOS and Landlock, which leaves UDP open, does
/// not on Linux; and no platform rule but the plan's absent-path and state-file rules.
pub fn check_proxy_only(set: &CapabilitySet, plan: &SandboxPlan) -> Result<(), SandboxError> {
    let refuse = |reason: String| Err(SandboxError::NotProxyOnly(reason));
    match set.network_mode() {
        NetworkMode::ProxyOnly { port, bind_ports } if bind_ports.is_empty() => {
            if *port == 0 {
                return refuse("the proxy port is 0".to_string());
            }
            if plan.core_ports.contains(port) {
                return refuse(format!("the proxy port {port} is one of the core's"));
            }
            if *port != plan.proxy_port {
                return refuse(format!("port {port} is not the plan's {}", plan.proxy_port));
            }
        }
        other => return refuse(format!("network mode {other}")),
    }
    if set.dns_enabled() {
        return refuse("the system resolver is reachable".to_string());
    }
    if !set.localhost_ports().is_empty()
        || !set.localhost_port_ranges().is_empty()
        || !set.tcp_connect_ports().is_empty()
        || !set.tcp_bind_ports().is_empty()
    {
        return refuse("a TCP port beyond the proxy's is granted".to_string());
    }
    let expected = host().map_or_else(Vec::new, |(platform, _)| platform_rules(plan, platform));
    if let Some(rule) = set
        .platform_rules()
        .iter()
        .find(|rule| !expected.contains(rule))
    {
        return refuse(format!("platform rule {rule}"));
    }
    Ok(())
}

/// The core's five ports, which no session set may reach.
#[must_use]
pub fn core_ports(ports: CorePorts) -> Vec<u16> {
    ports.all().iter().map(std::net::SocketAddr::port).collect()
}

/// Applies the set to this process and everything it starts; irreversible.
pub fn apply(set: &CapabilitySet) -> Result<(), SandboxError> {
    #[cfg(target_os = "macos")]
    {
        nono::Sandbox::apply_auto(set).map_err(|error| SandboxError::Apply(error.to_string()))
    }
    #[cfg(target_os = "linux")]
    {
        landlock_applied(nono::Sandbox::apply_auto(set))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = set;
        Err(SandboxError::UnsupportedPlatform)
    }
}

/// What Landlock's answer means: only no fallback is an applied set. A fallback is nono asking
/// for a seccomp supervisor the station does not run, so the network would not be enforced,
/// and an error is a set that could not be applied; both are refusals, never a pass.
#[cfg(target_os = "linux")]
fn landlock_applied<E: fmt::Display>(
    applied: Result<nono::sandbox::SeccompNetFallback, E>,
) -> Result<(), SandboxError> {
    use nono::sandbox::SeccompNetFallback;
    match applied {
        Ok(SeccompNetFallback::None) => Ok(()),
        Ok(fallback) => Err(SandboxError::Apply(format!(
            "Landlock cannot filter TCP on this kernel and nono asks for a seccomp \
             supervisor ({fallback:?}); the network would not be enforced"
        ))),
        Err(error) => Err(SandboxError::Apply(error.to_string())),
    }
}

/// The trampoline's step: the plan from the environment, the set built against the
/// embedded configuration, applied.
pub fn apply_from_environment() -> Result<(), SandboxError> {
    let plan = SandboxPlan::from_environment()?;
    let config = SandboxConfig::embedded().map_err(SandboxError::Config)?;
    let set = capability_set(&plan, &config.value)?;
    apply(&set)
}

#[cfg(test)]
mod tests;

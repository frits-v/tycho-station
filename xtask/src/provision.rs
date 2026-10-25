//! Creates what the developer side of `xtask setup` checks: the agent's group, user and home
//! directory, the shared group and its members, the deny entry for the agent in the developer's
//! home ACL, and both socket directories. A step runs only while its probe fails, and the probe
//! runs again after it; a step whose probe still fails stops the run. Steps that need root run
//! through `sudo`, which prompts on the terminal itself; this process never reads, holds or
//! passes a password. Root changes no owner and one mode: the agent home's, whose entry sits in
//! root-owned `/Users`, where no other user can swap it. In `/Users/Shared`, which every user
//! can write, the entry's owner could swap it for a link between the probe and the change.
//! The shared tool prefix needs no root step: the developer creates and fills it
//! (`prefix_install`). The last step installs the sudoers rule that lets the developer start
//! the prefix's zmx as the agent: written to a private directory, checked with `visudo -c -f`
//! as the developer, and installed by root with `install`, the one file root writes.

use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::prefix_install;
use crate::process::{self, Captured, Exit};
use crate::setup::{
    self, AGENT_GROUP_NAME, AGENT_HOME, AGENT_HOME_MODE, AGENT_SOCKET_DIR, AGENT_SOCKET_DIR_MODE,
    AGENT_USER_NAME, AgentHome, AgentHomeState, CORE_SOCKET_DIR_MODE, Check, Finding,
    HOME_DENY_ENTRY, Identity, SHARED_GROUP_NAME, Side, Status,
};
use crate::tool_prefix::{
    self, AgentTool, DirectoryState, MISE_PINNED_VERSION, Prefix, StationState, ToolState,
    TreeState,
};
use tycho_types::agent_switch::{self, DefaultsLine, Entry, Listing, SUDOERS_DROP_IN};

const PROVISION_STEPS_MAX: usize = 16;
/// Long enough for sudo's and sysadminctl's prompts to be answered at a terminal.
const REMEDY_TIMEOUT: Duration = Duration::from_mins(10);
const SUDO: &str = "/usr/bin/sudo";
const DSEDITGROUP: &str = "/usr/sbin/dseditgroup";
const SYSADMINCTL: &str = "/usr/sbin/sysadminctl";
const CREATEHOMEDIR: &str = "/usr/sbin/createhomedir";
const RMDIR: &str = "/bin/rmdir";
const CHMOD: &str = "/bin/chmod";
const INSTALL: &str = "/usr/bin/install";
const VISUDO: &str = "/usr/sbin/visudo";
const MV: &str = "/bin/mv";
/// Where root installs the checked rule before it is renamed into `sudoers.d`: a root-owned
/// directory sudo does not read, on the same volume. `install` writes its own temporary file
/// (`INS@XXXXXX`, no dot) in the target's directory, and sudo reads every name in `sudoers.d`
/// without a dot or a trailing `~`, so a partial file there makes sudo refuse every command
/// for every user. Only the rename touches `sudoers.d`.
const SUDOERS_STAGED: &str = "/etc/tycho-agent.sudoers.tmp";
/// Where the candidate rule is written before root installs it, under the core home; the
/// directory is the developer's at 0700, so only the developer and root read it.
const CANDIDATE_DIR_RELATIVE: [&str; 2] = [".tycho", "provision"];
const CANDIDATE_NAME: &str = "tycho-agent";
const PRIVATE_MODE: u32 = 0o700;
const CANDIDATE_MODE: u32 = 0o600;
/// For a step run as the developer; the prompts of root steps get `REMEDY_TIMEOUT`.
const DEVELOPER_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const PROMPT_NOTICE: &str =
    "sudo may ask for your password now, and sysadminctl for the new user's, on this terminal";
const FOREIGN_SOCKET_DIR_HINT: &str = "it is not an empty directory; inspect /Users/Shared/tycho-agent-zmx, remove it by hand, and run the task again";
const AGENT_FULL_NAME: &str = "Tycho Agent";
const AGENT_SHELL: &str = "/bin/zsh";
const AGENT_GID_PLACEHOLDER: &str = "<gid of tycho-agent>";
/// Mode a directory is created with before its group and final mode are set on the descriptor.
const CREATE_MODE: u32 = 0o700;
/// What sudo writes to stderr after a mistyped password that a later attempt corrected.
const SUDO_RETRY_LINE: &str = "Sorry, try again.";

/// Runs a command as the agent with no login shell, so none of the agent's startup files
/// runs, and with an environment that holds only what follows.
const AS_AGENT: &str = "sudo -u tycho-agent -H /usr/bin/env -i HOME=/Users/tycho-agent";
/// The keychain lookups of setup go by these names.
const AGENT_NAMES: &str = "USER=tycho-agent LOGNAME=tycho-agent";

/// The commands the operator types as the developer, who owns the vendor plans: a long-lived
/// Claude token and a Codex login written to `auth.json`, each stored in the core's
/// credential store from stdin, then the store's status. `setup-token` shows the token on
/// its own screen, so the operator pastes it into `credentials set`.
fn developer_credential_commands(prefix: &Prefix) -> Result<[String; 5], String> {
    let claude = prefix.tool_binary(
        AgentTool::Claude,
        &tool_prefix::pinned_version(AgentTool::Claude)?,
    );
    let codex = prefix.tool_binary(
        AgentTool::Codex,
        &tool_prefix::pinned_version(AgentTool::Codex)?,
    );
    let tycho = prefix.binary(tool_prefix::StationBinary::Tycho);
    Ok([
        format!("{} setup-token", claude.display()),
        format!("{} credentials set claude", tycho.display()),
        format!(
            "{} login -c 'cli_auth_credentials_store=\"file\"'",
            codex.display()
        ),
        format!(
            "{} credentials set codex < ~/.codex/auth.json",
            tycho.display()
        ),
        format!("{} credentials status", tycho.display()),
    ])
}

/// The commands the operator types as the agent: the cleared credential helper, then the
/// agent side of setup. Each runs through `sudo` with no login shell, the pinned install by
/// absolute path, and its environment set in full.
fn operator_commands(prefix: &Prefix) -> Result<[String; 2], String> {
    let environment = prefix.agent_environment_words()?;
    Ok([
        format!(
            "{AS_AGENT} PATH=/usr/bin:/bin /usr/bin/git config --global credential.helper \"\""
        ),
        format!(
            "{AS_AGENT} {AGENT_NAMES} {environment} {} setup",
            prefix.binary(tool_prefix::StationBinary::Xtask).display()
        ),
    ])
}

/// Every remedy, in the order each one's prerequisites come first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Remedy {
    CreateAgentGroup,
    CreateAgentUser,
    CreateAgentHome,
    NarrowAgentHomeMode,
    CreateSharedGroup,
    AddDeveloperToSharedGroup,
    AddAgentToSharedGroup,
    CloseDeveloperHome,
    RemoveForeignAgentSocketDir,
    PrepareAgentSocketDir,
    PrepareCoreSocketDir,
    CreateToolPrefix,
    InstallMise,
    InstallAgentTools,
    InstallStationBinaries,
    InstallSudoersRule,
}

const REMEDIES: [Remedy; 16] = [
    Remedy::CreateAgentGroup,
    Remedy::CreateAgentUser,
    Remedy::CreateAgentHome,
    Remedy::NarrowAgentHomeMode,
    Remedy::CreateSharedGroup,
    Remedy::AddDeveloperToSharedGroup,
    Remedy::AddAgentToSharedGroup,
    Remedy::CloseDeveloperHome,
    Remedy::RemoveForeignAgentSocketDir,
    Remedy::PrepareAgentSocketDir,
    Remedy::PrepareCoreSocketDir,
    Remedy::CreateToolPrefix,
    Remedy::InstallMise,
    Remedy::InstallAgentTools,
    Remedy::InstallStationBinaries,
    Remedy::InstallSudoersRule,
];
const _: () = assert!(REMEDIES.len() <= PROVISION_STEPS_MAX);

const AGENT_DIR_CHECKS: [Check; 5] = [
    Check::AgentDirExists,
    Check::AgentDirIsDirectory,
    Check::AgentDirOwnerUid,
    Check::AgentDirOwnerGid,
    Check::AgentDirMode,
];
const CORE_DIR_CHECKS: [Check; 4] = [
    Check::CoreDirExists,
    Check::CoreDirIsDirectory,
    Check::CoreDirOwnerUid,
    Check::CoreDirMode,
];

impl Remedy {
    const fn label(self) -> &'static str {
        match self {
            Self::CreateAgentGroup => "create the agent group",
            Self::CreateAgentUser => "create the agent user bound to the agent group",
            Self::CreateAgentHome => "create the agent user's home directory",
            Self::NarrowAgentHomeMode => "narrow the agent home's mode to 0700",
            Self::CreateSharedGroup => "create the shared group",
            Self::AddDeveloperToSharedGroup => "add the developer to the shared group",
            Self::AddAgentToSharedGroup => "add the agent user to the shared group",
            Self::CloseDeveloperHome => "deny the agent user the developer's home",
            Self::RemoveForeignAgentSocketDir => {
                "remove the agent socket directory another user owns"
            }
            Self::PrepareAgentSocketDir => "prepare the agent socket directory",
            Self::PrepareCoreSocketDir => "prepare the core socket directory",
            Self::CreateToolPrefix => "create the shared tool prefix",
            Self::InstallMise => "install the pinned mise into the tool prefix",
            Self::InstallAgentTools => "install the agent's tools into the tool prefix",
            Self::InstallStationBinaries => "build and install the station binaries",
            Self::InstallSudoersRule => {
                "install the sudoers rule that starts the prefix's zmx as the agent"
            }
        }
    }

    /// The checks that pass once the remedy has run.
    const fn targets(self) -> &'static [Check] {
        match self {
            Self::CreateAgentGroup => &[Check::AgentGroupExists],
            Self::CreateAgentUser => &[Check::AgentUserExists, Check::AgentPrimaryGroup],
            Self::CreateAgentHome | Self::NarrowAgentHomeMode => &[Check::AgentHomeDirectory],
            Self::CreateSharedGroup => &[Check::SharedGroupExists],
            Self::AddDeveloperToSharedGroup => &[Check::DeveloperInSharedGroup],
            Self::AddAgentToSharedGroup => &[Check::AgentInSharedGroup],
            Self::CloseDeveloperHome => &[Check::DeveloperHomeClosedToAgent],
            Self::RemoveForeignAgentSocketDir => &[Check::AgentDirOwnerUid],
            Self::PrepareAgentSocketDir => &AGENT_DIR_CHECKS,
            Self::PrepareCoreSocketDir => &CORE_DIR_CHECKS,
            Self::CreateToolPrefix => &[Check::PrefixDirectory, Check::PrefixTree],
            Self::InstallMise => &[Check::PrefixMise],
            Self::InstallAgentTools => &[Check::PrefixClaude, Check::PrefixCodex, Check::PrefixZmx],
            Self::InstallStationBinaries => &[Check::PrefixStationXtask, Check::PrefixStationTycho],
            Self::InstallSudoersRule => &[Check::SudoersRule],
        }
    }
}

/// What the probes found, with the facts the remedies' commands are built from.
#[derive(Debug, Clone)]
pub struct Snapshot {
    developer: Identity,
    findings: Vec<Finding>,
    agent_group_gid: Option<u32>,
    shared_group_gid: Option<u32>,
    /// The probe the home finding was made from, so the home steps decide on the same facts.
    agent_home: AgentHome,
    agent_dir_owner: Option<u32>,
    developer_home: Option<PathBuf>,
    core_dir: Option<PathBuf>,
    core_parent_missing: bool,
    /// The prefix probe the prefix findings were made from.
    prefix: tool_prefix::Probe,
    /// The `sudo -l` listing the sudoers finding was made from.
    sudoers: Listing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Need {
    Run,
    Skip,
    /// The probe could not run, so whether the remedy is needed is unknown.
    Blocked(String),
}

fn status_of(snapshot: &Snapshot, check: Check) -> Status {
    snapshot
        .findings
        .iter()
        .find(|finding| finding.check == check)
        .map_or_else(
            || Status::Unreachable {
                why: "no probe produced this finding".to_string(),
            },
            |finding| finding.status.clone(),
        )
}

fn passes(snapshot: &Snapshot, checks: &[Check]) -> bool {
    checks
        .iter()
        .all(|&check| status_of(snapshot, check).is_pass())
}

/// Present skips; missing or wrong runs.
fn need_for_wrong(status: &Status) -> Need {
    match status {
        Status::Present => Need::Skip,
        Status::Missing | Status::Wrong { .. } => Need::Run,
        Status::Unreachable { why } => Need::Blocked(why.clone()),
        Status::Deferred { .. } => Need::Blocked(status.to_string()),
    }
}

/// Present skips, missing runs; anything else is a state no remedy here creates.
fn need_for_absence(status: &Status) -> Need {
    match status {
        Status::Present => Need::Skip,
        Status::Missing => Need::Run,
        Status::Unreachable { why } => Need::Blocked(why.clone()),
        Status::Wrong { .. } | Status::Deferred { .. } => Need::Blocked(status.to_string()),
    }
}

/// `Ok(true)` when the directory exists and is a real directory, `Ok(false)` when it exists as
/// something else, which no remedy changes; a missing directory is `Err(Need::Run)`.
fn existing_directory(snapshot: &Snapshot, exists: Check, kind: Check) -> Result<bool, Need> {
    match status_of(snapshot, exists) {
        Status::Present => Ok(status_of(snapshot, kind).is_pass()),
        Status::Missing => Err(Need::Run),
        Status::Unreachable { why } => Err(Need::Blocked(why)),
        other => Err(Need::Blocked(other.to_string())),
    }
}

/// A directory neither the developer nor root owns, or a root-owned one that is not settled,
/// is removed by root and created again by the developer.
fn remove_agent_dir_need(snapshot: &Snapshot) -> Need {
    match existing_directory(snapshot, Check::AgentDirExists, Check::AgentDirIsDirectory) {
        Ok(true) => {}
        Ok(false) | Err(Need::Run) => return Need::Skip,
        Err(need) => return need,
    }
    let owned_by_developer = snapshot.agent_dir_owner == Some(snapshot.developer.uid);
    let settled = passes(
        snapshot,
        &[
            Check::AgentDirOwnerUid,
            Check::AgentDirOwnerGid,
            Check::AgentDirMode,
        ],
    );
    if owned_by_developer || settled {
        Need::Skip
    } else {
        Need::Run
    }
}

fn prepare_agent_dir_need(snapshot: &Snapshot) -> Need {
    if remove_agent_dir_need(snapshot) == Need::Run {
        return Need::Run;
    }
    match existing_directory(snapshot, Check::AgentDirExists, Check::AgentDirIsDirectory) {
        Ok(true) if passes(snapshot, &[Check::AgentDirOwnerGid, Check::AgentDirMode]) => Need::Skip,
        Ok(true) | Err(Need::Run) => Need::Run,
        Ok(false) => Need::Skip,
        Err(need) => need,
    }
}

fn prepare_core_dir_need(snapshot: &Snapshot) -> Need {
    match existing_directory(snapshot, Check::CoreDirExists, Check::CoreDirIsDirectory) {
        Ok(true) if !status_of(snapshot, Check::CoreDirOwnerUid).is_pass() => Need::Skip,
        Ok(true) if status_of(snapshot, Check::CoreDirMode).is_pass() => Need::Skip,
        Ok(true) | Err(Need::Run) => Need::Run,
        Ok(false) => Need::Skip,
        Err(need) => need,
    }
}

/// A home that exists in any form is not created again; what is wrong with it is the mode
/// step's or the operator's. Like the mode step, it acts only at `AGENT_HOME`.
fn create_home_need(snapshot: &Snapshot) -> Need {
    let home = &snapshot.agent_home;
    match &home.state {
        AgentHomeState::Missing if home.is_at_agent_home() => Need::Run,
        AgentHomeState::Ok | AgentHomeState::Missing | AgentHomeState::Wrong(_) => Need::Skip,
        AgentHomeState::Unreachable(why) => Need::Blocked(why.clone()),
        AgentHomeState::Unrecognised(what) => Need::Blocked(format!("unrecognised {what}")),
    }
}

/// Runs when only the mode is wider than 0700, at the path the chmod names. A missing home is
/// planned too, since `createhomedir` may make it wider; the step is decided again after it. A
/// record not yet read is the one the user step creates at that path.
fn narrow_home_need(snapshot: &Snapshot) -> Need {
    let home = &snapshot.agent_home;
    let at_chmod_path = home.is_at_agent_home();
    match &home.state {
        AgentHomeState::Missing if at_chmod_path => Need::Run,
        AgentHomeState::Wrong(mismatch) if at_chmod_path && mismatch.is_only_a_wider_mode() => {
            Need::Run
        }
        AgentHomeState::Ok | AgentHomeState::Missing | AgentHomeState::Wrong(_) => Need::Skip,
        AgentHomeState::Unreachable(why) => Need::Blocked(why.clone()),
        AgentHomeState::Unrecognised(what) => Need::Blocked(format!("unrecognised {what}")),
    }
}

/// A prefix another user owns, or that is a link, is left to the operator; nothing is
/// installed into it.
fn prefix_need(snapshot: &Snapshot, then: impl FnOnce(&tool_prefix::Probe) -> Need) -> Need {
    match &snapshot.prefix.directory {
        DirectoryState::Foreign(_) => Need::Skip,
        DirectoryState::Unreachable(why) => Need::Blocked(why.clone()),
        DirectoryState::Settled | DirectoryState::Missing | DirectoryState::WrongMode(_) => {
            then(&snapshot.prefix)
        }
    }
}

fn create_prefix_need(probe: &tool_prefix::Probe) -> Need {
    match (&probe.directory, &probe.tree) {
        (DirectoryState::Settled, TreeState::Unreachable(why)) => Need::Blocked(why.clone()),
        (DirectoryState::Settled, TreeState::Closed { .. } | TreeState::Open { .. }) => Need::Skip,
        _ => Need::Run,
    }
}

fn tool_need<'state>(states: impl IntoIterator<Item = &'state ToolState>) -> Need {
    let mut need = Need::Skip;
    for state in states {
        match state {
            ToolState::Pinned => {}
            ToolState::Absent
            | ToolState::WrongVersion(_)
            | ToolState::WrongSource(_)
            | ToolState::Modified(_) => {
                need = Need::Run;
            }
            ToolState::Unreachable(why) => return Need::Blocked(why.clone()),
        }
    }
    need
}

fn station_need(probe: &tool_prefix::Probe) -> Need {
    let mut need = Need::Skip;
    for (_, state) in &probe.station {
        match state {
            StationState::Current => {}
            StationState::Absent | StationState::Modified(_) | StationState::Stale { .. } => {
                need = Need::Run;
            }
            StationState::Unreachable(why) => return Need::Blocked(why.clone()),
        }
    }
    need
}

/// Decided on the listing, not the finding: an absent or stale entry, or the rule's entry with
/// another `Defaults!` line, is the station's own file to write again; other no-password
/// entries are the operator's to remove, and do not keep the rule from being installed.
fn sudoers_need(snapshot: &Snapshot) -> Need {
    match &snapshot.sudoers {
        Listing::PasswordRequired | Listing::NotAllowed => Need::Run,
        Listing::Listed(reading) => {
            if reading.entry == Entry::Exact && reading.defaults == DefaultsLine::Exact {
                Need::Skip
            } else {
                Need::Run
            }
        }
        Listing::Refused(why) => Need::Blocked(why.clone()),
        Listing::Unrecognised(text) => Need::Blocked(format!("sudo -l answered {text}")),
    }
}

fn need(remedy: Remedy, snapshot: &Snapshot) -> Need {
    let absence = |check| need_for_absence(&status_of(snapshot, check));
    match remedy {
        Remedy::CreateAgentGroup => absence(Check::AgentGroupExists),
        Remedy::CreateAgentUser => absence(Check::AgentUserExists),
        Remedy::CreateAgentHome => create_home_need(snapshot),
        Remedy::NarrowAgentHomeMode => narrow_home_need(snapshot),
        Remedy::CreateSharedGroup => absence(Check::SharedGroupExists),
        Remedy::AddDeveloperToSharedGroup => absence(Check::DeveloperInSharedGroup),
        Remedy::AddAgentToSharedGroup => absence(Check::AgentInSharedGroup),
        Remedy::CloseDeveloperHome => {
            need_for_wrong(&status_of(snapshot, Check::DeveloperHomeClosedToAgent))
        }
        Remedy::RemoveForeignAgentSocketDir => remove_agent_dir_need(snapshot),
        Remedy::PrepareAgentSocketDir => prepare_agent_dir_need(snapshot),
        Remedy::PrepareCoreSocketDir => prepare_core_dir_need(snapshot),
        Remedy::CreateToolPrefix => prefix_need(snapshot, create_prefix_need),
        Remedy::InstallMise => prefix_need(snapshot, |probe| tool_need([&probe.mise])),
        Remedy::InstallAgentTools => prefix_need(snapshot, |probe| {
            tool_need(probe.tools.iter().map(|(_, _, state)| state))
        }),
        Remedy::InstallStationBinaries => prefix_need(snapshot, station_need),
        Remedy::InstallSudoersRule => sudoers_need(snapshot),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Plan {
    steps: Vec<Remedy>,
    blocked: Vec<(Remedy, String)>,
}

fn plan(snapshot: &Snapshot) -> Plan {
    let mut steps = Vec::new();
    let mut blocked = Vec::new();
    for &remedy in &REMEDIES {
        match need(remedy, snapshot) {
            Need::Run => steps.push(remedy),
            Need::Skip => {}
            Need::Blocked(why) => blocked.push((remedy, why)),
        }
    }
    Plan { steps, blocked }
}

/// Failing findings that no planned step targets: these are left to the operator.
fn unremedied<'snapshot>(
    snapshot: &'snapshot Snapshot,
    steps: &[Remedy],
) -> Vec<&'snapshot Finding> {
    snapshot
        .findings
        .iter()
        .filter(|finding| !finding.status.is_pass())
        .filter(|finding| {
            !steps
                .iter()
                .any(|remedy| remedy.targets().contains(&finding.check))
        })
        .collect()
}

/// The group a directory is given; `gid` is `None` while the group does not exist yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupTarget {
    gid: Option<u32>,
    name: &'static str,
}

/// A directory to create level by level, then give a group and an exact mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryWork {
    /// Levels created when missing, parents first; the last is the target.
    levels: Vec<PathBuf>,
    group: Option<GroupTarget>,
    mode: u32,
}

impl DirectoryWork {
    fn target(&self) -> Option<&Path> {
        self.levels.last().map(PathBuf::as_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    /// A program and its arguments, run through sudo.
    Root(Vec<String>),
    /// Done in this process, as the developer.
    Directory(DirectoryWork),
    /// A program run as the developer on a directory that must be the developer's own.
    OnOwnDirectory {
        words: Vec<String>,
        directory: PathBuf,
    },
    /// A step of the shared tool prefix, as the developer.
    Prefix(PrefixStep),
    /// The sudoers rule: written and checked as the developer, installed by root.
    Sudoers(SudoersWork),
}

#[cfg(test)]
impl Action {
    /// What the action runs through sudo, in order.
    fn root_commands(&self) -> Vec<Vec<String>> {
        match self {
            Self::Root(words) => vec![words.clone()],
            Self::Sudoers(work) => sudoers_root_commands(&work.candidate).to_vec(),
            Self::Directory(_) | Self::OnOwnDirectory { .. } | Self::Prefix(_) => Vec::new(),
        }
    }
}

/// The candidate rule, the private directories it is written under, and the rule itself, or
/// why no rule can be written for this developer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SudoersWork {
    levels: Vec<PathBuf>,
    candidate: PathBuf,
    rule: Result<String, String>,
}

/// Root's three commands: install the checked candidate to the staging name, root's own
/// `visudo -c -f` of the installed file, then one rename onto the drop-in.
fn sudoers_root_commands(candidate: &Path) -> [Vec<String>; 3] {
    let candidate = candidate.display().to_string();
    [
        strings(&[
            INSTALL,
            "-S",
            "-o",
            "root",
            "-g",
            "wheel",
            "-m",
            "0440",
            &candidate,
            SUDOERS_STAGED,
        ]),
        strings(&[VISUDO, "-c", "-f", SUDOERS_STAGED]),
        strings(&[MV, "-f", SUDOERS_STAGED, SUDOERS_DROP_IN]),
    ]
}

fn visudo_words(candidate: &Path) -> Vec<String> {
    vec![
        VISUDO.to_string(),
        "-c".to_string(),
        "-f".to_string(),
        candidate.display().to_string(),
    ]
}

fn sudoers_work(snapshot: &Snapshot) -> Option<SudoersWork> {
    let home = snapshot.developer_home.clone()?;
    let mut levels = Vec::new();
    let mut level = home;
    for part in CANDIDATE_DIR_RELATIVE {
        level = level.join(part);
        levels.push(level.clone());
    }
    let candidate = level.join(CANDIDATE_NAME);
    let rule = setup::rule_zmx().and_then(|(zmx, _)| {
        agent_switch::rule(&snapshot.developer.username, AGENT_USER_NAME, &zmx)
            .map_err(|error| error.to_string())
    });
    Some(SudoersWork {
        levels,
        candidate,
        rule,
    })
}

/// `visudo -c -f` prints `<file>: parsed OK` and exits 0 for a rule it accepts, and names the
/// line and column of what it refuses on stderr with exit 1.
fn decode_visudo(captured: &Captured, candidate: &Path) -> Result<(), String> {
    let accepted = format!("{}: parsed OK", candidate.display());
    let stdout: Vec<&str> = meaningful_lines(&captured.stdout).collect();
    let quiet = meaningful_lines(&captured.stderr).next().is_none();
    match &captured.exit {
        Exit::Code(0) if stdout == [accepted.as_str()] && quiet => Ok(()),
        Exit::Code(1) => Err(format!(
            "visudo refused the rule: {}",
            first_meaningful(&captured.stdout, &captured.stderr)
        )),
        other => Err(format!(
            "visudo answered {other:?} with unrecognised output: {}",
            first_meaningful(&captured.stdout, &captured.stderr)
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixStep {
    CreateDirectories,
    InstallMise,
    InstallAgentTools,
    InstallStation,
}

/// What a prefix step does, as an operator would read it.
fn render_prefix(step: PrefixStep, prefix: &Prefix) -> Vec<String> {
    let root = prefix.root().display();
    let mut lines = match step {
        PrefixStep::CreateDirectories => vec![format!(
            "mkdir -m 0755 {root} {} {}",
            prefix.bin().display(),
            prefix.data_dir().display()
        )],
        PrefixStep::InstallMise => vec![
            format!(
                "download mise {MISE_PINNED_VERSION} and SHASUMS256.txt from github.com/jdx/mise releases"
            ),
            "require the published sha256 and the download's to equal the pinned digest"
                .to_string(),
            format!("install as {}, mode 0755", prefix.mise().display()),
        ],
        PrefixStep::InstallAgentTools => {
            let pins = tool_prefix::global_config().map_or_else(
                |why| why,
                |config| config.lines().skip(1).collect::<Vec<_>>().join(", "),
            );
            vec![
                format!("write {}: {pins}", prefix.global_config().display()),
                format!(
                    "umask 022; {} install, from / with only the prefix in the environment",
                    prefix.mise().display()
                ),
                format!(
                    "record each tool's executable, which mise which must name, and its install's sha256 in {}",
                    prefix.manifest().display()
                ),
            ]
        }
        PrefixStep::InstallStation => vec![
            "mbx build --release --locked -p xtask -p tycho".to_string(),
            format!(
                "install target/release/xtask and tycho into {}, mode 0755",
                prefix.bin().display()
            ),
            format!(
                "record their sha256 and the commit in {}",
                prefix.manifest().display()
            ),
        ],
    };
    lines.push("(as the developer)".to_string());
    lines
}

fn strings(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_string()).collect()
}

/// The `-GID` argument is the agent group's gid, or the placeholder while the group is absent;
/// the placeholder never reaches a command, since `execute` refuses it.
fn create_user_command(agent_group_gid: Option<u32>) -> Vec<String> {
    let gid =
        agent_group_gid.map_or_else(|| AGENT_GID_PLACEHOLDER.to_string(), |gid| gid.to_string());
    let mut words = strings(&[
        SYSADMINCTL,
        "-addUser",
        AGENT_USER_NAME,
        "-fullName",
        AGENT_FULL_NAME,
        "-password",
        "-",
        "-home",
        AGENT_HOME,
        "-shell",
        AGENT_SHELL,
        "-GID",
    ]);
    words.push(gid);
    words
}

fn narrow_home_command() -> Vec<String> {
    vec![
        CHMOD.to_string(),
        format!("{AGENT_HOME_MODE:04o}"),
        AGENT_HOME.to_string(),
    ]
}

fn add_member_command(user: &str) -> Vec<String> {
    strings(&[
        DSEDITGROUP,
        "-o",
        "edit",
        "-a",
        user,
        "-t",
        "user",
        SHARED_GROUP_NAME,
    ])
}

fn agent_dir_work(snapshot: &Snapshot) -> DirectoryWork {
    DirectoryWork {
        levels: vec![PathBuf::from(AGENT_SOCKET_DIR)],
        group: Some(GroupTarget {
            gid: snapshot.shared_group_gid,
            name: SHARED_GROUP_NAME,
        }),
        mode: AGENT_SOCKET_DIR_MODE,
    }
}

fn core_dir_work(snapshot: &Snapshot) -> Option<DirectoryWork> {
    let target = snapshot.core_dir.clone()?;
    let mut levels = Vec::new();
    if snapshot.core_parent_missing {
        levels.push(target.parent()?.to_path_buf());
    }
    levels.push(target);
    Some(DirectoryWork {
        levels,
        group: None,
        mode: CORE_SOCKET_DIR_MODE,
    })
}

fn action(remedy: Remedy, snapshot: &Snapshot) -> Option<Action> {
    let developer = snapshot.developer.username.as_str();
    Some(match remedy {
        Remedy::CreateAgentGroup => Action::Root(strings(&[
            DSEDITGROUP,
            "-o",
            "create",
            "-r",
            AGENT_FULL_NAME,
            AGENT_GROUP_NAME,
        ])),
        Remedy::CreateAgentUser => Action::Root(create_user_command(snapshot.agent_group_gid)),
        Remedy::CreateAgentHome => {
            Action::Root(strings(&[CREATEHOMEDIR, "-c", "-u", AGENT_USER_NAME]))
        }
        Remedy::NarrowAgentHomeMode => Action::Root(narrow_home_command()),
        Remedy::CreateSharedGroup => {
            Action::Root(strings(&[DSEDITGROUP, "-o", "create", SHARED_GROUP_NAME]))
        }
        Remedy::AddDeveloperToSharedGroup => Action::Root(add_member_command(developer)),
        Remedy::AddAgentToSharedGroup => Action::Root(add_member_command(AGENT_USER_NAME)),
        Remedy::CloseDeveloperHome => {
            let home = snapshot.developer_home.clone()?;
            Action::OnOwnDirectory {
                words: vec![
                    CHMOD.to_string(),
                    "+a".to_string(),
                    HOME_DENY_ENTRY.to_string(),
                    home.display().to_string(),
                ],
                directory: home,
            }
        }
        Remedy::RemoveForeignAgentSocketDir => Action::Root(strings(&[RMDIR, AGENT_SOCKET_DIR])),
        Remedy::PrepareAgentSocketDir => Action::Directory(agent_dir_work(snapshot)),
        Remedy::PrepareCoreSocketDir => Action::Directory(core_dir_work(snapshot)?),
        Remedy::CreateToolPrefix => Action::Prefix(PrefixStep::CreateDirectories),
        Remedy::InstallMise => Action::Prefix(PrefixStep::InstallMise),
        Remedy::InstallAgentTools => Action::Prefix(PrefixStep::InstallAgentTools),
        Remedy::InstallStationBinaries => Action::Prefix(PrefixStep::InstallStation),
        Remedy::InstallSudoersRule => Action::Sudoers(sudoers_work(snapshot)?),
    })
}

fn shell_word(word: &str) -> String {
    if word == AGENT_GID_PLACEHOLDER || !word.contains(' ') {
        word.to_string()
    } else {
        format!("\"{word}\"")
    }
}

/// The commands as an operator would type them, one per line.
fn render(action: &Action) -> Vec<String> {
    match action {
        Action::Root(words) => {
            let shown: Vec<String> = words.iter().map(|word| shell_word(word)).collect();
            vec![format!("sudo {}", shown.join(" "))]
        }
        Action::Directory(work) => {
            let mut lines: Vec<String> = work
                .levels
                .iter()
                .map(|level| format!("mkdir -m {CREATE_MODE:04o} {}", level.display()))
                .collect();
            if let Some(target) = work.target() {
                if let Some(group) = work.group {
                    lines.push(format!("chgrp {} {}", group.name, target.display()));
                }
                lines.push(format!("chmod {:04o} {}", work.mode, target.display()));
            }
            lines.push("(as the developer, in this process)".to_string());
            lines
        }
        Action::OnOwnDirectory { words, .. } => {
            let shown: Vec<String> = words.iter().map(|word| shell_word(word)).collect();
            vec![shown.join(" "), "(as the developer)".to_string()]
        }
        Action::Prefix(step) => render_prefix(*step, &Prefix::production()),
        Action::Sudoers(work) => {
            let candidate = work.candidate.display();
            let mut lines = vec![format!(
                "write {candidate}, mode {CANDIDATE_MODE:04o}, in a {PRIVATE_MODE:04o} directory (as the developer):"
            )];
            match &work.rule {
                Ok(rule) => lines.extend(rule.lines().map(|line| format!("  {line}"))),
                Err(why) => lines.push(format!("  no rule can be written: {why}")),
            }
            lines.push(format!(
                "{} (as the developer)",
                visudo_words(&work.candidate).join(" ")
            ));
            for words in sudoers_root_commands(&work.candidate) {
                lines.push(format!("sudo {}", words.join(" ")));
            }
            lines
        }
    }
}

/// How a remedy's command ended, through sudo or as the developer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandOutcome {
    Succeeded,
    /// sudo itself refused: no password, wrong password, or not in sudoers.
    SudoRefused(String),
    /// The command exited non-zero, or reported an error on a zero exit.
    Failed(String),
    /// Signal, timeout, output over the cap, or the process did not start.
    NotFinished(String),
    Unrecognised(String),
}

fn meaningful_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && *line != SUDO_RETRY_LINE)
}

fn first_meaningful(stdout: &str, stderr: &str) -> String {
    meaningful_lines(stderr)
        .chain(meaningful_lines(stdout))
        .next()
        .unwrap_or("no output")
        .to_string()
}

fn is_sudo_refusal(stderr: &str) -> bool {
    let mut lines = meaningful_lines(stderr).peekable();
    lines.peek().is_some()
        && lines.all(|line| {
            (line.starts_with("sudo: ") && line.contains("password"))
                || line.contains("is not in the sudoers file")
        })
}

/// sysadminctl logs each step to stderr as `<date> sysadminctl[<pid>:<thread>] <message>`.
fn decode_sysadminctl_success(stdout: &str, stderr: &str) -> CommandOutcome {
    if meaningful_lines(stdout).next().is_some() {
        return CommandOutcome::Unrecognised(first_meaningful(stdout, ""));
    }
    for line in meaningful_lines(stderr) {
        let Some((_, message)) = line.split_once("] ") else {
            return CommandOutcome::Unrecognised(line.to_string());
        };
        if !line.contains("sysadminctl[") {
            return CommandOutcome::Unrecognised(line.to_string());
        }
        let lowered = message.to_lowercase();
        if lowered.contains("error") || lowered.contains("fail") {
            return CommandOutcome::Failed(line.to_string());
        }
    }
    CommandOutcome::Succeeded
}

/// `createhomedir` reports `creating home directories for (<user>)`, then `created (<path>)`
/// per directory it made, or `cannot create '<path>' (<errno>)`. The forms are the binary's
/// format strings; which stream carries them is not relied on.
fn decode_createhomedir_success(stdout: &str, stderr: &str) -> CommandOutcome {
    let announced = format!("creating home directories for ({AGENT_USER_NAME})");
    for line in meaningful_lines(stdout).chain(meaningful_lines(stderr)) {
        if line.starts_with("cannot create '") {
            return CommandOutcome::Failed(line.to_string());
        }
        let created = line
            .strip_prefix("created (")
            .and_then(|rest| rest.strip_suffix(')'))
            .is_some_and(|path| path.starts_with('/'));
        if line != announced && !created {
            return CommandOutcome::Unrecognised(line.to_string());
        }
    }
    CommandOutcome::Succeeded
}

fn decode_command(program: &str, captured: &Captured) -> CommandOutcome {
    let (stdout, stderr) = (captured.stdout.as_str(), captured.stderr.as_str());
    match &captured.exit {
        Exit::Code(0) if program == SYSADMINCTL => decode_sysadminctl_success(stdout, stderr),
        Exit::Code(0) if program == CREATEHOMEDIR => decode_createhomedir_success(stdout, stderr),
        Exit::Code(0)
            if meaningful_lines(stdout)
                .chain(meaningful_lines(stderr))
                .next()
                .is_none() =>
        {
            CommandOutcome::Succeeded
        }
        Exit::Code(0) => CommandOutcome::Unrecognised(first_meaningful(stdout, stderr)),
        Exit::Code(1) if is_sudo_refusal(stderr) => {
            CommandOutcome::SudoRefused(first_meaningful("", stderr))
        }
        Exit::Code(code) => {
            CommandOutcome::Failed(format!("exit {code}: {}", first_meaningful(stdout, stderr)))
        }
        Exit::Signal => CommandOutcome::NotFinished("ended by a signal".to_string()),
        Exit::TimedOut => {
            CommandOutcome::NotFinished(format!("did not finish within {REMEDY_TIMEOUT:?}"))
        }
        Exit::OutputTooLarge => CommandOutcome::NotFinished("output over the cap".to_string()),
        Exit::OutputUnreadable => CommandOutcome::NotFinished("output unreadable".to_string()),
        Exit::OutputStillOpen => {
            CommandOutcome::NotFinished("output still open after it exited".to_string())
        }
        Exit::NotStarted(why) => CommandOutcome::NotFinished(format!("did not start: {why}")),
    }
}

/// Everything the run touches outside its own logic, so tests can record instead of act.
pub trait Host {
    fn snapshot(&mut self) -> Result<Snapshot, String>;
    fn run_as_root(&mut self, words: &[String]) -> Captured;
    fn prepare_directory(&mut self, work: &DirectoryWork, developer_uid: u32)
    -> Result<(), String>;
    /// Runs a program as the developer once `directory` is checked to be the developer's own.
    fn run_on_own_directory(
        &mut self,
        words: &[String],
        directory: &Path,
        developer_uid: u32,
    ) -> Result<Captured, String>;
    /// Runs one step of the shared tool prefix as the developer.
    fn run_prefix_step(&mut self, step: PrefixStep, developer: &Identity) -> Result<(), String>;
    /// Writes `content` new at `file`, under `levels` created or checked as the developer's
    /// own private directories.
    fn write_private(
        &mut self,
        levels: &[PathBuf],
        file: &Path,
        content: &str,
        developer_uid: u32,
    ) -> Result<(), String>;
    /// Runs a program as the developer with stdin closed.
    fn run_as_developer(&mut self, words: &[String]) -> Captured;
    /// Prints the setup report and returns its exit code.
    fn report(&mut self, developer: &Identity) -> i32;
}

#[derive(Debug)]
pub struct SystemHost;

impl Host for SystemHost {
    fn snapshot(&mut self) -> Result<Snapshot, String> {
        let developer = setup::current_identity()?;
        let (mut findings, agent_home) = setup::record_probe(&developer);
        findings.extend(setup::agent_record_findings());
        let prefix = tool_prefix::Probe::read(&Prefix::production(), &developer);
        findings.extend(prefix.findings());
        let (sudoers_finding, sudoers) = setup::sudoers_rule_probe();
        findings.push(sudoers_finding);
        let developer_home = setup::resolve_home(&developer.username).ok();
        let core_dir = developer_home
            .as_deref()
            .map(|home| PathBuf::from(setup::core_socket_dir_path(home)));
        let core_parent_missing = core_dir
            .as_deref()
            .and_then(Path::parent)
            .is_some_and(|parent| {
                matches!(fs::symlink_metadata(parent), Err(error) if error.kind() == io::ErrorKind::NotFound)
            });
        Ok(Snapshot {
            agent_group_gid: setup::group_id(AGENT_GROUP_NAME).ok().flatten(),
            shared_group_gid: setup::group_id(SHARED_GROUP_NAME).ok().flatten(),
            agent_home,
            agent_dir_owner: fs::symlink_metadata(AGENT_SOCKET_DIR)
                .ok()
                .map(|metadata| metadata.uid()),
            developer_home: developer_home.map(PathBuf::from),
            core_dir,
            core_parent_missing,
            developer,
            findings,
            prefix,
            sudoers,
        })
    }

    fn run_as_root(&mut self, words: &[String]) -> Captured {
        let mut command = Command::new(SUDO);
        command.args(words);
        process::run_bounded_with_terminal_input(&mut command, REMEDY_TIMEOUT)
    }

    fn prepare_directory(
        &mut self,
        work: &DirectoryWork,
        developer_uid: u32,
    ) -> Result<(), String> {
        prepare_directory(work, developer_uid)
    }

    /// The standard library sets no ACL on a descriptor, so `chmod +a` gets the path. The home
    /// sits in root-owned `/Users`, so only root can put another entry at that name between
    /// this check and the command.
    fn run_on_own_directory(
        &mut self,
        words: &[String],
        directory: &Path,
        developer_uid: u32,
    ) -> Result<Captured, String> {
        open_own_directory(directory, developer_uid)?;
        let (program, arguments) = words
            .split_first()
            .ok_or_else(|| "an empty command".to_string())?;
        let mut command = Command::new(program);
        command.args(arguments);
        Ok(process::run_bounded_capturing_stderr(
            &mut command,
            DEVELOPER_COMMAND_TIMEOUT,
        ))
    }

    fn run_prefix_step(&mut self, step: PrefixStep, developer: &Identity) -> Result<(), String> {
        let prefix = Prefix::production();
        match step {
            PrefixStep::CreateDirectories => {
                prefix_install::create_directories(&prefix, developer.uid)
            }
            PrefixStep::InstallMise => prefix_install::install_mise(&prefix),
            PrefixStep::InstallAgentTools => {
                prefix_install::install_agent_tools(&prefix, developer)
            }
            PrefixStep::InstallStation => prefix_install::install_station(&prefix),
        }
    }

    fn write_private(
        &mut self,
        levels: &[PathBuf],
        file: &Path,
        content: &str,
        developer_uid: u32,
    ) -> Result<(), String> {
        write_private(levels, file, content, developer_uid)
    }

    fn run_as_developer(&mut self, words: &[String]) -> Captured {
        let (program, arguments) = words
            .split_first()
            .map_or(("", &[][..]), |(program, rest)| (program.as_str(), rest));
        let mut command = Command::new(program);
        command.args(arguments).current_dir("/");
        process::run_bounded_capturing_stderr(&mut command, DEVELOPER_COMMAND_TIMEOUT)
    }

    fn report(&mut self, developer: &Identity) -> i32 {
        let produced = setup::developer_findings(developer);
        let mut findings = setup::assemble(Side::Developer, &produced);
        for record in setup::agent_record_findings() {
            if let Some(slot) = findings
                .iter_mut()
                .find(|finding| finding.check == record.check)
            {
                *slot = record;
            }
        }
        setup::print_findings(&findings);
        setup::summarize(Some(Side::Developer), &findings)
    }
}

/// Opens a real directory the developer owns. The path is checked without following links,
/// then opened with `O_NOFOLLOW`, and the opened inode must be the checked one, so a link or
/// another directory swapped in between is refused rather than followed.
pub fn open_own_directory(path: &Path, developer_uid: u32) -> Result<File, String> {
    let shown = path.display();
    let checked = fs::symlink_metadata(path).map_err(|error| format!("{shown}: {error}"))?;
    if !checked.file_type().is_dir() {
        return Err(format!("{shown} is not a directory"));
    }
    if checked.uid() != developer_uid {
        return Err(format!(
            "{shown} is owned by uid {}, not the developer",
            checked.uid()
        ));
    }
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
    Ok(directory)
}

/// Creates one level; an existing level must already be a real directory the developer owns.
pub fn create_level(path: &Path, developer_uid: u32) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => open_own_directory(path, developer_uid).map(drop),
        Err(error) if error.kind() == io::ErrorKind::NotFound => DirBuilder::new()
            .mode(CREATE_MODE)
            .create(path)
            .map_err(|error| format!("mkdir {}: {error}", path.display())),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Creates or checks each level as the developer's own, makes the last one 0700 on its
/// descriptor, then writes the file new there, removing an earlier candidate first: no other
/// user can reach the directory, so nothing can be swapped in between.
fn write_private(
    levels: &[PathBuf],
    file: &Path,
    content: &str,
    developer_uid: u32,
) -> Result<(), String> {
    for level in levels {
        create_level(level, developer_uid)?;
    }
    let last = levels
        .last()
        .ok_or_else(|| "a private file with no directory".to_string())?;
    let directory = open_own_directory(last, developer_uid)?;
    directory
        .set_permissions(Permissions::from_mode(PRIVATE_MODE))
        .map_err(|error| format!("chmod {PRIVATE_MODE:04o} {}: {error}", last.display()))?;
    if file.parent() != Some(last.as_path()) {
        return Err(format!("{} is not in {}", file.display(), last.display()));
    }
    match fs::remove_file(file) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{}: {error}", file.display())),
    }
    let mut written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(CANDIDATE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(file)
        .map_err(|error| format!("{}: {error}", file.display()))?;
    written
        .write_all(content.as_bytes())
        .and_then(|()| written.sync_all())
        .map_err(|error| format!("{}: {error}", file.display()))
}

fn prepare_directory(work: &DirectoryWork, developer_uid: u32) -> Result<(), String> {
    for level in &work.levels {
        create_level(level, developer_uid)?;
    }
    let target = work
        .target()
        .ok_or_else(|| "a directory step with no directory".to_string())?;
    let shown = target.display();
    let directory = open_own_directory(target, developer_uid)?;
    let group = match work.group {
        Some(GroupTarget {
            gid: Some(gid),
            name,
        }) => Some((gid, name)),
        Some(GroupTarget { gid: None, name }) => {
            return Err(format!("the gid of {name} could not be read"));
        }
        None => None,
    };
    if let Some((gid, name)) = group {
        std::os::unix::fs::fchown(&directory, None, Some(gid))
            .map_err(|error| format!("chgrp {name} {shown}: {error}"))?;
    }
    directory
        .set_permissions(Permissions::from_mode(work.mode))
        .map_err(|error| format!("chmod {:04o} {shown}: {error}", work.mode))?;
    let result = directory
        .metadata()
        .map_err(|error| format!("{shown}: {error}"))?;
    let mode = result.mode() & 0o7777;
    if mode != work.mode {
        return Err(format!(
            "{shown} has mode {mode:04o} after chmod {:04o}",
            work.mode
        ));
    }
    match group {
        Some((gid, name)) if result.gid() != gid => Err(format!(
            "{shown} has gid {} after chgrp {name} ({gid})",
            result.gid()
        )),
        _ => Ok(()),
    }
}

fn outcome_result(program: &str, outcome: &CommandOutcome) -> Result<(), String> {
    match outcome {
        CommandOutcome::Succeeded => Ok(()),
        CommandOutcome::SudoRefused(line) => Err(format!("sudo refused: {line}")),
        CommandOutcome::Failed(line) if program == RMDIR => Err(format!(
            "{program} failed: {line}; {FOREIGN_SOCKET_DIR_HINT}"
        )),
        CommandOutcome::Failed(line) => Err(format!("{program} failed: {line}")),
        CommandOutcome::NotFinished(why) => Err(format!("{program} {why}")),
        CommandOutcome::Unrecognised(line) => {
            Err(format!("{program} printed unrecognised output: {line}"))
        }
    }
}

/// Runs one action; any outcome but success is the reason the run stops.
fn execute(host: &mut impl Host, action: &Action, snapshot: &Snapshot) -> Result<(), String> {
    match action {
        Action::Root(words) => {
            if words.iter().any(|word| word == AGENT_GID_PLACEHOLDER) {
                return Err(
                    "the gid of tycho-agent could not be read after creating it".to_string()
                );
            }
            let program = words.first().map_or("", String::as_str);
            println!("xtask provision-agent: {PROMPT_NOTICE}");
            outcome_result(program, &decode_command(program, &host.run_as_root(words)))
        }
        Action::OnOwnDirectory { words, directory } => {
            let program = words.first().map_or("", String::as_str);
            let captured = host.run_on_own_directory(words, directory, snapshot.developer.uid)?;
            outcome_result(program, &decode_command(program, &captured))
        }
        Action::Directory(work) => {
            if let Some(GroupTarget { gid: None, name }) = work.group {
                return Err(format!("the gid of {name} could not be read"));
            }
            host.prepare_directory(work, snapshot.developer.uid)
        }
        Action::Prefix(step) => host.run_prefix_step(*step, &snapshot.developer),
        Action::Sudoers(work) => {
            let rule = work.rule.as_ref().map_err(Clone::clone)?;
            host.write_private(&work.levels, &work.candidate, rule, snapshot.developer.uid)?;
            decode_visudo(
                &host.run_as_developer(&visudo_words(&work.candidate)),
                &work.candidate,
            )?;
            println!("xtask provision-agent: {PROMPT_NOTICE}");
            let [install, check, rename] = sudoers_root_commands(&work.candidate);
            outcome_result(
                INSTALL,
                &decode_command(INSTALL, &host.run_as_root(&install)),
            )?;
            decode_visudo(&host.run_as_root(&check), Path::new(SUDOERS_STAGED))?;
            outcome_result(MV, &decode_command(MV, &host.run_as_root(&rename)))
        }
    }
}

fn verify(remedy: Remedy, snapshot: &Snapshot) -> Result<(), String> {
    if remedy == Remedy::CreateAgentHome {
        return match snapshot.agent_home.state {
            AgentHomeState::Ok | AgentHomeState::Wrong(_) => Ok(()),
            AgentHomeState::Missing
            | AgentHomeState::Unreachable(_)
            | AgentHomeState::Unrecognised(_) => Err(format!(
                "{} ran, but the home probe reads {}",
                remedy.label(),
                status_of(snapshot, Check::AgentHomeDirectory)
            )),
        };
    }
    if remedy == Remedy::RemoveForeignAgentSocketDir {
        return match status_of(snapshot, Check::AgentDirExists) {
            Status::Missing => Ok(()),
            status => Err(format!(
                "{} ran, but the directory probe reads {status}",
                remedy.label()
            )),
        };
    }
    let failing: Vec<String> = remedy
        .targets()
        .iter()
        .filter_map(|&check| {
            let status = status_of(snapshot, check);
            (!status.is_pass()).then(|| format!("{}: {status}", setup::check_name(check)))
        })
        .collect();
    if failing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} ran, but its probes still fail: {}",
            remedy.label(),
            failing.join("; ")
        ))
    }
}

/// Runs the planned steps in order, each only while still needed, each verified after.
fn apply(host: &mut impl Host, steps: &[Remedy], initial: Snapshot) -> Result<Snapshot, String> {
    let mut latest = initial;
    for (index, &remedy) in steps.iter().take(PROVISION_STEPS_MAX).enumerate() {
        let number = index.saturating_add(1);
        match need(remedy, &latest) {
            Need::Run => {}
            Need::Skip => {
                println!(
                    "xtask provision-agent: {number}. {}: already present, skipped",
                    remedy.label()
                );
                continue;
            }
            Need::Blocked(why) => {
                return Err(format!("{}: a probe could not run: {why}", remedy.label()));
            }
        }
        let action = action(remedy, &latest)
            .ok_or_else(|| format!("{}: the developer's home is unknown", remedy.label()))?;
        println!("xtask provision-agent: {number}. {}", remedy.label());
        for line in render(&action) {
            println!("  {line}");
        }
        execute(host, &action, &latest).map_err(|why| format!("{}: {why}", remedy.label()))?;
        latest = host.snapshot()?;
        verify(remedy, &latest)?;
    }
    Ok(latest)
}

fn print_plan(plan: &Plan, snapshot: &Snapshot) {
    match plan.steps.len() {
        0 => println!("xtask provision-agent: plan: nothing to run"),
        1 => println!("xtask provision-agent: plan: 1 step"),
        count => println!("xtask provision-agent: plan: {count} steps"),
    }
    for (index, &remedy) in plan.steps.iter().enumerate() {
        println!("  {}. {}", index.saturating_add(1), remedy.label());
        for line in action(remedy, snapshot)
            .map(|action| render(&action))
            .unwrap_or_default()
        {
            println!("     {line}");
        }
    }
    for (remedy, why) in &plan.blocked {
        println!(
            "xtask provision-agent: cannot plan {}: a probe could not run: {why}",
            remedy.label()
        );
    }
    for finding in unremedied(snapshot, &plan.steps) {
        println!(
            "xtask provision-agent: no remedy here for {}: {}",
            setup::check_name(finding.check),
            finding.status
        );
        if let Some(hint) = &finding.hint {
            println!("  hint: {hint}");
        }
    }
}

fn print_operator_steps() {
    println!("xtask provision-agent: left to the operator");
    println!("  from your terminal, as the developer, who owns the Claude and Codex plans:");
    print_commands(developer_credential_commands(&Prefix::production()));
    println!("  (paste the token setup-token shows into credentials set claude, then Ctrl-D)");
    println!("  then, each as tycho-agent with no login shell, in this order:");
    print_commands(operator_commands(&Prefix::production()));
    println!("  optional, as the developer, if the entire mirror is the sync remote: entire auth");
}

fn print_commands<const N: usize>(commands: Result<[String; N], String>) {
    match commands {
        Ok(commands) => {
            for command in commands {
                println!("    {command}");
            }
        }
        Err(why) => println!("    the commands cannot be shown: {why}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Apply,
    Print,
}

fn refusal_for(developer: &Identity) -> Option<String> {
    if developer.username == AGENT_USER_NAME {
        return Some(format!("runs as the developer, not as {AGENT_USER_NAME}"));
    }
    if developer.uid == 0 {
        return Some("runs as the developer, not as root; sudo is asked for per step".to_string());
    }
    None
}

fn provision(mode: Mode, stdin_is_terminal: bool, host: &mut impl Host) -> i32 {
    if mode == Mode::Apply && !stdin_is_terminal {
        eprintln!(
            "xtask provision-agent: stdin is not a terminal, and sudo and sysadminctl prompt on it; run it from a terminal, or pass --print for the plan"
        );
        return 2;
    }
    let snapshot = match host.snapshot() {
        Ok(snapshot) => snapshot,
        Err(why) => {
            eprintln!("xtask provision-agent: cannot tell who is running: {why}");
            return 1;
        }
    };
    if let Some(why) = refusal_for(&snapshot.developer) {
        eprintln!("xtask provision-agent: {why}");
        return 2;
    }
    let plan = plan(&snapshot);
    print_plan(&plan, &snapshot);
    if !plan.blocked.is_empty() {
        return 1;
    }
    if mode == Mode::Print {
        print_operator_steps();
        let outstanding = !plan.steps.is_empty() || !unremedied(&snapshot, &plan.steps).is_empty();
        return i32::from(outstanding);
    }
    let developer = snapshot.developer.clone();
    if let Err(why) = apply(host, &plan.steps, snapshot) {
        eprintln!("xtask provision-agent: stopped: {why}");
        return 1;
    }
    let code = host.report(&developer);
    print_operator_steps();
    code
}

pub fn run(arguments: &[String]) -> i32 {
    let mode = match arguments {
        [] => Mode::Apply,
        [flag] if flag == "--print" => Mode::Print,
        _ => {
            eprintln!("usage: xtask provision-agent [--print]");
            return 2;
        }
    };
    provision(mode, io::stdin().is_terminal(), &mut SystemHost)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::{Differs, HomeMismatch};
    use std::collections::VecDeque;
    use tycho_types::agent_switch::Reading;

    const DEVELOPER_UID: u32 = 501;
    const AGENT_GID: u32 = 502;
    const SHARED_GID: u32 = 503;
    const RECORD_CHECKS: [Check; 18] = [
        Check::AgentGroupExists,
        Check::AgentUserExists,
        Check::AgentHomeDirectory,
        Check::SharedGroupExists,
        Check::DeveloperInSharedGroup,
        Check::DeveloperHomeClosedToAgent,
        Check::AgentDirExists,
        Check::AgentDirIsDirectory,
        Check::AgentDirOwnerUid,
        Check::AgentDirOwnerGid,
        Check::AgentDirMode,
        Check::CoreDirFitsBudget,
        Check::CoreDirExists,
        Check::CoreDirIsDirectory,
        Check::CoreDirOwnerUid,
        Check::CoreDirMode,
        Check::AgentInSharedGroup,
        Check::AgentPrimaryGroup,
    ];

    fn identity(username: &str, uid: u32) -> Identity {
        Identity {
            uid,
            username: username.to_string(),
        }
    }

    fn settled_prefix() -> tool_prefix::Probe {
        tool_prefix::Probe {
            directory: DirectoryState::Settled,
            tree: TreeState::Closed { examined: 93 },
            mise: ToolState::Pinned,
            tools: tool_prefix::AgentTool::ALL
                .iter()
                .map(|&tool| (tool, tool_prefix::pinned_version(tool), ToolState::Pinned))
                .collect(),
            station: tool_prefix::StationBinary::ALL
                .iter()
                .map(|&binary| (binary, StationState::Current))
                .collect(),
        }
    }

    /// Sets the prefix probe and the findings made from it, as `SystemHost::snapshot` does.
    fn with_prefix(mut snapshot: Snapshot, prefix: tool_prefix::Probe) -> Snapshot {
        let findings = prefix.findings();
        snapshot
            .findings
            .retain(|kept| findings.iter().all(|finding| finding.check != kept.check));
        snapshot.findings.extend(findings);
        snapshot.prefix = prefix;
        snapshot
    }

    fn all_present() -> Snapshot {
        let snapshot = Snapshot {
            developer: identity("frits", DEVELOPER_UID),
            findings: RECORD_CHECKS
                .iter()
                .chain(std::iter::once(&Check::SudoersRule))
                .map(|&check| Finding::new(check, Status::Present))
                .collect(),
            agent_group_gid: Some(AGENT_GID),
            shared_group_gid: Some(SHARED_GID),
            agent_home: AgentHome {
                path: Some(AGENT_HOME.to_string()),
                state: AgentHomeState::Ok,
            },
            agent_dir_owner: Some(DEVELOPER_UID),
            developer_home: Some(PathBuf::from("/Users/frits")),
            core_dir: Some(PathBuf::from("/Users/frits/.tycho/zmx")),
            core_parent_missing: false,
            prefix: settled_prefix(),
            sudoers: Listing::Listed(exact_reading()),
        };
        with_prefix(snapshot, settled_prefix())
    }

    fn with(mut snapshot: Snapshot, changes: &[(Check, Status)]) -> Snapshot {
        for (check, status) in changes {
            for finding in &mut snapshot.findings {
                if finding.check == *check {
                    finding.status = status.clone();
                }
            }
        }
        snapshot
    }

    fn wrong(found: &str, wanted: &str) -> Status {
        Status::Wrong {
            found: found.to_string(),
            wanted: wanted.to_string(),
        }
    }

    fn all_missing() -> Snapshot {
        let absent = Status::Unreachable {
            why: "directory does not exist".to_string(),
        };
        let mut snapshot = with(
            all_present(),
            &[
                (Check::AgentGroupExists, Status::Missing),
                (Check::AgentUserExists, Status::Missing),
                (Check::SharedGroupExists, Status::Missing),
                (Check::DeveloperInSharedGroup, Status::Missing),
                (Check::AgentInSharedGroup, Status::Missing),
                (Check::AgentPrimaryGroup, Status::Missing),
                (Check::DeveloperHomeClosedToAgent, Status::Missing),
                (Check::AgentDirExists, Status::Missing),
                (Check::AgentDirIsDirectory, absent.clone()),
                (Check::AgentDirOwnerUid, absent.clone()),
                (Check::AgentDirOwnerGid, absent.clone()),
                (Check::AgentDirMode, absent.clone()),
                (Check::CoreDirExists, Status::Missing),
                (Check::CoreDirIsDirectory, absent.clone()),
                (Check::CoreDirOwnerUid, absent.clone()),
                (Check::CoreDirMode, absent),
                (
                    Check::SudoersRule,
                    Status::Unreachable {
                        why: "sudo: /Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx: command not found"
                            .to_string(),
                    },
                ),
            ],
        );
        snapshot.agent_group_gid = None;
        snapshot.shared_group_gid = None;
        snapshot.agent_dir_owner = None;
        snapshot.core_parent_missing = true;
        snapshot.sudoers = Listing::PasswordRequired;
        with_home(
            with_prefix(snapshot, empty_prefix()),
            None,
            AgentHomeState::Missing,
        )
    }

    fn empty_prefix() -> tool_prefix::Probe {
        tool_prefix::Probe {
            directory: DirectoryState::Missing,
            tree: TreeState::Absent,
            mise: ToolState::Absent,
            tools: settled_prefix()
                .tools
                .into_iter()
                .map(|(tool, pin, _)| (tool, pin, ToolState::Absent))
                .collect(),
            station: tool_prefix::StationBinary::ALL
                .iter()
                .map(|&binary| (binary, StationState::Absent))
                .collect(),
        }
    }

    /// Sets the home probe and the finding made from it, as `setup::record_probe` does.
    fn with_home(mut snapshot: Snapshot, path: Option<&str>, state: AgentHomeState) -> Snapshot {
        snapshot.agent_home = AgentHome {
            path: path.map(str::to_string),
            state,
        };
        let finding = setup::agent_home_finding(&snapshot.agent_home);
        snapshot
            .findings
            .retain(|kept| kept.check != Check::AgentHomeDirectory);
        snapshot.findings.push(finding);
        snapshot
    }

    fn home_mode(found: u32) -> AgentHomeState {
        AgentHomeState::Wrong(HomeMismatch {
            mode: Some(Differs {
                found,
                wanted: AGENT_HOME_MODE,
            }),
            ..HomeMismatch::default()
        })
    }

    /// The one file root writes, in three steps: the checked candidate installed root's at
    /// 0440 under a name outside `sudoers.d`, checked again by root's `visudo`, then renamed
    /// onto the drop-in.
    fn install_rule_commands() -> [Vec<String>; 3] {
        [
            strings(&[
                INSTALL,
                "-S",
                "-o",
                "root",
                "-g",
                "wheel",
                "-m",
                "0440",
                "/Users/frits/.tycho/provision/tycho-agent",
                "/etc/tycho-agent.sudoers.tmp",
            ]),
            strings(&[VISUDO, "-c", "-f", "/etc/tycho-agent.sudoers.tmp"]),
            strings(&[
                MV,
                "-f",
                "/etc/tycho-agent.sudoers.tmp",
                "/etc/sudoers.d/tycho-agent",
            ]),
        ]
    }

    /// No command root runs leaves a file in `sudoers.d` but the rename onto the drop-in, whose
    /// name sudo reads only once it is complete.
    #[test]
    fn nothing_but_the_final_rename_writes_in_the_sudoers_directory() {
        let [install, check, rename] = install_rule_commands();
        for words in [&install, &check] {
            assert!(
                !words.iter().any(|word| word.starts_with("/etc/sudoers.d/")),
                "{words:?}"
            );
        }
        assert_eq!(rename.last().map(String::as_str), Some(SUDOERS_DROP_IN));
        assert_eq!(
            Path::new(SUDOERS_STAGED).parent(),
            Path::new(SUDOERS_DROP_IN).parent().and_then(Path::parent),
            "install writes its temporary file beside the staging name, outside sudoers.d, on \
             the volume of the rename"
        );
    }

    fn createhomedir_words() -> Vec<String> {
        strings(&[CREATEHOMEDIR, "-c", "-u", "tycho-agent"])
    }

    fn chmod_home_words() -> Vec<String> {
        strings(&[CHMOD, "0700", "/Users/tycho-agent"])
    }

    fn captured(exit: Exit, stdout: &str, stderr: &str) -> Captured {
        Captured {
            exit,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        }
    }

    /// Hands out queued snapshots, the last one repeatedly, and records every action instead
    /// of taking it.
    #[derive(Debug, Default)]
    struct RecordingHost {
        snapshots: VecDeque<Snapshot>,
        root_results: VecDeque<Captured>,
        root_calls: Vec<Vec<String>>,
        visudo_results: VecDeque<Captured>,
        private_writes: Vec<(PathBuf, String)>,
        /// Every action in the order it was taken, by kind and first word.
        order: Vec<String>,
        developer_calls: Vec<Vec<String>>,
        directory_calls: Vec<DirectoryWork>,
        prefix_calls: Vec<PrefixStep>,
        snapshot_calls: usize,
        reports: usize,
    }

    impl RecordingHost {
        fn new(snapshots: Vec<Snapshot>) -> Self {
            Self {
                snapshots: snapshots.into(),
                ..Self::default()
            }
        }

        fn acted(&self) -> bool {
            !self.root_calls.is_empty()
                || !self.developer_calls.is_empty()
                || !self.directory_calls.is_empty()
                || !self.prefix_calls.is_empty()
        }
    }

    impl Host for RecordingHost {
        fn snapshot(&mut self) -> Result<Snapshot, String> {
            self.snapshot_calls = self.snapshot_calls.saturating_add(1);
            let next = if self.snapshots.len() > 1 {
                self.snapshots.pop_front()
            } else {
                self.snapshots.front().cloned()
            };
            next.ok_or_else(|| "no snapshot queued".to_string())
        }

        fn run_as_root(&mut self, words: &[String]) -> Captured {
            self.order
                .push(format!("root {}", words.first().map_or("", String::as_str)));
            self.root_calls.push(words.to_vec());
            self.root_results.pop_front().unwrap_or_else(|| {
                if words.first().map(String::as_str) == Some(VISUDO) {
                    let file = words.last().map_or("", String::as_str);
                    captured(Exit::Code(0), &format!("{file}: parsed OK\n"), "")
                } else {
                    captured(Exit::Code(0), "", "")
                }
            })
        }

        fn prepare_directory(
            &mut self,
            work: &DirectoryWork,
            _developer_uid: u32,
        ) -> Result<(), String> {
            self.directory_calls.push(work.clone());
            Ok(())
        }

        fn run_on_own_directory(
            &mut self,
            words: &[String],
            _directory: &Path,
            _developer_uid: u32,
        ) -> Result<Captured, String> {
            self.developer_calls.push(words.to_vec());
            Ok(captured(Exit::Code(0), "", ""))
        }

        fn run_prefix_step(
            &mut self,
            step: PrefixStep,
            _developer: &Identity,
        ) -> Result<(), String> {
            self.prefix_calls.push(step);
            Ok(())
        }

        fn write_private(
            &mut self,
            levels: &[PathBuf],
            file: &Path,
            content: &str,
            _developer_uid: u32,
        ) -> Result<(), String> {
            assert_eq!(levels.last().map(PathBuf::as_path), file.parent());
            self.order.push(format!("write {}", file.display()));
            self.private_writes
                .push((file.to_path_buf(), content.to_string()));
            Ok(())
        }

        fn run_as_developer(&mut self, words: &[String]) -> Captured {
            self.order.push(format!(
                "developer {}",
                words.first().map_or("", String::as_str)
            ));
            self.developer_calls.push(words.to_vec());
            self.visudo_results.pop_front().unwrap_or_else(|| {
                let file = words.last().map_or("", String::as_str);
                captured(Exit::Code(0), &format!("{file}: parsed OK\n"), "")
            })
        }

        fn report(&mut self, _developer: &Identity) -> i32 {
            self.reports = self.reports.saturating_add(1);
            0
        }
    }

    #[test]
    fn a_catalogue_with_everything_missing_plans_every_creation_in_dependency_order() {
        let snapshot = all_missing();
        let planned = plan(&snapshot);
        assert_eq!(
            planned.steps,
            vec![
                Remedy::CreateAgentGroup,
                Remedy::CreateAgentUser,
                Remedy::CreateAgentHome,
                Remedy::NarrowAgentHomeMode,
                Remedy::CreateSharedGroup,
                Remedy::AddDeveloperToSharedGroup,
                Remedy::AddAgentToSharedGroup,
                Remedy::CloseDeveloperHome,
                Remedy::PrepareAgentSocketDir,
                Remedy::PrepareCoreSocketDir,
                Remedy::CreateToolPrefix,
                Remedy::InstallMise,
                Remedy::InstallAgentTools,
                Remedy::InstallStationBinaries,
                Remedy::InstallSudoersRule,
            ]
        );
        assert!(planned.blocked.is_empty());
        assert!(unremedied(&snapshot, &planned.steps).is_empty());
        let user = action(Remedy::CreateAgentUser, &snapshot).map(|action| render(&action));
        assert_eq!(
            user,
            Some(vec![format!(
                "sudo {SYSADMINCTL} -addUser tycho-agent -fullName \"Tycho Agent\" -password - -home /Users/tycho-agent -shell /bin/zsh -GID <gid of tycho-agent>"
            )])
        );
        let core = action(Remedy::PrepareCoreSocketDir, &snapshot).map(|action| render(&action));
        assert_eq!(
            core,
            Some(vec![
                "mkdir -m 0700 /Users/frits/.tycho".to_string(),
                "mkdir -m 0700 /Users/frits/.tycho/zmx".to_string(),
                "chmod 0700 /Users/frits/.tycho/zmx".to_string(),
                "(as the developer, in this process)".to_string(),
            ])
        );
    }

    #[test]
    fn a_catalogue_where_everything_passes_plans_nothing_and_runs_nothing() {
        let snapshot = all_present();
        let planned = plan(&snapshot);
        assert!(planned.steps.is_empty());
        assert!(planned.blocked.is_empty());
        assert!(unremedied(&snapshot, &planned.steps).is_empty());
        let mut host = RecordingHost::new(vec![snapshot]);
        assert_eq!(provision(Mode::Apply, true, &mut host), 0);
        assert!(!host.acted());
        assert_eq!(host.reports, 1);
        let mut printing = RecordingHost::new(vec![all_present()]);
        assert_eq!(provision(Mode::Print, false, &mut printing), 0);
    }

    #[test]
    fn print_probes_once_and_runs_nothing() {
        let mut host = RecordingHost::new(vec![all_missing()]);
        assert_eq!(provision(Mode::Print, false, &mut host), 1);
        assert_eq!(host.snapshot_calls, 1);
        assert!(!host.acted());
        assert_eq!(host.reports, 0);
    }

    #[test]
    fn without_a_terminal_the_run_is_refused_before_any_probe() {
        let mut host = RecordingHost::new(vec![all_missing()]);
        assert_eq!(provision(Mode::Apply, false, &mut host), 2);
        assert_eq!(host.snapshot_calls, 0);
        assert!(!host.acted());
    }

    #[test]
    fn the_agent_user_and_root_are_refused_before_any_step() {
        for developer in [identity(AGENT_USER_NAME, 502), identity("root", 0)] {
            let mut snapshot = all_missing();
            snapshot.developer = developer;
            for mode in [Mode::Apply, Mode::Print] {
                let mut host = RecordingHost::new(vec![snapshot.clone()]);
                assert_eq!(provision(mode, true, &mut host), 2);
                assert!(!host.acted());
            }
        }
    }

    #[test]
    fn a_probe_that_could_not_run_blocks_the_whole_run() {
        let snapshot = with(
            all_missing(),
            &[(
                Check::SharedGroupExists,
                Status::Unreachable {
                    why: "dscl is not on PATH".to_string(),
                },
            )],
        );
        let planned = plan(&snapshot);
        assert_eq!(
            planned.blocked,
            vec![(Remedy::CreateSharedGroup, "dscl is not on PATH".to_string())]
        );
        let mut host = RecordingHost::new(vec![snapshot]);
        assert_eq!(provision(Mode::Apply, true, &mut host), 1);
        assert!(!host.acted());
    }

    #[test]
    fn unrecognised_output_from_a_remedy_stops_the_run() {
        let snapshot = with(
            all_present(),
            &[
                (Check::AgentGroupExists, Status::Missing),
                (Check::CoreDirExists, Status::Missing),
            ],
        );
        let mut host = RecordingHost::new(vec![snapshot]);
        host.root_results
            .push_back(captured(Exit::Code(0), "Group created, probably\n", ""));
        assert_eq!(provision(Mode::Apply, true, &mut host), 1);
        assert_eq!(host.root_calls.len(), 1);
        assert!(host.directory_calls.is_empty());
        assert_eq!(host.reports, 0);
    }

    #[test]
    fn a_remedy_whose_probe_still_fails_stops_and_names_what_it_saw() {
        let missing_group = with(all_present(), &[(Check::AgentGroupExists, Status::Missing)]);
        let mut host = RecordingHost::new(vec![missing_group.clone(), missing_group.clone()]);
        let stopped = apply(&mut host, &[Remedy::CreateAgentGroup], missing_group);
        assert_eq!(
            stopped.map(|_| ()),
            Err("create the agent group ran, but its probes still fail: agent group exists: missing".to_string())
        );
        assert_eq!(host.root_calls.len(), 1);
    }

    #[test]
    fn each_step_runs_in_order_is_verified_and_the_report_follows() {
        let initial = with(
            all_present(),
            &[
                (Check::AgentGroupExists, Status::Missing),
                (Check::CoreDirExists, Status::Missing),
            ],
        );
        let after_group = with(all_present(), &[(Check::CoreDirExists, Status::Missing)]);
        let mut host = RecordingHost::new(vec![initial, after_group, all_present()]);
        assert_eq!(provision(Mode::Apply, true, &mut host), 0);
        assert_eq!(
            host.root_calls,
            vec![strings(&[
                DSEDITGROUP,
                "-o",
                "create",
                "-r",
                "Tycho Agent",
                "tycho-agent"
            ])]
        );
        assert_eq!(host.directory_calls.len(), 1);
        assert_eq!(host.reports, 1);
    }

    #[test]
    fn a_step_an_earlier_step_settled_is_skipped() {
        let mut host = RecordingHost::new(vec![all_present()]);
        let settled = apply(
            &mut host,
            &[Remedy::AddDeveloperToSharedGroup],
            all_present(),
        );
        assert!(settled.is_ok());
        assert!(!host.acted());
    }

    #[test]
    fn the_user_is_bound_to_the_agent_gid_and_sysadminctl_asks_for_the_password() {
        let snapshot = all_present();
        let Some(Action::Root(words)) = action(Remedy::CreateAgentUser, &snapshot) else {
            panic!("the user step is a root command");
        };
        let password = words.iter().position(|word| word == "-password");
        assert_eq!(
            password.and_then(|index| words.get(index.saturating_add(1))),
            Some(&"-".to_string())
        );
        assert_eq!(words.last(), Some(&AGENT_GID.to_string()));
        let mut host = RecordingHost::new(vec![snapshot]);
        let unknown_gid = Action::Root(create_user_command(None));
        assert!(execute(&mut host, &unknown_gid, &all_present()).is_err());
        assert!(host.root_calls.is_empty());
    }

    #[test]
    fn a_socket_directory_another_user_owns_is_removed_by_root_and_made_again_by_the_developer() {
        let mut stranger = with(
            all_present(),
            &[(Check::AgentDirOwnerUid, wrong("503", "501 or 0"))],
        );
        stranger.agent_dir_owner = Some(503);
        assert_eq!(
            plan(&stranger).steps,
            vec![
                Remedy::RemoveForeignAgentSocketDir,
                Remedy::PrepareAgentSocketDir
            ]
        );
        assert_eq!(
            action(Remedy::RemoveForeignAgentSocketDir, &stranger),
            Some(Action::Root(strings(&[RMDIR, AGENT_SOCKET_DIR])))
        );
        let mut root_owned = with(
            all_present(),
            &[(Check::AgentDirMode, wrong("0755", "3770"))],
        );
        root_owned.agent_dir_owner = Some(0);
        assert_eq!(
            plan(&root_owned).steps,
            vec![
                Remedy::RemoveForeignAgentSocketDir,
                Remedy::PrepareAgentSocketDir
            ]
        );
        let mut settled_root = all_present();
        settled_root.agent_dir_owner = Some(0);
        assert!(plan(&settled_root).steps.is_empty());

        let mut removed = with(
            all_present(),
            &[
                (Check::AgentDirExists, Status::Missing),
                (Check::AgentDirOwnerUid, Status::Missing),
            ],
        );
        removed.agent_dir_owner = None;
        let mut host = RecordingHost::new(vec![stranger, removed, all_present()]);
        assert_eq!(provision(Mode::Apply, true, &mut host), 0);
        assert_eq!(host.root_calls, vec![strings(&[RMDIR, AGENT_SOCKET_DIR])]);
        assert_eq!(host.directory_calls.len(), 1);
    }

    #[test]
    fn a_failed_removal_stops_with_the_hint_before_the_developer_step() {
        let mut stranger = with(
            all_present(),
            &[(Check::AgentDirOwnerUid, wrong("503", "501 or 0"))],
        );
        stranger.agent_dir_owner = Some(503);
        let mut host = RecordingHost::new(vec![stranger.clone()]);
        host.root_results.push_back(captured(
            Exit::Code(1),
            "",
            "rmdir: /Users/Shared/tycho-agent-zmx: Directory not empty\n",
        ));
        let stopped = apply(&mut host, &plan(&stranger).steps, stranger.clone());
        assert!(stopped.is_err_and(|why| why.contains(FOREIGN_SOCKET_DIR_HINT)));
        assert!(host.directory_calls.is_empty());
        for refusal in [
            captured(Exit::Code(1), "", "sudo: a password is required\n"),
            captured(Exit::TimedOut, "", ""),
        ] {
            let mut refused = RecordingHost::new(vec![stranger.clone()]);
            refused.root_results.push_back(refusal);
            let stopped = apply(&mut refused, &plan(&stranger).steps, stranger.clone());
            assert!(stopped.is_err_and(|why| !why.contains(FOREIGN_SOCKET_DIR_HINT)));
        }
    }

    #[test]
    fn root_runs_only_the_allowlisted_commands_and_changes_one_mode_by_path() {
        let mut stranger = with(
            all_present(),
            &[
                (Check::AgentDirOwnerUid, wrong("503", "501 or 0")),
                (Check::AgentDirMode, wrong("0777", "3770")),
            ],
        );
        stranger.agent_dir_owner = Some(503);
        let wide_home = with_home(all_present(), Some(AGENT_HOME), home_mode(0o750));
        let mut examined = 0_u32;
        for snapshot in [all_missing(), stranger, all_present(), wide_home] {
            for remedy in REMEDIES {
                let commands = action(remedy, &snapshot)
                    .map(|action| action.root_commands())
                    .unwrap_or_default();
                for words in commands {
                    examined = examined.saturating_add(1);
                    let program = words.first().map(String::as_str);
                    assert!(
                        matches!(program, Some(DSEDITGROUP | SYSADMINCTL | RMDIR))
                            || words == createhomedir_words()
                            || words == chmod_home_words()
                            || install_rule_commands().contains(&words),
                        "{remedy:?} runs {words:?} as root"
                    );
                }
            }
        }
        assert!(examined >= 30, "only {examined} root commands examined");
        assert_eq!(
            action(Remedy::InstallSudoersRule, &all_present()).map(|action| action.root_commands()),
            Some(install_rule_commands().to_vec())
        );
        assert_eq!(
            action(Remedy::CreateAgentHome, &all_present()),
            Some(Action::Root(createhomedir_words()))
        );
        assert_eq!(
            action(Remedy::NarrowAgentHomeMode, &all_present()),
            Some(Action::Root(chmod_home_words()))
        );
    }

    #[test]
    fn a_missing_home_is_created_then_narrowed_once_and_reads_ok() {
        let missing = with_home(all_present(), Some(AGENT_HOME), AgentHomeState::Missing);
        assert_eq!(
            plan(&missing).steps,
            vec![Remedy::CreateAgentHome, Remedy::NarrowAgentHomeMode]
        );
        let created_wide = with_home(all_present(), Some(AGENT_HOME), home_mode(0o750));
        let mut host = RecordingHost::new(vec![missing.clone(), created_wide, all_present()]);
        host.root_results.push_back(captured(
            Exit::Code(0),
            "creating home directories for (tycho-agent)\ncreated (/Users/tycho-agent)\n",
            "",
        ));
        assert_eq!(provision(Mode::Apply, true, &mut host), 0);
        assert_eq!(
            host.root_calls,
            vec![createhomedir_words(), chmod_home_words()]
        );
        assert_eq!(host.reports, 1);

        let mut created_narrow = RecordingHost::new(vec![missing.clone(), all_present()]);
        assert_eq!(provision(Mode::Apply, true, &mut created_narrow), 0);
        assert_eq!(created_narrow.root_calls, vec![createhomedir_words()]);

        let mut still_wide = RecordingHost::new(vec![
            missing,
            with_home(all_present(), Some(AGENT_HOME), home_mode(0o750)),
        ]);
        assert_eq!(provision(Mode::Apply, true, &mut still_wide), 1);
        assert_eq!(
            still_wide.root_calls,
            vec![createhomedir_words(), chmod_home_words()]
        );
        assert_eq!(still_wide.reports, 0);
    }

    #[test]
    fn a_createhomedir_that_leaves_no_home_stops_before_the_chmod() {
        let missing = with_home(all_present(), Some(AGENT_HOME), AgentHomeState::Missing);
        let mut host = RecordingHost::new(vec![missing.clone(), missing]);
        assert_eq!(provision(Mode::Apply, true, &mut host), 1);
        assert_eq!(host.root_calls, vec![createhomedir_words()]);
        let mut failed = RecordingHost::new(vec![with_home(
            all_present(),
            Some(AGENT_HOME),
            AgentHomeState::Missing,
        )]);
        failed.root_results.push_back(captured(
            Exit::Code(0),
            "creating home directories for (tycho-agent)\ncannot create '/Users/tycho-agent' (13)\n",
            "",
        ));
        assert_eq!(provision(Mode::Apply, true, &mut failed), 1);
        assert_eq!(failed.root_calls, vec![createhomedir_words()]);
        assert_eq!(failed.snapshot_calls, 1);
    }

    #[test]
    fn a_home_the_task_must_not_change_is_left_to_the_operator_with_a_hint() {
        let mut owned_elsewhere = HomeMismatch {
            owner: Some(Differs {
                found: 501,
                wanted: 503,
            }),
            ..HomeMismatch::default()
        };
        owned_elsewhere.mode = Some(Differs {
            found: 0o755,
            wanted: AGENT_HOME_MODE,
        });
        let narrows = "mise run provision-agent narrows it";
        for (snapshot, expected) in [
            (
                with_home(
                    all_present(),
                    Some(AGENT_HOME),
                    AgentHomeState::Wrong(owned_elsewhere),
                ),
                "/Users/tycho-agent is not a directory the agent owns; inspect it and move it aside by hand, then run mise run provision-agent again".to_string(),
            ),
            (
                with_home(all_present(), Some(AGENT_HOME), home_mode(0o500)),
                "sudo -u tycho-agent /bin/chmod 0700 /Users/tycho-agent".to_string(),
            ),
            (
                with_home(all_present(), Some("/Users/elsewhere"), home_mode(0o755)),
                "sudo -u tycho-agent /bin/chmod 0700 /Users/elsewhere".to_string(),
            ),
            (
                with_home(all_present(), Some("/Users/elsewhere"), AgentHomeState::Missing),
                "the agent user record names /Users/elsewhere, not /Users/tycho-agent, and the task creates only /Users/tycho-agent; point NFSHomeDirectory at /Users/tycho-agent (sudo dscl . -create /Users/tycho-agent NFSHomeDirectory /Users/tycho-agent) and run mise run provision-agent again".to_string(),
            ),
        ] {
            let planned = plan(&snapshot);
            assert!(planned.steps.is_empty(), "{:?}", snapshot.agent_home);
            let left = unremedied(&snapshot, &planned.steps);
            assert_eq!(left.len(), 1);
            let hint = left
                .first()
                .filter(|finding| finding.check == Check::AgentHomeDirectory)
                .and_then(|finding| finding.hint.clone());
            assert_eq!(hint.as_deref(), Some(expected.as_str()));
            assert!(!expected.contains(narrows));
            let mut host = RecordingHost::new(vec![snapshot]);
            assert_eq!(provision(Mode::Print, false, &mut host), 1);
            assert!(!host.acted());
        }
    }

    #[test]
    fn the_narrowing_note_appears_only_where_the_task_narrows() {
        let wide = with_home(all_present(), Some(AGENT_HOME), home_mode(0o750));
        let hint = wide
            .findings
            .iter()
            .find(|finding| finding.check == Check::AgentHomeDirectory)
            .and_then(|finding| finding.hint.clone());
        assert_eq!(
            hint.as_deref(),
            Some(
                "sudo -u tycho-agent /bin/chmod 0700 /Users/tycho-agent (mise run provision-agent narrows it)"
            )
        );
        assert_eq!(plan(&wide).steps, vec![Remedy::NarrowAgentHomeMode]);
    }

    #[test]
    fn a_home_probe_that_could_not_run_or_read_an_unrecognised_record_blocks_the_run() {
        for state in [
            AgentHomeState::Unreachable("dscl is not on PATH".to_string()),
            AgentHomeState::Unrecognised("UniqueID \"x\" in the agent user record".to_string()),
        ] {
            let snapshot = with_home(all_present(), None, state);
            let planned = plan(&snapshot);
            let blocked: Vec<Remedy> = planned.blocked.iter().map(|(remedy, _)| *remedy).collect();
            assert_eq!(
                blocked,
                vec![Remedy::CreateAgentHome, Remedy::NarrowAgentHomeMode]
            );
            let mut host = RecordingHost::new(vec![snapshot]);
            assert_eq!(provision(Mode::Apply, true, &mut host), 1);
            assert!(!host.acted());
        }
    }

    #[test]
    fn decodes_createhomedir_output_and_rejects_the_unrecognised() {
        let home =
            |exit, stdout, stderr| decode_command(CREATEHOMEDIR, &captured(exit, stdout, stderr));
        assert_eq!(
            home(
                Exit::Code(0),
                "creating home directories for (tycho-agent)\ncreated (/Users/tycho-agent)\n",
                ""
            ),
            CommandOutcome::Succeeded
        );
        assert_eq!(
            home(
                Exit::Code(0),
                "",
                "creating home directories for (tycho-agent)\n"
            ),
            CommandOutcome::Succeeded
        );
        assert_eq!(
            home(
                Exit::Code(0),
                "creating home directories for (tycho-agent)\ncannot create '/Users/tycho-agent' (13)\n",
                ""
            ),
            CommandOutcome::Failed("cannot create '/Users/tycho-agent' (13)".to_string())
        );
        for unrecognised in [
            "creating home directories for (someone-else)\n",
            "created (relative)\n",
            "home made\n",
        ] {
            assert!(
                matches!(
                    home(Exit::Code(0), unrecognised, ""),
                    CommandOutcome::Unrecognised(_)
                ),
                "{unrecognised:?}"
            );
        }
        assert!(matches!(
            home(Exit::Code(1), "", "sudo: a password is required\n"),
            CommandOutcome::SudoRefused(_)
        ));
        assert!(matches!(
            home(
                Exit::Code(1),
                "",
                "createhomedir must be executed as root.\n"
            ),
            CommandOutcome::Failed(_)
        ));
    }

    #[test]
    fn a_home_the_agent_can_search_gets_the_deny_entry_as_the_developer() {
        let open_home = with(
            all_present(),
            &[(
                Check::DeveloperHomeClosedToAgent,
                wrong(
                    "mode 0750, and tycho-agent is in the home's group",
                    "user:tycho-agent denied search",
                ),
            )],
        );
        assert_eq!(plan(&open_home).steps, vec![Remedy::CloseDeveloperHome]);
        let expected = vec![
            CHMOD.to_string(),
            "+a".to_string(),
            HOME_DENY_ENTRY.to_string(),
            "/Users/frits".to_string(),
        ];
        let mut host = RecordingHost::new(vec![open_home.clone(), all_present()]);
        assert_eq!(provision(Mode::Apply, true, &mut host), 0);
        assert_eq!(host.developer_calls, vec![expected]);
        assert!(host.root_calls.is_empty());
        let mut still_open = RecordingHost::new(vec![open_home.clone(), open_home]);
        assert_eq!(provision(Mode::Apply, true, &mut still_open), 1);
        assert_eq!(still_open.reports, 0);
    }

    #[test]
    fn a_state_no_remedy_creates_is_left_to_the_operator() {
        let snapshot = with(
            all_present(),
            &[
                (Check::AgentDirIsDirectory, wrong("file", "directory")),
                (
                    Check::AgentPrimaryGroup,
                    wrong("gid 20 (staff)", "the gid of group tycho-agent"),
                ),
            ],
        );
        let planned = plan(&snapshot);
        assert!(planned.steps.is_empty());
        let left: Vec<Check> = unremedied(&snapshot, &planned.steps)
            .iter()
            .map(|finding| finding.check)
            .collect();
        assert_eq!(
            left,
            vec![Check::AgentDirIsDirectory, Check::AgentPrimaryGroup]
        );
        let mut host = RecordingHost::new(vec![snapshot]);
        assert_eq!(provision(Mode::Print, false, &mut host), 1);
    }

    #[test]
    fn decodes_each_root_outcome_and_rejects_the_unrecognised() {
        let quiet =
            |exit, stdout, stderr| decode_command(DSEDITGROUP, &captured(exit, stdout, stderr));
        assert_eq!(quiet(Exit::Code(0), "", ""), CommandOutcome::Succeeded);
        assert_eq!(
            quiet(Exit::Code(0), "", "Sorry, try again.\n"),
            CommandOutcome::Succeeded
        );
        assert_eq!(
            quiet(Exit::Code(0), "surprise\n", ""),
            CommandOutcome::Unrecognised("surprise".to_string())
        );
        for refusal in [
            "Sorry, try again.\nSorry, try again.\nsudo: 3 incorrect password attempts\n",
            "sudo: a password is required\n",
            "frits is not in the sudoers file.\n",
        ] {
            assert!(matches!(
                quiet(Exit::Code(1), "", refusal),
                CommandOutcome::SudoRefused(_)
            ));
        }
        assert_eq!(
            quiet(Exit::Code(64), "", "Group not found.\n"),
            CommandOutcome::Failed("exit 64: Group not found.".to_string())
        );
        assert_eq!(
            quiet(Exit::Code(1), "", "Record was not found.\n"),
            CommandOutcome::Failed("exit 1: Record was not found.".to_string())
        );
        for exit in [
            Exit::Signal,
            Exit::TimedOut,
            Exit::OutputTooLarge,
            Exit::OutputUnreadable,
            Exit::OutputStillOpen,
            Exit::NotStarted("no such file".to_string()),
        ] {
            assert!(matches!(
                quiet(exit, "", ""),
                CommandOutcome::NotFinished(_)
            ));
        }
    }

    #[test]
    fn decodes_sysadminctl_log_lines() {
        let user = |stderr| decode_command(SYSADMINCTL, &captured(Exit::Code(0), "", stderr));
        assert_eq!(
            user(
                "2026-10-09 12:00:00.000 sysadminctl[812:9031] Creating user record\n2026-10-09 12:00:00.100 sysadminctl[812:9031] Assigning UID: 502 GID: 502\n"
            ),
            CommandOutcome::Succeeded
        );
        assert!(matches!(
            user("2026-10-09 12:00:00.000 sysadminctl[812:9031] Error:-14120 creating record\n"),
            CommandOutcome::Failed(_)
        ));
        assert!(matches!(
            user("Creating user record\n"),
            CommandOutcome::Unrecognised(_)
        ));
        assert!(matches!(
            decode_command(SYSADMINCTL, &captured(Exit::Code(0), "unexpected\n", "")),
            CommandOutcome::Unrecognised(_)
        ));
    }

    fn scratch(name: &str) -> PathBuf {
        let base =
            std::env::temp_dir().join(format!("xtask-provision-{}-{name}", std::process::id()));
        fs::create_dir(&base).expect("create the scratch directory");
        base
    }

    #[test]
    fn a_directory_is_created_level_by_level_with_its_group_and_exact_mode() {
        let base = scratch("levels");
        let uid = fs::metadata(&base).expect("stat").uid();
        let gid = fs::metadata(&base).expect("stat").gid();
        let parent = base.join("parent");
        let target = parent.join("target");
        let work = DirectoryWork {
            levels: vec![parent.clone(), target.clone()],
            group: Some(GroupTarget {
                gid: Some(gid),
                name: "the scratch group",
            }),
            mode: 0o2770,
        };
        assert_eq!(prepare_directory(&work, uid), Ok(()));
        let made = fs::symlink_metadata(&target).expect("stat the target");
        assert_eq!(made.mode() & 0o7777, 0o2770);
        assert_eq!(made.gid(), gid);
        assert_eq!(
            fs::symlink_metadata(&parent).expect("stat").mode() & 0o777,
            0o700
        );
        assert_eq!(prepare_directory(&work, uid), Ok(()));
        assert!(prepare_directory(&work, uid.wrapping_add(1)).is_err());
        fs::remove_dir(&target).expect("remove target");
        fs::remove_dir(&parent).expect("remove parent");
        fs::remove_dir(&base).expect("remove base");
    }

    #[test]
    fn a_symlink_at_a_level_is_refused_and_its_target_keeps_its_mode() {
        let base = scratch("symlink");
        let uid = fs::metadata(&base).expect("stat").uid();
        let real = base.join("real");
        DirBuilder::new()
            .mode(0o700)
            .create(&real)
            .expect("create real");
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("plant the link");
        let work = DirectoryWork {
            levels: vec![link.clone()],
            group: None,
            mode: 0o2770,
        };
        let refused = prepare_directory(&work, uid);
        assert!(refused.is_err_and(|why| why.contains("is not a directory")));
        assert_eq!(
            fs::symlink_metadata(&real).expect("stat").mode() & 0o7777,
            0o700
        );
        let unknown_group = DirectoryWork {
            levels: vec![real.clone()],
            group: Some(GroupTarget {
                gid: None,
                name: SHARED_GROUP_NAME,
            }),
            mode: 0o2770,
        };
        assert!(prepare_directory(&unknown_group, uid).is_err());
        fs::remove_file(&link).expect("remove link");
        fs::remove_dir(&real).expect("remove real");
        fs::remove_dir(&base).expect("remove base");
    }

    #[test]
    fn an_empty_prefix_is_made_by_the_developer_in_order_with_no_root_step() {
        let initial = with_prefix(all_present(), empty_prefix());
        let planned = plan(&initial);
        assert_eq!(
            planned.steps,
            vec![
                Remedy::CreateToolPrefix,
                Remedy::InstallMise,
                Remedy::InstallAgentTools,
                Remedy::InstallStationBinaries,
            ]
        );
        let mut made = empty_prefix();
        made.directory = DirectoryState::Settled;
        made.tree = TreeState::Closed { examined: 3 };
        let after_directories = with_prefix(all_present(), made.clone());
        made.mise = ToolState::Pinned;
        let after_mise = with_prefix(all_present(), made.clone());
        made.tools = settled_prefix().tools;
        let after_tools = with_prefix(all_present(), made);
        let mut host = RecordingHost::new(vec![
            initial,
            after_directories,
            after_mise,
            after_tools,
            all_present(),
        ]);
        assert_eq!(provision(Mode::Apply, true, &mut host), 0);
        assert_eq!(
            host.prefix_calls,
            vec![
                PrefixStep::CreateDirectories,
                PrefixStep::InstallMise,
                PrefixStep::InstallAgentTools,
                PrefixStep::InstallStation,
            ]
        );
        assert!(host.root_calls.is_empty());
        assert_eq!(host.reports, 1);
    }

    #[test]
    fn a_prefix_another_user_owns_is_left_to_the_operator_and_nothing_goes_into_it() {
        let mut foreign = empty_prefix();
        foreign.directory =
            DirectoryState::Foreign("/Users/Shared/tycho is owned by uid 503".to_string());
        let snapshot = with_prefix(all_present(), foreign);
        let planned = plan(&snapshot);
        assert!(planned.steps.is_empty(), "{:?}", planned.steps);
        let left: Vec<Check> = unremedied(&snapshot, &planned.steps)
            .iter()
            .map(|finding| finding.check)
            .collect();
        assert!(left.contains(&Check::PrefixDirectory));
        assert!(left.contains(&Check::PrefixMise));
        let mut host = RecordingHost::new(vec![snapshot]);
        assert_eq!(provision(Mode::Print, false, &mut host), 1);
        assert!(!host.acted());
    }

    #[test]
    fn a_stale_station_build_is_rebuilt_and_a_probe_that_could_not_run_blocks() {
        let mut stale = settled_prefix();
        stale.station = vec![(
            tool_prefix::StationBinary::Tycho,
            StationState::Stale {
                installed: "a".repeat(40),
                checkout: "b".repeat(40),
            },
        )];
        assert_eq!(
            plan(&with_prefix(all_present(), stale)).steps,
            vec![Remedy::InstallStationBinaries]
        );
        let mut unknown = settled_prefix();
        unknown.mise = ToolState::Unreachable("mise did not finish".to_string());
        let planned = plan(&with_prefix(all_present(), unknown));
        assert_eq!(
            planned.blocked,
            vec![(Remedy::InstallMise, "mise did not finish".to_string())]
        );
    }

    #[test]
    fn a_prefix_step_whose_probe_still_fails_stops_the_run() {
        let initial = with_prefix(all_present(), empty_prefix());
        let mut host = RecordingHost::new(vec![initial.clone(), initial]);
        assert_eq!(provision(Mode::Apply, true, &mut host), 1);
        assert_eq!(host.prefix_calls, vec![PrefixStep::CreateDirectories]);
        assert_eq!(host.reports, 0);
    }

    #[test]
    fn the_operator_commands_run_the_pinned_installs_by_path_with_the_whole_environment() {
        let commands = operator_commands(&Prefix::production()).expect("the pins decode");
        let environment = "PATH=/Users/Shared/tycho/bin:/Users/Shared/tycho/mise/installs/claude/2.1.295:/Users/Shared/tycho/mise/installs/codex/0.160.1/bin:/Users/Shared/tycho/mise/installs/zmx/0.8.1:/usr/bin:/bin MISE_DATA_DIR=/Users/Shared/tycho/mise MISE_GLOBAL_CONFIG_FILE=/Users/Shared/tycho/mise.toml MISE_CACHE_DIR=/Users/Shared/tycho/cache MISE_OVERRIDE_CONFIG_FILENAMES=/Users/Shared/tycho/no-project-config MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES=none MISE_OFFLINE=1 MISE_AUTO_INSTALL=false MISE_STATE_DIR=/Users/tycho-agent/.local/state/mise";
        let as_agent = "sudo -u tycho-agent -H /usr/bin/env -i HOME=/Users/tycho-agent";
        assert_eq!(
            commands,
            [
                format!(
                    "{as_agent} PATH=/usr/bin:/bin /usr/bin/git config --global credential.helper \"\""
                ),
                format!(
                    "{as_agent} USER=tycho-agent LOGNAME=tycho-agent {environment} /Users/Shared/tycho/bin/xtask setup"
                ),
            ]
        );
        assert!(commands.iter().all(|command| !command.contains("shims")
            && command.starts_with("sudo -u tycho-agent -H /usr/bin/env -i ")));
        assert!(
            commands.iter().all(|command| !command.contains(" login")),
            "the agent logs in to no vendor"
        );
    }

    #[test]
    fn the_developer_stores_each_vendor_credential_from_stdin_by_the_prefix_tycho() {
        let commands =
            developer_credential_commands(&Prefix::production()).expect("the pins decode");
        assert_eq!(
            commands,
            [
                "/Users/Shared/tycho/mise/installs/claude/2.1.295/claude setup-token".to_string(),
                "/Users/Shared/tycho/bin/tycho credentials set claude".to_string(),
                "/Users/Shared/tycho/mise/installs/codex/0.160.1/bin/codex login -c 'cli_auth_credentials_store=\"file\"'".to_string(),
                "/Users/Shared/tycho/bin/tycho credentials set codex < ~/.codex/auth.json".to_string(),
                "/Users/Shared/tycho/bin/tycho credentials status".to_string(),
            ]
        );
        assert!(commands.iter().all(|command| !command.starts_with("sudo")));
    }

    fn exact_reading() -> Reading {
        Reading {
            entry: Entry::Exact,
            defaults: DefaultsLine::Exact,
            others: Vec::new(),
        }
    }

    fn rule_missing() -> Snapshot {
        let mut snapshot = with(all_present(), &[(Check::SudoersRule, Status::Missing)]);
        snapshot.sudoers = Listing::PasswordRequired;
        snapshot
    }

    fn with_listing(listing: Listing, status: Status) -> Snapshot {
        let mut snapshot = with(all_present(), &[(Check::SudoersRule, status)]);
        snapshot.sudoers = listing;
        snapshot
    }

    #[test]
    fn a_rule_a_pin_bump_left_is_installed_again_for_the_new_zmx() {
        let old = "/Users/Shared/tycho/mise/installs/zmx/0.7.1/zmx".to_string();
        let stale = with_listing(
            Listing::Listed(Reading {
                entry: Entry::Stale(old.clone()),
                defaults: DefaultsLine::Stale(old),
                others: Vec::new(),
            }),
            wrong("the rule for 0.7.1", "the rule for 0.8.1"),
        );
        assert_eq!(plan(&stale).steps, vec![Remedy::InstallSudoersRule]);
        let mut host = RecordingHost::new(vec![stale, all_present()]);
        assert_eq!(provision(Mode::Apply, true, &mut host), 0);
        assert_eq!(host.root_calls, install_rule_commands());
        let (_, content) = &host.private_writes[0];
        assert!(content.contains("/zmx/0.8.1/zmx") && !content.contains("0.7.1"));
    }

    #[test]
    fn an_unrelated_no_password_entry_does_not_keep_the_rule_from_being_installed() {
        let vpn = with_listing(
            Listing::Listed(Reading {
                entry: Entry::Absent,
                defaults: DefaultsLine::Absent,
                others: vec!["(root) NOPASSWD: /usr/local/bin/vpn-helper".to_string()],
            }),
            wrong("also without a password", "only the rule"),
        );
        assert_eq!(plan(&vpn).steps, vec![Remedy::InstallSudoersRule]);
        let differs = with_listing(
            Listing::Listed(Reading {
                entry: Entry::Exact,
                defaults: DefaultsLine::Differs("Defaults!x umask=0022".to_string()),
                others: Vec::new(),
            }),
            wrong("its Defaults line", "the rule's"),
        );
        assert_eq!(plan(&differs).steps, vec![Remedy::InstallSudoersRule]);
    }

    #[test]
    fn the_rule_is_written_privately_checked_by_visudo_then_installed_by_root() {
        let missing = rule_missing();
        assert_eq!(plan(&missing).steps, vec![Remedy::InstallSudoersRule]);
        let mut host = RecordingHost::new(vec![missing, all_present()]);
        assert_eq!(provision(Mode::Apply, true, &mut host), 0);
        let candidate = "/Users/frits/.tycho/provision/tycho-agent";
        assert_eq!(
            host.order,
            [
                format!("write {candidate}"),
                format!("developer {VISUDO}"),
                format!("root {INSTALL}"),
                format!("root {VISUDO}"),
                format!("root {MV}"),
            ]
        );
        assert_eq!(
            host.developer_calls,
            [strings(&[VISUDO, "-c", "-f", candidate])]
        );
        assert_eq!(host.root_calls, install_rule_commands());
        let (_, content) = &host.private_writes[0];
        assert_eq!(
            content,
            &agent_switch::rule(
                "frits",
                "tycho-agent",
                "/Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx"
            )
            .unwrap()
        );
    }

    #[test]
    fn a_rule_visudo_refuses_never_reaches_root() {
        let mut host = RecordingHost::new(vec![rule_missing()]);
        host.visudo_results.push_back(captured(
            Exit::Code(1),
            "",
            "/Users/frits/.tycho/provision/tycho-agent:3:7: syntax error\n",
        ));
        assert_eq!(provision(Mode::Apply, true, &mut host), 1);
        assert!(host.root_calls.is_empty(), "{:?}", host.root_calls);
        for (exit, stdout) in [
            (Exit::Code(0), "something else\n"),
            (Exit::Code(0), ""),
            (Exit::Code(2), ""),
            (Exit::TimedOut, ""),
        ] {
            let mut host = RecordingHost::new(vec![rule_missing()]);
            host.visudo_results.push_back(captured(exit, stdout, ""));
            assert_eq!(provision(Mode::Apply, true, &mut host), 1);
            assert!(host.root_calls.is_empty());
        }
    }

    #[test]
    fn a_staged_rule_root_s_visudo_refuses_is_never_renamed_into_place() {
        let mut host = RecordingHost::new(vec![rule_missing()]);
        host.root_results.push_back(captured(Exit::Code(0), "", ""));
        host.root_results.push_back(captured(
            Exit::Code(1),
            "",
            "/etc/tycho-agent.sudoers.tmp:2:7: syntax error\n",
        ));
        assert_eq!(provision(Mode::Apply, true, &mut host), 1);
        let [install, check, _] = install_rule_commands();
        assert_eq!(host.root_calls, [install, check]);
        let mut failed_install = RecordingHost::new(vec![rule_missing()]);
        failed_install.root_results.push_back(captured(
            Exit::Code(71),
            "",
            "install: permission denied\n",
        ));
        assert_eq!(provision(Mode::Apply, true, &mut failed_install), 1);
        assert_eq!(failed_install.root_calls.len(), 1);
    }

    #[test]
    fn an_installed_rule_whose_probe_still_fails_stops_the_run() {
        let mut host = RecordingHost::new(vec![rule_missing()]);
        assert_eq!(provision(Mode::Apply, true, &mut host), 1);
        assert_eq!(host.root_calls, install_rule_commands());
        assert_eq!(host.reports, 0);
    }

    #[test]
    fn a_wider_rule_is_left_to_the_operator_and_an_unreadable_one_blocks() {
        let wider = with_listing(
            Listing::Listed(Reading {
                others: vec!["(ALL) NOPASSWD: ALL".to_string()],
                ..exact_reading()
            }),
            wrong("a wider rule", "zmx alone"),
        );
        assert!(plan(&wider).steps.is_empty());
        assert_eq!(unremedied(&wider, &[]).len(), 1);
        let unreadable = with_listing(
            Listing::Unrecognised("garbage".to_string()),
            Status::Unreachable {
                why: "sudo answered something".to_string(),
            },
        );
        assert_eq!(plan(&unreadable).blocked.len(), 1);
    }

    #[test]
    fn the_rule_is_planned_while_sudo_asks_a_password_and_printed_in_full() {
        let snapshot = all_missing();
        assert_eq!(need(Remedy::InstallSudoersRule, &snapshot), Need::Run);
        let lines = action(Remedy::InstallSudoersRule, &snapshot)
            .map(|action| render(&action))
            .unwrap();
        assert_eq!(
            lines.first().map(String::as_str),
            Some(
                "write /Users/frits/.tycho/provision/tycho-agent, mode 0600, in a 0700 directory (as the developer):"
            )
        );
        assert!(lines
            .iter()
            .any(|line| line == "  frits ALL = (tycho-agent) NOPASSWD: /Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx"));
        assert_eq!(
            lines.last().map(String::as_str),
            Some("sudo /bin/mv -f /etc/tycho-agent.sudoers.tmp /etc/sudoers.d/tycho-agent")
        );
        let root_lines: Vec<&str> = lines
            .iter()
            .map(String::as_str)
            .filter(|line| line.starts_with("sudo "))
            .collect();
        assert_eq!(
            root_lines,
            [
                "sudo /usr/bin/install -S -o root -g wheel -m 0440 /Users/frits/.tycho/provision/tycho-agent /etc/tycho-agent.sudoers.tmp",
                "sudo /usr/sbin/visudo -c -f /etc/tycho-agent.sudoers.tmp",
                "sudo /bin/mv -f /etc/tycho-agent.sudoers.tmp /etc/sudoers.d/tycho-agent",
            ]
        );
    }

    #[test]
    fn a_private_candidate_is_written_new_at_0600_in_a_0700_directory() {
        let root = scratch("candidate");
        let uid = fs::metadata(&root).expect("stat").uid();
        let levels = vec![root.join("a"), root.join("a").join("b")];
        let file = root.join("a").join("b").join("rule");
        write_private(&levels, &file, "first\n", uid).unwrap();
        write_private(&levels, &file, "second\n", uid).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "second\n");
        assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, CANDIDATE_MODE);
        assert_eq!(
            fs::metadata(&levels[1]).unwrap().mode() & 0o777,
            PRIVATE_MODE
        );
        assert!(write_private(&levels, &root.join("elsewhere"), "x", uid).is_err());
        fs::remove_file(&file).unwrap();
        fs::remove_dir(&levels[1]).unwrap();
        fs::remove_dir(&levels[0]).unwrap();
        fs::remove_dir(&root).unwrap();
    }
}

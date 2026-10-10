//! Creates what the developer side of `xtask setup` checks: the agent's group and user, the
//! shared group and its members, the deny entry for the agent in the developer's home ACL, and
//! both socket directories. A step runs only while its probe fails, and the probe runs again
//! after it; a step whose probe still fails stops the run. Steps that need root run through
//! `sudo`, which prompts on the terminal itself; this process never reads, holds or passes a
//! password. Root never changes the owner or mode of a path: in `/Users/Shared`, which every
//! user can write, the entry's owner could swap it for a link between the probe and the change.

use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, IsTerminal};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::process::{self, Captured, Exit};
use crate::setup::{
    self, Check, Finding, Identity, Side, Status, AGENT_GROUP_NAME, AGENT_SOCKET_DIR,
    AGENT_SOCKET_DIR_MODE, AGENT_USER_NAME, CORE_SOCKET_DIR_MODE, HOME_DENY_ENTRY,
    SHARED_GROUP_NAME,
};

const PROVISION_STEPS_MAX: usize = 16;
/// Long enough for sudo's and sysadminctl's prompts to be answered at a terminal.
const REMEDY_TIMEOUT: Duration = Duration::from_secs(600);
const SUDO: &str = "/usr/bin/sudo";
const DSEDITGROUP: &str = "/usr/sbin/dseditgroup";
const SYSADMINCTL: &str = "/usr/sbin/sysadminctl";
const RMDIR: &str = "/bin/rmdir";
const CHMOD: &str = "/bin/chmod";
/// For a step run as the developer; the prompts of root steps get `REMEDY_TIMEOUT`.
const DEVELOPER_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const PROMPT_NOTICE: &str =
    "sudo may ask for your password now, and sysadminctl for the new user's, on this terminal";
const FOREIGN_SOCKET_DIR_HINT: &str = "it is not an empty directory; inspect /Users/Shared/tycho-agent-zmx, remove it by hand, and run the task again";
const AGENT_FULL_NAME: &str = "Tycho Agent";
const AGENT_HOME: &str = "/Users/tycho-agent";
const AGENT_SHELL: &str = "/bin/zsh";
const AGENT_GID_PLACEHOLDER: &str = "<gid of tycho-agent>";
/// Mode a directory is created with before its group and final mode are set on the descriptor.
const CREATE_MODE: u32 = 0o700;
/// What sudo writes to stderr after a mistyped password that a later attempt corrected.
const SUDO_RETRY_LINE: &str = "Sorry, try again.";

const OPERATOR_STEPS: [&str; 4] = [
    "as tycho-agent, from a terminal in that account (`su - tycho-agent` or a login session): `claude` (subscription login) and `codex login` (ChatGPT plan); each login is a flow in that user's session",
    "as tycho-agent: `git config --global credential.helper \"\"`, which clears every credential helper git reads, Apple's osxkeychain included",
    "optional, as the developer, if the entire mirror is the sync remote: `entire auth`",
    "then `mise run setup` as tycho-agent",
];

/// Every remedy, in the order each one's prerequisites come first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Remedy {
    CreateAgentGroup,
    CreateAgentUser,
    CreateSharedGroup,
    AddDeveloperToSharedGroup,
    AddAgentToSharedGroup,
    CloseDeveloperHome,
    RemoveForeignAgentSocketDir,
    PrepareAgentSocketDir,
    PrepareCoreSocketDir,
}

const REMEDIES: [Remedy; 9] = [
    Remedy::CreateAgentGroup,
    Remedy::CreateAgentUser,
    Remedy::CreateSharedGroup,
    Remedy::AddDeveloperToSharedGroup,
    Remedy::AddAgentToSharedGroup,
    Remedy::CloseDeveloperHome,
    Remedy::RemoveForeignAgentSocketDir,
    Remedy::PrepareAgentSocketDir,
    Remedy::PrepareCoreSocketDir,
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
            Self::CreateSharedGroup => "create the shared group",
            Self::AddDeveloperToSharedGroup => "add the developer to the shared group",
            Self::AddAgentToSharedGroup => "add the agent user to the shared group",
            Self::CloseDeveloperHome => "deny the agent user the developer's home",
            Self::RemoveForeignAgentSocketDir => {
                "remove the agent socket directory another user owns"
            }
            Self::PrepareAgentSocketDir => "prepare the agent socket directory",
            Self::PrepareCoreSocketDir => "prepare the core socket directory",
        }
    }

    /// The checks that pass once the remedy has run.
    const fn targets(self) -> &'static [Check] {
        match self {
            Self::CreateAgentGroup => &[Check::AgentGroupExists],
            Self::CreateAgentUser => &[Check::AgentUserExists, Check::AgentPrimaryGroup],
            Self::CreateSharedGroup => &[Check::SharedGroupExists],
            Self::AddDeveloperToSharedGroup => &[Check::DeveloperInSharedGroup],
            Self::AddAgentToSharedGroup => &[Check::AgentInSharedGroup],
            Self::CloseDeveloperHome => &[Check::DeveloperHomeClosedToAgent],
            Self::RemoveForeignAgentSocketDir => &[Check::AgentDirOwnerUid],
            Self::PrepareAgentSocketDir => &AGENT_DIR_CHECKS,
            Self::PrepareCoreSocketDir => &CORE_DIR_CHECKS,
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
    agent_dir_owner: Option<u32>,
    developer_home: Option<PathBuf>,
    core_dir: Option<PathBuf>,
    core_parent_missing: bool,
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

fn need(remedy: Remedy, snapshot: &Snapshot) -> Need {
    let absence = |check| need_for_absence(&status_of(snapshot, check));
    match remedy {
        Remedy::CreateAgentGroup => absence(Check::AgentGroupExists),
        Remedy::CreateAgentUser => absence(Check::AgentUserExists),
        Remedy::CreateSharedGroup => absence(Check::SharedGroupExists),
        Remedy::AddDeveloperToSharedGroup => absence(Check::DeveloperInSharedGroup),
        Remedy::AddAgentToSharedGroup => absence(Check::AgentInSharedGroup),
        Remedy::CloseDeveloperHome => {
            need_for_wrong(&status_of(snapshot, Check::DeveloperHomeClosedToAgent))
        }
        Remedy::RemoveForeignAgentSocketDir => remove_agent_dir_need(snapshot),
        Remedy::PrepareAgentSocketDir => prepare_agent_dir_need(snapshot),
        Remedy::PrepareCoreSocketDir => prepare_core_dir_need(snapshot),
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

fn decode_command(program: &str, captured: &Captured) -> CommandOutcome {
    let (stdout, stderr) = (captured.stdout.as_str(), captured.stderr.as_str());
    match &captured.exit {
        Exit::Code(0) if program == SYSADMINCTL => decode_sysadminctl_success(stdout, stderr),
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
    /// Prints the setup report and returns its exit code.
    fn report(&mut self, developer: &Identity) -> i32;
}

#[derive(Debug)]
pub struct SystemHost;

impl Host for SystemHost {
    fn snapshot(&mut self) -> Result<Snapshot, String> {
        let developer = setup::current_identity()?;
        let mut findings = setup::record_findings(&developer);
        findings.extend(setup::agent_record_findings());
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
            agent_dir_owner: fs::symlink_metadata(AGENT_SOCKET_DIR)
                .ok()
                .map(|metadata| metadata.uid()),
            developer_home: developer_home.map(PathBuf::from),
            core_dir,
            core_parent_missing,
            developer,
            findings,
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
fn open_own_directory(path: &Path, developer_uid: u32) -> Result<File, String> {
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
fn create_level(path: &Path, developer_uid: u32) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => open_own_directory(path, developer_uid).map(drop),
        Err(error) if error.kind() == io::ErrorKind::NotFound => DirBuilder::new()
            .mode(CREATE_MODE)
            .create(path)
            .map_err(|error| format!("mkdir {}: {error}", path.display())),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
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
            return Err(format!("the gid of {name} could not be read"))
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
    }
}

fn verify(remedy: Remedy, snapshot: &Snapshot) -> Result<(), String> {
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
                return Err(format!("{}: a probe could not run: {why}", remedy.label()))
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
    for step in OPERATOR_STEPS {
        println!("  - {step}");
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
        eprintln!("xtask provision-agent: stdin is not a terminal, and sudo and sysadminctl prompt on it; run it from a terminal, or pass --print for the plan");
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
    use std::collections::VecDeque;

    const DEVELOPER_UID: u32 = 501;
    const AGENT_GID: u32 = 502;
    const SHARED_GID: u32 = 503;
    const RECORD_CHECKS: [Check; 17] = [
        Check::AgentGroupExists,
        Check::AgentUserExists,
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

    fn all_present() -> Snapshot {
        Snapshot {
            developer: identity("frits", DEVELOPER_UID),
            findings: RECORD_CHECKS
                .iter()
                .map(|&check| Finding::new(check, Status::Present))
                .collect(),
            agent_group_gid: Some(AGENT_GID),
            shared_group_gid: Some(SHARED_GID),
            agent_dir_owner: Some(DEVELOPER_UID),
            developer_home: Some(PathBuf::from("/Users/frits")),
            core_dir: Some(PathBuf::from("/Users/frits/.tycho/zmx")),
            core_parent_missing: false,
        }
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
            ],
        );
        snapshot.agent_group_gid = None;
        snapshot.shared_group_gid = None;
        snapshot.agent_dir_owner = None;
        snapshot.core_parent_missing = true;
        snapshot
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
        developer_calls: Vec<Vec<String>>,
        directory_calls: Vec<DirectoryWork>,
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
            self.root_calls.push(words.to_vec());
            self.root_results
                .pop_front()
                .unwrap_or_else(|| captured(Exit::Code(0), "", ""))
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
                Remedy::CreateSharedGroup,
                Remedy::AddDeveloperToSharedGroup,
                Remedy::AddAgentToSharedGroup,
                Remedy::CloseDeveloperHome,
                Remedy::PrepareAgentSocketDir,
                Remedy::PrepareCoreSocketDir,
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
            &[(Check::AgentDirMode, wrong("0755", "2770"))],
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
    fn root_never_changes_the_owner_or_mode_of_a_path() {
        let mut stranger = with(
            all_present(),
            &[
                (Check::AgentDirOwnerUid, wrong("503", "501 or 0")),
                (Check::AgentDirMode, wrong("0777", "2770")),
            ],
        );
        stranger.agent_dir_owner = Some(503);
        for snapshot in [all_missing(), stranger, all_present()] {
            for remedy in REMEDIES {
                if let Some(Action::Root(words)) = action(remedy, &snapshot) {
                    let program = words.first().map(String::as_str);
                    assert!(
                        matches!(program, Some(DSEDITGROUP | SYSADMINCTL | RMDIR)),
                        "{remedy:?} runs {program:?} as root"
                    );
                }
            }
        }
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
            user("2026-10-09 12:00:00.000 sysadminctl[812:9031] Creating user record\n2026-10-09 12:00:00.100 sysadminctl[812:9031] Assigning UID: 502 GID: 502\n"),
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
}

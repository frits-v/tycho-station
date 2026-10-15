//! The identity switch: the sudoers rule and the decoders of the `sudo` answers that read it.
//!
//! The rule lets the developer, and so the core, start the prefix's zmx as the agent user with
//! no password. Provisioning writes the rule, setup and the boundary suite read it back, and the
//! spawner runs `zmx run` through it.
//!
//! sudo wraps zmx, not the launcher: the session daemon zmx forks then runs as the agent, and the
//! pid `zmx list` reports is the agent's shell after it executes the launcher.

use std::fmt;

pub const SUDO: &str = "/usr/bin/sudo";
/// A name without a dot: sudo skips files in `sudoers.d` whose names hold one.
pub const SUDOERS_DROP_IN: &str = "/etc/sudoers.d/tycho-agent";
/// The variables sudo passes to the agent's zmx.
///
/// `=` replaces the default list, which on macOS keeps `HOME`, `MAIL` and `SSH_AUTH_SOCK`.
/// `HOME` is kept so the switched run can name a
/// root-owned empty directory: zmx starts its session shell as a login shell, which would
/// otherwise read the agent's own startup files before the typed line runs.
pub const KEPT_VARIABLES: [&str; 4] = ["HOME", "ZMX_DIR", "ZMX_DIR_MODE", "ZMX_LOG_MODE"];
/// The `HOME` the switched run passes: root's, empty, and holding no startup file.
pub const SWITCHED_HOME: &str = "/var/empty";
/// sudo otherwise runs the command under the union of the caller's umask and its default 0022,
/// under which zmx makes the socket 0750 and the developer cannot connect.
pub const RULE_UMASK: &str = "0007";
/// A command outside the narrow rule, which a wider no-password rule would run.
pub const WIDER_PROBE_COMMAND: &str = "/usr/bin/true";
const PASSWORD_REQUIRED: &str = "sudo: a password is required";
const UNKNOWN_USER: &str = "sudo: unknown user ";
const NAME_MAX_BYTES: usize = 32;
const PATH_MAX_BYTES: usize = 512;
/// Text echoed from a probe's output is cut to this many characters.
const ECHO_MAX_CHARS: usize = 200;
/// A listing longer than this is refused, never read in part.
pub const LISTING_LINES_MAX: usize = 1024;
const MATCHING_HEADER: &str = "Matching Defaults entries for ";
const BOUND_HEADER: &str = "Runas and Command-specific defaults for ";
const PRIVILEGES_HEADER: &str = "User ";
const PRIVILEGES_MIDDLE: &str = " may run the following commands on ";
const NOT_ALLOWED_MIDDLE: &str = " is not allowed to run sudo on ";
const INDENT: &str = "    ";
const NO_AUTHENTICATE: &str = "!authenticate";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    Name(String),
    Path(String),
}

impl fmt::Display for RuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => write!(
                formatter,
                "{name:?} is not a user name a sudoers rule can carry unescaped"
            ),
            Self::Path(path) => write!(
                formatter,
                "{path:?} is not an absolute path a sudoers rule can carry unescaped"
            ),
        }
    }
}

fn check_name(name: &str) -> Result<(), RuleError> {
    let mut characters = name.chars();
    let first_ok = characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first == '_');
    let rest_ok = characters.all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '_' | '-')
    });
    if first_ok && rest_ok && name.len() <= NAME_MAX_BYTES {
        Ok(())
    } else {
        Err(RuleError::Name(name.to_string()))
    }
}

fn check_path(path: &str) -> Result<(), RuleError> {
    let characters_ok = path.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '/' | '.' | '_' | '-')
    });
    let components_ok = path
        .split('/')
        .skip(1)
        .all(|component| !component.is_empty() && component != "." && component != "..");
    if path.starts_with('/') && characters_ok && components_ok && path.len() <= PATH_MAX_BYTES {
        Ok(())
    } else {
        Err(RuleError::Path(path.to_string()))
    }
}

/// The drop-in: `developer` may run `zmx`, with any arguments, as `agent` only.
///
/// No password is asked, only the kept variables cross, and the command runs under umask 007.
/// The path is written out rather than through an alias, so `sudo -l` lists the path itself.
/// `ALL` appears only in the host field, which on one machine names that machine.
pub fn rule(developer: &str, agent: &str, zmx: &str) -> Result<String, RuleError> {
    check_name(developer)?;
    check_name(agent)?;
    check_path(zmx)?;
    let kept = KEPT_VARIABLES.join(" ");
    Ok(format!(
        "# Written by xtask provision-agent; xtask setup reads it back with sudo -l.\n\
         Defaults!{zmx} env_keep = \"{kept}\", umask = {RULE_UMASK}, umask_override\n\
         {developer} ALL = ({agent}) NOPASSWD: {zmx}\n"
    ))
}

/// `sudo` arguments that list every entry of the caller.
///
/// No prompt, and no cached ticket, which `-k` ignores without removing it. sudo lists without a password only
/// when some entry of the caller needs none.
#[must_use]
pub fn listing_arguments() -> Vec<String> {
    ["-n", "-k", "-l"].map(str::to_string).to_vec()
}

/// `sudo` arguments that run a command outside the narrow rule as the agent.
///
/// No prompt and no cached ticket. The developer may run anything as the agent with a password,
/// so only running a command outside the rule shows whether sudo itself still asks for one.
#[must_use]
pub fn wider_probe_arguments(agent: &str) -> Vec<String> {
    ["-n", "-k", "-u", agent, "--", WIDER_PROBE_COMMAND]
        .map(str::to_string)
        .to_vec()
}

/// What `sudo -n -k -u <agent> -- /usr/bin/true` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WiderProbe {
    /// The command outside the rule still needs a password.
    PasswordRequired,
    /// A rule runs commands outside zmx as the agent with no password.
    RanWithoutPassword,
    UnknownUser(String),
    Refused(String),
    Unrecognised(String),
}

/// The rule's no-password entry in the listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Absent,
    /// `(<agent>) NOPASSWD: <the pinned zmx>`.
    Exact,
    /// The same entry for another zmx install of the prefix, which a pin bump leaves behind.
    Stale(String),
}

/// The rule's `Defaults!<zmx>` line in the listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultsLine {
    Absent,
    /// Exactly the kept variables, umask 0007 and `umask_override`.
    Exact,
    /// A line bound to another zmx install of the prefix.
    Stale(String),
    /// A line bound to the pinned zmx with other settings, or more than one.
    Differs(String),
}

/// What a listing says of the rule and of every other way to run something without a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading {
    pub entry: Entry,
    pub defaults: DefaultsLine,
    /// Each other no-password entry, and each `!authenticate` default, as the listing names it.
    pub others: Vec<String>,
}

/// What `sudo -n -k -l` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listing {
    /// No entry of the caller needs no password, so sudo asked for one: the rule is absent.
    PasswordRequired,
    /// The caller may not run sudo on this host.
    NotAllowed,
    Listed(Reading),
    Refused(String),
    Unrecognised(String),
}

impl Reading {
    /// Exactly the rule and nothing else that needs no password.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.entry == Entry::Exact && self.defaults == DefaultsLine::Exact && self.others.is_empty()
    }
}

/// Where a listing's lines belong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Start,
    Matching,
    Bound,
    Privileges,
}

/// What `decode_listing` compares the listing against.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    pub agent: &'a str,
    pub zmx: &'a str,
    /// The directory every zmx install of the prefix lives under, ending in `/`.
    pub zmx_installs: &'a str,
}

impl Expected<'_> {
    fn is_other_install(&self, path: &str) -> bool {
        path != self.zmx
            && path
                .strip_prefix(self.zmx_installs)
                .and_then(|rest| rest.strip_suffix("/zmx"))
                .is_some_and(|version| !version.is_empty() && !version.contains('/'))
    }
}

/// Splits on `", "` outside double quotes; sudo quotes a value that holds a space.
fn split_list(text: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' if !escaped => {
                escaped = true;
                current.push(character);
                continue;
            }
            '"' if !escaped => quoted = !quoted,
            ',' if !quoted && !escaped && characters.peek() == Some(&' ') => {
                characters.next();
                items.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        escaped = false;
        current.push(character);
    }
    items.push(current);
    items
}

/// A defaults setting as sudo prints it, with its quotes removed.
fn setting(text: &str) -> String {
    text.chars().filter(|character| *character != '"').collect()
}

/// `Defaults<binding><members> <settings>`: the binding character, the members and the settings.
fn bound_line(line: &str) -> Option<(char, Vec<String>, Vec<String>)> {
    let rest = line.strip_prefix("Defaults")?;
    let mut characters = rest.chars();
    let binding = characters.next()?;
    let rest = characters.as_str();
    let mut members = Vec::new();
    let mut remainder = rest;
    loop {
        let (member, after) = remainder.split_once(' ')?;
        if let Some(listed) = member.strip_suffix(',') {
            members.push(listed.to_string());
            remainder = after;
        } else {
            members.push(member.to_string());
            remainder = after;
            break;
        }
    }
    let settings = split_list(remainder)
        .iter()
        .map(|item| setting(item))
        .collect();
    Some((binding, members, settings))
}

fn rule_settings() -> Vec<String> {
    let mut wanted = vec![
        format!("env_keep={}", KEPT_VARIABLES.join(" ")),
        format!("umask={RULE_UMASK}"),
        "umask_override".to_string(),
    ];
    wanted.sort();
    wanted
}

/// An entry line's command specifications: each command and whether it needs no password.
/// A tag holds until the next one changes it, as sudo prints only a changed tag.
fn commands(specs: &str) -> Vec<(String, bool)> {
    let mut no_password = false;
    let mut found = Vec::new();
    for item in split_list(specs) {
        let mut rest = item.as_str();
        for _ in 0..item.len() {
            let Some((word, after)) = rest.split_once(' ') else {
                break;
            };
            let is_option = word.split_once('=').is_some_and(|(name, _)| {
                !name.is_empty() && name.chars().all(|c| c.is_ascii_uppercase() || c == '_')
            });
            let tag = word.strip_suffix(':').filter(|name| {
                !name.is_empty() && name.chars().all(|c| c.is_ascii_uppercase() || c == '_')
            });
            match (is_option, tag) {
                (_, Some("NOPASSWD")) => no_password = true,
                (_, Some("PASSWD")) => no_password = false,
                (true, None) | (_, Some(_)) => {}
                (false, None) => break,
            }
            rest = after;
        }
        found.push((rest.to_string(), no_password));
    }
    found
}

#[derive(Debug)]
struct Accumulator {
    entry: Entry,
    defaults: DefaultsLine,
    others: Vec<String>,
}

impl Accumulator {
    fn matching(&mut self, line: &str) {
        for item in split_list(line) {
            if setting(&item) == NO_AUTHENTICATE {
                self.others.push(format!("Defaults {NO_AUTHENTICATE}"));
            }
        }
    }

    fn bound(&mut self, line: &str, expected: &Expected<'_>) -> Result<(), String> {
        let (binding, members, mut settings) = bound_line(line).ok_or_else(|| line.to_string())?;
        if settings.iter().any(|item| item == NO_AUTHENTICATE) {
            self.others.push(line.to_string());
        }
        if binding != '!' {
            return Ok(());
        }
        settings.sort();
        for member in &members {
            if member == expected.zmx {
                self.defaults = if self.defaults == DefaultsLine::Absent
                    && members.len() == 1
                    && settings == rule_settings()
                {
                    DefaultsLine::Exact
                } else {
                    DefaultsLine::Differs(line.to_string())
                };
            } else if expected.is_other_install(member) && self.defaults == DefaultsLine::Absent {
                self.defaults = DefaultsLine::Stale(member.clone());
            }
        }
        Ok(())
    }

    fn privileges(&mut self, line: &str, expected: &Expected<'_>) -> Result<(), String> {
        let (runas, specs) = line
            .strip_prefix('(')
            .and_then(|rest| rest.split_once(") "))
            .ok_or_else(|| line.to_string())?;
        for (command, no_password) in commands(specs) {
            if !no_password {
                continue;
            }
            if runas == expected.agent && command == expected.zmx {
                if self.entry == Entry::Absent {
                    self.entry = Entry::Exact;
                }
            } else if runas == expected.agent && expected.is_other_install(&command) {
                self.entry = Entry::Stale(command);
            } else {
                self.others.push(format!("({runas}) NOPASSWD: {command}"));
            }
        }
        Ok(())
    }
}

fn header(line: &str) -> Option<Section> {
    if line.starts_with(MATCHING_HEADER) && line.ends_with(':') {
        Some(Section::Matching)
    } else if line.starts_with(BOUND_HEADER) && line.ends_with(':') {
        Some(Section::Bound)
    } else if line.starts_with(PRIVILEGES_HEADER)
        && line.contains(PRIVILEGES_MIDDLE)
        && line.ends_with(':')
    {
        Some(Section::Privileges)
    } else {
        None
    }
}

fn echo(stdout: &str, stderr: &str) -> String {
    format!("stdout {stdout:?}, stderr {stderr:?}")
        .chars()
        .take(ECHO_MAX_CHARS)
        .collect()
}

fn read_listing(stdout: &str, expected: &Expected<'_>) -> Listing {
    let lines: Vec<&str> = stdout.lines().collect();
    if lines.len() > LISTING_LINES_MAX {
        return Listing::Unrecognised(format!(
            "{} lines; the limit is {LISTING_LINES_MAX}",
            lines.len()
        ));
    }
    let meaningful: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if let [only] = meaningful.as_slice() {
        if only.starts_with(PRIVILEGES_HEADER)
            && only.contains(NOT_ALLOWED_MIDDLE)
            && only.ends_with('.')
        {
            return Listing::NotAllowed;
        }
    }
    let mut section = Section::Start;
    let mut privileges_seen = false;
    let mut accumulator = Accumulator {
        entry: Entry::Absent,
        defaults: DefaultsLine::Absent,
        others: Vec::new(),
    };
    for line in meaningful {
        if let Some(body) = line.strip_prefix(INDENT) {
            let read = match section {
                Section::Start => Err(line.to_string()),
                Section::Matching => {
                    accumulator.matching(body);
                    Ok(())
                }
                Section::Bound => accumulator.bound(body, expected),
                Section::Privileges => accumulator.privileges(body, expected),
            };
            if let Err(unread) = read {
                return Listing::Unrecognised(unread.chars().take(ECHO_MAX_CHARS).collect());
            }
        } else if let Some(next) = header(line) {
            privileges_seen |= next == Section::Privileges;
            section = next;
        } else {
            return Listing::Unrecognised(line.chars().take(ECHO_MAX_CHARS).collect());
        }
    }
    if !privileges_seen {
        return Listing::Unrecognised("no privileges section".to_string());
    }
    Listing::Listed(Reading {
        entry: accumulator.entry,
        defaults: accumulator.defaults,
        others: accumulator.others,
    })
}

/// Decodes `sudo -n -k -l` against the rule.
///
/// sudo prints three sections: the matching defaults, the runas- and command-bound defaults,
/// and the entries, one line each when its output is a pipe, as sudo 1.9.17's `display_privs`
/// does.
#[must_use]
pub fn decode_listing(
    exit: Option<i32>,
    stdout: &str,
    stderr: &str,
    expected: &Expected<'_>,
) -> Listing {
    let err = meaningful(stderr);
    match exit {
        Some(0) if err.is_empty() => read_listing(stdout, expected),
        Some(1) if stdout.trim().is_empty() && err == [PASSWORD_REQUIRED] => {
            Listing::PasswordRequired
        }
        Some(0 | 1) if err.is_empty() => match read_listing(stdout, expected) {
            Listing::NotAllowed => Listing::NotAllowed,
            _ => Listing::Unrecognised(format!("exit {exit:?}, {}", echo(stdout, stderr))),
        },
        Some(1) if stdout.trim().is_empty() => match sudo_refusal(&err) {
            Some(Refusal::UnknownUser(user)) => Listing::Refused(format!("unknown user {user}")),
            Some(Refusal::Other(line)) if !line.starts_with(PASSWORD_REQUIRED) => {
                Listing::Refused(line)
            }
            Some(Refusal::Other(_)) | None => Listing::Unrecognised(echo(stdout, stderr)),
        },
        _ => Listing::Unrecognised(format!("exit {exit:?}, {}", echo(stdout, stderr))),
    }
}

fn meaningful(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

/// A refusal sudo prints about the user or the policy, by its first line; `None` for output
/// that is not sudo's.
fn sudo_refusal(stderr_lines: &[&str]) -> Option<Refusal> {
    let first = stderr_lines.first()?;
    if let Some(user) = first.strip_prefix(UNKNOWN_USER) {
        return Some(Refusal::UnknownUser(user.to_string()));
    }
    first
        .starts_with("sudo: ")
        .then(|| Refusal::Other((*first).to_string()))
}

enum Refusal {
    UnknownUser(String),
    Other(String),
}

#[must_use]
pub fn decode_wider(exit: Option<i32>, stdout: &str, stderr: &str) -> WiderProbe {
    let out = meaningful(stdout);
    let err = meaningful(stderr);
    match exit {
        Some(0) if out.is_empty() && err.is_empty() => WiderProbe::RanWithoutPassword,
        Some(1) if out.is_empty() && err == [PASSWORD_REQUIRED] => WiderProbe::PasswordRequired,
        Some(1) if out.is_empty() => match sudo_refusal(&err) {
            Some(Refusal::UnknownUser(user)) => WiderProbe::UnknownUser(user),
            Some(Refusal::Other(line)) if !line.starts_with(PASSWORD_REQUIRED) => {
                WiderProbe::Refused(line)
            }
            Some(Refusal::Other(_)) | None => WiderProbe::Unrecognised(echo(stdout, stderr)),
        },
        _ => WiderProbe::Unrecognised(format!("exit {exit:?}, {}", echo(stdout, stderr))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZMX: &str = "/Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx";
    const EXPECTED: Expected<'static> = Expected {
        agent: "tycho-agent",
        zmx: ZMX,
        zmx_installs: "/Users/Shared/tycho/mise/installs/zmx/",
    };
    /// The macOS defaults and the admin rule, printed in the form of sudo 1.9.17's
    /// `display_privs` and `sudoers_format_*` (`plugins/sudoers/display.c`, `fmtsudoers.c`).
    const MATCHING: &str = "Matching Defaults entries for frits on gorgonzola:\n    env_reset, env_keep+=BLOCKSIZE, env_keep+=\"COLORFGBG COLORTERM\", env_keep+=__CF_USER_TEXT_ENCODING, env_keep+=\"HOME MAIL\", lecture_file=/etc/sudo_lecture\n\n";
    const BOUND: &str = "Runas and Command-specific defaults for frits:\n    Defaults!/Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx env_keep=\"HOME ZMX_DIR ZMX_DIR_MODE ZMX_LOG_MODE\", umask=0007, umask_override\n\n";
    const PRIVILEGES: &str = "User frits may run the following commands on gorgonzola:\n    (ALL) ALL\n    (tycho-agent) NOPASSWD: /Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx\n";

    fn listed(stdout: &str) -> Listing {
        decode_listing(Some(0), stdout, "", &EXPECTED)
    }

    fn reading(stdout: &str) -> Reading {
        match listed(stdout) {
            Listing::Listed(reading) => reading,
            other => panic!("{other:?} for {stdout}"),
        }
    }

    #[test]
    fn the_rule_names_one_command_one_target_and_no_password_for_it_alone() {
        let rule = rule("frits", "tycho-agent", ZMX).unwrap();
        assert_eq!(
            rule,
            "# Written by xtask provision-agent; xtask setup reads it back with sudo -l.\n\
             Defaults!/Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx env_keep = \"HOME ZMX_DIR ZMX_DIR_MODE ZMX_LOG_MODE\", umask = 0007, umask_override\n\
             frits ALL = (tycho-agent) NOPASSWD: /Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx\n"
        );
        let words: Vec<&str> = rule.split_whitespace().collect();
        let all_at: Vec<usize> = words
            .iter()
            .enumerate()
            .filter(|(_, word)| word.contains("ALL"))
            .map(|(index, _)| index)
            .collect();
        let user_line = words.iter().position(|word| *word == "frits").unwrap();
        assert_eq!(
            all_at,
            [user_line + 1],
            "ALL appears only in the host field: {rule}"
        );
        for absent in [
            "SETENV",
            "/bin/sh",
            "/usr/bin/env",
            "+=",
            "!env_reset",
            "Cmnd_Alias",
        ] {
            assert!(!rule.contains(absent), "{absent} in {rule}");
        }
        assert_eq!(rule.matches("NOPASSWD").count(), 1);
    }

    #[test]
    fn exactly_the_rule_reads_exact() {
        let exact = reading(&format!("{MATCHING}{BOUND}{PRIVILEGES}"));
        assert!(exact.is_exact(), "{exact:?}");
    }

    #[test]
    fn a_rule_for_another_zmx_install_reads_stale_and_names_its_path() {
        let old = "/Users/Shared/tycho/mise/installs/zmx/0.7.1/zmx";
        let stale = reading(&format!("{MATCHING}{BOUND}{PRIVILEGES}").replace(ZMX, old));
        assert_eq!(stale.entry, Entry::Stale(old.to_string()));
        assert_eq!(stale.defaults, DefaultsLine::Stale(old.to_string()));
        assert!(stale.others.is_empty());
        assert!(!stale.is_exact());
    }

    #[test]
    fn an_unrelated_no_password_entry_neither_stands_for_the_rule_nor_passes_beside_it() {
        let vpn = "User frits may run the following commands on gorgonzola:\n    (ALL) ALL\n    (root) NOPASSWD: /usr/local/bin/vpn-helper\n";
        let alone = reading(&format!("{MATCHING}{vpn}"));
        assert_eq!(alone.entry, Entry::Absent);
        assert_eq!(alone.defaults, DefaultsLine::Absent);
        assert_eq!(alone.others, ["(root) NOPASSWD: /usr/local/bin/vpn-helper"]);
        let beside = reading(&format!(
            "{MATCHING}{BOUND}{PRIVILEGES}    (root) NOPASSWD: /usr/local/bin/vpn-helper\n"
        ));
        assert_eq!(beside.entry, Entry::Exact);
        assert!(!beside.is_exact());
    }

    #[test]
    fn every_other_way_to_run_without_a_password_is_named() {
        for (listing, other) in [
            (
                format!("{MATCHING}{BOUND}User frits may run the following commands on h:\n    (tycho-agent) NOPASSWD: /Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx, /bin/sh\n"),
                "(tycho-agent) NOPASSWD: /bin/sh",
            ),
            (
                format!("{MATCHING}{BOUND}User frits may run the following commands on h:\n    (ALL) NOPASSWD: ALL\n    (tycho-agent) NOPASSWD: /Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx\n"),
                "(ALL) NOPASSWD: ALL",
            ),
            (
                format!("Matching Defaults entries for frits on h:\n    env_reset, !authenticate\n\n{BOUND}{PRIVILEGES}"),
                "Defaults !authenticate",
            ),
            (
                format!("{MATCHING}Runas and Command-specific defaults for frits:\n    Defaults>tycho-agent !authenticate\n    Defaults!/Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx env_keep=\"HOME ZMX_DIR ZMX_DIR_MODE ZMX_LOG_MODE\", umask=0007, umask_override\n\n{PRIVILEGES}"),
                "Defaults>tycho-agent !authenticate",
            ),
            (
                format!("{MATCHING}{BOUND}User frits may run the following commands on h:\n    (tycho-agent) CWD=/ NOPASSWD: SETENV: /usr/bin/env\n    (tycho-agent) NOPASSWD: /Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx\n"),
                "(tycho-agent) NOPASSWD: /usr/bin/env",
            ),
        ] {
            let read = reading(&listing);
            assert_eq!(read.entry, Entry::Exact, "{listing}");
            assert!(read.others.iter().any(|named| named == other), "{read:?}");
            assert!(!read.is_exact());
        }
        let tag_reset = reading(&format!(
            "{MATCHING}{BOUND}User frits may run the following commands on h:\n    (tycho-agent) NOPASSWD: /Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx, PASSWD: /bin/sh\n"
        ));
        assert!(tag_reset.is_exact(), "{tag_reset:?}");
    }

    #[test]
    fn a_defaults_line_that_differs_or_is_missing_is_not_the_rule() {
        let missing = reading(&format!("{MATCHING}{PRIVILEGES}"));
        assert_eq!(missing.defaults, DefaultsLine::Absent);
        for settings in [
            "env_keep+=\"HOME ZMX_DIR ZMX_DIR_MODE ZMX_LOG_MODE\", umask=0007, umask_override",
            "env_keep=\"HOME ZMX_DIR ZMX_DIR_MODE ZMX_LOG_MODE SSH_AUTH_SOCK\", umask=0007, umask_override",
            "env_keep=\"HOME ZMX_DIR ZMX_DIR_MODE ZMX_LOG_MODE\", umask=0022, umask_override",
            "env_keep=\"HOME ZMX_DIR ZMX_DIR_MODE ZMX_LOG_MODE\", umask=0007",
            "env_keep=\"HOME ZMX_DIR ZMX_DIR_MODE ZMX_LOG_MODE\", umask=0007, umask_override, setenv",
        ] {
            let listing = format!(
                "{MATCHING}Runas and Command-specific defaults for frits:\n    Defaults!{ZMX} {settings}\n\n{PRIVILEGES}"
            );
            assert!(
                matches!(reading(&listing).defaults, DefaultsLine::Differs(_)),
                "{settings}"
            );
        }
        let twice = format!(
            "{MATCHING}Runas and Command-specific defaults for frits:\n    Defaults!{ZMX} env_keep=\"HOME ZMX_DIR ZMX_DIR_MODE ZMX_LOG_MODE\", umask=0007, umask_override\n    Defaults!{ZMX} env_keep=\"HOME ZMX_DIR ZMX_DIR_MODE ZMX_LOG_MODE\", umask=0007, umask_override\n\n{PRIVILEGES}"
        );
        assert!(matches!(reading(&twice).defaults, DefaultsLine::Differs(_)));
    }

    /// Captured with sudo 1.9.17p2 on macOS before any rule existed.
    #[test]
    fn decodes_each_listing_answer_and_rejects_the_unrecognised() {
        assert_eq!(
            decode_listing(Some(1), "", "sudo: a password is required\n", &EXPECTED),
            Listing::PasswordRequired
        );
        assert_eq!(
            decode_listing(
                Some(1),
                "User frits is not allowed to run sudo on gorgonzola.\n",
                "",
                &EXPECTED
            ),
            Listing::NotAllowed
        );
        assert!(matches!(
            decode_listing(
                Some(1),
                "",
                "sudo: a terminal is required to read the password\n",
                &EXPECTED
            ),
            Listing::Refused(_)
        ));
        let long = format!(
            "{PRIVILEGES}{}",
            "    (ALL) ALL\n".repeat(LISTING_LINES_MAX)
        );
        for (exit, stdout, stderr) in [
            (Some(0), "", ""),
            (Some(0), "garbage\n", ""),
            (Some(0), "    (ALL) ALL\n", ""),
            (Some(0), MATCHING, ""),
            (Some(0), "User frits may run the following commands on h:\n    ALL\n", ""),
            (Some(0), "Runas and Command-specific defaults for frits:\n    Something else\nUser frits may run the following commands on h:\n", ""),
            (Some(0), PRIVILEGES, "sudo: warning\n"),
            (Some(0), long.as_str(), ""),
            (Some(1), "", "sudo: a password is required\nmore\n"),
            (Some(1), "", "not sudo\n"),
            (Some(2), "", ""),
            (None, "", ""),
        ] {
            assert!(
                matches!(decode_listing(exit, stdout, stderr, &EXPECTED), Listing::Unrecognised(_)),
                "{exit:?} {stdout:?} {stderr:?}"
            );
        }
    }

    #[test]
    fn the_probes_never_prompt_and_never_use_or_drop_the_cached_ticket() {
        assert_eq!(listing_arguments(), ["-n", "-k", "-l"]);
        assert_eq!(
            wider_probe_arguments("tycho-agent"),
            ["-n", "-k", "-u", "tycho-agent", "--", "/usr/bin/true"]
        );
    }

    #[test]
    fn a_name_or_path_a_rule_would_have_to_escape_is_refused() {
        for name in [
            "",
            "Frits",
            "fr its",
            "fr,its",
            "x:y",
            "a=b",
            "ALL",
            &"a".repeat(33),
        ] {
            assert!(
                matches!(rule(name, "tycho-agent", ZMX), Err(RuleError::Name(_))),
                "{name:?}"
            );
            assert!(matches!(rule("frits", name, ZMX), Err(RuleError::Name(_))));
        }
        for path in [
            "zmx",
            "/a b/zmx",
            "/a,b/zmx",
            "/a/../zmx",
            "/a//zmx",
            "/a/zmx/",
            "/a\\b",
            "/a:b",
            "/a=b",
        ] {
            assert!(
                matches!(rule("frits", "tycho-agent", path), Err(RuleError::Path(_))),
                "{path:?}"
            );
        }
    }

    #[test]
    fn decodes_each_wider_answer_and_rejects_the_unrecognised() {
        assert_eq!(
            decode_wider(Some(1), "", "sudo: a password is required\n"),
            WiderProbe::PasswordRequired
        );
        assert_eq!(
            decode_wider(Some(0), "", ""),
            WiderProbe::RanWithoutPassword
        );
        assert_eq!(
            decode_wider(Some(1), "", "sudo: unknown user tycho-agent\n"),
            WiderProbe::UnknownUser("tycho-agent".to_string())
        );
        assert!(matches!(
            decode_wider(
                Some(1),
                "",
                "Sorry, user frits is not allowed to execute '/usr/bin/true' as tycho-agent\n"
            ),
            WiderProbe::Unrecognised(_)
        ));
        assert!(matches!(
            decode_wider(Some(1), "", "sudo: no tty present\n"),
            WiderProbe::Refused(_)
        ));
        for (exit, stdout, stderr) in [
            (Some(0), "x\n", ""),
            (Some(0), "", "sudo: warning\n"),
            (Some(1), "", "sudo: a password is required\nmore\n"),
            (Some(3), "", ""),
            (None, "", ""),
        ] {
            assert!(
                matches!(
                    decode_wider(exit, stdout, stderr),
                    WiderProbe::Unrecognised(_)
                ),
                "{exit:?} {stdout:?} {stderr:?}"
            );
        }
    }
}

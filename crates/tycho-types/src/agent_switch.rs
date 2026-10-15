//! The identity switch: the sudoers rule and the decoders of the `sudo` probes that read it.
//!
//! The rule lets the developer, and so the core, start the prefix's zmx as the agent user with
//! no password. Provisioning writes the rule, setup and the boundary suite probe it, and the
//! spawner runs `zmx run` through it.
//!
//! sudo wraps zmx, not the launcher: the session daemon zmx forks then runs as the agent, and the
//! pid `zmx list` reports is the agent's shell after it executes the launcher. The launcher's own
//! environment is typed inside the session after `env -i`, so only zmx's three variables cross
//! sudo.

use std::fmt;

pub const SUDO: &str = "/usr/bin/sudo";
/// A name without a dot: sudo skips files in `sudoers.d` whose names hold one.
pub const SUDOERS_DROP_IN: &str = "/etc/sudoers.d/tycho-agent";
pub const COMMAND_ALIAS: &str = "TYCHO_AGENT_ZMX";
/// The only variables sudo passes to the agent's zmx; `=` replaces the default list, which on
/// macOS keeps `HOME`, `MAIL` and `SSH_AUTH_SOCK`.
pub const KEPT_VARIABLES: [&str; 3] = ["ZMX_DIR", "ZMX_DIR_MODE", "ZMX_LOG_MODE"];
/// sudo otherwise runs the command under the union of the caller's umask and its default 0022,
/// under which zmx makes the socket 0750 and the developer cannot connect.
pub const RULE_UMASK: &str = "0007";
/// The argument the narrow probe lists the zmx command with.
pub const NARROW_PROBE_ARGUMENT: &str = "list";
/// A command outside the narrow rule, which a wider no-password rule would run.
pub const WIDER_PROBE_COMMAND: &str = "/usr/bin/true";
const PASSWORD_REQUIRED: &str = "sudo: a password is required";
const UNKNOWN_USER: &str = "sudo: unknown user ";
const NAME_MAX_BYTES: usize = 32;
const PATH_MAX_BYTES: usize = 512;
/// Text echoed from a probe's output is cut to this many characters.
const ECHO_MAX_CHARS: usize = 200;

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
/// No password is asked, only zmx's variables are kept, and the command runs under umask 007.
/// `ALL` appears only in the host field, which on one machine names that machine.
pub fn rule(developer: &str, agent: &str, zmx: &str) -> Result<String, RuleError> {
    check_name(developer)?;
    check_name(agent)?;
    check_path(zmx)?;
    let kept = KEPT_VARIABLES.join(" ");
    Ok(format!(
        "# Written by xtask provision-agent; xtask setup reads it back with sudo -l.\n\
         Cmnd_Alias {COMMAND_ALIAS} = {zmx}\n\
         Defaults!{COMMAND_ALIAS} env_keep = \"{kept}\", umask = {RULE_UMASK}, umask_override\n\
         {developer} ALL = ({agent}) NOPASSWD: {COMMAND_ALIAS}\n"
    ))
}

/// `sudo` arguments that ask whether the rule lets the caller run `zmx list` as the agent.
///
/// No prompt and no cached ticket: `-k` with a command ignores the ticket without removing it,
/// so the probe leaves the developer's sudo session as it was.
#[must_use]
pub fn narrow_probe_arguments(agent: &str, zmx: &str) -> Vec<String> {
    [
        "-n",
        "-k",
        "-l",
        "-u",
        agent,
        "--",
        zmx,
        NARROW_PROBE_ARGUMENT,
    ]
    .map(str::to_string)
    .to_vec()
}

/// What `sudo -l` prints for a permitted command: its full path and its arguments.
#[must_use]
pub fn narrow_probe_answer(zmx: &str) -> String {
    format!("{zmx} {NARROW_PROBE_ARGUMENT}")
}

/// `sudo` arguments that run a command outside the narrow rule as the agent.
///
/// No prompt and no cached ticket. The developer may run anything as the agent with a password,
/// so `sudo -l` answers "permitted" for any command once one entry needs none; only running one
/// shows whether a password is still asked for.
#[must_use]
pub fn wider_probe_arguments(agent: &str) -> Vec<String> {
    ["-n", "-k", "-u", agent, "--", WIDER_PROBE_COMMAND]
        .map(str::to_string)
        .to_vec()
}

/// What `sudo -n -k -l -u <agent> -- <zmx> list` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NarrowProbe {
    /// Exit 0 with the command echoed: the rule is in place.
    Permitted,
    /// No entry of the caller needs no password, so sudo would ask.
    PasswordRequired,
    /// Exit 1 with no output: the caller lists without a password, but not this command.
    NotPermitted,
    UnknownUser(String),
    /// Any other refusal from sudo, by its first line.
    Refused(String),
    Unrecognised(String),
}

/// What `sudo -n -k -u <agent> -- /usr/bin/true` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WiderProbe {
    /// The command outside the rule still needs a password: the rule is no wider.
    PasswordRequired,
    /// A rule runs commands outside zmx as the agent with no password.
    RanWithoutPassword,
    UnknownUser(String),
    Refused(String),
    Unrecognised(String),
}

fn meaningful(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

fn echo(stdout: &str, stderr: &str) -> String {
    format!("stdout {stdout:?}, stderr {stderr:?}")
        .chars()
        .take(ECHO_MAX_CHARS)
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
pub fn decode_narrow(exit: Option<i32>, stdout: &str, stderr: &str, zmx: &str) -> NarrowProbe {
    let out = meaningful(stdout);
    let err = meaningful(stderr);
    let answer = narrow_probe_answer(zmx);
    match exit {
        Some(0) if out == [answer.as_str()] && err.is_empty() => NarrowProbe::Permitted,
        Some(1) if out.is_empty() && err == [PASSWORD_REQUIRED] => NarrowProbe::PasswordRequired,
        Some(1) if out.is_empty() && err.is_empty() => NarrowProbe::NotPermitted,
        Some(1) if out.is_empty() => match sudo_refusal(&err) {
            Some(Refusal::UnknownUser(user)) => NarrowProbe::UnknownUser(user),
            Some(Refusal::Other(line)) if !line.starts_with(PASSWORD_REQUIRED) => {
                NarrowProbe::Refused(line)
            }
            Some(Refusal::Other(_)) | None => NarrowProbe::Unrecognised(echo(stdout, stderr)),
        },
        _ => NarrowProbe::Unrecognised(format!("exit {exit:?}, {}", echo(stdout, stderr))),
    }
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

    #[test]
    fn the_rule_names_one_command_one_target_and_no_password_for_it_alone() {
        let rule = rule("frits", "tycho-agent", ZMX).unwrap();
        assert_eq!(
            rule,
            "# Written by xtask provision-agent; xtask setup reads it back with sudo -l.\n\
             Cmnd_Alias TYCHO_AGENT_ZMX = /Users/Shared/tycho/mise/installs/zmx/0.8.1/zmx\n\
             Defaults!TYCHO_AGENT_ZMX env_keep = \"ZMX_DIR ZMX_DIR_MODE ZMX_LOG_MODE\", umask = 0007, umask_override\n\
             frits ALL = (tycho-agent) NOPASSWD: TYCHO_AGENT_ZMX\n"
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
        for absent in ["SETENV", "/bin/sh", "/usr/bin/env", "+=", "!env_reset"] {
            assert!(!rule.contains(absent), "{absent} in {rule}");
        }
        assert_eq!(rule.matches("NOPASSWD").count(), 1);
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
    fn the_probes_never_prompt_and_never_use_or_drop_the_cached_ticket() {
        assert_eq!(
            narrow_probe_arguments("tycho-agent", ZMX),
            ["-n", "-k", "-l", "-u", "tycho-agent", "--", ZMX, "list"]
        );
        assert_eq!(
            wider_probe_arguments("tycho-agent"),
            ["-n", "-k", "-u", "tycho-agent", "--", "/usr/bin/true"]
        );
    }

    /// Captured with sudo 1.9.17p2 on macOS before any rule existed, except the permitted
    /// answer, whose form is sudo(8)'s: the full path of the command and its arguments.
    #[test]
    fn decodes_each_narrow_answer_and_rejects_the_unrecognised() {
        let answer = format!("{ZMX} list\n");
        assert_eq!(
            decode_narrow(Some(0), &answer, "", ZMX),
            NarrowProbe::Permitted
        );
        assert_eq!(
            decode_narrow(Some(1), "", "sudo: a password is required\n", ZMX),
            NarrowProbe::PasswordRequired
        );
        assert_eq!(
            decode_narrow(Some(1), "", "", ZMX),
            NarrowProbe::NotPermitted
        );
        assert_eq!(
            decode_narrow(
                Some(1),
                "",
                "sudo: unknown user tycho-agent\nsudo: error initializing audit plugin sudoers_audit\n",
                ZMX
            ),
            NarrowProbe::UnknownUser("tycho-agent".to_string())
        );
        assert!(matches!(
            decode_narrow(
                Some(1),
                "",
                "sudo: a terminal is required to read the password\n",
                ZMX
            ),
            NarrowProbe::Refused(_)
        ));
        for (exit, stdout, stderr) in [
            (Some(0), "/usr/bin/true list\n", ""),
            (Some(0), "", ""),
            (Some(0), answer.as_str(), "sudo: warning\n"),
            (Some(1), "something\n", ""),
            (Some(1), "", "sudo: a password is required\nmore\n"),
            (Some(1), "", "not sudo\n"),
            (Some(2), "", ""),
            (None, "", ""),
        ] {
            assert!(
                matches!(
                    decode_narrow(exit, stdout, stderr, ZMX),
                    NarrowProbe::Unrecognised(_)
                ),
                "{exit:?} {stdout:?} {stderr:?}"
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

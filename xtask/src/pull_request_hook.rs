//! `xtask hook pre-tool-use`: refuses a `gh pr create` that opens a pull request ready for
//! review, and a `gh pr create` or `gh pr edit` whose title fails the commit subject check.
//! A review starts on `ready_for_review`, which GitHub sends only when a draft is marked ready.

use std::collections::HashMap;
use std::io::{self, Read};
use std::iter::Peekable;
use std::str::Chars;

use crate::{check_subject, explain, Verdict, HOOK_INPUT_MAX_BYTES};

const COMMAND_MAX_CHARS: usize = 256 * 1024;
const WORDS_MAX: usize = 8192;
/// The `gh pr create` and `gh pr edit` flags that take a value, so the value is never read as
/// a flag of its own.
const VALUE_FLAGS: [&str; 32] = [
    "-a",
    "--assignee",
    "-B",
    "--base",
    "-b",
    "--body",
    "-F",
    "--body-file",
    "-H",
    "--head",
    "-l",
    "--label",
    "-m",
    "--milestone",
    "-p",
    "--project",
    "-r",
    "--reviewer",
    "-T",
    "--template",
    "-R",
    "--repo",
    "--recover",
    "--add-assignee",
    "--add-label",
    "--add-project",
    "--add-reviewer",
    "--remove-assignee",
    "--remove-label",
    "--remove-project",
    "--remove-reviewer",
    "--remove-milestone",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Word {
    text: String,
    /// False when the shell would expand part of the word: an unquoted or double-quoted `$` or
    /// backtick.
    literal: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
}

#[derive(Debug)]
struct Lexer<'a> {
    chars: Peekable<Chars<'a>>,
    commands: Vec<Vec<Word>>,
    current: Vec<Word>,
    word: String,
    literal: bool,
    in_word: bool,
    pending_heredocs: Vec<String>,
    words: usize,
}

impl Lexer<'_> {
    fn end_word(&mut self) -> Result<(), String> {
        if !self.in_word {
            return Ok(());
        }
        self.words = self.words.saturating_add(1);
        if self.words > WORDS_MAX {
            return Err(format!("the command has more than {WORDS_MAX} words"));
        }
        self.current.push(Word {
            text: std::mem::take(&mut self.word),
            literal: self.literal,
        });
        self.literal = true;
        self.in_word = false;
        Ok(())
    }

    fn end_command(&mut self) -> Result<(), String> {
        self.end_word()?;
        if !self.current.is_empty() {
            self.commands.push(std::mem::take(&mut self.current));
        }
        Ok(())
    }

    fn push(&mut self, character: char) {
        if matches!(character, '$' | '`') {
            self.literal = false;
        }
        self.word.push(character);
        self.in_word = true;
    }

    fn single_quoted(&mut self) -> Result<(), String> {
        loop {
            match self.chars.next() {
                None => return Err("a single quote is never closed".to_string()),
                Some('\'') => break,
                Some(inner) => self.word.push(inner),
            }
        }
        self.in_word = true;
        Ok(())
    }

    fn double_quoted(&mut self) -> Result<(), String> {
        loop {
            match self.chars.next() {
                None => return Err("a double quote is never closed".to_string()),
                Some('"') => break,
                Some('\\') => match self.chars.next() {
                    Some(escaped @ ('"' | '\\' | '$' | '`')) => self.word.push(escaped),
                    Some(other) => {
                        self.word.push('\\');
                        self.push(other);
                    }
                    None => return Err("a double quote is never closed".to_string()),
                },
                Some(inner) => self.push(inner),
            }
        }
        self.in_word = true;
        Ok(())
    }

    /// The delimiter after `<<` or `<<-`, without its quotes.
    fn heredoc_delimiter(&mut self) -> Result<String, String> {
        self.chars.next_if_eq(&'-');
        while self.chars.next_if(|c| matches!(c, ' ' | '\t')).is_some() {}
        let quote = self.chars.next_if(|c| matches!(c, '\'' | '"'));
        let mut delimiter = String::new();
        while let Some(character) = self
            .chars
            .next_if(|c| c.is_ascii_alphanumeric() || *c == '_')
        {
            delimiter.push(character);
        }
        if delimiter.is_empty() {
            return Err("a heredoc has no delimiter".to_string());
        }
        if let Some(quote) = quote {
            if self.chars.next() != Some(quote) {
                return Err(format!("the heredoc delimiter {delimiter} is never closed"));
            }
        }
        Ok(delimiter)
    }

    /// Consumes a heredoc body through the line that is its delimiter.
    fn skip_heredoc_body(&mut self, delimiter: &str) -> Result<(), String> {
        loop {
            if self.chars.peek().is_none() {
                return Err(format!("the heredoc ending at {delimiter} is never closed"));
            }
            let mut line = String::new();
            for character in self.chars.by_ref() {
                if character == '\n' {
                    break;
                }
                line.push(character);
            }
            if line.trim_start_matches('\t') == delimiter {
                return Ok(());
            }
        }
    }

    fn run(mut self) -> Result<Vec<Vec<Word>>, String> {
        while let Some(character) = self.chars.next() {
            match character {
                ' ' | '\t' => self.end_word()?,
                ';' | '&' | '|' | '(' | ')' => self.end_command()?,
                '\n' => {
                    self.end_command()?;
                    for delimiter in std::mem::take(&mut self.pending_heredocs) {
                        self.skip_heredoc_body(&delimiter)?;
                    }
                }
                '#' if !self.in_word => while self.chars.next_if(|c| *c != '\n').is_some() {},
                '\\' => match self.chars.next() {
                    Some('\n') => {}
                    Some(next) => {
                        self.word.push(next);
                        self.in_word = true;
                    }
                    None => return Err("the command ends with a backslash".to_string()),
                },
                '\'' => self.single_quoted()?,
                '"' => self.double_quoted()?,
                '<' if self.chars.peek() == Some(&'<') => {
                    self.chars.next();
                    if self.chars.next_if_eq(&'<').is_some() {
                        self.push('<');
                        self.push('<');
                        self.push('<');
                    } else {
                        self.end_word()?;
                        let delimiter = self.heredoc_delimiter()?;
                        self.pending_heredocs.push(delimiter);
                    }
                }
                other => self.push(other),
            }
        }
        if !self.pending_heredocs.is_empty() {
            return Err("a heredoc body is missing".to_string());
        }
        self.end_command()?;
        Ok(self.commands)
    }
}

/// The command's simple commands, each as its words, with heredoc bodies and comments left out.
fn commands(command: &str) -> Result<Vec<Vec<Word>>, String> {
    let length = command.chars().count();
    if length > COMMAND_MAX_CHARS {
        return Err(format!(
            "the command is {length} characters; the limit is {COMMAND_MAX_CHARS}"
        ));
    }
    Lexer {
        chars: command.chars().peekable(),
        commands: Vec::new(),
        current: Vec::new(),
        word: String::new(),
        literal: true,
        in_word: false,
        pending_heredocs: Vec::new(),
        words: 0,
    }
    .run()
}

/// `NAME=value` with a shell name, as the name and the value.
fn assignment(word: &Word) -> Option<(&str, &str)> {
    let (name, value) = word.text.split_once('=')?;
    let mut characters = name.chars();
    let first = characters.next()?;
    let is_name = (first.is_ascii_alphabetic() || first == '_')
        && characters.all(|c| c.is_ascii_alphanumeric() || c == '_');
    is_name.then_some((name, value))
}

/// The value of a word that is exactly `$NAME` or `${NAME}` for a variable assigned literally
/// earlier in the command; any other word as written.
fn resolved(word: &Word, variables: &HashMap<String, String>) -> Word {
    if word.literal {
        return word.clone();
    }
    let name = word
        .text
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
        .or_else(|| word.text.strip_prefix('$'));
    name.and_then(|name| variables.get(name)).map_or_else(
        || word.clone(),
        |value| Word {
            text: value.clone(),
            literal: true,
        },
    )
}

fn judge_title(title: &str, literal: bool) -> Result<(), String> {
    if !literal {
        return Err(format!(
            "the pull request title `{title}` is not literal text; write the title itself so \
             it can be checked"
        ));
    }
    match check_subject(title) {
        Verdict::Ok => Ok(()),
        verdict => Err(format!(
            "the pull request title `{title}` fails the commit subject check: {}",
            explain(&verdict)
        )),
    }
}

fn judge_pull_request(
    verb: &str,
    arguments: &[Word],
    variables: &HashMap<String, String>,
) -> Result<(), String> {
    let mut draft = false;
    let mut remaining = arguments.iter().map(|word| resolved(word, variables));
    while let Some(argument) = remaining.next() {
        let text = argument.text.as_str();
        if let Some(title) = text.strip_prefix("--title=") {
            judge_title(title, argument.literal)?;
        } else if text == "--title" || text == "-t" {
            let title = remaining
                .next()
                .ok_or_else(|| format!("`{text}` has no title after it"))?;
            judge_title(&title.text, title.literal)?;
        } else if let Some(title) = text.strip_prefix("-t").filter(|_| !text.starts_with("--")) {
            judge_title(title, argument.literal)?;
        } else if matches!(text, "--draft" | "-d" | "--draft=true") {
            draft = true;
        } else if VALUE_FLAGS.contains(&text) {
            remaining.next();
        }
    }
    if verb == "create" && !draft {
        return Err(
            "`gh pr create` opens a pull request ready for review; open it as a \
                    draft with `--draft` and run `gh pr ready <number>` when it is ready, \
                    which starts the review"
                .to_string(),
        );
    }
    Ok(())
}

/// Allows a command unless one of its `gh pr create` or `gh pr edit` commands breaks a rule;
/// a command it cannot read is refused, since only `gh pr` commands reach this hook.
pub fn decide(command: &str) -> Decision {
    let commands = match commands(command) {
        Ok(commands) => commands,
        Err(reason) => {
            return Decision::Deny(format!("xtask hook could not read the command: {reason}"))
        }
    };
    let mut variables: HashMap<String, String> = HashMap::new();
    for words in &commands {
        let leading = words
            .iter()
            .take_while(|word| assignment(word).is_some())
            .count();
        let Some(rest) = words.get(leading..).filter(|rest| !rest.is_empty()) else {
            for word in words {
                if let Some((name, value)) = assignment(word) {
                    if word.literal {
                        variables.insert(name.to_string(), value.to_string());
                    } else {
                        variables.remove(name);
                    }
                }
            }
            continue;
        };
        let verb = match rest {
            [gh, pr, verb, ..]
                if gh.text == "gh"
                    && pr.text == "pr"
                    && matches!(verb.text.as_str(), "create" | "edit") =>
            {
                verb.text.as_str()
            }
            _ => continue,
        };
        let arguments = rest.get(3..).unwrap_or_default();
        if let Err(reason) = judge_pull_request(verb, arguments, &variables) {
            return Decision::Deny(reason);
        }
    }
    Decision::Allow
}

fn hook_command() -> Result<String, String> {
    let mut text = String::new();
    io::stdin()
        .take(HOOK_INPUT_MAX_BYTES)
        .read_to_string(&mut text)
        .map_err(|error| format!("the hook input is unreadable: {error}"))?;
    let event: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| format!("the hook input is not JSON: {error}"))?;
    if event.get("tool_name").and_then(serde_json::Value::as_str) != Some("Bash") {
        return Ok(String::new());
    }
    event
        .get("tool_input")
        .and_then(|input| input.get("command"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "the hook input has no Bash command".to_string())
}

fn deny_output(reason: &str) -> String {
    serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    })
    .to_string()
}

pub fn hook_pre_tool_use() -> i32 {
    let decision = match hook_command() {
        Ok(command) => decide(&command),
        Err(reason) => Decision::Deny(format!("xtask hook: {reason}")),
    };
    if let Decision::Deny(reason) = decision {
        let output = deny_output(&format!(
            "{reason}\n\nRule: docs/process.md (Code review, When a review runs)"
        ));
        #[expect(
            clippy::print_stdout,
            reason = "Claude Code reads a hook's decision from its standard output"
        )]
        {
            println!("{output}");
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::{commands, decide, Decision, COMMAND_MAX_CHARS};

    fn texts(command: &str) -> Vec<Vec<String>> {
        commands(command)
            .unwrap()
            .into_iter()
            .map(|words| words.into_iter().map(|word| word.text).collect())
            .collect()
    }

    fn denied(command: &str) -> String {
        match decide(command) {
            Decision::Deny(reason) => reason,
            Decision::Allow => panic!("allowed: {command}"),
        }
    }

    #[test]
    fn the_lexer_splits_on_operators_and_keeps_quoted_text_whole() {
        assert_eq!(
            texts("cd x && gh pr create --title 'fix: a; b' | tail\nls"),
            vec![
                vec!["cd", "x"],
                vec!["gh", "pr", "create", "--title", "fix: a; b"],
                vec!["tail"],
                vec!["ls"],
            ]
        );
        assert_eq!(
            texts("echo \"a \\\"b\\\" c\" d\\ e"),
            vec![vec!["echo", "a \"b\" c", "d e"]]
        );
        assert_eq!(
            texts("gh pr create \\\n  --draft # a comment"),
            vec![vec!["gh", "pr", "create", "--draft"]]
        );
    }

    #[test]
    fn a_heredoc_body_is_left_out_and_the_command_after_it_is_read() {
        let command = "gh pr create --draft --title 'fix: a' --body-file - <<'EOF'\n\
                       gh pr create --title Bad\n\
                       EOF\n\
                       gh pr view";
        assert_eq!(
            texts(command),
            vec![
                vec![
                    "gh",
                    "pr",
                    "create",
                    "--draft",
                    "--title",
                    "fix: a",
                    "--body-file",
                    "-"
                ],
                vec!["gh", "pr", "view"],
            ]
        );
        assert_eq!(decide(command), Decision::Allow);
        assert!(denied("cat <<EOF\nbody\nEOF\ngh pr create --fill").contains("--draft"));
    }

    #[test]
    fn an_unreadable_command_is_refused_with_the_reason() {
        for (command, reason) in [
            (
                "gh pr create --title 'fix: a",
                "single quote is never closed",
            ),
            (
                "gh pr create --title \"fix: a",
                "double quote is never closed",
            ),
            ("cat <<EOF\nno end", "never closed"),
            ("cat <<EOF", "heredoc body is missing"),
            ("cat << \nx", "no delimiter"),
            ("gh pr create \\", "ends with a backslash"),
        ] {
            let refusal = denied(command);
            assert!(refusal.contains(reason), "{command}: {refusal}");
        }
        let long = "a ".repeat(COMMAND_MAX_CHARS);
        assert!(denied(&long).contains("characters; the limit is"));
    }

    #[test]
    fn a_create_without_draft_is_refused_and_one_with_draft_is_allowed() {
        for command in [
            "gh pr create --title 'fix: a b'",
            "gh pr create --fill",
            "gh pr create --draft=false --fill",
            "cd /x && GH_PAGER= gh pr create --fill",
            "git push -q && gh pr create --base main --fill",
        ] {
            assert!(denied(command).contains("--draft"), "{command}");
        }
        for command in [
            "gh pr create --draft --fill",
            "gh pr create -d --fill",
            "gh pr create --draft=true --fill",
            "gh pr create --fill --draft --base main",
        ] {
            assert_eq!(decide(command), Decision::Allow, "{command}");
        }
    }

    #[test]
    fn a_draft_flag_given_as_another_flag_s_value_does_not_count() {
        assert!(denied("gh pr create --fill --body --draft").contains("--draft"));
        assert!(denied("gh pr create --fill -b '--draft'").contains("--draft"));
    }

    #[test]
    fn every_title_form_is_checked_on_create_and_edit() {
        for command in [
            "gh pr create --draft --title 'Fix: a'",
            "gh pr create --draft --title='fix: a.'",
            "gh pr create --draft -t 'nope'",
            "gh pr create --draft '-tfix: A'",
            "gh pr edit 3 --title 'fix: a.'",
        ] {
            assert!(
                denied(command).contains("fails the commit subject check"),
                "{command}"
            );
        }
        assert!(denied("gh pr edit 3 --title").contains("has no title after it"));
        assert_eq!(
            decide("gh pr edit 3 --title 'fix: keep a test secret out'"),
            Decision::Allow
        );
        assert_eq!(decide("gh pr edit 3 --add-label --title"), Decision::Allow);
    }

    #[test]
    fn a_title_in_a_literal_variable_is_checked_and_any_other_expansion_is_refused() {
        assert_eq!(
            decide("T=\"fix: keep it\"; gh pr create --draft --title \"$T\""),
            Decision::Allow
        );
        assert!(denied("T='Fix: it'; gh pr create --draft --title \"${T}\"")
            .contains("fails the commit subject check"));
        for command in [
            "gh pr create --draft --title \"$(git log -1 --format=%s)\"",
            "gh pr create --draft --title \"$UNSET\"",
            "T=\"$(date)\"; gh pr create --draft --title \"$T\"",
            "gh pr create --draft --title \"fix: `id`\"",
        ] {
            assert!(denied(command).contains("is not literal text"), "{command}");
        }
    }

    #[test]
    fn other_commands_and_quoted_mentions_are_allowed() {
        for command in [
            "gh pr view 3",
            "gh pr ready 3",
            "echo 'gh pr create'",
            "git commit -m \"docs: gh pr create needs --draft\"",
            "gh pr list | grep create",
            "cat <<< 'gh pr create'",
        ] {
            assert_eq!(decide(command), Decision::Allow, "{command}");
        }
    }
}

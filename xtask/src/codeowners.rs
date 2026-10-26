//! `check-codeowners`: `.github/CODEOWNERS` gates `docs/mandate.md`, and itself, behind the
//! operator's review and nothing else. GitHub applies the last rule that matches a path and
//! skips a line whose owner does not start with `@` as invalid, so a rule a later line can
//! override, or an owner on an invalid line, reads as "no review required" even with a rule
//! present. A rule for `.github/CODEOWNERS` protects the file from loosening its own
//! requirement without the same review.

use std::fs;
use std::path::Path;

use serde_json::Value;

const CODEOWNERS_PATH: &str = ".github/CODEOWNERS";
const MANDATE_PATH: &str = "docs/mandate.md";
const MANDATE_EXPORT_PATH: &str = "config/export/mandate.json";
const CODEOWNERS_MAX_BYTES: usize = 8192;
const RULES_MAX: usize = 16;

/// One non-comment, non-blank line: a path pattern and the owner tokens after it, exactly as
/// written, so a token missing its leading `@` is kept rather than dropped here.
#[derive(Debug)]
struct Rule {
    pattern: String,
    owners: Vec<String>,
}

/// A character GitHub's own CODEOWNERS parser is unlikely to treat as plain content: a
/// no-break space or another Unicode whitespace character reads as part of a pattern or an
/// owner rather than a separator, and a control character has no defined meaning there.
fn disallowed_char(c: char) -> bool {
    (c.is_whitespace() && c != ' ' && c != '\t') || (c.is_control() && c != '\t')
}

/// Lines of a bounded CODEOWNERS file into its rules, split on a plain space or tab only
/// (never generic Unicode whitespace, which would silently glue a pattern to its owner or an
/// owner to nothing across a no-break space), or the first defect that stops parsing: the
/// file is over its byte cap, a line holds a disallowed character, or more rules are present
/// than `RULES_MAX` allows.
fn rules(text: &str) -> Result<Vec<Rule>, String> {
    if text.len() > CODEOWNERS_MAX_BYTES {
        return Err(format!(
            "{CODEOWNERS_PATH} is over the {CODEOWNERS_MAX_BYTES}-byte cap"
        ));
    }
    let mut parsed = Vec::new();
    for (number, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(bad) = line.chars().find(|&c| disallowed_char(c)) {
            return Err(format!(
                "{CODEOWNERS_PATH}:{}: holds U+{:04X}, not a space or a tab; GitHub's own split on it is not something this check can rely on",
                number.saturating_add(1),
                bad as u32
            ));
        }
        let mut fields = line.split([' ', '\t']).filter(|field| !field.is_empty());
        let Some(pattern) = fields.next() else {
            continue;
        };
        let owners: Vec<String> = fields.map(str::to_string).collect();
        if parsed.len() >= RULES_MAX {
            return Err(format!(
                "{CODEOWNERS_PATH} holds more than {RULES_MAX} rules"
            ));
        }
        parsed.push(Rule {
            pattern: pattern.to_string(),
            owners,
        });
    }
    Ok(parsed)
}

/// The operator's GitHub login, read from the mandate export rather than hardcoded, so one
/// change to `config/mandate.cue` moves both the mandate's documented owner and this check.
fn operator_handle(export_path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(export_path)
        .map_err(|error| format!("cannot read {}: {error}", export_path.display()))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|error| format!("{}: {error}", export_path.display()))?;
    value
        .get("operator_github_handle")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("{} names no operator_github_handle", export_path.display()))
}

/// The owner-token defect for one path's rule, or none: every token must carry its `@`
/// (GitHub skips the whole line as invalid otherwise, which leaves the path with no owner it
/// recognises), and the recognised owners must be exactly the configured handle. No owner, an
/// unmarked one, or an extra one beside the operator's all weaken the requirement.
fn owner_defect(path: &str, owners: &[String], operator_handle: &str) -> Option<String> {
    let recognised: Vec<&str> = owners
        .iter()
        .filter_map(|owner| owner.strip_prefix('@'))
        .collect();
    if owners.len() != recognised.len() {
        return Some(format!(
            "{CODEOWNERS_PATH} names an owner for {path} with no leading @; GitHub skips the invalid line"
        ));
    }
    if recognised != [operator_handle] {
        return Some(format!(
            "{CODEOWNERS_PATH} must name exactly @{operator_handle} for {path}, found {recognised:?}"
        ));
    }
    None
}

/// Defects in a bounded, character-clean rule list. GitHub applies the last rule that matches
/// a path, so a rule can be overridden by nothing after it: the mandate's rule must be the
/// file's own last rule, and the rule protecting this file must be the one immediately
/// before it, with nothing between them, since anything between (a bare `*`, another pattern)
/// could itself override the self-protecting rule under the same "last match wins" reading.
/// Past position, `owner_defect` covers each rule's owner.
fn mandate_defects(rules: &[Rule], operator_handle: &str) -> Vec<String> {
    let len = rules.len();
    if len < 2 {
        return vec![format!(
            "{CODEOWNERS_PATH} needs two rules in order: one for {CODEOWNERS_PATH} itself, then one for {MANDATE_PATH}"
        )];
    }
    let mut defects = Vec::new();
    match rules.get(len.saturating_sub(1)) {
        Some(rule) if rule.pattern == MANDATE_PATH => {
            if let Some(defect) = owner_defect(MANDATE_PATH, &rule.owners, operator_handle) {
                defects.push(defect);
            }
        }
        _ => defects.push(format!(
            "{CODEOWNERS_PATH}: the file's last rule must be for {MANDATE_PATH}, so nothing after it can change what GitHub applies to it"
        )),
    }
    match rules.get(len.saturating_sub(2)) {
        Some(rule) if rule.pattern == CODEOWNERS_PATH => {
            if let Some(defect) = owner_defect(CODEOWNERS_PATH, &rule.owners, operator_handle) {
                defects.push(defect);
            }
        }
        _ => defects.push(format!(
            "{CODEOWNERS_PATH}: the rule just before the one for {MANDATE_PATH} must be for {CODEOWNERS_PATH} itself, with nothing between them"
        )),
    }
    defects
}

pub fn check_codeowners() -> i32 {
    check_codeowners_at(Path::new(CODEOWNERS_PATH), Path::new(MANDATE_EXPORT_PATH))
}

fn check_codeowners_at(codeowners_path: &Path, export_path: &Path) -> i32 {
    let text = match fs::read_to_string(codeowners_path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!(
                "xtask check-codeowners: cannot read {}: {error}",
                codeowners_path.display()
            );
            return 1;
        }
    };
    let rule_list = match rules(&text) {
        Ok(list) => list,
        Err(error) => {
            eprintln!("xtask check-codeowners: {error}");
            return 1;
        }
    };
    if rule_list.is_empty() {
        eprintln!(
            "xtask check-codeowners: examined 0 rules in {}; a check over nothing is a failure",
            codeowners_path.display()
        );
        return 1;
    }
    let operator_handle = match operator_handle(export_path) {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!("xtask check-codeowners: {error}");
            return 1;
        }
    };
    let defects = mandate_defects(&rule_list, &operator_handle);
    if defects.is_empty() {
        println!(
            "xtask check-codeowners: examined {} rules, no defects",
            rule_list.len()
        );
        return 0;
    }
    eprintln!(
        "xtask check-codeowners: examined {} rules, {} defects",
        rule_list.len(),
        defects.len()
    );
    for defect in &defects {
        eprintln!("  {defect}");
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    const HANDLE: &str = "frits-v";
    const SELF_RULE: &str = ".github/CODEOWNERS @frits-v";
    const MANDATE_RULE: &str = "docs/mandate.md @frits-v";

    fn parse(text: &str) -> Vec<Rule> {
        rules(text).expect("text parses")
    }

    #[test]
    fn both_rules_in_order_with_the_operators_handle_pass() {
        let text = format!(
            "# this file and the mandate change only with the operator's review\n{SELF_RULE}\n{MANDATE_RULE}\n"
        );
        let defects = mandate_defects(&parse(&text), HANDLE);
        assert_eq!(defects, Vec::<String>::new());
    }

    #[test]
    fn only_the_mandate_rule_with_no_self_rule_is_a_defect() {
        let text = format!("{MANDATE_RULE}\n");
        let defects = mandate_defects(&parse(&text), HANDLE);
        assert_eq!(
            defects,
            vec![format!(
                "{CODEOWNERS_PATH} needs two rules in order: one for {CODEOWNERS_PATH} itself, then one for {MANDATE_PATH}"
            )]
        );
    }

    #[test]
    fn something_else_just_before_the_mandate_rule_is_a_defect() {
        let text = format!("docs/other.md @frits-v\n{MANDATE_RULE}\n");
        let defects = mandate_defects(&parse(&text), HANDLE);
        assert_eq!(
            defects,
            vec![format!(
                "{CODEOWNERS_PATH}: the rule just before the one for {MANDATE_PATH} must be for {CODEOWNERS_PATH} itself, with nothing between them"
            )]
        );
    }

    #[test]
    fn a_bare_star_between_the_self_rule_and_the_mandate_rule_is_a_defect() {
        // Without the adjacency requirement, this shape would pass: GitHub's "last match
        // wins" lets the bare `*` (no owner) override the self-protecting rule before it.
        let text = format!("{SELF_RULE}\n*\n{MANDATE_RULE}\n");
        let defects = mandate_defects(&parse(&text), HANDLE);
        assert_eq!(
            defects,
            vec![format!(
                "{CODEOWNERS_PATH}: the rule just before the one for {MANDATE_PATH} must be for {CODEOWNERS_PATH} itself, with nothing between them"
            )]
        );
    }

    #[test]
    fn a_trailing_bare_star_after_the_mandate_rule_overrides_it_and_is_a_defect() {
        let text = format!("{SELF_RULE}\n{MANDATE_RULE}\n*\n");
        let defects = mandate_defects(&parse(&text), HANDLE);
        assert_eq!(
            defects,
            vec![
                format!(
                    "{CODEOWNERS_PATH}: the file's last rule must be for {MANDATE_PATH}, so nothing after it can change what GitHub applies to it"
                ),
                format!(
                    "{CODEOWNERS_PATH}: the rule just before the one for {MANDATE_PATH} must be for {CODEOWNERS_PATH} itself, with nothing between them"
                ),
            ]
        );
    }

    #[test]
    fn a_later_duplicate_mandate_rule_with_no_owner_wins_and_is_a_defect() {
        let text = format!("{SELF_RULE}\n{MANDATE_RULE}\ndocs/mandate.md\n");
        let defects = mandate_defects(&parse(&text), HANDLE);
        assert_eq!(
            defects,
            vec![
                format!(
                    "{CODEOWNERS_PATH} must name exactly @{HANDLE} for {MANDATE_PATH}, found []"
                ),
                format!(
                    "{CODEOWNERS_PATH}: the rule just before the one for {MANDATE_PATH} must be for {CODEOWNERS_PATH} itself, with nothing between them"
                ),
            ]
        );
    }

    #[test]
    fn a_later_broader_rule_with_a_different_owner_overrides_the_mandate_rule_and_is_a_defect() {
        let text = format!("{SELF_RULE}\n{MANDATE_RULE}\ndocs/ @someone-else\n");
        let defects = mandate_defects(&parse(&text), HANDLE);
        assert_eq!(defects.len(), 2);
        assert!(defects[0].contains("must be for docs/mandate.md"));
    }

    #[test]
    fn an_owner_missing_its_leading_at_sign_is_a_defect() {
        let text = format!("{SELF_RULE}\ndocs/mandate.md frits-v\n");
        let defects = mandate_defects(&parse(&text), HANDLE);
        assert_eq!(
            defects,
            vec![format!(
                "{CODEOWNERS_PATH} names an owner for {MANDATE_PATH} with no leading @; GitHub skips the invalid line"
            )]
        );
    }

    #[test]
    fn an_extra_owner_beside_the_operator_is_a_defect() {
        let text = format!("{SELF_RULE}\ndocs/mandate.md @frits-v @someone-else\n");
        let defects = mandate_defects(&parse(&text), HANDLE);
        assert_eq!(
            defects,
            vec![format!(
                "{CODEOWNERS_PATH} must name exactly @{HANDLE} for {MANDATE_PATH}, found [\"frits-v\", \"someone-else\"]"
            )]
        );
    }

    #[test]
    fn the_self_rule_with_the_wrong_owner_is_its_own_defect() {
        let text = format!(".github/CODEOWNERS @someone-else\n{MANDATE_RULE}\n");
        let defects = mandate_defects(&parse(&text), HANDLE);
        assert_eq!(
            defects,
            vec![format!(
                "{CODEOWNERS_PATH} must name exactly @{HANDLE} for {CODEOWNERS_PATH}, found [\"someone-else\"]"
            )]
        );
    }

    // A no-break space (U+00A0) is whitespace to Rust's generic splitter but not one of the
    // two separators GitHub is taken to use; each shape it can hide a broken rule behind is
    // refused outright rather than guessed at.

    #[test]
    fn a_no_break_space_between_a_pattern_and_its_owner_is_refused() {
        let text = "docs/mandate.md\u{a0}@frits-v\n";
        assert!(rules(text).is_err());
    }

    #[test]
    fn a_leading_no_break_space_on_a_pattern_is_refused() {
        let text = "\u{a0}docs/mandate.md @frits-v\n";
        assert!(rules(text).is_err());
    }

    #[test]
    fn a_trailing_no_break_space_on_an_owner_is_refused() {
        let text = "docs/mandate.md @frits-v\u{a0}\n";
        assert!(rules(text).is_err());
    }

    #[test]
    fn a_line_of_only_a_no_break_space_is_refused_not_read_as_blank() {
        let text = "\u{a0}\n";
        assert!(rules(text).is_err());
    }

    #[test]
    fn a_file_over_the_byte_cap_is_refused() {
        let text = format!(
            "# {}\n{SELF_RULE}\n{MANDATE_RULE}\n",
            "x".repeat(CODEOWNERS_MAX_BYTES)
        );
        let error = rules(&text).expect_err("over the cap");
        assert!(error.contains("byte cap"));
    }

    #[test]
    fn more_rules_than_the_cap_is_refused() {
        use std::fmt::Write;

        let mut text = String::new();
        for n in 0..=RULES_MAX {
            writeln!(text, "docs/filler-{n}.md @frits-v").expect("writing to a String never fails");
        }
        let error = rules(&text).expect_err("over the cap");
        assert!(error.contains("more than"));
    }

    fn write(path: &Path, content: &str) {
        fs::write(path, content).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    }

    fn mandate_export_fixture(path: &Path) {
        write(
            path,
            &format!("{{\"operator_github_handle\": \"{HANDLE}\"}}"),
        );
    }

    #[test]
    fn an_export_with_no_operator_handle_fails_the_check() {
        let codeowners = std::env::temp_dir().join(format!(
            "xtask-codeowners-valid3-{}.txt",
            std::process::id()
        ));
        write(&codeowners, &format!("{SELF_RULE}\n{MANDATE_RULE}\n"));
        let export = std::env::temp_dir().join(format!(
            "xtask-codeowners-export-no-handle-{}.json",
            std::process::id()
        ));
        write(&export, "{}");
        assert_eq!(check_codeowners_at(&codeowners, &export), 1);
        drop(fs::remove_file(&codeowners));
        drop(fs::remove_file(&export));
    }

    #[test]
    fn an_unreadable_codeowners_file_fails_the_check() {
        let missing = std::env::temp_dir().join(format!(
            "xtask-codeowners-missing-{}.txt",
            std::process::id()
        ));
        drop(fs::remove_file(&missing));
        let export = std::env::temp_dir().join(format!(
            "xtask-codeowners-export-unreadable-{}.json",
            std::process::id()
        ));
        mandate_export_fixture(&export);
        assert_eq!(check_codeowners_at(&missing, &export), 1);
        drop(fs::remove_file(&export));
    }

    #[test]
    fn a_blank_or_comment_only_codeowners_file_examines_zero_rules_and_fails() {
        let codeowners =
            std::env::temp_dir().join(format!("xtask-codeowners-empty-{}.txt", std::process::id()));
        write(&codeowners, "# nothing here\n\n");
        let export = std::env::temp_dir().join(format!(
            "xtask-codeowners-export-empty-{}.json",
            std::process::id()
        ));
        mandate_export_fixture(&export);
        assert_eq!(check_codeowners_at(&codeowners, &export), 1);
        drop(fs::remove_file(&codeowners));
        drop(fs::remove_file(&export));
    }

    #[test]
    fn a_valid_codeowners_file_against_the_real_export_path_shape_passes() {
        let codeowners =
            std::env::temp_dir().join(format!("xtask-codeowners-valid-{}.txt", std::process::id()));
        write(&codeowners, &format!("{SELF_RULE}\n{MANDATE_RULE}\n"));
        let export = std::env::temp_dir().join(format!(
            "xtask-codeowners-export-valid-{}.json",
            std::process::id()
        ));
        mandate_export_fixture(&export);
        assert_eq!(check_codeowners_at(&codeowners, &export), 0);
        drop(fs::remove_file(&codeowners));
        drop(fs::remove_file(&export));
    }

    #[test]
    fn an_unreadable_mandate_export_fails_the_check() {
        let codeowners = std::env::temp_dir().join(format!(
            "xtask-codeowners-valid2-{}.txt",
            std::process::id()
        ));
        write(&codeowners, &format!("{SELF_RULE}\n{MANDATE_RULE}\n"));
        let missing_export = std::env::temp_dir().join(format!(
            "xtask-codeowners-export-missing-{}.json",
            std::process::id()
        ));
        drop(fs::remove_file(&missing_export));
        assert_eq!(check_codeowners_at(&codeowners, &missing_export), 1);
        drop(fs::remove_file(&codeowners));
    }
}

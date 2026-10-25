//! `check-codeowners`: `.github/CODEOWNERS` gates `docs/mandate.md` behind the operator's
//! review and nothing else. GitHub applies the last rule that matches a path and drops an
//! owner token that does not start with `@`, so a rule a later line can override, or an
//! owner GitHub silently ignores, reads as "no review required" even with a rule present.

use std::fs;
use std::path::Path;

use serde_json::Value;

const CODEOWNERS_PATH: &str = ".github/CODEOWNERS";
const MANDATE_PATH: &str = "docs/mandate.md";
const MANDATE_EXPORT_PATH: &str = "config/export/mandate.json";

/// One non-comment, non-blank line: a path pattern and the owner tokens after it, exactly as
/// written, so a token missing its leading `@` is kept rather than dropped here.
struct Rule {
    pattern: String,
    owners: Vec<String>,
}

fn rules(text: &str) -> Vec<Rule> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pattern = fields.next()?.to_string();
            let owners = fields.map(str::to_string).collect();
            Some(Rule { pattern, owners })
        })
        .collect()
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

/// Defects in a rule list; an empty list has none, since the caller treats zero rules as its
/// own failure before examining any content. GitHub applies the last rule that matches a
/// path, so the mandate's rule must be the file's own last rule: anything after it, whether
/// or not it names `docs/mandate.md` itself, could be the one GitHub actually applies. Past
/// that, every owner token must carry its `@` (GitHub drops one that does not, which can
/// leave a rule with no owner it recognises), and the recognised owners must be exactly the
/// configured handle: no owner, an unmarked one, or an extra one all weaken the requirement.
fn mandate_defects(rules: &[Rule], operator_handle: &str) -> Vec<String> {
    let Some(last) = rules.last() else {
        return Vec::new();
    };
    let Some(mandate_rule) = rules.iter().rev().find(|rule| rule.pattern == MANDATE_PATH) else {
        return vec![format!(
            "{CODEOWNERS_PATH} names no rule for {MANDATE_PATH}"
        )];
    };
    if !std::ptr::eq(mandate_rule, last) {
        return vec![format!(
            "{CODEOWNERS_PATH}: a rule after the one for {MANDATE_PATH} can change what GitHub applies to it; the mandate's rule must be the file's last rule"
        )];
    }
    let owners = &mandate_rule.owners;
    let recognised: Vec<&str> = owners
        .iter()
        .filter_map(|owner| owner.strip_prefix('@'))
        .collect();
    if owners.len() != recognised.len() {
        return vec![format!(
            "{CODEOWNERS_PATH} names an owner for {MANDATE_PATH} with no leading @, which GitHub drops"
        )];
    }
    if recognised != [operator_handle] {
        return vec![format!(
            "{CODEOWNERS_PATH} must name exactly @{operator_handle} for {MANDATE_PATH}, found {recognised:?}"
        )];
    }
    Vec::new()
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
    let rule_list = rules(&text);
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

    #[test]
    fn a_mandate_rule_with_the_operators_handle_as_its_only_last_rule_passes() {
        let text =
            "# the mandate changes only with the operator's review\ndocs/mandate.md @frits-v\n";
        let defects = mandate_defects(&rules(text), HANDLE);
        assert_eq!(defects, Vec::<String>::new());
    }

    #[test]
    fn a_file_with_no_mandate_rule_is_a_defect() {
        let defects = mandate_defects(&rules("docs/other.md @frits-v\n"), HANDLE);
        assert_eq!(
            defects,
            vec![format!(
                "{CODEOWNERS_PATH} names no rule for {MANDATE_PATH}"
            )]
        );
    }

    // The five shapes GitHub's "last match wins" and "an owner needs its @" rules let through
    // a naive "there is a rule with an owner" check: each must be a defect.

    #[test]
    fn a_trailing_bare_star_after_the_mandate_rule_overrides_it_and_is_a_defect() {
        let text = "docs/mandate.md @frits-v\n*\n";
        let defects = mandate_defects(&rules(text), HANDLE);
        assert_eq!(defects.len(), 1);
        assert!(defects[0].contains("must be the file's last rule"));
    }

    #[test]
    fn a_later_duplicate_mandate_rule_with_no_owner_wins_and_is_a_defect() {
        let text = "docs/mandate.md @frits-v\ndocs/mandate.md\n";
        let defects = mandate_defects(&rules(text), HANDLE);
        assert_eq!(defects.len(), 1);
        assert!(defects[0].contains(MANDATE_PATH));
    }

    #[test]
    fn an_owner_missing_its_leading_at_sign_is_a_defect() {
        let defects = mandate_defects(&rules("docs/mandate.md frits-v\n"), HANDLE);
        assert_eq!(defects.len(), 1);
        assert!(defects[0].contains("no leading @"));
    }

    #[test]
    fn a_later_broader_rule_with_a_different_owner_overrides_the_mandate_rule_and_is_a_defect() {
        let text = "docs/mandate.md @frits-v\ndocs/ @someone-else\n";
        let defects = mandate_defects(&rules(text), HANDLE);
        assert_eq!(defects.len(), 1);
        assert!(defects[0].contains("must be the file's last rule"));
    }

    #[test]
    fn an_extra_owner_beside_the_operator_is_a_defect() {
        let defects = mandate_defects(&rules("docs/mandate.md @frits-v @someone-else\n"), HANDLE);
        assert_eq!(defects.len(), 1);
        assert!(defects[0].contains("must name exactly @frits-v"));
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
        write(&codeowners, "docs/mandate.md @frits-v\n");
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
        write(&codeowners, "docs/mandate.md @frits-v\n");
        let missing_export = std::env::temp_dir().join(format!(
            "xtask-codeowners-export-missing-{}.json",
            std::process::id()
        ));
        drop(fs::remove_file(&missing_export));
        assert_eq!(check_codeowners_at(&codeowners, &missing_export), 1);
        drop(fs::remove_file(&codeowners));
    }
}

//! `check-codeowners`: `.github/CODEOWNERS` names at least one owner for the mandate, so a
//! change to it is never one line away from silently dropping required code-owner review.

use std::fs;

const CODEOWNERS_PATH: &str = ".github/CODEOWNERS";
const MANDATE_PATH: &str = "docs/mandate.md";

/// One non-comment, non-blank line: a path pattern and the owners after it.
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

/// The rule count and any defects: no rule for the mandate, or one with no owner, both read
/// as "no code-owner review required" by GitHub.
fn codeowners_defects(text: &str) -> (usize, Vec<String>) {
    let rules = rules(text);
    if rules.is_empty() {
        return (0, Vec::new());
    }
    let mandate_rule = rules.iter().find(|rule| rule.pattern == MANDATE_PATH);
    let defects = match mandate_rule {
        None => vec![format!(
            "{CODEOWNERS_PATH} names no rule for {MANDATE_PATH}"
        )],
        Some(rule) if rule.owners.is_empty() => vec![format!(
            "{CODEOWNERS_PATH} names {MANDATE_PATH} with no owner, which requires no review"
        )],
        Some(_) => Vec::new(),
    };
    (rules.len(), defects)
}

pub fn check_codeowners() -> i32 {
    let text = match fs::read_to_string(CODEOWNERS_PATH) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("xtask check-codeowners: cannot read {CODEOWNERS_PATH}: {error}");
            return 1;
        }
    };
    let (examined, defects) = codeowners_defects(&text);
    if examined == 0 {
        eprintln!(
            "xtask check-codeowners: examined 0 rules in {CODEOWNERS_PATH}; a check over nothing is a failure"
        );
        return 1;
    }
    if defects.is_empty() {
        println!("xtask check-codeowners: examined {examined} rules, no defects");
        return 0;
    }
    eprintln!(
        "xtask check-codeowners: examined {examined} rules, {} defects",
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

    #[test]
    fn a_mandate_rule_with_an_owner_is_the_only_rule_examined_and_passes() {
        let text =
            "# the mandate changes only with the operator's review\ndocs/mandate.md @frits-v\n";
        let (examined, defects) = codeowners_defects(text);
        assert_eq!(examined, 1);
        assert_eq!(defects, Vec::<String>::new());
    }

    #[test]
    fn a_file_with_no_mandate_rule_is_a_defect() {
        let text = "docs/other.md @frits-v\n";
        let (examined, defects) = codeowners_defects(text);
        assert_eq!(examined, 1);
        assert_eq!(
            defects,
            vec![format!(
                "{CODEOWNERS_PATH} names no rule for {MANDATE_PATH}"
            )]
        );
    }

    #[test]
    fn a_mandate_rule_with_no_owner_is_a_defect_not_silent_approval() {
        let text = "docs/mandate.md\n";
        let (examined, defects) = codeowners_defects(text);
        assert_eq!(examined, 1);
        assert_eq!(
            defects,
            vec![format!(
                "{CODEOWNERS_PATH} names {MANDATE_PATH} with no owner, which requires no review"
            )]
        );
    }

    #[test]
    fn a_blank_or_comment_only_file_examines_zero_rules() {
        let (examined, defects) = codeowners_defects("# nothing here\n\n");
        assert_eq!(examined, 0);
        assert_eq!(defects, Vec::<String>::new());
    }
}

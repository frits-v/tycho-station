//! `check-ledger`: every function a ledger row names as its enforcement exists in the sources.
//!
//! A name is a backticked span whose last `::` segment is snake case, longer than twelve
//! characters and holds an underscore, taken when the span is a Rust path (every segment snake
//! case, not starting with `std`) or, bare, when it holds at least three underscores. Test
//! names here read as sentences of four words or more; a bare span with fewer is in practice a
//! wire value, a lint, a GitHub event or a token claim, which names nothing in the sources. A
//! name resolves to a `fn` or `mod` of that name, or a `.rs` file of that stem, under `crates/`
//! or `xtask/`. A name the ledger cites that lives outside the repository, or that a row names
//! because it was deleted, is listed with its reason in `notes/ledger-names-elsewhere.txt`; an
//! entry there that no row cites, or that the sources define, is itself a defect.

use std::collections::BTreeSet;
use std::path::Path;

use crate::sarif::Finding;

pub const LEDGER: &str = "notes/ledger.md";
pub const ELSEWHERE: &str = "notes/ledger-names-elsewhere.txt";
/// Files larger than this are refused rather than read in part.
pub const LEDGER_MAX_BYTES: u64 = 1024 * 1024;
const NAME_MIN_CHARS: usize = 13;
const BARE_UNDERSCORES_MIN: usize = 3;

fn snake(word: &str) -> bool {
    let mut characters = word.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && characters.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The name a backticked span cites, if it cites one.
#[must_use]
pub fn cited_name(span: &str) -> Option<&str> {
    let segments: Vec<&str> = span.split("::").collect();
    let (last, path) = segments.split_last()?;
    if !snake(last) || last.len() < NAME_MIN_CHARS || !last.contains('_') {
        return None;
    }
    let taken = if path.is_empty() {
        last.matches('_').count() >= BARE_UNDERSCORES_MIN
    } else {
        path.first() != Some(&"std") && path.iter().all(|segment| snake(segment))
    };
    taken.then_some(last)
}

/// Every cited name with the line it is on, in order.
#[must_use]
pub fn cited_names(ledger: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (index, line) in ledger.lines().enumerate() {
        for (position, span) in line.split('`').enumerate() {
            if position % 2 == 1 {
                if let Some(name) = cited_name(span) {
                    found.push((index.saturating_add(1), name.to_string()));
                }
            }
        }
    }
    found
}

/// The `fn` and `mod` names a Rust source defines.
#[must_use]
pub fn defined_names(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in source.lines() {
        let words: Vec<&str> = line
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|word| !word.is_empty())
            .collect();
        for pair in words.windows(2) {
            if let [keyword, name] = pair {
                if *keyword == "fn" || *keyword == "mod" {
                    names.insert((*name).to_string());
                }
            }
        }
    }
    names
}

/// The names `notes/ledger-names-elsewhere.txt` lists, one per line before `#`.
#[must_use]
pub fn elsewhere_names(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let name = line.split('#').next().unwrap_or("").trim();
            (!name.is_empty()).then(|| (index.saturating_add(1), name.to_string()))
        })
        .collect()
}

/// The defects: cited names nothing defines and the list does not hold, and listed names
/// that no row cites or that the sources define.
#[must_use]
pub fn ledger_defects(
    cited: &[(usize, String)],
    defined: &BTreeSet<String>,
    elsewhere: &[(usize, String)],
) -> Vec<Finding> {
    let listed: BTreeSet<&str> = elsewhere.iter().map(|(_, name)| name.as_str()).collect();
    let mut defects: Vec<Finding> = cited
        .iter()
        .filter(|(_, name)| !defined.contains(name) && !listed.contains(name.as_str()))
        .map(|(line, name)| {
            Finding::at(
                Path::new(LEDGER),
                *line,
                1,
                "check-ledger/undefined",
                format!("`{name}` is cited as enforcement, but no fn, mod or file defines it"),
            )
        })
        .collect();
    let cited_set: BTreeSet<&str> = cited.iter().map(|(_, name)| name.as_str()).collect();
    for (line, name) in elsewhere {
        let why = if !cited_set.contains(name.as_str()) {
            Some("no ledger row cites it")
        } else if defined.contains(name) {
            Some("the sources define it")
        } else {
            None
        };
        if let Some(why) = why {
            defects.push(Finding::at(
                Path::new(ELSEWHERE),
                *line,
                1,
                "check-ledger/stale-exception",
                format!("`{name}` is listed as defined elsewhere, but {why}"),
            ));
        }
    }
    defects
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_span_is_a_name_only_as_a_rust_path_or_a_long_bare_identifier() {
        assert_eq!(
            cited_name("zmx::tests::a_link_at_the_log_is_replaced"),
            Some("a_link_at_the_log_is_replaced")
        );
        assert_eq!(cited_name("kill::deliver_through"), Some("deliver_through"));
        assert_eq!(
            cited_name("the_rule_is_present_only_when_exact"),
            Some("the_rule_is_present_only_when_exact")
        );
        for not_a_name in [
            "vendor_login_required",
            "ready_for_review",
            "std::fs::remove_dir_all",
            "crates/tycho/tests/boundary.rs",
            "env_keep = \"HOME\"",
            "Zmx::agent",
            "TOKEN_LIFETIME_MIN",
            "short_name",
            "Defaults>root !authenticate",
            "zmx::Zmx::from_agent_side",
        ] {
            assert_eq!(cited_name(not_a_name), None, "{not_a_name}");
        }
    }

    #[test]
    fn a_cited_name_nothing_defines_is_a_defect_and_a_defined_one_is_not() {
        let ledger = "| Date | Rule | Enforced by |\n|---|---|---|\n| 2026-10-15 | A rule. | `zmx::tests::a_real_test_that_exists`, `a_missing_test_name_is_here` |\n";
        let cited = cited_names(ledger);
        assert_eq!(
            cited,
            [
                (3, "a_real_test_that_exists".to_string()),
                (3, "a_missing_test_name_is_here".to_string()),
            ]
        );
        let defined =
            defined_names("#[test]\nfn a_real_test_that_exists() {}\nmod other_module {}\n");
        let defects = ledger_defects(&cited, &defined, &[]);
        assert_eq!(defects.len(), 1, "{defects:?}");
        assert!(defects[0].message.contains("a_missing_test_name_is_here"));
        assert_eq!(defects[0].line, 3);
    }

    #[test]
    fn a_listed_exception_covers_a_name_and_a_stale_one_is_a_defect() {
        let cited = vec![(3, "a_hook_function_in_python".to_string())];
        let defined = defined_names("fn defined_elsewhere_too() {}\n");
        let listed = elsewhere_names(
            "a_hook_function_in_python  # in a script outside the repository\n\n# a comment\nno_longer_cited_anywhere # gone\ndefined_elsewhere_too # now defined\n",
        );
        let defects = ledger_defects(&cited, &defined, &listed);
        let messages: Vec<&str> = defects
            .iter()
            .map(|defect| defect.message.as_str())
            .collect();
        assert_eq!(defects.len(), 2, "{messages:?}");
        assert!(
            messages[0].contains("no_longer_cited_anywhere")
                && messages[0].contains("no ledger row")
        );
        assert!(messages[1].contains("defined_elsewhere_too"));
    }

    #[test]
    fn the_committed_ledger_yields_its_cited_names() {
        let ledger = std::fs::read_to_string(crate::setup::workspace_root().join(LEDGER)).unwrap();
        assert!(cited_names(&ledger).len() > 100);
    }
}

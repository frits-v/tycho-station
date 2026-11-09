use super::*;

const HEADER: &str = "| Date | Rule | Enforced by |\n|---|---|---|\n";
const DIGEST_HEADER: &str =
    "# Ledger\n\nOne row per rule.\n\n| Date | Rule | Enforced by | Archive |\n|---|---|---|---|\n";

fn source(path: &str, text: &str) -> Source {
    Source {
        path: path.to_string(),
        text: text.to_string(),
    }
}

fn archive(month: &str, rows: &str) -> Source {
    source(
        &format!("notes/ledger/{month}.md"),
        &format!("# Ledger, {month}\n\n{HEADER}{rows}"),
    )
}

fn digest(rows: &str, months: &[&str]) -> Source {
    let definitions: String = months
        .iter()
        .map(|month| format!("[{month}]: ledger/{month}.md\n"))
        .collect::<Vec<_>>()
        .concat();
    source(LEDGER, &format!("{DIGEST_HEADER}{rows}\n{definitions}"))
}

fn rules_of(defects: &[Finding]) -> Vec<(&str, &str)> {
    defects
        .iter()
        .map(|defect| (defect.rule.as_str(), defect.message.as_str()))
        .collect()
}

const OCTOBER: &str = "| 2026-10-09 | A test of a kill path fails when the kill does not run. | `kill` tests |\n| 2026-10-12 | A test that spawns git removes the hook environment: it set `core.bare`. | `git_environment` |\n";

#[test]
fn a_digest_that_links_every_archive_row_once_has_no_defects() {
    let rows = "| 2026-10-09 | A kill-path test fails without the kill. | `kill` tests | [A test of a][2026-10] |\n| 2026-10-12 | Git spawns drop the hook environment. | `git_environment` | [A test that spawns][2026-10] |\n";
    let (defects, examined) =
        pairing_defects(&digest(rows, &["2026-10"]), &[archive("2026-10", OCTOBER)]);
    assert!(defects.is_empty(), "{:?}", rules_of(&defects));
    assert_eq!(
        examined.iter().map(|file| file.rows).collect::<Vec<_>>(),
        [2, 2]
    );
}

#[test]
fn an_archive_row_no_digest_row_links_is_a_defect() {
    let rows = "| 2026-10-09 | A kill-path test fails without the kill. | `kill` tests | [A test of a][2026-10] |\n";
    let (defects, _) = pairing_defects(&digest(rows, &["2026-10"]), &[archive("2026-10", OCTOBER)]);
    assert_eq!(defects.len(), 1, "{:?}", rules_of(&defects));
    assert_eq!(defects[0].rule, "check-ledger/unlinked");
    assert_eq!(defects[0].path, "notes/ledger/2026-10.md");
    assert_eq!(defects[0].line, 6);
}

#[test]
fn a_link_whose_archive_row_is_missing_is_a_defect() {
    let rows = "| 2026-10-09 | A kill-path test fails without the kill. | `kill` tests | [A test of a][2026-10] |\n| 2026-10-12 | Git spawns drop the hook environment. | `git_environment` | [A test that spawns][2026-10] |\n| 2026-10-13 | A row whose full row was never archived. | none | [A row never archived][2026-10] |\n";
    let (defects, _) = pairing_defects(&digest(rows, &["2026-10"]), &[archive("2026-10", OCTOBER)]);
    assert_eq!(rules_of(&defects).len(), 1, "{:?}", rules_of(&defects));
    assert_eq!(defects[0].rule, "check-ledger/link");
    assert!(defects[0].message.contains("opens no row"));
    assert_eq!(defects[0].line, 9);
}

#[test]
fn a_digest_row_with_no_archive_link_or_an_unknown_month_is_a_defect() {
    let rows = "| 2026-10-09 | A kill-path test fails without the kill. | `kill` tests | [A test of a][2026-10] |\n| 2026-10-12 | Git spawns drop the hook environment. | `git_environment` | [A test that spawns][2026-10] |\n| 2026-10-13 | A row with no archive. | none |  |\n";
    let (defects, _) = pairing_defects(&digest(rows, &["2026-10"]), &[archive("2026-10", OCTOBER)]);
    assert_eq!(defects.len(), 1, "{:?}", rules_of(&defects));
    assert!(defects[0].message.contains("links no archive row"));

    let rows = "| 2026-10-09 | A kill-path test fails without the kill. | `kill` tests | [A test of a][2026-09] |\n| 2026-10-12 | Git spawns drop the hook environment. | `git_environment` | [A test that spawns][2026-10] |\n";
    let (defects, _) = pairing_defects(&digest(rows, &["2026-10"]), &[archive("2026-10", OCTOBER)]);
    let found = rules_of(&defects);
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found[0].1.contains("names no archive file"));
    assert_eq!(found[1].0, "check-ledger/unlinked");
}

#[test]
fn a_digest_over_its_bound_is_a_defect() {
    let rows = "| 2026-10-09 | A kill-path test fails without the kill. | `kill` tests | [A test of a][2026-10] |\n| 2026-10-12 | Git spawns drop the hook environment. | `git_environment` | [A test that spawns][2026-10] |\n";
    let mut over = digest(rows, &["2026-10"]);
    let padding = DIGEST_MAX_BYTES
        .saturating_sub(over.text.len())
        .saturating_add(1);
    over.text.push_str(&"x".repeat(padding));
    let (defects, _) = pairing_defects(&over, &[archive("2026-10", OCTOBER)]);
    assert_eq!(defects.len(), 1, "{:?}", rules_of(&defects));
    assert_eq!(defects[0].rule, "check-ledger/size");

    let mut at = digest(rows, &["2026-10"]);
    at.text.push_str(&"x".repeat(padding.saturating_sub(1)));
    assert_eq!(at.text.len(), DIGEST_MAX_BYTES);
    assert!(
        pairing_defects(&at, &[archive("2026-10", OCTOBER)])
            .0
            .is_empty()
    );
}

#[test]
fn a_link_that_opens_several_rows_another_date_or_a_row_twice_is_a_defect() {
    let rows = "| 2026-10-09 | Kill-path tests. | `kill` tests | [A test][2026-10] |\n";
    let (defects, _) = pairing_defects(&digest(rows, &["2026-10"]), &[archive("2026-10", OCTOBER)]);
    assert!(
        rules_of(&defects)[0].1.contains("opens 2 rows"),
        "{:?}",
        rules_of(&defects)
    );

    let rows = "| 2026-10-12 | A kill-path test fails without the kill. | `kill` tests | [A test of a][2026-10] |\n| 2026-10-12 | Git spawns drop the hook environment. | `git_environment` | [A test that spawns][2026-10] |\n";
    let (defects, _) = pairing_defects(&digest(rows, &["2026-10"]), &[archive("2026-10", OCTOBER)]);
    assert_eq!(defects.len(), 1, "{:?}", rules_of(&defects));
    assert!(
        defects[0]
            .message
            .contains("dated 2026-10-12 but its first link opens a row dated 2026-10-09")
    );

    let rows = "| 2026-10-09 | A kill-path test fails without the kill. | `kill` tests | [A test of a][2026-10] |\n| 2026-10-12 | Git spawns drop the hook environment. | `git_environment` | [A test that spawns][2026-10], [A test of a kill][2026-10] |\n";
    let (defects, _) = pairing_defects(&digest(rows, &["2026-10"]), &[archive("2026-10", OCTOBER)]);
    assert_eq!(defects.len(), 1, "{:?}", rules_of(&defects));
    assert!(
        defects[0]
            .message
            .contains("linked from digest lines [7, 8]")
    );
}

#[test]
fn a_digest_row_may_link_rows_of_two_months() {
    let november = "| 2026-11-02 | A kill test fails when nothing was killed. | `kill` tests |\n";
    let rows = "| 2026-10-09 | A kill-path test fails without the kill. | `kill` tests | [A test of a][2026-10], [A kill test][2026-11] |\n| 2026-10-12 | Git spawns drop the hook environment. | `git_environment` | [A test that spawns][2026-10] |\n";
    let (defects, examined) = pairing_defects(
        &digest(rows, &["2026-10", "2026-11"]),
        &[archive("2026-10", OCTOBER), archive("2026-11", november)],
    );
    assert!(defects.is_empty(), "{:?}", rules_of(&defects));
    assert_eq!(examined.len(), 3);
}

#[test]
fn a_link_matches_only_at_a_word_boundary() {
    assert!(opens("A test of a kill path", "A test of a"));
    assert!(opens("A test, then", "A test"));
    assert!(opens("`xtask ci` runs", "`xtask ci`"));
    assert!(!opens("A tester runs", "A test"));
    assert!(!opens("A test_name runs", "A test"));
    assert!(!opens("Another test", "A test"));
}

#[test]
fn table_lines_and_archive_cells_decode_to_their_states_and_reject_the_rest() {
    assert_eq!(table_line(0, "# Ledger", 3), TableLine::Outside);
    assert_eq!(
        table_line(0, "| Date | Rule | Enforced by |", 3),
        TableLine::Header
    );
    assert_eq!(table_line(0, "|---|---|---|", 3), TableLine::Separator);
    assert!(matches!(
        table_line(4, "| 2026-10-09 | A rule. | none |", 3),
        TableLine::Row(Row {
            line: 5,
            date: "2026-10-09",
            ..
        })
    ));
    for unrecognised in [
        "| 2026-10-09 | A rule. | none | extra |",
        "| 2026-10-09 | A rule. |",
        "| 26-10-09 | A rule. | none |",
        "| 2026-10-09 | A rule. | none",
        "|",
    ] {
        assert_eq!(
            table_line(0, unrecognised, 3),
            TableLine::Unrecognised,
            "{unrecognised}"
        );
    }
    assert_eq!(
        links("[A rule][2026-10], [B rule][2026-11]"),
        Some(vec![
            Link {
                text: "A rule",
                month: "2026-10"
            },
            Link {
                text: "B rule",
                month: "2026-11"
            },
        ])
    );
    assert_eq!(links(""), Some(vec![]));
    for malformed in [
        "A rule",
        "[A rule](ledger/2026-10.md)",
        "[A rule][2026-10] [B][2026-10]",
        "[][2026-10]",
    ] {
        assert_eq!(links(malformed), None, "{malformed}");
    }
    assert_eq!(archive_month("notes/ledger/2026-10.md"), Some("2026-10"));
    for not_a_month in [
        "notes/ledger/README.md",
        "notes/ledger/2026-1.md",
        "notes/ledger/2026-10.txt",
    ] {
        assert_eq!(archive_month(not_a_month), None, "{not_a_month}");
    }
}

#[test]
fn a_misnamed_archive_a_misdated_row_and_a_bad_definition_are_shape_defects() {
    let rows = "| 2026-10-09 | A kill-path test fails without the kill. | `kill` tests | [A test of a][2026-10] |\n| 2026-10-12 | Git spawns drop the hook environment. | `git_environment` | [A test that spawns][2026-10] |\n";
    let mut misdated = OCTOBER.to_string();
    misdated.push_str("| 2026-11-01 | A row filed a month early. | none |\n");
    let mut wrong_target = digest(rows, &["2026-10"]);
    wrong_target.text = wrong_target
        .text
        .replace("]: ledger/2026-10.md", "]: ledger/2026-09.md");
    let (defects, _) = pairing_defects(
        &wrong_target,
        &[
            archive("2026-10", &misdated),
            source("notes/ledger/notes.md", HEADER),
        ],
    );
    let found = rules_of(&defects);
    assert!(
        found.iter().all(|(rule, _)| *rule != "check-ledger/size"),
        "{found:?}"
    );
    for expected in [
        "an archive file is named",
        "does not name an archive file",
        "no definition `[2026-10]: ledger/2026-10.md`",
        "a row dated 2026-11-01 in the 2026-10 archive",
    ] {
        assert!(
            found.iter().any(|(_, message)| message.contains(expected)),
            "{expected}: {found:?}"
        );
    }
}

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
    let ledger = source(
        LEDGER,
        "| Date | Rule | Enforced by |\n|---|---|---|\n| 2026-10-15 | A rule. | `zmx::tests::a_real_test_that_exists`, `a_missing_test_name_is_here` |\n",
    );
    let cited = cited_names(&ledger);
    assert_eq!(
        cited
            .iter()
            .map(|citation| (citation.line, citation.name.as_str()))
            .collect::<Vec<_>>(),
        [
            (3, "a_real_test_that_exists"),
            (3, "a_missing_test_name_is_here")
        ]
    );
    let defined = defined_names("#[test]\nfn a_real_test_that_exists() {}\nmod other_module {}\n");
    let defects = name_defects(&cited, &defined, &[]);
    assert_eq!(defects.len(), 1, "{defects:?}");
    assert!(defects[0].message.contains("a_missing_test_name_is_here"));
    assert_eq!(defects[0].line, 3);
}

#[test]
fn a_name_cited_only_in_an_archive_is_checked_there_and_keeps_its_exception() {
    let ledger = source(
        LEDGER,
        "| 2026-10-09 | A rule. | `kill` tests | [A test][2026-10] |\n",
    );
    let october = archive(
        "2026-10",
        "| 2026-10-09 | A test. | `kill::tests::an_archived_test_nobody_wrote`, `a_hook_function_kept_outside` |\n",
    );
    let cited: Vec<Citation> = [&ledger, &october]
        .into_iter()
        .flat_map(cited_names)
        .collect();
    let listed = elsewhere_names("a_hook_function_kept_outside  # outside the repository\n");
    let defects = name_defects(&cited, &BTreeSet::new(), &listed);
    assert_eq!(defects.len(), 1, "{defects:?}");
    assert_eq!(defects[0].rule, "check-ledger/undefined");
    assert_eq!(defects[0].path, "notes/ledger/2026-10.md");
    assert_eq!(defects[0].line, 5);
    assert!(defects[0].message.contains("an_archived_test_nobody_wrote"));
}

#[test]
fn a_listed_exception_covers_a_name_and_a_stale_one_is_a_defect() {
    let cited = vec![Citation {
        path: LEDGER.to_string(),
        line: 3,
        name: "a_hook_function_in_python".to_string(),
    }];
    let defined = defined_names("fn defined_elsewhere_too() {}\n");
    let listed = elsewhere_names(
        "a_hook_function_in_python  # in a script outside the repository\n\n# a comment\nno_longer_cited_anywhere # gone\ndefined_elsewhere_too # now defined\n",
    );
    let defects = name_defects(&cited, &defined, &listed);
    let messages: Vec<&str> = defects
        .iter()
        .map(|defect| defect.message.as_str())
        .collect();
    assert_eq!(defects.len(), 2, "{messages:?}");
    assert!(
        messages[0].contains("no_longer_cited_anywhere") && messages[0].contains("no ledger row")
    );
    assert!(messages[1].contains("defined_elsewhere_too"));
}

#[test]
fn the_committed_digest_links_every_archived_row_once_within_its_bound() {
    let (digest, archives, _) = read_sources(crate::setup::workspace_root()).unwrap();
    let (defects, examined) = pairing_defects(&digest, &archives);
    assert!(defects.is_empty(), "{:?}", rules_of(&defects));
    let rows_archived: usize = examined.iter().skip(1).map(|file| file.rows).sum();
    assert!(rows_archived > 100, "{examined:?}");
    assert!(citations(&digest, &archives).unwrap().len() > 100);
}

#[test]
fn a_digest_enforcement_name_no_linked_full_row_holds_is_a_defect() {
    let rows = "| 2026-10-09 | A kill-path test fails without the kill. | `kill`, `kill::renamed_away` | [A test of a][2026-10] |\n| 2026-10-12 | Git spawns drop the hook environment. | `kill` | [A test that spawns][2026-10] |\n";
    let (defects, _) = pairing_defects(&digest(rows, &["2026-10"]), &[archive("2026-10", OCTOBER)]);
    let found = rules_of(&defects);
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(
        found
            .iter()
            .all(|(rule, _)| *rule == "check-ledger/enforcement")
    );
    assert!(found[0].1.contains("`kill::renamed_away`"), "{found:?}");
    assert_eq!((defects[0].line, defects[1].line), (7, 8));
}

/// A scratch repository root holding the given ledger files; `remove_scratch` removes it.
fn scratch_root(name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("xtask-ledger-{}-{name}", std::process::id()));
    for dir in ["", "notes", ARCHIVE_DIR] {
        std::fs::create_dir(root.join(dir)).unwrap();
    }
    for (path, text) in files {
        std::fs::write(root.join(path), text).unwrap();
    }
    root
}

fn remove_scratch(root: &Path, files: &[(&str, &str)]) {
    for (path, _) in files {
        std::fs::remove_file(root.join(path)).unwrap();
    }
    for dir in [ARCHIVE_DIR, "notes", ""] {
        std::fs::remove_dir(root.join(dir)).unwrap();
    }
}

#[test]
fn no_archive_file_is_a_failure_not_a_clean_pass() {
    let files = [(LEDGER, "# Ledger\n"), (ELSEWHERE, "")];
    let root = scratch_root("no-archive", &files);
    let read = read_sources(&root);
    remove_scratch(&root, &files);
    let refusal = read.unwrap_err();
    assert!(refusal.contains("examined 0 archive files"), "{refusal}");
}

#[test]
fn ledger_files_that_cite_no_name_are_a_failure_not_a_clean_pass() {
    let files = [
        (
            LEDGER,
            "| 2026-10-09 | A rule. | `kill` | [A rule][2026-10] |\n",
        ),
        (
            "notes/ledger/2026-10.md",
            "| 2026-10-09 | A rule. | `kill` tests |\n",
        ),
        (ELSEWHERE, ""),
    ];
    let root = scratch_root("no-names", &files);
    let read = read_sources(&root);
    remove_scratch(&root, &files);
    let (digest, archives, _) = read.unwrap();
    assert_eq!(archives.len(), 1);
    let refusal = citations(&digest, &archives).unwrap_err();
    assert!(refusal.contains("examined 0 cited names"), "{refusal}");
}

#[test]
fn an_enforcement_name_counts_only_in_a_linked_enforced_by_cell_and_as_whole_segments() {
    let renamed = "| 2026-10-09 | A pid is a hint: the core runs `zmx kill` by name. | `terminate::tests::each_failed_check_is_its_own_refusal` |\n";
    let rows = "| 2026-10-09 | A pid is a hint. | `kill` tests | [A pid is][2026-10] |\n";
    let (defects, _) = pairing_defects(&digest(rows, &["2026-10"]), &[archive("2026-10", renamed)]);
    assert_eq!(defects.len(), 1, "{:?}", rules_of(&defects));
    assert_eq!(defects[0].rule, "check-ledger/enforcement");
    assert!(defects[0].message.contains("`kill`"));

    let kept = renamed.replace("terminate::", "kill::");
    let (defects, _) = pairing_defects(&digest(rows, &["2026-10"]), &[archive("2026-10", &kept)]);
    assert!(defects.is_empty(), "{:?}", rules_of(&defects));

    assert!(span_holds(
        "services::work_unit::ruling_promise",
        "work_unit::ruling_promise"
    ));
    assert!(span_holds("xtask check-rules", "xtask check-rules"));
    assert!(span_holds("kill::tests::a_name", "kill"));
    assert!(!span_holds("verification::tests::a_name", "verify"));
    assert!(!span_holds(
        "services::session::keep_proxy_audit",
        "session::keep"
    ));
    assert!(!span_holds("kill", "kill::tests"));
}

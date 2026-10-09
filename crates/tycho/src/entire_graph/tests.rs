use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use super::*;
use crate::code_graph::ChangeKind;

const VERSION_PINNED: &str = include_str!("../fixtures/entire-graph-version-pinned.json");
const VERSION_OTHER: &str = include_str!("../fixtures/entire-graph-version-other.json");
const DOCTOR: &str = include_str!("../fixtures/entire-graph-doctor.json");
const INDEX_BUILT: &str = include_str!("../fixtures/entire-graph-index-built.json");
const INDEX_CACHE_HIT: &str = include_str!("../fixtures/entire-graph-index-cache-hit.json");
const INDEX_NOT_A_REPOSITORY: &str =
    include_str!("../fixtures/entire-graph-index-not-a-repository.txt");
const DEF_FOUND: &str = include_str!("../fixtures/entire-graph-def-found.json");
const DEF_FUZZY: &str = include_str!("../fixtures/entire-graph-def-fuzzy.json");
const DEF_MANY: &str = include_str!("../fixtures/entire-graph-def-many.json");
const NEIGHBORS_FOUND: &str = include_str!("../fixtures/entire-graph-neighbors-found.json");
const NEIGHBORS_FUZZY: &str = include_str!("../fixtures/entire-graph-neighbors-fuzzy.json");
const NEIGHBORS_AMBIGUOUS: &str = include_str!("../fixtures/entire-graph-neighbors-ambiguous.json");
const DIFF_FOUND: &str = include_str!("../fixtures/entire-graph-diff-found.json");
const DIFF_EMPTY: &str = include_str!("../fixtures/entire-graph-diff-empty.json");
const DIFF_KINDS: &str = include_str!("../fixtures/entire-graph-diff-kinds.json");
const DIFF_BAD_REVISION: &str = include_str!("../fixtures/entire-graph-diff-bad-revision.txt");
const GARBAGE: [&str; 4] = ["", "not json", "[1, 2]", "{\"unexpected\": true}"];

fn captured(code: i32, stdout: &str) -> Result<Captured, CommandError> {
    let captured = Captured {
        status: ExitStatus::from_raw(code << 8),
        stdout: stdout.to_string(),
        stderr: String::new(),
    };
    if code < 0 {
        return Err(CommandError::NotUtf8(stdout.to_string()));
    }
    Ok(captured)
}

fn is_unrecognised<T>(decoded: &Decoded<T>) -> bool {
    matches!(decoded, Decoded::Unrecognised(_))
}

#[test]
fn version_pinned_sample_is_pinned() {
    assert_eq!(
        decode_version(&captured(0, VERSION_PINNED)),
        VersionState::Pinned
    );
}

#[test]
fn version_gate_refuses_a_different_version() {
    assert_eq!(
        decode_version(&captured(0, VERSION_OTHER)),
        VersionState::Other("v0.3.0".to_string())
    );
    let stub = std::env::temp_dir().join(format!("tycho-graph-stub-{}", std::process::id()));
    std::fs::write(
        &stub,
        format!("#!/bin/sh\nprintf '%s' '{}'\n", VERSION_OTHER.trim()),
    )
    .unwrap();
    std::fs::set_permissions(&stub, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let graph = EntireGraph::open(&stub, Path::new("/nonexistent"));
    std::fs::remove_file(&stub).unwrap();
    let Err(GraphError::VersionRefused(reason)) = graph else {
        panic!("a different version was accepted");
    };
    assert!(reason.contains("v0.3.0"), "{reason}");
}

#[test]
fn version_of_a_missing_binary_is_absent() {
    let result = command::run_status(
        Path::new("/nonexistent/entire-graph"),
        &["version", "--json"],
        &[],
        COMMAND_TIMEOUT,
    );
    assert_eq!(decode_version(&result), VersionState::Absent);
    let graph = EntireGraph::open(
        Path::new("/nonexistent/entire-graph"),
        Path::new("/nonexistent"),
    );
    assert!(matches!(graph, Err(GraphError::VersionRefused(_))));
}

#[test]
fn version_garbage_or_failure_is_unrecognised() {
    for garbage in GARBAGE
        .iter()
        .chain(&["{\"provider\":\"other\",\"version\":\"v0.4.0\"}"])
    {
        assert!(matches!(
            decode_version(&captured(0, garbage)),
            VersionState::Unrecognised(_)
        ));
    }
    assert!(matches!(
        decode_version(&captured(1, VERSION_PINNED)),
        VersionState::Unrecognised(_)
    ));
    assert!(matches!(
        decode_version(&captured(-1, "")),
        VersionState::Unrecognised(_)
    ));
}

#[test]
fn doctor_sample_reports_no_egress() {
    assert_eq!(decode_doctor(DOCTOR), EgressState::NoEgress);
}

#[test]
fn doctor_with_a_remote_capability_is_egress() {
    let remote = DOCTOR.replace("\"upload_telemetry\":false", "\"upload_telemetry\":true");
    assert_eq!(
        decode_doctor(&remote),
        EgressState::Egress("upload_telemetry".to_string())
    );
    let flag_off = DOCTOR.replace("\"no_egress\":true", "\"no_egress\":false");
    assert!(matches!(decode_doctor(&flag_off), EgressState::Egress(_)));
}

#[test]
fn doctor_garbage_is_unrecognised() {
    let empty = "{\"no_egress\":true,\"phase_1_local_only\":{}}";
    for garbage in GARBAGE.iter().chain(&[empty]) {
        assert!(matches!(
            decode_doctor(garbage),
            EgressState::Unrecognised(_)
        ));
    }
}

#[test]
fn index_cold_sample_is_built() {
    let IndexOutcome::Built(summary) = decode_index(true, INDEX_BUILT, "") else {
        panic!("not built");
    };
    assert!(!summary.cache_hit);
    assert_eq!(summary.latency_ms, 708);
    assert_eq!(summary.commit, "d6d29b11631c2a2e8d29e50490fed10f1558b73e");
    assert_eq!(summary.counts.files, 45);
    assert_eq!(summary.counts.symbols, 810);
    assert_eq!(summary.counts.relations, 2478);
    assert_eq!(summary.completeness, Completeness::Complete);
}

#[test]
fn index_warm_sample_is_a_cache_hit() {
    let IndexOutcome::Built(summary) = decode_index(true, INDEX_CACHE_HIT, "") else {
        panic!("not built");
    };
    assert!(summary.cache_hit);
}

#[test]
fn index_degraded_level_is_decoded() {
    let degraded = INDEX_BUILT.replace(
        "\"completeness_level\":\"ok\"",
        "\"completeness_level\":\"degraded\"",
    );
    let IndexOutcome::Built(summary) = decode_index(true, &degraded, "") else {
        panic!("not built");
    };
    assert_eq!(summary.completeness, Completeness::Degraded);
}

#[test]
fn index_with_no_files_is_empty_not_built() {
    let empty = INDEX_BUILT
        .replace("\"files\":45", "\"files\":0")
        .replace("\"symbols\":810", "\"symbols\":0");
    assert_eq!(decode_index(true, &empty, ""), IndexOutcome::Empty);
}

#[test]
fn index_from_another_version_is_unrecognised() {
    let other = INDEX_BUILT.replace(
        "\"provider_version\":\"v0.4.0\"",
        "\"provider_version\":\"v0.5.0\"",
    );
    assert!(matches!(
        decode_index(true, &other, ""),
        IndexOutcome::Unrecognised(_)
    ));
    let unknown_level = INDEX_BUILT.replace(
        "\"completeness_level\":\"ok\"",
        "\"completeness_level\":\"meh\"",
    );
    assert!(matches!(
        decode_index(true, &unknown_level, ""),
        IndexOutcome::Unrecognised(_)
    ));
}

#[test]
fn index_outside_a_repository_is_not_a_repository() {
    assert!(matches!(
        decode_index(false, "", INDEX_NOT_A_REPOSITORY),
        IndexOutcome::NotARepository(_)
    ));
    assert!(matches!(
        decode_index(false, "", "boom"),
        IndexOutcome::Failed(_)
    ));
}

#[test]
fn index_garbage_is_unrecognised() {
    for garbage in GARBAGE {
        assert!(matches!(
            decode_index(true, garbage, ""),
            IndexOutcome::Unrecognised(_)
        ));
    }
}

#[test]
fn def_sample_is_found() {
    let Decoded::Answer {
        answer,
        revisions,
        index_cache_hit,
    } = decode_definitions(true, DEF_FOUND, "")
    else {
        panic!("no answer");
    };
    assert_eq!(index_cache_hit, Some(false));
    assert_eq!(
        revisions,
        Revisions::Commit("d6d29b11631c2a2e8d29e50490fed10f1558b73e".to_string())
    );
    assert_eq!(
        answer,
        Definitions::Found {
            declarations: vec![Location {
                qualified_name: "run_bounded".to_string(),
                kind: "function".to_string(),
                file_path: "crates/tycho/src/watchdog.rs".to_string(),
                line: 273,
            }],
            truncated: false,
        }
    );
}

#[test]
fn def_fuzzy_sample_is_not_found() {
    let Decoded::Answer { answer, .. } = decode_definitions(true, DEF_FUZZY, "") else {
        panic!("no answer");
    };
    let Definitions::NotFound { nearest } = answer else {
        panic!("a fuzzy match decoded as found");
    };
    assert_eq!(nearest.len(), 1);
}

#[test]
fn def_many_sample_is_found_and_truncated() {
    let Decoded::Answer { answer, .. } = decode_definitions(true, DEF_MANY, "") else {
        panic!("no answer");
    };
    let Definitions::Found {
        declarations,
        truncated,
    } = answer
    else {
        panic!("not found");
    };
    assert_eq!(declarations.len(), 4);
    assert!(truncated);
}

#[test]
fn def_over_the_result_bound_is_too_many() {
    let mut value: Value = serde_json::from_str(DEF_FOUND).unwrap();
    let declaration = value["declarations"][0].clone();
    value["declarations"] = Value::Array(vec![declaration; GRAPH_RESULTS_MAX_ITEMS + 1]);
    assert_eq!(
        decode_definitions(true, &value.to_string(), ""),
        Decoded::TooMany(GRAPH_RESULTS_MAX_ITEMS + 1)
    );
}

#[test]
fn def_garbage_or_failure_is_not_an_answer() {
    for garbage in GARBAGE {
        assert!(is_unrecognised(&decode_definitions(true, garbage, "")));
    }
    assert!(matches!(
        decode_definitions(false, "", "boom"),
        Decoded::Failed(_)
    ));
}

#[test]
fn neighbors_sample_is_found() {
    let Decoded::Answer { answer, .. } = decode_callers(true, NEIGHBORS_FOUND, "") else {
        panic!("no answer");
    };
    let Callers::Found { callers, truncated } = answer else {
        panic!("not found");
    };
    assert!(!truncated);
    let names: Vec<&str> = callers
        .iter()
        .map(|caller| caller.qualified_name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "the_loop_stops_at_its_bound",
            "the_loop_stops_on_the_stop_file",
            "run_watchdog"
        ]
    );
}

#[test]
fn neighbors_fuzzy_sample_is_not_found() {
    let Decoded::Answer { answer, .. } = decode_callers(true, NEIGHBORS_FUZZY, "") else {
        panic!("no answer");
    };
    assert!(matches!(answer, Callers::NotFound { .. }));
}

#[test]
fn neighbors_ambiguous_sample_is_ambiguous() {
    let Decoded::Answer { answer, .. } = decode_callers(true, NEIGHBORS_AMBIGUOUS, "") else {
        panic!("no answer");
    };
    let Callers::Ambiguous { candidates } = answer else {
        panic!("not ambiguous");
    };
    assert_eq!(candidates.len(), 9);
}

#[test]
fn neighbors_over_the_result_bound_is_rejected() {
    let mut value: Value = serde_json::from_str(NEIGHBORS_FOUND).unwrap();
    let caller = value["matches"][0]["incoming"][0].clone();
    value["matches"][0]["incoming"] = Value::Array(vec![caller; GRAPH_RESULTS_MAX_ITEMS + 1]);
    assert!(is_unrecognised(&decode_callers(
        true,
        &value.to_string(),
        ""
    )));
    let focus = value["matches"][0].clone();
    value["matches"] = Value::Array(vec![focus; GRAPH_RESULTS_MAX_ITEMS + 1]);
    assert_eq!(
        decode_callers(true, &value.to_string(), ""),
        Decoded::TooMany(GRAPH_RESULTS_MAX_ITEMS + 1)
    );
}

#[test]
fn neighbors_garbage_is_unrecognised() {
    for garbage in GARBAGE {
        assert!(is_unrecognised(&decode_callers(true, garbage, "")));
    }
    let unflagged = NEIGHBORS_AMBIGUOUS.replace("\"disambiguation_required\":true", "\"x\":1");
    assert!(is_unrecognised(&decode_callers(true, &unflagged, "")));
}

#[test]
fn diff_sample_lists_changed_entities() {
    let Decoded::Answer { answer, .. } = decode_impact(true, DIFF_FOUND, "") else {
        panic!("no answer");
    };
    let Impact::Complete(entities) = answer else {
        panic!("not complete");
    };
    let first = entities.first().unwrap();
    assert_eq!(first.file_path, "crates/tycho/src/command.rs");
    assert_eq!(first.name, "CommandError");
    assert_eq!(first.dependents, 11);
}

#[test]
fn diff_empty_sample_has_a_null_file_list() {
    assert_eq!(
        decode_impact(true, DIFF_EMPTY, ""),
        Decoded::Answer {
            answer: Impact::Complete(Vec::new()),
            revisions: Revisions::Range {
                base: "HEAD~1".to_string(),
                head: "HEAD".to_string(),
            },
            index_cache_hit: None,
        }
    );
}

#[test]
fn diff_over_its_budget_is_partial() {
    let mut value: Value = serde_json::from_str(DIFF_FOUND).unwrap();
    value["warnings"] = serde_json::json!([{"code": BUDGET_EXCEEDED}]);
    let Decoded::Answer { answer, .. } = decode_impact(true, &value.to_string(), "") else {
        panic!("no answer");
    };
    assert!(matches!(answer, Impact::Partial(_)));
}

#[test]
fn diff_over_the_entity_bound_is_too_many() {
    let mut value: Value = serde_json::from_str(DIFF_FOUND).unwrap();
    let change = value["files"][0]["changes"][0].clone();
    value["files"][0]["changes"] = Value::Array(vec![change; IMPACT_ENTITIES_MAX_ITEMS + 1]);
    assert_eq!(
        decode_impact(true, &value.to_string(), ""),
        Decoded::TooMany(IMPACT_ENTITIES_MAX_ITEMS + 1)
    );
}

#[test]
fn diff_bad_revision_or_garbage_is_not_an_answer() {
    assert!(matches!(
        decode_impact(false, "", DIFF_BAD_REVISION),
        Decoded::Failed(_)
    ));
    for garbage in GARBAGE {
        assert!(is_unrecognised(&decode_impact(true, garbage, "")));
    }
}

#[test]
fn a_long_failure_message_is_cut_to_its_bound() {
    let long = "é".repeat(MESSAGE_MAX_BYTES);
    let IndexOutcome::Failed(message) = decode_index(false, "", &long) else {
        panic!("not failed");
    };
    assert!(message.len() <= MESSAGE_MAX_BYTES);
}

/// A canonical directory under `target`, removed when dropped.
struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("entire-graph-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(std::fs::canonicalize(path).unwrap())
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// A shell stand-in for the plugin: the pinned version, the given doctor report, and
/// `index_bytes` zero bytes from `index`.
fn stub(dir: &TestDir, doctor: &str, index_bytes: usize) -> PathBuf {
    let path = dir.0.join("entire-graph");
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\n  version) printf '%s' '{}' ;;\n  doctor) printf '%s' '{}' ;;\n  index) head -c {index_bytes} /dev/zero ;;\nesac\n",
        VERSION_PINNED.trim(),
        doctor.trim()
    );
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    path
}

#[test]
fn index_names_are_stable_and_distinct_per_checkout() {
    let dir = TestDir::new("names");
    for name in ["one/wu03", "two/wu03"] {
        std::fs::create_dir_all(dir.0.join(name)).unwrap();
    }
    let first = Checkout::parse(&dir.0.join("one/wu03")).unwrap();
    let second = Checkout::parse(&dir.0.join("two/wu03")).unwrap();
    assert_eq!(index_name(&first), index_name(&first));
    assert_ne!(index_name(&first), index_name(&second));
    assert!(index_name(&first).starts_with("wu03-"));
}

#[test]
fn an_index_name_keeps_only_its_bound_of_the_directory_name() {
    let dir = TestDir::new("long-name");
    let stem = "n".repeat(INDEX_NAME_MAX_BYTES);
    for suffix in ["a", "b"] {
        std::fs::create_dir_all(dir.0.join(format!("{stem}{suffix}"))).unwrap();
    }
    let first = index_name(&Checkout::parse(&dir.0.join(format!("{stem}a"))).unwrap());
    let second = index_name(&Checkout::parse(&dir.0.join(format!("{stem}b"))).unwrap());
    assert_eq!(first.len(), INDEX_NAME_MAX_BYTES + 17);
    assert!(first.starts_with(&format!("{stem}-")));
    assert_ne!(first, second);
}

#[test]
fn an_index_inside_the_checkout_is_refused() {
    let dir = TestDir::new("inside");
    let graph = EntireGraph {
        binary: PathBuf::from("/nonexistent/entire-graph"),
        index_root: dir.0.join(".graph"),
    };
    let checkout = Checkout::parse(&dir.0).unwrap();
    assert!(matches!(
        graph.prepare(&checkout),
        Err(GraphError::IndexInsideCheckout(_))
    ));
}

#[test]
fn an_index_root_reached_through_a_symlink_into_the_checkout_is_refused() {
    let dir = TestDir::new("symlink");
    let checkout_path = dir.0.join("checkout");
    std::fs::create_dir_all(&checkout_path).unwrap();
    std::os::unix::fs::symlink(&checkout_path, dir.0.join("link")).unwrap();
    let binary = stub(&dir, DOCTOR, 0);
    let graph = EntireGraph::open(&binary, &dir.0.join("link/graph")).unwrap();
    assert_eq!(graph.index_root(), checkout_path.join("graph"));
    let checkout = Checkout::parse(&checkout_path).unwrap();
    assert!(matches!(
        graph.prepare(&checkout),
        Err(GraphError::IndexInsideCheckout(_))
    ));
}

#[test]
fn open_refuses_a_plugin_that_reports_egress() {
    let dir = TestDir::new("egress");
    let remote = DOCTOR.replace("\"upload_telemetry\":false", "\"upload_telemetry\":true");
    let binary = stub(&dir, &remote, 0);
    let graph = EntireGraph::open(&binary, &dir.0.join("index"));
    assert!(
        matches!(graph, Err(GraphError::EgressNotRuledOut(reason)) if reason == "upload_telemetry")
    );
    let binary = stub(&dir, DOCTOR, 0);
    assert!(EntireGraph::open(&binary, &dir.0.join("index")).is_ok());
}

#[test]
fn index_output_over_the_adapter_cap_is_refused() {
    let dir = TestDir::new("output-cap");
    let checkout_path = dir.0.join("checkout");
    std::fs::create_dir_all(&checkout_path).unwrap();
    let binary = stub(&dir, DOCTOR, GRAPH_OUTPUT_MAX_BYTES + 1);
    let graph = EntireGraph::open(&binary, &dir.0.join("index")).unwrap();
    let checkout = Checkout::parse(&checkout_path).unwrap();
    let unit = WorkUnitId::parse("wu-graph").unwrap();
    let result = graph.build(&StepKey::parse("graph.cap").unwrap(), &unit, &checkout);
    let Err(GraphError::Command("index", message)) = result else {
        panic!("output over the cap was accepted: {result:?}");
    };
    assert!(
        message.contains(&GRAPH_OUTPUT_MAX_BYTES.to_string()),
        "{message}"
    );
}

#[test]
fn inherited_entire_variables_are_removed() {
    let names = ["ENTIRE_PLUGIN_DATA_DIR", "ENTIRE_REPO_ROOT", "HOME", "PATH"]
        .into_iter()
        .map(OsString::from);
    assert_eq!(
        entire_variables(names),
        [
            OsString::from("ENTIRE_PLUGIN_DATA_DIR"),
            OsString::from("ENTIRE_REPO_ROOT")
        ]
    );
}

#[test]
fn every_versioned_decoder_refuses_another_format_version() {
    let bumped = |text: &str| text.replacen("\"format_version\":1", "\"format_version\":2", 1);
    assert!(matches!(
        decode_index(true, &bumped(INDEX_BUILT), ""),
        IndexOutcome::Unrecognised(_)
    ));
    assert!(is_unrecognised(&decode_definitions(
        true,
        &bumped(DEF_FOUND),
        ""
    )));
    assert!(is_unrecognised(&decode_callers(
        true,
        &bumped(NEIGHBORS_FOUND),
        ""
    )));
    let versioned_diff = DIFF_EMPTY.replacen('{', "{\"format_version\":1,", 1);
    assert!(is_unrecognised(&decode_impact(true, &versioned_diff, "")));
    let versioned_doctor = DOCTOR.replacen('{', "{\"format_version\":1,", 1);
    assert!(matches!(
        decode_doctor(&versioned_doctor),
        EgressState::Unrecognised(_)
    ));
    let versioned_version = VERSION_PINNED.replacen('{', "{\"format_version\":1,", 1);
    assert!(matches!(
        decode_version(&captured(0, &versioned_version)),
        VersionState::Unrecognised(_)
    ));
}

#[test]
fn neighbors_with_a_fuzzy_kind_and_no_flag_is_not_found() {
    let kind_only = NEIGHBORS_FUZZY.replace("\"fuzzy_match\":true,", "");
    assert!(!kind_only.contains("\"fuzzy_match\":"));
    let Decoded::Answer { answer, .. } = decode_callers(true, &kind_only, "") else {
        panic!("no answer");
    };
    assert!(matches!(answer, Callers::NotFound { .. }));
}

#[test]
fn neighbors_with_a_non_boolean_fuzzy_flag_is_unrecognised() {
    let odd = NEIGHBORS_FUZZY.replace("\"fuzzy_match\":true", "\"fuzzy_match\":\"yes\"");
    assert!(is_unrecognised(&decode_callers(true, &odd, "")));
}

#[test]
fn diff_kinds_sample_decodes_every_change_type() {
    let Decoded::Answer { answer, .. } = decode_impact(true, DIFF_KINDS, "") else {
        panic!("no answer");
    };
    let Impact::Complete(entities) = answer else {
        panic!("not complete");
    };
    let kinds: Vec<ChangeKind> = entities.iter().map(|entity| entity.change).collect();
    assert_eq!(
        kinds,
        [
            ChangeKind::SignatureChanged,
            ChangeKind::BodyChanged,
            ChangeKind::Removed,
            ChangeKind::Removed,
            ChangeKind::Renamed
        ]
    );
}

#[test]
fn diff_with_an_unknown_change_type_is_unrecognised() {
    let unknown = DIFF_KINDS.replacen("\"body_changed\"", "\"moved\"", 1);
    assert!(is_unrecognised(&decode_impact(true, &unknown, "")));
    assert_eq!(
        decode_change_type("moved"),
        ChangeType::Unrecognised("moved".to_string())
    );
}

#[test]
fn diff_with_no_dependents_count_is_unrecognised() {
    let mut value: Value = serde_json::from_str(DIFF_FOUND).unwrap();
    value["files"][0]["changes"][0]
        .as_object_mut()
        .unwrap()
        .remove("dependents_count");
    assert!(is_unrecognised(&decode_impact(
        true,
        &value.to_string(),
        ""
    )));
}

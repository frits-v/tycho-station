use super::*;
use crate::agent_files::current_uid;
use crate::launch_spec::tests::NAME;
use std::os::unix::fs::PermissionsExt;

fn newlines(bytes: &[u8]) -> usize {
    std::str::from_utf8(bytes).unwrap().matches('\n').count()
}

fn session() -> SessionName {
    SessionName::parse(NAME).unwrap()
}

fn event(decision: &str, mode: &str, target: &str) -> NetworkAuditEvent {
    serde_json::from_value(serde_json::json!({
        "timestamp_unix_ms": 7, "mode": mode, "decision": decision,
        "target": target, "port": 443, "reason": "host not in allowlist"
    }))
    .unwrap()
}

#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in a scratch directory no other user can write"
)]
fn scratch(test: &str) -> AgentDirs {
    let root = std::env::temp_dir().join(format!("tycho-audit-{test}-{}", std::process::id()));
    if root.exists() {
        std::fs::remove_dir_all(&root).unwrap();
    }
    let dirs = AgentDirs::new(root).unwrap();
    std::fs::create_dir_all(dirs.spool_root()).unwrap();
    dirs
}

#[expect(
    clippy::disallowed_methods,
    reason = "fixtures live in a scratch directory no other user can write"
)]
fn remove(dirs: &AgentDirs) {
    std::fs::remove_dir_all(&dirs.socket_dir).unwrap();
}

/// A refusal is a firing of the session proxy naming the destination, an admission is an
/// examination, and the counts cover every line.
#[test]
fn a_refusal_is_a_firing_and_an_admission_an_examination() {
    let dirs = scratch("firing");
    let path = audit_path(&dirs, &session());
    let events = [
        event("allow", "reverse", "anthropic"),
        event("allow", "connect", "statsig.anthropic.com"),
        event("deny", "connect", "github.com"),
    ];
    assert_eq!(write(&path, &events).unwrap(), 3);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, AUDIT_FILE_MODE);
    let AuditRead::Read(audit) = read(&dirs, &session(), current_uid()) else {
        panic!("the audit did not read back");
    };
    assert_eq!(audit.examinations, 2);
    assert_eq!(audit.unrecognised, 0);
    assert!(!audit.at_cap);
    assert_eq!(
        audit.firings,
        [Firing {
            mechanism: MECHANISM.to_string(),
            session: session(),
            subject: "github.com:443".to_string(),
            unix_ms: 7,
            reason: Some("host not in allowlist".to_string()),
        }]
    );
    assert_eq!(
        audit.to_string(),
        "2 examinations, 1 firings [github.com:443], 0 unrecognised"
    );
    remove(&dirs);
}

#[test]
fn no_file_reads_absent_and_an_empty_one_examined_nothing() {
    let dirs = scratch("absent");
    assert_eq!(read(&dirs, &session(), current_uid()), AuditRead::Absent);
    write(&audit_path(&dirs, &session()), &[]).unwrap();
    let AuditRead::Read(audit) = read(&dirs, &session(), current_uid()) else {
        panic!("an empty audit did not read");
    };
    assert_eq!((audit.examinations, audit.firings.len()), (0, 0));
    remove(&dirs);
}

/// The proxy keeps 4096 events and drops the rest; the file then ends with the line that
/// says so, and the decoder reports the counts as a lower bound.
#[test]
fn a_proxy_at_its_cap_writes_its_events_and_the_cap_line() {
    let events = vec![event("deny", "connect", "github.com"); AUDIT_EVENTS_MAX];
    let bytes = encode(&events).unwrap();
    assert_eq!(newlines(&bytes), AUDIT_LINES_MAX);
    assert!(bytes.len() <= AUDIT_FILE_MAX_BYTES);
    let audit = decode(&session(), &bytes);
    assert!(audit.at_cap);
    assert_eq!(audit.firing_count, AUDIT_EVENTS_MAX);
    assert_eq!(audit.firings.len(), FIRINGS_KEPT_MAX);
    assert!(audit.to_string().ends_with("at the proxy's cap"), "{audit}");
    let below = encode(&events[1..]).unwrap();
    assert!(!decode(&session(), &below).at_cap);
}

/// Every line that is not one the launcher writes counts as unrecognised, never as a
/// decision: garbage, an unknown field or decision, an approval, a line over its bound, and a
/// line past the most the launcher writes.
#[test]
fn a_line_the_launcher_never_writes_is_unrecognised() {
    let good =
        serde_json::to_string(&AuditLine::of(&event("allow", "connect", "a.example"))).unwrap();
    let approval = serde_json::to_string(&AuditLine {
        decision: LineDecision::Other,
        ..AuditLine::of(&event("allow", "connect", "a.example"))
    })
    .unwrap();
    let long = format!(
        "{{\"unix_ms\":1,\"decision\":\"allow\",\"path\":\"connect\",\"target\":\"{}\",\"port\":443,\"reason\":null}}",
        "a".repeat(AUDIT_LINE_MAX_BYTES)
    );
    let unknown_field = good.replacen('{', "{\"extra\":1,", 1);
    let unknown_decision = good.replace("\"allow\"", "\"maybe\"");
    let lines = [
        "not json".to_string(),
        unknown_field,
        unknown_decision,
        approval,
        long,
        good.clone(),
    ];
    let audit = decode(&session(), lines.join("\n").as_bytes());
    assert_eq!((audit.examinations, audit.unrecognised), (1, 5), "{audit}");
    let past = vec![good; AUDIT_LINES_MAX + 2].join("\n");
    let audit = decode(&session(), past.as_bytes());
    assert_eq!(
        (audit.examinations, audit.unrecognised),
        (AUDIT_LINES_MAX, 2)
    );
}

/// The file is read as the agent's regular file within its bound, never through a link and
/// never blocking on a FIFO; each refusal is unreadable, not absent.
#[test]
fn a_link_fifo_foreign_or_oversized_audit_is_unreadable() {
    let dirs = scratch("refused");
    let path = audit_path(&dirs, &session());
    let target = dirs.socket_dir.join("target");
    write(&target, &[event("allow", "connect", "a.example")]).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(matches!(
        read(&dirs, &session(), current_uid()),
        AuditRead::Unreadable { .. }
    ));
    assert!(
        write(&path, &[]).is_err(),
        "the launcher wrote through a planted link"
    );
    std::fs::remove_file(&path).unwrap();
    nix::unistd::mkfifo(&path, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
    assert!(matches!(
        read(&dirs, &session(), current_uid()),
        AuditRead::Unreadable { .. }
    ));
    std::fs::remove_file(&path).unwrap();
    write(&path, &[]).unwrap();
    assert!(matches!(
        read(&dirs, &session(), current_uid().wrapping_add(1)),
        AuditRead::Unreadable { .. }
    ));
    assert!(
        write(&path, &[]).is_err(),
        "a second write replaced the file"
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, vec![b'\n'; AUDIT_FILE_MAX_BYTES + 1]).unwrap();
    assert!(matches!(
        read(&dirs, &session(), current_uid()),
        AuditRead::Unreadable { .. }
    ));
    remove(&dirs);
}

/// What the vendor named is kept within its bound and without control characters, so a
/// target cannot forge a line or a log entry.
#[test]
fn a_target_and_reason_are_cut_to_their_bounds_without_control_characters() {
    let mut forged = event(
        "deny",
        "connect",
        &format!("a\nb\u{1b}[2J{}", "c".repeat(400)),
    );
    forged.reason = Some(format!("r\n{}", "x".repeat(400)));
    let line = AuditLine::of(&forged);
    assert!(line.target.len() <= TARGET_MAX_BYTES);
    assert!(line.target.starts_with("ab[2J"), "{}", line.target);
    assert!(!line.target.chars().any(char::is_control));
    let reason = line.reason.unwrap();
    assert!(reason.len() <= REASON_MAX_BYTES && !reason.contains('\n'));
    let bytes = encode(&[forged]).unwrap();
    assert_eq!(newlines(&bytes), 1);
    assert!(bytes.len() <= AUDIT_LINE_MAX_BYTES + 1);
}

/// A refusal is a firing whatever the vendor put in the host name: a name of quotes or
/// backslashes doubles under JSON's escaping, and nono's reason repeats it, so the bound is
/// taken on the escaped text and a cut field ends with the marker.
#[test]
fn a_quote_or_backslash_heavy_host_still_decodes_as_a_firing() {
    let mut examined = 0_usize;
    for heavy in ["\"", "\\", "\"\\", "\u{e9}\""] {
        let host = heavy.repeat(400);
        let mut forged = event("deny", "connect", &host);
        forged.reason = Some(format!("host {host}:443 is not in the allowlist"));
        let bytes = encode(&[forged]).unwrap();
        let line = std::str::from_utf8(&bytes).unwrap().trim_end();
        assert!(
            line.len() <= AUDIT_LINE_MAX_BYTES,
            "{heavy:?}: a line of {} bytes",
            line.len()
        );
        let audit = decode(&session(), &bytes);
        assert_eq!(
            (audit.firing_count, audit.unrecognised),
            (1, 0),
            "{heavy:?}: {audit}"
        );
        let firing = &audit.firings[0];
        assert!(firing.subject.contains(CUT_MARKER), "{}", firing.subject);
        assert!(
            firing
                .reason
                .as_deref()
                .is_some_and(|reason| reason.ends_with(CUT_MARKER))
        );
        examined += 1;
    }
    assert_eq!(examined, 4);
}

/// Every field at its widest, each text field all quotes, still fits the line bound.
#[test]
fn the_widest_line_fits_its_bound() {
    let widest = AuditLine {
        unix_ms: u64::MAX,
        decision: LineDecision::CapReached,
        path: "\"".repeat(PATH_MAX_BYTES / 2),
        target: "\"".repeat(TARGET_MAX_BYTES / 2),
        port: Some(u16::MAX),
        reason: Some("\"".repeat(REASON_MAX_BYTES / 2)),
    };
    let line = serde_json::to_string(&widest).unwrap();
    assert!(line.len() <= AUDIT_LINE_MAX_BYTES, "{}", line.len());
    let short = cut(&"\"".repeat(TARGET_MAX_BYTES), TARGET_MAX_BYTES);
    assert!(serde_json::to_string(&short).unwrap().len() - 2 <= TARGET_MAX_BYTES);
}

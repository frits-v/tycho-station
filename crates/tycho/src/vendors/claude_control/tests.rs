use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::thread;

use tycho_types::session::SessionName;
use tycho_types::task_packet::AbsolutePath;

use super::*;
use crate::spawn::CLAUDE_SANDBOX_SETTINGS;

const REGISTRY_IDLE: &str = include_str!("../../fixtures/claude-registry-idle.json");
const REGISTRY_WAITING: &str = include_str!("../../fixtures/claude-registry-waiting.json");
const TRANSCRIPT_TAIL: &str = include_str!("../../fixtures/claude-transcript-tail.jsonl");
const SESSION_ID: &str = "56736586-cf23-4aaa-955f-7ea9c1fb1e15";
const SETTINGS: &str = r#"{"autoCompactWindow":1000000,"crossSessionInbound":"accept","sandbox":{"allowUnsandboxedCommands":false,"enabled":true,"excludedCommands":[],"failIfUnavailable":true,"network":{"allowAllUnixSockets":false,"allowLocalBinding":false,"allowedDomains":[]}}}"#;

fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tcc-{test}-{}", std::process::id()));
    if dir.exists() {
        fs::remove_dir_all(&dir).unwrap();
    }
    fs::create_dir_all(dir.join("sessions")).unwrap();
    dir
}

fn adapter(config_dir: &Path) -> ClaudeControl {
    ClaudeControl::new(
        PathBuf::from("/opt/claude/bin/claude"),
        config_dir.to_path_buf(),
    )
}

fn launch(resume: bool) -> ControlLaunch {
    ControlLaunch {
        session: SessionName::parse("cf7a.wu03.ctl.claude").unwrap(),
        vendor_session: VendorSessionId::parse(SESSION_ID).unwrap(),
        model: "haiku".to_string(),
        effort: Effort::Low,
        permission: PermissionMode::DontAsk,
        sandbox_settings: CLAUDE_SANDBOX_SETTINGS.to_string(),
        working_dir: AbsolutePath::parse("/Users/agent/control/cf7a-wu03").unwrap(),
        resume,
    }
}

fn session() -> VendorSessionId {
    VendorSessionId::parse(SESSION_ID).unwrap()
}

#[test]
fn the_command_line_is_exact_and_resume_re_passes_the_settings() {
    let command = adapter(Path::new("/c"))
        .control_command(&launch(false))
        .unwrap();
    let expected = [
        "/opt/claude/bin/claude",
        "--model",
        "haiku",
        "--effort",
        "low",
        "--permission-mode",
        "dontAsk",
        "--name",
        "cf7a.wu03.ctl.claude",
        "--session-id",
        SESSION_ID,
        "--settings",
        SETTINGS,
    ];
    assert_eq!(command.argv, expected);
    assert_eq!(command.terminal, VendorTerminal::Inherit);
    assert_eq!(
        command.working_dir,
        PathBuf::from("/Users/agent/control/cf7a-wu03")
    );
    let resumed = adapter(Path::new("/c"))
        .control_command(&launch(true))
        .unwrap();
    let mut expected_resume = expected.map(str::to_string).to_vec();
    expected_resume[9] = "--resume".to_string();
    assert_eq!(resumed.argv, expected_resume);
    assert!(command
        .argv
        .iter()
        .all(|word| ShortText::parse(word).is_ok()));
}

#[test]
fn effort_model_and_sandbox_are_checked() {
    let control = adapter(Path::new("/c"));
    let mut minimal = launch(false);
    minimal.effort = Effort::Minimal;
    assert!(matches!(
        control.control_command(&minimal),
        Err(VendorError::Unsupported(_))
    ));
    for model in [
        "",
        "Opus",
        "haiku;rm",
        &"m".repeat(MODEL_NAME_MAX_BYTES + 1),
    ] {
        let mut bad = launch(false);
        bad.model = model.to_string();
        assert!(control.control_command(&bad).is_err(), "{model:?}");
    }
    assert!(settings_json("{}").is_err(), "no sandbox object");
    assert!(settings_json("[]").is_err());
    assert!(settings_json(r#"{"sandbox":true}"#).is_err());
    let wide = format!(r#"{{"sandbox":{{"x":"{}"}}}}"#, "y".repeat(TEXT_MAX_BYTES));
    assert!(settings_json(&wide).is_err(), "over the argument bound");
    let loose =
        r#"{"sandbox":{"enabled":true},"crossSessionInbound":"refuse","autoCompactWindow":100000}"#;
    let settings: Value = serde_json::from_str(&settings_json(loose).unwrap()).unwrap();
    assert_eq!(settings["crossSessionInbound"], "accept");
    assert_eq!(settings["autoCompactWindow"], AUTO_COMPACT_WINDOW_MAX);
}

#[test]
fn registry_files_decode_to_every_observed_state() {
    let idle = decode_registry(REGISTRY_IDLE.as_bytes()).unwrap();
    assert_eq!(idle.session_id, SESSION_ID);
    assert_eq!(
        idle.messaging_socket_path.as_deref(),
        Some("/tmp/cc-socks/69821.sock")
    );
    assert_eq!(observation_of(&idle), Observation::Idle { pid: 69821 });
    let waiting = decode_registry(REGISTRY_WAITING.as_bytes()).unwrap();
    assert_eq!(
        observation_of(&waiting),
        Observation::Waiting {
            pid: 69821,
            waiting_for: WaitingFor::PermissionPrompt
        }
    );
    let mut busy = idle.clone();
    busy.status = "busy".to_string();
    assert_eq!(observation_of(&busy), Observation::Busy { pid: 69821 });
    let mut other_wait = waiting;
    other_wait.waiting_for = Some("plan approval".to_string());
    assert!(matches!(
        observation_of(&other_wait),
        Observation::Waiting {
            waiting_for: WaitingFor::Unrecognised(_),
            ..
        }
    ));
    let mut unknown = idle;
    unknown.status = "sleeping".to_string();
    assert!(matches!(
        observation_of(&unknown),
        Observation::Unrecognised { .. }
    ));
    for garbage in [
        "",
        "not json",
        "[1]",
        r#"{"pid":0,"sessionId":"x","cwd":"/","kind":"interactive","status":"idle"}"#,
    ] {
        assert!(decode_registry(garbage.as_bytes()).is_err(), "{garbage:?}");
    }
}

#[test]
fn context_size_is_the_last_turns_input_and_cache_tokens() {
    assert_eq!(
        context_of(TRANSCRIPT_TAIL),
        ContextReport::Tokens { tokens: 41_913 }
    );
    let peer_only = TRANSCRIPT_TAIL.lines().next().unwrap();
    assert_eq!(context_of(peer_only), ContextReport::NoTurnYet);
    assert_eq!(context_of(""), ContextReport::NoTurnYet);
    let no_tokens = r#"{"type":"assistant","message":{"usage":{"output_tokens":3}}}"#;
    assert!(matches!(
        context_of(no_tokens),
        ContextReport::Unrecognised { .. }
    ));
    let cut = format!("{{\"type\":\"assistant\",\"usage\" \n{TRANSCRIPT_TAIL}");
    assert_eq!(
        context_of(&cut),
        ContextReport::Tokens { tokens: 41_913 },
        "a cut first line is skipped"
    );
}

#[test]
fn the_project_slug_replaces_every_non_alphanumeric_byte() {
    assert_eq!(
        project_slug("/Users/frits/.tw12/work"),
        "-Users-frits--tw12-work"
    );
    assert_eq!(
        project_slug("/Users/frits/src/tycho-station"),
        "-Users-frits-src-tycho-station"
    );
}

#[test]
fn the_instruction_line_is_one_json_user_message() {
    let text = ShortText::parse("Task packet sha256:ab: \"plan\" it").unwrap();
    assert_eq!(
        instruction_line(&text),
        "{\"message\":{\"content\":\"Task packet sha256:ab: \\\"plan\\\" it\",\"role\":\"user\"},\"type\":\"user\"}\n"
    );
}

/// A listener that reads one line, answers with `reply`, and returns the line it read.
fn listener(path: &Path, reply: &'static [u8]) -> thread::JoinHandle<String> {
    let listener = UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        reader.get_mut().write_all(reply).unwrap();
        line
    })
}

#[test]
fn each_socket_outcome_has_its_own_state() {
    let dir = scratch("post");
    let socket = dir.join("i.sock");
    let line = instruction_line(&ShortText::parse("go").unwrap());
    let server = listener(&socket, b"");
    assert!(matches!(post(&socket, &line), Delivery::Posted { .. }));
    assert_eq!(server.join().unwrap(), line);
    fs::remove_file(&socket).unwrap();
    let server = listener(&socket, b"ok");
    assert!(matches!(post(&socket, &line), Delivery::Replied { reply, .. } if reply == "ok"));
    server.join().unwrap();
    assert!(
        matches!(post(&socket, &line), Delivery::Refused { .. }),
        "a stale socket"
    );
    fs::remove_file(&socket).unwrap();
    assert!(matches!(post(&socket, &line), Delivery::NoSocket { .. }));
    let _held = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o000)).unwrap();
    assert!(matches!(post(&socket, &line), Delivery::Denied { .. }));
    fs::remove_dir_all(&dir).unwrap();
}

fn registry_file(dir: &Path, name: &str, pid: u32, socket: &Path) {
    let entry = json!({
        "pid": pid, "sessionId": SESSION_ID, "cwd": "/w", "kind": "interactive",
        "status": "idle", "messagingSocketPath": socket.display().to_string(),
    });
    fs::write(dir.join("sessions").join(name), entry.to_string()).unwrap();
}

#[test]
fn a_session_is_found_only_through_a_live_process_holding_its_id() {
    let dir = scratch("locate");
    let control = adapter(&dir);
    let socket = dir.join("i.sock");
    assert_eq!(control.locate(&session()), Located::Absent);
    registry_file(&dir, "1.json", PID_MAX, &socket);
    assert_eq!(control.locate(&session()), Located::Absent, "a dead pid");
    assert_eq!(
        control.address(&session(), &ShortText::parse("go").unwrap()),
        Delivery::NoSession
    );
    registry_file(&dir, "2.json", std::process::id(), &socket);
    fs::write(dir.join("sessions").join("2.key"), "not a record").unwrap();
    assert!(
        matches!(control.locate(&session()), Located::Found(entry) if entry.pid == std::process::id())
    );
    let server = listener(&socket, b"");
    let delivered = control.address(&session(), &ShortText::parse("go").unwrap());
    assert_eq!(
        delivered,
        Delivery::Posted {
            socket: socket.display().to_string()
        }
    );
    assert!(server.join().unwrap().contains("\"content\":\"go\""));
    assert_eq!(
        control.observe(&session()),
        Observation::Idle {
            pid: std::process::id()
        }
    );
    assert_eq!(control.context_size(&session()), ContextReport::NoTurnYet);
    registry_file(&dir, "3.json", std::process::id(), &socket);
    assert_eq!(control.locate(&session()), Located::Ambiguous(2));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_registry_over_its_bound_is_unreadable_not_partly_scanned() {
    let dir = scratch("bound");
    for index in 0..=REGISTRY_FILES_MAX {
        fs::write(dir.join("sessions").join(format!("{index}.key")), "").unwrap();
    }
    assert!(matches!(
        adapter(&dir).locate(&session()),
        Located::Unreadable(_)
    ));
    assert!(matches!(
        adapter(&dir).address(&session(), &ShortText::parse("go").unwrap()),
        Delivery::Unreadable { .. }
    ));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_context_size_reads_the_sessions_transcript() {
    let dir = scratch("context");
    let socket = dir.join("i.sock");
    registry_file(&dir, "2.json", std::process::id(), &socket);
    let project = dir.join("projects").join("-w");
    fs::create_dir_all(&project).unwrap();
    fs::write(project.join(format!("{SESSION_ID}.jsonl")), TRANSCRIPT_TAIL).unwrap();
    assert_eq!(
        adapter(&dir).context_size(&session()),
        ContextReport::Tokens { tokens: 41_913 }
    );
    fs::remove_dir_all(&dir).unwrap();
}

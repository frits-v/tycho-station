use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::thread;

use tycho_types::session::SessionName;
use tycho_types::task_packet::AbsolutePath;

use super::*;
use crate::spawn::CLAUDE_SANDBOX_SETTINGS;
use crate::vendors::control::AddressTarget;

const REGISTRY_IDLE: &str = include_str!("../../fixtures/claude-registry-idle.json");
const REGISTRY_WAITING: &str = include_str!("../../fixtures/claude-registry-waiting.json");
// Captured from another session in the same directory: an SDK entrypoint of 2.1.239.
const REGISTRY_NO_STATUS: &str = include_str!("../../fixtures/claude-registry-no-status.json");
// Captured from 2.1.280: the peer turn as written, and an assistant line trimmed to its type,
// ids, model and usage, with its content cut to one word.
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

fn target() -> AddressTarget {
    AddressTarget {
        session: SessionName::parse("cf7a.wu03.ctl.claude").unwrap(),
        vendor_session: session(),
    }
}

fn go(control: &ClaudeControl) -> Delivery {
    control.address(
        &target(),
        &ShortText::parse("wu03:task_packet:1").unwrap(),
        &ShortText::parse("go").unwrap(),
    )
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
    // Synthetic: `busy` was observed in `claude agents --json`, not captured in a registry file.
    let mut busy = idle.clone();
    busy.status = Some("busy".to_string());
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
    let no_status = decode_registry(REGISTRY_NO_STATUS.as_bytes()).unwrap();
    assert_eq!(no_status.pid, 19793);
    assert!(matches!(
        observation_of(&no_status),
        Observation::Unrecognised { .. }
    ));
    let mut unknown = idle;
    unknown.status = Some("sleeping".to_string());
    assert!(matches!(
        observation_of(&unknown),
        Observation::Unrecognised { .. }
    ));
    for garbage in [
        "",
        "not json",
        "[1]",
        r#"{"pid":0,"sessionId":"x","cwd":"/","kind":"interactive","status":"idle"}"#,
        r#"{"sessionId":"x","status":"idle"}"#,
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
    assert_eq!(go(&control), Delivery::NoSession);
    registry_file(&dir, "2.json", std::process::id(), &socket);
    fs::write(dir.join("sessions").join("2.key"), "not a record").unwrap();
    assert!(
        matches!(control.locate(&session()), Located::Found(entry) if entry.pid == std::process::id())
    );
    let server = listener(&socket, b"");
    let delivered = go(&control);
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
    assert!(matches!(go(&adapter(&dir)), Delivery::Unreadable { .. }));
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

/// A channel whose write takes `accept` bytes and then fails, and whose half-close can fail.
struct Failing {
    accept: usize,
    taken: usize,
    shutdown_fails: bool,
}

impl Channel for Failing {
    fn write_some(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let room = self.accept.saturating_sub(self.taken);
        if room == 0 {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        let count = room.min(bytes.len()).min(3);
        self.taken = self.taken.saturating_add(count);
        Ok(count)
    }

    fn half_close(&mut self) -> io::Result<()> {
        if self.shutdown_fails {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        }
        Ok(())
    }

    fn read_reply(&mut self, _reply: &mut Vec<u8>) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_failure_after_the_first_byte_or_at_the_half_close_counts_as_written() {
    let line = instruction_line(&ShortText::parse("go").unwrap());
    let post_with = |accept, shutdown_fails| {
        let mut channel = Failing {
            accept,
            taken: 0,
            shutdown_fails,
        };
        post_on(&mut channel, "s".to_string(), &line)
    };
    assert!(matches!(post_with(0, false), Delivery::WriteFailed { .. }));
    let partial = post_with(5, false);
    assert!(
        matches!(partial, Delivery::WriteInterrupted { sent: 5, .. }),
        "{partial:?}"
    );
    let unclosed = post_with(line.len(), true);
    assert!(
        matches!(unclosed, Delivery::WriteInterrupted { sent, .. } if sent == line.len()),
        "{unclosed:?}"
    );
    assert_eq!(
        post_with(line.len(), false),
        Delivery::Posted {
            socket: "s".to_string()
        }
    );
    assert!(partial.written() && unclosed.written());
}

/// A real stream whose half-close waits until the peer has read the line and hung up.
struct AfterPeerClosed {
    stream: UnixStream,
    peer: Option<thread::JoinHandle<String>>,
}

impl Channel for AfterPeerClosed {
    fn write_some(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.write_some(bytes)
    }

    fn half_close(&mut self) -> io::Result<()> {
        if let Some(peer) = self.peer.take() {
            peer.join().unwrap();
        }
        self.stream.half_close()
    }

    fn read_reply(&mut self, reply: &mut Vec<u8>) -> io::Result<()> {
        self.stream.read_reply(reply)
    }
}

#[test]
fn a_peer_that_hangs_up_before_the_half_close_never_triggers_a_fallback() {
    let dir = scratch("hangup");
    let socket = dir.join("i.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let peer = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        line
    });
    let mut channel = AfterPeerClosed {
        stream: UnixStream::connect(&socket).unwrap(),
        peer: Some(peer),
    };
    let line = instruction_line(&ShortText::parse("go").unwrap());
    let delivery = post_on(&mut channel, socket.display().to_string(), &line);
    assert!(delivery.written(), "{delivery:?}");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_socket_or_registry_of_another_user_sends_the_instruction_to_the_relay() {
    let dir = scratch("relay");
    let agent = AgentDirs::new(dir.join("agent")).unwrap();
    fs::create_dir_all(&agent.socket_dir).unwrap();
    let socket = dir.join("i.sock");
    registry_file(&dir, "2.json", std::process::id(), &socket);
    let _held = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(
        go(&adapter(&dir)),
        Delivery::RelayFailed {
            reason: "no relay directory is configured".to_string()
        }
    );
    let relaying = adapter(&dir).with_relay(agent.clone(), RelayMode::OnRefusal);
    let file = crate::relay::relay_file_name(&ShortText::parse("wu03:task_packet:1").unwrap());
    assert_eq!(go(&relaying), Delivery::Relayed { file: file.clone() });
    let written = crate::relay::relay_dir(&agent, &target().session).join(&file);
    assert!(fs::read_to_string(written)
        .unwrap()
        .contains("\"content\":\"go\""));
    fs::set_permissions(dir.join("sessions"), fs::Permissions::from_mode(0o000)).unwrap();
    assert!(matches!(relaying.locate(&session()), Located::Denied(_)));
    assert_eq!(go(&relaying), Delivery::Relayed { file: file.clone() });
    fs::set_permissions(dir.join("sessions"), fs::Permissions::from_mode(0o755)).unwrap();
    let always = adapter(&dir).with_relay(agent, RelayMode::Always);
    assert_eq!(go(&always), Delivery::Relayed { file });
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_registry_file_that_cannot_be_read_or_decoded_is_unreadable_not_absent() {
    let dir = scratch("undecodable");
    fs::write(dir.join("sessions").join("9.json"), "{\"pid\":").unwrap();
    assert!(matches!(
        adapter(&dir).locate(&session()),
        Located::Unreadable(reason) if reason.contains("9.json")
    ));
    fs::write(dir.join("sessions").join("9.json"), "{}").unwrap();
    fs::set_permissions(
        dir.join("sessions").join("9.json"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    assert!(matches!(
        adapter(&dir).observe(&session()),
        Observation::Unreadable { .. }
    ));
    fs::remove_dir_all(&dir).unwrap();
}

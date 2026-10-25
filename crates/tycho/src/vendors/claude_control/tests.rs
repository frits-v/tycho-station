#![expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::thread;

use tycho_types::session::SessionName;
use tycho_types::task_packet::AbsolutePath;

use super::*;
use crate::spawn::CLAUDE_SANDBOX_OFF;
use crate::test_sockets::{bound_without_listener, listener};
use crate::vendors::control::AddressTarget;

const REGISTRY_IDLE: &str = include_str!("../../fixtures/claude-registry-idle.json");
const REGISTRY_WAITING: &str = include_str!("../../fixtures/claude-registry-waiting.json");
// Captured from another session in the same directory: an SDK entrypoint of 2.1.239.
const REGISTRY_NO_STATUS: &str = include_str!("../../fixtures/claude-registry-no-status.json");
// Captured from 2.1.280: the peer turn as written, and an assistant line trimmed to its type,
// ids, model and usage, with its content cut to one word.
const TRANSCRIPT_TAIL: &str = include_str!("../../fixtures/claude-transcript-tail.jsonl");
const SESSION_ID: &str = "56736586-cf23-4aaa-955f-7ea9c1fb1e15";
// serde_json keeps insertion order (`preserve_order`): the core's settings, then the adapter's.
const SETTINGS: &str =
    r#"{"sandbox":{"enabled":false},"crossSessionInbound":"accept","autoCompactWindow":1000000}"#;

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
        current_uid(),
    )
    .with_sockets_dirs(vec![config_dir.to_path_buf()])
}

/// The socket path a registry entry of this test process names in `dir`.
fn own_socket(dir: &Path) -> PathBuf {
    dir.join(format!("{}.sock", std::process::id()))
}

fn launch(resume: bool) -> ControlLaunch {
    ControlLaunch {
        session: SessionName::parse("cf7a.wu03.ctl.claude").unwrap(),
        vendor_session: VendorSessionId::parse(SESSION_ID).unwrap(),
        model: "haiku".to_string(),
        effort: Effort::Low,
        permission: PermissionMode::DontAsk,
        sandbox_settings: CLAUDE_SANDBOX_OFF.to_string(),
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
    assert!(
        command
            .argv
            .iter()
            .all(|word| ShortText::parse(word).is_ok())
    );
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
        "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"Task packet sha256:ab: \\\"plan\\\" it\"}}\n"
    );
}

#[test]
fn each_socket_outcome_has_its_own_state() {
    let dir = scratch("post");
    let line = instruction_line(&ShortText::parse("go").unwrap());
    let posted = dir.join("posted.sock");
    let server = listener(&posted, b"");
    let delivery = post(&posted, &line, current_uid());
    assert!(matches!(delivery, Delivery::Posted { .. }), "{delivery:?}");
    assert_eq!(server.join().unwrap(), line);
    let replied = dir.join("replied.sock");
    let server = listener(&replied, b"ok");
    let delivery = post(&replied, &line, current_uid());
    assert!(
        matches!(&delivery, Delivery::Replied { reply, .. } if reply == "ok"),
        "{delivery:?}"
    );
    server.join().unwrap();
    let stale = dir.join("stale.sock");
    let _bound = bound_without_listener(&stale);
    let delivery = post(&stale, &line, current_uid());
    assert!(
        matches!(delivery, Delivery::Refused { .. }),
        "a stale socket: {delivery:?}"
    );
    let delivery = post(&dir.join("absent.sock"), &line, current_uid());
    assert!(
        matches!(delivery, Delivery::NoSocket { .. }),
        "{delivery:?}"
    );
    let denied = dir.join("denied.sock");
    let _held = UnixListener::bind(&denied).unwrap();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000)).unwrap();
    let delivery = post(&denied, &line, current_uid());
    assert!(matches!(delivery, Delivery::Denied { .. }), "{delivery:?}");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_child_holding_a_dropped_listener_keeps_it_listening_but_a_bound_socket_stays_refused() {
    let dir = scratch("inherited");
    let dropped = dir.join("dropped.sock");
    let listening = UnixListener::bind(&dropped).unwrap();
    let stale = dir.join("stale.sock");
    let bound = bound_without_listener(&stale);
    // A child's stdin and stdout carry no close-on-exec flag: the same copies a child spawned
    // during the window between `socket()` and setting that flag on macOS would hold.
    let mut holder = Command::new("/bin/sleep")
        .arg("30")
        .stdin(Stdio::from(OwnedFd::from(listening.try_clone().unwrap())))
        .stdout(Stdio::from(bound.try_clone().unwrap()))
        .spawn()
        .unwrap();
    drop(listening);
    drop(bound);
    let through_child = UnixStream::connect(&dropped);
    let refused = UnixStream::connect(&stale);
    holder.kill().unwrap();
    holder.wait().unwrap();
    assert!(
        through_child.is_ok(),
        "a dropped listener a child still holds accepts: {through_child:?}"
    );
    assert!(
        matches!(&refused, Err(error) if error.kind() == io::ErrorKind::ConnectionRefused),
        "{refused:?}"
    );
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
    let socket = own_socket(&dir);
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
    let socket = own_socket(&dir);
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
    let socket = own_socket(&dir);
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
    assert!(
        fs::read_to_string(written)
            .unwrap()
            .contains("\"content\":\"go\"")
    );
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

#[test]
fn a_live_entry_is_found_beside_a_registry_file_that_cannot_be_decoded() {
    let dir = scratch("beside");
    let socket = own_socket(&dir);
    fs::write(dir.join("sessions").join("9.json"), "{\"pid\":").unwrap();
    registry_file(&dir, "2.json", std::process::id(), &socket);
    assert!(matches!(
        adapter(&dir).locate(&session()),
        Located::Found(entry) if entry.pid == std::process::id()
    ));
    fs::remove_file(dir.join("sessions").join("2.json")).unwrap();
    assert!(matches!(
        adapter(&dir).locate(&session()),
        Located::Unreadable(reason) if reason.contains("9.json")
    ));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_pre_existing_relay_file_is_relayed_only_when_it_is_the_cores_identical_line() {
    let dir = scratch("existing");
    let agent = AgentDirs::new(dir.join("agent")).unwrap();
    fs::create_dir_all(&agent.socket_dir).unwrap();
    let always = adapter(&dir).with_relay(agent.clone(), RelayMode::Always);
    let file = crate::relay::relay_file_name(&ShortText::parse("wu03:task_packet:1").unwrap());
    assert_eq!(go(&always), Delivery::Relayed { file: file.clone() });
    assert_eq!(go(&always), Delivery::Relayed { file: file.clone() });
    let written = crate::relay::relay_dir(&agent, &target().session).join(&file);
    fs::remove_file(&written).unwrap();
    // Another writer's file cannot be made here; a different line stands in for it.
    let planted = instruction_line(&ShortText::parse("planted").unwrap());
    crate::agent_files::write_new_mode(&written, planted.as_bytes(), 0o640).unwrap();
    assert!(matches!(
        go(&always),
        Delivery::RelayFailed { reason } if reason.contains("another instruction")
    ));
    always.release(&target().session).unwrap();
    assert!(!crate::relay::relay_dir(&agent, &target().session).exists());
    assert_eq!(go(&always), Delivery::Relayed { file });
    fs::remove_dir_all(&dir).unwrap();
}

/// A listener the adapter must never connect to.
fn untouched(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

fn never_connected(listener: &UnixListener) -> bool {
    matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
}

#[test]
fn a_socket_path_must_be_absolute_and_named_for_the_pid_in_a_vendor_directory() {
    let sockets = sockets_dirs(Some(Path::new("/run/user/501")), 501);
    assert_eq!(
        sockets,
        [
            PathBuf::from("/run/user/501/cc-socks"),
            PathBuf::from("/tmp/cc-socks"),
            PathBuf::from("/tmp/cc-socks-501"),
        ]
    );
    assert_eq!(sockets_dirs(None, 501).len(), 2);
    assert_eq!(sockets_dirs(Some(Path::new("run")), 501).len(), 2);
    for dir in &sockets {
        let raw = dir.join("7.sock");
        assert_eq!(
            socket_shape(&raw.display().to_string(), 7, &sockets).unwrap(),
            raw
        );
    }
    for raw in [
        "",
        "7.sock",
        "tmp/cc-socks/7.sock",
        "/tmp/cc-socks/../cc-socks/7.sock",
        "/tmp/cc-socks/sub/../7.sock",
        "/tmp/cc-socks/sub/7.sock",
        "/tmp/cc-socks-502/7.sock",
        "/run/user/501/7.sock",
        "/tmp/7.sock",
        "/tmp/cc-socks/8.sock",
        "/tmp/cc-socks/7.sock.x",
        "/tmp/cc-socks",
    ] {
        assert!(socket_shape(raw, 7, &sockets).is_err(), "{raw:?}");
    }
}

#[test]
fn a_registry_socket_outside_the_sockets_directory_is_refused_unconnected() {
    let dir = scratch("outside");
    let elsewhere = dir.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let socket = own_socket(&elsewhere);
    let held = untouched(&socket);
    registry_file(&dir, "2.json", std::process::id(), &socket);
    let delivery = go(&adapter(&dir));
    assert!(
        matches!(&delivery, Delivery::Untrusted { reason } if reason.contains("is not in")),
        "{delivery:?}"
    );
    assert!(never_connected(&held));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_registry_socket_not_named_for_the_entrys_pid_is_refused_unconnected() {
    let dir = scratch("name");
    let socket = dir.join(format!("{}.sock", std::process::id().wrapping_add(1)));
    let held = untouched(&socket);
    registry_file(&dir, "2.json", std::process::id(), &socket);
    let delivery = go(&adapter(&dir));
    assert!(
        matches!(&delivery, Delivery::Untrusted { reason } if reason.contains("is not named")),
        "{delivery:?}"
    );
    assert!(never_connected(&held));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_symlink_at_the_socket_path_is_refused_unconnected() {
    let dir = scratch("link");
    let elsewhere = dir.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let real = elsewhere.join("real.sock");
    let held = untouched(&real);
    let socket = own_socket(&dir);
    symlink(&real, &socket).unwrap();
    registry_file(&dir, "2.json", std::process::id(), &socket);
    let delivery = go(&adapter(&dir));
    assert!(
        matches!(&delivery, Delivery::Untrusted { reason } if reason.contains("Symlink")),
        "{delivery:?}"
    );
    assert!(never_connected(&held));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_regular_file_at_the_socket_path_is_refused() {
    let dir = scratch("regular");
    let socket = own_socket(&dir);
    fs::write(&socket, "").unwrap();
    registry_file(&dir, "2.json", std::process::id(), &socket);
    let delivery = go(&adapter(&dir));
    assert!(
        matches!(&delivery, Delivery::Untrusted { reason } if reason.contains("Regular")),
        "{delivery:?}"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_socket_of_another_owner_is_refused_unconnected() {
    let dir = scratch("owner");
    let socket = own_socket(&dir);
    let held = untouched(&socket);
    registry_file(&dir, "2.json", std::process::id(), &socket);
    let other = current_uid().wrapping_add(1);
    let delivery = go(&adapter(&dir).with_agent_uid(other));
    assert!(
        matches!(&delivery, Delivery::Untrusted { reason } if reason.contains(&format!("expected a directory of uid {other}"))),
        "{delivery:?}"
    );
    assert!(never_connected(&held));
    let socket_of = |uid| PathFacts {
        kind: PathKind::Socket,
        uid,
    };
    assert!(check_socket_facts(socket_of(current_uid()), current_uid()).is_ok());
    assert!(check_socket_facts(socket_of(other), current_uid()).is_err());
    for kind in [
        PathKind::Symlink,
        PathKind::Regular,
        PathKind::Directory,
        PathKind::Other,
    ] {
        let facts = PathFacts {
            kind,
            uid: current_uid(),
        };
        assert!(
            check_socket_facts(facts, current_uid()).is_err(),
            "{kind:?}"
        );
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_transcript_outside_the_projects_directory_reports_no_context() {
    let dir = scratch("transcript-link");
    registry_file(&dir, "2.json", std::process::id(), &own_socket(&dir));
    let name = format!("{SESSION_ID}.jsonl");
    let outside = dir.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join(&name), TRANSCRIPT_TAIL).unwrap();
    let projects = dir.join("projects");
    fs::create_dir_all(&projects).unwrap();
    let project = projects.join("-w");
    symlink(&outside, &project).unwrap();
    let linked_dir = adapter(&dir).context_size(&session());
    assert!(
        matches!(linked_dir, ContextReport::Unrecognised { .. }),
        "{linked_dir:?}"
    );
    fs::remove_file(&project).unwrap();
    fs::create_dir(&project).unwrap();
    symlink(outside.join(&name), project.join(&name)).unwrap();
    let linked_file = adapter(&dir).context_size(&session());
    assert!(
        matches!(linked_file, ContextReport::Unrecognised { .. }),
        "{linked_file:?}"
    );
    fs::remove_file(project.join(&name)).unwrap();
    fs::write(project.join(&name), TRANSCRIPT_TAIL).unwrap();
    let other_owner = adapter(&dir)
        .with_agent_uid(current_uid().wrapping_add(1))
        .context_size(&session());
    assert!(
        matches!(other_owner, ContextReport::Unrecognised { .. }),
        "{other_owner:?}"
    );
    assert_eq!(
        adapter(&dir).context_size(&session()),
        ContextReport::Tokens { tokens: 41_913 }
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_listener_of_another_uid_is_refused_before_any_byte_is_written() {
    let dir = scratch("peer");
    let socket = own_socket(&dir);
    let listener = untouched(&socket);
    let line = instruction_line(&ShortText::parse("go").unwrap());
    let delivery = post(&socket, &line, current_uid().wrapping_add(1));
    assert!(
        matches!(&delivery, Delivery::Untrusted { reason } if reason.contains("listener runs as uid")),
        "{delivery:?}"
    );
    assert!(!delivery.written());
    let (mut accepted, _) = listener.accept().unwrap();
    accepted.set_nonblocking(false).unwrap();
    let mut received = Vec::new();
    accepted.read_to_end(&mut received).unwrap();
    assert!(received.is_empty(), "{received:?}");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_socket_in_any_vendor_directory_is_posted_and_one_elsewhere_refused() {
    let dir = scratch("dirs");
    let first = dir.join("first");
    let second = dir.join("second");
    let other = dir.join("other");
    for each in [&first, &second, &other] {
        fs::create_dir_all(each).unwrap();
    }
    let control = adapter(&dir).with_sockets_dirs(vec![first.clone(), second.clone()]);
    for each in [&first, &second] {
        let socket = own_socket(each);
        registry_file(&dir, "2.json", std::process::id(), &socket);
        let server = listener(&socket, b"");
        assert!(matches!(go(&control), Delivery::Posted { .. }), "{each:?}");
        server.join().unwrap();
    }
    let socket = own_socket(&other);
    let held = untouched(&socket);
    registry_file(&dir, "2.json", std::process::id(), &socket);
    assert!(matches!(go(&control), Delivery::Untrusted { .. }));
    assert!(never_connected(&held));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_symlinked_sockets_directory_is_refused_by_real_dir() {
    let dir = scratch("dirlink");
    let real = dir.join("real");
    fs::create_dir_all(&real).unwrap();
    let link = dir.join("cc-socks");
    symlink(&real, &link).unwrap();
    assert!(matches!(real_dir(&real, current_uid()), DirState::Real));
    assert!(matches!(
        real_dir(&link, current_uid()),
        DirState::Refused(_)
    ));
    assert!(matches!(
        real_dir(&dir.join("absent"), current_uid()),
        DirState::Missing
    ));
    assert!(matches!(
        real_dir(&real, current_uid().wrapping_add(1)),
        DirState::Refused(_)
    ));
    let held = untouched(&own_socket(&real));
    registry_file(&dir, "2.json", std::process::id(), &own_socket(&link));
    let delivery = go(&adapter(&dir).with_sockets_dirs(vec![link]));
    assert!(
        matches!(&delivery, Delivery::Untrusted { reason } if reason.contains("Symlink")),
        "{delivery:?}"
    );
    assert!(never_connected(&held));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_sockets_directory_the_core_cannot_search_sends_the_instruction_to_the_relay() {
    let dir = scratch("eacces");
    let sockets = dir.join("socks");
    fs::create_dir_all(&sockets).unwrap();
    let socket = own_socket(&sockets);
    let _held = UnixListener::bind(&socket).unwrap();
    registry_file(&dir, "2.json", std::process::id(), &socket);
    fs::set_permissions(&sockets, fs::Permissions::from_mode(0o000)).unwrap();
    let checked = check_socket(&socket, current_uid());
    let agent = AgentDirs::new(dir.join("agent")).unwrap();
    fs::create_dir_all(&agent.socket_dir).unwrap();
    let relaying = adapter(&dir)
        .with_sockets_dirs(vec![sockets.clone()])
        .with_relay(agent, RelayMode::OnRefusal);
    let delivery = go(&relaying);
    fs::set_permissions(&sockets, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(checked, Err(Delivery::Denied { .. })),
        "{checked:?}"
    );
    assert!(matches!(delivery, Delivery::Relayed { .. }), "{delivery:?}");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_launchers_lookup_refuses_a_mismatched_pid_and_hands_on_an_unbound_socket() {
    let dir = scratch("launcher-pid");
    let pid = std::process::id();
    let sockets = [dir.clone()];
    let lookup = || socket_in_registry(&dir, pid, &sockets, current_uid());
    assert_eq!(lookup(), Ok(None));
    let socket = own_socket(&dir);
    registry_file(&dir, &format!("{pid}.json"), pid.wrapping_add(1), &socket);
    assert!(matches!(lookup(), Err(reason) if reason.contains("names pid")));
    registry_file(&dir, &format!("{pid}.json"), pid, &socket);
    assert_eq!(lookup(), Ok(Some(socket.clone())), "not bound yet");
    let _held = UnixListener::bind(&socket).unwrap();
    assert_eq!(lookup(), Ok(Some(socket)));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_launchers_lookup_refuses_an_untrusted_socket() {
    let dir = scratch("launcher-refused");
    let pid = std::process::id();
    let sockets = [dir.clone()];
    let lookup = |uid| socket_in_registry(&dir, pid, &sockets, uid);
    let socket = own_socket(&dir);
    registry_file(&dir, &format!("{pid}.json"), pid, &socket);
    let held = UnixListener::bind(&socket).unwrap();
    assert!(
        matches!(lookup(current_uid().wrapping_add(1)), Err(reason) if reason.contains("Untrusted"))
    );
    drop(held);
    fs::remove_file(&socket).unwrap();
    fs::write(&socket, "").unwrap();
    assert!(matches!(lookup(current_uid()), Err(reason) if reason.contains("Regular")));
    let elsewhere = dir.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    registry_file(&dir, &format!("{pid}.json"), pid, &own_socket(&elsewhere));
    assert!(matches!(lookup(current_uid()), Err(reason) if reason.contains("is not in")));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_fifo_or_directory_at_the_transcript_path_reports_no_context_without_blocking() {
    let dir = scratch("transcript-type");
    registry_file(&dir, "2.json", std::process::id(), &own_socket(&dir));
    let project = dir.join("projects").join("-w");
    fs::create_dir_all(&project).unwrap();
    let transcript = project.join(format!("{SESSION_ID}.jsonl"));
    nix::unistd::mkfifo(&transcript, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let config_dir = dir.clone();
    thread::spawn(move || {
        if sender
            .send(adapter(&config_dir).context_size(&session()))
            .is_err()
        {}
    });
    let fifo = receiver.recv_timeout(Duration::from_secs(2));
    assert!(
        matches!(fifo, Ok(ContextReport::Unrecognised { .. })),
        "{fifo:?}"
    );
    fs::remove_file(&transcript).unwrap();
    fs::create_dir(&transcript).unwrap();
    let directory = adapter(&dir).context_size(&session());
    assert!(
        matches!(directory, ContextReport::Unrecognised { .. }),
        "{directory:?}"
    );
    fs::remove_dir_all(&dir).unwrap();
}

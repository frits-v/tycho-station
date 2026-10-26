use super::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;

use crate::credentials::tests::CLAUDE_TOKEN;

const RESPONSE_MAX_BYTES: u64 = 4096;
const HEAD_MAX_BYTES: usize = 4096;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn hosts(names: &[&str]) -> Vec<String> {
    names.iter().map(ToString::to_string).collect()
}

/// Sends one request head and reads the status line of the answer.
fn status_of(port: u16, head: &str) -> String {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream.write_all(head.as_bytes()).unwrap();
    let mut answer = Vec::new();
    drop(stream.take(RESPONSE_MAX_BYTES).read_to_end(&mut answer));
    String::from_utf8_lossy(&answer)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

fn connect_head(target: &str, token: Option<&str>) -> String {
    let auth = token.map_or_else(String::new, |token| {
        format!("Proxy-Authorization: Bearer {token}\r\n")
    });
    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n")
}

#[test]
fn the_proxy_listens_on_loopback_and_hands_the_child_only_the_named_variables() {
    let proxy = SessionProxy::start(&hosts(&["api.anthropic.com"]), None).unwrap();
    assert_ne!(proxy.port(), 0);
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).is_ok());
    let names = proxy.child_environment_names();
    assert!(
        names
            .iter()
            .all(|name| CHILD_ENVIRONMENT_NAMES.contains(&name.as_str())),
        "{names:?}"
    );
    let environment = proxy.child_environment();
    let https = environment
        .iter()
        .find(|(name, _)| name == "HTTPS_PROXY")
        .map(|(_, value)| value.clone())
        .unwrap();
    assert!(
        https.ends_with(&format!("@127.0.0.1:{}", proxy.port())),
        "the proxy URL names another listener"
    );
    assert!(!format!("{proxy:?}").contains(proxy.handle.token.as_str()));
    let record = proxy.stop();
    assert_eq!(record, ProxyRecord::default());
}

#[test]
fn a_connect_to_a_host_off_the_allowlist_is_refused_and_recorded_with_or_without_the_token() {
    let proxy = SessionProxy::start(&hosts(&["api.anthropic.com"]), None).unwrap();
    let token = proxy.handle.token.to_string();
    for given in [Some(token.as_str()), Some("not-the-token"), None] {
        let status = status_of(proxy.port(), &connect_head("github.com:443", given));
        assert!(status.contains(" 403 "), "{status}");
    }
    let record = proxy.stop();
    assert_eq!(record.denied, 3);
    assert_eq!(record.allowed, 0);
    assert_eq!(record.denied_targets, ["github.com:443"]);
}

#[test]
fn an_empty_allowlist_refuses_every_host() {
    let proxy = SessionProxy::start(&[], None).unwrap();
    let token = proxy.handle.token.to_string();
    let status = status_of(
        proxy.port(),
        &connect_head("api.anthropic.com:443", Some(&token)),
    );
    assert!(status.contains(" 403 "), "{status}");
    assert_eq!(proxy.stop().denied, 1);
}

fn refused(status: &str) -> bool {
    status.is_empty()
        || [" 400 ", " 401 ", " 403 ", " 404 ", " 407 "]
            .iter()
            .any(|code| status.contains(code))
}

/// With no credential route a request in origin form is never forwarded, whatever bearer it
/// carries: the proxy drops it or refuses it.
#[test]
fn a_plain_request_is_refused_without_a_route_whatever_its_bearer() {
    let proxy = SessionProxy::start(&hosts(&["api.anthropic.com"]), None).unwrap();
    let token = proxy.handle.token.to_string();
    for bearer in [token.as_str(), "phantom", ""] {
        let head = format!(
            "GET /anthropic/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {bearer}\r\n\r\n"
        );
        let status = status_of(proxy.port(), &head);
        assert!(refused(&status), "{status}");
    }
    drop(proxy.stop());
}

/// The proxy is no way around the sandbox to the core: a tunnel or a forwarded request to
/// loopback, the core's ports included, is refused like any host off the allowlist.
#[test]
fn the_proxy_refuses_loopback_and_every_core_port() {
    let proxy = SessionProxy::start(&hosts(&["api.anthropic.com"]), None).unwrap();
    let token = proxy.handle.token.to_string();
    let mut examined = 0_usize;
    for port in crate::sandbox::core_ports(crate::config::CorePorts::PRODUCTION) {
        for host in ["127.0.0.1", "localhost", "[::1]"] {
            let target = format!("{host}:{port}");
            let tunnel = status_of(proxy.port(), &connect_head(&target, Some(&token)));
            assert!(tunnel.contains(" 403 "), "CONNECT {target}: {tunnel}");
            let forward = status_of(
                proxy.port(),
                &format!(
                    "GET http://{target}/health HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
                ),
            );
            assert!(refused(&forward), "GET http://{target}: {forward}");
            examined += 1;
        }
    }
    assert_eq!(examined, 15);
    let record = proxy.stop();
    assert_eq!(record.allowed, 0, "{record}");
}

#[test]
fn a_record_counts_every_decision_and_names_each_refused_target_once_within_its_bound() {
    let event = |decision: &str, target: String| -> NetworkAuditEvent {
        serde_json::from_value(serde_json::json!({
            "timestamp_unix_ms": 1, "mode": "connect", "decision": decision,
            "target": target, "port": 443
        }))
        .unwrap()
    };
    let mut events = vec![event("allow", "api.anthropic.com".into())];
    for index in 0..(DENIED_TARGETS_MAX + 5) {
        events.push(event("deny", format!("h{index}.example.com")));
        events.push(event("deny", format!("h{index}.example.com")));
    }
    let record = ProxyRecord::of(&events);
    assert!(!record.at_cap);
    assert_eq!(record.allowed, 1);
    assert_eq!(record.denied, 2 * (DENIED_TARGETS_MAX + 5));
    assert_eq!(record.denied_targets.len(), DENIED_TARGETS_MAX);
    assert_eq!(record.denied_targets[0], "h0.example.com:443");
}

#[test]
fn a_record_at_the_proxy_s_cap_says_later_events_were_dropped() {
    let event: NetworkAuditEvent = serde_json::from_value(serde_json::json!({
        "timestamp_unix_ms": 1, "mode": "connect", "decision": "allow",
        "target": "api.anthropic.com", "port": 443
    }))
    .unwrap();
    let record = ProxyRecord::of(&vec![event; AUDIT_EVENTS_MAX]);
    assert!(record.at_cap);
    assert!(
        record
            .to_string()
            .contains("cap of 4096 events was reached"),
        "{record}"
    );
}

fn handed() -> Option<HandedToken> {
    HandedToken::of(&Credential::parse(CredentialVendor::Claude, CLAUDE_TOKEN.as_bytes()).unwrap())
}

fn value_of<'a>(environment: &'a [(String, String)], name: &str) -> Option<&'a str> {
    environment
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// A Claude session's vendor gets the route's base URL and the phantom, which is the proxy's
/// session token, and the handed token in no value at all.
#[test]
fn a_handed_token_gives_the_vendor_the_phantom_and_the_base_url_and_never_itself() {
    let proxy = SessionProxy::start(&hosts(&["api.anthropic.com"]), handed()).unwrap();
    let environment = proxy.child_environment();
    let session_token = proxy.handle.token.to_string();
    assert_eq!(
        value_of(&environment, CLAUDE_TOKEN_ENV),
        Some(session_token.as_str())
    );
    assert_eq!(
        value_of(&environment, "NONO_PROXY_TOKEN"),
        Some(session_token.as_str())
    );
    assert_eq!(
        value_of(&environment, ANTHROPIC_BASE_URL_ENV),
        Some(format!("http://127.0.0.1:{}/{ANTHROPIC_ROUTE}", proxy.port()).as_str())
    );
    let mut examined = 0_usize;
    for (name, value) in &environment {
        assert!(
            CHILD_ENVIRONMENT_NAMES.contains(&name.as_str())
                || ROUTE_ENVIRONMENT_NAMES.contains(&name.as_str()),
            "{name} is not a name the vendor may be given"
        );
        assert!(
            !value.contains(CLAUDE_TOKEN),
            "{name} carries the handed token"
        );
        examined += 1;
    }
    assert!(examined >= ROUTE_ENVIRONMENT_NAMES.len() + 2, "{examined}");
    assert!(!format!("{proxy:?}").contains(CLAUDE_TOKEN));
    drop(proxy.stop());
}

/// Without a handed token there is no route, so neither the base URL nor a phantom.
#[test]
fn no_handed_token_means_no_route_and_no_phantom() {
    let proxy = SessionProxy::start(&hosts(&["api.anthropic.com"]), None).unwrap();
    let names = proxy.child_environment_names();
    for name in ROUTE_ENVIRONMENT_NAMES {
        assert!(!names.iter().any(|given| given == name), "{names:?}");
    }
    drop(proxy.stop());
}

/// An upstream on loopback that answers once and hands back the request head it read.
fn upstream() -> (u16, mpsc::Receiver<String>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while head.len() < HEAD_MAX_BYTES && !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => head.push(byte[0]),
                _ => break,
            }
        }
        drop(sender.send(String::from_utf8_lossy(&head).into_owned()));
        drop(
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"),
        );
    });
    (port, receiver)
}

fn route_request(bearer: &str) -> String {
    format!(
        "GET /{ANTHROPIC_ROUTE}/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {bearer}\r\nx-api-key: {OTHER_KEY}\r\nConnection: close\r\n\r\n"
    )
}

/// Another account's key a vendor may add beside the phantom.
const OTHER_KEY: &str = "sk-ant-api03-another-account";

/// The route swaps the phantom for the handed token on its way upstream and forwards nothing
/// for a bearer that is not the phantom. It passes an `x-api-key` the vendor added through
/// unchanged: nono-proxy 0.80.0 strips only the injected header and hop-by-hop headers, and
/// offers no hook to strip more, so another account's key rides along (design section 7,
/// residuals).
#[test]
fn the_route_sends_the_handed_token_upstream_in_place_of_the_phantom() {
    let (port, heads) = upstream();
    let route = RouteConfig {
        upstream: format!("http://127.0.0.1:{port}"),
        ..anthropic_route()
    };
    let config = ProxyConfig {
        routes: vec![route],
        ..config(&[], false)
    };
    let proxy = SessionProxy::start_with(config, handed()).unwrap();
    let phantom = proxy.handle.token.to_string();
    for bearer in ["not-the-phantom", CLAUDE_TOKEN] {
        let status = status_of(proxy.port(), &route_request(bearer));
        assert!(refused(&status), "{bearer}: {status}");
    }
    assert!(
        heads.recv_timeout(Duration::from_millis(500)).is_err(),
        "a request without the phantom reached the upstream"
    );
    let status = status_of(proxy.port(), &route_request(&phantom));
    assert!(status.contains(" 200 "), "{status}");
    let head = heads.recv_timeout(IO_TIMEOUT).unwrap();
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case(&format!("authorization: Bearer {CLAUDE_TOKEN}"))),
        "{head}"
    );
    assert!(
        !head.contains(&phantom),
        "the phantom went upstream: {head}"
    );
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case(&format!("x-api-key: {OTHER_KEY}"))),
        "the route now drops x-api-key; strike the residual in design section 7: {head}"
    );
    let record = proxy.stop();
    assert_eq!(record.denied, 2, "{record}");
    assert!(record.allowed >= 1, "{record}");
    assert_eq!(
        record.modes.keys().collect::<Vec<_>>(),
        ["reverse"],
        "{record}"
    );
}

/// A tunnel to the route's upstream is refused even with the session token, so the route,
/// where the proxy holds the token, is the only way to the model API.
#[test]
fn a_connect_to_the_route_s_upstream_is_refused_even_with_the_session_token() {
    let proxy = SessionProxy::start(&hosts(&["api.anthropic.com"]), handed()).unwrap();
    let token = proxy.handle.token.to_string();
    let status = status_of(
        proxy.port(),
        &connect_head("api.anthropic.com:443", Some(&token)),
    );
    assert!(status.contains(" 403 "), "{status}");
    let record = proxy.stop();
    assert_eq!(record.denied_targets, ["api.anthropic.com:443"], "{record}");
    assert_eq!(record.modes.get("connect").copied(), Some(1), "{record}");
}

#[test]
fn the_capture_backend_answers_only_the_route_s_credential() {
    let backend = InMemoryCredential {
        token: handed().unwrap(),
    };
    let request = |name: &str| CredentialCaptureRequest {
        credential_name: name.to_string(),
        route_id: ANTHROPIC_ROUTE.to_string(),
        request_host: "api.anthropic.com".to_string(),
        request_path: "/v1/models".to_string(),
        request_method: "GET".to_string(),
        session_id: "session".to_string(),
        cache_scope: "session".to_string(),
    };
    match backend.capture(request(ANTHROPIC_CREDENTIAL)) {
        Ok(CredentialCaptureResponse {
            material: CredentialCaptureMaterial::Secret(secret),
            ..
        }) => assert_eq!(secret.as_str(), CLAUDE_TOKEN),
        other => panic!("{:?}", other.map(|response| response.metadata)),
    }
    assert!(backend.capture(request("codex")).is_err());
    assert!(backend.capture(request("")).is_err());
}

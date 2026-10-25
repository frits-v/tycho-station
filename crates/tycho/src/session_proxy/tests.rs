use super::*;
use std::io::{Read, Write};
use std::net::TcpStream;

const RESPONSE_MAX_BYTES: u64 = 4096;
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
    let proxy = SessionProxy::start(&hosts(&["api.anthropic.com"])).unwrap();
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
    let proxy = SessionProxy::start(&hosts(&["api.anthropic.com"])).unwrap();
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
    let proxy = SessionProxy::start(&[]).unwrap();
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
    let proxy = SessionProxy::start(&hosts(&["api.anthropic.com"])).unwrap();
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
    let proxy = SessionProxy::start(&hosts(&["api.anthropic.com"])).unwrap();
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

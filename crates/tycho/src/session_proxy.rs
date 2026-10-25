//! The session proxy: a `nono_proxy` server on loopback for the life of one vendor.
//!
//! It is the only destination the vendor's sandbox lets it connect to. It admits a CONNECT
//! only to the vendor's allowed hosts and records each decision in memory. For a Claude
//! session it also serves the `anthropic` route: the vendor sends the proxy's session token
//! as its OAuth token, and the proxy swaps it for the token the hand-off put in the
//! launcher's memory, which never reaches the vendor.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use nono::undo::{NetworkAuditDecision, NetworkAuditEvent};
use nono_proxy::capture::{
    CredentialCaptureBackend, CredentialCaptureError, CredentialCaptureMaterial,
    CredentialCaptureMetadata, CredentialCaptureRequest, CredentialCaptureResponse,
};
use nono_proxy::config::{InjectMode, RouteConfig};
use nono_proxy::{ProxyConfig, ProxyHandle};
use zeroize::Zeroizing;

use crate::credentials::{CLAUDE_TOKEN_ENV, Credential, CredentialVendor};

/// The route Claude's model traffic takes: `ANTHROPIC_BASE_URL` points at the proxy under it.
pub const ANTHROPIC_ROUTE: &str = "anthropic";
pub const ANTHROPIC_UPSTREAM: &str = "https://api.anthropic.com";
/// The credential name the route asks the launcher's capture backend for; no command runs.
pub const ANTHROPIC_CREDENTIAL: &str = "claude";
/// The variable `credential_env_vars` sets for the route's base URL.
pub const ANTHROPIC_BASE_URL_ENV: &str = "ANTHROPIC_BASE_URL";

/// Worker threads of the proxy's runtime; one session's vendor is its only client.
const PROXY_THREADS: usize = 2;
/// How long stopping waits for the proxy's tasks before it drops them.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum ProxyError {
    Runtime(std::io::Error),
    Start(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => write!(formatter, "proxy runtime: {error}"),
            Self::Start(reason) => write!(formatter, "proxy did not start: {reason}"),
        }
    }
}

impl std::error::Error for ProxyError {}

/// The decisions one session's proxy made, counted, with the hosts it refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyRecord {
    pub allowed: usize,
    pub denied: usize,
    pub other: usize,
    /// Each refused destination once, in the order first refused.
    pub denied_targets: Vec<String>,
    /// The proxy held `AUDIT_EVENTS_MAX` events, so it dropped every later one.
    pub at_cap: bool,
    /// Events by the path they took: `connect` (an opaque tunnel), `connect_intercept` (a
    /// tunnel the proxy terminated to inject the credential), `reverse` (a request to the
    /// route's base URL), `external`.
    pub modes: BTreeMap<String, usize>,
}

/// nono-proxy 0.80.0 keeps at most this many audit events between drains and drops the rest,
/// so the counts of a longer session are a lower bound.
pub const AUDIT_EVENTS_MAX: usize = 4096;

/// Every name `child_environment` may set.
///
/// The proxy URL in both cases, the bypass list in both cases, nono's own two, and Node's
/// hint. A process the vendor starts in between, such as `tycho worker`, passes exactly
/// these on.
pub const CHILD_ENVIRONMENT_NAMES: [&str; 9] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "NONO_NO_PROXY",
    "NONO_PROXY_TOKEN",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "NODE_USE_ENV_PROXY",
];

/// The names the `anthropic` route adds: its base URL and the phantom, which is the proxy's
/// session token under the name Claude reads its OAuth token from.
pub const ROUTE_ENVIRONMENT_NAMES: [&str; 2] = [ANTHROPIC_BASE_URL_ENV, CLAUDE_TOKEN_ENV];

/// Refused destinations a record names; the counts cover every event the proxy kept.
pub const DENIED_TARGETS_MAX: usize = 32;

impl ProxyRecord {
    #[must_use]
    pub fn of(events: &[NetworkAuditEvent]) -> Self {
        let mut record = Self {
            at_cap: events.len() >= AUDIT_EVENTS_MAX,
            ..Self::default()
        };
        for event in events {
            let mode = serde_json::to_value(&event.mode)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_else(|| "unrecognised".to_string());
            let count = record.modes.entry(mode).or_insert(0);
            *count = count.saturating_add(1);
            match event.decision {
                NetworkAuditDecision::Allow => record.allowed = record.allowed.saturating_add(1),
                NetworkAuditDecision::Deny => {
                    record.denied = record.denied.saturating_add(1);
                    let target = format!("{}:{}", event.target, event.port.unwrap_or_default());
                    if record.denied_targets.len() < DENIED_TARGETS_MAX
                        && !record.denied_targets.contains(&target)
                    {
                        record.denied_targets.push(target);
                    }
                }
                _ => record.other = record.other.saturating_add(1),
            }
        }
        record
    }
}

impl fmt::Display for ProxyRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} allowed, {} denied, {} other; denied: [{}]",
            self.allowed,
            self.denied,
            self.other,
            self.denied_targets.join(", ")
        )?;
        let modes: Vec<String> = self
            .modes
            .iter()
            .map(|(mode, count)| format!("{mode}={count}"))
            .collect();
        write!(formatter, "; paths: [{}]", modes.join(", "))?;
        if self.at_cap {
            write!(
                formatter,
                "; the proxy's cap of {AUDIT_EVENTS_MAX} events was reached and later events \
                 were dropped"
            )?;
        }
        Ok(())
    }
}

/// The token the hand-off delivered, held for the proxy's capture backend; never logged.
pub struct HandedToken(Zeroizing<String>);

impl HandedToken {
    /// The Claude token of a credential; `None` for any other vendor's.
    #[must_use]
    pub fn of(credential: &Credential) -> Option<Self> {
        (credential.vendor() == CredentialVendor::Claude)
            .then(|| Self(Zeroizing::new(credential.expose().to_string())))
    }
}

impl fmt::Debug for HandedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HandedToken(redacted)")
    }
}

/// The proxy's credential capture backend: answers the route's one credential from memory and
/// refuses any other name. No command runs and no file is read.
#[derive(Debug)]
struct InMemoryCredential {
    token: HandedToken,
}

impl CredentialCaptureBackend for InMemoryCredential {
    fn capture(
        &self,
        request: CredentialCaptureRequest,
    ) -> Result<CredentialCaptureResponse, CredentialCaptureError> {
        let metadata = CredentialCaptureMetadata {
            cache_action: "memory".to_string(),
            ..CredentialCaptureMetadata::default()
        };
        if request.credential_name != ANTHROPIC_CREDENTIAL {
            return Err(CredentialCaptureError::new(
                format!("no credential named {:?}", request.credential_name),
                metadata,
            ));
        }
        Ok(CredentialCaptureResponse {
            material: CredentialCaptureMaterial::Secret(self.token.0.clone()),
            metadata,
        })
    }
}

/// The `anthropic` route: requests to `ANTHROPIC_BASE_URL` reach `api.anthropic.com` with
/// `Authorization: Bearer <handed token>` in place of the phantom the vendor sent, which is
/// the proxy's session token in `CLAUDE_CODE_OAUTH_TOKEN`.
#[must_use]
pub fn anthropic_route() -> RouteConfig {
    RouteConfig {
        prefix: ANTHROPIC_ROUTE.to_string(),
        upstream: ANTHROPIC_UPSTREAM.to_string(),
        credential_key: Some(format!("cmd://{ANTHROPIC_CREDENTIAL}")),
        redeem_phantoms: Vec::new(),
        inject_mode: InjectMode::Header,
        inject_header: "Authorization".to_string(),
        credential_format: Some("Bearer {}".to_string()),
        path_pattern: None,
        path_replacement: None,
        query_param_name: None,
        proxy: None,
        env_var: Some(CLAUDE_TOKEN_ENV.to_string()),
        ..RouteConfig::default()
    }
}

/// The configuration for one session: loopback, an ephemeral port, the vendor's hosts and no
/// other, the session token required, and the `anthropic` route when a token is handed.
#[must_use]
pub fn config(allowed_hosts: &[String], route: bool) -> ProxyConfig {
    ProxyConfig {
        bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        bind_port: 0,
        allowed_hosts: allowed_hosts.to_vec(),
        strict_filter: true,
        require_auth: true,
        enable_network_audit: true,
        routes: if route {
            vec![anthropic_route()]
        } else {
            Vec::new()
        },
        ..ProxyConfig::default()
    }
}

/// A running proxy and the runtime that serves it; stopped by `stop`, or when dropped.
pub struct SessionProxy {
    runtime: Option<tokio::runtime::Runtime>,
    handle: ProxyHandle,
    /// What the proxy started with; `credential_env_vars` reads the routes from it. It holds
    /// no secret: the token lives in the capture backend.
    config: ProxyConfig,
}

impl fmt::Debug for SessionProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionProxy")
            .field("port", &self.handle.port)
            .field("routes", &self.config.routes.len())
            .finish_non_exhaustive()
    }
}

impl SessionProxy {
    /// A proxy on the vendor's allowlist; with a handed token, also the `anthropic` route.
    pub fn start(allowed_hosts: &[String], token: Option<HandedToken>) -> Result<Self, ProxyError> {
        Self::start_with(config(allowed_hosts, token.is_some()), token)
    }

    fn start_with(config: ProxyConfig, token: Option<HandedToken>) -> Result<Self, ProxyError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(PROXY_THREADS)
            .thread_name("tycho-proxy")
            .enable_all()
            .build()
            .map_err(ProxyError::Runtime)?;
        let backend = token.map(|token| {
            Arc::new(InMemoryCredential { token }) as Arc<dyn CredentialCaptureBackend>
        });
        let handle = runtime
            .block_on(
                nono_proxy::server::start_with_approval_and_capture_registry(
                    config.clone(),
                    None,
                    backend,
                ),
            )
            .map_err(|error| ProxyError::Start(error.to_string()))?;
        Ok(Self {
            runtime: Some(runtime),
            handle,
            config,
        })
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.handle.port
    }

    /// What the vendor's environment gains: the proxy URL with the session token, `NO_PROXY`
    /// for loopback, the hint that makes Node's fetch use them, and for a route its base URL
    /// and the phantom, which is the same session token. The values carry that token, so
    /// they are never logged.
    #[must_use]
    pub fn child_environment(&self) -> Vec<(String, String)> {
        let mut pairs = self.handle.env_vars();
        pairs.extend(self.handle.credential_env_vars(&self.config));
        pairs
    }

    /// The names `child_environment` sets, for logs and tests.
    #[must_use]
    pub fn child_environment_names(&self) -> Vec<String> {
        self.child_environment()
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    /// Takes the decisions recorded so far.
    #[must_use]
    pub fn drain(&self) -> ProxyRecord {
        ProxyRecord::of(&self.handle.drain_audit_events())
    }

    /// Takes the recorded events themselves, for the session's audit file.
    #[must_use]
    pub fn drain_events(&self) -> Vec<NetworkAuditEvent> {
        self.handle.drain_audit_events()
    }

    /// Stops accepting, then gives the runtime a bounded time to finish.
    pub fn stop(mut self) -> ProxyRecord {
        let record = self.drain();
        self.shut_down();
        record
    }

    /// Stops accepting and hands back the events not yet drained.
    pub fn stop_with_events(mut self) -> Vec<NetworkAuditEvent> {
        let events = self.drain_events();
        self.shut_down();
        events
    }

    fn shut_down(&mut self) {
        self.handle.shutdown();
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(SHUTDOWN_GRACE);
        }
    }
}

impl Drop for SessionProxy {
    fn drop(&mut self) {
        self.shut_down();
    }
}

#[cfg(test)]
mod tests;

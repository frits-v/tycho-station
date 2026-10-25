//! The session proxy: a `nono_proxy` server on loopback for the life of one vendor.
//!
//! It is the only destination the vendor's sandbox lets it connect to. It admits a CONNECT
//! only to the vendor's allowed hosts and records every decision in memory.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use nono::undo::{NetworkAuditDecision, NetworkAuditEvent};
use nono_proxy::{ProxyConfig, ProxyHandle};

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

/// The configuration for one session: loopback, an ephemeral port, the vendor's hosts and no
/// other, the session token required, no credential route.
#[must_use]
pub fn config(allowed_hosts: &[String]) -> ProxyConfig {
    ProxyConfig {
        bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        bind_port: 0,
        allowed_hosts: allowed_hosts.to_vec(),
        strict_filter: true,
        require_auth: true,
        enable_network_audit: true,
        ..ProxyConfig::default()
    }
}

/// A running proxy and the runtime that serves it; stopped by `stop`, or when dropped.
pub struct SessionProxy {
    runtime: Option<tokio::runtime::Runtime>,
    handle: ProxyHandle,
}

impl fmt::Debug for SessionProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionProxy")
            .field("port", &self.handle.port)
            .finish_non_exhaustive()
    }
}

impl SessionProxy {
    pub fn start(allowed_hosts: &[String]) -> Result<Self, ProxyError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(PROXY_THREADS)
            .thread_name("tycho-proxy")
            .enable_all()
            .build()
            .map_err(ProxyError::Runtime)?;
        let handle = runtime
            .block_on(nono_proxy::start(config(allowed_hosts)))
            .map_err(|error| ProxyError::Start(error.to_string()))?;
        Ok(Self {
            runtime: Some(runtime),
            handle,
        })
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.handle.port
    }

    /// What the vendor's environment gains: the proxy URL with the session token, `NO_PROXY`
    /// for loopback, and the hint that makes Node's fetch use them. The values carry the
    /// session token, so they are never logged.
    #[must_use]
    pub fn child_environment(&self) -> Vec<(String, String)> {
        self.handle.env_vars()
    }

    /// The names `child_environment` sets, for logs and tests.
    #[must_use]
    pub fn child_environment_names(&self) -> Vec<String> {
        self.handle
            .env_vars()
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    /// Takes the decisions recorded so far.
    #[must_use]
    pub fn drain(&self) -> ProxyRecord {
        ProxyRecord::of(&self.handle.drain_audit_events())
    }

    /// Stops accepting, then gives the runtime a bounded time to finish.
    pub fn stop(mut self) -> ProxyRecord {
        let record = self.drain();
        self.shut_down();
        record
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

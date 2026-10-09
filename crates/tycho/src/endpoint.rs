//! Serves the Restate services over HTTP on a loopback port.

use std::io;
use std::net::SocketAddr;

use restate_sdk::prelude::{Endpoint, HttpServer};

use crate::probe::Probe;
use crate::services::epic::Epic;
use crate::services::operator::Operator;
use crate::services::reconciler::Reconciler;
use crate::services::session::Session;
use crate::services::work_unit::WorkUnit;
use crate::services::worker_run::WorkerRun;
use crate::services::Ports;

/// The probe and the spine services, built from the given ports.
#[must_use]
pub fn build(ports: &Ports) -> Endpoint {
    Endpoint::builder()
        .bind(Probe)
        .bind(Epic::new(ports))
        .bind(Session::new(ports))
        .bind(Reconciler::new(ports))
        .bind(Operator::new(ports.operator_secret.clone()))
        .bind(WorkUnit::new(ports))
        .bind(WorkerRun::new(ports))
        .build()
}

/// Blocks until the process receives ctrl-c or SIGTERM.
pub fn serve(address: SocketAddr, ports: &Ports) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let endpoint = build(ports);
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(address).await?;
        HttpServer::new(endpoint).serve(listener).await;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launch_probe::LAUNCH_PROBE_SERVICE;
    use crate::services::merge_gate::NoGate;
    use crate::services::spawner::NoLauncher;
    use crate::services::Timing;
    use std::sync::Arc;

    #[test]
    fn production_endpoint_never_binds_the_launch_probe() {
        let ports = Ports {
            spawner: Arc::new(NoLauncher),
            merge_gate: Arc::new(NoGate),
            timing: Timing::default(),
            config: Arc::new(crate::config_store::FactoryConfig::embedded().unwrap()),
            operator_secret: None,
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = build(&ports);
        runtime.spawn(async move { HttpServer::new(endpoint).serve(listener).await });
        let manifest = reqwest::blocking::Client::builder()
            .http2_prior_knowledge()
            .build()
            .unwrap()
            .get(format!("http://{address}/discover"))
            .header("accept", "application/vnd.restate.endpointmanifest.v3+json")
            .send()
            .unwrap()
            .text()
            .unwrap();
        runtime.shutdown_background();
        assert!(manifest.contains("\"Session\""), "{manifest}");
        assert!(!manifest.contains(LAUNCH_PROBE_SERVICE), "{manifest}");
    }
}

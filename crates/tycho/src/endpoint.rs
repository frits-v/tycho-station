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
        .bind(Epic)
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

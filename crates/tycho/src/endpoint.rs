//! Serves the Restate services over HTTP on a loopback port.

use std::io;
use std::net::SocketAddr;

use restate_sdk::prelude::{Endpoint, HttpServer};

use crate::probe::Probe;

/// Blocks until the process receives ctrl-c or SIGTERM.
pub fn serve(address: SocketAddr) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(address).await?;
        let endpoint = Endpoint::builder().bind(Probe).build();
        HttpServer::new(endpoint).serve(listener).await;
        Ok(())
    })
}

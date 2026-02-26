mod raw;

use crate::{Args, error, server::raw::handle_raw_connection};
use common::prelude::*;
use rustls::ServerConfig;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

pub async fn run_server(args: &Args, tls_config: Arc<ServerConfig>) -> error::Result<()> {
    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|e| error::Error::network(format!("failed to bind to {}: {e}", args.listen)))?;

    info!(listen = %args.listen, mode = %args.mode, "listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "accept error");
                continue;
            }
        };

        let config = tls_config.clone();
        tokio::spawn(match args.proto {
            ProtocolMode::Raw => handle_raw_connection(stream, peer, config),
            ProtocolMode::Http1 => todo!(),
        });
    }
}

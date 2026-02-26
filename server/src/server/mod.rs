mod http1;
mod raw;

use crate::{
    Args,
    error::{Error as ServerError, Result as ServerResult},
    server::{http1::handle_http1_connection, raw::handle_raw_connection},
};
use common::prelude::*;
use rustls::ServerConfig;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

pub async fn run_server(args: &Args, tls_config: Arc<ServerConfig>) -> ServerResult<()> {
    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|e| ServerError::network(format!("failed to bind to {}: {e}", args.listen)))?;

    info!(
        listen = %args.listen,
        mode = %args.mode,
        proto = %args.proto,
        "listening"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "accept error");
                continue;
            }
        };

        let config = tls_config.clone();
        let proto = args.proto;
        tokio::spawn(async move {
            match proto {
                ProtocolMode::Raw => handle_raw_connection(stream, peer, config).await,
                ProtocolMode::Http1 => handle_http1_connection(stream, peer, config).await,
            }
        });
    }
}

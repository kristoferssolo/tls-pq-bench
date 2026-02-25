use crate::{Args, error};
use common::protocol::{read_request, write_payload};
use rustls::{ServerConfig, server::Acceptor};
use std::{io::ErrorKind, net::SocketAddr, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};
use tokio_rustls::LazyConfigAcceptor;
use tracing::{debug, info, warn};

pub async fn handle_connection(stream: TcpStream, peer: SocketAddr, tls_config: Arc<ServerConfig>) {
    let acceptor = LazyConfigAcceptor::new(Acceptor::default(), stream);
    let start_handshake = match acceptor.await {
        Ok(sh) => sh,
        Err(e) => {
            return warn!(peer = %peer, error = %e, "TLS accept error");
        }
    };

    let mut tls_stream = match start_handshake.into_stream(tls_config).await {
        Ok(s) => s,
        Err(e) => {
            return warn!(peer = %peer, error = %e, "TLS handshake error");
        }
    };

    let (_, conn) = tls_stream.get_ref();
    info!(
        cipher = ?conn.negotiated_cipher_suite(),
        version = ?conn.protocol_version(),
        "connection established"
    );

    loop {
        let payload_size = match read_request(&mut tls_stream).await {
            Ok(size) => size,
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                debug!(peer = %peer, "client disconnected");
                break;
            }
            Err(e) => {
                warn!(peer = %peer, error = %e, "connection error");
                break;
            }
        };

        if let Err(e) = write_payload(&mut tls_stream, payload_size).await {
            warn!(peer = %peer, error = %e, "write error");
            break;
        }

        // Flush to ensure data is sent
        if let Err(e) = tls_stream.flush().await {
            warn!(peer = %peer, error = %e, "flush error");
            break;
        }
    }
}

pub async fn run_server(args: Args, tls_config: Arc<ServerConfig>) -> error::Result<()> {
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
        tokio::spawn(handle_connection(stream, peer, config));
    }
}

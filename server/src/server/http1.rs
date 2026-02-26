use bytes::Bytes;
use common::prelude::*;
use http_body_util::Full;
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{ALLOW, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue},
    server::conn::http1::Builder,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use rustls::{ServerConfig, server::Acceptor};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::net::TcpStream;
use tokio_rustls::LazyConfigAcceptor;
use tracing::{info, warn};

type RespBody = Full<Bytes>;

pub async fn handle_http1_connection(
    stream: TcpStream,
    peer: SocketAddr,
    tls_config: Arc<ServerConfig>,
) {
    let acceptor = LazyConfigAcceptor::new(Acceptor::default(), stream);
    let start_handshake = match acceptor.await {
        Ok(sh) => sh,
        Err(e) => {
            return warn!(peer = %peer, error = %e, "TLS accept error");
        }
    };

    let tls_stream = match start_handshake.into_stream(tls_config).await {
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

    let service = service_fn(move |req| async move { Ok::<_, Infallible>(handle_request(&req)) });

    let io = TokioIo::new(tls_stream);

    if let Err(e) = Builder::new()
        .keep_alive(false)
        .serve_connection(io, service)
        .await
    {
        warn!(peer = %peer, error = %e, "http1 serve error");
    }
}

fn handle_request(req: &Request<Incoming>) -> Response<RespBody> {
    if req.method() != Method::GET {
        let mut response = text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        response
            .headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET"));
        return response;
    }

    let n = match parse_bytes_path(req.uri().path()) {
        Ok(n) => n,
        Err(status) => {
            let msg = match status {
                StatusCode::NOT_FOUND => "not found",
                StatusCode::PAYLOAD_TOO_LARGE => "payload too large",
                _ => "bad request",
            };
            return text_response(status, msg);
        }
    };

    let payload = generate_payload(n);
    let mut response = Response::new(Full::new(Bytes::from(payload)));
    *response.status_mut() = StatusCode::OK;

    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(CONNECTION, HeaderValue::from_static("close"));

    #[allow(clippy::option_if_let_else)]
    match HeaderValue::from_str(&n.to_string()) {
        Ok(v) => {
            headers.insert(CONTENT_LENGTH, v);
            response
        }
        Err(_) => text_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
    }
}

fn parse_bytes_path(path: &str) -> Result<u64, StatusCode> {
    let Some(rest) = path.strip_prefix("/bytes/") else {
        return Err(StatusCode::NOT_FOUND);
    };

    if rest.is_empty() || rest.contains('/') {
        return Err(StatusCode::BAD_REQUEST);
    }

    let n = rest.parse::<u64>().map_err(|_| StatusCode::BAD_REQUEST)?;

    if n > MAX_PAYLOAD_SIZE {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    Ok(n)
}

fn text_response(status: StatusCode, msg: &'static str) -> Response<RespBody> {
    let mut response = Response::new(Full::new(Bytes::from_static(msg.as_bytes())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

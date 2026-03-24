use bytes::Bytes;
use common::prelude::*;
use futures::stream;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Frame,
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

type RespBody = BoxBody<Bytes, Infallible>;

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

fn handle_request<B>(req: &Request<B>) -> Response<RespBody> {
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

    let mut response = Response::new(steaming_payload_body(n));
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

#[allow(clippy::cast_possible_truncation)]
fn steaming_payload_body(size: u64) -> BoxBody<Bytes, Infallible> {
    const CHUNK_SIZE: usize = 64 * 1024;

    let stream = stream::unfold((size as usize, 0), |(remaining, offset)| async move {
        if remaining == 0 {
            return None;
        }
        let chunk_len = remaining.min(CHUNK_SIZE);
        let chunk = (0..chunk_len)
            .map(|i| ((offset + i) & 0xFF) as u8)
            .collect::<Vec<_>>();
        let frame = Frame::data(Bytes::from(chunk));

        Some((
            Ok::<_, Infallible>(frame),
            (remaining - chunk_len, offset + chunk_len),
        ))
    });

    StreamBody::new(stream).boxed()
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
    let mut response = Response::new(Full::new(Bytes::from_static(msg.as_bytes())).boxed());
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

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_none, assert_ok, assert_some};
    use http_body_util::BodyExt;

    fn make_get_request(uri: &str) -> Request<()> {
        assert_ok!(Request::builder().method(Method::GET).uri(uri).body(()))
    }

    #[test]
    fn parse_bytes_path_accepts_valid_numeric_size() {
        let min_n = assert_ok!(parse_bytes_path("/bytes/0"));
        assert_eq!(min_n, 0);

        let n = assert_ok!(parse_bytes_path("/bytes/1024"));
        assert_eq!(n, 1024);

        let max_n = assert_ok!(parse_bytes_path(&format!("/bytes/{MAX_PAYLOAD_SIZE}")));
        assert_eq!(max_n, MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn parse_bytes_path_rejects_non_bytes_prefix() {
        let status = assert_err!(parse_bytes_path("/foo/1024"));
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn parse_bytes_path_rejects_empty_size_segment() {
        let status = assert_err!(parse_bytes_path("/bytes/"));
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_bytes_path_rejects_non_numeric_size() {
        let status = assert_err!(parse_bytes_path("/bytes/foo"));
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_bytes_path_rejects_nested_segments() {
        let status = assert_err!(parse_bytes_path("/bytes/16/extra"));
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_bytes_path_rejects_payload_above_max() {
        let status = assert_err!(parse_bytes_path(&format!(
            "/bytes/{}",
            MAX_PAYLOAD_SIZE + 1
        )));
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn handle_request_get_bytes_returns_200_with_expected_headers() {
        let req = make_get_request("/bytes/16");

        let resp = handle_request(&req);
        assert_eq!(resp.status(), StatusCode::OK);

        let content_type = assert_some!(resp.headers().get("content-type"));
        assert_eq!(content_type, "application/octet-stream");

        let content_length = assert_some!(resp.headers().get("content-length"));
        assert_eq!(content_length, "16");

        let connection = assert_some!(resp.headers().get("connection"));
        assert_eq!(connection, "close");

        assert_none!(resp.headers().get("allow"));
    }

    #[tokio::test]
    async fn handle_request_get_bytes_returns_body_with_requested_length() {
        let req = make_get_request("/bytes/32");

        let resp = handle_request(&req);
        assert_eq!(resp.status(), StatusCode::OK);

        let content_length = assert_some!(resp.headers().get("content-length"));
        assert_eq!(content_length, "32");

        let body = assert_ok!(resp.into_body().collect().await).to_bytes();
        assert_eq!(body.len(), 32);

        assert_eq!(body[0], 0x00);
        assert_eq!(body[1], 0x01);
        assert_eq!(body[31], 0x1F);
    }

    #[test]
    fn handle_request_get_unknown_path_returns_404() {
        let req = make_get_request("/unknown");

        let resp = handle_request(&req);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let content_type = assert_some!(resp.headers().get("content-type"));
        assert_eq!(content_type, "text/plain; charset=utf-8");

        let connection = assert_some!(resp.headers().get("connection"));
        assert_eq!(connection, "close");
    }

    #[test]
    fn handle_request_post_bytes_returns_405_and_allow_get() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/bytes/32")
            .body(())
            .expect("post request");

        let resp = handle_request(&req);
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        let allow = assert_some!(resp.headers().get("allow"));
        assert_eq!(allow, "GET");

        let connection = assert_some!(resp.headers().get("connection"));
        assert_eq!(connection, "close");
    }

    #[test]
    fn handle_request_get_bytes_without_size_segment_returns_404() {
        let req = make_get_request("/bytes");

        let resp = handle_request(&req);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        assert_none!(resp.headers().get("content-length"));

        let connection = assert_some!(resp.headers().get("connection"));
        assert_eq!(connection, "close");
    }

    #[test]
    fn handle_request_get_bytes_with_non_numeric_size_returns_400() {
        let req = make_get_request("/bytes/foo");

        let resp = handle_request(&req);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        assert_none!(resp.headers().get("content-length"));

        let connection = assert_some!(resp.headers().get("connection"));
        assert_eq!(connection, "close");
    }

    #[test]
    fn handle_request_get_bytes_with_nested_path_returns_400() {
        let req = make_get_request("/bytes/16/extra");

        let resp = handle_request(&req);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        assert_none!(resp.headers().get("content-length"));

        let connection = assert_some!(resp.headers().get("connection"));
        assert_eq!(connection, "close");
    }

    #[test]
    fn handle_request_get_bytes_exceeding_max_payload_returns_413() {
        let req = make_get_request(&format!("/bytes/{}", MAX_PAYLOAD_SIZE + 1));

        let resp = handle_request(&req);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        assert_none!(resp.headers().get("content-length"));

        let connection = assert_some!(resp.headers().get("connection"));
        assert_eq!(connection, "close");
    }

    #[tokio::test]
    async fn handle_request_get_bytes_streams_across_chunk_boundry() {
        let req = make_get_request("/bytes/70000");

        let resp = handle_request(&req);
        assert_eq!(resp.status(), StatusCode::OK);

        let content_length = assert_some!(resp.headers().get("content-length"));
        assert_ok!(content_length.to_str(), "70000");

        let body = assert_ok!(resp.into_body().collect().await).to_bytes();
        assert_eq!(body.len(), 70_000);
        assert_eq!(body[0], 0x00);
        assert_eq!(body[255], 0xFF);
        assert_eq!(body[256], 0x00);
        assert_eq!(body[65_535], 0xFF);
        assert_eq!(body[65_536], 0x00);
    }
}

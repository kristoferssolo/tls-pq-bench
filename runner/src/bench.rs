use crate::config::BenchmarkConfig;
use common::prelude::*;
use futures::{StreamExt, stream::FuturesUnordered};
use miette::{Context, IntoDiagnostic};
use rustls::pki_types::ServerName;
use std::{
    io::{Write, stdout},
    net::SocketAddr,
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use tracing::info;

/// Result of a single benchmark iteration.
struct IterationResult {
    tcp: u128,
    handshake: u128,
    ttlb: u128,
}

pub async fn run_benchmark(
    config: &BenchmarkConfig,
    tls_connector: &TlsConnector,
    server_name: &ServerName<'static>,
) -> miette::Result<()> {
    let server = config.server;

    info!(
        warmup = config.warmup,
        iters = config.iters,
        concurrency = config.concurrency,
        "running benchmark iterations"
    );

    for _ in 0..config.warmup {
        run_iteration(
            server,
            config.proto,
            config.payload,
            tls_connector,
            server_name,
        )
        .await?;
    }
    info!("warmup complete");

    let mut output = stdout();
    run_and_write(config, tls_connector, server_name, &mut output).await?;
    output
        .flush()
        .into_diagnostic()
        .context("failed to flush output")?;

    info!("benchmark complete");
    Ok(())
}

async fn run_and_write<W: Write + Send>(
    config: &BenchmarkConfig,
    tls_connector: &TlsConnector,
    server_name: &ServerName<'static>,
    output: &mut W,
) -> miette::Result<()> {
    let mut in_flight = FuturesUnordered::new();
    let mut issued = 0;

    loop {
        while issued < config.iters && in_flight.len() < config.concurrency as usize {
            in_flight.push(run_single_iteration(
                issued,
                config.payload,
                config.proto,
                config.mode,
                config.server,
                tls_connector.clone(),
                server_name.clone(),
            ));
            issued += 1;
        }

        match in_flight.next().await {
            Some(record) => writeln!(output, "{}", record?)
                .into_diagnostic()
                .context("failed to write record")?,
            None => break,
        }
    }

    Ok(())
}

async fn run_single_iteration(
    i: u32,
    payload_bytes: u32,
    proto: ProtocolMode,
    mode: KeyExchangeMode,
    server: SocketAddr,
    tls_connector: TlsConnector,
    server_name: ServerName<'static>,
) -> miette::Result<BenchRecord> {
    let result = run_iteration(server, proto, payload_bytes, &tls_connector, &server_name).await?;

    Ok(BenchRecord {
        iteration: u64::from(i),
        proto,
        mode,
        payload_bytes: u64::from(payload_bytes),
        tcp_ns: result.tcp,
        handshake_ns: result.handshake,
        ttlb_ns: result.ttlb,
    })
}

/// Run a single benchmark iteration over TLS.
async fn run_iteration(
    server: SocketAddr,
    proto: ProtocolMode,
    payload_bytes: u32,
    tls_connector: &TlsConnector,
    server_name: &ServerName<'static>,
) -> miette::Result<IterationResult> {
    let tcp_start = Instant::now();

    let stream = TcpStream::connect(server)
        .await
        .into_diagnostic()
        .context("TCP connection failed")?;

    let tcp_ns = tcp_start.elapsed().as_nanos();

    let hs_start = Instant::now();
    let mut tls_stream = tls_connector
        .connect(server_name.clone(), stream)
        .await
        .into_diagnostic()
        .context("TLS handshake failed")?;

    let handshake_ns = hs_start.elapsed().as_nanos();

    let ttlb_start = Instant::now();
    run_exchange(&mut tls_stream, proto, payload_bytes).await?;

    let ttlb_ns = tcp_ns + handshake_ns + ttlb_start.elapsed().as_nanos();

    Ok(IterationResult {
        tcp: tcp_ns,
        handshake: handshake_ns,
        ttlb: ttlb_ns,
    })
}

async fn run_exchange<S>(
    tls_stream: &mut S,
    proto: ProtocolMode,
    payload_bytes: u32,
) -> miette::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match proto {
        ProtocolMode::Raw => run_raw_exchange(tls_stream, payload_bytes).await,
        ProtocolMode::Http1 => run_http1_exchange(tls_stream, payload_bytes).await,
    }
}

async fn run_raw_exchange<S>(tls_stream: &mut S, payload_bytes: u32) -> miette::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_request(tls_stream, u64::from(payload_bytes))
        .await
        .into_diagnostic()
        .context("write request failed")?;

    read_payload(tls_stream, u64::from(payload_bytes))
        .await
        .into_diagnostic()
        .context("read payload failed")?;
    Ok(())
}

async fn run_http1_exchange<S>(tls_stream: &mut S, payload_bytes: u32) -> miette::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = build_http1_request(payload_bytes);

    tls_stream
        .write_all(&request)
        .await
        .into_diagnostic()
        .context("write http1 request failed")?;

    tls_stream
        .flush()
        .await
        .into_diagnostic()
        .context("flush http1 request failed")?;

    let mut response_buf = Vec::with_capacity(1024);
    let mut chunk = [0; 1024];

    let (content_length, body_start) = loop {
        let n = tls_stream
            .read(&mut chunk)
            .await
            .into_diagnostic()
            .context("read http1 response failed")?;

        if n == 0 {
            return Err(common::Error::protocol("unexpected EOF before http1 headers").into());
        }

        response_buf.extend_from_slice(&chunk[..n]);

        if let Some(pos) = find_headers_end(&response_buf) {
            let headers = str::from_utf8(&response_buf[..pos])
                .into_diagnostic()
                .context("http1 headers are not valid UTF-8")?;
            let content_length = parse_content_length(headers)?;
            break (content_length, pos + 4);
        }
    };

    let body_already_read = response_buf.len() - body_start;
    if body_already_read > content_length {
        return Err(common::Error::protocol("http1 body exceeded content-length").into());
    }

    let mut remaining = content_length - body_already_read;
    let mut body_buf = vec![0; 64 * 1024];

    while remaining > 0 {
        let to_read = remaining.min(body_buf.len());
        tls_stream
            .read_exact(&mut body_buf[..to_read])
            .await
            .into_diagnostic()
            .context("read http1 body failed")?;
        remaining -= to_read;
    }

    Ok(())
}

fn build_http1_request(payload_bytes: u32) -> Vec<u8> {
    format!("GET /bytes/{payload_bytes} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

fn parse_content_length(headers: &str) -> miette::Result<usize> {
    let mut lines = headers.lines();

    let status_line = lines
        .next()
        .ok_or_else(|| common::Error::protocol("missing http1 status line"))?;

    let mut parts = status_line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| common::Error::protocol("missing http1 version"))?;
    let status = parts
        .next()
        .ok_or_else(|| common::Error::protocol("missing http1 status"))?;

    if version != "HTTP/1.1" {
        return Err(common::Error::protocol(format!("unsupported http version: {version}")).into());
    }
    if status != "200" {
        return Err(common::Error::protocol(format!("unsupported http status: {status}")).into());
    }

    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            return value
                .trim()
                .parse::<usize>()
                .into_diagnostic()
                .context("invalid content-length header");
        }
    }
    Err(common::Error::protocol("missing content-length header").into())
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_none, assert_ok, assert_some};

    #[test]
    fn build_http1_request_formats_get_requests() {
        let request = build_http1_request(16);
        let request_string = String::from_utf8(request).expect("valid string");
        assert_eq!(
            request_string,
            "GET /bytes/16 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn parse_content_length_accepts_200() {
        let headers = "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n";
        let len = assert_ok!(parse_content_length(headers));
        assert_eq!(len, 16);
    }

    #[test]
    fn parse_content_length_rejects_missing_header() {
        let headers = "HTTP/1.1 200 OK\r\nConnection: close\r\n";
        assert_err!(parse_content_length(headers));
    }

    #[test]
    fn parse_content_length_accepts_mixed_case_header_name() {
        let headers = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n";
        let len = assert_ok!(parse_content_length(headers));
        assert_eq!(len, 8);

        let headers = "HTTP/1.1 200 OK\r\ncontent-length: 9\r\nConnection: close\r\n";
        let len = assert_ok!(parse_content_length(headers));
        assert_eq!(len, 9);
    }

    #[test]
    fn parse_content_length_rejects_non_200_status() {
        let headers = "HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\nConnection: close\r\n";
        assert_err!(parse_content_length(headers));
    }

    #[test]
    fn parse_content_length_rejects_unsupported_http_version() {
        let headers = "HTTP/1.0 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n";
        assert_err!(parse_content_length(headers));
    }

    #[test]
    fn parse_content_length_rejects_invalid_numeric_value() {
        let headers = "HTTP/1.1 200 OK\r\nContent-Length: nope\r\nConnection: close\r\n";
        assert_err!(parse_content_length(headers));
    }

    #[test]
    fn find_headers_end_returns_none_when_separator_missing() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n";
        assert_none!(find_headers_end(response));
    }

    #[test]
    fn find_headers_end_returns_separator_offset() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody";
        let pos = assert_some!(find_headers_end(response));
        assert_eq!(pos, 34);
    }

    #[tokio::test]
    async fn run_http1_exchange_accepts_bytes_read_full_body() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut req = [0; 256];
            let n = server.read(&mut req).await.expect("read request");

            let request = str::from_utf8(&req[..n]).expect("utf8 request");
            assert!(request.starts_with("GET /bytes/16 HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            assert!(request.contains("Connection: close\r\n"));

            server
                .write_all( b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n0123456789abcdef")
                .await
                .expect("write response");
        });

        assert_ok!(run_http1_exchange(&mut client, 16).await);
        assert_ok!(server_task.await);
    }

    #[tokio::test]
    async fn run_http1_exchange_accepts_bytes_read_with_headers() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut req = [0; 256];
            let _ = server.read(&mut req).await.expect("read request");

            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody")
                .await
                .expect("write response");
        });

        assert_ok!(run_http1_exchange(&mut client, 4).await);
        assert_ok!(server_task.await);
    }

    #[tokio::test]
    async fn run_http1_exchange_rejects_missing_content_length() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut req = [0; 256];
            let _ = server.read(&mut req).await.expect("read request");

            server
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody")
                .await
                .expect("write response");
        });

        assert_err!(run_http1_exchange(&mut client, 4).await);
        assert_ok!(server_task.await);
    }

    #[tokio::test]
    async fn run_http1_exchange_reads_remaining_body_after_header_parse() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut req = [0_u8; 256];
            let _ = server.read(&mut req).await.expect("read request");

            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n12")
                .await
                .expect("write partial response");

            server
                .write_all(b"345678")
                .await
                .expect("write remaining body");
        });

        assert_ok!(run_http1_exchange(&mut client, 8).await);
        assert_ok!(server_task.await);
    }
}

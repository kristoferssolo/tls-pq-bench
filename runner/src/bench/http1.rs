use miette::{Context, IntoDiagnostic};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn run_http1_exchange<S>(
    tls_stream: &mut S,
    payload_bytes: u32,
    host_header: &str,
) -> miette::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = build_http1_request(payload_bytes, host_header);

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

fn build_http1_request(payload_bytes: u32, host_header: &str) -> Vec<u8> {
    format!(
        "GET /bytes/{payload_bytes} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
    )
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
        let request = build_http1_request(16, "bench.example.com");
        let request_string = String::from_utf8(request).expect("valid string");
        assert_eq!(
            request_string,
            "GET /bytes/16 HTTP/1.1\r\nHost: bench.example.com\r\nConnection: close\r\n\r\n"
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
            assert!(request.contains("Host: bench.example.com\r\n"));
            assert!(request.contains("Connection: close\r\n"));

            server
                .write_all( b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n0123456789abcdef")
                .await
                .expect("write response");
        });

        assert_ok!(run_http1_exchange(&mut client, 16, "bench.example.com").await);
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

        assert_ok!(run_http1_exchange(&mut client, 4, "bench.example.com").await);
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

        assert_err!(run_http1_exchange(&mut client, 4, "bench.example.com").await);
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

        assert_ok!(run_http1_exchange(&mut client, 8, "bench.example.com").await);
        assert_ok!(server_task.await);
    }
}

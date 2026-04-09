use common::prelude::*;
use miette::{Context, IntoDiagnostic};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

pub async fn run_raw_exchange<S>(tls_stream: &mut S, payload_bytes: u32) -> miette::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_request(tls_stream, payload_bytes)
        .await
        .into_diagnostic()
        .context("write request failed")?;

    tls_stream
        .flush()
        .await
        .into_diagnostic()
        .context("flush raw request failed")?;

    read_payload(tls_stream, payload_bytes)
        .await
        .into_diagnostic()
        .context("read payload failed")?;
    Ok(())
}

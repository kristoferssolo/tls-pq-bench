use common::prelude::*;
use miette::{Context, IntoDiagnostic};
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn run_raw_exchange<S>(tls_stream: &mut S, payload_bytes: u32) -> miette::Result<()>
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

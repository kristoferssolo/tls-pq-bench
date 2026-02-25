// Casts are intentional: MAX_PAYLOAD_SIZE (16 MiB) fits in usize on 64-bit,
// and byte patterns are explicitly masked to 0xFF before casting.
#![allow(clippy::cast_possible_truncation)]

use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Size of the request header (u64 payload size).
pub const REQUEST_SIZE: usize = 8;

/// Maximum allowed payload size (16 MiB).
pub const MAX_PAYLOAD_SIZE: u64 = 16 * 1024 * 1024;

/// Read the payload size request from a stream.
///
/// # Errors
/// Returns an error if reading fails or payload size exceeds maximum.
pub async fn read_request<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<u64> {
    let mut buf = [0u8; REQUEST_SIZE];
    reader.read_exact(&mut buf).await?;
    let size = u64::from_le_bytes(buf);

    if size > MAX_PAYLOAD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("payload size {size} exceeds maximum {MAX_PAYLOAD_SIZE}"),
        ));
    }

    Ok(size)
}

/// Write a payload size request to a stream.
///
/// # Errors
/// Returns an error if writing fails.
pub async fn write_request<W: AsyncWriteExt + Unpin>(writer: &mut W, size: u64) -> io::Result<()> {
    let buf = size.to_le_bytes();
    writer.write_all(&buf).await
}

/// Generate deterministic payload of the given size.
///
/// The pattern is a repeating sequence: 0x00, 0x01, ..., 0xFF, 0x00, ...
#[must_use]
pub fn generate_payload(size: u64) -> Vec<u8> {
    (0..size).map(|i| (i & 0xFF) as u8).collect()
}

/// Write deterministic payload to a stream.
///
/// Writes in chunks to avoid allocating large buffers.
///
/// # Errors
/// Returns an error if writing fails.
pub async fn write_payload<W: AsyncWriteExt + Unpin>(writer: &mut W, size: u64) -> io::Result<()> {
    const CHUNK_SIZE: usize = 64 * 1024;
    let mut remaining = size as usize;
    let mut offset = 0;

    while remaining > 0 {
        let chunk_len = remaining.min(CHUNK_SIZE);
        let chunk = (0..chunk_len)
            .map(|i| ((offset + i) & 0xFF) as u8)
            .collect::<Vec<_>>();
        writer.write_all(&chunk).await?;
        remaining -= chunk_len;
        offset += chunk_len;
    }

    Ok(())
}

/// Read and discard payload from a stream, returning the number of bytes read.
///
/// # Errors
/// Returns an error if reading fails.
pub async fn read_payload<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    expected_size: u64,
) -> io::Result<u64> {
    const CHUNK_SIZE: usize = 64 * 1024;
    let mut buf = vec![0; CHUNK_SIZE];
    let mut total_read = 0;

    while total_read < expected_size {
        let to_read = ((expected_size - total_read) as usize).min(CHUNK_SIZE);
        reader.read_exact(&mut buf[..to_read]).await?;
        total_read += to_read as u64;
    }

    Ok(total_read)
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use std::io::Cursor;

    #[test]
    fn generate_payload_pattern() {
        let payload = generate_payload(300);
        assert_eq!(payload.len(), 300);
        assert_eq!(payload[0], 0x00);
        assert_eq!(payload[255], 0xFF);
        assert_eq!(payload[256], 0x00);
        assert_eq!(payload[299], 43);
    }

    #[test]
    fn generate_payload_empty() {
        let payload = generate_payload(0);
        assert_eq!(payload.len(), 0);
    }

    #[test]
    fn generate_payload_chunk_boundary() {
        let payload = generate_payload(64 * 1024);
        assert_eq!(payload.len(), 65_536);
        assert_eq!(payload[255], 0xFF);
        assert_eq!(payload[256], 0x00);
        assert_eq!(payload[65_535], 255);
    }

    #[test]
    fn generate_payload_at_max_size() {
        let payload = generate_payload(MAX_PAYLOAD_SIZE);
        assert_eq!(payload.len(), 16_777_216);
        assert_eq!(payload[255], 0xFF);
        assert_eq!(payload[256], 0x00);
        assert_eq!(payload[MAX_PAYLOAD_SIZE as usize - 1], 255);
    }

    #[tokio::test]
    async fn roundtrip_request() {
        let mut buf = Vec::new();
        assert_ok!(write_request(&mut buf, 12_345).await);
        assert_eq!(buf.len(), REQUEST_SIZE);

        let mut cursor = Cursor::new(buf);
        let size = assert_ok!(read_request(&mut cursor).await);
        assert_eq!(size, 12345);
    }

    #[tokio::test]
    async fn reject_oversized_request() {
        let buf = (MAX_PAYLOAD_SIZE + 1).to_le_bytes();
        let mut cursor = Cursor::new(buf);
        let result = read_request(&mut cursor).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn read_payload_exact_size() {
        let payload = generate_payload(500);
        let mut cursor = Cursor::new(payload.clone());
        let read = assert_ok!(read_payload(&mut cursor, 500).await);
        assert_eq!(read, 500);
    }

    #[tokio::test]
    async fn write_payload_chunk_boundary() {
        let size = 64 * 1024;
        let mut buf = Vec::new();
        assert_ok!(write_payload(&mut buf, size as u64).await);
        assert_eq!(buf.len(), size);
        assert_eq!(buf[0], 0x00);
        assert_eq!(buf[size - 1], 0xFF);
    }
}

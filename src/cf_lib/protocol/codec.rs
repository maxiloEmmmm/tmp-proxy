use capnp::message::{Builder, HeapAllocator, Reader, ReaderOptions, ReaderSegments};
use std::io::Cursor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::cf_lib::CfError;

const MAX_SEGMENTS: usize = 64;
const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// Reads one unpacked Cap'n Proto message from an asynchronous stream.
///
/// Example: segment table plus payload -> parsed message reader.
pub(crate) async fn read_message<R>(
    stream: &mut R,
) -> Result<Reader<capnp::serialize::OwnedSegments>, CfError>
where
    R: AsyncRead + Unpin,
{
    let segment_count_minus_one = stream
        .read_u32_le()
        .await
        .map_err(|error| CfError::new(format!("read capnp segment count failed: {error}")))?;
    let segment_count = segment_count_minus_one as usize + 1;
    if segment_count > MAX_SEGMENTS {
        return Err(CfError::new(format!(
            "capnp message has too many segments: {segment_count}"
        )));
    }

    let mut sizes = Vec::with_capacity(segment_count);
    let mut payload_bytes = 0usize;
    for _ in 0..segment_count {
        let words = stream
            .read_u32_le()
            .await
            .map_err(|error| CfError::new(format!("read capnp segment size failed: {error}")))?;
        let bytes = (words as usize)
            .checked_mul(8)
            .ok_or_else(|| CfError::new("capnp segment size overflow"))?;
        payload_bytes = payload_bytes
            .checked_add(bytes)
            .ok_or_else(|| CfError::new("capnp message size overflow"))?;
        sizes.push(words);
    }
    if payload_bytes > MAX_MESSAGE_BYTES {
        return Err(CfError::new(format!(
            "capnp message exceeds {MAX_MESSAGE_BYTES} bytes"
        )));
    }

    // Trigger: an even segment count makes the table contain an odd number
    // of u32 values. Cap'n Proto pads tables to a whole 64-bit word.
    // Directly reading payload would shift every segment by four bytes.
    // Consuming this padding prevents corrupt request and RPC decoding.
    if segment_count % 2 == 0 {
        let _padding = stream
            .read_u32_le()
            .await
            .map_err(|error| CfError::new(format!("read capnp table padding failed: {error}")))?;
    }

    let table_words = 1 + segment_count + usize::from(segment_count % 2 == 0);
    let mut encoded = Vec::with_capacity(table_words * 4 + payload_bytes);
    encoded.extend_from_slice(&segment_count_minus_one.to_le_bytes());
    for size in sizes {
        encoded.extend_from_slice(&size.to_le_bytes());
    }
    if segment_count % 2 == 0 {
        encoded.extend_from_slice(&0_u32.to_le_bytes());
    }
    let table_bytes = encoded.len();
    encoded.resize(table_bytes + payload_bytes, 0);
    stream
        .read_exact(&mut encoded[table_bytes..])
        .await
        .map_err(|error| CfError::new(format!("read capnp payload failed: {error}")))?;

    capnp::serialize::read_message(
        Cursor::new(encoded),
        ReaderOptions {
            traversal_limit_in_words: Some((MAX_MESSAGE_BYTES / 8) as usize),
            nesting_limit: 64,
        },
    )
    .map_err(|error| CfError::new(format!("decode capnp message failed: {error}")))
}

/// Encodes one unpacked Cap'n Proto message into owned bytes.
///
/// Example: message builder -> segment table plus payload bytes.
pub(crate) fn encode_message(message: &Builder<HeapAllocator>) -> Result<Vec<u8>, CfError> {
    let mut encoded = Vec::new();
    capnp::serialize::write_message(&mut encoded, message)
        .map_err(|error| CfError::new(format!("encode capnp message failed: {error}")))?;
    Ok(encoded)
}

/// Writes previously encoded Cap'n Proto bytes to an asynchronous stream.
///
/// Example: owned encoded frame -> flushed control or data stream.
pub(crate) async fn write_encoded<W>(stream: &mut W, encoded: &[u8]) -> Result<(), CfError>
where
    W: AsyncWrite + Unpin,
{
    stream
        .write_all(encoded)
        .await
        .map_err(|error| CfError::new(format!("write capnp message failed: {error}")))?;
    stream
        .flush()
        .await
        .map_err(|error| CfError::new(format!("flush capnp message failed: {error}")))
}

/// Reads a typed root from a parsed Cap'n Proto message.
///
/// Example: message reader plus generated type -> typed reader.
pub(crate) fn root<'a, T>(message: &'a Reader<impl ReaderSegments>) -> Result<T, CfError>
where
    T: capnp::traits::FromPointerReader<'a>,
{
    message
        .get_root::<T>()
        .map_err(|error| CfError::new(format!("read capnp root failed: {error}")))
}

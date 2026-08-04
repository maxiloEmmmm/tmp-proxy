use capnp::message::Builder;
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::cf_lib::protocol::codec;
use crate::cf_lib::protocol::quic_metadata_protocol_capnp::{
    connect_request, connect_response, ConnectionType,
};
use crate::cf_lib::{CfError, CfResponse, RequestKind};

pub(crate) const DATA_SIGNATURE: [u8; 6] = [0x0A, 0x36, 0xCD, 0x12, 0xA1, 0x3E];
const PROTOCOL_VERSION: [u8; 2] = *b"01";

/// Decoded Cloudflare QUIC request metadata.
///
/// Example: Cap'n Proto ConnectRequest -> application fields.
pub(crate) struct DataRequest {
    /// Request protocol kind.
    pub(crate) kind: RequestKind,
    /// Request destination.
    pub(crate) destination: String,
    /// Request metadata key-value pairs.
    pub(crate) metadata: HashMap<String, String>,
}

/// Reads and validates one Cloudflare QUIC data request.
///
/// Example: `signature + version + ConnectRequest -> DataRequest`.
pub(crate) async fn read_request<R>(stream: &mut R) -> Result<DataRequest, CfError>
where
    R: AsyncRead + Unpin,
{
    let mut signature = [0_u8; 6];
    stream
        .read_exact(&mut signature)
        .await
        .map_err(|error| CfError::new(format!("read data signature failed: {error}")))?;
    if signature != DATA_SIGNATURE {
        return Err(CfError::new(format!(
            "unknown Cloudflare data signature: {signature:02X?}"
        )));
    }
    let mut version = [0_u8; 2];
    stream
        .read_exact(&mut version)
        .await
        .map_err(|error| CfError::new(format!("read data protocol version failed: {error}")))?;
    if version != PROTOCOL_VERSION {
        return Err(CfError::new(format!(
            "unsupported Cloudflare data protocol version: {}",
            String::from_utf8_lossy(&version)
        )));
    }

    let message = codec::read_message(stream).await?;
    let request = codec::root::<connect_request::Reader<'_>>(&message)?;
    let kind = match request
        .get_type()
        .map_err(|error| CfError::new(format!("read request type failed: {error}")))?
    {
        ConnectionType::Http => RequestKind::Http,
        ConnectionType::Websocket => RequestKind::WebSocket,
        ConnectionType::Tcp => RequestKind::Tcp,
    };
    let destination = request
        .get_dest()
        .map_err(|error| CfError::new(format!("read request destination failed: {error}")))?
        .to_str()
        .map_err(|error| CfError::new(format!("request destination is not UTF-8: {error}")))?
        .to_string();
    let list = request
        .get_metadata()
        .map_err(|error| CfError::new(format!("read request metadata failed: {error}")))?;
    let mut metadata = HashMap::with_capacity(list.len() as usize);
    for entry in list {
        let key_text = entry
            .get_key()
            .map_err(|error| CfError::new(format!("read metadata key failed: {error}")))?;
        let key = key_text
            .to_str()
            .map_err(|error| CfError::new(format!("metadata key is not UTF-8: {error}")))?;
        let value_text = entry
            .get_val()
            .map_err(|error| CfError::new(format!("read metadata value failed: {error}")))?;
        let value = value_text
            .to_str()
            .map_err(|error| CfError::new(format!("metadata value is not UTF-8: {error}")))?;
        metadata.insert(key.to_string(), value.to_string());
    }
    Ok(DataRequest {
        kind,
        destination,
        metadata,
    })
}

/// Writes a successful Cloudflare QUIC data response.
///
/// Example: status `101` plus headers -> ConnectResponse metadata.
pub(crate) async fn write_response<W>(stream: &mut W, response: &CfResponse) -> Result<(), CfError>
where
    W: AsyncWrite + Unpin,
{
    let mut metadata = Vec::with_capacity(response.headers.len() + 1);
    metadata.push(("HttpStatus".to_string(), response.status.to_string()));
    for (name, value) in &response.headers {
        let value = value
            .to_str()
            .map_err(|error| CfError::new(format!("response header is not text: {error}")))?;
        metadata.push((format!("HttpHeader:{name}"), value.to_string()));
    }
    write_connect_response(stream, "", &metadata).await
}

/// Writes a rejected Cloudflare QUIC data response.
///
/// Example: status `403` -> ConnectResponse metadata.
pub(crate) async fn write_rejection<W>(stream: &mut W, status: u16) -> Result<(), CfError>
where
    W: AsyncWrite + Unpin,
{
    write_connect_response(
        stream,
        "",
        &[("HttpStatus".to_string(), status.to_string())],
    )
    .await
}

/// Encodes the common QUIC response preamble and Cap'n Proto body.
///
/// Example: empty error plus metadata -> accepted response frame.
async fn write_connect_response<W>(
    stream: &mut W,
    error: &str,
    metadata: &[(String, String)],
) -> Result<(), CfError>
where
    W: AsyncWrite + Unpin,
{
    let mut message = Builder::new_default();
    {
        let mut response = message.init_root::<connect_response::Builder<'_>>();
        response.set_error(error);
        let mut list = response.reborrow().init_metadata(metadata.len() as u32);
        for (index, (key, value)) in metadata.iter().enumerate() {
            let mut entry = list.reborrow().get(index as u32);
            entry.set_key(key);
            entry.set_val(value);
        }
    }
    let encoded = codec::encode_message(&message)?;
    drop(message);
    stream
        .write_all(&DATA_SIGNATURE)
        .await
        .map_err(|error| CfError::new(format!("write data signature failed: {error}")))?;
    stream
        .write_all(&PROTOCOL_VERSION)
        .await
        .map_err(|error| CfError::new(format!("write data protocol version failed: {error}")))?;
    codec::write_encoded(stream, &encoded).await
}

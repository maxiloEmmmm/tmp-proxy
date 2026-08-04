use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures_util::{SinkExt, StreamExt};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    tungstenite::protocol::{Message, Role},
    WebSocketStream,
};
use url::Url;

use crate::cf_lib::{CfResponse, CfStream, IncomingRequest, RequestKind};

const WEBSOCKET_PATH: &str = "/tcp";

/// Builds the public WSS URL containing the active access UUID.
///
/// Example: host plus UUID -> a WSS URL carrying the stable `code` key.
pub(crate) fn build_wss_url(hostname: &str, uuid: &str) -> Result<String, String> {
    let mut url = Url::parse(&format!("wss://{hostname}"))
        .map_err(|error| format!("build tunnel url failed: {error}"))?;
    url.set_path(WEBSOCKET_PATH);
    url.query_pairs_mut().append_pair("code", uuid);
    Ok(url.to_string())
}

/// Handles one authenticated Cloudflare WebSocket request.
///
/// Example: matching UUID -> TCP connection to the configured target.
pub(crate) async fn handle_request(
    request: IncomingRequest,
    target: String,
    expected_uuid: String,
) -> Result<(), String> {
    if !uuid_matches(&request, &expected_uuid) {
        reject_request(request, 403).await?;
        return Ok(());
    }
    if request.kind != RequestKind::WebSocket {
        reject_request(request, 404).await?;
        return Ok(());
    }

    let accept = websocket_accept_value(&request)?;
    let tcp = TcpStream::connect(&target)
        .await
        .map_err(|error| format!("connect target {target} failed: {error}"))?;
    let mut response = CfResponse::new(101);
    response.headers.insert(
        http::header::SEC_WEBSOCKET_ACCEPT,
        http::HeaderValue::from_str(&accept)
            .map_err(|error| format!("invalid websocket accept header: {error}"))?,
    );
    let stream = request
        .respond(response)
        .await
        .map_err(|error| format!("respond websocket failed: {error}"))?;
    let websocket = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
    bridge_tcp_websocket(tcp, websocket).await
}

/// Extracts the UUID carried in the stable `code` query key.
///
/// Example: `"/tcp?code=<uuid>" -> Some("<uuid>")`.
pub(crate) fn extract_uuid(raw: &str) -> Option<String> {
    let parsed = Url::parse(raw)
        .or_else(|_| Url::parse(&format!("wss://tmp.local{raw}")))
        .ok()?;
    parsed
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
}

/// Rejects one Cloudflare request before it reaches the target.
///
/// Example: stale UUID -> HTTP-like status `403`.
async fn reject_request(request: IncomingRequest, status: u16) -> Result<(), String> {
    request
        .reject(status)
        .await
        .map_err(|error| format!("respond rejection failed: {error}"))
}

/// Checks all URL-bearing Cloudflare metadata for the expected UUID.
///
/// Example: destination `?code=<uuid>` matches the expected UUID.
fn uuid_matches(request: &IncomingRequest, expected: &str) -> bool {
    // 触发条件: Cloudflare metadata 字段随入口协议变化。
    // 不能直接依赖单字段: QUIC 与 HTTP/2 提供的字段不同。
    // 防止副作用: 避免字段名差异导致正确 URL 被误拒。
    if extract_uuid(&request.destination).as_deref() == Some(expected) {
        return true;
    }
    request
        .metadata
        .iter()
        .filter(|(key, _)| {
            let key = key.to_ascii_lowercase();
            key.contains("path") || key.contains("uri") || key.contains("url")
        })
        .any(|(_, value)| extract_uuid(value).as_deref() == Some(expected))
}

/// Computes the RFC 6455 WebSocket accept value for a Cloudflare request.
///
/// Example: `Sec-WebSocket-Key` -> base64 SHA-1 accept header.
fn websocket_accept_value(request: &IncomingRequest) -> Result<String, String> {
    let key = request
        .metadata
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("HttpHeader:Sec-Websocket-Key"))
        .map(|(_, value)| value)
        .ok_or_else(|| "missing websocket key".to_string())?;
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    Ok(BASE64.encode(digest.finalize()))
}

/// Bridges target TCP bytes and Cloudflare WebSocket frames bidirectionally.
///
/// Example: SSH bytes from TCP become WebSocket binary messages.
async fn bridge_tcp_websocket(
    tcp: TcpStream,
    websocket: WebSocketStream<CfStream>,
) -> Result<(), String> {
    let (mut tcp_reader, mut tcp_writer) = tcp.into_split();
    let (mut websocket_writer, mut websocket_reader) = websocket.split();

    let tcp_to_websocket = async {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let len = tcp_reader
                .read(&mut buffer)
                .await
                .map_err(|error| format!("read tcp failed: {error}"))?;
            if len == 0 {
                let _ = websocket_writer.close().await;
                return Ok::<(), String>(());
            }
            websocket_writer
                .send(Message::Binary(buffer[..len].to_vec().into()))
                .await
                .map_err(|error| format!("write Cloudflare websocket failed: {error}"))?;
        }
    };

    let websocket_to_tcp = async {
        while let Some(message) = websocket_reader.next().await {
            let message =
                message.map_err(|error| format!("read Cloudflare websocket failed: {error}"))?;
            match message {
                Message::Binary(data) => tcp_writer
                    .write_all(&data)
                    .await
                    .map_err(|error| format!("write tcp failed: {error}"))?,
                Message::Text(text) => tcp_writer
                    .write_all(text.as_bytes())
                    .await
                    .map_err(|error| format!("write tcp text failed: {error}"))?,
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
        let _ = tcp_writer.shutdown().await;
        Ok::<(), String>(())
    };

    tokio::select! {
        result = tcp_to_websocket => result,
        result = websocket_to_tcp => result,
    }
}

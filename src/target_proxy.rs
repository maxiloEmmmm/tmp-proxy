use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures_util::{SinkExt, StreamExt};
use sha1::{Digest, Sha1};
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    tungstenite::protocol::{Message, Role},
    WebSocketStream,
};
use url::Url;

use crate::cf_lib::{CfResponse, CfStream, IncomingRequest, RequestKind};
use crate::connection_activity::ConnectionActivity;

const WEBSOCKET_PATH: &str = "/tcp";

/// Target selection policy for one tunnel request.
///
/// Example: daemon policy allows `port=2222`; GUI policy remains fixed.
#[derive(Clone)]
pub(crate) enum Target {
    /// Fixed address used by GUI and headless xx modes.
    Fixed {
        /// Complete host and port passed to `TcpStream::connect`.
        address: String,
    },
    /// Fixed daemon IP whose port may be overridden by the request URL.
    PortOverride {
        /// IP supplied through daemon `-ip` and never controlled by the URL.
        ip: IpAddr,
        /// Port used when the request URL omits `port`.
        default_port: u16,
    },
}

impl Target {
    /// Creates a target that rejects URL port overrides.
    ///
    /// Example: `fixed("nas:22")` always connects to `nas:22`.
    pub(crate) fn fixed(address: String) -> Self {
        Self::Fixed { address }
    }

    /// Creates a daemon target with a fixed IP and request-selectable port.
    ///
    /// Example: IP `127.0.0.1`, default `22`, request `port=80` -> port 80.
    pub(crate) fn with_port_override(ip: IpAddr, default_port: u16) -> Self {
        Self::PortOverride { ip, default_port }
    }

    /// Resolves one request port under this target policy.
    ///
    /// Example: daemon target plus `Some(80)` -> `127.0.0.1:80`.
    pub(crate) fn resolve(&self, requested_port: Option<u16>) -> Result<String, String> {
        match self {
            Self::Fixed { address } if requested_port.is_none() => Ok(address.clone()),
            Self::Fixed { .. } => Err("target does not allow a port override".to_string()),
            Self::PortOverride { ip, default_port } => {
                Ok(SocketAddr::new(*ip, requested_port.unwrap_or(*default_port)).to_string())
            }
        }
    }
}

/// Builds the public WSS URL containing the active access UUID.
///
/// Example: host, UUID and port 22 -> URL carrying `code` and `port`.
pub(crate) fn build_wss_url(
    hostname: &str,
    uuid: &str,
    port: Option<u16>,
) -> Result<String, String> {
    let mut url = Url::parse(&format!("wss://{hostname}"))
        .map_err(|error| format!("build tunnel url failed: {error}"))?;
    url.set_path(WEBSOCKET_PATH);
    let mut query = url.query_pairs_mut();
    query.append_pair("code", uuid);
    if let Some(port) = port {
        if port == 0 {
            return Err("tunnel URL port must be 1..65535".to_string());
        }
        query.append_pair("port", &port.to_string());
    }
    drop(query);
    Ok(url.to_string())
}

/// Handles one authenticated Cloudflare WebSocket request.
///
/// Example: matching UUID plus tracker -> one counted target connection.
pub(crate) async fn handle_request(
    request: IncomingRequest,
    target: Target,
    expected_uuids: Vec<String>,
    activity: Option<ConnectionActivity>,
) -> Result<(), String> {
    let Some(request_url) = matching_request_url(&request, &expected_uuids) else {
        reject_request(request, 403).await?;
        return Ok(());
    };
    if request_url_path(request_url).as_deref() != Some(WEBSOCKET_PATH) {
        reject_request(request, 404).await?;
        return Ok(());
    }
    if request.kind != RequestKind::WebSocket {
        reject_request(request, 404).await?;
        return Ok(());
    }
    let requested_port = match extract_target_port(request_url) {
        Ok(port) => port,
        Err(_) => {
            reject_request(request, 400).await?;
            return Ok(());
        }
    };
    let target = match target.resolve(requested_port) {
        Ok(target) => target,
        Err(_) => {
            reject_request(request, 400).await?;
            return Ok(());
        }
    };

    let tcp = TcpStream::connect(&target)
        .await
        .map_err(|error| format!("connect target {target} failed: {error}"))?;
    let _connection_lease = match activity {
        Some(activity) => match activity.try_begin() {
            Some(lease) => Some(lease),
            None => {
                // 触发条件: 空闲刷新封口与已鉴权请求完成目标连接并发发生。
                // 不能继续升级 WebSocket: 该 session 即将被主动关闭。
                // 防止副作用: 拒绝迟到请求，避免刷新误杀一个新活跃连接。
                reject_request(request, 503).await?;
                return Ok(());
            }
        },
        None => None,
    };
    let websocket = upgrade_websocket(request).await?;
    bridge_tcp_websocket(tcp, websocket).await
}

/// Extracts the UUID carried in the stable `code` query key.
///
/// Example: `"/tcp?code=<uuid>" -> Some("<uuid>")`.
pub(crate) fn extract_uuid(raw: &str) -> Option<String> {
    let parsed = parse_request_url(raw)?;
    parsed
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
}

/// Extracts and validates the optional target `port` query value.
///
/// Example: `"/tcp?code=x&port=2222" -> Ok(Some(2222))`.
pub(crate) fn extract_target_port(raw: &str) -> Result<Option<u16>, String> {
    let parsed = parse_request_url(raw).ok_or_else(|| "request URL is invalid".to_string())?;
    let mut ports = parsed
        .query_pairs()
        .filter(|(key, _)| key == "port")
        .map(|(_, value)| value.into_owned());
    let Some(raw_port) = ports.next() else {
        return Ok(None);
    };
    if ports.next().is_some() {
        return Err("request URL contains duplicate port values".to_string());
    }
    raw_port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .map(Some)
        .ok_or_else(|| "request URL port must be 1..65535".to_string())
}

/// Parses either a complete URL or the request path emitted by Cloudflare.
///
/// Example: `"/tcp?code=x"` is parsed against a temporary WSS origin.
fn parse_request_url(raw: &str) -> Option<Url> {
    Url::parse(raw)
        .or_else(|_| Url::parse(&format!("wss://tmp.local{raw}")))
        .ok()
}

/// Rejects one Cloudflare request before it reaches the target.
///
/// Example: stale UUID -> HTTP-like status `403`.
pub(crate) async fn reject_request(request: IncomingRequest, status: u16) -> Result<(), String> {
    request
        .reject(status)
        .await
        .map_err(|error| format!("respond rejection failed: {error}"))
}

/// Finds URL-bearing Cloudflare metadata containing any accepted UUID.
///
/// Example: destination carrying current or previous UUID returns that destination.
pub(crate) fn matching_request_url<'a>(
    request: &'a IncomingRequest,
    expected: &[String],
) -> Option<&'a str> {
    // 触发条件: Cloudflare metadata 字段随入口协议变化。
    // 不能直接依赖单字段: QUIC 与 HTTP/2 提供的字段不同。
    // 防止副作用: 避免字段名差异导致正确 URL 被误拒。
    if request_url_matches(&request.destination, expected) {
        return Some(&request.destination);
    }
    request
        .metadata
        .iter()
        .filter(|(key, _)| {
            let key = key.to_ascii_lowercase();
            key.contains("path") || key.contains("uri") || key.contains("url")
        })
        .find(|(_, value)| request_url_matches(value, expected))
        .map(|(_, value)| value.as_str())
}

/// Finds the request path used by the proxy facade to choose legacy or mux handling.
///
/// Example: Cloudflare metadata containing `/mux?code=x` returns `/mux`.
pub(crate) fn request_path(request: &IncomingRequest) -> Option<String> {
    if let Some(path) =
        request_url_path(&request.destination).filter(|path| path == "/tcp" || path == "/mux")
    {
        return Some(path);
    }
    request
        .metadata
        .iter()
        .filter(|(key, _)| {
            let key = key.to_ascii_lowercase();
            key.contains("path") || key.contains("uri") || key.contains("url")
        })
        .find_map(|(_, value)| {
            request_url_path(value).filter(|path| path == "/tcp" || path == "/mux")
        })
}

/// Parses only the path component of a complete URL or Cloudflare request target.
///
/// Example: `/tcp?code=x -> /tcp`.
pub(crate) fn request_url_path(raw: &str) -> Option<String> {
    parse_request_url(raw).map(|url| url.path().to_string())
}

/// Checks whether one request URL carries any UUID from an acceptance snapshot.
///
/// Example: URL code `old` plus `[new, old]` -> true.
fn request_url_matches(raw: &str, expected: &[String]) -> bool {
    let Some(received) = extract_uuid(raw) else {
        return false;
    };
    expected.iter().any(|candidate| candidate == &received)
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

/// Upgrades one already authenticated Cloudflare request to a server WebSocket.
///
/// Example: both legacy and mux handlers reuse the same RFC 6455 response path.
pub(crate) async fn upgrade_websocket(
    request: IncomingRequest,
) -> Result<WebSocketStream<CfStream>, String> {
    let accept = websocket_accept_value(&request)?;
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
    Ok(WebSocketStream::from_raw_socket(stream, Role::Server, None).await)
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

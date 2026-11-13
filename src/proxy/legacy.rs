use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};
use tokio_tungstenite::{tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream};

use crate::{
    cf_lib::IncomingRequest,
    connection_activity::ConnectionActivity,
    endpoint,
    target_proxy::{self, Target},
};

use super::websocket;

/// Interval between legacy yy WebSocket heartbeat frames.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Legacy client preserving one WebSocket per adjacent TCP connection.
///
/// Example: compatibility mode accepts one sing-box TCP and dials one `/tcp` WSS.
#[derive(Clone)]
pub(super) struct Client {
    /// Refreshable endpoint source shared by independently accepted TCP connections.
    endpoint: endpoint::Source,
    /// Direct or HTTP CONNECT WebSocket dialer.
    connector: websocket::Connector,
}

/// Legacy server preserving one target TCP per incoming WebSocket request.
///
/// Example: `/tcp?code=x&port=22` connects one daemon target socket.
#[derive(Clone)]
pub(super) struct Server {
    /// Target selection policy owned by the proxy facade.
    target: Target,
}

impl Client {
    /// Creates the compatibility client without opening a WebSocket early.
    ///
    /// Example: every later `handle_tcp` snapshots the latest endpoint URL.
    pub(super) fn new(endpoint: endpoint::Source, connector: websocket::Connector) -> Self {
        Self {
            endpoint,
            connector,
        }
    }

    /// Bridges one adjacent TCP through its own legacy WebSocket.
    ///
    /// Example: an expired KV hostname refreshes once before returning failure.
    pub(super) async fn handle_tcp(&self, tcp: TcpStream) -> Result<(), String> {
        let mut endpoint = self.endpoint.clone();
        let wss_url = endpoint.current();
        let first_error = match self.connector.connect(&wss_url).await {
            Ok(websocket) => return bridge_tcp_websocket(tcp, websocket).await,
            Err(error) => error,
        };
        let Some(refreshed) = endpoint.refresh_after_failure(&wss_url).await else {
            return Err(format!("connect websocket failed: {first_error}"));
        };
        let websocket = self.connector.connect(&refreshed).await.map_err(|error| {
            format!("connect refreshed websocket failed: {error}; initial error: {first_error}")
        })?;
        bridge_tcp_websocket(tcp, websocket).await
    }
}

impl Server {
    /// Creates a compatibility server with one stable target policy.
    ///
    /// Example: daemon target IP plus request port remains resolved per request.
    pub(super) fn new(target: Target) -> Self {
        Self { target }
    }

    /// Handles one legacy request through the existing 1:1 implementation.
    ///
    /// Example: valid `/tcp` request connects and relays one target TCP.
    pub(super) async fn handle_request(
        &self,
        request: IncomingRequest,
        expected_uuids: Vec<String>,
        activity: Option<ConnectionActivity>,
    ) -> Result<(), String> {
        target_proxy::handle_request(request, self.target.clone(), expected_uuids, activity).await
    }
}

/// Bridges one adjacent TCP and one concrete client WebSocket in both directions.
///
/// Example: TCP bytes become binary messages until either side closes.
async fn bridge_tcp_websocket(
    tcp: TcpStream,
    websocket: WebSocketStream<MaybeTlsStream<TcpStream>>,
) -> Result<(), String> {
    let (mut tcp_reader, mut tcp_writer) = tcp.into_split();
    let (mut websocket_writer, mut websocket_reader) = websocket.split();
    let tcp_to_websocket = async {
        let mut buffer = BytesMut::zeroed(16 * 1024);
        let first_heartbeat = time::Instant::now() + HEARTBEAT_INTERVAL;
        let mut heartbeat = time::interval_at(first_heartbeat, HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                read = tcp_reader.read(&mut buffer) => {
                    let read = read.map_err(|error| format!("read tcp failed: {error}"))?;
                    if read == 0 {
                        let _ = websocket_writer.close().await;
                        return Ok::<(), String>(());
                    }
                    websocket_writer
                        .send(Message::Binary(Bytes::copy_from_slice(&buffer[..read])))
                        .await
                        .map_err(|error| format!("write websocket failed: {error}"))?;
                }
                _ = heartbeat.tick() => {
                    // 触发条件：空闲 SSH 可能长期没有业务数据。
                    // 不能依赖自动 Pong：peer 不会主动制造 Ping。
                    // 防止副作用：周期心跳避免公网 WSS 被空闲回收。
                    websocket_writer
                        .send(Message::Ping(Bytes::new()))
                        .await
                        .map_err(|error| format!("write websocket heartbeat failed: {error}"))?;
                }
            }
        }
    };
    let websocket_to_tcp = async {
        while let Some(message) = websocket_reader.next().await {
            match message.map_err(|error| format!("read websocket failed: {error}"))? {
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

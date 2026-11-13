use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::{net::TcpStream, sync::mpsc, sync::Mutex, time};
use tokio_tungstenite::{tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{endpoint, proxy::websocket, target_proxy};

use super::{
    bridge::bridge_tcp,
    core::{Config, Endpoint, Role},
    protocol::{decode, encode, Frame},
};

/// Capacity between the mux core and concrete WebSocket adapter.
const CARRIER_QUEUE_CAPACITY: usize = 1;

/// Heartbeat interval keeping an otherwise idle shared WebSocket alive.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Client-side mux facade pooling one live WSS for all adjacent TCP streams.
///
/// Example: hundreds of sing-box TCP connections share one endpoint session.
#[derive(Clone)]
pub(crate) struct Client {
    /// Refreshable WSS discovery source.
    endpoint: endpoint::Source,
    /// Direct or HTTP CONNECT WebSocket dialer.
    connector: websocket::Connector,
    /// Single pooled mux session, replaced only after carrier failure.
    session: Arc<Mutex<Option<Session>>>,
}

/// One pooled mux session and the URL generation that created it.
struct Session {
    /// Transport-independent mux core.
    endpoint: Endpoint,
}

impl Client {
    /// Creates a lazy mux client that connects only when the first TCP arrives.
    ///
    /// Example: yy startup performs no WSS handshake until sing-box connects.
    pub(crate) fn new(endpoint: endpoint::Source, connector: websocket::Connector) -> Self {
        Self {
            endpoint,
            connector,
            session: Arc::new(Mutex::new(None)),
        }
    }

    /// Opens one logical stream on the pooled WSS and bridges its adjacent TCP.
    ///
    /// Example: URL query `port=10808` becomes OPEN target port 10808.
    pub(crate) async fn handle_tcp(&self, tcp: TcpStream) -> Result<(), String> {
        let (session, target_port) = self.session().await?;
        match session.open(target_port).await {
            Ok(stream) => bridge_tcp(tcp, stream).await,
            Err(_) if session.is_closed() => {
                self.clear_closed_session().await;
                let (replacement, target_port) = self.session().await?;
                let stream = replacement.open(target_port).await?;
                bridge_tcp(tcp, stream).await
            }
            Err(error) => Err(error),
        }
    }

    /// Returns the live session or creates exactly one while concurrent accepts wait.
    ///
    /// Example: ten simultaneous TCP accepts still perform one WSS handshake.
    async fn session(&self) -> Result<(Endpoint, u16), String> {
        let raw = self.endpoint.current();
        let (_, requested_port) = mux_url(&raw)?;
        let mut session = self.session.lock().await;
        if let Some(current) = session
            .as_ref()
            .filter(|current| !current.endpoint.is_closed())
        {
            return Ok((current.endpoint.clone(), requested_port));
        }

        let mut endpoint_source = self.endpoint.clone();
        let mut selected = raw;
        let websocket = match connect_mux(&selected, &self.connector).await {
            Ok(websocket) => websocket,
            Err(first_error) => {
                let Some(refreshed) = endpoint_source.refresh_after_failure(&selected).await else {
                    return Err(first_error);
                };
                selected = refreshed;
                connect_mux(&selected, &self.connector)
                    .await
                    .map_err(|error| format!("connect refreshed mux websocket failed: {error}"))?
            }
        };
        let (_, selected_port) = mux_url(&selected)?;
        let endpoint = start_websocket(websocket)?;
        *session = Some(Session {
            endpoint: endpoint.clone(),
        });
        Ok((endpoint, selected_port))
    }

    /// Removes a dead pooled endpoint without disturbing a newer replacement.
    ///
    /// Example: OPEN failing before TCP read permits one safe reconnect attempt.
    async fn clear_closed_session(&self) {
        let mut session = self.session.lock().await;
        if session
            .as_ref()
            .is_some_and(|current| current.endpoint.is_closed())
        {
            session.take();
        }
    }
}

/// Connects the `/mux` URL derived from a legacy-compatible endpoint record.
///
/// Example: `/tcp?code=x&port=80` dials `/mux?code=x` and returns port separately.
async fn connect_mux(
    raw: &str,
    connector: &websocket::Connector,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, String> {
    let (url, _) = mux_url(raw)?;
    connector
        .connect(&url)
        .await
        .map_err(|error| format!("connect mux websocket failed: {error}"))
}

/// Converts an endpoint URL into the shared carrier URL and OPEN target port.
///
/// Example: missing `port` becomes zero, requesting the daemon default target.
fn mux_url(raw: &str) -> Result<(String, u16), String> {
    let mut url = Url::parse(raw).map_err(|error| format!("invalid mux URL: {error}"))?;
    if url.scheme() != "wss" {
        return Err("mux URL must use wss://".to_string());
    }
    if target_proxy::extract_uuid(raw).is_none() {
        return Err("mux URL must contain code".to_string());
    }
    let target_port = target_proxy::extract_target_port(raw)?.unwrap_or(0);
    let retained: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != "port")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.set_path("/mux");
    url.set_query(None);
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in retained {
            query.append_pair(&key, &value);
        }
    }
    Ok((url.to_string(), target_port))
}

/// Attaches a concrete client WebSocket to the transport-independent mux core.
///
/// Example: binary WS messages are decoded into the core's inbound frame channel.
fn start_websocket(
    websocket: WebSocketStream<MaybeTlsStream<TcpStream>>,
) -> Result<Endpoint, String> {
    let (carrier_out_tx, carrier_out_rx) = mpsc::channel(CARRIER_QUEUE_CAPACITY);
    let (carrier_in_tx, carrier_in_rx) = mpsc::channel(CARRIER_QUEUE_CAPACITY);
    let endpoint = Endpoint::start(
        Role::Client,
        Config::default(),
        carrier_out_tx,
        carrier_in_rx,
    )?;
    spawn_websocket_tasks(websocket, carrier_out_rx, carrier_in_tx);
    Ok(endpoint)
}

/// Runs concrete client WebSocket reader and writer tasks until either direction fails.
///
/// Example: writer failure cancels the reader so dropping its sender closes the mux core.
fn spawn_websocket_tasks(
    websocket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    mut outbound: mpsc::Receiver<Frame>,
    inbound: mpsc::Sender<Frame>,
) {
    let (mut writer, mut reader) = websocket.split();
    let cancel = CancellationToken::new();
    let writer_cancel = cancel.clone();
    tokio::spawn(async move {
        let first_heartbeat = time::Instant::now() + HEARTBEAT_INTERVAL;
        let mut heartbeat = time::interval_at(first_heartbeat, HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        loop {
            let result = tokio::select! {
                _ = writer_cancel.cancelled() => return,
                frame = outbound.recv() => match frame {
                    Some(frame) => writer.send(Message::Binary(encode(frame))).await,
                            None => {
                                // 发送侧退出后必须唤醒接收侧，否则空闲 WebSocket 可能长期存活。
                                writer_cancel.cancel();
                                return;
                            }
                },
                // 触发条件：共享 WSS 可以暂时没有 active stream。
                // 不能依赖业务 DATA：空闲期间不会自然产生写流量。
                // 防止副作用：主动 Ping 避免公网链路被空闲回收。
                _ = heartbeat.tick() => writer.send(Message::Ping(Bytes::new())).await,
            };
            if result.is_err() {
                writer_cancel.cancel();
                return;
            }
        }
    });
    tokio::spawn(async move {
        loop {
            let message = tokio::select! {
                _ = cancel.cancelled() => return,
                message = reader.next() => message,
            };
            let Some(Ok(message)) = message else {
                cancel.cancel();
                return;
            };
            match message {
                Message::Binary(binary) => match decode(binary) {
                    Ok(frame) => {
                        if inbound.send(frame).await.is_err() {
                            cancel.cancel();
                            return;
                        }
                    }
                    Err(_) => {
                        cancel.cancel();
                        return;
                    }
                },
                Message::Close(_) => {
                    cancel.cancel();
                    return;
                }
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Text(_) | Message::Frame(_) => {
                    cancel.cancel();
                    return;
                }
            }
        }
    });
}

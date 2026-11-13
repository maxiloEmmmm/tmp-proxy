use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::{net::TcpStream, sync::mpsc, time};
use tokio_tungstenite::{tungstenite::protocol::Message, WebSocketStream};
use tokio_util::sync::CancellationToken;

use crate::{
    cf_lib::{CfStream, IncomingRequest, RequestKind},
    connection_activity::ConnectionActivity,
    target_proxy::{self, Target},
};

use super::{
    bridge::bridge_tcp,
    core::{Config, Endpoint, Role, RESET_OPEN_FAILED},
    protocol::{decode, encode, Frame},
};

/// Capacity between the mux core and concrete server WebSocket adapter.
const CARRIER_QUEUE_CAPACITY: usize = 1;

/// Heartbeat interval keeping an otherwise idle shared WebSocket alive.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Server-side mux handler connecting every OPEN to one independent target TCP.
///
/// Example: one `/mux` WSS carries many daemon-side target connections.
#[derive(Clone)]
pub(crate) struct Server {
    /// Target IP and default-port policy shared by all logical streams.
    target: Target,
}

impl Server {
    /// Creates a mux server without allocating a session before a request arrives.
    ///
    /// Example: one daemon proxy facade owns this value across tunnel requests.
    pub(crate) fn new(target: Target) -> Self {
        Self { target }
    }

    /// Authenticates, upgrades, and serves one shared `/mux` WebSocket request.
    ///
    /// Example: every OPEN is connected before its OPEN_OK is returned.
    pub(crate) async fn handle_request(
        &self,
        request: IncomingRequest,
        expected_uuids: Vec<String>,
        activity: Option<ConnectionActivity>,
    ) -> Result<(), String> {
        let Some(request_url) = target_proxy::matching_request_url(&request, &expected_uuids)
        else {
            target_proxy::reject_request(request, 403).await?;
            return Ok(());
        };
        if target_proxy::request_url_path(request_url).as_deref() != Some("/mux")
            || request.kind != RequestKind::WebSocket
        {
            target_proxy::reject_request(request, 404).await?;
            return Ok(());
        }
        let websocket = target_proxy::upgrade_websocket(request).await?;
        let endpoint = start_websocket(websocket)?;
        self.serve(endpoint, activity).await
    }

    /// Accepts logical streams until the shared carrier closes.
    ///
    /// Example: target connection refusal rejects only its OPEN request.
    async fn serve(
        &self,
        endpoint: Endpoint,
        activity: Option<ConnectionActivity>,
    ) -> Result<(), String> {
        loop {
            tokio::select! {
                _ = endpoint.closed() => return Ok(()),
                incoming = endpoint.accept() => {
                    let incoming = incoming?;
                    // 触发条件：复用 WSS 可以在没有业务 stream 时长期存活。
                    // 不能按 WSS 持有 lease：这会让 daemon 的空闲刷新永久失效。
                    // 防止副作用：每个 OPEN 单独计数，封口后拒绝迟到 stream。
                    let connection_lease = match &activity {
                        Some(activity) => match activity.try_begin() {
                            Some(lease) => Some(lease),
                            None => {
                                incoming.reject(RESET_OPEN_FAILED).await?;
                                continue;
                            }
                        },
                        None => None,
                    };
                    let target_policy = self.target.clone();
                    tokio::spawn(async move {
                        let result = async {
                            let requested_port = (incoming.target_port() != 0)
                                .then_some(incoming.target_port());
                            let target = match target_policy.resolve(requested_port) {
                                Ok(target) => target,
                                Err(_) => {
                                    incoming.reject(RESET_OPEN_FAILED).await?;
                                    return Ok::<(), String>(());
                                }
                            };
                            match TcpStream::connect(&target).await {
                                Ok(tcp) => {
                                    let stream = incoming.accept().await?;
                                    // lease 跟随逻辑 stream，而不是共享 WSS。
                                    let _connection_lease = connection_lease;
                                    bridge_tcp(tcp, stream).await
                                }
                                Err(_) => incoming.reject(RESET_OPEN_FAILED).await,
                            }
                        }.await;
                        if let Err(error) = result {
                            eprintln!("mux target stream failed: {error}");
                        }
                    });
                }
            }
        }
    }
}

/// Attaches a concrete Cloudflare WebSocket to the transport-independent mux core.
///
/// Example: Cloudflare binary messages become core frames without leaking into daemon code.
fn start_websocket(websocket: WebSocketStream<CfStream>) -> Result<Endpoint, String> {
    let (carrier_out_tx, carrier_out_rx) = mpsc::channel(CARRIER_QUEUE_CAPACITY);
    let (carrier_in_tx, carrier_in_rx) = mpsc::channel(CARRIER_QUEUE_CAPACITY);
    let endpoint = Endpoint::start(
        Role::Server,
        Config::default(),
        carrier_out_tx,
        carrier_in_rx,
    )?;
    spawn_websocket_tasks(websocket, carrier_out_rx, carrier_in_tx);
    Ok(endpoint)
}

/// Runs concrete server WebSocket reader and writer tasks until either direction fails.
///
/// Example: malformed binary input cancels both tasks and all logical streams.
fn spawn_websocket_tasks(
    websocket: WebSocketStream<CfStream>,
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

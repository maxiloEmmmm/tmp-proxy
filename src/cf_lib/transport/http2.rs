use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use bytes::Bytes;
use h2::server::{Connection, SendResponse};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::cf_lib::control_plane::ControlPlane;
use crate::cf_lib::edge_discovery::EdgeAddress;
use crate::cf_lib::quick_tunnel::Credentials;
use crate::cf_lib::tls;
use crate::cf_lib::{CfError, CfResponse, CfStream, IncomingRequest, RequestKind};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UPGRADE_HEADER: &str = "cf-cloudflared-proxy-connection-upgrade";
const TCP_SOURCE_HEADER: &str = "cf-cloudflared-proxy-src";
const REQUEST_HEADERS: &str = "cf-cloudflared-request-headers";
const RESPONSE_HEADERS: &str = "cf-cloudflared-response-headers";
const RESPONSE_META: &str = "cf-cloudflared-response-meta";

/// Concrete HTTP/2 server connection carried over client-side TLS.
type H2Connection = Connection<TlsStream<TcpStream>, Bytes>;

/// Registered HTTP/2 fallback connection and control plane.
///
/// Example: TCP edge connection receives edge-initiated HTTP/2 streams.
pub(crate) struct Http2Transport {
    /// Registration RPC stream used during graceful shutdown.
    control: ControlPlane,
    /// Cloudflare colo reported by registration.
    location: String,
    /// Requests accepted by the independently polled HTTP/2 driver.
    incoming: mpsc::Receiver<Result<H2Request, CfError>>,
    /// Cancellation token used to stop and drop the HTTP/2 connection.
    driver_shutdown: CancellationToken,
    /// Task continuously polling the HTTP/2 connection state machine.
    driver: JoinHandle<()>,
}

/// Edge-initiated HTTP/2 request and its response sender.
type H2Request = (Request<h2::RecvStream>, SendResponse<Bytes>);

impl Http2Transport {
    /// Connects TLS and registers over the edge's control HTTP/2 stream.
    ///
    /// Example: QUIC failure -> registered HTTP/2 fallback.
    pub(crate) async fn connect(
        edge: EdgeAddress,
        credentials: &Credentials,
        previous_attempts: u8,
    ) -> Result<Self, CfError> {
        let tcp = time::timeout(CONNECT_TIMEOUT, TcpStream::connect(edge.socket))
            .await
            .map_err(|_| CfError::new("HTTP/2 edge TCP connection timed out"))?
            .map_err(|error| CfError::new(format!("connect HTTP/2 edge failed: {error}")))?;
        tcp.set_nodelay(true)
            .map_err(|error| CfError::new(format!("configure HTTP/2 TCP failed: {error}")))?;
        let server_name = ServerName::try_from(tls::http2_server_name())
            .map_err(|error| CfError::new(format!("invalid HTTP/2 server name: {error}")))?;
        let tls = time::timeout(
            CONNECT_TIMEOUT,
            TlsConnector::from(tls::http2_config()?).connect(server_name, tcp),
        )
        .await
        .map_err(|_| CfError::new("HTTP/2 edge TLS handshake timed out"))?
        .map_err(|error| CfError::new(format!("HTTP/2 edge TLS failed: {error}")))?;
        let mut connection = time::timeout(CONNECT_TIMEOUT, h2::server::handshake(tls))
            .await
            .map_err(|_| CfError::new("HTTP/2 handshake timed out"))?
            .map_err(|error| CfError::new(format!("HTTP/2 handshake failed: {error}")))?;
        let (request, mut response) =
            time::timeout(CONNECT_TIMEOUT, accept_control(&mut connection))
                .await
                .map_err(|_| CfError::new("HTTP/2 control stream timed out"))??;
        let response_head = Response::builder()
            .status(StatusCode::OK)
            .header(RESPONSE_HEADERS, "")
            .header(RESPONSE_META, r#"{"src":"origin"}"#)
            .body(())
            .map_err(|error| CfError::new(format!("build control response failed: {error}")))?;
        let send = response
            .send_response(response_head, false)
            .map_err(|error| CfError::new(format!("send control response failed: {error}")))?;
        let (incoming_sender, incoming) = mpsc::channel(128);
        let driver_shutdown = CancellationToken::new();
        let driver_cancel = driver_shutdown.clone();
        let driver = tokio::spawn(async move {
            drive_connection(connection, incoming_sender, driver_cancel).await;
        });
        let registration = ControlPlane::register(
            CfStream::http2(send, request.into_body()),
            credentials,
            previous_attempts,
            false,
        )
        .await;
        let (control, details) = match registration {
            Ok(registered) => registered,
            Err(error) => {
                driver_shutdown.cancel();
                let _ = driver.await;
                return Err(error);
            }
        };
        Ok(Self {
            control,
            location: details.location,
            incoming,
            driver_shutdown,
            driver,
        })
    }

    /// Returns the registered Cloudflare colo.
    ///
    /// Example: successful fallback registration -> `"SJC"`.
    pub(crate) fn location(&self) -> &str {
        &self.location
    }

    /// Accepts edge-initiated HTTP/2 request streams until disconnect.
    ///
    /// Example: WebSocket request headers -> unified incoming request.
    pub(crate) async fn run(
        mut self,
        requests: mpsc::Sender<IncomingRequest>,
        shutdown: CancellationToken,
    ) -> Result<(), CfError> {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    let result = self.control.unregister().await;
                    self.driver_shutdown.cancel();
                    let _ = self.driver.await;
                    return result;
                },
                accepted = self.incoming.recv() => {
                    let Some(accepted) = accepted else {
                        self.driver_shutdown.cancel();
                        let _ = self.driver.await;
                        return Err(CfError::new("HTTP/2 edge connection closed"));
                    };
                    let (request, response) = accepted?;
                    let incoming = decode_request(request, response)?;
                    requests.send(incoming).await
                        .map_err(|_| CfError::new("Cloudflare request receiver closed"))?;
                }
            }
        }
    }
}

/// Polls the H2 connection continuously so control and data bodies make progress.
///
/// Example: registration reads a DATA frame while this task drives the socket.
async fn drive_connection(
    mut connection: H2Connection,
    incoming: mpsc::Sender<Result<H2Request, CfError>>,
    shutdown: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => return,
            accepted = connection.accept() => accepted,
        };
        let Some(accepted) = accepted else {
            return;
        };
        let accepted = accepted
            .map_err(|error| CfError::new(format!("accept HTTP/2 request failed: {error}")));
        if incoming.send(accepted).await.is_err() {
            return;
        }
    }
}

/// Waits for and validates the special HTTP/2 control stream.
///
/// Example: upgrade header `control-stream` -> accepted control request.
async fn accept_control(
    connection: &mut H2Connection,
) -> Result<(Request<h2::RecvStream>, SendResponse<Bytes>), CfError> {
    loop {
        let Some(accepted) = connection.accept().await else {
            return Err(CfError::new("HTTP/2 edge closed before control stream"));
        };
        let (request, mut response) = accepted
            .map_err(|error| CfError::new(format!("accept HTTP/2 control failed: {error}")))?;
        if request
            .headers()
            .get(UPGRADE_HEADER)
            .and_then(|value| value.to_str().ok())
            == Some("control-stream")
        {
            return Ok((request, response));
        }

        // Trigger: an edge may race a data stream ahead of registration.
        // The session cannot expose it before authentication has completed.
        // Rejecting it prevents an unauthenticated request from entering the app.
        let rejected = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(())
            .map_err(|error| CfError::new(format!("build early rejection failed: {error}")))?;
        response.send_response(rejected, true).map_err(|error| {
            CfError::new(format!("reject early HTTP/2 request failed: {error}"))
        })?;
    }
}

/// Converts one HTTP/2 request into transport-neutral metadata.
///
/// Example: serialized WebSocket headers -> `IncomingRequest::WebSocket`.
fn decode_request(
    request: Request<h2::RecvStream>,
    response: SendResponse<Bytes>,
) -> Result<IncomingRequest, CfError> {
    let kind = match request
        .headers()
        .get(UPGRADE_HEADER)
        .and_then(|value| value.to_str().ok())
    {
        Some("websocket") => RequestKind::WebSocket,
        _ if request.headers().contains_key(TCP_SOURCE_HEADER) => RequestKind::Tcp,
        _ => RequestKind::Http,
    };
    let destination = request.uri().to_string();
    let mut metadata = HashMap::new();
    metadata.insert("HttpMethod".to_string(), request.method().to_string());
    metadata.insert(
        "HttpHost".to_string(),
        request
            .uri()
            .authority()
            .map(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
    );
    metadata.insert(
        "HttpPath".to_string(),
        request
            .uri()
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or("/")
            .to_string(),
    );
    if let Some(serialized) = request.headers().get(REQUEST_HEADERS) {
        deserialize_headers(serialized, &mut metadata)?;
    }
    for (name, value) in request.headers() {
        if name.as_str().starts_with("cf-cloudflared-") {
            continue;
        }
        if let Ok(value) = value.to_str() {
            metadata.insert(format!("HttpHeader:{name}"), value.to_string());
        }
    }
    let recv = request.into_body();
    Ok(IncomingRequest::new(
        kind,
        destination,
        metadata,
        super::PendingResponse::Http2 { response, recv },
    ))
}

/// Builds Cloudflare's HTTP/2 response header envelope.
///
/// Example: status `101` and WebSocket accept header -> HTTP/2 status `200`.
pub(crate) fn build_response(response: &CfResponse) -> Result<Response<()>, CfError> {
    let status = if response.status == 101 {
        StatusCode::OK
    } else {
        StatusCode::from_u16(response.status)
            .map_err(|error| CfError::new(format!("invalid HTTP response status: {error}")))?
    };
    let serialized = serialize_headers(&response.headers)?;
    Response::builder()
        .status(status)
        .header(RESPONSE_HEADERS, serialized)
        .header(RESPONSE_META, r#"{"src":"origin"}"#)
        .body(())
        .map_err(|error| CfError::new(format!("build HTTP/2 response failed: {error}")))
}

/// Decodes Cloudflare's raw-base64 HTTP/1 header envelope.
///
/// Example: `base64(name):base64(value)` -> `HttpHeader:name=value`.
fn deserialize_headers(
    serialized: &HeaderValue,
    metadata: &mut HashMap<String, String>,
) -> Result<(), CfError> {
    let serialized = serialized
        .to_str()
        .map_err(|error| CfError::new(format!("request header envelope is not text: {error}")))?;
    for pair in serialized.split(';').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair
            .split_once(':')
            .ok_or_else(|| CfError::new("invalid Cloudflare request header envelope"))?;
        let name = STANDARD_NO_PAD
            .decode(name)
            .map_err(|error| CfError::new(format!("decode request header name failed: {error}")))?;
        let value = STANDARD_NO_PAD.decode(value).map_err(|error| {
            CfError::new(format!("decode request header value failed: {error}"))
        })?;
        let name = String::from_utf8(name)
            .map_err(|error| CfError::new(format!("request header name is not UTF-8: {error}")))?;
        let value = String::from_utf8(value)
            .map_err(|error| CfError::new(format!("request header value is not UTF-8: {error}")))?;
        metadata.insert(format!("HttpHeader:{name}"), value);
    }
    Ok(())
}

/// Encodes response headers using Cloudflare's raw-base64 envelope.
///
/// Example: `Sec-WebSocket-Accept: x` -> one base64 pair.
fn serialize_headers(headers: &HeaderMap) -> Result<String, CfError> {
    let mut pairs = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let value = value
            .to_str()
            .map_err(|error| CfError::new(format!("response header is not text: {error}")))?;
        pairs.push(format!(
            "{}:{}",
            STANDARD_NO_PAD.encode(name.as_str()),
            STANDARD_NO_PAD.encode(value)
        ));
    }
    Ok(pairs.join(";"))
}

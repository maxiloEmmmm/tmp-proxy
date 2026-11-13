//! Establishes client WebSockets directly or through an HTTP CONNECT proxy.

use std::env;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_tungstenite::{client_async_tls, connect_async, MaybeTlsStream, WebSocketStream};
use url::{Host, Url};

const MAX_CONNECT_RESPONSE_BYTES: usize = 8 * 1024;

/// Concrete WebSocket dialing policy selected once at process startup.
///
/// Example: no `HTTPS_PROXY` uses `Direct`; `http://127.0.0.1:10808` uses `HttpConnect`.
#[derive(Clone)]
enum Route {
    /// Opens the target TCP connection directly.
    Direct,
    /// Opens the target through one HTTP CONNECT proxy.
    HttpConnect {
        /// Proxy host without URL syntax.
        host: String,
        /// Proxy TCP listener port.
        port: u16,
    },
}

/// Cloneable connector shared by mux and legacy clients.
///
/// Example: one parsed environment setting serves every later WSS dial.
#[derive(Clone)]
pub(super) struct Connector {
    /// Selected direct or HTTP CONNECT route.
    route: Route,
}

impl Connector {
    /// Reads the optional standard HTTPS proxy environment once.
    ///
    /// Example: `HTTPS_PROXY=http://127.0.0.1:10808` -> HTTP CONNECT connector.
    pub(super) fn from_env() -> Result<Self, String> {
        let Some(raw) = proxy_env()? else {
            return Ok(Self {
                route: Route::Direct,
            });
        };
        let proxy = Url::parse(&raw).map_err(|error| format!("invalid HTTPS_PROXY: {error}"))?;
        if proxy.scheme() != "http" {
            return Err("HTTPS_PROXY must use http://".to_string());
        }
        if !proxy.username().is_empty() || proxy.password().is_some() {
            return Err("HTTPS_PROXY authentication is not supported".to_string());
        }
        if proxy.path() != "/" || proxy.query().is_some() || proxy.fragment().is_some() {
            return Err("HTTPS_PROXY must not contain a path, query, or fragment".to_string());
        }
        let host = proxy
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or("HTTPS_PROXY host is missing")?
            .to_string();
        let port = proxy
            .port_or_known_default()
            .ok_or("HTTPS_PROXY port is missing")?;
        Ok(Self {
            route: Route::HttpConnect { host, port },
        })
    }

    /// Connects one WSS URL using the startup-selected route.
    ///
    /// Example: HTTP CONNECT first tunnels `host:443`, then performs TLS and WebSocket handshakes.
    pub(super) async fn connect(
        &self,
        raw_url: &str,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, String> {
        match &self.route {
            Route::Direct => connect_async(raw_url)
                .await
                .map(|(websocket, _)| websocket)
                .map_err(|error| format!("connect websocket failed: {error}")),
            Route::HttpConnect { host, port } => {
                connect_through_http_proxy(raw_url, host, *port).await
            }
        }
    }
}

/// Returns the first non-empty HTTPS proxy environment value.
///
/// Example: empty `HTTPS_PROXY` plus `https_proxy=http://proxy:80` -> lowercase value.
fn proxy_env() -> Result<Option<String>, String> {
    for name in ["HTTPS_PROXY", "https_proxy"] {
        match env::var(name) {
            Ok(value) if !value.trim().is_empty() => return Ok(Some(value)),
            Ok(_) | Err(env::VarError::NotPresent) => {}
            Err(env::VarError::NotUnicode(_)) => {
                return Err(format!("{name} is not valid UTF-8"));
            }
        }
    }
    Ok(None)
}

/// Establishes an HTTP CONNECT tunnel and upgrades WSS over the resulting TCP stream.
///
/// Example: proxy `127.0.0.1:10808` plus WSS host `x.example` -> `CONNECT x.example:443`.
async fn connect_through_http_proxy(
    raw_url: &str,
    proxy_host: &str,
    proxy_port: u16,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, String> {
    let target = target_authority(raw_url)?;
    let mut stream = TcpStream::connect((proxy_host, proxy_port))
        .await
        .map_err(|error| {
            format!("connect HTTPS proxy {proxy_host}:{proxy_port} failed: {error}")
        })?;
    let request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("write HTTPS proxy CONNECT failed: {error}"))?;
    read_connect_response(&mut stream).await?;
    client_async_tls(raw_url, stream)
        .await
        .map(|(websocket, _)| websocket)
        .map_err(|error| format!("connect proxied websocket failed: {error}"))
}

/// Builds the CONNECT authority while retaining brackets for IPv6 literals.
///
/// Example: `wss://[::1]/mux` -> `[::1]:443`.
fn target_authority(raw_url: &str) -> Result<String, String> {
    let url = Url::parse(raw_url).map_err(|error| format!("invalid websocket URL: {error}"))?;
    if url.scheme() != "wss" {
        return Err("proxied websocket URL must use wss://".to_string());
    }
    let host = match url.host().ok_or("websocket URL host is missing")? {
        Host::Domain(domain) => domain.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    let port = url
        .port_or_known_default()
        .ok_or("websocket URL port is missing")?;
    Ok(format!("{host}:{port}"))
}

/// Consumes one bounded CONNECT response and accepts only a 2xx status.
///
/// Example: `HTTP/1.1 200 Connection established` -> tunnel ready.
async fn read_connect_response(stream: &mut TcpStream) -> Result<(), String> {
    let mut response = Vec::with_capacity(512);
    let mut buffer = [0_u8; 512];
    while !response.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(|error| format!("read HTTPS proxy CONNECT response failed: {error}"))?;
        if read == 0 {
            return Err("HTTPS proxy closed before CONNECT response".to_string());
        }
        if response.len() + read > MAX_CONNECT_RESPONSE_BYTES {
            return Err("HTTPS proxy CONNECT response exceeds 8 KiB".to_string());
        }
        response.extend_from_slice(&buffer[..read]);
    }
    let status_line_end = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or("HTTPS proxy CONNECT status line is malformed")?;
    let status_line = std::str::from_utf8(&response[..status_line_end])
        .map_err(|_| "HTTPS proxy CONNECT status is not UTF-8")?;
    let status = status_line
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or("HTTPS proxy CONNECT status code is malformed")?;
    if !(200..300).contains(&status) {
        return Err(format!("HTTPS proxy CONNECT rejected with status {status}"));
    }
    Ok(())
}

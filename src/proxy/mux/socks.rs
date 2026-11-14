use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use super::{
    bridge::bridge_tcp_prefixed,
    client::Client,
    core::{Datagram, Stream, RESET_LOCAL_IO},
};

/// SOCKS5 protocol version selected by the mixed-port detector.
const SOCKS5_VERSION: u8 = 5;

/// SOCKS5 command requesting one UDP relay association.
const UDP_ASSOCIATE: u8 = 3;

/// Largest UDP packet accepted from the local SOCKS5 client.
const MAX_UDP_PACKET: usize = 65_535;

/// Parsed SOCKS5 request bytes retained for transparent forwarding.
///
/// Example: `UDP ASSOCIATE 0.0.0.0:0 -> command=3`.
struct Request {
    /// SOCKS5 command byte used to select TCP or UDP handling.
    command: u8,
    /// Exact request bytes forwarded to the daemon-side sing-box.
    raw: Bytes,
}

/// Parsed SOCKS5 reply returned by the daemon-side sing-box.
///
/// Example: `0.0.0.0:53001 -> port=53001`.
struct Reply {
    /// SOCKS5 reply status where zero means success.
    status: u8,
    /// Bound port selected by the daemon-side sing-box.
    port: u16,
    /// Exact reply bytes used by non-UDP paths.
    raw: Bytes,
}

/// Buffered reader and window-aware writer for one logical mux stream.
///
/// Example: a reply and an immediate banner in one DATA frame retain the banner.
struct MuxControl {
    /// Logical stream connected to the daemon-side sing-box.
    stream: Stream,
    /// Bytes received beyond the current SOCKS5 field boundary.
    buffered: BytesMut,
}

/// Initial direction and protocol selected without consuming adjacent TCP bytes.
///
/// Example: local `0x05` selects SOCKS5; an SSH banner selects raw forwarding.
pub(super) enum InitialFlow {
    /// Client-first SOCKS5 traffic requiring UDP ASSOCIATE mediation.
    Socks5,
    /// Opaque TCP, optionally beginning with bytes already received from the target.
    Raw {
        /// Target bytes removed from the mux queue during direction detection.
        remote_prefix: Bytes,
    },
}

/// Detects SOCKS5 while allowing server-first raw protocols to make progress.
///
/// Example: SSH target banner arriving before client data immediately selects raw TCP.
pub(super) async fn classify(tcp: &TcpStream, stream: &Stream) -> Result<InitialFlow, String> {
    let mut byte = [0_u8; 1];
    tokio::select! {
        local = tcp.peek(&mut byte) => {
            let read = local.map_err(|error| format!("peek yy tcp protocol failed: {error}"))?;
            if read == 1 && byte[0] == SOCKS5_VERSION {
                Ok(InitialFlow::Socks5)
            } else {
                Ok(InitialFlow::Raw { remote_prefix: Bytes::new() })
            }
        }
        remote = stream.recv_chunk() => {
            let remote_prefix = remote
                .ok_or_else(|| "mux target closed before protocol detection".to_string())?;
            Ok(InitialFlow::Raw { remote_prefix })
        }
    }
}

/// Relays SOCKS5 TCP unchanged and maps UDP ASSOCIATE onto one mux datagram.
///
/// Example: a returned B-side UDP port is replaced with one A-side loopback port.
pub(super) async fn handle(
    mut tcp: TcpStream,
    stream: Stream,
    client: &Client,
) -> Result<(), String> {
    let local_ip = tcp
        .local_addr()
        .map_err(|error| format!("read SOCKS5 local address failed: {error}"))?
        .ip();
    let mut remote = MuxControl::new(stream);
    let negotiation = async {
        accept_no_auth(&mut tcp).await?;
        let request = read_request(&mut tcp).await?;
        open_remote_socks(&mut remote, &request.raw).await?;
        let reply = read_reply(&mut remote).await?;
        Ok::<_, String>((request, reply))
    }
    .await;
    let (request, reply) = match negotiation {
        Ok(negotiated) => negotiated,
        Err(error) => return abort_remote(remote, error).await,
    };

    if request.command != UDP_ASSOCIATE || reply.status != 0 {
        tcp.write_all(&reply.raw)
            .await
            .map_err(|error| format!("write SOCKS5 reply failed: {error}"))?;
        let (stream, prefix) = remote.into_parts();
        if reply.status != 0 {
            let _ = stream.reset(RESET_LOCAL_IO).await;
            return Ok(());
        }
        return bridge_tcp_prefixed(tcp, stream, prefix).await;
    }

    if reply.port == 0 {
        write_failure(&mut tcp).await?;
        let (stream, _) = remote.into_parts();
        let _ = stream.reset(RESET_LOCAL_IO).await;
        return Err("SOCKS5 server returned UDP relay port zero".to_string());
    }

    let udp = match UdpSocket::bind(SocketAddr::new(local_ip, 0)).await {
        Ok(udp) => udp,
        Err(error) => {
            let _ = write_failure(&mut tcp).await;
            return abort_remote(
                remote,
                format!("bind local SOCKS5 UDP relay failed: {error}"),
            )
            .await;
        }
    };
    let local_udp = match udp.local_addr() {
        Ok(address) => address,
        Err(error) => {
            let _ = write_failure(&mut tcp).await;
            return abort_remote(
                remote,
                format!("read local SOCKS5 UDP relay failed: {error}"),
            )
            .await;
        }
    };
    let datagram = match client.open_datagram(reply.port).await {
        Ok(datagram) => datagram,
        Err(error) => {
            write_failure(&mut tcp).await?;
            let (stream, _) = remote.into_parts();
            let _ = stream.reset(RESET_LOCAL_IO).await;
            return Err(error);
        }
    };
    if let Err(error) = tcp.write_all(&success_reply(local_udp)).await {
        let _ = datagram.close().await;
        return abort_remote(
            remote,
            format!("write local SOCKS5 UDP relay reply failed: {error}"),
        )
        .await;
    }

    bridge_udp(tcp, udp, datagram, remote).await
}

/// Completes controlled no-authentication locally without spending a WAN round trip.
///
/// Example: client `[5,1,0]` receives `[5,0]` directly from yy.
async fn accept_no_auth(tcp: &mut TcpStream) -> Result<(), String> {
    let header = read_tcp_exact(tcp, 2, "SOCKS5 greeting header").await?;
    if header[0] != SOCKS5_VERSION || header[1] == 0 {
        return Err("invalid SOCKS5 greeting".to_string());
    }
    let methods = read_tcp_exact(tcp, header[1] as usize, "SOCKS5 methods").await?;
    if !methods.contains(&0) {
        tcp.write_all(&[SOCKS5_VERSION, 0xff])
            .await
            .map_err(|error| format!("reject SOCKS5 methods failed: {error}"))?;
        return Err("SOCKS5 client did not offer no-authentication".to_string());
    }
    tcp.write_all(&[SOCKS5_VERSION, 0])
        .await
        .map_err(|error| format!("accept SOCKS5 no-authentication failed: {error}"))
}

/// Pipelines daemon-side greeting and request into one mux DATA exchange.
///
/// Example: `[5,1,0] + CONNECT` lets B sing-box answer without a second WAN request.
async fn open_remote_socks(remote: &mut MuxControl, request: &[u8]) -> Result<(), String> {
    let mut pipelined = BytesMut::with_capacity(3 + request.len());
    pipelined.extend_from_slice(&[SOCKS5_VERSION, 1, 0]);
    pipelined.extend_from_slice(request);
    remote.send_all(&pipelined).await?;
    let selection = remote.read_exact(2).await?;
    if selection.as_ref() != [SOCKS5_VERSION, 0] {
        return Err("daemon-side SOCKS5 rejected no-authentication".to_string());
    }
    Ok(())
}

/// Reads one complete SOCKS5 command without consuming later TCP payload.
///
/// Example: a domain request reads its length-prefixed host and two-byte port exactly.
async fn read_request(tcp: &mut TcpStream) -> Result<Request, String> {
    let header = read_tcp_exact(tcp, 4, "SOCKS5 request header").await?;
    if header[0] != SOCKS5_VERSION || header[2] != 0 {
        return Err("invalid SOCKS5 request header".to_string());
    }
    let address = read_tcp_address(tcp, header[3], "SOCKS5 request address").await?;
    let mut raw = BytesMut::with_capacity(header.len() + address.len());
    raw.extend_from_slice(&header);
    raw.extend_from_slice(&address);
    Ok(Request {
        command: header[1],
        raw: raw.freeze(),
    })
}

/// Reads one complete SOCKS5 server reply and extracts its bound port.
///
/// Example: an IPv6 bound address still yields the trailing two-byte port.
async fn read_reply(remote: &mut MuxControl) -> Result<Reply, String> {
    let header = remote.read_exact(4).await?;
    if header[0] != SOCKS5_VERSION || header[2] != 0 {
        return Err("invalid SOCKS5 reply header".to_string());
    }
    let address = remote.read_address(header[3]).await?;
    let port_offset = address
        .len()
        .checked_sub(2)
        .ok_or_else(|| "SOCKS5 reply omitted bound port".to_string())?;
    let port = u16::from_be_bytes([address[port_offset], address[port_offset + 1]]);
    let mut raw = BytesMut::with_capacity(header.len() + address.len());
    raw.extend_from_slice(&header);
    raw.extend_from_slice(&address);
    Ok(Reply {
        status: header[1],
        port,
        raw: raw.freeze(),
    })
}

/// Reads a SOCKS5 address tail from adjacent TCP according to ATYP.
///
/// Example: ATYP 3 reads `length + domain + port`.
async fn read_tcp_address(
    tcp: &mut TcpStream,
    address_type: u8,
    context: &str,
) -> Result<Bytes, String> {
    match address_type {
        1 => read_tcp_exact(tcp, 6, context).await,
        4 => read_tcp_exact(tcp, 18, context).await,
        3 => {
            let length = read_tcp_exact(tcp, 1, context).await?;
            let suffix = read_tcp_exact(tcp, length[0] as usize + 2, context).await?;
            let mut address = BytesMut::with_capacity(1 + suffix.len());
            address.extend_from_slice(&length);
            address.extend_from_slice(&suffix);
            Ok(address.freeze())
        }
        _ => Err(format!("unsupported SOCKS5 address type {address_type}")),
    }
}

/// Reads an exact adjacent TCP field with stable error context.
///
/// Example: a fragmented four-byte header is reassembled before returning.
async fn read_tcp_exact(
    tcp: &mut TcpStream,
    length: usize,
    context: &str,
) -> Result<Bytes, String> {
    let mut output = BytesMut::zeroed(length);
    tcp.read_exact(&mut output)
        .await
        .map_err(|error| format!("read {context} failed: {error}"))?;
    Ok(output.freeze())
}

/// Builds a successful SOCKS5 reply advertising the local UDP relay.
///
/// Example: `127.0.0.1:40000 -> IPv4 success reply`.
fn success_reply(address: SocketAddr) -> Bytes {
    let mut reply = BytesMut::with_capacity(22);
    reply.extend_from_slice(&[SOCKS5_VERSION, 0, 0]);
    match address.ip() {
        IpAddr::V4(ip) => {
            reply.extend_from_slice(&[1]);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.extend_from_slice(&[4]);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&address.port().to_be_bytes());
    reply.freeze()
}

/// Reports a local UDP-association setup failure to the SOCKS5 client.
///
/// Example: mux association rejection -> general failure bound to port zero.
async fn write_failure(tcp: &mut TcpStream) -> Result<(), String> {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let mut reply = BytesMut::from(&success_reply(address)[..]);
    reply[1] = 1;
    tcp.write_all(&reply)
        .await
        .map_err(|error| format!("write SOCKS5 failure reply failed: {error}"))
}

/// Bridges one local SOCKS5 UDP endpoint and its daemon-side relay association.
///
/// Example: closing either TCP control stream tears down only this UDP association.
async fn bridge_udp(
    mut tcp: TcpStream,
    udp: UdpSocket,
    datagram: Datagram,
    mut remote: MuxControl,
) -> Result<(), String> {
    let result = bridge_udp_inner(&mut tcp, &udp, &datagram, &mut remote).await;
    finish_udp(result, datagram, remote).await
}

/// Runs UDP forwarding while the outer owner guarantees cleanup on every exit.
///
/// Example: a failed first packet still closes both mux resources.
async fn bridge_udp_inner(
    tcp: &mut TcpStream,
    udp: &UdpSocket,
    datagram: &Datagram,
    remote: &mut MuxControl,
) -> Result<(), String> {
    let mut buffer = vec![0_u8; MAX_UDP_PACKET];
    let first = loop {
        tokio::select! {
            packet = udp.recv_from(&mut buffer) => {
                let (length, peer) = packet
                    .map_err(|error| format!("receive local SOCKS5 UDP failed: {error}"))?;
                if length != 0 {
                    break (Bytes::copy_from_slice(&buffer[..length]), peer);
                }
            }
            result = wait_tcp_control(tcp) => return result,
            result = remote.wait_control() => return result,
        }
    };
    udp.connect(first.1)
        .await
        .map_err(|error| format!("lock local SOCKS5 UDP peer failed: {error}"))?;
    let _ = datagram.send(first.0).await?;

    let result = loop {
        tokio::select! {
            packet = udp.recv(&mut buffer) => {
                let length = packet
                    .map_err(|error| format!("receive local SOCKS5 UDP failed: {error}"))?;
                if length != 0 {
                    let _ = datagram.send(Bytes::copy_from_slice(&buffer[..length])).await?;
                }
            }
            packet = datagram.recv() => {
                let Some(packet) = packet else {
                    break Ok(());
                };
                udp.send(&packet)
                    .await
                    .map_err(|error| format!("send local SOCKS5 UDP failed: {error}"))?;
            }
            result = wait_tcp_control(tcp) => break result,
            result = remote.wait_control() => break result,
        }
    };
    result
}

/// Waits for a SOCKS5 UDP control connection to close without accepting payload.
///
/// Example: EOF ends the association; any extra TCP byte is rejected as garbage.
async fn wait_tcp_control(tcp: &mut TcpStream) -> Result<(), String> {
    let mut byte = [0_u8; 1];
    match tcp.read(&mut byte).await {
        Ok(0) => Ok(()),
        Ok(_) => Err("unexpected data on SOCKS5 UDP control connection".to_string()),
        Err(error) => Err(format!(
            "read SOCKS5 UDP control connection failed: {error}"
        )),
    }
}

/// Closes both mux resources after one UDP association ends.
///
/// Example: client TCP EOF emits DATAGRAM_CLOSE and resets its B-side control stream.
async fn finish_udp(
    result: Result<(), String>,
    datagram: Datagram,
    remote: MuxControl,
) -> Result<(), String> {
    let _ = datagram.close().await;
    let (stream, _) = remote.into_parts();
    let _ = stream.reset(RESET_LOCAL_IO).await;
    result
}

/// Resets one partially negotiated B-side stream before returning its error.
///
/// Example: a malformed SOCKS5 request cannot retain one mux stream slot.
async fn abort_remote(remote: MuxControl, error: String) -> Result<(), String> {
    let (stream, _) = remote.into_parts();
    let _ = stream.reset(RESET_LOCAL_IO).await;
    Err(error)
}

impl MuxControl {
    /// Creates a field-aware reader around one newly opened logical stream.
    ///
    /// Example: an empty buffer precedes the first SOCKS5 method reply.
    fn new(stream: Stream) -> Self {
        Self {
            stream,
            buffered: BytesMut::new(),
        }
    }

    /// Sends all control bytes while respecting stream and connection windows.
    ///
    /// Example: a short SOCKS5 request normally consumes one send permit.
    async fn send_all(&self, mut payload: &[u8]) -> Result<(), String> {
        while !payload.is_empty() {
            let permit = self.stream.reserve_send().await?;
            let length = permit.amount().min(payload.len());
            permit
                .send(Bytes::copy_from_slice(&payload[..length]))
                .await?;
            payload = &payload[length..];
        }
        self.stream.mark_send_idle().await
    }

    /// Reads exactly one protocol field and retains any following target bytes.
    ///
    /// Example: reading two reply bytes from a larger DATA frame preserves its suffix.
    async fn read_exact(&mut self, length: usize) -> Result<Bytes, String> {
        while self.buffered.len() < length {
            let payload = self
                .stream
                .recv_chunk()
                .await
                .ok_or_else(|| "daemon-side SOCKS5 control stream closed".to_string())?;
            self.buffered.extend_from_slice(&payload);
        }
        let output = self.buffered.split_to(length).freeze();
        self.stream.consumed(length).await?;
        Ok(output)
    }

    /// Reads one SOCKS5 address tail from the mux stream according to ATYP.
    ///
    /// Example: ATYP 1 reads four IPv4 bytes followed by two port bytes.
    async fn read_address(&mut self, address_type: u8) -> Result<Bytes, String> {
        match address_type {
            1 => self.read_exact(6).await,
            4 => self.read_exact(18).await,
            3 => {
                let length = self.read_exact(1).await?;
                let suffix = self.read_exact(length[0] as usize + 2).await?;
                let mut address = BytesMut::with_capacity(1 + suffix.len());
                address.extend_from_slice(&length);
                address.extend_from_slice(&suffix);
                Ok(address.freeze())
            }
            _ => Err(format!(
                "unsupported SOCKS5 reply address type {address_type}"
            )),
        }
    }

    /// Waits for B-side UDP control closure and rejects unexpected TCP payload.
    ///
    /// Example: daemon FIN returns success and releases the matching UDP association.
    async fn wait_control(&mut self) -> Result<(), String> {
        if !self.buffered.is_empty() {
            return Err("unexpected buffered data on SOCKS5 UDP control stream".to_string());
        }
        match self.stream.recv_chunk().await {
            None => Ok(()),
            Some(payload) => {
                self.stream.consumed(payload.len()).await?;
                Err("unexpected data on daemon-side SOCKS5 UDP control stream".to_string())
            }
        }
    }

    /// Returns the logical stream and any bytes received after SOCKS5 negotiation.
    ///
    /// Example: CONNECT success plus an SSH banner yields a non-empty prefix.
    fn into_parts(self) -> (Stream, Bytes) {
        (self.stream, self.buffered.freeze())
    }
}

#[cfg(test)]
#[path = "socks_test.rs"]
mod socks_test;

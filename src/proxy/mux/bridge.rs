use std::io::ErrorKind;

use bytes::BytesMut;
use futures_util::FutureExt;
use tokio::{io::AsyncWriteExt, net::tcp::OwnedReadHalf, net::TcpStream};

use super::core::{Stream, RESET_LOCAL_IO};

/// Bridges one adjacent business TCP and one logical mux stream bidirectionally.
///
/// Example: yy passes its sing-box TCP; daemon passes its target TCP.
pub(super) async fn bridge_tcp(tcp: TcpStream, stream: Stream) -> Result<(), String> {
    let (tcp_reader, mut tcp_writer) = tcp.into_split();
    let upload = async {
        let mut scheduler_active = false;
        loop {
            wait_readable(&tcp_reader, &stream, &mut scheduler_active).await?;
            // 为什么先等 readable 再占 window：
            // - 触发条件：连接总 window 被所有 stream 共享。
            // - 不能先占 credit 再等 TCP：空闲 stream 会囤积公共额度。
            // - 防止副作用：window=0 时仍不会执行下面的 try_read。
            let permit = stream.reserve_send().await?;
            let mut payload = BytesMut::zeroed(permit.amount());
            match tcp_reader.try_read(&mut payload) {
                Ok(0) => {
                    drop(permit);
                    stream.finish_send().await?;
                    return Ok::<(), String>(());
                }
                Ok(read) => {
                    payload.truncate(read);
                    permit.send(payload.freeze()).await?;
                    scheduler_active = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    drop(permit);
                }
                Err(error) => return Err(format!("read adjacent tcp failed: {error}")),
            }
        }
    };
    let download = async {
        while let Some(payload) = stream.recv_chunk().await {
            tcp_writer
                .write_all(&payload)
                .await
                .map_err(|error| format!("write adjacent tcp failed: {error}"))?;
            // WINDOW_UPDATE 必须在目标 TCP 实际消费后生成，不能在收到 DATA 时提前返还。
            stream.consumed(payload.len()).await?;
        }
        tcp_writer
            .shutdown()
            .await
            .map_err(|error| format!("shutdown adjacent tcp failed: {error}"))?;
        Ok::<(), String>(())
    };

    let result = tokio::try_join!(upload, download).map(|_| ());
    if result.is_err() {
        let _ = stream.reset(RESET_LOCAL_IO).await;
    } else {
        stream.complete().await?;
    }
    result
}

/// Waits for adjacent TCP data and marks a previously active flow idle when needed.
///
/// Example: immediately readable bulk TCP stays active; a pause aligns its next DATA on rejoin.
async fn wait_readable(
    tcp_reader: &OwnedReadHalf,
    stream: &Stream,
    scheduler_active: &mut bool,
) -> Result<(), String> {
    if *scheduler_active {
        if let Some(result) = tcp_reader.readable().now_or_never() {
            return result.map_err(|error| format!("wait adjacent tcp readable failed: {error}"));
        }
        stream.mark_send_idle().await?;
        *scheduler_active = false;
    }
    tokio::select! {
        ready = tcp_reader.readable() => {
            ready.map_err(|error| format!("wait adjacent tcp readable failed: {error}"))
        }
        _ = stream.closed() => Err("mux stream closed".to_string()),
    }
}

#[cfg(test)]
#[path = "bridge_test.rs"]
mod bridge_test;

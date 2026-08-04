use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::discovery::Report;

const DEFAULT_PORT: u16 = 9000;
const RECORD_TTL: Duration = Duration::from_secs(10);

/// CLI configuration for the in-memory discovery center.
///
/// Example: no flags -> `0.0.0.0:9000`.
pub(crate) struct Config {
    /// Local IP on which the center Web service listens.
    pub(crate) listen_ip: IpAddr,
    /// Local TCP port on which the center Web service listens.
    pub(crate) port: u16,
}

impl Config {
    /// Parses contextual `-ip` and `-port` center flags.
    ///
    /// Example: `-ip 127.0.0.1 -port 9100` -> `127.0.0.1:9100`.
    pub(crate) fn parse(args: &[String]) -> Result<Self, String> {
        if args.len() % 2 != 0 {
            return Err(center_usage());
        }
        let mut listen_ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let mut port = DEFAULT_PORT;
        let mut ip_seen = false;
        let mut port_seen = false;
        for pair in args.chunks_exact(2) {
            match pair[0].as_str() {
                "-ip" if !ip_seen => {
                    listen_ip = pair[1]
                        .parse()
                        .map_err(|error| format!("invalid center -ip: {error}"))?;
                    ip_seen = true;
                }
                "-port" if !port_seen => {
                    port = parse_port(&pair[1], "center -port")?;
                    port_seen = true;
                }
                _ => return Err(center_usage()),
            }
        }
        Ok(Self { listen_ip, port })
    }

    /// Returns the exact socket address used by the center listener.
    ///
    /// Example: IP `0.0.0.0`, port `9000` -> `0.0.0.0:9000`.
    fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.listen_ip, self.port)
    }
}

/// Shared center state cloned into Axum request handlers.
#[derive(Clone)]
struct CenterState {
    /// Latest report per daemon key and its receive time.
    records: Arc<RwLock<HashMap<String, StoredReport>>>,
}

/// One report retained until its ten-second freshness window expires.
struct StoredReport {
    /// Public record returned by `/list`.
    report: Report,
    /// Monotonic time at which `/report` accepted the record.
    received_at: Instant,
}

/// Runs the in-memory discovery Web service indefinitely.
///
/// Example: `-center` exposes `POST /report` and `GET /list` on port 9000.
pub(crate) async fn run(config: Config) -> Result<(), String> {
    let address = config.listen_addr();
    let listener = TcpListener::bind(address)
        .await
        .map_err(|error| format!("listen discovery center on {address} failed: {error}"))?;
    let state = CenterState {
        records: Arc::new(RwLock::new(HashMap::new())),
    };
    let app = Router::new()
        .route("/report", post(post_report))
        .route("/list", get(get_list))
        .with_state(state);
    println!("discovery center listening on {address}");
    axum::serve(listener, app)
        .await
        .map_err(|error| format!("serve discovery center failed: {error}"))
}

/// Stores a valid daemon report, replacing the previous value for its key.
///
/// Example: a second `nas-01` report atomically replaces the first.
async fn post_report(
    State(state): State<CenterState>,
    Json(report): Json<Report>,
) -> Result<StatusCode, (StatusCode, String)> {
    report
        .validate()
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let key = report.key.clone();
    state.records.write().await.insert(
        key,
        StoredReport {
            report,
            received_at: Instant::now(),
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Returns fresh records sorted by key and removes stale records.
///
/// Example: reports older than ten seconds are absent from the JSON array.
async fn get_list(State(state): State<CenterState>) -> Json<Vec<Report>> {
    let mut records = state.records.write().await;
    records.retain(|_, stored| stored.received_at.elapsed() < RECORD_TTL);
    let mut result = records
        .values()
        .map(|stored| stored.report.clone())
        .collect::<Vec<_>>();
    result.sort_by(|left, right| left.key.cmp(&right.key));
    Json(result)
}

/// Parses one non-zero TCP port for center mode.
///
/// Example: `"9000" -> 9000`, `"0" -> error`.
fn parse_port(raw: &str, name: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .map_err(|_| format!("{name} must be 1..65535"))
        .and_then(|port| {
            if port == 0 {
                Err(format!("{name} must be 1..65535"))
            } else {
                Ok(port)
            }
        })
}

/// Returns the accepted center command syntax.
///
/// Example: malformed flags -> this usage string.
fn center_usage() -> String {
    "usage: tmp-proxy -center [-ip <listen_ip>] [-port <listen_port>]".to_string()
}

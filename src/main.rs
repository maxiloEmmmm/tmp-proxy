mod access_uuid;
mod cf_lib;
mod connection_activity;
mod daemon;
mod discovery;
mod target_proxy;

/// Generated Cloudflare QUIC request-stream schema.
///
/// Example: Cap'n Proto request bytes -> typed metadata reader.
#[allow(dead_code)]
pub(crate) mod quic_metadata_protocol_capnp {
    include!(concat!(env!("OUT_DIR"), "/quic_metadata_protocol_capnp.rs"));
}

/// Generated Cloudflare registration RPC schema.
///
/// Example: registration params -> Cap'n Proto wire builder.
#[allow(dead_code)]
pub(crate) mod tunnelrpc_capnp {
    include!(concat!(env!("OUT_DIR"), "/tunnelrpc_capnp.rs"));
}

use bytes::Bytes;
use cf_lib::SessionEvent;
use eframe::egui;
use futures_util::{SinkExt, StreamExt};
use std::env;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command as TokioCommand;
use tokio::runtime::{Builder, Handle};
use tokio::task::JoinHandle;
use tokio::time;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as TokioMessage};
use tokio_util::sync::CancellationToken;
use url::Url;

const DEFAULT_YY_LISTEN: &str = "0.0.0.0:0";
const DEFAULT_NAS_SSH_PORT: &str = "22";

/// CLI mode selected from process arguments.
///
/// Example: `[] -> Gui`, `["-yy", "wss://x/tcp?code=<uuid>"] -> Yy`.
enum LaunchMode {
    /// Start the graphical xx side for the device/user machine.
    Gui,
    /// Start the xx side without a GUI for diagnostics or server usage.
    Xx(XxConfig),
    /// Start the yy side that exposes a local TCP listener.
    Yy(YyConfig),
    /// Start yy-like proxying and run a local command with the chosen port.
    Zz(ZzConfig),
    /// Start the non-GUI target proxy with rotating access codes.
    Daemon(daemon::Config),
    /// Start the in-memory discovery center Web service.
    Center(discovery::center::Config),
}

/// Source used to resolve the WSS endpoint for yy/zz.
///
/// Example: `Kv { key: "cfp/demo", query: "port=544" }` -> one discovered URL.
enum EndpointSpec {
    /// A complete WSS URL supplied directly by the caller.
    Url(String),
    /// A complete Cloudflare KV key plus optional raw query suffix.
    Kv {
        /// Full KV key, including any configured prefix.
        key: String,
        /// Optional query string appended after the generated `code` query.
        query: Option<String>,
    },
}

/// Runtime configuration for yy mode.
///
/// Example: `wss_url=wss://a.trycloudflare.com/tcp?code=<uuid>`.
struct YyConfig {
    /// WSS endpoint source.
    endpoint: EndpointSpec,
    /// Local TCP listener address used by yy.
    listen_addr: String,
}

/// Runtime configuration for headless xx mode.
///
/// Example: `tmp-proxy xx 192.168.32.17:22 admin`.
struct XxConfig {
    /// Target endpoint reachable from the user-side machine.
    target: String,
    /// SSH username inserted into the final zz command.
    username: String,
}

/// Runtime configuration for zz mode.
///
/// Example: `tmp-proxy zz wss://x/tcp?code=<uuid> -- ssh -p {PORT} u@127.0.0.1`.
struct ZzConfig {
    /// WSS endpoint source.
    endpoint: EndpointSpec,
    /// Command vector after `--`, with `{PORT}` placeholders.
    command: Vec<String>,
}

/// Request sent from the GUI to the xx worker.
///
/// Example: `target=10.0.0.58:22, username=eustache`.
struct XxRequest {
    /// Target endpoint reachable from the user-side machine.
    target: String,
    /// SSH username inserted into the final zz command.
    username: String,
}

/// Messages emitted by the async worker to the GUI.
///
/// Example: `Ready { wss_url, pairing_uuid, yy_command }`.
enum GuiEvent {
    /// Human-readable status update.
    Status(String),
    /// Tunnel is ready and the user can run yy.
    Ready {
        /// Public WSS URL consumed by yy, including the pairing UUID.
        wss_url: String,
        /// UUID v4 embedded in `wss_url` under the stable `code` key.
        pairing_uuid: String,
        /// Ready-to-run zz command.
        zz_command: String,
    },
    /// Fatal worker error.
    Error(String),
    /// Worker stopped without producing a ready URL.
    Stopped(String),
}

/// Handle for a running xx background worker.
///
/// Example: `handle.stop()` cancels the local tunnel runtime.
struct RunningWorker {
    /// Cancellation token shared with the tunnel thread.
    cancel: CancellationToken,
    /// Tokio task supervising the worker lifetime.
    task: JoinHandle<()>,
}

/// egui state for the xx graphical workflow.
///
/// Example: user enters `10.0.0.58:22`, clicks start, then sees a URL and UUID.
struct ProxyGui {
    /// Tokio handle used to spawn validation work.
    runtime: Handle,
    /// Target host:port typed by the user.
    target_input: String,
    /// NAS web username typed by the user for the generated ssh command.
    username_input: String,
    /// Current status line shown in the UI.
    status: String,
    /// WSS URL used by yy.
    wss_url: String,
    /// Pairing UUID embedded in the URL under the stable `code` key.
    pairing_uuid: String,
    /// Ready-to-run zz command.
    zz_command: String,
    /// Deadline for the temporary copy feedback label.
    copy_tip_until: Option<Instant>,
    /// Receiver for async worker events.
    receiver: Option<mpsc::Receiver<GuiEvent>>,
    /// Running worker handle, if the tunnel is active.
    worker: Option<RunningWorker>,
}

/// Starts the selected program mode.
///
/// Example: `tmp-proxy` starts GUI; `tmp-proxy zz wss://x -- ssh -p {PORT} u@127.0.0.1`.
fn main() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}

/// Builds the Tokio runtime manually and dispatches CLI mode.
///
/// Example: no arguments opens the xx window.
fn run() -> Result<i32, String> {
    let mode = parse_launch_mode(env::args().skip(1).collect())?;
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("create tokio runtime failed: {err}"))?;

    match mode {
        LaunchMode::Gui => run_gui(runtime.handle().clone()).map(|_| 0),
        LaunchMode::Xx(config) => runtime.block_on(run_headless_xx(config)).map(|_| 0),
        LaunchMode::Yy(config) => runtime.block_on(run_yy(config)).map(|_| 0),
        LaunchMode::Zz(config) => runtime.block_on(run_zz(config)),
        LaunchMode::Daemon(config) => runtime.block_on(daemon::run(config)).map(|_| 0),
        LaunchMode::Center(config) => runtime.block_on(discovery::center::run(config)).map(|_| 0),
    }
}

/// Parses the small public CLI surface.
///
/// Example: `["zz", "wss://x", "--", "ssh", "-p", "{PORT}"] -> zz config`.
fn parse_launch_mode(args: Vec<String>) -> Result<LaunchMode, String> {
    match args.as_slice() {
        [] => Ok(LaunchMode::Gui),
        [flag, rest @ ..] if flag == "-daemon" => {
            daemon::Config::parse(rest).map(LaunchMode::Daemon)
        }
        [flag, rest @ ..] if flag == "-center" => {
            discovery::center::Config::parse(rest).map(LaunchMode::Center)
        }
        [subcommand, target, username] if subcommand == "xx" => Ok(LaunchMode::Xx(XxConfig {
            target: target.clone(),
            username: username.clone(),
        })),
        [flag, rest @ ..] if flag == "-yy" => parse_yy_mode(rest),
        [subcommand, rest @ ..] if subcommand == "zz" => parse_zz_mode(rest),
        _ => Err(launch_usage()),
    }
}

/// Parses yy's direct-URL and KV-key forms.
///
/// Example: `-kvk cfp/demo -query port=544` -> KV endpoint with query suffix.
fn parse_yy_mode(args: &[String]) -> Result<LaunchMode, String> {
    if args.first().map(String::as_str) == Some("-kvk") {
        let key = args
            .get(1)
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .ok_or_else(launch_usage)?;
        let mut query = None;
        let mut listen_addr = DEFAULT_YY_LISTEN.to_string();
        let mut index = 2;
        while index < args.len() {
            match args[index].as_str() {
                "-query" if query.is_none() => {
                    query = Some(
                        args.get(index + 1)
                            .filter(|value| !value.is_empty())
                            .cloned()
                            .ok_or_else(launch_usage)?,
                    );
                    index += 2;
                }
                _ if index + 1 == args.len() && listen_addr == DEFAULT_YY_LISTEN => {
                    listen_addr = args[index].clone();
                    index += 1;
                }
                _ => return Err(launch_usage()),
            }
        }
        return Ok(LaunchMode::Yy(YyConfig {
            endpoint: EndpointSpec::Kv { key, query },
            listen_addr,
        }));
    }
    match args {
        [wss_url] => Ok(LaunchMode::Yy(YyConfig {
            endpoint: EndpointSpec::Url(wss_url.clone()),
            listen_addr: DEFAULT_YY_LISTEN.to_string(),
        })),
        [wss_url, listen_addr] => Ok(LaunchMode::Yy(YyConfig {
            endpoint: EndpointSpec::Url(wss_url.clone()),
            listen_addr: listen_addr.clone(),
        })),
        _ => Err(launch_usage()),
    }
}

/// Parses zz's direct-URL and KV-key forms.
///
/// Example: `-kvk cfp/demo -- ssh -p {PORT}` -> KV-backed zz mode.
fn parse_zz_mode(args: &[String]) -> Result<LaunchMode, String> {
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(launch_usage)?;
    if separator == 0 || separator + 1 >= args.len() {
        return Err(launch_usage());
    }
    let endpoint_args = &args[..separator];
    let command = args[separator + 1..].to_vec();
    let endpoint = match endpoint_args {
        [wss_url] => EndpointSpec::Url(wss_url.clone()),
        [flag, key] if flag == "-kvk" && !key.trim().is_empty() => EndpointSpec::Kv {
            key: key.clone(),
            query: None,
        },
        [flag, key, query_flag, query]
            if flag == "-kvk"
                && query_flag == "-query"
                && !key.trim().is_empty()
                && !query.is_empty() =>
        {
            EndpointSpec::Kv {
                key: key.clone(),
                query: Some(query.clone()),
            }
        }
        _ => return Err(launch_usage()),
    };
    Ok(LaunchMode::Zz(ZzConfig { endpoint, command }))
}

/// Returns the public command syntax.
///
/// Example: malformed `-kvk` arguments -> this usage string.
fn launch_usage() -> String {
    "usage: tmp-proxy | tmp-proxy xx <target> <username> | tmp-proxy -yy <wss_url> [listen_addr] | tmp-proxy -yy -kvk <full_kv_key> [-query <query>] [listen_addr] | tmp-proxy zz <wss_url> -- <command...> | tmp-proxy zz -kvk <full_kv_key> [-query <query>] -- <command...> | tmp-proxy -daemon ... | tmp-proxy -center ...".to_string()
}

/// Runs the native xx GUI.
///
/// Example: `run_gui(handle)` opens a window with a target field.
fn run_gui(runtime: Handle) -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([560.0, 320.0])
            .with_min_inner_size([480.0, 260.0]),
        ..Default::default()
    };
    eframe::run_native(
        "tmp-proxy",
        options,
        Box::new(move |context| {
            context.egui_ctx.set_visuals(build_gui_visuals());
            Ok(Box::new(ProxyGui::new(runtime.clone())))
        }),
    )
    .map_err(|err| format!("start gui failed: {err}"))
}

/// Builds a high-contrast dark theme for small remote desktop windows.
///
/// Example: `build_gui_visuals()` returns dark visuals with readable labels.
fn build_gui_visuals() -> egui::Visuals {
    let mut visuals = egui::Visuals::dark();
    let text = egui::Color32::from_rgb(232, 238, 247);
    let weak_text = egui::Color32::from_rgb(194, 204, 219);
    let panel = egui::Color32::from_rgb(18, 25, 34);
    let input = egui::Color32::from_rgb(4, 8, 13);
    let button = egui::Color32::from_rgb(33, 43, 56);
    let hovered = egui::Color32::from_rgb(47, 61, 78);
    let active = egui::Color32::from_rgb(59, 78, 101);
    let stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(102, 119, 142));

    visuals.panel_fill = panel;
    visuals.window_fill = panel;
    visuals.extreme_bg_color = input;
    visuals.text_edit_bg_color = Some(input);
    visuals.faint_bg_color = egui::Color32::from_rgb(25, 34, 45);
    visuals.weak_text_color = Some(weak_text);

    visuals.widgets.noninteractive.fg_stroke.color = text;
    visuals.widgets.inactive.fg_stroke.color = text;
    visuals.widgets.hovered.fg_stroke.color = text;
    visuals.widgets.active.fg_stroke.color = text;
    visuals.widgets.open.fg_stroke.color = text;

    visuals.widgets.inactive.bg_fill = button;
    visuals.widgets.inactive.weak_bg_fill = button;
    visuals.widgets.inactive.bg_stroke = stroke;
    visuals.widgets.hovered.bg_fill = hovered;
    visuals.widgets.hovered.weak_bg_fill = hovered;
    visuals.widgets.hovered.bg_stroke = stroke;
    visuals.widgets.active.bg_fill = active;
    visuals.widgets.active.weak_bg_fill = active;
    visuals.widgets.active.bg_stroke = stroke;
    visuals.widgets.open.bg_fill = hovered;
    visuals.widgets.open.weak_bg_fill = hovered;
    visuals.widgets.open.bg_stroke = stroke;
    visuals
}

impl ProxyGui {
    /// Creates the initial GUI state.
    ///
    /// Example: `ProxyGui::new(handle)` starts with empty target input.
    fn new(runtime: Handle) -> Self {
        Self {
            runtime,
            target_input: String::new(),
            username_input: String::new(),
            status: "idle".to_string(),
            wss_url: String::new(),
            pairing_uuid: String::new(),
            zz_command: String::new(),
            copy_tip_until: None,
            receiver: None,
            worker: None,
        }
    }

    /// Starts the xx worker after collecting GUI inputs.
    ///
    /// Example: target `10.0.0.58:22` starts validation and tunnel setup.
    fn start_worker(&mut self) {
        if self.worker.is_some() {
            return;
        }

        let target = normalize_gui_target(&self.target_input);
        self.target_input = target.clone();
        let username = self.username_input.trim().to_string();
        let (sender, receiver) = mpsc::channel();
        let cancel = CancellationToken::new();
        let request = XxRequest { target, username };
        let worker_cancel = cancel.clone();
        let task = self.runtime.spawn(async move {
            if let Err(err) = run_xx_worker(request, sender.clone(), worker_cancel).await {
                let _ = sender.send(GuiEvent::Error(err));
            }
        });

        self.status = "starting".to_string();
        self.wss_url.clear();
        self.pairing_uuid.clear();
        self.zz_command.clear();
        self.copy_tip_until = None;
        self.receiver = Some(receiver);
        self.worker = Some(RunningWorker { cancel, task });
    }

    /// Stops the running xx worker and clears the handle.
    ///
    /// Example: called when the window closes, so the tunnel runtime is cancelled.
    fn stop_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.cancel.cancel();
            worker.task.abort();
            self.status = "stopped".to_string();
        }
    }

    /// Applies pending worker events to the GUI state.
    ///
    /// Example: `Ready` fills the URL, UUID, and yy command fields.
    fn drain_events(&mut self) {
        let Some(receiver) = &self.receiver else {
            return;
        };

        while let Ok(event) = receiver.try_recv() {
            match event {
                GuiEvent::Status(text) => self.status = text,
                GuiEvent::Ready {
                    wss_url,
                    pairing_uuid,
                    zz_command,
                } => {
                    self.status = "ready".to_string();
                    self.wss_url = wss_url;
                    self.pairing_uuid = pairing_uuid;
                    self.zz_command = zz_command;
                }
                GuiEvent::Error(text) => {
                    self.status = format!("error: {text}");
                    self.worker = None;
                }
                GuiEvent::Stopped(text) => {
                    self.status = text;
                    self.worker = None;
                }
            }
        }
    }
}

/// Normalizes the GUI target before validation and display.
///
/// Example: `"192.168.32.17" -> "192.168.32.17:22"`.
fn normalize_gui_target(raw: &str) -> String {
    let target = raw.trim();
    if target
        .rsplit_once(':')
        .is_some_and(|(_, port)| !port.is_empty())
    {
        target.to_string()
    } else {
        format!("{target}:{DEFAULT_NAS_SSH_PORT}")
    }
}

impl Drop for ProxyGui {
    /// Stops background tunnel resources when the GUI is dropped.
    ///
    /// Example: closing the window cancels the Cloudflare session.
    fn drop(&mut self) {
        self.stop_worker();
    }
}

impl eframe::App for ProxyGui {
    /// Renders the xx user interface.
    ///
    /// Example: pressing Start verifies target and creates a tunnel.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_events();
        self.clear_expired_copy_tip();

        ui.vertical(|ui| {
            ui.heading("tmp-proxy");
            ui.add_space(8.0);
            ui.label("Please confirm NAS version is 1.10+ and enable NAS SSH: Settings -> Security -> SSH");
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label("nas ip:ssh-port");
                ui.text_edit_singleline(&mut self.target_input);
                ui.label("(default ssh port: 22)");
            });

            ui.horizontal(|ui| {
                ui.label("nas web username");
                ui.text_edit_singleline(&mut self.username_input);
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(self.worker.is_none(), egui::Button::new("Start"))
                    .clicked()
                {
                    self.start_worker();
                }
                if ui
                    .add_enabled(self.worker.is_some(), egui::Button::new("Stop"))
                    .clicked()
                {
                    self.stop_worker();
                }
            });

            ui.separator();
            ui.label(format!("status: {}", self.status));
            if !self.wss_url.is_empty() {
                ui.label("url");
                ui.text_edit_singleline(&mut self.wss_url);
            }
            if !self.pairing_uuid.is_empty() {
                ui.label("uuid");
                ui.text_edit_singleline(&mut self.pairing_uuid);
            }
            if !self.zz_command.is_empty() {
                ui.label("zz");
                ui.horizontal(|ui| {
                    ui.text_edit_multiline(&mut self.zz_command);
                    if ui.button("Copy").clicked() {
                        ui.ctx().copy_text(self.zz_command.clone());
                        self.copy_tip_until = Some(Instant::now() + Duration::from_secs(2));
                    }
                });
                if self.copy_tip_until.is_some() {
                    ui.label("Copied");
                }
            }
        });

        if self.worker.is_some() || self.copy_tip_until.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(100));
        }
    }
}

impl ProxyGui {
    /// Clears the temporary copy feedback after its deadline.
    ///
    /// Example: deadline older than now hides `Copied`.
    fn clear_expired_copy_tip(&mut self) {
        if self
            .copy_tip_until
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.copy_tip_until = None;
        }
    }
}

/// Runs the xx-side workflow behind the GUI.
///
/// Example: validates `10.0.0.58:22` and `eustache`, then starts a tunnel.
async fn run_xx_worker(
    request: XxRequest,
    sender: mpsc::Sender<GuiEvent>,
    cancel: CancellationToken,
) -> Result<(), String> {
    let target = validate_target(&request.target)?;
    let username = validate_username(&request.username)?;
    send_status(&sender, format!("checking {target}"));
    check_target_open(&target).await?;

    let pairing_uuid = generate_pairing_uuid();
    send_status(&sender, "target ready, creating tunnel".to_string());
    run_cf_tunnel(target, username, pairing_uuid, sender.clone(), cancel).await?;
    let _ = sender.send(GuiEvent::Stopped("stopped".to_string()));
    Ok(())
}

/// Sends a best-effort status update to the GUI.
///
/// Example: `send_status(tx, "ready")` updates the status label.
fn send_status(sender: &mpsc::Sender<GuiEvent>, text: String) {
    let _ = sender.send(GuiEvent::Status(text));
}

/// Runs xx mode without a GUI and prints worker events to stdout.
///
/// Example: `tmp-proxy xx 192.168.32.17:22 admin` prints the zz command.
async fn run_headless_xx(config: XxConfig) -> Result<(), String> {
    let (sender, receiver) = mpsc::channel();
    let cancel = CancellationToken::new();
    thread::Builder::new()
        .name("tmp-proxy-headless-events".to_string())
        .spawn(move || print_headless_events(receiver))
        .map_err(|err| format!("start event printer failed: {err}"))?;
    run_xx_worker(
        XxRequest {
            target: config.target,
            username: config.username,
        },
        sender,
        cancel,
    )
    .await
}

/// Prints headless xx events in a shell-friendly format.
///
/// Example: `Ready` emits `zz: tmp-proxy zz ...`.
fn print_headless_events(receiver: mpsc::Receiver<GuiEvent>) {
    while let Ok(event) = receiver.recv() {
        match event {
            GuiEvent::Status(text) => println!("status: {text}"),
            GuiEvent::Ready {
                wss_url,
                pairing_uuid,
                zz_command,
            } => {
                println!("url: {wss_url}");
                println!("uuid: {pairing_uuid}");
                println!("zz: {zz_command}");
            }
            GuiEvent::Error(text) => println!("error: {text}"),
            GuiEvent::Stopped(text) => println!("status: {text}"),
        }
    }
}

/// Validates a target endpoint string.
///
/// Example: `"10.0.0.58:22" -> Ok("10.0.0.58:22")`.
fn validate_target(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err("nas ip:ssh-port must be host:port".to_string());
    };
    if host.trim().is_empty() {
        return Err("nas ip is empty".to_string());
    }
    parse_port(port.trim(), "nas ssh port")?;
    Ok(format!("{}:{}", host.trim(), port.trim()))
}

/// Validates a username that will be embedded into the generated ssh command.
///
/// Example: `" eustache " -> Ok("eustache")`.
fn validate_username(raw: &str) -> Result<String, String> {
    let username = raw.trim();
    if username.is_empty() {
        return Err("nas web username is empty".to_string());
    }
    Ok(username.to_string())
}

/// Parses one TCP port.
///
/// Example: `"22" -> Ok(22)`, `"0" -> Err`.
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

/// Verifies that the target TCP port is open from the xx side.
///
/// Example: `check_target_open("10.0.0.58:22")` succeeds when SSH is reachable.
async fn check_target_open(target: &str) -> Result<(), String> {
    time::timeout(Duration::from_secs(5), TcpStream::connect(target))
        .await
        .map_err(|_| format!("connect {target} timed out"))?
        .map_err(|err| format!("connect {target} failed: {err}"))?;
    Ok(())
}

/// Generates a UUID v4 for one tunnel session.
///
/// Example: `generate_pairing_uuid() -> one canonical UUID v4 string`.
fn generate_pairing_uuid() -> String {
    access_uuid::AccessUuid::generate().value().to_string()
}

/// Creates a Quick Tunnel and serves Cloudflare requests through it.
///
/// Example: prints `wss://host/tcp?code=<uuid>` after Cloudflare registers.
async fn run_cf_tunnel(
    target: String,
    username: String,
    pairing_uuid: String,
    sender: mpsc::Sender<GuiEvent>,
    cancel: CancellationToken,
) -> Result<(), String> {
    send_status(&sender, "creating trycloudflare tunnel".to_string());
    let quick_tunnel = cf_lib::create_quick_tunnel()
        .await
        .map_err(|err| format!("create tunnel failed: {err}"))?;
    let wss_url = target_proxy::build_wss_url(&quick_tunnel.hostname, &pairing_uuid, None)?;
    let session = quick_tunnel.session;
    let mut events = session.events();
    let zz_command = build_default_zz_command(&wss_url, &username);
    let mut ready_sent = false;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                session.shutdown().await
                    .map_err(|error| format!("shutdown tunnel failed: {error}"))?;
                return Ok(());
            }
            event = events.recv() => match event {
                Ok(SessionEvent::Connected { transport, location }) => {
                    if !ready_sent {
                        let _ = sender.send(GuiEvent::Ready {
                            wss_url: wss_url.clone(),
                            pairing_uuid: pairing_uuid.clone(),
                            zz_command: zz_command.clone(),
                        });
                        ready_sent = true;
                    }
                    send_status(&sender, format!("ready via {transport:?} at {location}"));
                }
                Ok(SessionEvent::Reconnecting { delay, reason }) => send_status(
                    &sender,
                    format!("connection lost ({reason}), retrying in {}ms", delay.as_millis()),
                ),
                Ok(SessionEvent::Stopped) => return Ok(()),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Err("tunnel event channel closed".to_string());
                }
            },
            request = session.accept() => {
                let request = request.map_err(|error| format!("accept tunnel request failed: {error}"))?;
                let target = target_proxy::Target::fixed(target.clone());
                let pairing_uuid = pairing_uuid.clone();
                tokio::spawn(async move {
                    if let Err(error) = target_proxy::handle_request(
                        request,
                        target,
                        pairing_uuid,
                        None,
                    ).await {
                        eprintln!("{error}");
                    }
                });
            }
        }
    }
}

/// Builds the default shell command shown in the xx GUI.
///
/// Example: `url=wss://x, user=e -> tmp-proxy zz 'wss://x' -- ssh -p {PORT} 'e@127.0.0.1'`.
fn build_default_zz_command(wss_url: &str, username: &str) -> String {
    format!(
        "tmp-proxy zz {} -- ssh -p {{PORT}} {}",
        shell_quote_single(wss_url),
        shell_quote_single(&format!("{username}@127.0.0.1"))
    )
}

/// Quotes one value for POSIX-like shells.
///
/// Example: `a'b -> 'a'\''b'`.
fn shell_quote_single(raw: &str) -> String {
    format!("'{}'", raw.replace('\'', "'\\''"))
}

/// Runs yy mode and exposes a local TCP listener.
///
/// Example: `tmp-proxy -yy wss://x/tcp?code=<uuid> 0.0.0.0:0`.
async fn run_yy(config: YyConfig) -> Result<(), String> {
    let wss_url = resolve_endpoint(config.endpoint).await?;
    validate_yy_url(&wss_url)?;
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|err| format!("listen {} failed: {err}", config.listen_addr))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("read listen addr failed: {err}"))?;
    println!("listening {addr}");

    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|err| format!("accept failed: {err}"))?;
        let wss_url = wss_url.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_yy_tcp_connection(stream, &wss_url).await {
                eprintln!("{peer}: {err}");
            }
        });
    }
}

/// Resolves a direct WSS URL or reads one from a complete KV key.
///
/// Example: `Kv { key: "cfp/demo" }` -> `wss://host/tcp?code=<uuid>`.
async fn resolve_endpoint(endpoint: EndpointSpec) -> Result<String, String> {
    match endpoint {
        EndpointSpec::Url(wss_url) => Ok(wss_url),
        EndpointSpec::Kv { key, query } => {
            let backend = discovery::config::load(None)?
                .ok_or("KV endpoint requires a cf_kv reporter configuration")?;
            let discovery::config::BackendConfig::CfKv(config) = backend else {
                return Err("KV endpoint requires reporter.type: cf_kv".to_string());
            };
            let reader = discovery::kv::KvReader::new(config)?;
            let endpoint = reader.read(&key).await?;
            let wss_url = target_proxy::build_wss_url(&endpoint.hostname, &endpoint.code, None)?;
            append_endpoint_query(&wss_url, query.as_deref())
        }
    }
}

/// Appends a caller-provided query string without allowing it to replace `code`.
///
/// Example: base URL plus `port=544` -> URL with `code=<uuid>&port=544`.
fn append_endpoint_query(wss_url: &str, query: Option<&str>) -> Result<String, String> {
    let Some(query) = query else {
        return Ok(wss_url.to_string());
    };
    let query = query.trim().trim_start_matches('?').trim_start_matches('&');
    if query.is_empty() || query.contains('#') || query.contains('?') {
        return Err("-query must contain a non-empty query string without ? or #".to_string());
    }
    let mut url =
        Url::parse(wss_url).map_err(|error| format!("invalid generated wss url: {error}"))?;
    if url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == "code") {
        return Err("-query must not override code".to_string());
    }
    let combined = match url.query() {
        Some(existing) if !existing.is_empty() => format!("{existing}&{query}"),
        _ => query.to_string(),
    };
    url.set_query(Some(&combined));
    Ok(url.to_string())
}

/// Runs zz mode and exposes a local TCP listener for a child command.
///
/// Example: `tmp-proxy zz wss://x -- ssh -p {PORT} u@127.0.0.1`.
async fn run_zz(config: ZzConfig) -> Result<i32, String> {
    let wss_url = resolve_endpoint(config.endpoint).await?;
    validate_yy_url(&wss_url)?;
    let listener = TcpListener::bind(DEFAULT_YY_LISTEN)
        .await
        .map_err(|err| format!("listen {DEFAULT_YY_LISTEN} failed: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("read listen addr failed: {err}"))?;
    let command = replace_port_placeholders(config.command, addr.port());
    let mut child = spawn_zz_command(&command)?;
    let cancel = CancellationToken::new();
    let mut accept_task = tokio::spawn(run_zz_accept_loop(listener, wss_url, cancel.clone()));

    println!("listening {addr}");
    println!("running {}", command.join(" "));

    tokio::select! {
        status = child.wait() => {
            cancel.cancel();
            accept_task.abort();
            let status = status.map_err(|err| format!("wait command failed: {err}"))?;
            Ok(status.code().unwrap_or(1))
        }
        result = &mut accept_task => {
            drop(child);
            match result {
                Ok(Ok(())) => Ok(0),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(format!("proxy task failed: {err}")),
            }
        }
    }
}

/// Replaces the `{PORT}` token in zz command arguments.
///
/// Example: `["ssh", "-p", "{PORT}"], 3456 -> ["ssh", "-p", "3456"]`.
fn replace_port_placeholders(command: Vec<String>, port: u16) -> Vec<String> {
    command
        .into_iter()
        .map(|arg| arg.replace("{PORT}", &port.to_string()))
        .collect()
}

/// Spawns the zz child command with inherited stdio.
///
/// Example: `["ssh", "-p", "1234", "u@127.0.0.1"]` starts ssh.
fn spawn_zz_command(command: &[String]) -> Result<tokio::process::Child, String> {
    let Some((program, args)) = command.split_first() else {
        return Err("zz command is empty".to_string());
    };
    let mut process = TokioCommand::new(program);
    process.args(args).kill_on_drop(true);
    process
        .spawn()
        .map_err(|err| format!("start command failed: {err}"))
}

/// Accepts zz TCP connections until cancellation.
///
/// Example: every local ssh connection is bridged to the remote WebSocket URL.
async fn run_zz_accept_loop(
    listener: TcpListener,
    wss_url: String,
    cancel: CancellationToken,
) -> Result<(), String> {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            accepted = listener.accept() => {
                let (stream, peer) = accepted.map_err(|err| format!("accept failed: {err}"))?;
                let wss_url = wss_url.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_yy_tcp_connection(stream, &wss_url).await {
                        eprintln!("{peer}: {err}");
                    }
                });
            }
        }
    }
}

/// Validates that yy was given a WSS URL with an embedded UUID v4.
///
/// Example: `wss://x/tcp?code=<uuid-v4>` is accepted.
fn validate_yy_url(wss_url: &str) -> Result<(), String> {
    let url = Url::parse(wss_url).map_err(|err| format!("invalid wss url: {err}"))?;
    if url.scheme() != "wss" {
        return Err("yy url must use wss://".to_string());
    }
    if target_proxy::extract_uuid(wss_url)
        .filter(|uuid| access_uuid::is_valid_v4(uuid))
        .is_none()
    {
        return Err("yy url must include ?code=<canonical UUID v4>".to_string());
    }
    target_proxy::extract_target_port(wss_url)
        .map_err(|error| format!("yy url has invalid port: {error}"))?;
    Ok(())
}

/// Handles one local yy TCP connection by dialing the remote WebSocket URL.
///
/// Example: local SSH connection becomes one `wss://.../tcp?code=<uuid>` connection.
async fn handle_yy_tcp_connection(stream: TcpStream, wss_url: &str) -> Result<(), String> {
    let (ws, _) = connect_async(wss_url)
        .await
        .map_err(|err| format!("connect websocket failed: {err}"))?;
    bridge_tcp_tokio_ws(stream, ws).await
}

/// Bridges a TCP stream and a tokio-tungstenite WebSocket in both directions.
///
/// Example: TCP SSH bytes are sent as WS binary frames and back.
async fn bridge_tcp_tokio_ws<S>(
    tcp: TcpStream,
    ws: tokio_tungstenite::WebSocketStream<S>,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut tcp_reader, mut tcp_writer) = tcp.into_split();
    let (mut ws_writer, mut ws_reader) = ws.split();

    let tcp_to_ws = async {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let len = tcp_reader
                .read(&mut buffer)
                .await
                .map_err(|err| format!("read tcp failed: {err}"))?;
            if len == 0 {
                let _ = ws_writer.close().await;
                return Ok::<(), String>(());
            }
            ws_writer
                .send(TokioMessage::Binary(Bytes::copy_from_slice(&buffer[..len])))
                .await
                .map_err(|err| format!("write websocket failed: {err}"))?;
        }
    };

    let ws_to_tcp = async {
        while let Some(message) = ws_reader.next().await {
            let message = message.map_err(|err| format!("read websocket failed: {err}"))?;
            match message {
                TokioMessage::Binary(data) => tcp_writer
                    .write_all(&data)
                    .await
                    .map_err(|err| format!("write tcp failed: {err}"))?,
                TokioMessage::Text(text) => tcp_writer
                    .write_all(text.as_bytes())
                    .await
                    .map_err(|err| format!("write tcp text failed: {err}"))?,
                TokioMessage::Close(_) => break,
                TokioMessage::Ping(_) | TokioMessage::Pong(_) | TokioMessage::Frame(_) => {}
            }
        }
        let _ = tcp_writer.shutdown().await;
        Ok::<(), String>(())
    };

    tokio::select! {
        result = tcp_to_ws => result,
        result = ws_to_tcp => result,
    }
}

//! Phone-home client: connects outbound to the EC-PKI-Playground backend
//! over a long-lived WebSocket (`ws /api/orchestrator/connect`), receives
//! dispatched commands, and streams their `OpRunState` progress back.
//!
//! The backend is the authoritative capability gate — it checks the calling
//! human's role via `require_capability` before ever forwarding a command,
//! and includes that role in every dispatched frame (see `InboundCommand`).
//! `CommandRegistry::dispatch` re-checks that *forwarded* role locally: a
//! second, structural gate, not the primary one — `identity.role` in the
//! local config is not consulted here at all.
//!
//! The framing/dispatch translation (`handle_command`) is a plain sync
//! function so it's unit-testable with an in-memory channel, without a real
//! socket — the actual connect/reconnect I/O loop below it is verified
//! manually (same tier as `powershell::RealPowerShell`, `service::scm`).

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_tungstenite::Connector;
use tokio_tungstenite::tungstenite::{
    Message, client::IntoClientRequest, handshake::client::Request,
    http::HeaderValue,
};
use url::Url;

use crate::{
    authz::Role,
    config::ExecutorConfig,
    powershell::PowerShellExecutor,
    registry::CommandRegistry,
    report::{OpRunState, OpStatus, ProgressSink},
};

/// One command dispatched by the backend, tagged with the job id its
/// progress should be reported under and the role the backend authenticated
/// the calling human as.
#[derive(Debug, Clone, Deserialize)]
pub struct InboundCommand {
    pub job_id: String,
    pub command: String,
    #[serde(default)]
    pub params: std::collections::HashMap<String, String>,
    pub role: Role,
}

/// One progress frame sent back to the backend, tagged with the job id it
/// belongs to so the backend can relay it onto the matching
/// `/api/ws/jobs/{job_id}` channel.
#[derive(Debug, Clone, Serialize)]
pub struct OutboundProgress {
    pub job_id: String,
    pub state: OpRunState,
}

struct TaggedProgressSink {
    job_id: String,
    sender: mpsc::UnboundedSender<OutboundProgress>,
}

impl ProgressSink for TaggedProgressSink {
    fn report(&self, state: OpRunState) {
        let _ = self.sender.send(OutboundProgress {
            job_id: self.job_id.clone(),
            state,
        });
    }
}

/// Dispatches one inbound command and forwards its progress. Handlers
/// already report their own terminal `done` state via the sink on success
/// (see `commands/*.rs`), so this only synthesizes a terminal `error` frame
/// when dispatch itself fails (unknown command, forbidden role, or a
/// `CommandError` a handler never got the chance to report itself).
pub fn handle_command(
    registry: &CommandRegistry,
    shell: Arc<dyn PowerShellExecutor>,
    cmd: InboundCommand,
    sender: &mpsc::UnboundedSender<OutboundProgress>,
) {
    let sink = TaggedProgressSink {
        job_id: cmd.job_id.clone(),
        sender: sender.clone(),
    };

    if let Err(err) =
        registry.dispatch(&cmd.command, cmd.role, cmd.params, &sink, shell)
    {
        let _ = sender.send(OutboundProgress {
            job_id: cmd.job_id,
            state: OpRunState::error(err.to_string()),
        });
    }
}

fn connect_url(config: &ExecutorConfig) -> Result<Url> {
    let base = config
        .backend
        .url
        .as_deref()
        .context("backend.url is required to connect")?;
    let mut url = Url::parse(base).context("parsing backend.url")?;
    let ws_scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(ws_scheme).map_err(|()| {
        anyhow::anyhow!("backend.url has an unsupported scheme")
    })?;
    url.set_path("/api/orchestrator/connect");
    Ok(url)
}

/// Build the WS upgrade request, carrying vm_id/token as headers rather than
/// query params — the long-lived agent token stays out of the backend's and
/// any reverse proxy's access logs. (The backend also accepts the browser-style
/// `?vm_id=&token=` for the manual/dev path.)
fn connect_request(config: &ExecutorConfig) -> Result<Request> {
    let url = connect_url(config)?;
    let mut request = url
        .as_str()
        .into_client_request()
        .context("building ws upgrade request")?;
    let headers = request.headers_mut();
    headers.insert(
        "x-orchestrator-vm-id",
        HeaderValue::from_str(&config.identity.vm_id)
            .context("vm_id is not a valid header value")?,
    );
    headers.insert(
        "x-orchestrator-token",
        HeaderValue::from_str(&config.identity.agent_token)
            .context("agent_token is not a valid header value")?,
    );
    Ok(request)
}

/// Build the WebSocket TLS connector with an **explicit** `ring` crypto
/// provider.
///
/// `tokio_tungstenite::connect_async` builds its `ClientConfig` through the
/// argument-less `ClientConfig::builder()`, which resolves the crypto provider
/// from a process-global default or from unambiguous crate features. In the
/// release Windows build neither path held — rustls's feature auto-detection
/// yielded no provider and a `CryptoProvider::install_default()` in `main` was
/// not observed at the connect site — so the first handshake panicked
/// ("Could not automatically determine the process-level CryptoProvider").
/// Passing the provider explicitly via `builder_with_provider` sidesteps that
/// resolution entirely, so the connection is immune to however rustls's
/// features happen to unify in a given build.
fn tls_connector() -> Result<Connector> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("configuring TLS protocol versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Connector::Rustls(Arc::new(config)))
}

/// How a connection ended: a plain drop/close, or the backend's explicit
/// "another connection took over this vm_id" close (code 4409) — a duplicate
/// process on this machine or a copied ISO elsewhere. The latter gets a much
/// longer backoff so two instances can't evict each other in a tight loop.
enum ConnectionEnd {
    Normal,
    Superseded,
}

/// The backend's takeover close code (mirrors `routers/orchestrator.py`).
const CLOSE_SUPERSEDED: u16 = 4409;

/// Serialize and send one progress frame. On a write failure the frame is
/// parked in `pending` for the next connection — a long command's terminal
/// result must survive the socket it started on. Returns whether the
/// connection is still usable.
async fn send_progress<S>(
    write: &mut S,
    msg: OutboundProgress,
    pending: &mut Option<OutboundProgress>,
) -> bool
where
    S: futures_util::Sink<Message> + Unpin,
{
    let Ok(text) = serde_json::to_string(&msg) else {
        return true; // unserializable frame — a bug; drop it, keep the socket
    };
    // Log the outbound half of the backend↔agent exchange. Terminal frames
    // (done/error) at info so the command-level round-trip is visible in the
    // default log; the chattier intermediate progress at debug.
    match msg.state.status {
        OpStatus::Done | OpStatus::Error => tracing::info!(
            job_id = %msg.job_id,
            status = ?msg.state.status,
            detail = msg.state.detail.as_deref().unwrap_or_default(),
            "-> sending terminal result to backend"
        ),
        _ => tracing::debug!(
            job_id = %msg.job_id,
            status = ?msg.state.status,
            phase = msg.state.phase.as_deref().unwrap_or_default(),
            percent = msg.state.percent.unwrap_or_default(),
            "-> sending progress to backend"
        ),
    }
    if write.send(Message::Text(text)).await.is_err() {
        tracing::warn!(
            job_id = %msg.job_id,
            "socket write failed; parking frame for the next connection"
        );
        *pending = Some(msg);
        return false;
    }
    true
}

async fn connect_once(
    config: &ExecutorConfig,
    registry: &Arc<CommandRegistry>,
    shell: &Arc<dyn PowerShellExecutor>,
    tx: &mpsc::UnboundedSender<OutboundProgress>,
    rx: &mut mpsc::UnboundedReceiver<OutboundProgress>,
    pending: &mut Option<OutboundProgress>,
) -> Result<ConnectionEnd> {
    let request = connect_request(config)?;
    let target = request.uri().to_string();
    tracing::debug!(url = %target, "opening phone-home websocket");
    let (stream, response) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        Some(tls_connector()?),
    )
    .await
    .with_context(|| format!("connecting to backend at {target}"))?;
    tracing::info!(
        url = %target,
        vm_id = %config.identity.vm_id,
        status = response.status().as_u16(),
        "connected to backend"
    );

    let (mut write, mut read) = stream.split();

    // A frame the previous connection accepted but failed to write — deliver
    // it before anything else (frames queued in `rx` while disconnected
    // follow naturally via the select loop).
    if let Some(msg) = pending.take()
        && !send_progress(&mut write, msg, pending).await
    {
        return Ok(ConnectionEnd::Normal);
    }

    let mut ping =
        tokio::time::interval(Duration::from_secs(KEEPALIVE_PING_SECS));
    ping.tick().await; // the first tick fires immediately — skip it

    loop {
        tokio::select! {
            frame = read.next() => {
                let Some(frame) = frame else {
                    return Ok(ConnectionEnd::Normal);
                };
                let frame = frame.context("reading from backend")?;
                let text = match frame {
                    Message::Text(text) => text,
                    Message::Close(Some(cf))
                        if u16::from(cf.code) == CLOSE_SUPERSEDED =>
                    {
                        return Ok(ConnectionEnd::Superseded);
                    }
                    _ => continue,
                };

                let cmd: InboundCommand = match serde_json::from_str(&text) {
                    Ok(cmd) => cmd,
                    Err(err) => {
                        tracing::warn!(?err, "received malformed command frame");
                        continue;
                    }
                };

                // Log the inbound half of the exchange (params omitted — they
                // can carry secrets like passwords for a domain join).
                tracing::info!(
                    job_id = %cmd.job_id,
                    command = %cmd.command,
                    role = ?cmd.role,
                    param_count = cmd.params.len(),
                    "<- received command from backend"
                );

                let registry = Arc::clone(registry);
                let shell = Arc::clone(shell);
                let tx = tx.clone();
                tokio::task::spawn_blocking(move || {
                    handle_command(&registry, shell, cmd, &tx);
                });
            }
            msg = rx.recv() => {
                // `run_forever` holds a sender for the process lifetime, so
                // recv only yields None at shutdown.
                let Some(msg) = msg else {
                    return Ok(ConnectionEnd::Normal);
                };
                if !send_progress(&mut write, msg, pending).await {
                    return Ok(ConnectionEnd::Normal);
                }
            }
            _ = ping.tick() => {
                // A long, quiet command sends no frames; a periodic ping
                // keeps the connection from being dropped by an idle-timeout
                // in a reverse proxy / tunnel between us and the backend.
                if write.send(Message::Ping(Vec::new())).await.is_err() {
                    return Ok(ConnectionEnd::Normal);
                }
            }
        }
    }
}

/// Client→server WebSocket ping cadence. A long, quiet command produces no
/// frames, so without this the connection can be dropped by an idle-timeout in
/// a reverse proxy / tunnel (e.g. Cloudflare) sitting between agent and backend.
const KEEPALIVE_PING_SECS: u64 = 30;

const RECONNECT_DELAYS_SECS: [u64; 5] = [1, 2, 5, 10, 30];

/// Backoff after a 4409 supersede — long enough that two instances fighting
/// over one vm_id can't keep evicting each other every couple of seconds.
const SUPERSEDED_DELAY_SECS: u64 = 300;

/// A connection that lived at least this long counts as healthy, resetting
/// the reconnect backoff — without this, `attempt` only ever grows and every
/// later drop (even after days of uptime) starts at the 30s cap.
const HEALTHY_CONNECTION_SECS: u64 = 60;

/// Connects, dispatches, and reconnects with capped backoff forever. Only
/// returns if the config itself is unusable (e.g. no `backend.url`) — a
/// dropped connection is retried, never treated as fatal.
pub async fn run_forever(
    config: &ExecutorConfig,
    registry: Arc<CommandRegistry>,
    shell: Arc<dyn PowerShellExecutor>,
) -> Result<()> {
    // Fail fast on bad config, before the first attempt — and surface the
    // resolved target so a wrong `backend.url` (or a proxy answering 404 for
    // it) is diagnosable straight from the log.
    let target = connect_url(config)?;
    tracing::info!(
        url = %target,
        vm_id = %config.identity.vm_id,
        "phone-home target resolved"
    );

    // Outbound frames outlive any one connection: a command started on one
    // socket delivers its result through whichever socket is live when it
    // finishes (frames queue here while disconnected, plus a one-slot
    // `pending` for a frame that failed mid-write).
    let (tx, mut rx) = mpsc::unbounded_channel::<OutboundProgress>();
    let mut pending: Option<OutboundProgress> = None;

    let mut attempt = 0usize;
    loop {
        let started = std::time::Instant::now();
        let outcome =
            connect_once(config, &registry, &shell, &tx, &mut rx, &mut pending)
                .await;
        if started.elapsed() >= Duration::from_secs(HEALTHY_CONNECTION_SECS) {
            attempt = 0;
        }
        match outcome {
            Ok(ConnectionEnd::Superseded) => {
                tracing::warn!(
                    "backend superseded this connection: another agent \
                     instance is using this vm_id (duplicate process or \
                     copied ISO) — backing off {SUPERSEDED_DELAY_SECS}s"
                );
                tokio::time::sleep(Duration::from_secs(SUPERSEDED_DELAY_SECS))
                    .await;
                continue;
            }
            Ok(ConnectionEnd::Normal) => {
                tracing::warn!(url = %target, "backend closed the connection; reconnecting")
            }
            Err(err) => tracing::warn!(
                url = %target,
                error = format!("{err:#}"),
                "phone-home connection failed; reconnecting"
            ),
        }

        let delay =
            RECONNECT_DELAYS_SECS[attempt.min(RECONNECT_DELAYS_SECS.len() - 1)];
        attempt += 1;
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{commands::build_default_registry, powershell::MockPowerShell};
    use std::collections::HashMap;

    fn recv_all(
        rx: &mut mpsc::UnboundedReceiver<OutboundProgress>,
    ) -> Vec<OutboundProgress> {
        let mut out = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            out.push(msg);
        }
        out
    }

    #[test]
    fn guest_forbidden_command_reports_a_terminal_error_frame() {
        let registry = build_default_registry();
        let shell: Arc<dyn PowerShellExecutor> =
            Arc::new(MockPowerShell::new());
        let (tx, mut rx) = mpsc::unbounded_channel();

        handle_command(
            &registry,
            shell,
            InboundCommand {
                job_id: "job-1".into(),
                command: "powershell.exec_arbitrary".into(),
                params: HashMap::from([("script".into(), "echo hi".into())]),
                role: Role::Guest,
            },
            &tx,
        );

        let frames = recv_all(&mut rx);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].job_id, "job-1");
        assert_eq!(frames[0].state.status, crate::report::OpStatus::Error);
    }

    #[test]
    fn allowed_command_forwards_the_handlers_own_progress_and_done_frames() {
        let registry = build_default_registry();
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(r#"{"chain_ok":true,"healthy":true}"#);
        let shell: Arc<dyn PowerShellExecutor> = shell;
        let (tx, mut rx) = mpsc::unbounded_channel();

        handle_command(
            &registry,
            shell,
            InboundCommand {
                job_id: "job-2".into(),
                command: "cert.verify".into(),
                params: HashMap::from([(
                    "path".into(),
                    "C:\\win11.cer".into(),
                )]),
                role: Role::Guest,
            },
            &tx,
        );

        let frames = recv_all(&mut rx);
        assert!(frames.iter().all(|f| f.job_id == "job-2"));
        assert!(
            frames
                .iter()
                .any(|f| f.state.status == crate::report::OpStatus::Running)
        );
        let done = frames
            .iter()
            .find(|f| f.state.status == crate::report::OpStatus::Done)
            .expect("expected a done frame");
        assert_eq!(done.state.result.as_ref().unwrap()["chain_ok"], true);
    }

    #[test]
    fn unknown_command_reports_a_terminal_error_frame() {
        let registry = build_default_registry();
        let shell: Arc<dyn PowerShellExecutor> =
            Arc::new(MockPowerShell::new());
        let (tx, mut rx) = mpsc::unbounded_channel();

        handle_command(
            &registry,
            shell,
            InboundCommand {
                job_id: "job-3".into(),
                command: "does.not_exist".into(),
                params: HashMap::new(),
                role: Role::Operator,
            },
            &tx,
        );

        let frames = recv_all(&mut rx);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].state.status, crate::report::OpStatus::Error);
        // The backend's boot-probe fallback matches this exact wording to
        // detect an agent that predates a command — it is a compatibility
        // surface, not just a message.
        assert_eq!(
            frames[0].state.detail.as_deref(),
            Some("unknown command 'does.not_exist'")
        );
    }

    #[test]
    fn connect_url_rejects_missing_backend_url() {
        let config = ExecutorConfig {
            identity: crate::config::IdentityConfig {
                vm_id: "dev".into(),
                agent_token: "tok".into(),
                role: Role::Operator,
            },
            backend: crate::config::BackendConfig { url: None },
            execution: Default::default(),
            service: Default::default(),
        };
        assert!(connect_url(&config).is_err());
    }

    #[test]
    fn connect_request_carries_identity_in_headers_not_query() {
        let config = ExecutorConfig {
            identity: crate::config::IdentityConfig {
                vm_id: "vm-42".into(),
                agent_token: "secret".into(),
                role: Role::Operator,
            },
            backend: crate::config::BackendConfig {
                url: Some("http://127.0.0.1:8000".into()),
            },
            execution: Default::default(),
            service: Default::default(),
        };
        let request = connect_request(&config).unwrap();
        assert_eq!(request.uri().scheme_str(), Some("ws"));
        assert_eq!(request.uri().path(), "/api/orchestrator/connect");
        // Token must not leak into the URL (the reason for header auth).
        assert!(request.uri().query().unwrap_or("").is_empty());
        assert_eq!(
            request.headers().get("x-orchestrator-vm-id").unwrap(),
            "vm-42"
        );
        assert_eq!(
            request.headers().get("x-orchestrator-token").unwrap(),
            "secret"
        );
    }
}

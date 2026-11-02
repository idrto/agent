//! The Source agent as a long-lived owner of sessions and transfers.
//!
//! Per configured Target a supervisor keeps a WebRTC session up (reconnecting
//! with backoff), proves this device and verifies the Target in-band
//! (`idr.bind`), publishes the bound session to the transfer [`Manager`], and
//! accepts Target→Source transfers under local policy. Transfers belong to the
//! manager, so they outlive whatever queued them and resume after reconnects
//! and restarts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use idr_core::{LogicalStream, StreamPriority};
use idr_protocol::peer_bind::{BindRole, TrustPolicy, VerifiedPeer, BIND_SERVICE};
use idr_protocol::transfer::{TransferId, TRANSFER_SERVICE};
use crate::{SessionOpener, SourceRuntime, SourceSession};
use idr_transfer::bind::{bind_peer, LocalIdentity};
use idr_transfer::io::Framed;
use idr_transfer::native::control::Control;
use idr_transfer::native::ipc::{self, IpcAddr};
use idr_transfer::native::manager::{DeferredSink, Link, Manager};
use idr_transfer::native::free_space;
use idr_transfer::policy::{PolicyEngine, ReceivePolicy, SendPolicy};
use idr_transfer::storage::StreamOpener;
use idr_transfer::{Limits, Routed, Router};
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Builds a fresh runtime per connection attempt (Presence client + native peer).
pub type RuntimeFactory = Arc<dyn Fn() -> SourceRuntime + Send + Sync>;

pub struct DaemonConfig {
    /// Holds `transfers.db` (the outbox).
    pub data_dir: PathBuf,
    /// Target FQHNs to keep sessions with.
    pub targets: Vec<String>,
    pub identity: Arc<LocalIdentity>,
    /// Entity root certificates (DER) Targets must chain to.
    pub roots: Vec<Vec<u8>>,
    pub receive_dir: PathBuf,
    pub receive_policy: ReceivePolicy,
    pub send_policy: SendPolicy,
    pub limits: Limits,
    pub reconnect_min: Duration,
    pub reconnect_max: Duration,
    /// Serve the local CLI here (None: no IPC).
    pub ipc: Option<IpcAddr>,
    /// Directories `transfer accept --out` may choose (besides `receive_dir`).
    pub permitted_dirs: Vec<PathBuf>,
    /// How long an interactive offer waits for `transfer accept` / `reject`.
    pub offer_expiry: Duration,
}

pub struct Daemon {
    manager: Arc<Manager>,
    shutdown: watch::Sender<bool>,
    cfg: Arc<DaemonConfig>,
    runtimes: RuntimeFactory,
    engine: PolicyEngine,
    rt: Handle,
    /// One supervisor per Target: configured ones, plus any a send names.
    supervisors: Mutex<HashMap<String, JoinHandle<()>>>,
}

impl Daemon {
    /// Start inside a Tokio runtime; supervisors run on it.
    pub fn start(cfg: DaemonConfig, runtimes: RuntimeFactory) -> Result<Self> {
        std::fs::create_dir_all(&cfg.data_dir).context("create data dir")?;
        std::fs::create_dir_all(&cfg.receive_dir).context("create receive dir")?;
        let manager = Manager::open(&cfg.data_dir, cfg.limits.clone(), cfg.send_policy.clone())
            .context("open transfer outbox")?;
        let dest = cfg.receive_dir.clone();
        let engine = PolicyEngine::new(cfg.receive_policy.clone(), Some(Arc::new(move || free_space(&dest))));
        let (shutdown, _) = watch::channel(false);
        if let Some(addr) = cfg.ipc.clone() {
            let mut permitted = cfg.permitted_dirs.clone();
            permitted.push(cfg.receive_dir.clone());
            let handler = Arc::new(Control { manager: manager.clone(), permitted });
            let rx = shutdown.subscribe();
            tokio::spawn(async move {
                if let Err(e) = ipc::serve(addr, handler, rx).await {
                    warn!(error = %e, "local IPC unavailable");
                }
            });
        }
        let daemon = Self {
            manager,
            shutdown,
            cfg: Arc::new(cfg),
            runtimes,
            engine,
            rt: Handle::current(),
            supervisors: Mutex::new(HashMap::new()),
        };
        for fqhn in daemon.cfg.targets.clone() {
            daemon.add_target(&fqhn);
        }
        // Restored transfers whose Target isn't configured still need a session.
        for info in daemon.manager.list() {
            if info.direction == idr_transfer::native::manager::Direction::Outgoing && !info.state.is_done() {
                daemon.add_target(&info.peer);
            }
        }
        Ok(daemon)
    }

    pub fn manager(&self) -> &Arc<Manager> {
        &self.manager
    }

    /// Keep a bound session with `fqhn` from now on (no-op if already kept).
    pub fn add_target(&self, fqhn: &str) {
        let mut sups = self.supervisors.lock().unwrap();
        if sups.contains_key(fqhn) || *self.shutdown.borrow() {
            return;
        }
        let (link_tx, link_rx) = watch::channel(None);
        self.manager.set_link(fqhn, link_rx);
        let task = self.rt.spawn(supervise(
            fqhn.to_string(),
            self.cfg.clone(),
            self.runtimes.clone(),
            self.manager.clone(),
            self.engine.clone(),
            link_tx,
            self.shutdown.subscribe(),
        ));
        sups.insert(fqhn.to_string(), task);
    }

    /// Queue `paths` for `target` (see [`queue_paths`]).
    pub fn send_paths(&self, target: &str, paths: &[PathBuf]) -> Result<TransferId> {
        let id = queue_paths(&self.manager, target, paths)?;
        self.add_target(target);
        Ok(id)
    }

    /// Queue a selection inside `folder` (see [`queue_selection`]).
    pub fn send_selection(&self, target: &str, folder: &Path, selected: &[String]) -> Result<TransferId> {
        let id = queue_selection(&self.manager, target, folder, selected)?;
        self.add_target(target);
        Ok(id)
    }

    /// Close sessions. Running transfers stop resumably and continue after the
    /// next start.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let sups: Vec<_> = self.supervisors.lock().unwrap().drain().map(|(_, t)| t).collect();
        for s in sups {
            let _ = tokio::time::timeout(Duration::from_secs(5), s).await;
        }
    }
}

pub use idr_transfer::native::control::{queue_paths, queue_selection};

struct SourceLink {
    opener: SessionOpener,
    peer: VerifiedPeer,
    generation: u64,
}

struct TransferStreams(SessionOpener);

#[async_trait]
impl StreamOpener for TransferStreams {
    async fn open(&mut self) -> idr_core::Result<Box<dyn LogicalStream>> {
        self.0.open(TRANSFER_SERVICE, StreamPriority::Bulk).await
    }
}

impl Link for SourceLink {
    fn opener(&self) -> Box<dyn StreamOpener> {
        Box::new(TransferStreams(self.opener.clone()))
    }
    fn peer(&self) -> &VerifiedPeer {
        &self.peer
    }
    fn generation(&self) -> u64 {
        self.generation
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Prove this device to the Target and verify the Target names `fqhn`.
async fn bind(session: &SourceSession, cfg: &DaemonConfig, fqhn: &str) -> Option<VerifiedPeer> {
    let stream = match session.opener().open(BIND_SERVICE, StreamPriority::Interactive).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%fqhn, error = %e, "Target refused peer binding; transfers disabled on this session");
            return None;
        }
    };
    let trust = TrustPolicy {
        roots: cfg.roots.clone(),
        require_ski: None,
        require_dns: Some(fqhn.to_string()),
        now: unix_now(),
    };
    match bind_peer(&mut Framed::new(stream), BindRole::Offerer, session.bind_context(), &cfg.identity, &trust, cfg.limits.step_timeout).await {
        Ok(p) => Some(p),
        Err(code) => {
            warn!(%fqhn, code = code.as_str(), "Target identity not verified; transfers disabled on this session");
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn supervise(
    fqhn: String,
    cfg: Arc<DaemonConfig>,
    runtimes: RuntimeFactory,
    manager: Arc<Manager>,
    engine: PolicyEngine,
    link: watch::Sender<Option<Arc<dyn Link>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut generation = 0u64;
    let mut delay = cfg.reconnect_min;
    while !*shutdown.borrow() {
        let mut runtime = runtimes();
        let connected = tokio::select! {
            r = runtime.connect(&fqhn) => r,
            _ = shutdown.changed() => break,
        };
        let mut session = match connected {
            Ok(s) => s,
            Err(e) => {
                warn!(%fqhn, error = %e, retry_in = ?delay, "connect failed");
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = shutdown.changed() => break,
                }
                delay = (delay * 2).min(cfg.reconnect_max);
                continue;
            }
        };
        delay = cfg.reconnect_min;
        info!(%fqhn, "session up");
        let mut lease: Option<Duration> = None;
        if let Some(peer) = bind(&session, &cfg, &fqhn).await {
            lease = Some(Duration::from_secs((engine.lease_until(&peer) - unix_now()).max(1) as u64));
            generation += 1;
            let _ = link.send(Some(Arc::new(SourceLink {
                opener: session.opener(),
                peer: peer.clone(),
                generation,
            })));
            let mut incoming = session.accept_streams(&[TRANSFER_SERVICE]).await;
            let (manager, engine, fqhn2, dir) = (manager.clone(), engine.clone(), fqhn.clone(), cfg.receive_dir.clone());
            let step = cfg.limits.step_timeout;
            let (interactive, expiry) = (cfg.receive_policy.interactive, cfg.offer_expiry);
            tokio::spawn(async move {
                let router = Router::default();
                while let Some(inc) = incoming.recv().await {
                    if let Routed::Control { header, stream } = router.route(inc.stream, step).await {
                        let (manager, router, fqhn, dir) = (manager.clone(), router.clone(), fqhn2.clone(), dir.clone());
                        // Interactive endpoints park offers for `transfer accept`; headless never asks.
                        let prompt = interactive.then(|| manager.prompt(expiry));
                        let mut consent = engine.consent(Some(peer.clone()), prompt);
                        let peer_path = peer.path;
                        tokio::spawn(async move {
                            let sink = DeferredSink::new(manager.clone(), dir);
                            manager.receive(&fqhn, peer_path, &router, header, stream, sink, &mut consent).await;
                        });
                    }
                }
            });
        }
        let closed = session.closed();
        let reauth = manager.reauth_needed(&fqhn);
        // Authorization lasts one lease; then stop transfers resumably and
        // re-authorize through a fresh session (Presence re-checks the Source).
        let lease_end = async {
            match lease {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = closed => info!(%fqhn, "session ended; reconnecting"),
            _ = lease_end => {
                info!(%fqhn, "authorization lease ended; re-authorizing");
                let _ = link.send(None);
                manager.interrupt(&fqhn, idr_transfer::Command::AuthExpired).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
                let _ = idr_core::PeerSession::close(&mut session).await;
            }
            _ = reauth.notified() => {
                info!(%fqhn, "a transfer needs re-authorization; reconnecting");
                let _ = link.send(None);
                let _ = idr_core::PeerSession::close(&mut session).await;
            }
            _ = shutdown.changed() => {
                let _ = link.send(None);
                let _ = idr_core::PeerSession::close(&mut session).await;
                break;
            }
        }
        let _ = link.send(None);
    }
}

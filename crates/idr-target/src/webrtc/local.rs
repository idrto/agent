//! Target-local endpoint: peer binding and file transfer on WebRTC sessions.
//!
//! `idr.bind` and `idr.transfer` streams terminate here, not at a TCP service.
//! Per session:
//!
//! 1. The Source opens `idr.bind`. It is accepted only when Presence attested
//!    the Source's identity (`offer.source.policy`); [`bind_peer`] then requires
//!    the proven SKI to be that one.
//! 2. `idr.transfer` streams are refused until the binding succeeded. They go
//!    through the transfer [`Router`] and [`receive`] with [`NativeSink`] storage
//!    and [`PolicyEngine`] consent for the bound peer.
//! 3. The Target can send to a bound Source ([`TransferEndpoint::send`]) over
//!    Target-initiated streams.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use idr_core::{IdrError, IdrErrorKind, LogicalStream, StreamId, StreamPriority};
use idr_protocol::peer_bind::{BindContext, BindRole, TrustPolicy, VerifiedPeer, BIND_SERVICE};
use idr_protocol::transfer::{TransferErrorKind, TransferId, TRANSFER_SERVICE};
use idr_transfer::bind::{bind_peer, LocalIdentity};
use idr_transfer::io::Framed;
use idr_transfer::native::manager::{DeferredSink, Link, Manager};
use idr_transfer::native::NativeSink;
use idr_transfer::policy::PolicyEngine;
use idr_transfer::storage::{SourceFiles, StreamOpener};
use idr_transfer::{receive, send, Command, Limits, Outcome, Outgoing, Routed, Router, TransferEvent};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot, watch};
use uuid::Uuid;

/// Is `service` handled by this endpoint rather than a TCP connector?
pub fn is_local_service(service: &str) -> bool {
    service == BIND_SERVICE || service == TRANSFER_SERVICE
}

/// A Target-local stream end as a [`LogicalStream`].
pub struct IoStream {
    id: StreamId,
    io: DuplexStream,
}

impl IoStream {
    pub fn new(id: u32, io: DuplexStream) -> Self {
        Self { id: StreamId(id), io }
    }
}

fn closed(e: std::io::Error) -> IdrError {
    IdrError::new(IdrErrorKind::TransportClosed, e.to_string())
}

#[async_trait]
impl LogicalStream for IoStream {
    fn id(&self) -> StreamId {
        self.id
    }
    async fn write(&mut self, buf: &[u8]) -> idr_core::Result<usize> {
        self.io.write(buf).await.map_err(closed)
    }
    async fn read(&mut self, buf: &mut [u8]) -> idr_core::Result<usize> {
        self.io.read(buf).await.map_err(closed)
    }
    async fn half_close(&mut self) -> idr_core::Result<()> {
        self.io.shutdown().await.map_err(closed)
    }
    async fn reset(&mut self, _reason: u16) -> idr_core::Result<()> {
        self.io.shutdown().await.map_err(closed)
    }
}

pub struct TransferConfig {
    /// This Target's DP device identity.
    pub identity: LocalIdentity,
    /// Entity root certificates (DER) peers must chain to.
    pub roots: Vec<Vec<u8>>,
    pub policy: PolicyEngine,
    /// Permitted receive directory (already checked against policy).
    pub receive_dir: PathBuf,
    pub limits: Limits,
    pub bind_timeout: Duration,
    /// Track transfers (IPC, restart-durable sends to Sources). None: untracked.
    pub manager: Option<Arc<Manager>>,
    /// Ask the local user (via the manager) for offers no rule auto-accepts,
    /// waiting this long. None: headless, deny.
    pub offer_expiry: Option<Duration>,
}

/// A stream the session accepted for a local service.
pub struct LocalStream {
    pub service: String,
    pub stream: IoStream,
}

/// Target-initiated open, served by the session loop.
pub type OpenRequest = (String, StreamPriority, oneshot::Sender<Result<IoStream, String>>);

struct SessionEntry {
    peer: watch::Receiver<Option<VerifiedPeer>>,
    open: mpsc::Sender<OpenRequest>,
}

/// One per Target; shared by every WebRTC session.
pub struct TransferEndpoint {
    cfg: TransferConfig,
    sessions: Mutex<HashMap<Uuid, SessionEntry>>,
    events: mpsc::UnboundedSender<(TransferId, TransferEvent)>,
    /// Per verified Source SKI: its current session for the manager, and a generation.
    links: Mutex<HashMap<String, (LinkTx, u64)>>,
}

type LinkTx = watch::Sender<Option<Arc<dyn Link>>>;

/// A bound Source session, as the manager sees it.
struct TargetLink {
    open: mpsc::Sender<OpenRequest>,
    peer: VerifiedPeer,
    generation: u64,
}

impl Link for TargetLink {
    fn opener(&self) -> Box<dyn StreamOpener> {
        Box::new(SessionStreams(self.open.clone()))
    }
    fn peer(&self) -> &VerifiedPeer {
        &self.peer
    }
    fn generation(&self) -> u64 {
        self.generation
    }
}

/// Per-session wiring handed to the session loop.
pub struct SessionLocal {
    /// Accepted local streams go here.
    pub streams: mpsc::Sender<LocalStream>,
    /// Some once the Source proved its identity on this session.
    pub peer: watch::Receiver<Option<VerifiedPeer>>,
    /// Target-initiated opens to serve.
    pub opens: mpsc::Receiver<OpenRequest>,
}

impl TransferEndpoint {
    pub fn new(cfg: TransferConfig) -> (Arc<Self>, mpsc::UnboundedReceiver<(TransferId, TransferEvent)>) {
        let (events, rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                cfg,
                sessions: Mutex::new(HashMap::new()),
                events,
                links: Mutex::new(HashMap::new()),
            }),
            rx,
        )
    }

    /// Start serving a session. `attested_ski` is the Presence-signed
    /// `offer.source.policy.ski`; without it nothing binds and nothing transfers.
    pub fn start_session(self: &Arc<Self>, ctx: BindContext, attested_ski: Option<String>) -> SessionLocal {
        let (stream_tx, stream_rx) = mpsc::channel(16);
        let (peer_tx, peer_rx) = watch::channel(None);
        let (open_tx, open_rx) = mpsc::channel(16);
        let session_id = Uuid::parse_str(&ctx.session_id).unwrap_or_default();
        self.sessions.lock().unwrap().insert(
            session_id,
            SessionEntry {
                peer: peer_rx.clone(),
                open: open_tx,
            },
        );
        tokio::spawn(self.clone().serve(session_id, ctx, attested_ski, stream_rx, peer_tx));
        SessionLocal {
            streams: stream_tx,
            peer: peer_rx,
            opens: open_rx,
        }
    }

    pub fn end_session(&self, session_id: Uuid) {
        self.sessions.lock().unwrap().remove(&session_id);
    }

    /// Sessions whose Source has bound (verified identity).
    pub fn bound_sessions(&self) -> Vec<Uuid> {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, e)| e.peer.borrow().is_some())
            .map(|(id, _)| *id)
            .collect()
    }

    /// The verified Source on `session_id`, if it bound.
    pub fn peer(&self, session_id: Uuid) -> Option<VerifiedPeer> {
        self.sessions
            .lock()
            .unwrap()
            .get(&session_id)
            .and_then(|s| s.peer.borrow().clone())
    }

    async fn serve(
        self: Arc<Self>,
        session_id: Uuid,
        ctx: BindContext,
        attested_ski: Option<String>,
        mut streams: mpsc::Receiver<LocalStream>,
        peer_tx: watch::Sender<Option<VerifiedPeer>>,
    ) {
        let router = Router::default();
        // Non-manager receives on this session, so a lease expiry can stop them.
        let running: Arc<Mutex<Vec<mpsc::Sender<Command>>>> = Arc::default();
        let mut published: Option<(String, u64)> = None;
        let mut lease_timer: Option<tokio::task::JoinHandle<()>> = None;
        while let Some(LocalStream { service, stream }) = streams.recv().await {
            if service == BIND_SERVICE {
                if peer_tx.borrow().is_some() {
                    continue; // one binding per session
                }
                let trust = TrustPolicy {
                    roots: self.cfg.roots.clone(),
                    require_ski: attested_ski.clone(),
                    require_dns: None,
                    now: unix_now(),
                };
                let mut framed = Framed::new(Box::new(stream));
                match bind_peer(&mut framed, BindRole::Answerer, &ctx, &self.cfg.identity, &trust, self.cfg.bind_timeout).await {
                    Ok(peer) => {
                        tracing::info!(%session_id, "Source identity bound to session");
                        let _ = peer_tx.send(Some(peer.clone()));
                        published = self.publish(session_id, &peer);
                        lease_timer = Some(self.clone().expire_lease(session_id, peer, peer_tx.clone(), running.clone()));
                    }
                    Err(code) => tracing::warn!(%session_id, code = code.as_str(), "Source binding failed"),
                }
                continue;
            }
            let routed = router.route(Box::new(stream), self.cfg.limits.step_timeout).await;
            if let Routed::Control { header, stream } = routed {
                let this = self.clone();
                let router = router.clone();
                let peer = peer_tx.borrow().clone();
                let running = running.clone();
                tokio::spawn(async move {
                    let prompt = match (&this.cfg.manager, this.cfg.offer_expiry) {
                        (Some(m), Some(expiry)) => Some(m.prompt(expiry)),
                        _ => None,
                    };
                    let mut consent = this.cfg.policy.consent(peer.clone(), prompt);
                    if let (Some(m), Some(p)) = (&this.cfg.manager, &peer) {
                        let sink = DeferredSink::new(m.clone(), this.cfg.receive_dir.clone());
                        m.receive(&p.ski, p.path, &router, header, stream, sink, &mut consent).await;
                        return;
                    }
                    let id = header.transfer_id;
                    let mut sink = match NativeSink::new(&this.cfg.receive_dir) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(error = %e, "receive directory unavailable");
                            return;
                        }
                    };
                    let (ev_tx, ev_rx) = mpsc::unbounded_channel();
                    let forward = this.forward(id, ev_rx);
                    let (cmd_tx, cmd_rx) = mpsc::channel(4);
                    running.lock().unwrap().push(cmd_tx);
                    receive(&router, header, stream, &mut sink, &mut consent, &this.cfg.limits, ev_tx, cmd_rx).await;
                    forward.await;
                });
            }
        }
        if let Some(t) = lease_timer {
            t.abort();
        }
        if let Some((ski, generation)) = published {
            if let Some((tx, g)) = self.links.lock().unwrap().get(&ski) {
                if *g == generation {
                    let _ = tx.send(None);
                }
            }
        }
        self.end_session(session_id);
    }

    /// Make this session the manager's route to the bound Source.
    fn publish(&self, session_id: Uuid, peer: &VerifiedPeer) -> Option<(String, u64)> {
        let manager = self.cfg.manager.as_ref()?;
        let open = self.sessions.lock().unwrap().get(&session_id)?.open.clone();
        let mut links = self.links.lock().unwrap();
        let fresh = !links.contains_key(&peer.ski);
        let (tx, g) = links.entry(peer.ski.clone()).or_insert_with(|| (watch::channel(None).0, 0));
        *g += 1;
        if fresh {
            manager.set_link(&peer.ski, tx.subscribe());
        }
        let _ = tx.send(Some(Arc::new(TargetLink { open, peer: peer.clone(), generation: *g })));
        Some((peer.ski.clone(), *g))
    }

    /// When the Source's authorization lease ends, stop its transfers on this
    /// session (they keep their data) and refuse new ones until it re-binds on
    /// a fresh, re-authorized session.
    fn expire_lease(
        self: Arc<Self>,
        session_id: Uuid,
        peer: VerifiedPeer,
        peer_tx: watch::Sender<Option<VerifiedPeer>>,
        running: Arc<Mutex<Vec<mpsc::Sender<Command>>>>,
    ) -> tokio::task::JoinHandle<()> {
        let secs = (self.cfg.policy.lease_until(&peer) - unix_now()).max(0) as u64;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(secs)).await;
            tracing::info!(%session_id, "Source authorization lease ended; stopping its transfers");
            let _ = peer_tx.send(None);
            if let Some((tx, _)) = self.links.lock().unwrap().get(&peer.ski) {
                let _ = tx.send(None);
            }
            if let Some(m) = &self.cfg.manager {
                m.interrupt(&peer.ski, Command::AuthExpired).await;
            }
            let senders = std::mem::take(&mut *running.lock().unwrap());
            for s in senders {
                let _ = s.send(Command::AuthExpired).await;
            }
        })
    }

    fn forward(
        &self,
        id: TransferId,
        mut rx: mpsc::UnboundedReceiver<TransferEvent>,
    ) -> impl std::future::Future<Output = ()> {
        let out = self.events.clone();
        async move {
            while let Some(ev) = rx.recv().await {
                let _ = out.send((id, ev));
            }
        }
    }

    /// Send to the bound Source on `session_id` (Target→Source).
    pub async fn send<F: SourceFiles>(
        &self,
        session_id: Uuid,
        req: Outgoing<F>,
        cmds: mpsc::Receiver<Command>,
    ) -> Outcome {
        let entry = {
            let s = self.sessions.lock().unwrap();
            s.get(&session_id).map(|e| (e.peer.borrow().clone(), e.open.clone()))
        };
        let Some((Some(_peer), open)) = entry else {
            return Outcome::Rejected(TransferErrorKind::Unauthorized);
        };
        let id = req.transfer_id;
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        let forward = self.forward(id, ev_rx);
        let mut opener = SessionStreams(open);
        let (outcome, ()) = tokio::join!(send(&mut opener, req, &self.cfg.limits, ev_tx, cmds), forward);
        outcome
    }
}

/// Opens Target-initiated transfer streams through the session loop.
struct SessionStreams(mpsc::Sender<OpenRequest>);

#[async_trait]
impl StreamOpener for SessionStreams {
    async fn open(&mut self) -> idr_core::Result<Box<dyn LogicalStream>> {
        let gone = || IdrError::new(IdrErrorKind::TransportClosed, "session closed");
        let (tx, rx) = oneshot::channel();
        self.0
            .send((TRANSFER_SERVICE.to_string(), StreamPriority::Bulk, tx))
            .await
            .map_err(|_| gone())?;
        match rx.await.map_err(|_| gone())? {
            Ok(s) => Ok(Box::new(s)),
            Err(m) => Err(IdrError::new(IdrErrorKind::ConnectionRefused, m)),
        }
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

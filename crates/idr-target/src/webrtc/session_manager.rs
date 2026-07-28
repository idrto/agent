use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::config::WebRtcConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Negotiating,
    IceConnecting,
    DataChannelOpen,
    Active,
    Failed,
    Closed,
}

/// Inbox for remote ICE trickle delivered from Presence while a peer is live.
#[derive(Clone)]
pub struct PeerIceInbox {
    tx: mpsc::Sender<RemoteIceMsg>,
}

#[derive(Debug)]
pub enum RemoteIceMsg {
    Candidate { candidate: String, mid: String },
    End,
}

impl PeerIceInbox {
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<RemoteIceMsg>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
    }

    pub async fn add_candidate(&self, candidate: String, mid: String) -> anyhow::Result<()> {
        self.tx
            .send(RemoteIceMsg::Candidate { candidate, mid })
            .await
            .map_err(|_| anyhow::anyhow!("peer ice inbox closed"))
    }

    pub async fn end_candidates(&self) -> anyhow::Result<()> {
        self.tx
            .send(RemoteIceMsg::End)
            .await
            .map_err(|_| anyhow::anyhow!("peer ice inbox closed"))
    }
}

struct SessionEntry {
    state: SessionState,
    created_at: Instant,
    last_activity: Instant,
    open_streams: u32,
    ice_inbox: Option<PeerIceInbox>,
}

#[derive(Default)]
struct Inner {
    sessions: HashMap<Uuid, SessionEntry>,
}

pub struct WebRtcSessionManager {
    cfg: WebRtcConfig,
    inner: Mutex<Inner>,
}

impl WebRtcSessionManager {
    pub fn new(cfg: WebRtcConfig) -> Arc<Self> {
        let mgr = Arc::new(Self {
            cfg,
            inner: Mutex::new(Inner::default()),
        });
        let weak = Arc::downgrade(&mgr);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                let Some(mgr) = weak.upgrade() else { break };
                mgr.reap();
            }
        });
        mgr
    }

    pub fn try_acquire(
        self: &Arc<Self>,
        session_id: Uuid,
    ) -> Result<OwnedSessionGuard, SessionError> {
        let mut inner = self.inner.lock();
        if inner.sessions.contains_key(&session_id) {
            return Err(SessionError::Duplicate);
        }
        if inner.sessions.len() as u32 >= self.cfg.max_sessions {
            return Err(SessionError::Busy);
        }
        let now = Instant::now();
        inner.sessions.insert(
            session_id,
            SessionEntry {
                state: SessionState::Negotiating,
                created_at: now,
                last_activity: now,
                open_streams: 0,
                ice_inbox: None,
            },
        );
        Ok(OwnedSessionGuard {
            manager: Arc::clone(self),
            session_id,
            keep: false,
        })
    }

    pub fn register_ice_inbox(&self, session_id: Uuid, inbox: PeerIceInbox) {
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.sessions.get_mut(&session_id) {
            entry.ice_inbox = Some(inbox);
        }
    }

    pub fn clear_ice_inbox(&self, session_id: Uuid) {
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.sessions.get_mut(&session_id) {
            entry.ice_inbox = None;
        }
    }

    pub fn ice_inbox(&self, session_id: Uuid) -> Option<PeerIceInbox> {
        self.inner
            .lock()
            .sessions
            .get(&session_id)
            .and_then(|e| e.ice_inbox.clone())
    }

    pub fn set_state(&self, session_id: Uuid, state: SessionState) {
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.sessions.get_mut(&session_id) {
            entry.state = state;
            entry.last_activity = Instant::now();
        }
    }

    pub fn touch(&self, session_id: Uuid) {
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.sessions.get_mut(&session_id) {
            entry.last_activity = Instant::now();
        }
    }

    pub fn stream_opened(&self, session_id: Uuid) {
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.sessions.get_mut(&session_id) {
            entry.open_streams = entry.open_streams.saturating_add(1);
            entry.last_activity = Instant::now();
            if matches!(
                entry.state,
                SessionState::DataChannelOpen
                    | SessionState::IceConnecting
                    | SessionState::Negotiating
            ) {
                entry.state = SessionState::Active;
            }
        }
    }

    pub fn stream_closed(&self, session_id: Uuid) {
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.sessions.get_mut(&session_id) {
            entry.open_streams = entry.open_streams.saturating_sub(1);
            entry.last_activity = Instant::now();
        }
    }

    pub fn active_count(&self) -> u32 {
        self.inner.lock().sessions.len() as u32
    }

    pub fn contains(&self, session_id: Uuid) -> bool {
        self.inner.lock().sessions.contains_key(&session_id)
    }

    pub fn end_session(&self, session_id: Uuid) {
        self.release(session_id);
    }

    fn release(&self, session_id: Uuid) {
        let mut inner = self.inner.lock();
        inner.sessions.remove(&session_id);
    }

    fn reap(&self) {
        let now = Instant::now();
        let idle = self.cfg.idle_timeout();
        let nego = self.cfg.negotiation_timeout();
        let mut inner = self.inner.lock();
        inner.sessions.retain(|_, entry| {
            let timed_out = match entry.state {
                SessionState::Negotiating | SessionState::IceConnecting => {
                    now.duration_since(entry.created_at) > nego
                }
                SessionState::DataChannelOpen | SessionState::Active => {
                    entry.open_streams == 0 && now.duration_since(entry.last_activity) > idle
                }
                SessionState::Failed | SessionState::Closed => true,
            };
            !timed_out
        });
    }
}

/// Keeps the session slot until dropped (failure) or `keep_alive()` (success).
pub struct OwnedSessionGuard {
    manager: Arc<WebRtcSessionManager>,
    session_id: Uuid,
    keep: bool,
}

impl OwnedSessionGuard {
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Leave the session in the table after this guard drops (negotiation succeeded).
    pub fn keep_alive(mut self) {
        self.keep = true;
    }
}

impl Drop for OwnedSessionGuard {
    fn drop(&mut self) {
        if !self.keep {
            self.manager.release(self.session_id);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    Busy,
    Duplicate,
    NegotiationFailed(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => write!(f, "max concurrent WebRTC sessions reached"),
            Self::Duplicate => write!(f, "session already exists"),
            Self::NegotiationFailed(msg) => write!(f, "negotiation failed: {msg}"),
        }
    }
}

impl std::error::Error for SessionError {}

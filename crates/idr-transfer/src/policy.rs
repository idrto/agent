//! Local transfer policy: identity, consent modes, admin limits, rate limits,
//! concurrency, and race-free quota / disk reservation.
//!
//! Each endpoint enforces its own policy. The receiver decides here; the sender
//! checks [`SendPolicy`] before offering. The effective permission is the
//! intersection: nothing a peer sends can loosen local policy, and a sender's own
//! confirmation (`--yes`) is never receiver consent.
//!
//! Order of checks for an incoming offer (first failure wins):
//! 1. verified peer (a successful [`crate::bind::bind_peer`]) with an unexpired lease;
//! 2. receiving enabled and not `RejectAll`;
//! 3. per-peer offer rate and failure cool-off;
//! 4. administrative limits (largest file, total size), which outrank user consent;
//! 5. the peer's rule (deny), concurrency and pending-offer caps;
//! 6. approval: auto-accept within its size limit, else ask (interactive only),
//!    else deny (headless default);
//! 7. quota and free-disk reservation, atomically with every other transfer.
//!
//! Organization policy can slot in as another check; it isn't built here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use idr_protocol::peer_bind::VerifiedPeer;
use idr_protocol::transfer::{TransferErrorKind, TransferId};
use tokio::sync::mpsc;

use crate::events::{Command, EventTx, Outcome, TransferEvent};
use crate::manifest::OfferSummary;
use crate::storage::{Approval, Consent, MaybeSend, OfferInfo};

use TransferErrorKind::{
    AuthorizationExpired, LimitExceeded, Rejected, StorageFailed, Unauthorized,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConsentMode {
    /// Ask the user for anything not auto-accepted (interactive endpoints only).
    #[default]
    AlwaysAsk,
    RejectAll,
}

/// Per-peer rule, keyed by verified SKI (never a display name).
#[derive(Debug, Clone, Default)]
pub struct PeerRule {
    pub deny: bool,
    /// Accept without asking, within `auto_accept_max_bytes` and the admin limits.
    pub auto_accept: bool,
    pub auto_accept_max_bytes: Option<u64>,
    pub max_file_bytes: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ReceivePolicy {
    pub enabled: bool,
    /// A user can be asked. Headless endpoints never ask: unmatched offers are denied.
    pub interactive: bool,
    pub mode: ConsentMode,
    pub peers: HashMap<String, PeerRule>,
    /// Admin limits; they bound auto-accept and user approval alike.
    pub max_file_bytes: u64,
    pub max_transfer_bytes: u64,
    /// Bytes all incomplete incoming transfers may reserve together.
    pub quota_bytes: u64,
    pub max_concurrent_per_peer: u32,
    pub max_concurrent_total: u32,
    /// Offers waiting for a user decision.
    pub max_pending_offers: u32,
    pub offers_per_minute: u32,
    /// Refused offers in a row before the peer is cooled off.
    pub max_failures: u32,
    pub cooloff: Duration,
    /// Longest a transfer's authorization lasts before re-authorization.
    pub lease: Duration,
}

impl ReceivePolicy {
    /// Interactive app default: receiving on, always ask.
    pub fn interactive() -> Self {
        Self {
            interactive: true,
            ..Self::headless()
        }
    }

    /// Headless default: nothing is accepted without an explicit peer rule.
    pub fn headless() -> Self {
        Self {
            enabled: true,
            interactive: false,
            mode: ConsentMode::AlwaysAsk,
            peers: HashMap::new(),
            max_file_bytes: 64 << 30,
            max_transfer_bytes: 256 << 30,
            quota_bytes: 50 << 30,
            max_concurrent_per_peer: 4,
            max_concurrent_total: 16,
            max_pending_offers: 8,
            offers_per_minute: 10,
            max_failures: 5,
            cooloff: Duration::from_secs(600),
            lease: Duration::from_secs(15 * 60),
        }
    }
}

/// Shortest configurable lease. Each resume re-reads the already-sent prefix
/// (receiver verify + hash, sender hash); at the 64 GiB file cap that is a few
/// minutes, so a shorter lease could end every attempt before new data moves.
pub const MIN_LEASE: Duration = Duration::from_secs(5 * 60);

/// The lease from a `lease_minutes` setting: 15 min by default, never below [`MIN_LEASE`].
pub fn lease_from_minutes(minutes: Option<u64>) -> Duration {
    minutes.map_or(Duration::from_secs(15 * 60), |m| Duration::from_secs(m.saturating_mul(60)).max(MIN_LEASE))
}

/// Asks the local user about an offer (interactive endpoints).
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Prompt: MaybeSend {
    async fn ask(&mut self, peer: &VerifiedPeer, offer: &OfferInfo<'_>) -> bool;
}

/// Free bytes at the destination, if known (native: [`crate::native::free_space`]).
pub type DiskProbe = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

#[derive(Default)]
struct PeerState {
    active: u32,
    window_start: Option<Instant>,
    offers_in_window: u32,
    failures: u32,
    cooled_until: Option<Instant>,
}

#[derive(Default)]
struct State {
    peers: HashMap<String, PeerState>,
    active_total: u32,
    pending: u32,
    reserved: HashMap<TransferId, (String, u64)>,
}

/// Shared by every session on this endpoint.
#[derive(Clone)]
pub struct PolicyEngine {
    policy: Arc<ReceivePolicy>,
    disk: Option<DiskProbe>,
    state: Arc<Mutex<State>>,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl PolicyEngine {
    pub fn new(policy: ReceivePolicy, disk: Option<DiskProbe>) -> Self {
        Self {
            policy: Arc::new(policy),
            disk,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    /// Consent for offers on one session. `peer` is the result of the binding
    /// exchange; `None` (anonymous, unverified, binding failed) refuses everything.
    pub fn consent(&self, peer: Option<VerifiedPeer>, prompt: Option<Box<dyn Prompt>>) -> PeerConsent {
        PeerConsent {
            engine: self.clone(),
            peer,
            prompt,
            admitted: None,
        }
    }

    /// When this peer's authorization for a new transfer ends: the policy lease,
    /// capped by the peer's certificate chain.
    pub fn lease_until(&self, peer: &VerifiedPeer) -> i64 {
        (unix_now() + self.policy.lease.as_secs() as i64).min(peer.not_after)
    }

    /// Bytes currently reserved by incomplete incoming transfers.
    pub fn reserved_bytes(&self) -> u64 {
        self.state.lock().unwrap().reserved.values().map(|(_, b)| b).sum()
    }

    /// Admission checks before asking anyone. On success one concurrency slot is
    /// held for this peer.
    fn admit(&self, peer: &VerifiedPeer, s: &OfferSummary) -> Result<Option<Approval>, TransferErrorKind> {
        let p = &self.policy;
        if unix_now() > peer.not_after {
            return Err(AuthorizationExpired);
        }
        if !p.enabled || p.mode == ConsentMode::RejectAll {
            return Err(Unauthorized);
        }
        let now = Instant::now();
        let mut st = self.state.lock().unwrap();
        let ps = st.peers.entry(peer.ski.clone()).or_default();
        if ps.cooled_until.is_some_and(|t| now < t) {
            return Err(LimitExceeded);
        }
        if ps.window_start.is_none_or_elapsed(now, Duration::from_secs(60)) {
            ps.window_start = Some(now);
            ps.offers_in_window = 0;
        }
        ps.offers_in_window += 1;
        if ps.offers_in_window > p.offers_per_minute {
            return Err(LimitExceeded);
        }
        let rule = p.peers.get(&peer.ski).cloned().unwrap_or_default();
        let file_cap = rule.max_file_bytes.unwrap_or(u64::MAX).min(p.max_file_bytes);
        if s.largest_file > file_cap || s.total_bytes > p.max_transfer_bytes {
            return Err(LimitExceeded);
        }
        if rule.deny {
            return Err(Unauthorized);
        }
        let ps = st.peers.get(&peer.ski).unwrap();
        if ps.active >= p.max_concurrent_per_peer || st.active_total >= p.max_concurrent_total {
            return Err(LimitExceeded);
        }
        let auto = rule.auto_accept
            && s.total_bytes <= rule.auto_accept_max_bytes.unwrap_or(u64::MAX);
        let approval = if auto {
            Some(Approval::Auto)
        } else if p.interactive && p.mode == ConsentMode::AlwaysAsk {
            if st.pending >= p.max_pending_offers {
                return Err(LimitExceeded);
            }
            st.pending += 1;
            None
        } else {
            // Headless: unknown peers and known peers without auto-accept are denied.
            return Err(Unauthorized);
        };
        st.peers.get_mut(&peer.ski).unwrap().active += 1;
        st.active_total += 1;
        Ok(approval)
    }

    /// Quota and disk, checked and reserved under one lock.
    fn reserve(&self, id: TransferId, peer: &str, bytes: u64) -> Result<(), TransferErrorKind> {
        let mut st = self.state.lock().unwrap();
        let reserved: u64 = st.reserved.values().map(|(_, b)| b).sum();
        if reserved.saturating_add(bytes) > self.policy.quota_bytes {
            return Err(LimitExceeded);
        }
        if let Some(free) = self.disk.as_ref().and_then(|d| d()) {
            if reserved.saturating_add(bytes) > free {
                return Err(StorageFailed);
            }
        }
        st.reserved.insert(id, (peer.to_string(), bytes));
        Ok(())
    }

    fn release(&self, id: Option<&TransferId>, peer: &str, failed: bool) {
        let mut st = self.state.lock().unwrap();
        if let Some(id) = id {
            st.reserved.remove(id);
        }
        st.active_total = st.active_total.saturating_sub(1);
        let cooloff = self.policy.cooloff;
        let max_failures = self.policy.max_failures;
        let ps = st.peers.entry(peer.to_string()).or_default();
        ps.active = ps.active.saturating_sub(1);
        if failed {
            ps.failures += 1;
            if ps.failures >= max_failures {
                ps.cooled_until = Some(Instant::now() + cooloff);
                ps.failures = 0;
            }
        } else {
            ps.failures = 0;
        }
    }

    fn note_refusal(&self, peer: &str) {
        let mut st = self.state.lock().unwrap();
        let (cooloff, max) = (self.policy.cooloff, self.policy.max_failures);
        let ps = st.peers.entry(peer.to_string()).or_default();
        ps.failures += 1;
        if ps.failures >= max {
            ps.cooled_until = Some(Instant::now() + cooloff);
            ps.failures = 0;
        }
    }
}

trait WindowExt {
    fn is_none_or_elapsed(&self, now: Instant, len: Duration) -> bool;
}

impl WindowExt for Option<Instant> {
    fn is_none_or_elapsed(&self, now: Instant, len: Duration) -> bool {
        match self {
            None => true,
            Some(t) => now.duration_since(*t) >= len,
        }
    }
}

/// [`Consent`] for one session's peer.
pub struct PeerConsent {
    engine: PolicyEngine,
    peer: Option<VerifiedPeer>,
    prompt: Option<Box<dyn Prompt>>,
    /// Holding a concurrency slot (and maybe a reservation) for this transfer.
    admitted: Option<(TransferId, bool)>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Consent for PeerConsent {
    async fn decide(&mut self, offer: &OfferInfo<'_>) -> Result<Approval, TransferErrorKind> {
        let Some(peer) = self.peer.clone() else {
            return Err(Unauthorized);
        };
        let pre = match self.engine.admit(&peer, offer.summary) {
            Ok(a) => a,
            Err(k) => {
                self.engine.note_refusal(&peer.ski);
                return Err(k);
            }
        };
        self.admitted = Some((*offer.transfer_id, false));
        let approval = match pre {
            Some(a) => a,
            None => {
                let yes = match self.prompt.as_mut() {
                    Some(p) => p.ask(&peer, offer).await,
                    None => false,
                };
                self.engine.state.lock().unwrap().pending -= 1;
                if !yes {
                    self.engine.release(None, &peer.ski, false);
                    self.admitted = None;
                    return Err(Rejected);
                }
                Approval::User
            }
        };
        if let Err(k) = self.engine.reserve(*offer.transfer_id, &peer.ski, offer.summary.total_bytes) {
            self.engine.release(None, &peer.ski, false);
            self.admitted = None;
            return Err(k);
        }
        self.admitted = Some((*offer.transfer_id, true));
        tracing::info!(approval = ?approval, "transfer offer approved");
        Ok(approval)
    }

    async fn finished(&mut self, outcome: &Outcome) {
        let (Some((id, reserved)), Some(peer)) = (self.admitted.take(), self.peer.as_ref()) else {
            return;
        };
        let failed = matches!(outcome, Outcome::Failed(TransferErrorKind::ProtocolViolation));
        self.engine.release(reserved.then_some(&id), &peer.ski, failed);
    }
}

/// What the local sender may send to whom.
#[derive(Debug, Clone)]
pub struct SendPolicy {
    pub enabled: bool,
    /// Verified SKIs this device may send to; `None` = any verified peer.
    pub allowed_peers: Option<Vec<String>>,
    pub max_transfer_bytes: u64,
}

impl Default for SendPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_peers: None,
            max_transfer_bytes: 256 << 30,
        }
    }
}

impl SendPolicy {
    /// Check before offering. A sender-side confirmation never replaces the
    /// receiver's own decision.
    pub fn check(&self, peer: Option<&VerifiedPeer>, s: &OfferSummary) -> Result<(), TransferErrorKind> {
        let peer = peer.ok_or(Unauthorized)?;
        if !self.enabled
            || self
                .allowed_peers
                .as_ref()
                .is_some_and(|a| !a.contains(&peer.ski))
        {
            return Err(Unauthorized);
        }
        if unix_now() > peer.not_after {
            return Err(AuthorizationExpired);
        }
        if s.total_bytes > self.max_transfer_bytes {
            return Err(LimitExceeded);
        }
        Ok(())
    }
}

/// Drive a transfer's authorization lease. `margin` before `until`, emit
/// `LeaseExpiring` and try `renew` (the existing re-authorization path, e.g. a
/// fresh session); a renewal extends the lease. If none arrives by `until`, send
/// [`Command::AuthExpired`]: the engine checkpoints and stops, keeping verified
/// data for a resume after re-authorization. Ends when `cmds` closes.
pub async fn lease_watch<F, Fut>(
    mut until: tokio::time::Instant,
    margin: Duration,
    mut renew: F,
    cmds: mpsc::Sender<Command>,
    events: EventTx,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<tokio::time::Instant>>,
{
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(until.checked_sub(margin).unwrap_or(until)) => {}
            _ = cmds.closed() => return,
        }
        let _ = events.send(TransferEvent::LeaseExpiring {
            secs_left: until.saturating_duration_since(tokio::time::Instant::now()).as_secs(),
        });
        let renewed = tokio::select! {
            r = renew() => r,
            _ = tokio::time::sleep_until(until) => None,
        };
        match renewed {
            Some(next) if next > until => until = next,
            _ => {
                tokio::time::sleep_until(until).await;
                let _ = cmds.send(Command::AuthExpired).await;
                return;
            }
        }
    }
}

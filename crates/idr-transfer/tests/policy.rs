//! Identity binding, consent policy, quota and authorization-lease tests.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use common::*;
use ed25519_dalek::SigningKey;
use idr_protocol::peer_bind::{self, BindContext, BindRole, TrustPolicy, VerifiedPeer};
use idr_protocol::transfer::{new_transfer_id, ManifestKind, TransferErrorKind as K};
use idr_transfer::bind::{bind_peer, LocalIdentity};
use idr_transfer::io::Framed;
use idr_transfer::manifest::{build, OfferSummary, Selected};
use idr_transfer::mem::{MemFiles, MemSink};
use idr_transfer::policy::{lease_watch, PeerRule, PolicyEngine, Prompt, ReceivePolicy, SendPolicy};
use idr_transfer::storage::{Approval, Consent, OfferInfo};
use idr_transfer::{Command, Limits, Outcome, TransferEvent};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType,
};
use tokio::sync::{mpsc, watch};

// ---- A small DP-shaped PKI -------------------------------------------------

fn keys(seed: u8) -> (SigningKey, KeyPair) {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&[seed; 32]);
    (
        SigningKey::from_bytes(&[seed; 32]),
        KeyPair::try_from(der.as_slice()).unwrap(),
    )
}

fn params(cn: &str, ca: bool, years: (i32, i32)) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    p.distinguished_name = dn;
    p.not_before = rcgen::date_time_ymd(years.0, 1, 1);
    p.not_after = rcgen::date_time_ymd(years.1, 1, 1);
    if ca {
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    }
    p
}

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn root(seed: u8) -> Ca {
    let (_, key) = keys(seed);
    let cert = params("root", true, (2020, 2099)).self_signed(&key).unwrap();
    Ca { cert, key }
}

fn zone(root: &Ca, seed: u8) -> Ca {
    let (_, key) = keys(seed);
    let cert = params("zone", true, (2020, 2099))
        .signed_by(&key, &root.cert, &root.key)
        .unwrap();
    Ca { cert, key }
}

/// A device leaf (`urn:dp:ski:<ski>` and optional host DNS SAN), chained via `issuer`.
fn device(issuer: &Ca, seed: u8, ski: &str, host: Option<&str>, years: (i32, i32)) -> LocalIdentity {
    let (sk, kp) = keys(seed);
    let mut p = params(ski, false, years);
    p.subject_alt_names = vec![SanType::URI(format!("urn:dp:ski:{ski}").try_into().unwrap())];
    if let Some(h) = host {
        p.subject_alt_names.push(SanType::DnsName(h.try_into().unwrap()));
    }
    let leaf = p.signed_by(&kp, &issuer.cert, &issuer.key).unwrap();
    LocalIdentity {
        key: sk,
        ski: ski.into(),
        chain_pem: format!("{}{}", leaf.pem(), issuer.cert.pem()),
    }
}

const FQHN: &str = "laptop--acme.idr.to";

fn ctx(session: &str) -> BindContext {
    BindContext {
        session_id: session.into(),
        target_fqhn: FQHN.into(),
        offerer_fingerprint: "sha-256 AA:AA".into(),
        answerer_fingerprint: "sha-256 BB:BB".into(),
        path: None,
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn trust(root: &Ca) -> TrustPolicy {
    TrustPolicy {
        roots: vec![root.cert.der().to_vec()],
        now: now(),
        ..TrustPolicy::default()
    }
}

fn pipe() -> (Framed, Framed) {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let (_c, cut) = watch::channel(false);
    std::mem::forget(_c);
    let s = |io| Framed::new(Box::new(MemStream { io, cut: cut.clone(), hook: None }));
    (s(a), s(b))
}

/// Both sides bind; returns (what the Source learned, what the Target learned).
async fn bind_both(
    source: &LocalIdentity,
    target: &LocalIdentity,
    source_trust: TrustPolicy,
    target_trust: TrustPolicy,
) -> (Result<VerifiedPeer, K>, Result<VerifiedPeer, K>) {
    let (mut s, mut t) = pipe();
    let c = ctx("session-1");
    let d = Duration::from_secs(5);
    tokio::join!(
        bind_peer(&mut s, BindRole::Offerer, &c, source, &source_trust, d),
        bind_peer(&mut t, BindRole::Answerer, &c, target, &target_trust, d),
    )
}

// ---- Identity binding ------------------------------------------------------

/// AUTH-001: both peers verify each other, chained through a zone CA to the
/// entity root; the Target also matches the Presence-attested SKI and the Source
/// checks the Target's certificate names the FQHN it dialled.
#[tokio::test]
async fn peers_verify_each_other() {
    let r = root(1);
    let z = zone(&r, 2);
    let src = device(&z, 3, "src-ski", None, (2020, 2099));
    let tgt = device(&r, 4, "tgt-ski", Some(FQHN), (2020, 2099));
    let (at_source, at_target) = bind_both(
        &src,
        &tgt,
        TrustPolicy { require_dns: Some(FQHN.into()), ..trust(&r) },
        TrustPolicy { require_ski: Some("src-ski".into()), ..trust(&r) },
    )
    .await;
    let target_seen = at_source.unwrap();
    assert_eq!((target_seen.ski.as_str(), target_seen.role), ("tgt-ski", BindRole::Answerer));
    let source_seen = at_target.unwrap();
    assert_eq!((source_seen.ski.as_str(), source_seen.role), ("src-ski", BindRole::Offerer));
    assert_eq!(source_seen.not_after, 4_070_908_800, "earliest notAfter in the chain");
}

/// AUTH-006 / AUTH-007 / AUTH-008: a proof is only valid for its own nonces,
/// fingerprints, roles and session.
#[test]
fn proofs_do_not_transfer_to_other_sessions_fingerprints_or_roles() {
    let r = root(1);
    let src = device(&r, 3, "src-ski", None, (2020, 2099));
    let c = ctx("session-1");
    let (on, an) = ([1u8; 32], [2u8; 32]);
    let sig = peer_bind::sign(&src.key, &peer_bind::transcript(&c, BindRole::Offerer, &on, &an));
    let check = |t: Vec<u8>| peer_bind::verify(BindRole::Offerer, "src-ski", &src.chain_pem, &sig, &t, &trust(&r));
    assert!(check(peer_bind::transcript(&c, BindRole::Offerer, &on, &an)).is_ok());

    let replay = peer_bind::transcript(&c, BindRole::Offerer, &[9; 32], &an);
    assert_eq!(check(replay), Err(peer_bind::BindError::SignatureInvalid), "replayed nonce");
    let mut other_fp = c.clone();
    other_fp.answerer_fingerprint = "sha-256 CC:CC".into();
    assert!(check(peer_bind::transcript(&other_fp, BindRole::Offerer, &on, &an)).is_err());
    assert!(check(peer_bind::transcript(&c, BindRole::Answerer, &on, &an)).is_err(), "role swap");
    let mut other_session = c.clone();
    other_session.session_id = "session-2".into();
    assert!(check(peer_bind::transcript(&other_session, BindRole::Offerer, &on, &an)).is_err());
}

/// AUTH-009: expired or not-yet-valid certificates, and another entity's root.
#[tokio::test]
async fn bad_certificates_are_refused() {
    let r = root(1);
    let tgt = device(&r, 4, "tgt-ski", Some(FQHN), (2020, 2099));
    for (years, expect) in [((2020, 2021), K::AuthorizationExpired), ((2090, 2099), K::AuthorizationExpired)] {
        let src = device(&r, 3, "src-ski", None, years);
        let (_, at_target) = bind_both(&src, &tgt, trust(&r), trust(&r)).await;
        assert_eq!(at_target, Err(expect), "{years:?}");
    }
    let other = root(9);
    let stranger = device(&other, 5, "src-ski", None, (2020, 2099));
    let (_, at_target) = bind_both(&stranger, &tgt, trust(&r), trust(&r)).await;
    assert_eq!(at_target, Err(K::Unauthorized), "other entity's root");
}

/// AUTH-003 / AUTH-004 / AUTH-005: a Source whose proven SKI isn't the one
/// Presence verified and signed is refused, whatever it calls itself.
#[tokio::test]
async fn ski_must_match_presence_attestation() {
    let r = root(1);
    let src = device(&r, 3, "src-ski", None, (2020, 2099));
    let tgt = device(&r, 4, "tgt-ski", Some(FQHN), (2020, 2099));
    let (_, at_target) = bind_both(
        &src,
        &tgt,
        trust(&r),
        TrustPolicy { require_ski: Some("someone-else".into()), ..trust(&r) },
    )
    .await;
    assert_eq!(at_target, Err(K::Unauthorized));
}

/// The Source verifies the Target before any Target-initiated transfer: a
/// device certificate that doesn't name the dialled FQHN is refused.
#[tokio::test]
async fn source_refuses_a_target_without_the_fqhn() {
    let r = root(1);
    let src = device(&r, 3, "src-ski", None, (2020, 2099));
    let impostor = device(&r, 6, "other-device", Some("printer--acme.idr.to"), (2020, 2099));
    let (at_source, _) = bind_both(
        &src,
        &impostor,
        TrustPolicy { require_dns: Some(FQHN.into()), ..trust(&r) },
        trust(&r),
    )
    .await;
    assert_eq!(at_source, Err(K::Unauthorized));
}

/// A device can't mint a certificate with its own (non-CA) key: an enrolled
/// device forging a leaf that names the Target's host is refused.
#[tokio::test]
async fn non_ca_issuer_cannot_mint_identities() {
    let r = root(1);
    let src = device(&r, 3, "src-ski", None, (2020, 2099));
    let (_, attacker_kp) = keys(7);
    let attacker_leaf = {
        let mut p = params("attacker", false, (2020, 2099));
        p.subject_alt_names = vec![SanType::URI("urn:dp:ski:attacker".try_into().unwrap())];
        p.signed_by(&attacker_kp, &r.cert, &r.key).unwrap()
    };
    let (forged_sk, forged_kp) = keys(8);
    let mut p = params("forged", false, (2020, 2099));
    p.subject_alt_names = vec![
        SanType::URI("urn:dp:ski:tgt-ski".try_into().unwrap()),
        SanType::DnsName(FQHN.try_into().unwrap()),
    ];
    let forged = p.signed_by(&forged_kp, &attacker_leaf, &attacker_kp).unwrap();
    let impostor = LocalIdentity {
        key: forged_sk,
        ski: "tgt-ski".into(),
        chain_pem: format!("{}{}", forged.pem(), attacker_leaf.pem()),
    };
    let (at_source, _) = bind_both(
        &src,
        &impostor,
        TrustPolicy { require_dns: Some(FQHN.into()), ..trust(&r) },
        trust(&r),
    )
    .await;
    assert_eq!(at_source, Err(K::Unauthorized));
}

// ---- Consent policy ----------------------------------------------------------

fn peer(ski: &str) -> VerifiedPeer {
    VerifiedPeer { ski: ski.into(), role: BindRole::Offerer, not_after: i64::MAX, path: None }
}

fn summary(total: u64, largest: u64) -> OfferSummary {
    OfferSummary {
        kind: ManifestKind::Files,
        files: 1,
        dirs: 0,
        total_bytes: total,
        largest_file: largest,
        top_level: vec!["f".into()],
        more_top_level: 0,
    }
}

async fn decide(c: &mut impl Consent, total: u64) -> Result<Approval, K> {
    let id = new_transfer_id();
    c.decide(&OfferInfo { transfer_id: &id, digest: &[0; 32], summary: &summary(total, total), resume: false }).await
}

struct Answer(bool, Arc<AtomicU32>);

#[async_trait]
impl Prompt for Answer {
    async fn ask(&mut self, _: &VerifiedPeer, _: &OfferInfo<'_>) -> bool {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0
    }
}

fn auto(ski: &str, max: Option<u64>) -> (String, PeerRule) {
    (ski.into(), PeerRule { auto_accept: true, auto_accept_max_bytes: max, ..PeerRule::default() })
}

/// AUTH-002 / AUTH-003: without a verified binding nothing is accepted.
#[tokio::test]
async fn unverified_peers_are_refused() {
    let e = PolicyEngine::new(ReceivePolicy::interactive(), None);
    let asked = Arc::new(AtomicU32::new(0));
    let mut c = e.consent(None, Some(Box::new(Answer(true, asked.clone()))));
    assert_eq!(decide(&mut c, 10).await, Err(K::Unauthorized));
    assert_eq!(asked.load(Ordering::SeqCst), 0, "user was asked about an unverified peer");
}

/// AUTH-011 / AUTH-012 / AUTH-015 / CLI-014: interactive asks; headless denies
/// unknown peers and known peers without auto-accept.
#[tokio::test]
async fn interactive_asks_and_headless_denies() {
    let asked = Arc::new(AtomicU32::new(0));
    let e = PolicyEngine::new(ReceivePolicy::interactive(), None);
    let mut yes = e.consent(Some(peer("a")), Some(Box::new(Answer(true, asked.clone()))));
    assert_eq!(decide(&mut yes, 10).await, Ok(Approval::User));
    let mut no = e.consent(Some(peer("a")), Some(Box::new(Answer(false, asked.clone()))));
    assert_eq!(decide(&mut no, 10).await, Err(K::Rejected));

    let mut known = ReceivePolicy::headless();
    known.peers.insert("known".into(), PeerRule::default());
    let h = PolicyEngine::new(known, None);
    assert_eq!(decide(&mut h.consent(Some(peer("stranger")), None), 10).await, Err(K::Unauthorized));
    assert_eq!(decide(&mut h.consent(Some(peer("known")), None), 10).await, Err(K::Unauthorized));
}

/// AUTH-013 / AUTH-014 / EVT-003: allowlisted auto-accept within its size limit only.
#[tokio::test]
async fn auto_accept_is_bounded() {
    let mut p = ReceivePolicy::headless();
    p.peers.extend([auto("friend", Some(1000)), ("enemy".into(), PeerRule { deny: true, auto_accept: true, ..PeerRule::default() })]);
    let e = PolicyEngine::new(p, None);
    assert_eq!(decide(&mut e.consent(Some(peer("friend")), None), 1000).await, Ok(Approval::Auto));
    assert_eq!(decide(&mut e.consent(Some(peer("friend")), None), 1001).await, Err(K::Unauthorized));
    assert_eq!(decide(&mut e.consent(Some(peer("enemy")), None), 1).await, Err(K::Unauthorized));
}

/// AUTH-020: administrative limits win over a user's yes (and the user isn't asked).
#[tokio::test]
async fn admin_limits_beat_user_approval() {
    let mut p = ReceivePolicy::interactive();
    p.max_file_bytes = 100;
    let asked = Arc::new(AtomicU32::new(0));
    let e = PolicyEngine::new(p, None);
    let mut c = e.consent(Some(peer("a")), Some(Box::new(Answer(true, asked.clone()))));
    assert_eq!(decide(&mut c, 101).await, Err(K::LimitExceeded));
    assert_eq!(asked.load(Ordering::SeqCst), 0);
}

/// AUTH-021 / PERF-011: concurrent offers can't overcommit the quota.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn quota_reservation_is_atomic() {
    let mut p = ReceivePolicy::headless();
    p.quota_bytes = 50;
    p.max_concurrent_total = 1000;
    p.max_concurrent_per_peer = 1000;
    p.offers_per_minute = 1000;
    for i in 0..40 {
        p.peers.extend([auto(&format!("p{i}"), None)]);
    }
    let e = PolicyEngine::new(p, None);
    let tasks: Vec<_> = (0..40)
        .map(|i| {
            let e = e.clone();
            tokio::spawn(async move { decide(&mut e.consent(Some(peer(&format!("p{i}"))), None), 10).await })
        })
        .collect();
    let mut ok = 0;
    for t in tasks {
        if t.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, 5);
    assert_eq!(e.reserved_bytes(), 50);
}

/// Disk space is reserved like quota (StorageFailed when it wouldn't fit).
#[tokio::test]
async fn disk_reservation() {
    let mut p = ReceivePolicy::headless();
    p.peers.extend([auto("a", None)]);
    let e = PolicyEngine::new(p, Some(Arc::new(|| Some(15))));
    assert!(decide(&mut e.consent(Some(peer("a")), None), 10).await.is_ok());
    assert_eq!(decide(&mut e.consent(Some(peer("a")), None), 10).await, Err(K::StorageFailed));
}

/// AUTH-022 / PERF-006 / PERF-008 / ST-007: per-peer concurrency, offer rate and
/// pending-offer caps; repeated refusals cool a peer off.
#[tokio::test]
async fn rate_concurrency_and_pending_limits() {
    let mut p = ReceivePolicy::headless();
    p.max_concurrent_per_peer = 2;
    p.peers.extend([auto("a", None)]);
    let e = PolicyEngine::new(p, None);
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut c = e.consent(Some(peer("a")), None);
        assert!(decide(&mut c, 1).await.is_ok());
        held.push(c);
    }
    assert_eq!(decide(&mut e.consent(Some(peer("a")), None), 1).await, Err(K::LimitExceeded));
    held.pop().unwrap().finished(&Outcome::Completed).await;
    assert!(decide(&mut e.consent(Some(peer("a")), None), 1).await.is_ok(), "slot freed");

    let mut p = ReceivePolicy::headless();
    p.offers_per_minute = 3;
    p.max_failures = 100;
    let e = PolicyEngine::new(p, None);
    for _ in 0..3 {
        assert_eq!(decide(&mut e.consent(Some(peer("f")), None), 1).await, Err(K::Unauthorized));
    }
    assert_eq!(decide(&mut e.consent(Some(peer("f")), None), 1).await, Err(K::LimitExceeded), "flood");

    let mut p = ReceivePolicy::headless();
    p.max_failures = 2;
    p.peers.extend([auto("g", Some(1))]);
    let e = PolicyEngine::new(p, None);
    for _ in 0..2 {
        assert!(decide(&mut e.consent(Some(peer("g")), None), 5).await.is_err());
    }
    assert_eq!(decide(&mut e.consent(Some(peer("g")), None), 1).await, Err(K::LimitExceeded), "cooled off");

    // Pending prompts are capped.
    struct Never;
    #[async_trait]
    impl Prompt for Never {
        async fn ask(&mut self, _: &VerifiedPeer, _: &OfferInfo<'_>) -> bool {
            std::future::pending().await
        }
    }
    let mut p = ReceivePolicy::interactive();
    p.max_pending_offers = 2;
    p.max_concurrent_per_peer = 10;
    let e = PolicyEngine::new(p, None);
    let waiting: Vec<_> = (0..2)
        .map(|_| {
            let e = e.clone();
            tokio::spawn(async move { decide(&mut e.consent(Some(peer("q")), Some(Box::new(Never))), 1).await })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(decide(&mut e.consent(Some(peer("q")), Some(Box::new(Never))), 1).await, Err(K::LimitExceeded));
    waiting.iter().for_each(|w| w.abort());
}

/// AUTH-018 / AUTH-016: the sender's own policy; a sender-side yes never
/// stands in for the receiver.
#[tokio::test(flavor = "multi_thread")]
async fn sender_policy_and_receiver_independence() {
    let s = summary(10, 10);
    assert_eq!(SendPolicy { enabled: false, ..SendPolicy::default() }.check(Some(&peer("t")), &s), Err(K::Unauthorized));
    let only_b = SendPolicy { allowed_peers: Some(vec!["b".into()]), ..SendPolicy::default() };
    assert_eq!(only_b.check(Some(&peer("t")), &s), Err(K::Unauthorized));
    assert!(only_b.check(Some(&peer("b")), &s).is_ok());
    assert_eq!(SendPolicy::default().check(None, &s), Err(K::Unauthorized));

    // Sender approved locally; headless receiver with no rule still refuses.
    let files = MemFiles::default();
    files.insert(&["x"], vec![1; 10]);
    let m = build(ManifestKind::Files, vec![Selected::file(&["x"], 10)], &Limits::default()).unwrap();
    let e = PolicyEngine::new(ReceivePolicy::headless(), None);
    let sink = MemSink::default();
    let r = run_with(m, files, sink.clone(), e.consent(Some(peer("sender")), None), Opts::default()).await;
    assert_eq!(r.sender, Outcome::Rejected(K::Unauthorized));
    assert!(sink.visible().is_empty());
}

// ---- Authorization lease and revocation --------------------------------------

/// AUTH-029: a lease never outlives the peer's certificate chain.
#[test]
fn lease_is_capped_by_certificate() {
    let e = PolicyEngine::new(ReceivePolicy::headless(), None);
    let soon = VerifiedPeer { not_after: now() + 60, ..peer("a") };
    assert!(e.lease_until(&soon) <= now() + 60);
    let later = VerifiedPeer { not_after: i64::MAX, ..peer("a") };
    let until = e.lease_until(&later);
    assert!(until <= now() + 15 * 60 && until > now() + 14 * 60);
}

/// AUTH-024 / AUTH-025 / AUTH-026 / EVT-008: the watcher warns, renews when it
/// can, and expires the transfer when it can't.
#[tokio::test(start_paused = true)]
async fn lease_watch_renews_then_expires() {
    let (cmd_tx, mut cmd_rx) = mpsc::channel(4);
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    let start = tokio::time::Instant::now();
    let renewals = Arc::new(AtomicU32::new(0));
    let r = renewals.clone();
    tokio::spawn(lease_watch(
        start + Duration::from_secs(900),
        Duration::from_secs(60),
        move || {
            let n = r.fetch_add(1, Ordering::SeqCst);
            async move { (n == 0).then(|| start + Duration::from_secs(1800)) }
        },
        cmd_tx,
        ev_tx,
    ));
    let cmd = cmd_rx.recv().await;
    assert_eq!(cmd, Some(Command::AuthExpired));
    assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(1800), "renewed once");
    assert_eq!(renewals.load(Ordering::SeqCst), 2);
    let warnings = std::iter::from_fn(|| ev_rx.try_recv().ok())
        .filter(|e| matches!(e, TransferEvent::LeaseExpiring { .. }))
        .count();
    assert_eq!(warnings, 2);
}

/// AUTH-023 / AUTH-026 / AUTH-027 / AUTH-028: lease expiry and revocation stop
/// both sides without user involvement and keep verified data, checkpointed at
/// the exact offset reached; a later attempt needs fresh authorization.
#[tokio::test(flavor = "multi_thread")]
async fn expiry_and_revocation_stop_and_keep_data() {
    for (cmd, code) in [(Command::AuthExpired, K::AuthorizationExpired), (Command::Revoked, K::Unauthorized)] {
        let files = MemFiles::default();
        files.insert(&["big"], vec![7; 3_000_000]);
        let m = build(ManifestKind::Files, vec![Selected::file(&["big"], 3_000_000)], &Limits::default()).unwrap();
        let id = new_transfer_id();
        let sink = MemSink::default();
        let r = run(m.clone(), files.clone(), sink.clone(), Opts {
            id: Some(id),
            // Paused by the sender, so a transfer is certainly in flight.
            sender_cmds: vec![(Duration::from_millis(1), Command::Pause)],
            receiver_cmds: vec![(Duration::from_millis(30), cmd)],
            ..Opts::default()
        })
        .await;
        assert_eq!((r.sender.clone(), r.receiver.clone()), (Outcome::Interrupted(code), Outcome::Interrupted(code)), "{cmd:?}");
        assert!(sink.holds(&id), "verified data dropped on {cmd:?}");
        let kept = sink.partial_len(&id, 0);
        assert!(kept > 0);

        // Re-authorization refused (revoked / lease not renewed): nothing resumes.
        let e = PolicyEngine::new(ReceivePolicy::headless(), None);
        let denied = run_with(m.clone(), files.clone(), sink.reopen(), e.consent(Some(peer("x")), None), Opts {
            id: Some(id),
            resume: true,
            ..Opts::default()
        })
        .await;
        assert_eq!(denied.sender, Outcome::Rejected(K::Unauthorized));
        assert!(sink.holds(&id));

        // Fresh authorization: resumes from the flushed checkpoint, nothing lost.
        let resumed = run(m, files, sink.reopen(), Opts { id: Some(id), resume: true, ..Opts::default() }).await;
        assert_eq!(resumed.receiver, Outcome::Completed);
    }
}

async fn run(
    m: idr_protocol::transfer::Manifest,
    files: MemFiles,
    sink: MemSink,
    opts: Opts,
) -> Run {
    run_with(m, files, sink, idr_transfer::mem::AcceptAll(Approval::User), opts).await
}

//! Runs the peer-binding exchange ([`idr_protocol::peer_bind`]) on a stream.
//!
//! Both peers run [`bind_peer`] symmetrically. The result is the only source of
//! peer identity for transfer policy: names, emails or ids inside transfer
//! messages are never used. Without a successful binding a peer is unverified,
//! and [`crate::policy`] refuses every transfer with it, in both directions.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use idr_protocol::peer_bind::{
    self, BindContext, BindError, BindMsg, BindRole, TrustPolicy, VerifiedPeer,
};
use idr_protocol::transfer::{new_transfer_id, TransferErrorKind};

use crate::io::Framed;

pub const BIND_VERSION: u16 = 1;

/// This device's DP identity: signing key and certificate chain (leaf first).
pub struct LocalIdentity {
    pub key: SigningKey,
    pub ski: String,
    pub chain_pem: String,
}

impl LocalIdentity {
    /// From a DP identity: the Ed25519 private JWK's `d` (base64url), its SKI
    /// and certificate chain (leaf first). None if `d` isn't an Ed25519 seed.
    pub fn from_jwk(d: &str, ski: &str, chain_pem: &str) -> Option<Self> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let seed: [u8; 32] = URL_SAFE_NO_PAD.decode(d).ok()?.try_into().ok()?;
        Some(Self {
            key: SigningKey::from_bytes(&seed),
            ski: ski.to_string(),
            chain_pem: chain_pem.to_string(),
        })
    }
}

/// Entity roots (DER) a peer must chain to: the configured root PEM, else the
/// self-signed root at the end of this device's own chain (root-issued devices).
pub fn entity_roots(configured_pem: Option<&str>, chain_pem: &str) -> Option<Vec<Vec<u8>>> {
    match configured_pem {
        Some(pem) => peer_bind::pem_certs(pem),
        None => peer_bind::root_of_chain(chain_pem).map(|r| vec![r]),
    }
}

fn nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    n[..16].copy_from_slice(&new_transfer_id());
    n[16..].copy_from_slice(&new_transfer_id());
    n
}

fn refusal(e: BindError) -> TransferErrorKind {
    tracing::warn!(reason = ?e, "peer binding refused");
    match e {
        BindError::Expired => TransferErrorKind::AuthorizationExpired,
        _ => TransferErrorKind::Unauthorized,
    }
}

/// Prove this device to the peer and verify the peer, both bound to `ctx`.
pub async fn bind_peer(
    stream: &mut Framed,
    role: BindRole,
    ctx: &BindContext,
    me: &LocalIdentity,
    trust: &TrustPolicy,
    timeout: Duration,
) -> Result<VerifiedPeer, TransferErrorKind> {
    // Without both DTLS fingerprints the proof wouldn't be tied to this connection.
    if ctx.offerer_fingerprint.is_empty() || ctx.answerer_fingerprint.is_empty() {
        return Err(TransferErrorKind::Unauthorized);
    }
    let run = async {
        let mine = nonce();
        stream
            .send(&BindMsg::Hello {
                version: BIND_VERSION,
                nonce: mine,
            })
            .await?;
        let theirs = match stream.next::<BindMsg>(4096).await? {
            Some(BindMsg::Hello { version, nonce }) if version == BIND_VERSION => nonce,
            Some(BindMsg::Hello { .. }) => return Err(TransferErrorKind::IncompatibleVersion),
            _ => return Err(TransferErrorKind::ProtocolViolation),
        };
        let (offerer, answerer) = match role {
            BindRole::Offerer => (mine, theirs),
            BindRole::Answerer => (theirs, mine),
        };
        let signature = peer_bind::sign(
            &me.key,
            &peer_bind::transcript(ctx, role, &offerer, &answerer),
        );
        stream
            .send(&BindMsg::Proof {
                ski: me.ski.clone(),
                chain_pem: me.chain_pem.clone(),
                signature,
            })
            .await?;
        let Some(BindMsg::Proof {
            ski,
            chain_pem,
            signature,
        }) = stream.next::<BindMsg>(64 * 1024).await?
        else {
            return Err(TransferErrorKind::ProtocolViolation);
        };
        let expected = peer_bind::transcript(ctx, role.peer(), &offerer, &answerer);
        let mut peer = peer_bind::verify(role.peer(), &ski, &chain_pem, &signature, &expected, trust)
            .map_err(refusal)?;
        peer.path = ctx.path;
        Ok(peer)
    };
    tokio::time::timeout(timeout, run)
        .await
        .map_err(|_| TransferErrorKind::Timeout)?
}

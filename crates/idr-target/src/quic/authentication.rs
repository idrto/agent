use idr_protocol::quic_control::{ClientHello, QuicControlMessage};
use idr_protocol::PROTOCOL_VERSION;
use crate::relay::descriptor::ConnectionAuthorization;
use crate::relay::descriptor::StableRelayDescriptor;
use uuid::Uuid;

pub fn build_client_hello(
    descriptor: &StableRelayDescriptor,
    auth: &ConnectionAuthorization,
    target_identity: &str,
) -> QuicControlMessage {
    QuicControlMessage::ClientHello(ClientHello {
        protocol_version: PROTOCOL_VERSION,
        message_id: Uuid::new_v4(),
        session_id: auth.session_id,
        target_fqhn: auth.target_fqhn.clone(),
        target_identity: target_identity.to_string(),
        connection_token: auth.connection_token.clone(),
        connection_epoch: auth.connection_epoch,
        relay_id: descriptor.relay_id.clone(),
    })
}

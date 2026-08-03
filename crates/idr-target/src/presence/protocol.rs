use idr_protocol::signaling::{CommandResultCode, EnsureRelayConnectionAck, SignalingMessageType};
use uuid::Uuid;

pub fn ensure_relay_ack(
    command_id: Uuid,
    session_id: Uuid,
    result: CommandResultCode,
    detail: Option<String>,
) -> EnsureRelayConnectionAck {
    EnsureRelayConnectionAck {
        version: idr_protocol::PROTOCOL_VERSION,
        message_type: SignalingMessageType::EnsureRelayConnectionAck,
        message_id: Uuid::new_v4(),
        command_id,
        session_id,
        result,
        detail,
        selected_target_identity: None,
    }
}

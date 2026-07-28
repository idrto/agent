use idr_target::protocol::signaling::{
    CommandResultCode, EnsureRelayConnectionCommand, EnsureRelayConnectionUnsigned, RelayDescriptor,
    SignalingMessageType,
};
use idr_target::protocol::PROTOCOL_VERSION;
use idr_target::presence::dedup::{CachedCommandResult, CommandDedup, DedupAction};
use idr_target::storage::{Storage, StorageWriter};
use idr_target::telemetry::Metrics;
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use uuid::Uuid;

fn sample_command(signing: &SigningKey, command_id: Uuid) -> EnsureRelayConnectionCommand {
    let unsigned = EnsureRelayConnectionUnsigned {
        version: PROTOCOL_VERSION,
        message_type: SignalingMessageType::EnsureRelayConnection,
        message_id: Uuid::new_v4(),
        command_id,
        session_id: Uuid::new_v4(),
        target_fqhn: "device-01.example.idr.to".into(),
        relay: RelayDescriptor {
            relay_id: "relay-a".into(),
            ipv4: Some("127.0.0.1".into()),
            ipv6: None,
            port: 4433,
            server_name: "relay-a.idr.to".into(),
            alpn: "idr-relay-v1".into(),
            region: None,
        },
        connection_token: "token".into(),
        connection_epoch: 1,
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::minutes(5),
        presence_generation: 1,
        using_party: None,
        paying_party: None,
        signature: String::new(),
    };
    EnsureRelayConnectionCommand::sign(unsigned, signing).unwrap()
}

#[tokio::test]
async fn duplicate_command_id_deduplicates() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("dedup.db");
    let storage = Storage::open(&idr_target::config::SqliteConfig {
        path: db,
        cache_kib: 512,
        wal_autocheckpoint_pages: 256,
        journal_size_limit_bytes: 1_048_576,
    })
    .unwrap();
    let writer = StorageWriter::spawn(storage.clone(), Metrics::new());
    let dedup = CommandDedup::new(
        std::time::Duration::from_secs(300),
        1000,
        storage,
        writer,
    );

    let signing = SigningKey::generate(&mut rand::rngs::OsRng);
    let cmd_id = Uuid::new_v4();
    let cmd = sample_command(&signing, cmd_id);

    let first = dedup.check_or_register(&cmd).await.unwrap();
    let second = dedup.check_or_register(&cmd).await.unwrap();

    match (first, second) {
        (DedupAction::Process(_), DedupAction::Wait(_)) => {}
        _ => panic!("expected process then wait"),
    }

    dedup
        .complete(
            cmd_id,
            idr_target::protocol::crypto::content_digest(
                &serde_json::to_value(&cmd).unwrap(),
            ),
            CachedCommandResult {
                result: CommandResultCode::Active,
                detail: None,
            },
        )
        .await;

    let third = dedup.check_or_register(&cmd).await.unwrap();
    assert!(matches!(third, DedupAction::Cached(_)));
}

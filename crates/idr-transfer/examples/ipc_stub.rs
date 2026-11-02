//! A stand-in agent for client tests (the Dart SDK's IPC client): serves canned
//! answers through the real `ipc::serve` (same pipe/socket, DACL, framing),
//! under the agent name given as the first argument, until killed.
//!
//! `cargo run -p idr-transfer --features native --example ipc_stub -- <agent> <dir>`

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use idr_transfer::native::ipc::{serve, Handler, IpcAddr, Request, Response};

struct Stub(AtomicU64);

#[async_trait]
impl Handler for Stub {
    async fn handle(&self, req: Request) -> Response {
        let n = self.0.fetch_add(1, Ordering::Relaxed) + 1;
        match req {
            Request::List => Response::ok(serde_json::json!([{
                "id": "00112233445566778899aabbccddeeff", "direction": "incoming", "peer": "src-ski",
                "state": "pending", "path": "host", "relayed": false, "connection": "direct",
                "summary": { "files": 1, "dirs": 0, "total_bytes": 5, "top_level": ["a.txt"], "more_top_level": 0 },
                "progress": { "bytes_done": 0, "bytes_total": 5, "files_done": 0, "files_total": 1, "files_failed": 0, "bytes_per_sec": 0 },
                "served": n,
            }])),
            Request::Peers => Response::ok(serde_json::json!([{ "peer": "src-ski", "path": "turn", "connection": "relayed" }])),
            Request::Accept { out: Some(out), .. } => Response::ok(serde_json::json!({ "out": out })),
            Request::Reject { .. } => Response::err("rejected"),
            Request::Send { target, paths } => Response::ok(serde_json::json!({
                "id": "ffeeddccbbaa99887766554433221100", "direction": "outgoing", "peer": target, "state": "queued",
                "path": null, "relayed": null, "connection": "unknown", "sent_paths": paths,
                "summary": { "files": paths.len(), "dirs": 0, "total_bytes": 0, "top_level": [], "more_top_level": 0 },
                "progress": { "bytes_done": 0, "bytes_total": 0, "files_done": 0, "files_total": paths.len(), "files_failed": 0, "bytes_per_sec": 0 },
            })),
            _ => Response::ok(serde_json::Value::Null),
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let agent = args.next().expect("agent name");
    let dir = PathBuf::from(args.next().expect("data dir"));
    let addr = IpcAddr::for_agent(&agent, &dir)?;
    let (_stop, rx) = tokio::sync::watch::channel(false);
    println!("listening {}", addr.0);
    serve(addr, Arc::new(Stub(AtomicU64::new(0))), rx).await
}

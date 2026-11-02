//! What both agents' `transfer` commands do: queue paths, and serve the CLI's
//! IPC requests against a [`Manager`]. Shared so Source and Target expose the
//! same commands, states and error codes.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use idr_protocol::transfer::{new_transfer_id, ManifestKind, TransferErrorKind, TransferId};

use super::ipc::{Handler, Request, Response};
use super::manager::{info_json, parse_id, FilesSpec, Manager};
use super::{enumerate, NativeFiles};
use crate::manifest::build;
use crate::Limits;

/// Why paths can't be sent.
#[derive(Debug)]
pub struct QueueError(pub String);

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for QueueError {}

/// Queue `paths` for `peer`: one directory (sent as a folder, links and special
/// files left out) or one or more files (sent as loose files).
pub fn queue_paths(manager: &Arc<Manager>, peer: &str, paths: &[PathBuf]) -> Result<TransferId, QueueError> {
    let err = |m: &str| QueueError(m.to_string());
    let (manifest, spec) = match paths {
        [dir] if dir.is_dir() => {
            let name = dir
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| err("folder name is not valid UTF-8"))?
                .to_string();
            let parent = dir.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
            let root = cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())
                .map_err(|e| QueueError(e.to_string()))?;
            let found = enumerate(&root, &[vec![name]]).map_err(|e| QueueError(e.to_string()))?;
            if found.skipped > 0 {
                tracing::info!(skipped = found.skipped, "links and special files left out");
            }
            let m = build(ManifestKind::Folder, found.selected, &Limits::default())
                .map_err(|k| QueueError(format!("folder can't be sent: {}", k.as_str())))?;
            (m, FilesSpec::Root(parent.to_path_buf()))
        }
        files if !files.is_empty() && files.iter().all(|p| p.is_file()) => {
            let (_, selected) = NativeFiles::loose(files).map_err(|e| QueueError(e.to_string()))?;
            let m = build(ManifestKind::Files, selected, &Limits::default())
                .map_err(|k| QueueError(format!("files can't be sent: {}", k.as_str())))?;
            (m, FilesSpec::Loose(files.to_vec()))
        }
        _ => return Err(err("send one folder, or one or more files")),
    };
    Ok(manager.send(peer, new_transfer_id(), manifest, spec))
}

/// Queue a selection inside `folder` for `peer`: `selected` are paths relative
/// to `folder` (`/`-separated). Sent as that folder holding only the selection.
pub fn queue_selection(manager: &Arc<Manager>, peer: &str, folder: &Path, selected: &[String]) -> Result<TransferId, QueueError> {
    let err = |m: &str| QueueError(m.to_string());
    let name = folder
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| err("folder name is not valid UTF-8"))?
        .to_string();
    let mut selections = Vec::with_capacity(selected.len());
    for rel in selected {
        let parts: Vec<String> = rel.split('/').map(str::to_string).collect();
        if parts.iter().any(|p| p.is_empty() || p == "." || p == ".." || p.contains('\\')) {
            return Err(err("selection paths must be relative, without . or .."));
        }
        selections.push(std::iter::once(name.clone()).chain(parts).collect::<Vec<_>>());
    }
    if selections.is_empty() {
        return Err(err("empty selection"));
    }
    let parent = folder.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let root = cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority()).map_err(|e| QueueError(e.to_string()))?;
    let found = enumerate(&root, &selections).map_err(|e| QueueError(e.to_string()))?;
    let m = build(ManifestKind::Folder, found.selected, &Limits::default())
        .map_err(|k| QueueError(format!("selection can't be sent: {}", k.as_str())))?;
    Ok(manager.send(peer, new_transfer_id(), m, FilesSpec::Root(parent.to_path_buf())))
}

/// Serves the `transfer` CLI over IPC.
pub struct Control {
    pub manager: Arc<Manager>,
    /// Directories `accept --out` may choose.
    pub permitted: Vec<PathBuf>,
}

fn done(r: Result<(), TransferErrorKind>) -> Response {
    match r {
        Ok(()) => Response::ok(serde_json::Value::Null),
        Err(k) => Response::err(k.as_str()),
    }
}

#[async_trait]
impl Handler for Control {
    async fn handle(&self, req: Request) -> Response {
        let m = &self.manager;
        let Some(id) = (match &req {
            Request::Send { .. } | Request::List | Request::Peers => Some([0; 16]),
            Request::Status { id }
            | Request::Pause { id }
            | Request::Resume { id }
            | Request::Cancel { id }
            | Request::RetryFailed { id }
            | Request::Accept { id, .. }
            | Request::Reject { id } => parse_id(id),
        }) else {
            return Response::err("invalid_argument");
        };
        match req {
            Request::Send { target, paths } => match queue_paths(m, &target, &paths) {
                Ok(t) => Response::ok(info_json(&m.status(&t).unwrap())),
                Err(e) => {
                    tracing::warn!(error = %e, "transfer send refused");
                    Response::err("invalid_argument")
                }
            },
            Request::List => Response::ok(m.list().iter().map(info_json).collect()),
            Request::Peers => Response::ok(
                m.peers()
                    .into_iter()
                    .map(|(peer, path)| {
                        serde_json::json!({
                            "peer": peer,
                            "path": path.map(|p| p.as_str()),
                            "connection": idr_protocol::webrtc_ice::IcePath::connection(path),
                        })
                    })
                    .collect(),
            ),
            Request::Status { .. } => match m.status(&id) {
                Some(i) => Response::ok(info_json(&i)),
                None => Response::err("not_found"),
            },
            Request::Pause { .. } => done(m.pause(&id).await),
            Request::Resume { .. } => done(m.resume(&id).await),
            Request::Cancel { .. } => done(m.cancel(&id).await),
            Request::RetryFailed { .. } => done(m.retry(&id)),
            Request::Accept { out, .. } => done(m.accept(&id, out, &self.permitted)),
            Request::Reject { .. } => done(m.reject(&id)),
        }
    }
}

/// Run one `transfer` CLI command against the agent at `addr`. Returns false
/// when the agent refused it (the caller exits non-zero).
pub async fn run_cli(addr: &super::ipc::IpcAddr, agent: &str, req: Request, json: bool) -> Result<bool, String> {
    let resp = match super::ipc::call(addr, &req).await {
        Ok(r) => r,
        Err(super::ipc::CallError::Unavailable) => {
            return Err(format!("{agent} is not running (start it with `{agent} run`)"))
        }
        Err(super::ipc::CallError::Io(e)) => return Err(e.to_string()),
    };
    let peers = matches!(req, Request::Peers);
    if json {
        println!("{}", serde_json::to_string_pretty(&resp).unwrap_or_default());
    } else if resp.ok && peers {
        print_peers(&resp.data);
    } else if resp.ok {
        print_transfers(&resp.data);
    } else {
        eprintln!("refused: {}", resp.error.as_deref().unwrap_or("unknown"));
    }
    Ok(resp.ok)
}

/// One line per connected peer.
pub fn print_peers(data: &serde_json::Value) {
    match data.as_array() {
        Some(v) if !v.is_empty() => {
            for p in v {
                println!("{}  {}", p["peer"].as_str().unwrap_or(""), p["connection"].as_str().unwrap_or("unknown"));
            }
        }
        _ => println!("no connected peers"),
    }
}

/// One line per transfer, as both CLIs print them.
pub fn print_transfers(data: &serde_json::Value) {
    let one = |t: &serde_json::Value| {
        let p = &t["progress"];
        let failed = match p["files_failed"].as_u64() {
            Some(n) if n > 0 => format!(", {n} failed"),
            _ => String::new(),
        };
        println!(
            "{}  {:<8} {:<22} {}  {}/{} bytes  {}/{} files{failed}",
            t["id"].as_str().unwrap_or(""),
            t["direction"].as_str().unwrap_or(""),
            t["state"].as_str().unwrap_or(""),
            t["peer"].as_str().unwrap_or(""),
            p["bytes_done"],
            p["bytes_total"],
            p["files_done"],
            p["files_total"],
        );
    };
    match data {
        serde_json::Value::Array(v) if v.is_empty() => println!("no transfers"),
        serde_json::Value::Array(v) => v.iter().for_each(one),
        serde_json::Value::Null => println!("ok"),
        t => one(t),
    }
}

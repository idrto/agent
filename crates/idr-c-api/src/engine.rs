//! In-process Source engine behind opaque C handles.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_core::session::PeerSession;
use idr_core::stream::LogicalStream;
use idr_protocol::webrtc_signaling::SourceAuthMode;
use idr_source::{SourceRuntime, SourceSession};
use parking_lot::Mutex;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use crate::error::set_last_error;
use crate::mock_backend;

pub const ABI_VERSION: u32 = 2;

/// Auth mode codes for `idr_engine_config_t.auth_mode`.
pub const IDR_AUTH_BEARER: u32 = 0;
pub const IDR_AUTH_DEVICE_TOKEN: u32 = 1;
pub const IDR_AUTH_MTLS: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EngineConfig {
    pub abi_version: u32,
    pub struct_size: u32,
    /// 1 = in-process mock (unit/FFI tests only). 0 = native libdatachannel.
    pub use_mock: u32,
    pub source_id: *const std::os::raw::c_char,
    pub source_region: *const std::os::raw::c_char,
    /// Required for product connect (bearer / device token).
    pub auth_token: *const std::os::raw::c_char,
    /// See `IDR_AUTH_*`.
    pub auth_mode: u32,
    /// Discovery URL for native mode (e.g. well-known or local presence JSON).
    pub discovery_url: *const std::os::raw::c_char,
    pub discovery_key: *const std::os::raw::c_char,
    pub insecure_dev: u32,
}

impl EngineConfig {
    pub fn validate(&self) -> Result<()> {
        if self.abi_version != ABI_VERSION {
            return Err(IdrError::new(
                IdrErrorKind::IncompatibleVersion,
                format!("abi_version {} != {ABI_VERSION}", self.abi_version),
            ));
        }
        if (self.struct_size as usize) < std::mem::size_of::<EngineConfig>() {
            return Err(IdrError::new(
                IdrErrorKind::InvalidArgument,
                "struct_size too small",
            ));
        }
        Ok(())
    }
}

fn map_auth_mode(code: u32) -> Result<SourceAuthMode> {
    match code {
        IDR_AUTH_BEARER => Ok(SourceAuthMode::Bearer),
        IDR_AUTH_DEVICE_TOKEN => Ok(SourceAuthMode::DeviceToken),
        IDR_AUTH_MTLS => Ok(SourceAuthMode::Mtls),
        _ => Err(IdrError::new(
            IdrErrorKind::InvalidArgument,
            format!("unknown auth_mode {code}"),
        )),
    }
}

#[derive(Debug, Clone)]
pub enum EngineEvent {
    Connected { session_id: u64 },
    StreamOpened { session_id: u64, stream_id: u64 },
    BytesAvailable { stream_id: u64, len: usize },
    StreamClosed { stream_id: u64 },
    Error { code: u32, message: String },
}

struct SessionSlot {
    session: SourceSession,
    streams: HashMap<u64, Box<dyn LogicalStream>>,
}

pub struct Engine {
    rt: Runtime,
    runtime: Mutex<SourceRuntime>,
    sessions: Mutex<HashMap<u64, SessionSlot>>,
    next_session: AtomicU64,
    next_stream_handle: AtomicU64,
    event_tx: mpsc::Sender<EngineEvent>,
    event_rx: Mutex<mpsc::Receiver<EngineEvent>>,
}

impl Engine {
    pub fn new(cfg: &EngineConfig) -> Result<Self> {
        cfg.validate()?;
        let source_id = cstr(cfg.source_id).unwrap_or_else(|| "dart-embedded".into());
        let region = cstr(cfg.source_region).unwrap_or_else(|| "unknown".into());
        let auth_token = cstr(cfg.auth_token).unwrap_or_default();
        let auth_mode = map_auth_mode(cfg.auth_mode)?;

        if auth_token.is_empty() {
            return Err(IdrError::new(
                IdrErrorKind::AuthenticationFailed,
                "auth_token is required",
            ));
        }

        let rt = Runtime::new().map_err(|e| {
            IdrError::new(IdrErrorKind::InternalError, format!("tokio runtime: {e}"))
        })?;

        let runtime = if cfg.use_mock != 0 {
            mock_backend::mock_runtime(&source_id, &region, auth_mode, &auth_token)
        } else {
            #[cfg(feature = "native")]
            {
                let discovery_url = cstr(cfg.discovery_url).ok_or_else(|| {
                    IdrError::new(
                        IdrErrorKind::InvalidArgument,
                        "discovery_url required for native mode",
                    )
                })?;
                let discovery_key = cstr(cfg.discovery_key).unwrap_or_default();
                rt.block_on(crate::native_backend::native_runtime(
                    crate::native_backend::NativeBackendConfig {
                        source_id: source_id.clone(),
                        source_region: region.clone(),
                        auth_mode,
                        auth_token: auth_token.clone(),
                        discovery_url,
                        discovery_key_b64: discovery_key,
                        insecure_dev: cfg.insecure_dev != 0,
                    },
                ))?
            }
            #[cfg(not(feature = "native"))]
            {
                return Err(IdrError::new(
                    IdrErrorKind::NotInitialized,
                    "native WebRTC backend not linked; build with --features native (libdatachannel)",
                ));
            }
        };

        let (event_tx, event_rx) = mpsc::channel(256);
        Ok(Self {
            rt,
            runtime: Mutex::new(runtime),
            sessions: Mutex::new(HashMap::new()),
            next_session: AtomicU64::new(1),
            next_stream_handle: AtomicU64::new(1),
            event_tx,
            event_rx: Mutex::new(event_rx),
        })
    }

    pub fn connect(&self, target_fqhn: &str) -> Result<u64> {
        let mut runtime = self.runtime.lock();
        let session = match self.rt.block_on(runtime.connect(target_fqhn)) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&e);
                return Err(e);
            }
        };
        let id = self.next_session.fetch_add(1, Ordering::Relaxed);
        self.sessions.lock().insert(
            id,
            SessionSlot {
                session,
                streams: HashMap::new(),
            },
        );
        let _ = self
            .event_tx
            .try_send(EngineEvent::Connected { session_id: id });
        Ok(id)
    }

    pub fn disconnect(&self, session_id: u64) -> Result<()> {
        let mut sessions = self.sessions.lock();
        let Some(mut slot) = sessions.remove(&session_id) else {
            return Err(IdrError::new(
                IdrErrorKind::InvalidArgument,
                "unknown session",
            ));
        };
        self.rt.block_on(slot.session.close())?;
        Ok(())
    }

    pub fn open_stream(&self, session_id: u64, service: &str) -> Result<u64> {
        let mut sessions = self.sessions.lock();
        let slot = sessions
            .get_mut(&session_id)
            .ok_or_else(|| IdrError::new(IdrErrorKind::InvalidArgument, "unknown session"))?;
        let stream = self.rt.block_on(slot.session.open_named_stream(service))?;
        let handle = self.next_stream_handle.fetch_add(1, Ordering::Relaxed);
        slot.streams.insert(handle, stream);
        let _ = self.event_tx.try_send(EngineEvent::StreamOpened {
            session_id,
            stream_id: handle,
        });
        Ok(handle)
    }

    /// JSON array of Target named services (always refreshes over the mux).
    pub fn named_services_json(&self, session_id: u64) -> Result<String> {
        let mut sessions = self.sessions.lock();
        let slot = sessions
            .get_mut(&session_id)
            .ok_or_else(|| IdrError::new(IdrErrorKind::InvalidArgument, "unknown session"))?;
        if let Err(e) = self.rt.block_on(slot.session.refresh_named_services()) {
            // Keep last catalog if refresh fails (Target offline mid-session).
            if slot.session.named_services().is_empty() {
                return Err(e);
            }
            tracing::warn!(error = %e, "services catalog refresh failed; using cached list");
        }
        let mut out = String::from('[');
        for (i, name) in slot.session.named_services().iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('"');
            for ch in name.chars() {
                match ch {
                    '"' | '\\' => {
                        out.push('\\');
                        out.push(ch);
                    }
                    c if c.is_control() => {}
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        out.push(']');
        Ok(out)
    }

    /// JSON array of structured catalog entries (credential_mode, require_upstream_tls, …).
    pub fn named_service_catalog_json(&self, session_id: u64) -> Result<String> {
        let mut sessions = self.sessions.lock();
        let slot = sessions
            .get_mut(&session_id)
            .ok_or_else(|| IdrError::new(IdrErrorKind::InvalidArgument, "unknown session"))?;
        if let Err(e) = self.rt.block_on(slot.session.refresh_named_services()) {
            if slot.session.catalog_entries().is_empty()
                && slot.session.named_services().is_empty()
            {
                return Err(e);
            }
            tracing::warn!(error = %e, "services catalog refresh failed; using cached detailed list");
        }
        let entries = slot.session.catalog_entries();
        if entries.is_empty() {
            let synthesized: Vec<_> = slot
                .session
                .named_services()
                .iter()
                .map(|n| idr_protocol::stream_mux::ServiceCatalogEntry::name_only(n.clone()))
                .collect();
            return Ok(catalog_entries_to_json(&synthesized));
        }
        Ok(catalog_entries_to_json(entries))
    }

    pub fn stream_write(&self, session_id: u64, stream_id: u64, buf: &[u8]) -> Result<usize> {
        let mut sessions = self.sessions.lock();
        let slot = sessions
            .get_mut(&session_id)
            .ok_or_else(|| IdrError::new(IdrErrorKind::InvalidArgument, "unknown session"))?;
        let stream = slot
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| IdrError::new(IdrErrorKind::InvalidArgument, "unknown stream"))?;
        self.rt.block_on(stream.write(buf))
    }

    pub fn stream_read(&self, session_id: u64, stream_id: u64, buf: &mut [u8]) -> Result<usize> {
        let mut sessions = self.sessions.lock();
        let slot = sessions
            .get_mut(&session_id)
            .ok_or_else(|| IdrError::new(IdrErrorKind::InvalidArgument, "unknown session"))?;

        // Pump inbound DC frames into stream inboxes before blocking on read.
        // `timeout` must be created inside `block_on` (needs the Tokio reactor).
        for _ in 0..64 {
            match self.rt.block_on(async {
                tokio::time::timeout(Duration::from_millis(25), slot.session.pump_once()).await
            }) {
                Ok(Ok(())) => {}
                Ok(Err(_)) => break,
                Err(_) => break, // no peer event this slice
            }
        }

        let stream = slot
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| IdrError::new(IdrErrorKind::InvalidArgument, "unknown stream"))?;
        // Wait long enough for Target→Ollama→response to arrive on the DC.
        let n = self.rt.block_on(async {
            match tokio::time::timeout(Duration::from_secs(2), stream.read(buf)).await {
                Ok(r) => r,
                Err(_) => Ok(0),
            }
        })?;
        if n > 0 {
            let _ = self
                .event_tx
                .try_send(EngineEvent::BytesAvailable { stream_id, len: n });
        }
        Ok(n)
    }

    pub fn stream_half_close(&self, session_id: u64, stream_id: u64) -> Result<()> {
        let mut sessions = self.sessions.lock();
        let slot = sessions
            .get_mut(&session_id)
            .ok_or_else(|| IdrError::new(IdrErrorKind::InvalidArgument, "unknown session"))?;
        let stream = slot
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| IdrError::new(IdrErrorKind::InvalidArgument, "unknown stream"))?;
        self.rt.block_on(stream.half_close())
    }

    pub fn stream_reset(&self, session_id: u64, stream_id: u64, reason: u16) -> Result<()> {
        let mut sessions = self.sessions.lock();
        let slot = sessions
            .get_mut(&session_id)
            .ok_or_else(|| IdrError::new(IdrErrorKind::InvalidArgument, "unknown session"))?;
        let stream = slot
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| IdrError::new(IdrErrorKind::InvalidArgument, "unknown stream"))?;
        self.rt.block_on(stream.reset(reason))?;
        let _ = self
            .event_tx
            .try_send(EngineEvent::StreamClosed { stream_id });
        Ok(())
    }

    pub fn poll_event(&self) -> Option<EngineEvent> {
        self.event_rx.lock().try_recv().ok()
    }

    /// Inject DP DeviceIdentity JSON (from Dart flutter_secure_storage).
    pub fn set_dp_identity_json(&self, json: &str) -> Result<()> {
        let identity = idr_dp::device_identity_from_json(json).map_err(|e| {
            IdrError::new(IdrErrorKind::InvalidArgument, format!("dp identity: {e}"))
        })?;
        self.runtime.lock().set_identity(identity);
        Ok(())
    }
}

fn cstr(ptr: *const std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(|s| s.to_owned())
}

fn catalog_entries_to_json(entries: &[idr_protocol::stream_mux::ServiceCatalogEntry]) -> String {
    use idr_protocol::stream_mux::{CredentialMode, ServiceTransportKind};
    let mut out = String::from('[');
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let kind = match e.kind {
            ServiceTransportKind::Http => "http",
            ServiceTransportKind::Tcp => "tcp",
        };
        let mode = match e.credential_mode {
            CredentialMode::Source => "source",
            CredentialMode::Target => "target",
        };
        out.push('{');
        out.push_str("\"name\":\"");
        json_escape_into(&mut out, &e.name);
        out.push_str("\",\"kind\":\"");
        out.push_str(kind);
        out.push_str("\",\"credential_mode\":\"");
        out.push_str(mode);
        out.push_str("\",\"require_upstream_tls\":");
        out.push_str(if e.require_upstream_tls {
            "true"
        } else {
            "false"
        });
        out.push('}');
    }
    out.push(']');
    out
}

fn json_escape_into(out: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '"' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
}

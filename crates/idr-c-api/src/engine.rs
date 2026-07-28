//! In-process Source engine behind opaque C handles.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_core::session::PeerSession;
use idr_core::stream::LogicalStream;
use idr_source::{SourceRuntime, SourceSession};
use parking_lot::Mutex;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use crate::error::set_last_error;
use crate::mock_backend;

pub const ABI_VERSION: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EngineConfig {
    pub abi_version: u32,
    pub struct_size: u32,
    /// 1 = in-process mock (tests / CI). 0 = reserved for native (not yet wired).
    pub use_mock: u32,
    pub source_id: *const std::os::raw::c_char,
    pub source_region: *const std::os::raw::c_char,
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

        if cfg.use_mock == 0 {
            return Err(IdrError::new(
                IdrErrorKind::NotInitialized,
                "native WebRTC backend not linked in this build; set use_mock=1",
            ));
        }

        let rt = Runtime::new().map_err(|e| {
            IdrError::new(IdrErrorKind::InternalError, format!("tokio runtime: {e}"))
        })?;
        let runtime = mock_backend::mock_runtime(&source_id, &region);
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

        // Pump peer → demux without holding the stream borrow.
        for _ in 0..16 {
            match self.rt.block_on(slot.session.pump_once()) {
                Ok(()) => {}
                Err(_) => break,
            }
        }

        let stream = slot
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| IdrError::new(IdrErrorKind::InvalidArgument, "unknown stream"))?;
        let n = self.rt.block_on(async {
            match tokio::time::timeout(Duration::from_millis(100), stream.read(buf)).await {
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
}

fn cstr(ptr: *const std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller-provided NUL-terminated C string or null (handled above).
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(|s| s.to_owned())
}

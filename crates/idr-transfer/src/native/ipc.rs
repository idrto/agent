//! Local, OS-authenticated IPC between the agent and its CLI.
//!
//! No network listener exists. Only the user running the agent can connect:
//!
//! - Unix: a socket in a `0700` directory; every connection's peer UID must
//!   equal the agent's.
//! - Windows: a named pipe whose DACL grants only the agent's user SID, with
//!   remote (SMB) clients rejected.
//!
//! The protocol is one JSON request per line and one JSON response per line;
//! a connection may carry any number of them (a GUI keeps one open).
//!
//! Clients check the other end too: the server must run as the same user (a
//! pipe name another account created first is refused, not talked to).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::watch;

/// Requests the CLI sends. Transfer ids are hex strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Send { target: String, paths: Vec<PathBuf> },
    List,
    Status { id: String },
    Pause { id: String },
    Resume { id: String },
    Cancel { id: String },
    RetryFailed { id: String },
    Accept { id: String, out: Option<PathBuf> },
    Reject { id: String },
    /// Peers with a bound session now: send targets (Source FQHNs or Target SKIs).
    Peers,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    /// Stable error code (e.g. a `TransferErrorKind` string) when `!ok`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub data: serde_json::Value,
}

impl Response {
    pub fn ok(data: serde_json::Value) -> Self {
        Self { ok: true, error: None, data }
    }

    pub fn err(code: &str) -> Self {
        Self { ok: false, error: Some(code.to_string()), data: serde_json::Value::Null }
    }
}

#[async_trait]
pub trait Handler: Send + Sync {
    async fn handle(&self, req: Request) -> Response;
}

/// Where an agent listens: `agent` is e.g. `"source-agent"`; `dir` holds the
/// Unix socket (Windows uses a per-user pipe name instead).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcAddr(pub String);

impl IpcAddr {
    pub fn for_agent(agent: &str, dir: &Path) -> io::Result<Self> {
        imp::addr(agent, dir)
    }
}

#[derive(Debug)]
pub enum CallError {
    /// No agent listening (or not ours to talk to).
    Unavailable,
    Io(io::Error),
}

/// One request to the running agent.
pub async fn call(addr: &IpcAddr, req: &Request) -> Result<Response, CallError> {
    let stream = imp::connect(addr).await.map_err(|_| CallError::Unavailable)?;
    let (r, mut w) = tokio::io::split(stream);
    let mut line = serde_json::to_vec(req).map_err(|e| CallError::Io(e.into()))?;
    line.push(b'\n');
    w.write_all(&line).await.map_err(CallError::Io)?;
    let mut reader = BufReader::new(r);
    let mut buf = String::new();
    if reader.read_line(&mut buf).await.map_err(CallError::Io)? == 0 {
        return Err(CallError::Unavailable);
    }
    serde_json::from_str(&buf).map_err(|e| CallError::Io(e.into()))
}

const MAX_LINE: usize = 64 * 1024;

async fn serve_conn<S: AsyncRead + AsyncWrite + Unpin>(stream: S, handler: Arc<dyn Handler>) {
    let (r, mut w) = tokio::io::split(stream);
    // One request line may not exceed MAX_LINE.
    let mut reader = BufReader::new(r.take(MAX_LINE as u64));
    let mut buf = String::new();
    loop {
        buf.clear();
        match reader.read_line(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        reader.get_mut().set_limit(MAX_LINE as u64);
        let resp = match serde_json::from_str::<Request>(&buf) {
            Ok(req) => handler.handle(req).await,
            Err(_) => Response::err("invalid_argument"),
        };
        let mut out = serde_json::to_vec(&resp).unwrap_or_default();
        out.push(b'\n');
        if w.write_all(&out).await.is_err() {
            return;
        }
    }
}

/// Serve `handler` at `addr` until `shutdown` turns true.
pub async fn serve(addr: IpcAddr, handler: Arc<dyn Handler>, shutdown: watch::Receiver<bool>) -> io::Result<()> {
    imp::serve(addr, handler, shutdown).await
}

#[cfg(unix)]
mod imp {
    use std::os::unix::fs::PermissionsExt;

    use tokio::net::{UnixListener, UnixStream};

    use super::*;

    pub fn addr(agent: &str, dir: &Path) -> io::Result<IpcAddr> {
        let dir = dir.join("ipc");
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(IpcAddr(dir.join(format!("{agent}.sock")).to_string_lossy().into_owned()))
    }

    pub async fn connect(addr: &IpcAddr) -> io::Result<UnixStream> {
        let s = connect_any(addr).await?;
        // The socket must belong to an agent running as this user.
        if s.peer_cred()?.uid() != rustix::process::getuid().as_raw() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "agent socket owned by another user"));
        }
        Ok(s)
    }

    async fn connect_any(addr: &IpcAddr) -> io::Result<UnixStream> {
        UnixStream::connect(&addr.0).await
    }

    pub async fn serve(addr: IpcAddr, handler: Arc<dyn Handler>, mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
        let _ = std::fs::remove_file(&addr.0);
        let listener = UnixListener::bind(&addr.0)?;
        std::fs::set_permissions(&addr.0, std::fs::Permissions::from_mode(0o600))?;
        let me = rustix::process::getuid().as_raw();
        loop {
            let (stream, _) = tokio::select! {
                r = listener.accept() => r?,
                _ = shutdown.changed() => return Ok(()),
            };
            match stream.peer_cred() {
                Ok(c) if c.uid() == me => {
                    tokio::spawn(serve_conn(stream, handler.clone()));
                }
                _ => tracing::warn!("IPC connection from another user refused"),
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;

    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, ServerOptions};
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::*;

    /// The current user's SID as a string (`S-1-5-21-…`).
    pub fn user_sid() -> io::Result<String> {
        // SAFETY: the pseudo-handle of this process needs no closing.
        unsafe { process_sid(GetCurrentProcess()) }
    }

    /// The user SID `process` runs as.
    ///
    /// # Safety
    /// `process` must be a valid process handle with query access.
    unsafe fn process_sid(process: HANDLE) -> io::Result<String> {
        // SAFETY: standard token query; every out-pointer is valid, the token
        // handle and the SID string are released before returning.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
            let mut buf = vec![0u64; (len as usize).div_ceil(8)];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut c_void, len, &mut len);
            CloseHandle(token);
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut s: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut s) == 0 {
                return Err(io::Error::last_os_error());
            }
            let n = (0..).take_while(|&i| *s.add(i) != 0).count();
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
            LocalFree(s as *mut c_void);
            Ok(sid)
        }
    }

    /// Protected DACL: full access for this user only.
    pub fn sddl() -> io::Result<String> {
        Ok(format!("D:P(A;;GA;;;{})", user_sid()?))
    }

    pub fn addr(agent: &str, _dir: &Path) -> io::Result<IpcAddr> {
        Ok(IpcAddr(format!(r"\\.\pipe\idr-{agent}-{}", user_sid()?)))
    }

    pub async fn connect(addr: &IpcAddr) -> io::Result<NamedPipeClient> {
        let client = ClientOptions::new().open(&addr.0)?;
        use std::os::windows::io::AsRawHandle;
        server_is_this_user(client.as_raw_handle() as HANDLE)?;
        Ok(client)
    }

    /// Refuse a pipe whose server runs as someone else (another account could
    /// have created the name first, while the agent wasn't running).
    pub fn server_is_this_user(pipe: HANDLE) -> io::Result<()> {
        use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        let mut pid = 0u32;
        // SAFETY: `pipe` is an open pipe handle; the process handle is closed below.
        let sid = unsafe {
            if GetNamedPipeServerProcessId(pipe, &mut pid) == 0 {
                return Err(io::Error::last_os_error());
            }
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return Err(io::Error::last_os_error());
            }
            let sid = process_sid(process);
            CloseHandle(process);
            sid?
        };
        if sid != user_sid()? {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "agent pipe served by another user"));
        }
        Ok(())
    }

    struct Descriptor(PSECURITY_DESCRIPTOR);

    // SAFETY: the descriptor is immutable after creation and owned by this
    // value alone; moving it between threads is fine.
    unsafe impl Send for Descriptor {}

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe { LocalFree(self.0) };
        }
    }

    fn descriptor() -> io::Result<Descriptor> {
        let wide: Vec<u16> = sddl()?.encode_utf16().chain(Some(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut())
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor(sd))
    }

    fn create(addr: &IpcAddr, sd: &Descriptor, first: bool) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        // SAFETY: `sa` and the descriptor it points to outlive the call.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(&addr.0, &mut sa as *mut _ as *mut c_void)
        }
    }

    pub async fn serve(addr: IpcAddr, handler: Arc<dyn Handler>, mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
        let sd = descriptor()?;
        // First instance: fails if another process already owns this pipe name.
        let mut server = create(&addr, &sd, true)?;
        loop {
            tokio::select! {
                r = server.connect() => r?,
                _ = shutdown.changed() => return Ok(()),
            }
            let next = create(&addr, &sd, false)?;
            tokio::spawn(serve_conn(std::mem::replace(&mut server, next), handler.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;

    #[async_trait]
    impl Handler for Echo {
        async fn handle(&self, req: Request) -> Response {
            Response::ok(serde_json::to_value(req).unwrap())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn request_response_and_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let addr = IpcAddr(format!("{}-{}", IpcAddr::for_agent("idr-test", dir.path()).unwrap().0, std::process::id()));
        // CLI-020: nobody listening yet.
        assert!(matches!(call(&addr, &Request::List).await, Err(CallError::Unavailable)));

        let (stop, rx) = watch::channel(false);
        tokio::spawn(serve(addr.clone(), Arc::new(Echo), rx));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let req = Request::Pause { id: "ab".into() };
        for _ in 0..3 {
            let r = call(&addr, &req).await.unwrap();
            assert!(r.ok);
            assert_eq!(r.data["cmd"], "pause");
        }
        let _ = stop.send(true);
    }

    /// CLI-017: on Windows the pipe's DACL is protected and names only this user.
    #[cfg(windows)]
    #[test]
    fn pipe_dacl_allows_only_this_user() {
        let s = imp::sddl().unwrap();
        assert!(s.starts_with("D:P(A;;GA;;;S-1-"), "{s}");
        assert_eq!(s.matches("(A;").count(), 1, "exactly one allow entry");
    }

    /// CLI-017 / CLI-018: the DACL the OS actually holds for the live pipe grants
    /// this user only (and the pipe rejects remote clients by construction).
    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn live_pipe_dacl_is_owner_only() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
        };
        use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

        let dir = tempfile::tempdir().unwrap();
        let addr = IpcAddr(format!("{}-dacl-{}", IpcAddr::for_agent("idr-test", dir.path()).unwrap().0, std::process::id()));
        let (stop, rx) = watch::channel(false);
        tokio::spawn(serve(addr.clone(), Arc::new(Echo), rx));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let client = tokio::net::windows::named_pipe::ClientOptions::new().open(&addr.0).unwrap();
        // SAFETY: querying our own pipe handle; buffers are LocalFree'd.
        let sddl = unsafe {
            let mut sd = std::ptr::null_mut();
            let rc = GetSecurityInfo(
                client.as_raw_handle() as _,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            assert_eq!(rc, 0, "GetSecurityInfo failed");
            let mut s: *mut u16 = std::ptr::null_mut();
            assert_ne!(
                ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &mut s, std::ptr::null_mut()),
                0
            );
            let n = (0..).take_while(|&i| *s.add(i) != 0).count();
            let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
            LocalFree(s as _);
            LocalFree(sd as _);
            out
        };
        let me = imp::user_sid().unwrap();
        assert!(sddl.starts_with("D:P"), "DACL not protected: {sddl}");
        assert_eq!(sddl.matches("(A;").count(), 1, "{sddl}");
        assert!(sddl.contains(&me), "{sddl}");
        let _ = stop.send(true);
    }

    #[test]
    fn requests_have_stable_json() {
        let r = Request::Accept { id: "01".into(), out: Some("C:/in".into()) };
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"cmd":"accept","id":"01","out":"C:/in"}"#);
        assert_eq!(serde_json::to_string(&Request::RetryFailed { id: "x".into() }).unwrap(), r#"{"cmd":"retry_failed","id":"x"}"#);
    }
}

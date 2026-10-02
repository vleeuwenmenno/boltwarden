//! Local-only, user/session-bound named pipes. Overlapped I/O makes deadlines and
//! cancellation effective even when a peer stops reading during vault revocation.
use super::windows::*;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::windows::io::OwnedHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use windows_sys::Win32::{
    Foundation::*, Storage::FileSystem::*, System::IO::*, System::Pipes::*, System::Threading::*,
};

fn pipe_name(path: &Path) -> Vec<u16> {
    use sha2::{Digest, Sha256};
    use std::os::windows::ffi::OsStrExt;
    let bytes: Vec<_> = path
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect();
    let digest = Sha256::digest(&bytes);
    let hash: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    wide(format!(r"\\.\pipe\boltwarden-{}-{hash}", current_uid()))
}
pub fn runtime_dir() -> io::Result<PathBuf> {
    let (sid, session) = identity()?;
    Ok(PathBuf::from(format!("boltwarden-{sid}-{session}")))
}
pub fn current_uid() -> String {
    let (sid, session) = identity().expect("Cannot identify Windows login session");
    format!("{sid}-{session}")
}
pub fn peer_uid(stream: &Stream) -> io::Result<String> {
    let (sid, session) = process_identity(peer_process(stream)?)?;
    Ok(format!("{sid}-{session}"))
}
fn peer_process(stream: &Stream) -> io::Result<u32> {
    let pipe = stream.connection_handle()?;
    let mut pid = 0;
    check(unsafe {
        if stream.0.server {
            GetNamedPipeClientProcessId(raw(&pipe), &mut pid)
        } else {
            GetNamedPipeServerProcessId(raw(&pipe), &mut pid)
        }
    })?;
    Ok(pid)
}
pub fn peer_pid(stream: &Stream) -> io::Result<u32> {
    if peer_uid(stream)? != current_uid() {
        return Err(denied());
    }
    peer_process(stream)
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Pipe peer is not in this user's login session",
    )
}
pub fn remove_stale_socket(_: &Path) -> io::Result<()> {
    Ok(())
}
pub fn bind_private(path: &Path) -> io::Result<Listener> {
    Listener::bind(path)
}

struct Connection {
    handle: Mutex<Option<Arc<OwnedHandle>>>,
    server: bool,
    closed: AtomicBool,
    read_timeout: AtomicU64,
    write_timeout: AtomicU64,
    reader: Mutex<()>,
    writer: Mutex<()>,
}
#[derive(Clone)]
pub struct Stream(Arc<Connection>);
impl Stream {
    fn new(handle: OwnedHandle, server: bool) -> Self {
        Self(Arc::new(Connection {
            handle: Mutex::new(Some(Arc::new(handle))),
            server,
            closed: AtomicBool::new(false),
            read_timeout: AtomicU64::new(0),
            write_timeout: AtomicU64::new(5000),
            reader: Mutex::new(()),
            writer: Mutex::new(()),
        }))
    }
    fn connection_handle(&self) -> io::Result<Arc<OwnedHandle>> {
        self.0
            .handle
            .lock()
            .map_err(|_| io::Error::other("Pipe handle lock poisoned"))?
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Pipe closed"))
    }
    pub fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        let name = pipe_name(path.as_ref());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let result = handle(unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    null_mut(),
                )
            });
            match result {
                Ok(handle) => {
                    let stream = Self::new(handle, false);
                    if peer_uid(&stream)? != current_uid() {
                        return Err(denied());
                    }
                    return Ok(stream);
                }
                Err(error)
                    if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                        && Instant::now() < deadline =>
                unsafe {
                    WaitNamedPipeW(name.as_ptr(), 100);
                },
                Err(error) => return Err(error),
            }
        }
    }
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(self.clone())
    }
    pub fn set_read_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        self.0
            .read_timeout
            .store(timeout(duration), Ordering::Relaxed);
        Ok(())
    }
    pub fn set_write_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        self.0
            .write_timeout
            .store(timeout(duration), Ordering::Relaxed);
        Ok(())
    }
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        if how == Shutdown::Write {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Named pipes require explicit message framing",
            ));
        }
        self.0.closed.store(true, Ordering::SeqCst);
        let pipe = self
            .0
            .handle
            .lock()
            .map_err(|_| io::Error::other("Pipe handle lock poisoned"))?
            .take();
        if let Some(pipe) = pipe {
            unsafe {
                CancelIoEx(raw(&pipe), null());
                if self.0.server {
                    DisconnectNamedPipe(raw(&pipe));
                }
            }
            // Outstanding operations keep their own Arc until cancellation has
            // completed. Other Stream clones no longer keep the pipe open.
        }
        Ok(())
    }
    fn transfer(&self, pointer: *mut u8, length: usize, write: bool) -> io::Result<usize> {
        let _guard = if write {
            self.0.writer.lock()
        } else {
            self.0.reader.lock()
        }
        .map_err(|_| io::Error::other("Pipe lock poisoned"))?;
        if self.0.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Pipe closed"));
        }
        if length == 0 {
            return Ok(0);
        }
        let pipe = self.connection_handle()?;
        let event = handle(unsafe { CreateEventW(null(), 1, 0, null()) })?;
        let mut operation: OVERLAPPED = unsafe { std::mem::zeroed() };
        operation.hEvent = raw(&event);
        let count = length.min(65536) as u32;
        let result = unsafe {
            if write {
                WriteFile(raw(&pipe), pointer, count, null_mut(), &mut operation)
            } else {
                ReadFile(raw(&pipe), pointer, count, null_mut(), &mut operation)
            }
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) && !write {
                return Ok(0);
            }
            if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(error);
            }
        }
        // CancelIoEx can race the submission above. Recheck after submitting.
        if self.0.closed.load(Ordering::SeqCst) {
            unsafe {
                CancelIoEx(raw(&pipe), &operation);
            }
        }
        let millis = if write {
            self.0.write_timeout.load(Ordering::Relaxed)
        } else {
            self.0.read_timeout.load(Ordering::Relaxed)
        };
        let wait = unsafe {
            WaitForSingleObject(
                raw(&event),
                if millis == 0 {
                    INFINITE
                } else {
                    millis.min(u32::MAX as u64 - 1) as u32
                },
            )
        };
        if wait != WAIT_OBJECT_0 {
            unsafe {
                CancelIoEx(raw(&pipe), &operation);
                // The kernel must release operation and buffer before they go out of scope.
                WaitForSingleObject(raw(&event), INFINITE);
            }
            return Err(io::Error::new(
                if wait == WAIT_TIMEOUT {
                    io::ErrorKind::TimedOut
                } else {
                    io::ErrorKind::Other
                },
                "Pipe operation did not complete",
            ));
        }
        let mut transferred = 0;
        if unsafe { GetOverlappedResult(raw(&pipe), &operation, &mut transferred, 0) } == 0 {
            let error = io::Error::last_os_error();
            if !write && error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                return Ok(0);
            }
            return Err(error);
        }
        Ok(transferred as usize)
    }
    #[cfg(test)]
    pub fn pair() -> io::Result<(Self, Self)> {
        let path = PathBuf::from(format!("test-{}", uuid::Uuid::new_v4()));
        let listener = Listener::bind(&path)?;
        let thread = std::thread::spawn(move || Self::connect(path));
        let (server, _) = listener.accept()?;
        Ok((
            thread
                .join()
                .map_err(|_| io::Error::other("Pipe client panicked"))??,
            server,
        ))
    }
}
fn timeout(duration: Option<Duration>) -> u64 {
    duration.map_or(0, |d| d.as_millis().max(1).min(u64::MAX as u128) as u64)
}
impl Read for &Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.transfer(bytes.as_mut_ptr(), bytes.len(), false)
    }
}
impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        (&*self).read(bytes)
    }
}
impl Write for &Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.transfer(bytes.as_ptr().cast_mut(), bytes.len(), true)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        (&*self).write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Pending {
    handle: OwnedHandle,
    event: OwnedHandle,
    operation: Box<OVERLAPPED>,
}
// OVERLAPPED points only to the owned event; its Box never moves while submitted.
unsafe impl Send for Pending {}
impl Pending {
    fn new(name: &[u16], first: bool) -> io::Result<Self> {
        let security = PrivateSecurity::new()?;
        let attrs = security.attributes();
        let pipe = handle(unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX
                    | FILE_FLAG_OVERLAPPED
                    | if first {
                        FILE_FLAG_FIRST_PIPE_INSTANCE
                    } else {
                        0
                    },
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                5000,
                &attrs,
            )
        })?;
        let event = handle(unsafe { CreateEventW(null(), 1, 0, null()) })?;
        let mut operation: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
        operation.hEvent = raw(&event);
        if unsafe { ConnectNamedPipe(raw(&pipe), &mut *operation) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) {
                unsafe {
                    SetEvent(raw(&event));
                }
            } else if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(error);
            }
        }
        Ok(Self {
            handle: pipe,
            event,
            operation,
        })
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        unsafe {
            CancelIoEx(raw(&self.handle), &*self.operation);
            WaitForSingleObject(raw(&self.event), INFINITE);
        }
    }
}
pub struct Listener {
    _ownership: OwnedHandle,
    name: Vec<u16>,
    pending: Mutex<Pending>,
    nonblocking: AtomicBool,
}
impl Listener {
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let name = pipe_name(path.as_ref());
        // Keep a session-local ownership object as well as FIRST_PIPE_INSTANCE.
        // No abandoned-mutex recovery is needed: handle lifetime is ownership.
        let mutex_name = wide(format!(
            "Local\\{}",
            String::from_utf16_lossy(&name[..name.len() - 1]).replace('\\', "_")
        ));
        let security = PrivateSecurity::new()?;
        let attrs = security.attributes();
        let mutex = unsafe { CreateMutexW(&attrs, 0, mutex_name.as_ptr()) };
        let error = unsafe { GetLastError() };
        let ownership = handle(mutex)?;
        if error == ERROR_ALREADY_EXISTS {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "Endpoint already has a listener",
            ));
        }
        let pending = Pending::new(&name, true)?;
        Ok(Self {
            _ownership: ownership,
            name,
            pending: Mutex::new(pending),
            nonblocking: AtomicBool::new(false),
        })
    }
    pub fn set_nonblocking(&self, value: bool) -> io::Result<()> {
        self.nonblocking.store(value, Ordering::Relaxed);
        Ok(())
    }
    pub fn accept(&self) -> io::Result<(Stream, ())> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| io::Error::other("Pipe listener poisoned"))?;
        let wait = unsafe {
            WaitForSingleObject(
                raw(&pending.event),
                if self.nonblocking.load(Ordering::Relaxed) {
                    0
                } else {
                    INFINITE
                },
            )
        };
        if wait == WAIT_TIMEOUT {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if wait != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        // Hold an instance continuously so another server cannot claim this endpoint.
        let next = Pending::new(&self.name, false)?;
        let previous = std::mem::replace(&mut *pending, next);
        let stream = Stream::new(previous.handle.try_clone()?, true);
        if peer_uid(&stream)? != current_uid() {
            return Err(denied());
        }
        Ok((stream, ()))
    }
    pub fn incoming(&self) -> impl Iterator<Item = io::Result<Stream>> + '_ {
        std::iter::repeat_with(|| self.accept().map(|(stream, ())| stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pipe_peer_is_kernel_bound_and_a_second_listener_cannot_claim_the_name() {
        let path = PathBuf::from(format!("pipe-test-{}", uuid::Uuid::new_v4()));
        let listener = Listener::bind(&path).unwrap();
        assert!(Listener::bind(&path).is_err());
        let mut client = Stream::connect(&path).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        assert_eq!(peer_pid(&server).unwrap(), std::process::id());
        assert_eq!(peer_uid(&client).unwrap(), current_uid());
        client.write_all(b"request").unwrap();
        let mut body = [0; 7];
        server.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"request");
    }
    #[test]
    fn deadline_does_not_consume_the_next_message_and_shutdown_wakes_blocked_readers() {
        let (mut client, mut server) = Stream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        assert_eq!(
            client.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        server.write_all(b"x").unwrap();
        let mut byte = [0];
        client.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");
        client.set_read_timeout(None).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let shutdown = client.try_clone().unwrap();
        std::thread::spawn(move || {
            let _ = tx.send(client.read(&mut [0]));
        });
        std::thread::sleep(Duration::from_millis(30));
        shutdown.shutdown(Shutdown::Both).unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().is_err());
    }
    #[test]
    fn server_shutdown_disconnects_peer_even_while_other_server_clones_exist() {
        let (mut client, server) = Stream::pair().unwrap();
        let _retained = server.try_clone().unwrap();
        server.shutdown(Shutdown::Both).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(matches!(client.read(&mut [0]), Ok(0) | Err(_)));
    }
    #[test]
    fn client_shutdown_disconnects_server_even_while_client_clones_exist() {
        let (client, mut server) = Stream::pair().unwrap();
        let _retained = client.try_clone().unwrap();
        client.shutdown(Shutdown::Both).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(server.read(&mut [0]).unwrap(), 0);
    }
    #[test]
    fn nonblocking_accept_and_cancelled_listener_release_the_endpoint() {
        let path = PathBuf::from(format!("pipe-test-{}", uuid::Uuid::new_v4()));
        let listener = Listener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
        drop(listener);
        assert!(Listener::bind(&path).is_ok());
    }
}

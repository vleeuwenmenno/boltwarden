//! Clipboard ownership and expiry run on a thread that pumps Windows messages.
use crate::platform::windows::*;
use std::{
    io,
    ptr::{null, null_mut},
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    System::{DataExchange::*, Memory::*},
    UI::WindowsAndMessaging::*,
};
use zeroize::Zeroizing;
pub const CLEAR_AFTER: Duration = Duration::from_secs(45);
#[derive(Clone)]
pub struct Clipboard(Arc<mpsc::Sender<Command>>);
enum Command {
    Copy(Zeroizing<String>, mpsc::Sender<Result<(), String>>),
    Clear(mpsc::Sender<()>),
}
impl Default for Clipboard {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || worker(rx));
        Self(Arc::new(tx))
    }
}
impl Clipboard {
    pub fn copy(&self, text: &str) -> Result<(), String> {
        let (tx, rx) = mpsc::channel();
        self.0
            .send(Command::Copy(Zeroizing::new(text.to_owned()), tx))
            .map_err(|_| "Clipboard unavailable")?;
        rx.recv_timeout(Duration::from_secs(3))
            .map_err(|_| "Clipboard did not respond".to_string())?
    }
    pub fn clear(&self) {
        let (tx, rx) = mpsc::channel();
        if self.0.send(Command::Clear(tx)).is_ok() {
            // Lock/quit must not exit before the worker has attempted the clear.
            let _ = rx.recv_timeout(Duration::from_secs(2));
        }
    }
}
struct Open;
impl Open {
    fn acquire(window: HWND) -> io::Result<Self> {
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            if unsafe { OpenClipboard(window) } != 0 {
                return Ok(Self);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::last_os_error());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Open {
    fn drop(&mut self) {
        unsafe {
            CloseClipboard();
        }
    }
}
fn set(format: u32, bytes: &[u8]) -> io::Result<()> {
    let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len()) };
    if memory.is_null() {
        return Err(io::Error::last_os_error());
    }
    let pointer = unsafe { GlobalLock(memory) };
    if pointer.is_null() {
        unsafe {
            GlobalFree(memory);
        }
        return Err(io::Error::last_os_error());
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.cast(), bytes.len());
        GlobalUnlock(memory);
    }
    if unsafe { SetClipboardData(format, memory) }.is_null() {
        let error = io::Error::last_os_error();
        unsafe {
            GlobalFree(memory);
        }
        return Err(error);
    }
    Ok(()) // The OS now owns the allocation.
}
fn copy(window: HWND, text: &str) -> io::Result<u32> {
    let _clipboard = Open::acquire(window)?;
    check(unsafe { EmptyClipboard() })?;
    // Register privacy markers before publishing any secret text.
    for name in [
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
        "CanUploadToCloudClipboard",
    ] {
        let format = unsafe { RegisterClipboardFormatW(wide(name).as_ptr()) };
        if format == 0 {
            return Err(io::Error::last_os_error());
        }
        set(format, &0u32.to_ne_bytes())?;
    }
    let utf16 = Zeroizing::new(wide(text));
    let bytes = unsafe { std::slice::from_raw_parts(utf16.as_ptr().cast(), utf16.len() * 2) };
    set(13, bytes)?; // CF_UNICODETEXT
    Ok(unsafe { GetClipboardSequenceNumber() })
}
fn clear(window: HWND, sequence: u32) -> io::Result<()> {
    let _clipboard = Open::acquire(window)?;
    if unsafe { GetClipboardSequenceNumber() == sequence && GetClipboardOwner() == window } {
        check(unsafe { EmptyClipboard() })?;
    }
    Ok(())
}
fn worker(rx: mpsc::Receiver<Command>) {
    let window = unsafe {
        CreateWindowExW(
            0,
            wide("STATIC").as_ptr(),
            wide("Boltwarden clipboard").as_ptr(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            null_mut(),
            null_mut(),
            null(),
        )
    };
    if window.is_null() {
        return;
    }
    let mut owned: Option<(u32, Instant)> = None;
    loop {
        match rx.try_recv() {
            Ok(Command::Copy(text, reply)) => {
                let result = copy(window, &text)
                    .map(|sequence| {
                        owned = Some((sequence, Instant::now() + CLEAR_AFTER));
                    })
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            Ok(Command::Clear(reply)) => {
                if let Some((sequence, _)) = owned {
                    if clear(window, sequence).is_ok() {
                        owned = None;
                    } else {
                        owned = Some((sequence, Instant::now()));
                    }
                }
                let _ = reply.send(());
            }
            Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => (),
        }
        if let Some((sequence, deadline)) = owned {
            if Instant::now() >= deadline && clear(window, sequence).is_ok() {
                owned = None;
            }
        }
        unsafe {
            let mut message: MSG = std::mem::zeroed();
            while PeekMessageW(&mut message, null_mut(), 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if let Some((sequence, _)) = owned {
        let _ = clear(window, sequence);
    }
    unsafe {
        DestroyWindow(window);
    }
}

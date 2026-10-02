use crate::platform::windows::*;
use std::{
    io,
    ptr::{null, null_mut},
    sync::{
        OnceLock,
        mpsc::{self, Receiver, Sender},
    },
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::*,
    System::{LibraryLoader::*, RemoteDesktop::*, SystemInformation::*},
    UI::{Input::KeyboardAndMouse::*, WindowsAndMessaging::*},
};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    pub locked: bool,
    pub idle: bool,
    pub idle_for: Option<Duration>,
}
#[derive(Debug)]
pub enum Event {
    State(SessionState),
    LockRequested(&'static str),
    Unavailable(String),
}
static EVENTS: OnceLock<Sender<Event>> = OnceLock::new();
fn emit(event: Event) {
    if let Some(sender) = EVENTS.get() {
        let _ = sender.send(event);
    }
}
fn state() -> io::Result<SessionState> {
    let (_, session) = identity()?;
    let mut data = null_mut();
    let mut bytes = 0;
    check(unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session,
            WTSSessionInfoEx,
            &mut data,
            &mut bytes,
        )
    })?;
    let flags = if bytes as usize >= std::mem::size_of::<WTSINFOEXW>() {
        let info = unsafe { &*data.cast::<WTSINFOEXW>() };
        if info.Level == 1 {
            Some(unsafe { info.Data.WTSInfoExLevel1.SessionFlags } as u32)
        } else {
            None
        }
    } else {
        None
    };
    unsafe {
        WTSFreeMemory(data.cast());
    }
    let locked = match flags {
        Some(WTS_SESSIONSTATE_LOCK) => true,
        Some(WTS_SESSIONSTATE_UNLOCK) => false,
        _ => return Err(io::Error::other("Windows session lock state unavailable")),
    };
    let mut input = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    check(unsafe { GetLastInputInfo(&mut input) })?;
    let elapsed = unsafe { GetTickCount() }.wrapping_sub(input.dwTime);
    Ok(SessionState {
        locked,
        idle: elapsed > 0,
        idle_for: Some(Duration::from_millis(elapsed as u64)),
    })
}
unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    word: WPARAM,
    long: LPARAM,
) -> LRESULT {
    match message {
        WM_WTSSESSION_CHANGE => {
            if matches!(
                word as u32,
                WTS_SESSION_LOCK
                    | WTS_SESSION_LOGOFF
                    | WTS_CONSOLE_DISCONNECT
                    | WTS_REMOTE_DISCONNECT
            ) {
                emit(Event::LockRequested(
                    "Windows session locked or disconnected",
                ));
            }
        }
        WM_POWERBROADCAST if word as u32 == PBT_APMSUSPEND => {
            emit(Event::LockRequested("system suspend requested"))
        }
        WM_TIMER => match state() {
            Ok(state) => emit(Event::State(state)),
            Err(e) => emit(Event::Unavailable(e.to_string())),
        },
        _ => (),
    }
    unsafe { DefWindowProcW(window, message, word, long) }
}
fn watch() -> io::Result<()> {
    let name = wide("BoltwardenSessionMonitor");
    let instance = unsafe { GetModuleHandleW(null()) };
    let class = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        lpszClassName: name.as_ptr(),
        ..unsafe { std::mem::zeroed() }
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let window = unsafe {
        CreateWindowExW(
            0,
            name.as_ptr(),
            name.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            instance,
            null(),
        )
    };
    if window.is_null() {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        check(unsafe { WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) })?;
        if unsafe { SetTimer(window, 1, 5000, None) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // Subscribe before querying so a short lock/unlock transition is retained.
        emit(Event::State(state()?));
        let mut message: MSG = unsafe { std::mem::zeroed() };
        loop {
            let status = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
            if status <= 0 {
                return Err(io::Error::other("Windows session monitor stopped"));
            }
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    })();
    unsafe {
        WTSUnRegisterSessionNotification(window);
        DestroyWindow(window);
        UnregisterClassW(name.as_ptr(), instance);
    }
    result
}
pub fn subscribe() -> Receiver<Event> {
    let (tx, rx) = mpsc::channel();
    if EVENTS.set(tx).is_err() {
        return rx;
    }
    std::thread::spawn(|| {
        loop {
            if let Err(error) = watch() {
                emit(Event::Unavailable(error.to_string()));
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    });
    rx
}

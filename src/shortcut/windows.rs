use super::Shortcut;
use std::{sync::mpsc, time::Duration};
use windows_sys::Win32::{
    Foundation::*,
    System::Threading::GetCurrentThreadId,
    UI::{Input::KeyboardAndMouse::*, WindowsAndMessaging::*},
};
const APPLY: u32 = WM_APP + 17;
struct Request {
    shortcut: Option<Shortcut>,
    result: mpsc::Sender<Result<(), String>>,
}
pub struct Runtime {
    thread: u32,
    requests: mpsc::Sender<Request>,
}
impl Runtime {
    pub fn new(activate: mpsc::Sender<()>) -> Self {
        let (requests, receiver) = mpsc::channel::<Request>();
        let (ready, started) = mpsc::sync_channel(1);
        std::thread::spawn(move || unsafe {
            let mut message: MSG = std::mem::zeroed();
            PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_NOREMOVE);
            let _ = ready.send(GetCurrentThreadId());
            let mut current: Option<(i32, Shortcut)> = None;
            while GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) > 0 {
                if message.message == WM_HOTKEY {
                    if current
                        .as_ref()
                        .is_some_and(|(id, _)| *id as usize == message.wParam)
                    {
                        let _ = activate.send(());
                    }
                } else if message.message == APPLY {
                    while let Ok(request) = receiver.try_recv() {
                        let result = replace(&mut current, request.shortcut);
                        let _ = request.result.send(result);
                    }
                }
            }
            if let Some((id, _)) = current {
                UnregisterHotKey(std::ptr::null_mut(), id);
            }
        });
        Self {
            thread: started.recv().unwrap_or(0),
            requests,
        }
    }
    pub fn supported(&self) -> bool {
        self.thread != 0
    }
    pub fn unavailable_message(&self) -> String {
        "Windows shortcut service unavailable".into()
    }
    pub fn apply(
        &mut self,
        _: Option<&Shortcut>,
        shortcut: Option<&Shortcut>,
    ) -> Result<(), String> {
        let (result, response) = mpsc::channel();
        self.requests
            .send(Request {
                shortcut: shortcut.cloned(),
                result,
            })
            .map_err(|_| self.unavailable_message())?;
        if unsafe { PostThreadMessageW(self.thread, APPLY, 0, 0) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        response
            .recv_timeout(Duration::from_secs(3))
            .map_err(|_| "Windows shortcut service did not respond".to_owned())?
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        unsafe {
            PostThreadMessageW(self.thread, WM_QUIT, 0, 0);
        }
    }
}
fn replace(
    current: &mut Option<(i32, Shortcut)>,
    shortcut: Option<Shortcut>,
) -> Result<(), String> {
    if current.as_ref().map(|(_, key)| key) == shortcut.as_ref() {
        return Ok(());
    }
    let next = if let Some(shortcut) = shortcut {
        shortcut.validate()?;
        let id = if current.as_ref().is_some_and(|(id, _)| *id == 0xB011) {
            0xB012
        } else {
            0xB011
        };
        let modifiers = MOD_NOREPEAT
            | if shortcut.ctrl { MOD_CONTROL } else { 0 }
            | if shortcut.alt { MOD_ALT } else { 0 }
            | if shortcut.shift { MOD_SHIFT } else { 0 };
        if unsafe {
            RegisterHotKey(
                std::ptr::null_mut(),
                id,
                modifiers,
                shortcut.virtual_key().unwrap(),
            )
        } == 0
        {
            let error = unsafe { GetLastError() };
            return Err(if error == ERROR_HOTKEY_ALREADY_REGISTERED {
                "Already in use by Windows or another application; choose another shortcut".into()
            } else {
                format!(
                    "Could not register shortcut: {}",
                    std::io::Error::from_raw_os_error(error as i32)
                )
            });
        }
        Some((id, shortcut))
    } else {
        None
    };
    if let Some((id, _)) = current.take() {
        unsafe {
            UnregisterHotKey(std::ptr::null_mut(), id);
        }
    }
    *current = next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conflicts_preserve_previous_hotkey_and_clear_releases_it() {
        let (tx, rx) = mpsc::channel();
        let mut first = Runtime::new(tx.clone());
        let mut second = Runtime::new(tx);
        let a = Shortcut {
            ctrl: true,
            alt: true,
            shift: true,
            key: "F23".into(),
            ..Default::default()
        };
        let b = Shortcut {
            key: "F24".into(),
            ..a.clone()
        };
        first.apply(None, Some(&a)).unwrap();
        // Exercise the worker's hotkey dispatch without injecting system-wide keys.
        assert_ne!(
            unsafe { PostThreadMessageW(first.thread, WM_HOTKEY, 0xB011, 0) },
            0
        );
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        second.apply(None, Some(&b)).unwrap();
        assert!(first.apply(Some(&a), Some(&b)).is_err());
        assert!(second.apply(Some(&b), Some(&a)).is_err());
        first.apply(Some(&a), None).unwrap();
        assert_ne!(
            unsafe { PostThreadMessageW(first.thread, WM_HOTKEY, 0xB011, 0) },
            0
        );
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        second.apply(Some(&b), Some(&a)).unwrap();
        second.apply(Some(&a), None).unwrap();
    }
}

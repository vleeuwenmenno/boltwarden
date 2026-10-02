//! Best-effort Windows capture exclusion, scoped to this UI process's windows.
use std::{thread, time::Duration};
use windows_sys::Win32::{Foundation::*, UI::WindowsAndMessaging::*};
pub fn available() -> bool {
    true
}
struct State {
    obscure: bool,
    found: bool,
    error: Option<String>,
}
unsafe extern "system" fn apply_window(window: HWND, parameter: LPARAM) -> i32 {
    let state = unsafe { &mut *(parameter as *mut State) };
    let mut pid = 0;
    unsafe {
        GetWindowThreadProcessId(window, &mut pid);
    }
    if pid != std::process::id() {
        return 1;
    }
    state.found = true;
    let desired = if state.obscure {
        WDA_EXCLUDEFROMCAPTURE
    } else {
        WDA_NONE
    };
    let mut actual = 0;
    if unsafe { SetWindowDisplayAffinity(window, desired) } == 0
        || unsafe { GetWindowDisplayAffinity(window, &mut actual) } == 0
        || actual != desired
    {
        state.error = Some("Windows could not apply capture exclusion to this window".into());
    }
    1
}
pub fn apply(obscure: bool) -> Result<(), String> {
    for _ in 0..20 {
        let mut state = State {
            obscure,
            found: false,
            error: None,
        };
        unsafe {
            EnumWindows(Some(apply_window), (&mut state as *mut State) as isize);
        }
        if let Some(error) = state.error {
            return Err(error);
        }
        if state.found {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("Window is not available for capture exclusion".into())
}

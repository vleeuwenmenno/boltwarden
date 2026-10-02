#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() -> eframe::Result<()> {
    #[cfg(windows)]
    let is_window = std::env::args().any(|arg| arg == "--popup" || arg == "--vault-window");
    #[cfg(windows)]
    if !is_window {
        // CLI launches can use the parent console; Explorer launches stay quiet.
        // Window children already have a private stdin pipe from the daemon.
        // Attaching a console here must not replace that pipe's standard handle.
        unsafe {
            windows_sys::Win32::System::Console::AttachConsole(
                windows_sys::Win32::System::Console::ATTACH_PARENT_PROCESS,
            );
        }
    }
    let result = boltwarden::run();
    #[cfg(windows)]
    if is_window && let Err(error) = &result {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
        let message: Vec<u16> = format!(
            "Boltwarden could not open its window.\n\n{error}\n\nCopy this error with Ctrl+C to include it in a bug report."
        )
        .encode_utf16()
        .chain(Some(0))
        .collect();
        let title: Vec<u16> = "Boltwarden startup error\0".encode_utf16().collect();
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }
    result
}

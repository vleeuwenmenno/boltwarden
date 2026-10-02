use std::sync::mpsc;
use tray_icon::{
    MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuItem},
};
use windows_sys::Win32::{System::Threading::GetCurrentThreadId, UI::WindowsAndMessaging::*};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    Show,
    Hide,
    Toggle,
    Window,
    Quit,
}
pub struct Handle(u32);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            PostThreadMessageW(self.0, WM_QUIT, 0, 0);
        }
    }
}
pub fn spawn(tx: mpsc::Sender<TrayCommand>) -> Result<Handle, String> {
    let (ready, result) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let initialize = || -> Result<_, String> {
            let menu = Menu::new();
            for (id, label) in [
                ("show", "Show"),
                ("hide", "Hide"),
                ("toggle", "Toggle quick access"),
                ("window", "Open vault window"),
                ("quit", "Quit"),
            ] {
                menu.append(&MenuItem::with_id(id, label, true, None))
                    .map_err(|e| e.to_string())?;
            }
            let menu_tx = tx.clone();
            MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                let command = match event.id.as_ref() {
                    "show" => TrayCommand::Show,
                    "hide" => TrayCommand::Hide,
                    "toggle" => TrayCommand::Toggle,
                    "window" => TrayCommand::Window,
                    "quit" => TrayCommand::Quit,
                    _ => return,
                };
                let _ = menu_tx.send(command);
            }));
            TrayIconEvent::set_event_handler(Some(move |event| {
                if matches!(
                    event,
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
                ) {
                    let _ = tx.send(TrayCommand::Show);
                }
            }));
            let rgba = crate::logo::rgba(32, crate::ui::theme::theme().text);
            let icon = tray_icon::Icon::from_rgba(rgba, 32, 32).map_err(|e| e.to_string())?;
            TrayIconBuilder::new()
                .with_icon(icon)
                .with_menu(Box::new(menu))
                .with_tooltip("Boltwarden")
                .with_menu_on_left_click(false)
                .build()
                .map_err(|e| e.to_string())
        };
        match initialize() {
            Ok(tray) => {
                let _ = ready.send(Ok(Handle(unsafe { GetCurrentThreadId() })));
                let mut message: MSG = unsafe { std::mem::zeroed() };
                unsafe {
                    while GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) > 0 {
                        TranslateMessage(&message);
                        DispatchMessageW(&message);
                    }
                }
                drop(tray);
            }
            Err(error) => {
                let _ = ready.send(Err(error));
            }
        }
    });
    result
        .recv()
        .map_err(|_| "Tray initialization failed".to_string())?
}

//! The menu bar item. AppKit requires it on the main thread with events flowing, which
//! `platform::main_thread::recv` provides while the daemon waits for commands.
use crate::platform::main_thread::pump;
use objc2::MainThreadMarker;
use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};
use std::cell::RefCell;
use std::sync::mpsc;
use std::time::Duration;
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TrayCommand {
    Show,
    Hide,
    Toggle,
    Window,
    Quit,
}

thread_local! {
    // AppKit objects stay on the main thread, which owns the item until the daemon exits.
    static TRAY: RefCell<Option<TrayIcon>> = const { RefCell::new(None) };
}

pub struct Handle;

pub fn spawn(tx: mpsc::Sender<TrayCommand>) -> Result<Handle, String> {
    let mtm = MainThreadMarker::new().ok_or("the menu bar item needs the main thread")?;
    let app = NSApplication::sharedApplication(mtm);
    // A menu bar app: no Dock icon and no app menu.
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    app.finishLaunching();
    pump(&app, Duration::ZERO);

    let menu = Menu::new();
    for (id, label) in [
        ("show", "Show quick access"),
        ("window", "Open vault window"),
    ] {
        menu.append(&MenuItem::with_id(id, label, true, None))
            .map_err(|e| e.to_string())?;
    }
    menu.append(&PredefinedMenuItem::separator())
        .map_err(|e| e.to_string())?;
    menu.append(&MenuItem::with_id("quit", "Quit Boltwarden", true, None))
        .map_err(|e| e.to_string())?;
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        let command = match event.id.as_ref() {
            "show" => TrayCommand::Show,
            "window" => TrayCommand::Window,
            "quit" => TrayCommand::Quit,
            _ => return,
        };
        let _ = tx.send(command);
    }));

    // Template images are drawn from their alpha channel in the menu bar's own color.
    const SIZE: u32 = 36;
    let rgba = crate::logo::rgba(SIZE, eframe::egui::Color32::BLACK);
    let icon = tray_icon::Icon::from_rgba(rgba, SIZE, SIZE).map_err(|e| e.to_string())?;
    let tray = TrayIconBuilder::new()
        .with_icon_templated(icon)
        .with_menu(Box::new(menu))
        .with_tooltip("Boltwarden")
        .build()
        .map_err(|e| e.to_string())?;
    TRAY.with(|slot| *slot.borrow_mut() = Some(tray));
    Ok(Handle)
}

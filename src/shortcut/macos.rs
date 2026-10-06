//! Global shortcuts through Carbon's RegisterEventHotKey, which needs no Accessibility
//! permission. Hotkeys are registered and delivered on the daemon's main thread.
use super::Shortcut;
use crate::platform::main_thread;
use std::cell::RefCell;
use std::ffi::c_void;
use std::sync::{OnceLock, mpsc};

type OsStatus = i32;
type EventHandler = extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> OsStatus;

#[repr(C)]
struct EventTypeSpec {
    event_class: u32,
    event_kind: u32,
}

#[repr(C)]
struct EventHotKeyId {
    signature: u32,
    id: u32,
}

#[link(name = "Carbon", kind = "framework")]
unsafe extern "C" {
    fn GetApplicationEventTarget() -> *mut c_void;
    fn InstallEventHandler(
        target: *mut c_void,
        handler: EventHandler,
        type_count: u32,
        types: *const EventTypeSpec,
        user_data: *mut c_void,
        handler_ref: *mut *mut c_void,
    ) -> OsStatus;
    fn RegisterEventHotKey(
        key_code: u32,
        modifiers: u32,
        id: EventHotKeyId,
        target: *mut c_void,
        options: u32,
        hotkey_ref: *mut *mut c_void,
    ) -> OsStatus;
    fn UnregisterEventHotKey(hotkey_ref: *mut c_void) -> OsStatus;
}

const KEYBOARD_EVENTS: u32 = u32::from_be_bytes(*b"keyb");
const HOTKEY_PRESSED: u32 = 5;
const SIGNATURE: u32 = u32::from_be_bytes(*b"bltw");
const HOTKEY_EXISTS: OsStatus = -9878;

const COMMAND: u32 = 1 << 8;
const SHIFT: u32 = 1 << 9;
const OPTION: u32 = 1 << 11;
const CONTROL: u32 = 1 << 12;

static ACTIVATE: OnceLock<mpsc::Sender<()>> = OnceLock::new();

thread_local! {
    // Main thread only: the registered hotkey and the shortcut it stands for.
    static CURRENT: RefCell<Option<(*mut c_void, Shortcut)>> = const { RefCell::new(None) };
}

extern "C" fn hotkey_pressed(_: *mut c_void, _: *mut c_void, _: *mut c_void) -> OsStatus {
    if let Some(activate) = ACTIVATE.get() {
        let _ = activate.send(());
    }
    0
}

pub struct Runtime {
    supported: bool,
}

impl Runtime {
    pub fn new(activate: mpsc::Sender<()>) -> Self {
        let _ = ACTIVATE.set(activate);
        let supported = main_thread::run(|| {
            let types = EventTypeSpec {
                event_class: KEYBOARD_EVENTS,
                event_kind: HOTKEY_PRESSED,
            };
            let status = unsafe {
                InstallEventHandler(
                    GetApplicationEventTarget(),
                    hotkey_pressed,
                    1,
                    &types,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            status == 0
        })
        .unwrap_or(false);
        Self { supported }
    }

    pub fn supported(&self) -> bool {
        self.supported
    }

    pub fn unavailable_message(&self) -> String {
        "macOS shortcut service unavailable".into()
    }

    pub fn apply(
        &mut self,
        _: Option<&Shortcut>,
        shortcut: Option<&Shortcut>,
    ) -> Result<(), String> {
        if !self.supported {
            return Err(self.unavailable_message());
        }
        let shortcut = shortcut.cloned();
        main_thread::run(move || replace(shortcut))?
    }
}

/// Registers the new shortcut before releasing the old one, so a rejected shortcut
/// leaves the previous one working.
fn replace(shortcut: Option<Shortcut>) -> Result<(), String> {
    CURRENT.with(|current| {
        let mut current = current.borrow_mut();
        if current.as_ref().map(|(_, active)| active) == shortcut.as_ref() {
            return Ok(());
        }
        let registered = match &shortcut {
            Some(shortcut) => Some((register(shortcut)?, shortcut.clone())),
            None => None,
        };
        if let Some((hotkey, _)) = current.take() {
            unsafe {
                UnregisterEventHotKey(hotkey);
            }
        }
        *current = registered;
        Ok(())
    })
}

fn register(shortcut: &Shortcut) -> Result<*mut c_void, String> {
    let key = key_code(&shortcut.key).ok_or("This key is not available on a Mac keyboard")?;
    let mut hotkey = std::ptr::null_mut();
    let status = unsafe {
        RegisterEventHotKey(
            key,
            modifiers(shortcut),
            EventHotKeyId {
                signature: SIGNATURE,
                id: 1,
            },
            GetApplicationEventTarget(),
            0,
            &mut hotkey,
        )
    };
    match status {
        0 => Ok(hotkey),
        HOTKEY_EXISTS => Err(format!(
            "{} is already used by another app; choose another shortcut",
            shortcut.label()
        )),
        status => Err(format!("macOS rejected the shortcut (error {status})")),
    }
}

fn modifiers(shortcut: &Shortcut) -> u32 {
    [
        (shortcut.ctrl, CONTROL),
        (shortcut.alt, OPTION),
        (shortcut.shift, SHIFT),
        (shortcut.super_key, COMMAND),
    ]
    .into_iter()
    .filter(|(pressed, _)| *pressed)
    .fold(0, |mask, (_, bit)| mask | bit)
}

/// Virtual key codes by position on an ANSI keyboard (Carbon's kVK_* constants).
pub fn key_code(key: &str) -> Option<u32> {
    const LETTERS: [u32; 26] = [
        0x00, 0x0B, 0x08, 0x02, 0x0E, 0x03, 0x05, 0x04, 0x22, 0x26, 0x28, 0x25, 0x2E, 0x2D, 0x1F,
        0x23, 0x0C, 0x0F, 0x01, 0x11, 0x20, 0x09, 0x0D, 0x07, 0x10, 0x06,
    ];
    const DIGITS: [u32; 10] = [0x1D, 0x12, 0x13, 0x14, 0x15, 0x17, 0x16, 0x1A, 0x1C, 0x19];
    const FUNCTION: [u32; 20] = [
        0x7A, 0x78, 0x63, 0x76, 0x60, 0x61, 0x62, 0x64, 0x65, 0x6D, 0x67, 0x6F, 0x69, 0x6B, 0x71,
        0x6A, 0x40, 0x4F, 0x50, 0x5A,
    ];
    match key.as_bytes() {
        [letter @ b'A'..=b'Z'] => Some(LETTERS[(letter - b'A') as usize]),
        [digit @ b'0'..=b'9'] => Some(DIGITS[(digit - b'0') as usize]),
        _ if key == "Space" => Some(0x31),
        _ => {
            let number = key.strip_prefix('F')?.parse::<usize>().ok()?;
            (key == format!("F{number}"))
                .then(|| FUNCTION.get(number.checked_sub(1)?).copied())
                .flatten()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_keys_to_ansi_key_codes() {
        assert_eq!(key_code("A"), Some(0x00));
        assert_eq!(key_code("B"), Some(0x0B));
        assert_eq!(key_code("Z"), Some(0x06));
        assert_eq!(key_code("0"), Some(0x1D));
        assert_eq!(key_code("9"), Some(0x19));
        assert_eq!(key_code("Space"), Some(0x31));
        assert_eq!(key_code("F1"), Some(0x7A));
        assert_eq!(key_code("F20"), Some(0x5A));
        assert_eq!(key_code("F21"), None);
        assert_eq!(key_code("F01"), None);
    }

    #[test]
    fn combines_modifiers() {
        let shortcut = Shortcut {
            ctrl: true,
            alt: true,
            shift: false,
            super_key: true,
            key: "B".into(),
        };
        assert_eq!(modifiers(&shortcut), CONTROL | OPTION | COMMAND);
    }
}

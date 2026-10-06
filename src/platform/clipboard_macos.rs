//! The general pasteboard. Copies stay on this Mac (no Universal Clipboard) and carry
//! the nspasteboard.org concealed marker, so clipboard managers skip them. Expiry
//! clears only contents we still own, never text copied later by another application.
use objc2::rc::autoreleasepool;
use objc2_app_kit::{NSPasteboard, NSPasteboardContentsOptions, NSPasteboardTypeString};
use objc2_foundation::{NSData, NSString};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const CLEAR_AFTER: Duration = Duration::from_secs(45);

const CONCEALED_TYPE: &str = "org.nspasteboard.ConcealedType";

/// Holds the pasteboard change count of our last copy while it may still be ours.
#[derive(Clone, Default)]
pub struct Clipboard(Arc<Mutex<Option<isize>>>);

impl Clipboard {
    pub fn copy(&self, text: &str) -> Result<(), String> {
        let mut owned = self.0.lock().map_err(|_| "Clipboard unavailable")?;
        let count = autoreleasepool(|_| write(&NSPasteboard::generalPasteboard(), text))?;
        *owned = Some(count);
        drop(owned);
        let clipboard = self.clone();
        std::thread::spawn(move || {
            std::thread::sleep(CLEAR_AFTER);
            clipboard.expire(count);
        });
        Ok(())
    }

    fn expire(&self, count: isize) {
        if let Ok(mut owned) = self.0.lock()
            && *owned == Some(count)
        {
            *owned = None;
            autoreleasepool(|_| clear_if_unchanged(&NSPasteboard::generalPasteboard(), count));
        }
    }

    pub fn clear(&self) {
        if let Ok(mut owned) = self.0.lock()
            && let Some(count) = owned.take()
        {
            autoreleasepool(|_| clear_if_unchanged(&NSPasteboard::generalPasteboard(), count));
        }
    }
}

/// Replaces the pasteboard contents and returns the change count that identifies them.
fn write(pasteboard: &NSPasteboard, text: &str) -> Result<isize, String> {
    pasteboard.prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly);
    // Publish the privacy marker before the secret text.
    let marker = NSString::from_str(CONCEALED_TYPE);
    let text = NSString::from_str(text);
    if !pasteboard.setData_forType(Some(&NSData::new()), &marker)
        || !pasteboard.setString_forType(&text, unsafe { NSPasteboardTypeString })
    {
        pasteboard.clearContents();
        return Err("Could not copy to the macOS pasteboard".into());
    }
    Ok(pasteboard.changeCount())
}

fn clear_if_unchanged(pasteboard: &NSPasteboard, count: isize) {
    if pasteboard.changeCount() == count {
        pasteboard.clearContents();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use objc2::rc::Retained;

    /// A private pasteboard, so tests never touch the user's clipboard.
    fn private_pasteboard() -> Retained<NSPasteboard> {
        NSPasteboard::pasteboardWithUniqueName()
    }

    fn release(pasteboard: Retained<NSPasteboard>) {
        let _: () = unsafe { objc2::msg_send![&*pasteboard, releaseGlobally] };
    }

    fn read(pasteboard: &NSPasteboard) -> Option<String> {
        pasteboard
            .stringForType(unsafe { NSPasteboardTypeString })
            .map(|text| text.to_string())
    }

    #[test]
    fn copy_is_concealed_and_clear_removes_it() {
        let pasteboard = private_pasteboard();
        let count = write(&pasteboard, "hunter2").unwrap();
        assert_eq!(read(&pasteboard).as_deref(), Some("hunter2"));
        let types = pasteboard.types().unwrap();
        assert!(types.iter().any(|kind| kind.to_string() == CONCEALED_TYPE));
        clear_if_unchanged(&pasteboard, count);
        assert_eq!(read(&pasteboard), None);
        release(pasteboard);
    }

    #[test]
    fn clear_keeps_text_copied_later_by_someone_else() {
        let pasteboard = private_pasteboard();
        let count = write(&pasteboard, "hunter2").unwrap();
        pasteboard.clearContents();
        pasteboard.setString_forType(&NSString::from_str("mine"), unsafe {
            NSPasteboardTypeString
        });
        clear_if_unchanged(&pasteboard, count);
        assert_eq!(read(&pasteboard).as_deref(), Some("mine"));
        release(pasteboard);
    }
}

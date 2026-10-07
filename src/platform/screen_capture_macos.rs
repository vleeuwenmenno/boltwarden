//! Best-effort macOS capture exclusion for this UI process's windows. NSWindowSharingNone
//! keeps them out of screenshots, screen recording, and screen sharing that honor it.
use objc2::MainThreadMarker;
use objc2_app_kit::{NSApplication, NSWindowSharingType};
use std::ffi::c_void;
use std::time::Duration;

pub fn available() -> bool {
    true
}

pub fn apply(obscure: bool) -> Result<(), String> {
    // The window may not exist yet when this runs during startup.
    for _ in 0..20 {
        if on_main_thread(move || apply_to_windows(obscure)) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("Window is not available for capture exclusion".into())
}

/// Sets the sharing type of every window of this process; false when there is none yet.
fn apply_to_windows(obscure: bool) -> bool {
    let Some(mtm) = MainThreadMarker::new() else {
        return false;
    };
    let sharing = if obscure {
        NSWindowSharingType::None
    } else {
        NSWindowSharingType::ReadOnly
    };
    let windows = NSApplication::sharedApplication(mtm).windows();
    for window in windows.iter() {
        window.setSharingType(sharing);
    }
    !windows.is_empty()
}

unsafe extern "C" {
    static _dispatch_main_q: c_void;
    fn dispatch_sync_f(
        queue: *const c_void,
        context: *mut c_void,
        work: extern "C" fn(*mut c_void),
    );
}

/// Runs `work` on the main thread and waits for it. AppKit windows may only be changed
/// there, while capture preferences are applied from worker threads.
fn on_main_thread<F: FnOnce() -> R + Send, R: Send>(work: F) -> R {
    if MainThreadMarker::new().is_some() {
        return work();
    }
    struct Job<F, R> {
        work: Option<F>,
        result: Option<R>,
    }
    extern "C" fn run<F: FnOnce() -> R, R>(context: *mut c_void) {
        let job = unsafe { &mut *(context as *mut Job<F, R>) };
        if let Some(work) = job.work.take() {
            job.result = Some(work());
        }
    }
    let mut job = Job {
        work: Some(work),
        result: None,
    };
    unsafe {
        dispatch_sync_f(
            &raw const _dispatch_main_q,
            (&mut job as *mut Job<F, R>).cast(),
            run::<F, R>,
        );
    }
    job.result.expect("the main queue ran the job")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_are_only_changed_on_the_main_thread() {
        // Test threads are not the main thread; AppKit must not be touched from them.
        assert!(MainThreadMarker::new().is_none());
        assert!(!apply_to_windows(true));
    }
}

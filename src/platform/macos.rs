//! macOS window behavior for quick access.
use objc2::MainThreadMarker;
use objc2_app_kit::{NSView, NSWindowCollectionBehavior};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};

/// Runs the process as an accessory app: no Dock icon, and its windows may appear over
/// another app's fullscreen Space instead of switching the user back to the desktop.
pub fn accessory_app(options: &mut eframe::NativeOptions) {
    options.event_loop_builder = Some(Box::new(|builder| {
        builder.with_activation_policy(ActivationPolicy::Accessory);
    }));
}

/// Lets the window open on whichever Space is active, including fullscreen apps.
pub fn join_all_spaces(window: &impl HasWindowHandle) {
    let Ok(handle) = window.window_handle() else {
        return;
    };
    let RawWindowHandle::AppKit(handle) = handle.as_raw() else {
        return;
    };
    if MainThreadMarker::new().is_none() {
        return;
    }
    // SAFETY: winit's AppKit handle points at the window's content view, used on the
    // main thread while the window is alive.
    let view = unsafe { handle.ns_view.cast::<NSView>().as_ref() };
    if let Some(window) = view.window() {
        window.setCollectionBehavior(
            NSWindowCollectionBehavior::CanJoinAllSpaces
                | NSWindowCollectionBehavior::FullScreenAuxiliary,
        );
    }
}

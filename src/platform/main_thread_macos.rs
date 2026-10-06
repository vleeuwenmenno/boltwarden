//! The daemon's main thread. AppKit and Carbon deliver menu bar clicks and hotkeys there,
//! so while the daemon waits for commands it pumps their events and runs work queued by
//! other threads.
use objc2::MainThreadMarker;
use objc2::rc::autoreleasepool;
use objc2_app_kit::{NSApplication, NSEventMask};
use objc2_foundation::{NSDate, NSDefaultRunLoopMode};
use std::sync::{LazyLock, Mutex, mpsc};
use std::time::Duration;

type Task = Box<dyn FnOnce() + Send>;

/// Work for the main thread. Work queued before its loop starts waits there.
static TASKS: LazyLock<(Mutex<mpsc::Sender<Task>>, Mutex<mpsc::Receiver<Task>>)> =
    LazyLock::new(|| {
        let (tx, rx) = mpsc::channel();
        (Mutex::new(tx), Mutex::new(rx))
    });

/// Runs `work` on the main thread and returns its result. Other threads wait until the
/// daemon's main thread picks the work up from its event loop.
pub fn run<R: Send + 'static>(work: impl FnOnce() -> R + Send + 'static) -> Result<R, String> {
    if MainThreadMarker::new().is_some() {
        return Ok(work());
    }
    let (reply, result) = mpsc::channel();
    TASKS
        .0
        .lock()
        .map_err(|_| "the main thread queue is unavailable")?
        .send(Box::new(move || {
            let _ = reply.send(work());
        }))
        .map_err(|_| "the main thread stopped")?;
    result
        .recv_timeout(Duration::from_secs(3))
        .map_err(|_| "the main thread did not respond".to_string())
}

/// Waits for the next message while handling AppKit events and queued work.
pub fn recv<T>(rx: &mpsc::Receiver<T>) -> Result<T, mpsc::RecvError> {
    let Some(mtm) = MainThreadMarker::new() else {
        return rx.recv();
    };
    let app = NSApplication::sharedApplication(mtm);
    loop {
        run_queued();
        match rx.try_recv() {
            Ok(message) => return Ok(message),
            Err(mpsc::TryRecvError::Disconnected) => return Err(mpsc::RecvError),
            Err(mpsc::TryRecvError::Empty) => pump(&app, Duration::from_millis(50)),
        }
    }
}

fn run_queued() {
    let tasks: Vec<Task> = match TASKS.1.lock() {
        Ok(queue) => queue.try_iter().collect(),
        Err(_) => return,
    };
    for task in tasks {
        task();
    }
}

/// Handles AppKit events, waiting up to `wait` for the first one.
pub fn pump(app: &NSApplication, wait: Duration) {
    autoreleasepool(|_| {
        let mut until = NSDate::dateWithTimeIntervalSinceNow(wait.as_secs_f64());
        while let Some(event) = app.nextEventMatchingMask_untilDate_inMode_dequeue(
            NSEventMask::Any,
            Some(&until),
            unsafe { NSDefaultRunLoopMode },
            true,
        ) {
            app.sendEvent(&event);
            until = NSDate::distantPast();
        }
    });
}

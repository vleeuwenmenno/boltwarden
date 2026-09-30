use futures_lite::StreamExt;
use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::Duration;
use zbus::{
    Connection, MatchRule, MessageStream, Proxy,
    zvariant::{OwnedObjectPath, OwnedValue},
};

const SERVICE: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
const MANAGER_INTERFACE: &str = "org.freedesktop.login1.Manager";
const HEARTBEAT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    pub locked: bool,
    pub idle: bool,
    pub idle_for: Option<Duration>,
}

#[derive(Debug)]
pub enum Event {
    State(SessionState),
    LockRequested(&'static str),
    Unavailable(String),
}

/// Signals are primary; timer ticks only advance idle deadlines and check liveness.
/// Every reconnect subscribes before reading state, so transitions cannot be missed.
pub fn subscribe() -> Receiver<Event> {
    let (sender, receiver) = mpsc::sync_channel(16);
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = sender.send(Event::Unavailable(error.to_string()));
                return;
            }
        };
        runtime.block_on(async {
            loop {
                let result = async {
                    let builder =
                        zbus::connection::Builder::system()?.method_timeout(Duration::from_secs(2));
                    let connection = tokio::time::timeout(Duration::from_secs(5), builder.build())
                        .await
                        .map_err(|_| {
                            zbus::Error::Failure("System bus connection timed out".into())
                        })??;
                    watch(
                        &connection,
                        &sender,
                        std::env::var("XDG_SESSION_ID").ok().as_deref(),
                    )
                    .await
                }
                .await;
                let message = result
                    .err()
                    .map(|e: zbus::Error| e.to_string())
                    .unwrap_or_else(|| "Session monitor disconnected".into());
                if sender.send(Event::Unavailable(message)).is_err() {
                    break;
                }
                tokio::time::sleep(HEARTBEAT).await;
            }
        });
    });
    receiver
}

async fn session_path(
    connection: &Connection,
    manager: &Proxy<'_>,
    owner: &str,
    id: Option<&str>,
) -> zbus::Result<OwnedObjectPath> {
    if let Some(id) = id.filter(|id| !id.is_empty()) {
        return manager.call("GetSession", &(id,)).await;
    }
    if let Ok(path) = manager
        .call("GetSessionByPID", &(std::process::id(),))
        .await
    {
        return Ok(path);
    }
    // User services may not belong to a login session. Select one active graphical
    // session for our uid; ambiguity is a failure, never an arbitrary first session.
    let sessions: Vec<(String, u32, String, String, OwnedObjectPath)> =
        manager.call("ListSessions", &()).await?;
    let mut candidates = Vec::new();
    for (_, uid, _, _, path) in sessions {
        if uid != crate::unix_socket::current_uid() {
            continue;
        }
        let session = Proxy::new(connection, owner, path.as_str(), SESSION_INTERFACE).await?;
        let kind: String = session.get_property("Type").await?;
        let active: bool = session.get_property("Active").await?;
        if active && matches!(kind.as_str(), "wayland" | "x11" | "mir") {
            candidates.push(path);
        }
    }
    if candidates.len() != 1 {
        return Err(zbus::Error::Failure(
            "Could not identify a single active desktop session".into(),
        ));
    }
    Ok(candidates.remove(0))
}

async fn properties(connection: &Connection, owner: &str, path: &str) -> zbus::Result<Hints> {
    let proxy = Proxy::new(connection, owner, path, "org.freedesktop.DBus.Properties").await?;
    let values: HashMap<String, OwnedValue> = proxy.call("GetAll", &(SESSION_INTERFACE,)).await?;
    Hints::from_values(&values)
}

#[derive(Debug)]
struct Hints {
    locked: bool,
    idle: bool,
    idle_since: u64,
}
impl Hints {
    fn from_values(values: &HashMap<String, OwnedValue>) -> zbus::Result<Self> {
        let missing = || zbus::Error::Failure("Session lock/idle properties unavailable".into());
        Ok(Self {
            locked: bool::try_from(values.get("LockedHint").ok_or_else(missing)?)
                .map_err(zbus::Error::from)?,
            idle: bool::try_from(values.get("IdleHint").ok_or_else(missing)?)
                .map_err(zbus::Error::from)?,
            idle_since: values
                .get("IdleSinceHintMonotonic")
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(0),
        })
    }
    fn state(&self) -> SessionState {
        SessionState {
            locked: self.locked,
            idle: self.idle,
            idle_for: if self.idle && self.idle_since != 0 {
                monotonic_uptime()
                    .and_then(|now| now.checked_sub(Duration::from_micros(self.idle_since)))
            } else {
                None
            },
        }
    }
}

async fn watch(
    connection: &Connection,
    sender: &SyncSender<Event>,
    id: Option<&str>,
) -> zbus::Result<()> {
    let bus = Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await?;
    let owner: String = bus.call("GetNameOwner", &(SERVICE,)).await?;
    let manager = Proxy::new(connection, owner.as_str(), MANAGER_PATH, MANAGER_INTERFACE).await?;
    let path = session_path(connection, &manager, &owner, id).await?;
    let rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(owner.as_str())?
        .path_namespace(MANAGER_PATH)?
        .build();
    let mut signals = MessageStream::for_match_rule(rule, connection, Some(64)).await?;
    let owner_rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender("org.freedesktop.DBus")?
        .interface("org.freedesktop.DBus")?
        .member("NameOwnerChanged")?
        .add_arg(SERVICE)?
        .build();
    let mut owners = MessageStream::for_match_rule(owner_rule, connection, Some(4)).await?;
    // Validate the selected session belongs to this uid even when provided through env.
    let session = Proxy::new(connection, owner.as_str(), path.as_str(), SESSION_INTERFACE).await?;
    let (uid, _): (u32, OwnedObjectPath) = session.get_property("User").await?;
    if uid != crate::unix_socket::current_uid() {
        return Err(zbus::Error::Failure(
            "Desktop session belongs to another user".into(),
        ));
    }
    let mut hints = properties(connection, &owner, path.as_str()).await?;
    let mut timer = tokio::time::interval(HEARTBEAT);
    loop {
        if sender.send(Event::State(hints.state())).is_err() {
            return Ok(());
        }
        tokio::select! {
            signal = signals.next() => {
                let message = signal.ok_or_else(|| zbus::Error::Failure("System bus disconnected".into()))??;
                let header = message.header();
                let interface = header.interface().map(|v| v.as_str());
                let member = header.member().map(|v| v.as_str());
                let signal_path = header.path().map(|v| v.as_str());
                let reason = match (interface, member, signal_path) {
                    (Some(SESSION_INTERFACE), Some("Lock"), Some(p)) if p == path.as_str() => Some("screen lock requested"),
                    (Some(MANAGER_INTERFACE), Some("PrepareForSleep"), Some(MANAGER_PATH)) => {
                        let (preparing,): (bool,) = message.body().deserialize()?;
                        preparing.then_some("system suspend requested")
                    }
                    (Some("org.freedesktop.DBus.Properties"), Some("PropertiesChanged"), Some(p)) if p == path.as_str() => {
                        let (changed_interface, changed, _): (String, HashMap<String, OwnedValue>, Vec<String>) = message.body().deserialize()?;
                        if changed_interface == SESSION_INTERFACE {
                            // Preserve a lock edge even if a subsequent unlock precedes GetAll.
                            if changed.get("LockedHint").and_then(|v| bool::try_from(v).ok()) == Some(true) {
                                if sender.send(Event::LockRequested("screen locked")).is_err() { return Ok(()); }
                            }
                            hints = properties(connection, &owner, path.as_str()).await?;
                        }
                        None
                    }
                    (Some(MANAGER_INTERFACE), Some("SessionRemoved"), Some(MANAGER_PATH)) => {
                        let (_, removed): (String, OwnedObjectPath) = message.body().deserialize()?;
                        if removed == path { return Err(zbus::Error::Failure("Desktop session ended".into())); }
                        None
                    }
                    _ => None,
                };
                if let Some(reason) = reason {
                    if sender.send(Event::LockRequested(reason)).is_err() { return Ok(()); }
                }
            }
            _ = owners.next() => return Err(zbus::Error::Failure("Login service restarted or disconnected".into())),
            _ = timer.tick() => {
                // A bounded owner lookup catches an unresponsive or disconnected bus.
                let current: String = bus.call("GetNameOwner", &(SERVICE,)).await?;
                if current != owner { return Err(zbus::Error::Failure("Login service changed".into())); }
            }
        }
    }
}

fn monotonic_uptime() -> Option<Duration> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return None;
    }
    Some(Duration::new(
        time.tv_sec.try_into().ok()?,
        time.tv_nsec.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_or_invalid_lock_properties_are_not_treated_as_unlocked() {
        let mut values = HashMap::new();
        values.insert("IdleHint".into(), OwnedValue::from(false));
        assert!(Hints::from_values(&values).is_err());
        values.insert("LockedHint".into(), OwnedValue::from(true));
        let state = Hints::from_values(&values).unwrap().state();
        assert!(state.locked);
        assert!(!state.idle);
        assert_eq!(state.idle_for, None);
        values.insert("LockedHint".into(), OwnedValue::from(1u32));
        assert!(Hints::from_values(&values).is_err());
    }
    #[test]
    fn idle_duration_uses_monotonic_hint_and_rejects_future_timestamp() {
        let mut hints = Hints {
            locked: false,
            idle: true,
            idle_since: 1,
        };
        assert!(hints.state().idle_for.is_some());
        hints.idle_since = u64::MAX;
        assert_eq!(hints.state().idle_for, None);
        hints.idle_since = 0;
        assert_eq!(hints.state().idle_for, None);
    }
    const TEST_PATH: &str = "/org/freedesktop/login1/session/test";
    struct FakeManager;
    #[zbus::interface(name = "org.freedesktop.login1.Manager")]
    impl FakeManager {
        fn get_session(&self, _id: &str) -> OwnedObjectPath {
            TEST_PATH.try_into().unwrap()
        }
    }
    struct FakeSession;
    #[zbus::interface(name = "org.freedesktop.login1.Session")]
    impl FakeSession {
        #[zbus(property)]
        fn locked_hint(&self) -> bool {
            false
        }
        #[zbus(property)]
        fn idle_hint(&self) -> bool {
            false
        }
        #[zbus(property)]
        fn idle_since_hint_monotonic(&self) -> u64 {
            0
        }
        #[zbus(property)]
        fn user(&self) -> (u32, OwnedObjectPath) {
            (
                crate::unix_socket::current_uid(),
                "/org/freedesktop/login1/user/test".try_into().unwrap(),
            )
        }
    }
    struct PrivateBus(std::process::Child);
    impl Drop for PrivateBus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    async fn next_lock(receiver: &Receiver<Event>) -> &'static str {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(Event::LockRequested(reason)) = receiver.try_recv() {
                    break reason;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("lock signal was not delivered")
    }
    #[test]
    fn private_bus_delivers_lock_suspend_and_disconnect_without_trusting_other_senders() {
        use std::io::BufRead;
        let child = std::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("dbus-daemon required for integration test");
        let mut bus = PrivateBus(child);
        let mut address = String::new();
        std::io::BufReader::new(bus.0.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let service = zbus::connection::Builder::address(address.trim())
                .unwrap()
                .name(SERVICE)
                .unwrap()
                .serve_at(MANAGER_PATH, FakeManager)
                .unwrap()
                .serve_at(TEST_PATH, FakeSession)
                .unwrap()
                .build()
                .await
                .unwrap();
            let client = zbus::connection::Builder::address(address.trim())
                .unwrap()
                .build()
                .await
                .unwrap();
            let impostor = zbus::connection::Builder::address(address.trim())
                .unwrap()
                .build()
                .await
                .unwrap();
            let (sender, receiver) = mpsc::sync_channel(32);
            let watcher = tokio::spawn(async move { watch(&client, &sender, Some("test")).await });
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Ok(Event::State(state)) = receiver.try_recv() {
                        assert!(!state.locked);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .expect("initial state missing");
            impostor
                .emit_signal(None::<&str>, TEST_PATH, SESSION_INTERFACE, "Lock", &())
                .await
                .unwrap();
            service
                .emit_signal(
                    None::<&str>,
                    "/org/freedesktop/login1/session/other",
                    SESSION_INTERFACE,
                    "Lock",
                    &(),
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                !receiver
                    .try_iter()
                    .any(|event| matches!(event, Event::LockRequested(_)))
            );
            service
                .emit_signal(None::<&str>, TEST_PATH, SESSION_INTERFACE, "Lock", &())
                .await
                .unwrap();
            assert_eq!(next_lock(&receiver).await, "screen lock requested");
            service
                .emit_signal(
                    None::<&str>,
                    MANAGER_PATH,
                    MANAGER_INTERFACE,
                    "PrepareForSleep",
                    &(true,),
                )
                .await
                .unwrap();
            assert_eq!(next_lock(&receiver).await, "system suspend requested");
            // The property's latest value is false, but its earlier true edge must still lock.
            let changed = HashMap::from([("LockedHint", OwnedValue::from(true))]);
            service
                .emit_signal(
                    None::<&str>,
                    TEST_PATH,
                    "org.freedesktop.DBus.Properties",
                    "PropertiesChanged",
                    &(SESSION_INTERFACE, changed, Vec::<String>::new()),
                )
                .await
                .unwrap();
            assert_eq!(next_lock(&receiver).await, "screen locked");
            service.release_name(SERVICE).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_secs(2), watcher)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
        });
    }
}

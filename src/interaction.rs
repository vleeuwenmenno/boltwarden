//! One desktop interaction at a time, shared by browser and SSH requests.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Browser,
    Ssh,
    Unlock,
}

struct Active {
    kind: Kind,
    expires: Instant,
    cancelled: AtomicBool,
}

#[derive(Clone)]
pub struct Lease(Arc<Active>, bool);

impl Lease {
    pub fn expired(&self) -> bool {
        Instant::now() >= self.0.expires || self.0.cancelled.load(Ordering::Acquire)
    }
    pub fn shared(&self) -> bool {
        self.1
    }
}

#[derive(Default)]
pub struct Gate(Mutex<Weak<Active>>);

impl Gate {
    pub fn acquire(&self, kind: Kind) -> Result<Lease, String> {
        let mut active = self.0.lock().map_err(|_| "Interaction gate unavailable")?;
        if let Some(current) = active.upgrade()
            && current.expires > Instant::now()
            && !current.cancelled.load(Ordering::Acquire)
        {
            return if current.kind == Kind::Unlock && kind == Kind::Unlock {
                Ok(Lease(current, true))
            } else {
                Err("Busy".into())
            };
        }
        let lease = Lease(
            Arc::new(Active {
                kind,
                expires: Instant::now()
                    + Duration::from_secs(if kind == Kind::Unlock { 120 } else { 60 }),
                cancelled: AtomicBool::new(false),
            }),
            false,
        );
        *active = Arc::downgrade(&lease.0);
        Ok(lease)
    }
    pub fn cancel(&self, kind: Kind) {
        if let Ok(mut active) = self.0.lock()
            && let Some(current) = active.upgrade()
            && current.kind == kind
        {
            current.cancelled.store(true, Ordering::Release);
            *active = Weak::new();
        }
    }
}

pub fn global() -> &'static Gate {
    static GATE: OnceLock<Gate> = OnceLock::new();
    GATE.get_or_init(Gate::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn competing_prompts_are_rejected_and_released() {
        let gate = Gate::default();
        let browser = gate.acquire(Kind::Browser).unwrap();
        assert!(gate.acquire(Kind::Ssh).is_err());
        assert!(gate.acquire(Kind::Unlock).is_err());
        drop(browser);
        assert!(gate.acquire(Kind::Ssh).is_ok());
    }

    #[test]
    fn unlock_waiters_share_ownership() {
        let gate = Gate::default();
        let first = gate.acquire(Kind::Unlock).unwrap();
        let second = gate.acquire(Kind::Unlock).unwrap();
        drop(first);
        assert!(gate.acquire(Kind::Browser).is_err());
        drop(second);
        assert!(gate.acquire(Kind::Browser).is_ok());
    }

    #[test]
    fn cancelling_unlock_invalidates_all_waiters_without_blocking_a_new_prompt() {
        let gate = Gate::default();
        let first = gate.acquire(Kind::Unlock).unwrap();
        let second = gate.acquire(Kind::Unlock).unwrap();
        assert!(!first.shared());
        assert!(second.shared());
        gate.cancel(Kind::Unlock);
        assert!(first.expired() && second.expired());
        let browser = gate.acquire(Kind::Browser).unwrap();
        drop(first);
        drop(second);
        assert!(gate.acquire(Kind::Unlock).is_err());
        drop(browser);
        assert!(gate.acquire(Kind::Unlock).is_ok());
    }
}

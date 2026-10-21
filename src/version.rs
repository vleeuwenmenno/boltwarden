//! Versions of this executable and its public browser integration API.
//! Release tags are checked against Cargo.toml by scripts/check-release.py.
/// Package version for release builds; local builds add git state (see build.rs).
pub const APP: &str = env!("BOLTWARDEN_VERSION");
pub const BROWSER_API: u8 = crate::browser::protocol::VERSION;

pub fn summary() -> String {
    format!("Boltwarden {APP} · Browser API v{BROWSER_API}")
}

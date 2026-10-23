//! Public release announcements for the desktop app and the browser extension.
//!
//! The daemon owns one [`ReleaseService`]. Its worker asks the fixed GitHub releases API of
//! the Boltwarden repository for public release metadata, at most once a day automatically
//! (unless disabled) and on request. Requests carry no cookies, tokens, account, vault or
//! page data. Only validated versions and publish times are kept; release links are built
//! locally from strictly parsed tags, so nothing from the response is rendered or opened.
//! Reading a snapshot never touches the network, so it is safe while vault locks are held.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const REPOSITORY_URL: &str = "https://github.com/vleeuwenmenno/boltwarden";
const API_URL: &str = "https://api.github.com/repos/vleeuwenmenno/boltwarden/releases";
const USER_AGENT: &str = "Boltwarden release checker";
const PER_PAGE: usize = 100;
/// The newest releases come first; three pages cover far more history than needed.
const MAX_PAGES: u32 = 3;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CHECK_DEADLINE: Duration = Duration::from_secs(30);

const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const MANUAL_INTERVAL: Duration = Duration::from_secs(60);
const RETRY_INTERVAL: Duration = Duration::from_secs(10 * 60);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(6 * 60 * 60);
/// Leave the network alone right after login; the daemon often starts with the session.
const STARTUP_DELAY: Duration = Duration::from_secs(30);
/// The worker also wakes on this interval, because the monotonic clock may not advance
/// while the computer sleeps and the wall clock can then show that a check is due.
const WORKER_WAKE: Duration = Duration::from_secs(15 * 60);
/// Successful data older than this is reported as stale.
const STALE_AFTER_SECS: u64 = 3 * 24 * 60 * 60;

const CACHE_FILE: &str = "release-check.json";
const DISMISSAL_FILE: &str = "release-dismissal.json";
const CACHE_SCHEMA: u32 = 1;
const MAX_STATE_FILE_BYTES: u64 = 16 * 1024;
const MAX_TAG_LEN: usize = 40;
/// Publish times outside 2015..2200 are treated as corrupt.
const MIN_TIMESTAMP: u64 = 1_420_070_400;
const MAX_TIMESTAMP: u64 = 7_258_118_400;

/// A desktop release version: `X.Y.Z` or `X.Y.Z-rc.N`, numeric parts without leading zeros.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DesktopVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// Release candidate number; a final release sorts after all of its candidates.
    pub rc: Option<u32>,
}

impl DesktopVersion {
    pub fn parse(text: &str) -> Option<Self> {
        let (core, rc) = match text.split_once("-rc.") {
            Some((core, rc)) => (core, Some(number(rc).filter(|rc| *rc > 0)?)),
            None => (text, None),
        };
        let (major, minor, patch) = triple(core)?;
        Some(Self {
            major,
            minor,
            patch,
            rc,
        })
    }

    pub fn is_preview(&self) -> bool {
        self.rc.is_some()
    }
}

impl Ord for DesktopVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then(match (self.rc, other.rc) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(left), Some(right)) => left.cmp(&right),
            })
    }
}

impl PartialOrd for DesktopVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for DesktopVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(rc) = self.rc {
            write!(f, "-rc.{rc}")?;
        }
        Ok(())
    }
}

/// A browser extension version: numeric `X.Y.Z` only, as the browser stores require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtensionVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ExtensionVersion {
    pub fn parse(text: &str) -> Option<Self> {
        let (major, minor, patch) = triple(text)?;
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl fmt::Display for ExtensionVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn number(text: &str) -> Option<u32> {
    let valid = !text.is_empty()
        && text.len() <= 9
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    valid.then(|| text.parse().ok()).flatten()
}

fn triple(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.split('.');
    let result = (
        number(parts.next()?)?,
        number(parts.next()?)?,
        number(parts.next()?)?,
    );
    parts.next().is_none().then_some(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Desktop(DesktopVersion),
    Extension(ExtensionVersion),
}

/// Only `vX.Y.Z[-rc.N]` and `extension-vX.Y.Z` tags are releases; anything else is ignored.
fn parse_tag(tag: &str) -> Option<Tag> {
    if tag.len() > MAX_TAG_LEN {
        return None;
    }
    if let Some(version) = tag.strip_prefix("extension-v") {
        return ExtensionVersion::parse(version).map(Tag::Extension);
    }
    DesktopVersion::parse(tag.strip_prefix('v')?).map(Tag::Desktop)
}

fn desktop_tag(version: DesktopVersion) -> String {
    format!("v{version}")
}

fn extension_tag(version: ExtensionVersion) -> String {
    format!("extension-v{version}")
}

/// The release page for a tag that was produced by this module from a parsed version.
fn release_url(tag: &str) -> String {
    format!("{REPOSITORY_URL}/releases/tag/{tag}")
}

/// The version this executable reports. Builds with metadata (`+3.gabc1234.dirty`) come
/// from a source checkout, not a release, and never claim an upgrade automatically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub text: String,
    pub version: Option<DesktopVersion>,
    pub development: bool,
}

impl Installed {
    pub fn parse(text: &str) -> Self {
        let (base, development) = match text.split_once('+') {
            Some((base, _)) => (base, true),
            None => (text, false),
        };
        Self {
            text: text.chars().take(64).collect(),
            version: DesktopVersion::parse(base),
            development,
        }
    }

    pub fn current() -> Self {
        Self::parse(crate::version::APP)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Published<V> {
    version: V,
    published_at: u64,
}

/// The newest releases found by one successful check.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Feed {
    checked_at: u64,
    /// The last page was reached, so every release was seen.
    complete: bool,
    stable: Option<Published<DesktopVersion>>,
    /// Newest desktop release including candidates.
    preview: Option<Published<DesktopVersion>>,
    extension: Option<Published<ExtensionVersion>>,
}

impl Feed {
    fn empty(checked_at: u64) -> Self {
        Self {
            checked_at,
            complete: false,
            stable: None,
            preview: None,
            extension: None,
        }
    }

    fn add(&mut self, entries: &[serde_json::Value]) {
        for entry in entries {
            let Some(entry) = entry.as_object() else {
                continue;
            };
            // Drafts are not public; require an explicit false and a publish time.
            if entry.get("draft") != Some(&serde_json::Value::Bool(false)) {
                continue;
            }
            let Some(published_at) = entry
                .get("published_at")
                .and_then(|value| value.as_str())
                .and_then(parse_timestamp)
            else {
                continue;
            };
            // GitHub's prerelease flag is ignored: the tag decides. Extension releases
            // are marked as prereleases while store review is pending.
            match entry
                .get("tag_name")
                .and_then(|value| value.as_str())
                .and_then(parse_tag)
            {
                Some(Tag::Desktop(version)) => {
                    let release = Published {
                        version,
                        published_at,
                    };
                    if !version.is_preview() {
                        keep_newest(&mut self.stable, release);
                    }
                    keep_newest(&mut self.preview, release);
                }
                Some(Tag::Extension(version)) => keep_newest(
                    &mut self.extension,
                    Published {
                        version,
                        published_at,
                    },
                ),
                None => {}
            }
        }
    }
}

impl Feed {
    /// Keeps the newest release per channel from `previous` and this feed.
    fn merge_known(&mut self, previous: &Feed) {
        if let Some(release) = previous.stable {
            keep_newest(&mut self.stable, release);
        }
        if let Some(release) = previous.preview {
            keep_newest(&mut self.preview, release);
        }
        if let Some(release) = previous.extension {
            keep_newest(&mut self.extension, release);
        }
    }
}

fn keep_newest<V: Ord + Copy>(slot: &mut Option<Published<V>>, release: Published<V>) {
    if slot.is_none_or(|current| release.version > current.version) {
        *slot = Some(release);
    }
}

/// Seconds since the Unix epoch for GitHub's `YYYY-MM-DDTHH:MM:SSZ` timestamps.
fn parse_timestamp(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    let field = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = text.get(range)?;
        part.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (year, month, day) = (field(0..4)?, field(5..7)?, field(8..10)?);
    let (hour, minute, second) = (field(11..13)?, field(14..16)?, field(17..19)?);
    let days_in_month = match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return None,
    };
    if !(1..=days_in_month).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = crate::health::days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(seconds)
        .ok()
        .filter(|seconds| (MIN_TIMESTAMP..MAX_TIMESTAMP).contains(seconds))
}

/// `YYYY-MM-DD` (UTC) for a Unix timestamp.
pub fn format_day(unix: u64) -> String {
    // Howard Hinnant's civil_from_days.
    let z = (unix / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------------------
// Public snapshot: shared by the desktop RPC and the browser Status response.

/// Overall check state. Release fields may still hold earlier data in every state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    /// This process does not check for releases (standalone popup, tests).
    Unsupported,
    /// No successful check yet and none failed.
    Empty,
    /// A check is queued or running.
    Checking,
    /// The last successful check is recent.
    Fresh,
    /// The last successful check is older than three days.
    Stale,
    /// The most recent attempt failed; earlier data is kept.
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseError {
    Network,
    RateLimited,
    HttpStatus,
    TooLarge,
    InvalidResponse,
}

impl ReleaseError {
    pub fn describe(self) -> &'static str {
        match self {
            Self::Network => "GitHub could not be reached",
            Self::RateLimited => "GitHub asked to retry later",
            Self::HttpStatus => "GitHub returned an error",
            Self::TooLarge => "the release list was too large",
            Self::InvalidResponse => "the release list could not be read",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopUpdate {
    /// `offer` is newer than the installed version on its channel.
    Available,
    UpToDate,
    /// Not checked, the installed version is not a release version, the channel has no
    /// release, or the list was cut off before proving the installed version is newest.
    Unknown,
    /// A source build; the latest releases are shown but never offered.
    Development,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub version: String,
    pub tag: String,
    /// Built locally from the validated tag.
    pub url: String,
    /// Seconds since the Unix epoch.
    pub published_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopReleases {
    pub installed: String,
    pub update: DesktopUpdate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer: Option<ReleaseInfo>,
    /// The offered version was dismissed on this computer.
    #[serde(default)]
    pub dismissed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable: Option<ReleaseInfo>,
    /// Newest desktop release including release candidates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<ReleaseInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseSnapshot {
    pub state: CheckState,
    pub auto_check: bool,
    /// Last successful check, seconds since the Unix epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<u64>,
    /// Every published release was seen; without it only a newer release can be proven.
    #[serde(default)]
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ReleaseError>,
    /// Seconds until a manual check (desktop Check now or the browser's
    /// `check_updates`) is accepted again, after the one-minute limit or a GitHub rate
    /// limit. Absent when a check can be requested now or one is already running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
    pub desktop: DesktopReleases,
    /// Newest published extension release. The extension compares its own version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<ReleaseInfo>,
}

impl ReleaseSnapshot {
    /// For processes without a release checker.
    pub fn unsupported() -> Self {
        let installed = Installed::current();
        Self {
            state: CheckState::Unsupported,
            auto_check: false,
            checked_at: None,
            complete: false,
            error: None,
            retry_after_seconds: None,
            desktop: DesktopReleases {
                installed: installed.text.clone(),
                update: if installed.development {
                    DesktopUpdate::Development
                } else {
                    DesktopUpdate::Unknown
                },
                offer: None,
                dismissed: false,
                stable: None,
                preview: None,
            },
            extension: None,
        }
    }

    /// Fixed data for demo mode; `BOLTWARDEN_DEMO=update` shows an available update.
    pub fn demo(offer_update: bool) -> Self {
        let mut snapshot = Self::unsupported();
        snapshot.state = CheckState::Empty;
        snapshot.auto_check = true;
        snapshot.desktop.installed = "1.0.0-rc.5".into();
        snapshot.desktop.update = DesktopUpdate::Unknown;
        if offer_update {
            let release = desktop_info(Published {
                version: DesktopVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                    rc: None,
                },
                published_at: 1_790_000_000,
            });
            snapshot.state = CheckState::Fresh;
            snapshot.checked_at = Some(1_790_000_000);
            snapshot.complete = true;
            snapshot.desktop.update = DesktopUpdate::Available;
            snapshot.desktop.offer = Some(release.clone());
            snapshot.desktop.stable = Some(release.clone());
            snapshot.desktop.preview = Some(release);
        }
        snapshot
    }

    /// The release a compact notice should announce, if any.
    pub fn notice(&self) -> Option<&ReleaseInfo> {
        (self.desktop.update == DesktopUpdate::Available && !self.desktop.dismissed)
            .then_some(self.desktop.offer.as_ref())
            .flatten()
    }
}

fn desktop_info(release: Published<DesktopVersion>) -> ReleaseInfo {
    let tag = desktop_tag(release.version);
    ReleaseInfo {
        version: release.version.to_string(),
        url: release_url(&tag),
        tag,
        published_at: release.published_at,
    }
}

fn extension_info(release: Published<ExtensionVersion>) -> ReleaseInfo {
    let tag = extension_tag(release.version);
    ReleaseInfo {
        version: release.version.to_string(),
        url: release_url(&tag),
        tag,
        published_at: release.published_at,
    }
}

/// The release to offer this installation: stable users only see final releases,
/// release candidate users follow the newest candidate or final release.
fn desktop_offer(
    installed: &Installed,
    feed: Option<&Feed>,
) -> (DesktopUpdate, Option<Published<DesktopVersion>>) {
    let (Some(version), Some(feed)) = (installed.version, feed) else {
        let update = if installed.development {
            DesktopUpdate::Development
        } else {
            DesktopUpdate::Unknown
        };
        return (update, None);
    };
    if installed.development {
        return (DesktopUpdate::Development, None);
    }
    let candidate = if version.is_preview() {
        feed.preview
    } else {
        feed.stable
    };
    match candidate {
        Some(release) if release.version > version => (DesktopUpdate::Available, Some(release)),
        Some(_) if feed.complete => (DesktopUpdate::UpToDate, None),
        _ => (DesktopUpdate::Unknown, None),
    }
}

// ---------------------------------------------------------------------------------------
// Fetching.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    Network,
    RateLimited(Option<Duration>),
    HttpStatus,
    TooLarge,
    InvalidResponse,
}

impl FetchError {
    fn kind(self) -> ReleaseError {
        match self {
            Self::Network => ReleaseError::Network,
            Self::RateLimited(_) => ReleaseError::RateLimited,
            Self::HttpStatus => ReleaseError::HttpStatus,
            Self::TooLarge => ReleaseError::TooLarge,
            Self::InvalidResponse => ReleaseError::InvalidResponse,
        }
    }
}

/// One page of the releases API. `budget` is the most bytes the page may have.
pub trait Fetch: Send + Sync {
    fn page(&self, page: u32, budget: usize, deadline: Instant) -> Result<Vec<u8>, FetchError>;
}

struct GitHub {
    client: reqwest::blocking::Client,
}

impl GitHub {
    fn new() -> Result<Self, FetchError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(USER_AGENT)
            .https_only(true)
            .build()
            .map_err(|_| FetchError::Network)?;
        Ok(Self { client })
    }
}

impl Fetch for GitHub {
    fn page(&self, page: u32, budget: usize, deadline: Instant) -> Result<Vec<u8>, FetchError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(FetchError::Network);
        }
        let mut response = self
            .client
            .get(format!("{API_URL}?per_page={PER_PAGE}&page={page}"))
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .timeout(remaining.min(REQUEST_TIMEOUT))
            .send()
            .map_err(|_| FetchError::Network)?;
        let status = response.status();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
        };
        let retry_after = header("retry-after").and_then(|value| value.parse::<u64>().ok());
        let exhausted = header("x-ratelimit-remaining") == Some("0");
        let reset = header("x-ratelimit-reset").and_then(|value| value.parse::<u64>().ok());
        if status.as_u16() == 429
            || (status.as_u16() == 403 && (exhausted || retry_after.is_some()))
        {
            let delay = retry_after.or_else(|| reset.map(|reset| reset.saturating_sub(unix_now())));
            return Err(FetchError::RateLimited(delay.map(Duration::from_secs)));
        }
        if !status.is_success() {
            return Err(FetchError::HttpStatus);
        }
        if response
            .content_length()
            .is_some_and(|length| length > budget as u64)
        {
            return Err(FetchError::TooLarge);
        }
        let mut body = Vec::new();
        (&mut response)
            .take(budget as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| FetchError::Network)?;
        if body.len() > budget {
            return Err(FetchError::TooLarge);
        }
        Ok(body)
    }
}

/// Reads up to three pages of releases within the size and time budget.
fn run_check(fetch: &dyn Fetch, now: u64) -> Result<Feed, FetchError> {
    let deadline = Instant::now() + CHECK_DEADLINE;
    let mut budget = MAX_RESPONSE_BYTES;
    let mut feed = Feed::empty(now);
    for page in 1..=MAX_PAGES {
        if Instant::now() >= deadline {
            return Err(FetchError::Network);
        }
        let body = fetch.page(page, budget, deadline)?;
        if body.len() > budget {
            return Err(FetchError::TooLarge);
        }
        budget -= body.len();
        let entries: Vec<serde_json::Value> =
            serde_json::from_slice(&body).map_err(|_| FetchError::InvalidResponse)?;
        if entries.len() > PER_PAGE {
            return Err(FetchError::InvalidResponse);
        }
        feed.add(&entries);
        if entries.len() < PER_PAGE {
            feed.complete = true;
            break;
        }
    }
    Ok(feed)
}

// ---------------------------------------------------------------------------------------
// Persistence: the last successful result and the dismissed desktop version.

#[derive(Debug, Serialize, Deserialize)]
struct CacheFile {
    schema: u32,
    checked_at: u64,
    complete: bool,
    #[serde(default)]
    desktop_stable: Option<CachedRelease>,
    #[serde(default)]
    desktop_preview: Option<CachedRelease>,
    #[serde(default)]
    extension: Option<CachedRelease>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedRelease {
    tag: String,
    published_at: u64,
}

impl CacheFile {
    fn from_feed(feed: &Feed) -> Self {
        let desktop = |release: Option<Published<DesktopVersion>>| {
            release.map(|release| CachedRelease {
                tag: desktop_tag(release.version),
                published_at: release.published_at,
            })
        };
        Self {
            schema: CACHE_SCHEMA,
            checked_at: feed.checked_at,
            complete: feed.complete,
            desktop_stable: desktop(feed.stable),
            desktop_preview: desktop(feed.preview),
            extension: feed.extension.map(|release| CachedRelease {
                tag: extension_tag(release.version),
                published_at: release.published_at,
            }),
        }
    }

    /// Revalidates every field. A check time in the future cannot be trusted: keep the
    /// releases but date the check past the stale limit, so a check is due right away and
    /// the old data never proves "up to date". Clamping to now instead would restart the
    /// one-day wait on every daemon start until the clock reached the bogus date.
    fn into_feed(self, now: u64) -> Option<Feed> {
        if self.schema != CACHE_SCHEMA || self.checked_at < MIN_TIMESTAMP {
            return None;
        }
        let timestamp = |at: u64| (MIN_TIMESTAMP..MAX_TIMESTAMP).contains(&at).then_some(at);
        let desktop = |release: Option<CachedRelease>, preview: bool| match release {
            None => Some(None),
            Some(release) => match parse_tag(&release.tag)? {
                Tag::Desktop(version) if preview || !version.is_preview() => {
                    Some(Some(Published {
                        version,
                        published_at: timestamp(release.published_at)?,
                    }))
                }
                _ => None,
            },
        };
        let extension = match self.extension {
            None => None,
            Some(release) => match parse_tag(&release.tag)? {
                Tag::Extension(version) => Some(Published {
                    version,
                    published_at: timestamp(release.published_at)?,
                }),
                Tag::Desktop(_) => return None,
            },
        };
        let stable = desktop(self.desktop_stable, false)?;
        let preview = desktop(self.desktop_preview, true)?;
        if stable
            .is_some_and(|stable| preview.is_none_or(|preview| preview.version < stable.version))
        {
            return None;
        }
        Some(Feed {
            checked_at: if self.checked_at > now {
                now.saturating_sub(STALE_AFTER_SECS + 1)
            } else {
                self.checked_at
            },
            complete: self.complete,
            stable,
            preview,
            extension,
        })
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct DismissalFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    desktop: Option<String>,
}

#[derive(Debug, Clone)]
struct Paths {
    cache: Option<PathBuf>,
    dismissal: Option<PathBuf>,
}

impl Paths {
    fn standard() -> Self {
        Self {
            cache: crate::config::cache_dir().map(|dir| dir.join(CACHE_FILE)),
            dismissal: crate::config::config_path(DISMISSAL_FILE),
        }
    }
}

fn read_bounded(path: &Path) -> Option<Vec<u8>> {
    let file = std::fs::File::open(path).ok()?;
    let mut data = Vec::new();
    file.take(MAX_STATE_FILE_BYTES + 1)
        .read_to_end(&mut data)
        .ok()?;
    (data.len() as u64 <= MAX_STATE_FILE_BYTES).then_some(data)
}

fn load_feed(path: Option<&Path>, now: u64) -> Option<Feed> {
    let data = read_bounded(path?)?;
    serde_json::from_slice::<CacheFile>(&data)
        .ok()?
        .into_feed(now)
}

fn load_dismissal(path: Option<&Path>) -> Option<DesktopVersion> {
    let data = read_bounded(path?)?;
    let file: DismissalFile = serde_json::from_slice(&data).ok()?;
    DesktopVersion::parse(&file.desktop?)
}

fn write_json<T: Serialize>(path: Option<&Path>, value: &T) -> std::io::Result<()> {
    let path = path.ok_or_else(|| std::io::Error::other("storage directory unavailable"))?;
    let data = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    crate::config::write_private_path(path, &data)
}

// ---------------------------------------------------------------------------------------
// Scheduling.

#[derive(Debug)]
struct State {
    feed: Option<Feed>,
    dismissed: Option<DesktopVersion>,
    auto_check: bool,
    in_flight: bool,
    manual_pending: bool,
    error: Option<ReleaseError>,
    started: Instant,
    last_attempt: Option<Instant>,
    last_success: Option<Instant>,
    /// Automatic checks wait until then after a failure.
    retry_at: Option<Instant>,
    /// Every check waits until then after GitHub's rate limit answered.
    rate_limited_until: Option<Instant>,
}

impl State {
    fn new(
        feed: Option<Feed>,
        dismissed: Option<DesktopVersion>,
        auto: bool,
        now: Instant,
    ) -> Self {
        Self {
            feed,
            dismissed,
            auto_check: auto,
            in_flight: false,
            manual_pending: false,
            error: None,
            started: now,
            last_attempt: None,
            last_success: None,
            retry_at: None,
            rate_limited_until: None,
        }
    }

    fn rate_limited(&self, mono: Instant) -> bool {
        self.rate_limited_until.is_some_and(|until| mono < until)
    }

    fn auto_due(&self, wall: u64, mono: Instant) -> bool {
        if !self.auto_check
            || self.in_flight
            || self.rate_limited(mono)
            || self.retry_at.is_some_and(|at| mono < at)
            || mono.duration_since(self.started) < STARTUP_DELAY
            || self
                .last_attempt
                .is_some_and(|at| mono.duration_since(at) < RETRY_INTERVAL)
        {
            return false;
        }
        let Some(feed) = &self.feed else {
            return true;
        };
        // The wall clock catches up after sleep; the monotonic clock survives clock changes.
        wall.saturating_sub(feed.checked_at) >= CHECK_INTERVAL.as_secs()
            || self
                .last_success
                .is_some_and(|at| mono.duration_since(at) >= CHECK_INTERVAL)
    }

    /// How long until a manual check is accepted; `None` when it is accepted now or one is
    /// already queued or running.
    fn manual_wait(&self, mono: Instant) -> Option<Duration> {
        if self.in_flight || self.manual_pending {
            return None;
        }
        let until = |at: Instant| at.saturating_duration_since(mono);
        let wait = self
            .last_attempt
            .map(|at| until(at + MANUAL_INTERVAL))
            .unwrap_or_default()
            .max(self.rate_limited_until.map(until).unwrap_or_default());
        (!wait.is_zero()).then_some(wait)
    }

    /// Queues a user-requested check. Returns false when one ran too recently.
    fn request_manual(&mut self, mono: Instant) -> bool {
        if self.in_flight || self.manual_pending {
            return true;
        }
        if self.manual_wait(mono).is_some() {
            return false;
        }
        self.manual_pending = true;
        true
    }

    fn begin(&mut self, wall: u64, mono: Instant) -> bool {
        if self.in_flight || !(self.manual_pending || self.auto_due(wall, mono)) {
            return false;
        }
        self.manual_pending = false;
        self.in_flight = true;
        self.last_attempt = Some(mono);
        true
    }

    /// Records a finished check; returns the feed to persist after a success.
    fn finish(&mut self, result: Result<Feed, FetchError>, mono: Instant) -> Option<Feed> {
        self.in_flight = false;
        match result {
            Ok(mut feed) => {
                // Three pages may not reach an older release that is still the newest of
                // its channel. Only a complete list may forget known releases.
                if !feed.complete
                    && let Some(previous) = &self.feed
                {
                    feed.merge_known(previous);
                }
                self.error = None;
                self.retry_at = None;
                self.rate_limited_until = None;
                self.last_success = Some(mono);
                self.feed = Some(feed.clone());
                Some(feed)
            }
            Err(error) => {
                self.error = Some(error.kind());
                let delay = match error {
                    FetchError::RateLimited(delay) => {
                        let delay = delay
                            .unwrap_or(RETRY_INTERVAL)
                            .clamp(RETRY_INTERVAL, MAX_RETRY_DELAY);
                        self.rate_limited_until = Some(mono + delay);
                        delay
                    }
                    _ => RETRY_INTERVAL,
                };
                self.retry_at = Some(mono + delay);
                None
            }
        }
    }

    fn snapshot(&self, installed: &Installed, wall: u64, mono: Instant) -> ReleaseSnapshot {
        let feed = self.feed.as_ref();
        let state = if self.in_flight || self.manual_pending {
            CheckState::Checking
        } else if self.error.is_some() {
            CheckState::Error
        } else {
            match feed {
                None => CheckState::Empty,
                Some(feed) if wall.saturating_sub(feed.checked_at) > STALE_AFTER_SECS => {
                    CheckState::Stale
                }
                Some(_) => CheckState::Fresh,
            }
        };
        let (mut update, offer) = desktop_offer(installed, feed);
        // Only a recent, successful, complete check with no failure or check in progress
        // since can show that nothing newer exists; a known newer release stays offered.
        if update == DesktopUpdate::UpToDate && state != CheckState::Fresh {
            update = DesktopUpdate::Unknown;
        }
        ReleaseSnapshot {
            state,
            auto_check: self.auto_check,
            checked_at: feed.map(|feed| feed.checked_at),
            complete: feed.is_some_and(|feed| feed.complete),
            error: self.error,
            // Round up so a client never retries a moment too early.
            retry_after_seconds: self
                .manual_wait(mono)
                .map(|wait| wait.as_secs() + u64::from(wait.subsec_nanos() > 0)),
            desktop: DesktopReleases {
                installed: installed.text.clone(),
                update,
                dismissed: offer.is_some_and(|offer| Some(offer.version) == self.dismissed),
                offer: offer.map(desktop_info),
                stable: feed.and_then(|feed| feed.stable).map(desktop_info),
                preview: feed.and_then(|feed| feed.preview).map(desktop_info),
            },
            extension: feed.and_then(|feed| feed.extension).map(extension_info),
        }
    }
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
    installed: Installed,
    paths: Paths,
}

/// The daemon's release checker. Cloning shares it; the default checks nothing.
#[derive(Clone, Default)]
pub struct ReleaseService {
    shared: Option<Arc<Shared>>,
}

impl ReleaseService {
    /// A service that never checks; its snapshot reports [`CheckState::Unsupported`].
    pub fn unsupported() -> Self {
        Self::default()
    }

    /// Loads cached results and starts the worker thread. Only the real daemon calls this.
    pub fn start() -> Self {
        let auto = crate::config::load_settings().check_for_updates;
        let service = Self::with_paths(Paths::standard(), Installed::current(), auto);
        if let Some(shared) = service.shared.clone() {
            let spawned = std::thread::Builder::new()
                .name("release-check".into())
                .spawn(move || {
                    let fetch: Box<dyn Fetch> = match GitHub::new() {
                        Ok(github) => Box::new(github),
                        Err(error) => Box::new(Failing(error)),
                    };
                    worker(&shared, fetch.as_ref());
                });
            if let Err(error) = spawned {
                eprintln!("release checks unavailable: {error}");
                return Self::unsupported();
            }
        }
        service
    }

    /// A service without a worker, for tests elsewhere in the crate. `checked_today`
    /// pretends a successful check just ran, so no automatic check is due.
    #[cfg(test)]
    pub(crate) fn for_tests(auto: bool, checked_today: bool) -> Self {
        let dir =
            crate::test_temp_dir().join(format!("boltwarden-releases-{}", uuid::Uuid::new_v4()));
        let paths = Paths {
            cache: Some(dir.join(CACHE_FILE)),
            dismissal: Some(dir.join(DISMISSAL_FILE)),
        };
        let service = Self::with_paths(paths, Installed::parse("1.0.0"), auto);
        if checked_today && let Some(shared) = &service.shared {
            let mut state = shared.state.lock().unwrap();
            state.feed = Some(Feed::empty(unix_now()));
            state.last_success = Some(Instant::now());
        }
        service
    }

    #[cfg(test)]
    pub(crate) fn has_queued_check(&self) -> bool {
        self.shared
            .as_ref()
            .is_some_and(|shared| shared.state.lock().unwrap().manual_pending)
    }

    fn with_paths(paths: Paths, installed: Installed, auto: bool) -> Self {
        let now = unix_now();
        let state = State::new(
            load_feed(paths.cache.as_deref(), now),
            load_dismissal(paths.dismissal.as_deref()),
            auto,
            Instant::now(),
        );
        Self {
            shared: Some(Arc::new(Shared {
                state: Mutex::new(state),
                wake: Condvar::new(),
                installed,
                paths,
            })),
        }
    }

    /// Cheap and network-free.
    pub fn snapshot(&self) -> ReleaseSnapshot {
        let Some(shared) = &self.shared else {
            return ReleaseSnapshot::unsupported();
        };
        match shared.state.lock() {
            Ok(state) => state.snapshot(&shared.installed, unix_now(), Instant::now()),
            Err(_) => ReleaseSnapshot::unsupported(),
        }
    }

    /// Queues a check now, unless one ran within the last minute or GitHub asked to wait.
    /// Works when automatic checks are off. The result arrives in a later snapshot.
    pub fn check_now(&self) -> ReleaseSnapshot {
        if let Some(shared) = &self.shared
            && let Ok(mut state) = shared.state.lock()
            && state.request_manual(Instant::now())
        {
            shared.wake.notify_all();
        }
        self.snapshot()
    }

    pub fn set_auto_check(&self, enabled: bool) {
        if let Some(shared) = &self.shared
            && let Ok(mut state) = shared.state.lock()
        {
            state.auto_check = enabled;
            shared.wake.notify_all();
        }
    }

    /// Hides the notice for the desktop version currently offered, here and in quick access.
    pub fn dismiss(&self, version: &str) -> Result<ReleaseSnapshot, String> {
        let shared = self
            .shared
            .as_ref()
            .ok_or_else(|| "Release checks are unavailable".to_string())?;
        let version = DesktopVersion::parse(version).ok_or("Invalid release version")?;
        {
            let mut state = shared
                .state
                .lock()
                .map_err(|_| "Release state unavailable")?;
            let (_, offer) = desktop_offer(&shared.installed, state.feed.as_ref());
            if offer.is_none_or(|offer| offer.version != version) {
                return Err("That release is no longer offered".into());
            }
            state.dismissed = Some(version);
        }
        write_json(
            shared.paths.dismissal.as_deref(),
            &DismissalFile {
                desktop: Some(version.to_string()),
            },
        )
        .map_err(|error| format!("Could not save the dismissal: {error}"))?;
        Ok(self.snapshot())
    }

    /// Runs one check now if one is queued or due. Returns whether a check ran.
    fn step(&self, fetch: &dyn Fetch, wall: u64, mono: Instant) -> bool {
        let Some(shared) = &self.shared else {
            return false;
        };
        let Ok(mut state) = shared.state.lock() else {
            return false;
        };
        if !state.begin(wall, mono) {
            return false;
        }
        drop(state);
        let result = run_check(fetch, wall);
        let persist = match shared.state.lock() {
            Ok(mut state) => state.finish(result, Instant::now().max(mono)),
            Err(_) => return true,
        };
        if let Some(feed) = persist
            && let Err(error) =
                write_json(shared.paths.cache.as_deref(), &CacheFile::from_feed(&feed))
        {
            eprintln!("could not save release check: {error}");
        }
        true
    }
}

struct Failing(FetchError);

impl Fetch for Failing {
    fn page(&self, _: u32, _: usize, _: Instant) -> Result<Vec<u8>, FetchError> {
        Err(self.0)
    }
}

fn worker(shared: &Arc<Shared>, fetch: &dyn Fetch) {
    let service = ReleaseService {
        shared: Some(shared.clone()),
    };
    loop {
        // Read outside the state lock: the settings file is the source of truth.
        let auto = crate::config::load_settings().check_for_updates;
        if let Ok(mut state) = shared.state.lock() {
            state.auto_check = auto;
        }
        if service.step(fetch, unix_now(), Instant::now()) {
            continue;
        }
        let Ok(state) = shared.state.lock() else {
            return;
        };
        let wait = if state.manual_pending {
            Duration::ZERO
        } else {
            let startup = STARTUP_DELAY.saturating_sub(state.started.elapsed());
            if startup.is_zero() {
                WORKER_WAKE
            } else {
                startup
            }
        };
        if !wait.is_zero() {
            let _ = shared.wake.wait_timeout(state, wait);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    const NOW: u64 = 1_790_000_000;

    fn release(
        tag: &str,
        draft: bool,
        prerelease: bool,
        published: Option<&str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "tag_name": tag,
            "draft": draft,
            "prerelease": prerelease,
            "published_at": published,
            "body": "<script>ignored</script>",
            "html_url": "https://evil.example/",
        })
    }

    fn published(tag: &str) -> serde_json::Value {
        release(tag, false, false, Some("2026-09-01T10:00:00Z"))
    }

    fn feed_of(entries: &[serde_json::Value]) -> Feed {
        let mut feed = Feed::empty(NOW);
        feed.add(entries);
        feed.complete = true;
        feed
    }

    fn installed(text: &str) -> Installed {
        Installed::parse(text)
    }

    struct Pages {
        pages: Vec<Result<Vec<u8>, FetchError>>,
        calls: AtomicUsize,
    }

    impl Pages {
        fn new(pages: Vec<Result<Vec<u8>, FetchError>>) -> Self {
            Self {
                pages,
                calls: AtomicUsize::new(0),
            }
        }
        fn json(pages: Vec<Vec<serde_json::Value>>) -> Self {
            Self::new(
                pages
                    .into_iter()
                    .map(|page| Ok(serde_json::to_vec(&page).unwrap()))
                    .collect(),
            )
        }
    }

    impl Fetch for Pages {
        fn page(&self, page: u32, budget: usize, _: Instant) -> Result<Vec<u8>, FetchError> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            let body = self.pages[page as usize - 1].clone()?;
            if body.len() > budget {
                return Err(FetchError::TooLarge);
            }
            Ok(body)
        }
    }

    fn temp_paths() -> Paths {
        let dir =
            crate::test_temp_dir().join(format!("boltwarden-releases-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Paths {
            cache: Some(dir.join(CACHE_FILE)),
            dismissal: Some(dir.join(DISMISSAL_FILE)),
        }
    }

    fn service(paths: &Paths, installed_version: &str, auto: bool) -> ReleaseService {
        ReleaseService::with_paths(paths.clone(), installed(installed_version), auto)
    }

    fn state_of(service: &ReleaseService) -> std::sync::MutexGuard<'_, State> {
        service.shared.as_ref().unwrap().state.lock().unwrap()
    }

    fn v(text: &str) -> DesktopVersion {
        DesktopVersion::parse(text).unwrap()
    }

    #[test]
    fn parses_strict_versions_and_tags() {
        assert_eq!(
            v("1.2.3"),
            DesktopVersion {
                major: 1,
                minor: 2,
                patch: 3,
                rc: None
            }
        );
        assert_eq!(v("1.0.0-rc.10").rc, Some(10));
        for invalid in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.3-rc.0",
            "1.2.3-rc.01",
            "1.2.3-rc",
            "1.2.3-beta.1",
            "1.2.3-rc.1.2",
            " 1.2.3",
            "1.2.3+build",
            "-1.2.3",
            "1.2.3-rc.-1",
            "9999999999.0.0",
            "１.2.3",
        ] {
            assert_eq!(DesktopVersion::parse(invalid), None, "{invalid}");
        }
        assert_eq!(
            parse_tag("v1.0.0-rc.5"),
            Some(Tag::Desktop(v("1.0.0-rc.5")))
        );
        assert_eq!(
            parse_tag("extension-v0.5.10"),
            Some(Tag::Extension(ExtensionVersion {
                major: 0,
                minor: 5,
                patch: 10
            }))
        );
        for ignored in [
            "1.0.0",
            "V1.0.0",
            "v1.0.0 ",
            "extension-v0.5.10-rc.1",
            "extension-0.5.10",
            "browser-v1.0.0",
            "vv1.0.0",
            "extension-v1.2",
            "v1.0.0/../../x",
        ] {
            assert_eq!(parse_tag(ignored), None, "{ignored}");
        }
        assert_eq!(parse_tag(&format!("v1.0.0-rc.{}", "1".repeat(40))), None);
    }

    #[test]
    fn orders_versions_numerically_with_final_after_candidates() {
        assert!(v("1.0.0-rc.10") > v("1.0.0-rc.9"));
        assert!(v("1.0.0") > v("1.0.0-rc.10"));
        assert!(v("1.0.1-rc.1") > v("1.0.0"));
        assert!(v("1.10.0") > v("1.9.9"));
        assert!(v("2.0.0-rc.1") > v("1.99.99"));
        let extension = |text| ExtensionVersion::parse(text).unwrap();
        assert!(extension("0.5.10") > extension("0.5.9"));
        assert!(extension("1.0.0") > extension("0.99.99"));
    }

    #[test]
    fn recognizes_development_builds_by_metadata() {
        let release = installed("1.0.0-rc.5");
        assert_eq!(release.version, Some(v("1.0.0-rc.5")));
        assert!(!release.development);
        let dev = installed("1.0.0-rc.4+3.gabc1234.dirty");
        assert_eq!(dev.version, Some(v("1.0.0-rc.4")));
        assert!(dev.development);
        let untagged = installed("1.0.0-rc.1+gabc1234.untagged");
        assert!(untagged.development);
        assert_eq!(installed("nonsense").version, None);
    }

    #[test]
    fn selects_releases_ignoring_drafts_flags_and_invalid_entries() {
        let feed = feed_of(&[
            release("v9.0.0", true, false, Some("2026-09-01T10:00:00Z")),
            release("v8.0.0", false, false, None),
            serde_json::json!({"tag_name": "v7.0.0", "published_at": "2026-09-01T10:00:00Z"}),
            serde_json::json!({"tag_name": 5, "draft": false}),
            serde_json::json!("not an object"),
            release("v6.0.0", false, false, Some("yesterday")),
            published("v1.0.0-rc.10"),
            published("v1.0.0-rc.9"),
            // A final release wrongly marked as a prerelease still counts as stable.
            release("v0.4.0", false, true, Some("2026-01-01T00:00:00Z")),
            // Extension releases are prereleases on GitHub while store review is pending.
            release(
                "extension-v0.5.10",
                false,
                true,
                Some("2026-09-02T00:00:00Z"),
            ),
            published("extension-v0.5.9"),
            published("nightly"),
        ]);
        assert_eq!(feed.stable.map(|r| r.version), Some(v("0.4.0")));
        assert_eq!(feed.preview.map(|r| r.version), Some(v("1.0.0-rc.10")));
        assert_eq!(
            feed.extension.map(|r| r.version.to_string()),
            Some("0.5.10".into())
        );
        assert_eq!(feed.extension.unwrap().published_at, 1_788_307_200);
    }

    #[test]
    fn offers_finals_to_stable_users_and_candidates_to_testers() {
        let feed = feed_of(&[
            published("v1.0.0"),
            published("v1.1.0-rc.2"),
            published("v0.9.0"),
        ]);
        let offer = |text| {
            let (update, offer) = desktop_offer(&installed(text), Some(&feed));
            (update, offer.map(|offer| offer.version.to_string()))
        };
        assert_eq!(
            offer("0.9.0"),
            (DesktopUpdate::Available, Some("1.0.0".into()))
        );
        assert_eq!(offer("1.0.0"), (DesktopUpdate::UpToDate, None));
        assert_eq!(
            offer("1.0.0-rc.5"),
            (DesktopUpdate::Available, Some("1.1.0-rc.2".into()))
        );
        assert_eq!(offer("1.1.0-rc.2"), (DesktopUpdate::UpToDate, None));
        assert_eq!(offer("2.0.0"), (DesktopUpdate::UpToDate, None));
        assert_eq!(offer("1.0.0+3.gabc"), (DesktopUpdate::Development, None));
        assert_eq!(offer("garbage"), (DesktopUpdate::Unknown, None));
        // An RC tester moves on to the final release once it is the newest.
        let final_feed = feed_of(&[published("v1.0.0"), published("v1.0.0-rc.5")]);
        assert_eq!(
            desktop_offer(&installed("1.0.0-rc.5"), Some(&final_feed))
                .1
                .map(|r| r.version),
            Some(v("1.0.0"))
        );
        // A stable user with only candidates published is never offered one.
        let rc_only = feed_of(&[published("v2.0.0-rc.1")]);
        assert_eq!(
            desktop_offer(&installed("1.0.0"), Some(&rc_only)),
            (DesktopUpdate::Unknown, None)
        );
        assert_eq!(
            desktop_offer(&installed("1.0.0"), None),
            (DesktopUpdate::Unknown, None)
        );
    }

    #[test]
    fn incomplete_feed_proves_newer_releases_but_never_up_to_date() {
        let mut feed = feed_of(&[published("v1.0.0")]);
        feed.complete = false;
        assert_eq!(
            desktop_offer(&installed("1.0.0"), Some(&feed)).0,
            DesktopUpdate::Unknown
        );
        assert_eq!(
            desktop_offer(&installed("0.9.0"), Some(&feed)).0,
            DesktopUpdate::Available
        );
    }

    #[test]
    fn reads_pages_until_a_short_page_within_bounds() {
        let full: Vec<_> = (0..100).map(|n| published(&format!("v0.0.{n}"))).collect();
        let pages = Pages::json(vec![full.clone(), vec![published("v1.0.0")]]);
        let feed = run_check(&pages, NOW).unwrap();
        assert!(feed.complete);
        assert_eq!(pages.calls.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(feed.stable.unwrap().version, v("1.0.0"));

        let pages = Pages::json(vec![full.clone(), full.clone(), full.clone(), full.clone()]);
        let feed = run_check(&pages, NOW).unwrap();
        assert!(
            !feed.complete,
            "three full pages are a bounded, incomplete history"
        );
        assert_eq!(pages.calls.load(AtomicOrdering::SeqCst), 3);

        let too_many: Vec<_> = (0..101).map(|_| published("v1.0.0")).collect();
        assert_eq!(
            run_check(&Pages::json(vec![too_many]), NOW),
            Err(FetchError::InvalidResponse)
        );
        assert_eq!(
            run_check(&Pages::new(vec![Ok(b"{\"message\":\"x\"}".to_vec())]), NOW),
            Err(FetchError::InvalidResponse)
        );
        let huge = vec![b' '; MAX_RESPONSE_BYTES - 10];
        let mut first = serde_json::to_vec(&full).unwrap();
        first.extend_from_slice(&huge);
        assert_eq!(
            run_check(&Pages::new(vec![Ok(first), Ok(b"[]".to_vec())]), NOW),
            Err(FetchError::TooLarge)
        );
    }

    #[test]
    fn caches_validated_results_and_preserves_them_on_failure() {
        let paths = temp_paths();
        let service = service(&paths, "1.0.0-rc.5", true);
        let start = state_of(&service).started;
        let later = start + STARTUP_DELAY;
        let pages = Pages::json(vec![vec![
            published("v1.0.0"),
            published("extension-v0.5.10"),
        ]]);
        // Snapshots compare against the real clock.
        let now = unix_now();
        assert!(service.step(&pages, now, later));
        let snapshot = service.snapshot();
        assert_eq!(snapshot.state, CheckState::Fresh);
        assert_eq!(snapshot.desktop.update, DesktopUpdate::Available);
        let offer = snapshot.desktop.offer.unwrap();
        assert_eq!(
            offer.url,
            "https://github.com/vleeuwenmenno/boltwarden/releases/tag/v1.0.0"
        );

        // A failing check keeps the earlier results and reports the error.
        state_of(&service).manual_pending = true;
        assert!(service.step(&Pages::new(vec![Err(FetchError::Network)]), now, later));
        let failed = service.snapshot();
        assert_eq!(failed.state, CheckState::Error);
        assert_eq!(failed.error, Some(ReleaseError::Network));
        assert_eq!(failed.desktop.offer.unwrap().version, "1.0.0");

        // A new process reads the cache back, without fetching.
        let reloaded = service_for(&paths);
        let snapshot = reloaded.snapshot();
        assert_eq!(snapshot.desktop.preview.unwrap().version, "1.0.0");
        assert_eq!(snapshot.extension.unwrap().tag, "extension-v0.5.10");
        assert!(snapshot.complete);
    }

    fn service_for(paths: &Paths) -> ReleaseService {
        service(paths, "1.0.0-rc.5", true)
    }

    #[test]
    fn rejects_tampered_or_oversized_cache_files() {
        let paths = temp_paths();
        let cache = paths.cache.clone().unwrap();
        let write = |value: serde_json::Value| std::fs::write(&cache, value.to_string()).unwrap();
        let good = serde_json::json!({
            "schema": 1, "checked_at": NOW, "complete": true,
            "desktop_stable": {"tag": "v1.0.0", "published_at": NOW},
            "desktop_preview": {"tag": "v1.1.0-rc.1", "published_at": NOW},
            "extension": {"tag": "extension-v0.5.10", "published_at": NOW},
        });
        write(good.clone());
        assert!(load_feed(Some(&cache), NOW).is_some());
        for (field, value) in [
            ("schema", serde_json::json!(2)),
            (
                "desktop_stable",
                serde_json::json!({"tag": "v1.1.0-rc.1", "published_at": NOW}),
            ),
            (
                "desktop_stable",
                serde_json::json!({"tag": "javascript:alert(1)", "published_at": NOW}),
            ),
            (
                "desktop_preview",
                serde_json::json!({"tag": "v0.1.0", "published_at": NOW}),
            ),
            (
                "extension",
                serde_json::json!({"tag": "v1.0.0", "published_at": NOW}),
            ),
            (
                "extension",
                serde_json::json!({"tag": "extension-v0.5.10", "published_at": 5}),
            ),
            ("checked_at", serde_json::json!(5)),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            write(bad);
            assert!(load_feed(Some(&cache), NOW).is_none(), "{field}");
        }
        // A cache written by a clock that ran ahead keeps its releases but is stale and
        // due, on every restart, not just a day after the first one.
        let mut future = good.clone();
        future["checked_at"] = serde_json::json!(NOW + 10 * 86_400);
        write(future);
        for day in 0..3 {
            let now = NOW + day * 86_400;
            let feed = load_feed(Some(&cache), now).unwrap();
            assert!(feed.stable.is_some());
            assert!(now - feed.checked_at > STALE_AFTER_SECS);
            let started = Instant::now();
            let state = State::new(Some(feed), None, true, started);
            assert!(state.auto_due(now, started + STARTUP_DELAY), "day {day}");
            let snapshot = state.snapshot(&installed("1.0.0"), now, started);
            assert_eq!(snapshot.state, CheckState::Stale);
            assert_eq!(snapshot.desktop.update, DesktopUpdate::Unknown);
        }

        std::fs::write(&cache, vec![b' '; MAX_STATE_FILE_BYTES as usize + 1]).unwrap();
        assert!(load_feed(Some(&cache), NOW).is_none());
    }

    #[test]
    fn schedules_daily_checks_with_startup_delay_and_backoff() {
        let started = Instant::now();
        let mut state = State::new(None, None, true, started);
        assert!(!state.auto_due(NOW, started), "waits after startup");
        let mut mono = started + STARTUP_DELAY;
        assert!(state.begin(NOW, mono));
        assert!(!state.begin(NOW, mono), "one check at a time");
        state.finish(Ok(Feed::empty(NOW)), mono);

        mono += Duration::from_secs(60 * 60);
        assert!(!state.auto_due(NOW + 3_600, mono), "not again within a day");
        // After sleep the wall clock shows a day passed even though the monotonic one did not.
        assert!(state.auto_due(NOW + CHECK_INTERVAL.as_secs(), mono));
        // A clock set back never makes the check due early, the monotonic day still does.
        assert!(!state.auto_due(NOW - 86_400 * 30, mono));
        assert!(state.auto_due(NOW - 86_400 * 30, started + STARTUP_DELAY + CHECK_INTERVAL));

        // Failures retry after ten minutes, or later when GitHub asks.
        assert!(state.begin(NOW + CHECK_INTERVAL.as_secs(), mono));
        state.finish(Err(FetchError::Network), mono);
        let wall = NOW + 2 * CHECK_INTERVAL.as_secs();
        assert!(!state.auto_due(wall, mono + RETRY_INTERVAL - Duration::from_secs(1)));
        assert!(state.auto_due(wall, mono + RETRY_INTERVAL));

        assert!(state.begin(wall, mono + RETRY_INTERVAL));
        let mono = mono + RETRY_INTERVAL;
        state.finish(
            Err(FetchError::RateLimited(Some(Duration::from_secs(3_600)))),
            mono,
        );
        assert!(!state.auto_due(wall, mono + RETRY_INTERVAL));
        assert!(
            !state.request_manual(mono + Duration::from_secs(120)),
            "rate limit blocks manual checks"
        );
        assert!(state.auto_due(wall, mono + Duration::from_secs(3_600)));

        // A huge Retry-After is capped.
        assert!(state.begin(wall, mono + Duration::from_secs(3_600)));
        let mono = mono + Duration::from_secs(3_600);
        state.finish(
            Err(FetchError::RateLimited(Some(Duration::from_secs(
                u64::MAX / 4,
            )))),
            mono,
        );
        assert!(state.auto_due(wall, mono + MAX_RETRY_DELAY));
    }

    #[test]
    fn manual_checks_work_when_automatic_checks_are_off() {
        let started = Instant::now();
        let mut state = State::new(None, None, false, started);
        assert!(!state.auto_due(NOW, started + CHECK_INTERVAL));
        assert!(state.request_manual(started));
        assert_eq!(
            state.snapshot(&installed("1.0.0"), NOW, started).state,
            CheckState::Checking
        );
        assert!(
            state.begin(NOW, started),
            "manual checks skip the startup delay"
        );
        state.finish(Ok(Feed::empty(NOW)), started);
        let current = installed("1.0.0");
        let retry = |state: &State, after: u64| {
            state
                .snapshot(&current, NOW, started + Duration::from_millis(after))
                .retry_after_seconds
        };
        assert_eq!(retry(&state, 0), Some(60));
        assert_eq!(retry(&state, 58_500), Some(2), "rounds up");
        assert!(!state.request_manual(started + Duration::from_secs(59)));
        assert_eq!(retry(&state, 60_000), None);
        assert!(state.request_manual(started + MANUAL_INTERVAL));
        assert_eq!(retry(&state, 60_000), None, "queued checks need no retry");

        // A rate limit outlasts the one-minute limit and is reported as such.
        let mono = started + MANUAL_INTERVAL;
        assert!(state.begin(NOW, mono));
        state.finish(
            Err(FetchError::RateLimited(Some(Duration::from_secs(1_800)))),
            mono,
        );
        assert_eq!(retry(&state, 60_000), Some(1_800));
        assert!(!state.request_manual(mono + Duration::from_secs(1_799)));
        assert!(state.request_manual(mono + Duration::from_secs(1_800)));
    }

    #[test]
    fn incomplete_checks_keep_newer_known_releases_and_complete_ones_replace_them() {
        let paths = temp_paths();
        let service = service(&paths, "0.9.0", true);
        let later = state_of(&service).started + STARTUP_DELAY;
        let now = unix_now();
        let first = Pages::json(vec![vec![
            published("v1.0.0"),
            published("v1.1.0-rc.1"),
            published("extension-v0.6.0"),
        ]]);
        assert!(service.step(&first, now, later));

        // Three full pages of older releases: the newer ones fell off the end.
        let old: Vec<_> = (0..100).map(|n| published(&format!("v0.1.{n}"))).collect();
        let incomplete = Pages::json(vec![old.clone(), old.clone(), old.clone()]);
        state_of(&service).manual_pending = true;
        assert!(service.step(&incomplete, now, later + MANUAL_INTERVAL));
        let snapshot = service.snapshot();
        assert!(!snapshot.complete);
        assert_eq!(snapshot.desktop.stable.unwrap().version, "1.0.0");
        assert_eq!(snapshot.desktop.preview.unwrap().version, "1.1.0-rc.1");
        assert_eq!(snapshot.extension.unwrap().version, "0.6.0");
        assert_eq!(snapshot.desktop.offer.unwrap().version, "1.0.0");
        let reloaded = service_for(&paths).snapshot();
        assert_eq!(reloaded.desktop.stable.unwrap().version, "1.0.0");
        assert_eq!(reloaded.extension.unwrap().version, "0.6.0");
        assert!(!reloaded.complete);

        // A complete list is authoritative, even about releases that disappeared.
        let complete = Pages::json(vec![vec![published("v0.9.5")]]);
        state_of(&service).manual_pending = true;
        assert!(service.step(&complete, now, later + 2 * MANUAL_INTERVAL));
        let snapshot = service.snapshot();
        assert!(snapshot.complete);
        assert_eq!(snapshot.desktop.stable.unwrap().version, "0.9.5");
        assert_eq!(snapshot.extension, None);
        assert_eq!(service_for(&paths).snapshot().extension, None);
    }

    #[test]
    fn retrying_a_failed_check_stays_uncertain_until_it_succeeds() {
        let started = Instant::now();
        let mono = started + STARTUP_DELAY;
        let current = installed("1.0.0");
        let older = installed("0.9.0");
        let mut state = State::new(None, None, true, started);
        assert!(state.begin(NOW, mono));
        state.finish(Ok(feed_of(&[published("v1.0.0")])), mono);
        assert!(state.begin(NOW, mono + CHECK_INTERVAL));
        let mono = mono + CHECK_INTERVAL;
        state.finish(Err(FetchError::Network), mono);
        let update = |state: &State, installed: &Installed| {
            state.snapshot(installed, NOW, mono).desktop.update
        };
        assert_eq!(update(&state, &current), DesktopUpdate::Unknown);
        assert!(state.request_manual(mono + MANUAL_INTERVAL));
        assert_eq!(
            state.snapshot(&current, NOW, mono).state,
            CheckState::Checking
        );
        assert_eq!(update(&state, &current), DesktopUpdate::Unknown, "queued");
        assert_eq!(update(&state, &older), DesktopUpdate::Available);
        assert!(state.begin(NOW, mono + MANUAL_INTERVAL));
        assert_eq!(update(&state, &current), DesktopUpdate::Unknown, "running");
        assert_eq!(update(&state, &older), DesktopUpdate::Available);
        state.finish(Ok(feed_of(&[published("v1.0.0")])), mono + MANUAL_INTERVAL);
        assert_eq!(update(&state, &current), DesktopUpdate::UpToDate);
    }

    #[test]
    fn failed_or_stale_checks_never_claim_up_to_date() {
        let started = Instant::now();
        let current = installed("1.0.0");
        let mut state = State::new(None, None, true, started);
        let mono = started + STARTUP_DELAY;
        assert!(state.begin(NOW, mono));
        state.finish(Ok(feed_of(&[published("v1.0.0")])), mono);
        let snapshot = state.snapshot(&current, NOW, mono);
        assert_eq!(snapshot.desktop.update, DesktopUpdate::UpToDate);

        state.manual_pending = true;
        let later = mono + MANUAL_INTERVAL;
        assert!(state.begin(NOW, later));
        state.finish(Err(FetchError::Network), later);
        let failed = state.snapshot(&current, NOW, later);
        assert_eq!(failed.state, CheckState::Error);
        assert_eq!(failed.desktop.update, DesktopUpdate::Unknown);
        assert!(failed.desktop.stable.is_some(), "known releases are kept");

        let mut stale = State::new(Some(feed_of(&[published("v1.0.0")])), None, true, started);
        assert_eq!(
            stale
                .snapshot(&current, NOW + STALE_AFTER_SECS + 1, started)
                .desktop
                .update,
            DesktopUpdate::Unknown
        );
        // A newer release that is already known is still offered after a failure.
        stale.error = Some(ReleaseError::Network);
        let older = installed("0.9.0");
        let snapshot = stale.snapshot(&older, NOW + STALE_AFTER_SECS + 1, started);
        assert_eq!(snapshot.desktop.update, DesktopUpdate::Available);
        assert_eq!(snapshot.notice().unwrap().version, "1.0.0");
    }

    #[test]
    fn reports_empty_fresh_stale_and_unsupported_states() {
        let started = Instant::now();
        let mut state = State::new(None, None, true, started);
        let current = installed("1.0.0");
        assert_eq!(
            state.snapshot(&current, NOW, started).state,
            CheckState::Empty
        );
        state.feed = Some(feed_of(&[published("v1.0.0")]));
        assert_eq!(
            state.snapshot(&current, NOW, started).state,
            CheckState::Fresh
        );
        assert_eq!(
            state.snapshot(&current, NOW, started).desktop.update,
            DesktopUpdate::UpToDate
        );
        assert_eq!(
            state
                .snapshot(&current, NOW + STALE_AFTER_SECS + 1, started)
                .state,
            CheckState::Stale
        );
        let unsupported = ReleaseService::unsupported();
        assert_eq!(unsupported.snapshot().state, CheckState::Unsupported);
        assert!(unsupported.dismiss("1.0.0").is_err());
        unsupported.check_now();
    }

    #[test]
    fn dismissal_is_per_offered_version_and_persisted() {
        let paths = temp_paths();
        let service = service(&paths, "0.9.0", true);
        assert!(service.dismiss("1.0.0").is_err(), "nothing offered yet");
        state_of(&service).feed = Some(feed_of(&[published("v1.0.0")]));
        assert!(service.dismiss("0.9.5").is_err());
        assert!(service.dismiss("not a version").is_err());
        let snapshot = service.dismiss("1.0.0").unwrap();
        assert!(snapshot.desktop.dismissed);
        assert_eq!(snapshot.notice(), None);

        let reloaded = ReleaseService::with_paths(paths.clone(), installed("0.9.0"), true);
        state_of(&reloaded).feed = Some(feed_of(&[published("v1.0.0")]));
        assert!(reloaded.snapshot().desktop.dismissed);
        // A newer release is announced again.
        state_of(&reloaded).feed = Some(feed_of(&[published("v1.0.1")]));
        let snapshot = reloaded.snapshot();
        assert!(!snapshot.desktop.dismissed);
        assert_eq!(snapshot.notice().unwrap().version, "1.0.1");

        std::fs::write(
            paths.dismissal.as_ref().unwrap(),
            br#"{"desktop":"../../x"}"#,
        )
        .unwrap();
        assert_eq!(load_dismissal(paths.dismissal.as_deref()), None);
    }

    #[test]
    fn parses_github_timestamps_and_formats_days() {
        assert_eq!(parse_timestamp("2026-09-01T10:00:00Z"), Some(1_788_256_800));
        assert!(parse_timestamp("2024-02-29T00:00:00Z").is_some());
        for invalid in [
            "2026-02-31T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
        ] {
            assert_eq!(parse_timestamp(invalid), None, "{invalid}");
        }
        for invalid in [
            "2026-09-01",
            "2026-09-01T10:00:00",
            "2026-13-01T10:00:00Z",
            "2026-09-01T24:00:00Z",
            "2026-09-01T10:00:00+01:00",
            "1970-01-01T00:00:00Z",
            "2026-0a-01T10:00:00Z",
        ] {
            assert_eq!(parse_timestamp(invalid), None, "{invalid}");
        }
        assert_eq!(format_day(1_788_256_800), "2026-09-01");
        assert_eq!(format_day(951_782_400), "2000-02-29");
    }

    #[test]
    fn snapshot_wire_shape_is_stable() {
        let snapshot = ReleaseSnapshot::demo(true);
        let value = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(value["state"], "fresh");
        assert_eq!(value["desktop"]["update"], "available");
        assert_eq!(value["desktop"]["offer"]["tag"], "v1.0.0");
        assert!(value.get("error").is_none());
        let decoded: ReleaseSnapshot = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, snapshot);
        let minimal: ReleaseSnapshot = serde_json::from_value(serde_json::json!({
            "state": "unsupported", "auto_check": false,
            "desktop": {"installed": "1.0.0", "update": "unknown"}
        }))
        .unwrap();
        assert_eq!(minimal.state, CheckState::Unsupported);
    }
}

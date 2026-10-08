//! Vault health checks for the action center: reused, weak and unsecured passwords,
//! duplicates, expiring cards, breached websites, and sites that offer two-factor login
//! or passkeys.
//!
//! The two-factor and passkey checks compare saved websites against the public
//! 2fa.directory lists, and the breach check against the public Have I Been Pwned
//! breach list. Those lists are downloaded whole, so no vault data leaves the machine;
//! they are cached on disk for a day.

use crate::model::{BwItemDetail, HealthCheck, HealthReport, ItemState};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TWO_FACTOR_URL: &str = "https://api.2fa.directory/v3/totp.json";
const PASSKEYS_URL: &str = "https://passkeys-api.2fa.directory/v1/all.json";
const BREACHES_URL: &str = "https://haveibeenpwned.com/api/v3/breaches";
const DIRECTORY_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// After a failed download, wait this long before trying again.
const DIRECTORY_RETRY: Duration = Duration::from_secs(10 * 60);
const EXPIRY_WARNING_DAYS: i64 = 30;
/// zxcvbn scores below this count as weak (0 and 1 are "too guessable", 2 "somewhat").
const STRONG_SCORE: u8 = 3;

/// Domains from 2fa.directory: sites with two-factor login, and sites with passkeys.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Directory {
    two_factor: HashSet<String>,
    passkeys: HashSet<String>,
    #[serde(skip)]
    error: Option<String>,
}

impl Directory {
    #[cfg(test)]
    pub fn from_domains(two_factor: &[&str], passkeys: &[&str]) -> Self {
        Self {
            two_factor: two_factor.iter().map(|d| d.to_string()).collect(),
            passkeys: passkeys.iter().map(|d| d.to_string()).collect(),
            error: None,
        }
    }

    /// A few well-known sites, so demo mode shows the directory checks offline.
    pub fn demo() -> Self {
        let set = |domains: &[&str]| domains.iter().map(|d| d.to_string()).collect();
        Self {
            two_factor: set(&["github.com", "gitlab.com", "google.com", "dropbox.com"]),
            passkeys: set(&["github.com", "gitlab.com", "google.com"]),
            error: None,
        }
    }

    /// Changes whenever a different list is loaded.
    pub fn fingerprint(&self) -> (usize, usize, bool) {
        (
            self.two_factor.len(),
            self.passkeys.len(),
            self.error.is_some(),
        )
    }
}

/// A public list the action center downloads whole and caches on disk for a day.
trait PublicList: Default + serde::Serialize + serde::de::DeserializeOwned {
    const CACHE_FILE: &'static str;
    fn download() -> Result<Self, String>;
    fn is_empty(&self) -> bool;
    fn has_error(&self) -> bool;
    fn set_error(&mut self, error: String);
}

impl PublicList for Directory {
    const CACHE_FILE: &'static str = "2fa-directory.json";

    fn download() -> Result<Self, String> {
        download_directory()
    }

    fn is_empty(&self) -> bool {
        self.two_factor.is_empty() && self.passkeys.is_empty()
    }

    fn has_error(&self) -> bool {
        self.error.is_some()
    }

    fn set_error(&mut self, error: String) {
        self.error = Some(error);
    }
}

type Slot<T> = Mutex<Option<(Instant, Arc<T>)>>;

static DIRECTORY: Slot<Directory> = Mutex::new(None);
static BREACHES: Slot<Breaches> = Mutex::new(None);

/// The cached directory, downloading it when it is older than a day. Call this without
/// holding the vault lock: the download can take a few seconds.
pub fn directory() -> Arc<Directory> {
    cached(&DIRECTORY)
}

/// The cached breach list, downloading it when it is older than a day. Call this
/// without holding the vault lock.
pub fn breaches() -> Arc<Breaches> {
    cached(&BREACHES)
}

fn cached<T: PublicList>(slot: &Slot<T>) -> Arc<T> {
    let Ok(mut slot) = slot.lock() else {
        return Arc::new(T::default());
    };
    if let Some((at, list)) = slot.as_ref() {
        let ttl = if list.has_error() {
            DIRECTORY_RETRY
        } else {
            DIRECTORY_TTL
        };
        if at.elapsed() < ttl {
            return list.clone();
        }
    }
    let list = Arc::new(load_list::<T>());
    *slot = Some((Instant::now(), list.clone()));
    list
}

fn load_list<T: PublicList>() -> T {
    let path = cache_path(T::CACHE_FILE);
    if let Some(cached) = path
        .as_ref()
        .and_then(|path| read_cache(path, DIRECTORY_TTL))
    {
        return cached;
    }
    match T::download() {
        Ok(list) => {
            if let Some(path) = &path {
                let _ = write_cache(path, &list);
            }
            list
        }
        Err(error) => {
            // A stale list beats no list.
            let mut list: T = path
                .as_ref()
                .and_then(|path| read_cache(path, Duration::MAX))
                .unwrap_or_default();
            if list.is_empty() {
                list.set_error(error);
            }
            list
        }
    }
}

fn http_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        // Have I Been Pwned rejects requests without a user agent.
        .user_agent(concat!("Boltwarden/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())
}

fn download_directory() -> Result<Directory, String> {
    let client = http_client()?;
    let fetch = |url: &str| -> Result<serde_json::Value, String> {
        let response = client
            .get(url)
            .send()
            .map_err(|e| format!("could not download the 2fa.directory list: {e}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "2fa.directory answered HTTP {}",
                response.status().as_u16()
            ));
        }
        response
            .json()
            .map_err(|e| format!("could not read the 2fa.directory list: {e}"))
    };
    Ok(Directory {
        two_factor: parse_two_factor(&fetch(TWO_FACTOR_URL)?),
        passkeys: parse_passkeys(&fetch(PASSKEYS_URL)?),
        error: None,
    })
}

/// `[["Name", {"domain": "x.com", "additional-domains": [...], "tfa": [...]}], ...]`
fn parse_two_factor(value: &serde_json::Value) -> HashSet<String> {
    let mut domains = HashSet::new();
    for entry in value.as_array().into_iter().flatten() {
        let Some(site) = entry.get(1) else { continue };
        if let Some(domain) = site.get("domain").and_then(|d| d.as_str()) {
            domains.insert(domain.to_ascii_lowercase());
        }
        for domain in site
            .get("additional-domains")
            .and_then(|d| d.as_array())
            .into_iter()
            .flatten()
            .filter_map(|d| d.as_str())
        {
            domains.insert(domain.to_ascii_lowercase());
        }
    }
    domains
}

/// `{"x.com": {"passwordless": "allowed"}, "y.com": {"mfa": "allowed"}, ...}`
fn parse_passkeys(value: &serde_json::Value) -> HashSet<String> {
    value
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, site)| site.get("passwordless").is_some() || site.get("mfa").is_some())
        .map(|(domain, _)| domain.to_ascii_lowercase())
        .collect()
}

/// Websites from Have I Been Pwned whose breach exposed passwords, with the most
/// recent such breach per domain.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Breaches {
    sites: HashMap<String, Breach>,
    #[serde(skip)]
    error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Breach {
    title: String,
    /// When the breach happened, in days since 1970-01-01.
    day: i64,
}

impl Breaches {
    #[cfg(test)]
    pub fn from_sites(sites: &[(&str, &str)]) -> Self {
        Self {
            sites: sites
                .iter()
                .filter_map(|(domain, date)| {
                    let breach = Breach {
                        title: domain.to_string(),
                        day: parse_day(date)?,
                    };
                    Some((domain.to_string(), breach))
                })
                .collect(),
            error: None,
        }
    }

    /// A fictional breach, so demo mode shows the check offline.
    pub fn demo() -> Self {
        let breach = Breach {
            title: "Example (demo)".into(),
            day: days_from_civil(2024, 3, 1),
        };
        Self {
            sites: HashMap::from([("example.com".to_string(), breach)]),
            error: None,
        }
    }

    /// Changes whenever a different list is loaded.
    pub fn fingerprint(&self) -> (usize, bool) {
        (self.sites.len(), self.error.is_some())
    }

    /// The latest breach of the host or one of its parent domains.
    fn latest(&self, host: &str) -> Option<&Breach> {
        domain_candidates(host)
            .filter_map(|domain| self.sites.get(domain))
            .max_by_key(|breach| breach.day)
    }
}

impl PublicList for Breaches {
    const CACHE_FILE: &'static str = "hibp-breaches.json";

    fn download() -> Result<Self, String> {
        let response = http_client()?
            .get(BREACHES_URL)
            .send()
            .map_err(|e| format!("could not download the Have I Been Pwned list: {e}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "Have I Been Pwned answered HTTP {}",
                response.status().as_u16()
            ));
        }
        let value = response
            .json()
            .map_err(|e| format!("could not read the Have I Been Pwned list: {e}"))?;
        Ok(Self {
            sites: parse_breaches(&value),
            error: None,
        })
    }

    fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }

    fn has_error(&self) -> bool {
        self.error.is_some()
    }

    fn set_error(&mut self, error: String) {
        self.error = Some(error);
    }
}

/// `[{"Title": "X", "Domain": "x.com", "BreachDate": "2019-01-31",
/// "DataClasses": ["Passwords", ...], "IsVerified": true, ...}, ...]`
///
/// Keeps verified breaches of a website that exposed passwords. Fabricated, spam-list,
/// malware and stealer-log entries are left out, as are retired ones.
fn parse_breaches(value: &serde_json::Value) -> HashMap<String, Breach> {
    let mut sites: HashMap<String, Breach> = HashMap::new();
    let flag = |breach: &serde_json::Value, name: &str| {
        breach.get(name).and_then(|v| v.as_bool()).unwrap_or(false)
    };
    for breach in value.as_array().into_iter().flatten() {
        if !flag(breach, "IsVerified")
            || [
                "IsFabricated",
                "IsSpamList",
                "IsMalware",
                "IsStealerLog",
                "IsRetired",
            ]
            .iter()
            .any(|name| flag(breach, name))
        {
            continue;
        }
        let exposed_passwords = breach
            .get("DataClasses")
            .and_then(|v| v.as_array())
            .is_some_and(|classes| classes.iter().any(|c| c.as_str() == Some("Passwords")));
        let domain = breach
            .get("Domain")
            .and_then(|v| v.as_str())
            .map(|d| d.trim().trim_start_matches("www.").to_ascii_lowercase())
            .unwrap_or_default();
        let day = breach
            .get("BreachDate")
            .and_then(|v| v.as_str())
            .and_then(parse_day);
        let (true, Some(day)) = (exposed_passwords && domain.contains('.'), day) else {
            continue;
        };
        let title = breach
            .get("Title")
            .and_then(|v| v.as_str())
            .unwrap_or(&domain)
            .to_string();
        let latest = sites.get(&domain).is_some_and(|known| known.day >= day);
        if !latest {
            sites.insert(domain, Breach { title, day });
        }
    }
    sites
}

fn cache_path(file: &str) -> Option<PathBuf> {
    Some(crate::config::cache_dir()?.join(file))
}

fn read_cache<T: serde::de::DeserializeOwned>(path: &PathBuf, ttl: Duration) -> Option<T> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    if modified.elapsed().unwrap_or(Duration::MAX) > ttl && ttl != Duration::MAX {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

#[cfg(windows)]
fn write_cache<T: serde::Serialize>(path: &PathBuf, list: &T) -> std::io::Result<()> {
    crate::platform::windows::write_private(path, &serde_json::to_vec(list)?)
}

#[cfg(unix)]
fn write_cache<T: serde::Serialize>(path: &PathBuf, list: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(list)?)?;
    std::fs::rename(tmp, path)
}

pub fn report(
    items: &[BwItemDetail],
    directory: &Directory,
    breaches: &Breaches,
    now: SystemTime,
) -> HealthReport {
    let active = items
        .iter()
        .filter(|item| item.state == ItemState::Active)
        .collect::<Vec<_>>();
    let logins = active
        .iter()
        .filter(|item| item.item_type == "login")
        .collect::<Vec<_>>();
    let with_password = logins
        .iter()
        .filter(|item| item.password.as_deref().is_some_and(|p| !p.is_empty()))
        .collect::<Vec<_>>();

    let mut findings: HashMap<HealthCheck, Vec<String>> = HashMap::new();
    let flag = |findings: &mut HashMap<HealthCheck, Vec<String>>, check, id: &str| {
        findings.entry(check).or_default().push(id.to_string())
    };

    let mut by_password: HashMap<&str, Vec<&str>> = HashMap::new();
    for item in &with_password {
        let password = item.password.as_deref().unwrap_or_default();
        by_password.entry(password).or_default().push(&item.id);
    }
    let reused = by_password
        .values()
        .filter(|ids| ids.len() > 1)
        .flatten()
        .copied()
        .collect::<HashSet<_>>();

    let mut strength = [0usize; 5];
    let mut risky = HashSet::new();
    for item in &with_password {
        let password = item.password.as_deref().unwrap_or_default();
        let mut inputs = vec![item.name.as_str()];
        inputs.extend(item.username.as_deref());
        let score = u8::from(zxcvbn::zxcvbn(password, &inputs).score());
        strength[usize::from(score.min(4))] += 1;
        if score < STRONG_SCORE {
            flag(&mut findings, HealthCheck::WeakPasswords, &item.id);
            risky.insert(item.id.as_str());
        }
        if reused.contains(item.id.as_str()) {
            flag(&mut findings, HealthCheck::ReusedPasswords, &item.id);
            risky.insert(item.id.as_str());
        }
        if password_predates_breach(item, breaches) {
            flag(&mut findings, HealthCheck::BreachedWebsites, &item.id);
            risky.insert(item.id.as_str());
        }
    }

    let mut seen: HashMap<(String, &str, &str), &str> = HashMap::new();
    for item in &logins {
        let hosts = hosts(&item.uris);
        if item.uris.iter().any(|uri| is_unsecured(uri)) {
            flag(&mut findings, HealthCheck::UnsecuredWebsites, &item.id);
            if item.password.is_some() {
                risky.insert(item.id.as_str());
            }
        }
        if let (Some(host), Some(password)) = (hosts.first(), item.password.as_deref()) {
            let key = (
                host.clone(),
                item.username.as_deref().unwrap_or_default(),
                password,
            );
            match seen.get(&key) {
                Some(first) => {
                    if !findings
                        .get(&HealthCheck::Duplicates)
                        .is_some_and(|ids| ids.iter().any(|id| id == first))
                    {
                        flag(&mut findings, HealthCheck::Duplicates, first);
                    }
                    flag(&mut findings, HealthCheck::Duplicates, &item.id);
                }
                None => {
                    seen.insert(key, &item.id);
                }
            }
        }
        let matches = |domains: &HashSet<String>| {
            hosts
                .iter()
                .any(|host| domain_candidates(host).any(|d| domains.contains(d)))
        };
        if item.totp.is_none() && matches(&directory.two_factor) {
            flag(&mut findings, HealthCheck::TwoFactorAvailable, &item.id);
        }
        if item.passkeys.is_empty() && matches(&directory.passkeys) {
            flag(&mut findings, HealthCheck::PasskeysAvailable, &item.id);
        }
    }

    let today = days_since_epoch(now);
    for item in active.iter().filter(|item| item.item_type == "card") {
        if card_expires_by(item, today + EXPIRY_WARNING_DAYS) {
            flag(&mut findings, HealthCheck::Expiring, &item.id);
        }
    }

    let passwords = with_password.len();
    let score = (100 * passwords.saturating_sub(risky.len()))
        .checked_div(passwords)
        .map_or(100, |score| score as u8);
    HealthReport {
        passwords,
        strength,
        score,
        findings: HealthCheck::ALL
            .into_iter()
            .filter_map(|check| findings.remove(&check).map(|ids| (check, ids)))
            .collect(),
        directory_error: directory.error.clone(),
        breach_error: breaches.error.clone(),
    }
}

/// Whether one of the login's websites had a breach on or after the day its password
/// was last changed. Without a known date, the password may predate the breach.
fn password_predates_breach(item: &BwItemDetail, breaches: &Breaches) -> bool {
    let Some(breach_day) = hosts(&item.uris)
        .iter()
        .filter_map(|host| breaches.latest(host))
        .map(|breach| breach.day)
        .max()
    else {
        return false;
    };
    let changed = item
        .dates
        .password_changed_at
        .as_deref()
        .or(item.dates.creation_date.as_deref())
        .and_then(parse_day);
    changed.is_none_or(|day| day <= breach_day)
}

/// Days since 1970-01-01 for the date at the start of an ISO 8601 timestamp.
fn parse_day(timestamp: &str) -> Option<i64> {
    let date = timestamp.get(..10)?;
    let mut parts = date.split('-').map(|part| part.parse::<i64>().ok());
    let (Some(Some(year)), Some(Some(month)), Some(Some(day)), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    ((1..=12).contains(&month) && (1..=31).contains(&day))
        .then(|| days_from_civil(year, month, day))
}

/// Lowercase hostnames of the item's websites. Bare domains count as https.
fn hosts(uris: &[String]) -> Vec<String> {
    uris.iter()
        .filter_map(|uri| {
            let uri = uri.trim();
            let parsed = url::Url::parse(uri)
                .ok()
                .filter(|url| matches!(url.scheme(), "http" | "https"))
                .or_else(|| {
                    (!uri.contains("://"))
                        .then(|| url::Url::parse(&format!("https://{uri}")).ok())
                        .flatten()
                })?;
            match parsed.host()? {
                url::Host::Domain(domain) => Some(
                    domain
                        .trim_end_matches('.')
                        .trim_start_matches("www.")
                        .to_ascii_lowercase(),
                ),
                _ => None,
            }
        })
        .collect()
}

/// "login.example.co.uk", "example.co.uk", "co.uk": the host and each parent domain,
/// so a login saved for a subdomain matches the directory's main domain.
fn domain_candidates(host: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(host), |host| {
        host.split_once('.').map(|(_, rest)| rest)
    })
    .filter(|domain| domain.contains('.'))
}

/// A plain-HTTP website that is not on this machine or the local network.
fn is_unsecured(uri: &str) -> bool {
    let Ok(url) = url::Url::parse(uri.trim()) else {
        return false;
    };
    if url.scheme() != "http" {
        return false;
    }
    match url.host() {
        Some(url::Host::Domain(domain)) => {
            let domain = domain.to_ascii_lowercase();
            domain != "localhost"
                && !domain.ends_with(".localhost")
                && !domain.ends_with(".local")
                && !domain.ends_with(".lan")
                && !domain.ends_with(".home.arpa")
                && domain.contains('.')
        }
        Some(url::Host::Ipv4(ip)) => !(ip.is_loopback() || ip.is_private() || ip.is_link_local()),
        Some(url::Host::Ipv6(ip)) => !ip.is_loopback(),
        None => false,
    }
}

fn card_expires_by(item: &BwItemDetail, day: i64) -> bool {
    let field = |name: &str| {
        item.custom_fields
            .iter()
            .find(|field| field.name == name)
            .and_then(|field| field.value.trim().parse::<i64>().ok())
    };
    let (Some(month), Some(year)) = (field("Exp Month"), field("Exp Year")) else {
        return false;
    };
    if !(1..=12).contains(&month) {
        return false;
    }
    let year = if year < 100 { 2000 + year } else { year };
    // A card is valid through the last day of its expiry month.
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    days_from_civil(next_year, next_month, 1) - 1 <= day
}

pub fn days_since_epoch(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86_400) as i64)
        .unwrap_or(0)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CustomField, ItemDates, Passkey};

    fn login(id: &str, password: &str, uri: &str) -> BwItemDetail {
        BwItemDetail {
            id: id.into(),
            name: id.into(),
            username: Some("alice".into()),
            password: Some(password.into()),
            uris: vec![uri.into()],
            totp: None,
            notes: None,
            custom_fields: Vec::new(),
            folder: None,
            folder_id: None,
            favorite: false,
            passkeys: Vec::new(),
            item_type: "login".into(),
            ssh_key: None,
            state: ItemState::Active,
            dates: ItemDates::default(),
        }
    }

    fn at(year: i64, month: i64, day: i64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(days_from_civil(year, month, day) as u64 * 86_400)
    }

    #[test]
    fn flags_reused_weak_unsecured_and_duplicate_logins() {
        let strong = "vX7#qL9!tR2$wM5&";
        let items = vec![
            login("a", strong, "https://one.example.com"),
            login("b", strong, "https://two.example.com"),
            login("c", "password", "https://three.example.com"),
            login("d", "Zr8@kP3^nB6*yH1%", "http://plain.example.com/login"),
            login("e", "Zr8@kP3^nB6*yH1%", "http://plain.example.com/other"),
            login("f", "Qw4!eR5@tY6#uI7$", "http://192.168.1.1"),
        ];
        let report = report(
            &items,
            &Directory::default(),
            &Breaches::default(),
            at(2026, 9, 30),
        );

        assert_eq!(report.items(HealthCheck::ReusedPasswords).len(), 4);
        assert_eq!(report.items(HealthCheck::WeakPasswords), ["c"]);
        assert_eq!(report.items(HealthCheck::UnsecuredWebsites), ["d", "e"]);
        assert_eq!(report.items(HealthCheck::Duplicates), ["d", "e"]);
        assert_eq!(report.passwords, 6);
        // Only "f" is free of risks.
        assert_eq!(report.score, 16);
        assert_eq!(report.strength.iter().sum::<usize>(), 6);
    }

    #[test]
    fn suggests_two_factor_and_passkeys_from_the_directory() {
        let mut with_totp = login("totp", "vX7#qL9!tR2$wM5&", "https://accounts.example.com");
        with_totp.totp = Some("JBSWY3DPEHPK3PXP".into());
        let mut with_passkey = login("pk", "Zr8@kP3^nB6*yH1%", "https://www.example.com");
        with_passkey.passkeys = vec![Passkey {
            rp_id: "example.com".into(),
            ..Passkey::default()
        }];
        let plain = login("plain", "Qw4!eR5@tY6#uI7$", "example.com");
        let other = login("other", "Mn3$bV4%cX5^zL6&", "https://other.org");
        let directory = Directory::from_domains(&["example.com"], &["example.com"]);

        let report = report(
            &[with_totp, with_passkey, plain, other],
            &directory,
            &Breaches::default(),
            at(2026, 9, 30),
        );

        assert_eq!(
            report.items(HealthCheck::TwoFactorAvailable),
            ["pk", "plain"]
        );
        assert_eq!(
            report.items(HealthCheck::PasskeysAvailable),
            ["totp", "plain"]
        );
    }

    #[test]
    fn flags_cards_that_expire_within_a_month() {
        let card = |id: &str, month: &str, year: &str| {
            let mut item = login(id, "", "");
            item.item_type = "card".into();
            item.password = None;
            item.uris.clear();
            item.custom_fields = vec![
                CustomField {
                    name: "Exp Month".into(),
                    value: month.into(),
                    hidden: false,
                },
                CustomField {
                    name: "Exp Year".into(),
                    value: year.into(),
                    hidden: false,
                },
            ];
            item
        };
        let items = vec![
            card("expired", "8", "2026"),
            card("soon", "10", "26"),
            card("later", "12", "2026"),
        ];

        let report = report(
            &items,
            &Directory::default(),
            &Breaches::default(),
            at(2026, 10, 5),
        );

        assert_eq!(report.items(HealthCheck::Expiring), ["expired", "soon"]);
    }

    #[test]
    fn parses_directory_lists() {
        let two_factor = serde_json::json!([
            ["Example", {"domain": "Example.com", "additional-domains": ["example.org"], "tfa": ["totp"]}],
        ]);
        let passkeys = serde_json::json!({
            "a.com": {"passwordless": "allowed"},
            "b.com": {"mfa": "allowed"},
            "c.com": {"contact": {}},
        });
        assert_eq!(
            parse_two_factor(&two_factor),
            ["example.com", "example.org"]
                .map(String::from)
                .into_iter()
                .collect()
        );
        assert_eq!(
            parse_passkeys(&passkeys),
            ["a.com", "b.com"].map(String::from).into_iter().collect()
        );
    }

    #[test]
    fn flags_logins_whose_password_predates_a_breach() {
        let dated = |id: &str, uri: &str, created: &str, changed: Option<&str>| {
            let mut item = login(id, &format!("{id}-Vq7#Lm2!Zt9$"), uri);
            item.dates.creation_date = Some(format!("{created}T10:00:00.000Z"));
            item.dates.password_changed_at = changed.map(|day| format!("{day}T10:00:00.000Z"));
            item
        };
        let items = vec![
            dated("old", "https://login.breached.com", "2018-01-01", None),
            dated(
                "changed",
                "https://breached.com",
                "2018-01-01",
                Some("2021-06-01"),
            ),
            dated("same-day", "breached.com", "2020-05-01", None),
            dated("newer", "https://breached.com", "2022-01-01", None),
            dated("safe", "https://other.com", "2018-01-01", None),
            login("undated", "Zr8@kP3^nB6*yH1%", "https://www.breached.com"),
        ];
        let breaches = Breaches::from_sites(&[("breached.com", "2020-05-01")]);

        let report = report(&items, &Directory::default(), &breaches, at(2026, 9, 30));

        assert_eq!(
            report.items(HealthCheck::BreachedWebsites),
            ["old", "same-day", "undated"]
        );
        // Three of six logins are at risk.
        assert_eq!(report.score, 50);
    }

    #[test]
    fn parses_breaches_that_exposed_passwords() {
        let list = serde_json::json!([
            {"Title": "Old", "Domain": "x.com", "BreachDate": "2015-03-01",
             "DataClasses": ["Email addresses", "Passwords"], "IsVerified": true},
            {"Title": "New", "Domain": "www.X.com", "BreachDate": "2019-01-31",
             "DataClasses": ["Passwords"], "IsVerified": true},
            {"Title": "Emails", "Domain": "y.com", "BreachDate": "2020-01-01",
             "DataClasses": ["Email addresses"], "IsVerified": true},
            {"Title": "Unverified", "Domain": "z.com", "BreachDate": "2020-01-01",
             "DataClasses": ["Passwords"], "IsVerified": false},
            {"Title": "Fake", "Domain": "f.com", "BreachDate": "2020-01-01",
             "DataClasses": ["Passwords"], "IsVerified": true, "IsFabricated": true},
            {"Title": "List", "Domain": "", "BreachDate": "2020-01-01",
             "DataClasses": ["Passwords"], "IsVerified": true},
        ]);

        let sites = parse_breaches(&list);

        assert_eq!(sites.len(), 1);
        assert_eq!(
            sites["x.com"],
            Breach {
                title: "New".into(),
                day: days_from_civil(2019, 1, 31),
            }
        );
    }

    #[test]
    fn parses_iso_dates() {
        assert_eq!(parse_day("2020-05-01"), Some(days_from_civil(2020, 5, 1)));
        assert_eq!(
            parse_day("2020-05-01T10:00:00.000Z"),
            Some(days_from_civil(2020, 5, 1))
        );
        assert_eq!(parse_day("2020-13-01"), None);
        assert_eq!(parse_day("May 2020"), None);
        assert_eq!(parse_day(""), None);
    }

    #[test]
    fn computes_civil_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(
            days_since_epoch(at(2026, 9, 30)),
            days_from_civil(2026, 9, 30)
        );
    }
}

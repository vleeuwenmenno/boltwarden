//! Vault health checks for the action center: reused, weak and unsecured passwords,
//! duplicates, expiring cards, and sites that offer two-factor login or passkeys.
//!
//! The two-factor and passkey checks compare saved websites against the public
//! 2fa.directory lists. Those lists are downloaded whole, so no vault data leaves the
//! machine; they are cached on disk for a day.

use crate::model::{BwItemDetail, HealthCheck, HealthReport, ItemState};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TWO_FACTOR_URL: &str = "https://api.2fa.directory/v3/totp.json";
const PASSKEYS_URL: &str = "https://passkeys-api.2fa.directory/v1/all.json";
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

    fn is_empty(&self) -> bool {
        self.two_factor.is_empty() && self.passkeys.is_empty()
    }
}

static DIRECTORY: Mutex<Option<(Instant, Arc<Directory>)>> = Mutex::new(None);

/// The cached directory, downloading it when it is older than a day. Call this without
/// holding the vault lock: the download can take a few seconds.
pub fn directory() -> Arc<Directory> {
    let Ok(mut slot) = DIRECTORY.lock() else {
        return Arc::new(Directory::default());
    };
    if let Some((at, directory)) = slot.as_ref() {
        let ttl = if directory.error.is_some() {
            DIRECTORY_RETRY
        } else {
            DIRECTORY_TTL
        };
        if at.elapsed() < ttl {
            return directory.clone();
        }
    }
    let directory = Arc::new(load_directory());
    *slot = Some((Instant::now(), directory.clone()));
    directory
}

fn load_directory() -> Directory {
    let path = cache_path();
    if let Some(cached) = path
        .as_ref()
        .and_then(|path| read_cache(path, DIRECTORY_TTL))
    {
        return cached;
    }
    match download_directory() {
        Ok(directory) => {
            if let Some(path) = &path {
                let _ = write_cache(path, &directory);
            }
            directory
        }
        Err(error) => {
            // A stale list beats no list.
            let mut directory = path
                .as_ref()
                .and_then(|path| read_cache(path, Duration::MAX))
                .unwrap_or_default();
            if directory.is_empty() {
                directory.error = Some(error);
            }
            directory
        }
    }
}

fn download_directory() -> Result<Directory, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
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

fn cache_path() -> Option<PathBuf> {
    Some(crate::config::cache_dir()?.join("2fa-directory.json"))
}

fn read_cache(path: &PathBuf, ttl: Duration) -> Option<Directory> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    if modified.elapsed().unwrap_or(Duration::MAX) > ttl && ttl != Duration::MAX {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn write_cache(path: &PathBuf, directory: &Directory) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(directory)?)?;
    std::fs::rename(tmp, path)
}

pub fn report(items: &[BwItemDetail], directory: &Directory, now: SystemTime) -> HealthReport {
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
    }
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
        let report = report(&items, &Directory::default(), at(2026, 9, 30));

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

        let report = report(&items, &Directory::default(), at(2026, 10, 5));

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
    fn computes_civil_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(
            days_since_epoch(at(2026, 9, 30)),
            days_from_civil(2026, 9, 30)
        );
    }
}

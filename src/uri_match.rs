//! URI matching is owned by the daemon. Browser callers never select the rule.

use regex::RegexBuilder;
use url::{Host, Url};

const MAX_URI_BYTES: usize = 16 * 1024;
const MAX_REGEX_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UriMatchType {
    Domain,
    #[default]
    Host,
    StartsWith,
    Exact,
    RegularExpression,
    Never,
    Unsupported,
}

impl UriMatchType {
    pub fn from_bitwarden(value: u64) -> Self {
        match value {
            0 => Self::Domain,
            1 => Self::Host,
            2 => Self::StartsWith,
            3 => Self::Exact,
            4 => Self::RegularExpression,
            5 => Self::Never,
            _ => Self::Unsupported,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LoginUri {
    pub uri: String,
    pub match_type: Option<UriMatchType>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MatchResult {
    pub matched: bool,
    pub insecure_downgrade: bool,
}

/// Only ordinary HTTP(S) documents are eligible. Userinfo is never useful for
/// browser autofill and can disguise the destination shown to the user.
pub fn page_url(value: &str) -> Option<Url> {
    if value.len() > MAX_URI_BYTES {
        return None;
    }
    let url = Url::parse(value).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none())
    .then_some(url)
}

fn saved_url(value: &str) -> Option<Url> {
    if value.contains("://") {
        page_url(value)
    } else {
        // A missing scheme is common in imported vaults. Do not reinterpret an
        // explicitly non-web scheme or a userinfo-like value as a hostname.
        let url = page_url(&format!("https://{value}"))?;
        (!value.contains('@')).then_some(url)
    }
}

fn normalized_host(url: &Url) -> Option<String> {
    url.host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
}

fn domain(url: &Url) -> Option<String> {
    let host = normalized_host(url)?;
    match url.host()? {
        Host::Ipv4(_) | Host::Ipv6(_) => Some(host),
        Host::Domain(_) => Some(psl::domain_str(&host).unwrap_or(&host).to_string()),
    }
}

fn regex_matches(pattern: &str, value: &str) -> bool {
    if pattern.len() > MAX_REGEX_BYTES {
        return false;
    }
    // Do not retain vault URI patterns in a process-global cache after locking.
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(256 * 1024)
        .dfa_size_limit(1024 * 1024)
        .build()
        .is_ok_and(|regex| regex.is_match(value))
}

pub fn matches(saved: &str, kind: UriMatchType, page: &str) -> MatchResult {
    let Some(page_url) = page_url(page) else {
        return MatchResult::default();
    };
    if saved.is_empty() || saved.len() > MAX_URI_BYTES {
        return MatchResult::default();
    }
    // Regexes must be handled before parsing: they are patterns, not URLs.
    if kind == UriMatchType::RegularExpression {
        let matched = regex_matches(saved, page);
        return MatchResult {
            matched,
            // An arbitrary pattern cannot reliably express an HTTPS expectation.
            // Require explicit confirmation for every HTTP regex match.
            insecure_downgrade: matched && page_url.scheme() == "http",
        };
    }
    if matches!(kind, UriMatchType::Never | UriMatchType::Unsupported) {
        return MatchResult::default();
    }
    let Some(saved_url) = saved_url(saved) else {
        return MatchResult::default();
    };
    let matched = match kind {
        UriMatchType::Domain => domain(&saved_url) == domain(&page_url),
        UriMatchType::Host => {
            normalized_host(&saved_url) == normalized_host(&page_url)
                && saved_url.port() == page_url.port()
        }
        // Preserve Bitwarden's literal case-sensitive prefix and exact rules.
        UriMatchType::StartsWith => page.starts_with(saved),
        UriMatchType::Exact => page == saved,
        _ => false,
    };
    MatchResult {
        matched,
        insecure_downgrade: matched && saved_url.scheme() == "https" && page_url.scheme() == "http",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_requires_the_same_host_and_normalized_port() {
        for (saved, page, expected) in [
            ("example.com", "https://example.com/login", true),
            ("example.com:8443", "https://example.com:8443/login", true),
            ("https://example.com:443", "https://example.com/", true),
            ("https://example.com:8443", "https://example.com/", false),
            ("https://example.com", "https://sub.example.com/", false),
            ("https://EXAMPLE.COM.", "https://example.com/", true),
            ("https://bücher.de", "https://xn--bcher-kva.de/", true),
            ("http://127.0.0.1:8000", "http://127.0.0.1:8000/", true),
            ("http://[::1]:8000", "http://[::1]:8001/", false),
            ("localhost:8000", "http://localhost:8000/", true),
            (
                "https://example.com",
                "https://example.com@evil.com/",
                false,
            ),
            ("https://example.com@evil.com", "https://evil.com/", false),
            ("file:///example.com", "https://example.com/", false),
        ] {
            assert_eq!(
                matches(saved, UriMatchType::Host, page).matched,
                expected,
                "{saved} {page}"
            );
        }
    }

    #[test]
    fn domain_uses_private_suffixes_and_local_hosts() {
        for (saved, page, expected) in [
            ("https://a.example.co.uk", "https://b.example.co.uk", true),
            ("https://a.github.io", "https://b.github.io", false),
            ("https://a.github.io", "https://www.a.github.io", true),
            ("http://127.0.0.1", "http://127.0.0.2", false),
            ("http://localhost", "http://localhost:8000", true),
            ("http://printer", "http://other-printer", false),
        ] {
            assert_eq!(
                matches(saved, UriMatchType::Domain, page).matched,
                expected,
                "{saved} {page}"
            );
        }
    }

    #[test]
    fn explicit_rules_fail_closed_and_regex_is_not_parsed_as_a_url() {
        assert!(
            matches(
                "https://example.com/login/",
                UriMatchType::StartsWith,
                "https://example.com/login/page"
            )
            .matched
        );
        assert!(
            !matches(
                "https://example.com/login",
                UriMatchType::Exact,
                "https://example.com/login?next=/"
            )
            .matched
        );
        assert!(
            matches(
                r"^https://[a-z]+\.example\.com/",
                UriMatchType::RegularExpression,
                "https://LOGIN.example.com/"
            )
            .matched
        );
        for pattern in ["[", "(?<=example)com", r"(example)\1"] {
            assert!(
                !matches(
                    pattern,
                    UriMatchType::RegularExpression,
                    "https://example.com/"
                )
                .matched
            );
        }
        assert!(
            !matches(
                &"x".repeat(MAX_REGEX_BYTES + 1),
                UriMatchType::RegularExpression,
                "https://example.com/"
            )
            .matched
        );
        for kind in [UriMatchType::Never, UriMatchType::Unsupported] {
            assert!(!matches("https://example.com/", kind, "https://example.com/").matched);
        }
        assert!(!matches("example.com", UriMatchType::Host, "javascript:example.com").matched);
        assert_eq!(UriMatchType::from_bitwarden(200), UriMatchType::Unsupported);
    }

    #[test]
    fn https_downgrades_require_confirmation() {
        assert_eq!(
            matches(
                "https://example.com/",
                UriMatchType::Host,
                "http://example.com/"
            ),
            MatchResult {
                matched: true,
                insecure_downgrade: true
            }
        );
        assert!(
            !matches(
                "http://example.com/",
                UriMatchType::Host,
                "http://example.com/"
            )
            .insecure_downgrade
        );
        assert!(
            matches(
                r"^https?://example\.com/",
                UriMatchType::RegularExpression,
                "http://example.com/"
            )
            .insecure_downgrade
        );
    }
}

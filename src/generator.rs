//! Password and passphrase generation. Every character and word is drawn uniformly with
//! kernel randomness (rejection sampling, no modulo bias). Nothing is saved or copied
//! until the user explicitly saves or copies the edited item.

use zeroize::Zeroize;

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*-_=+?";
/// Characters that are easy to confuse with one another when read or typed.
const AMBIGUOUS: &str = "Il1O0o";

pub const LENGTH_RANGE: std::ops::RangeInclusive<usize> = 8..=128;
pub const WORDS_RANGE: std::ops::RangeInclusive<usize> = 3..=20;

/// EFF Long Wordlist, shared with the browser extension's generator.
const WORDLIST_SOURCE: &str = include_str!("../extension/lib/password-words.ts");

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GeneratorMode {
    #[default]
    Password,
    Passphrase,
}

/// Generator preferences, remembered in the settings. Never holds a generated value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct GeneratorOptions {
    pub mode: GeneratorMode,
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            mode: GeneratorMode::Password,
            length: 24,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
            words: 5,
            separator: "-".into(),
            capitalize: true,
            include_number: true,
        }
    }
}

impl GeneratorOptions {
    /// The character classes a password draws from, after removing ambiguous characters.
    /// Lowercase letters stand in when every class is switched off.
    fn classes(&self) -> Vec<Vec<char>> {
        let mut classes = [
            (self.uppercase, UPPER),
            (self.lowercase, LOWER),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, chars)| {
            chars
                .chars()
                .filter(|c| !self.avoid_ambiguous || !AMBIGUOUS.contains(*c))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
        if classes.is_empty() {
            classes.push(LOWER.chars().collect());
        }
        classes
    }

    /// Bits of entropy of a value generated with these options, ignoring the small loss
    /// from requiring every class to appear.
    pub fn entropy_bits(&self) -> f64 {
        match self.mode {
            GeneratorMode::Password => {
                let alphabet = self.classes().iter().map(Vec::len).sum::<usize>();
                self.length() as f64 * (alphabet as f64).log2()
            }
            GeneratorMode::Passphrase => {
                let number = if self.include_number {
                    10f64.log2() + (self.words() as f64).log2()
                } else {
                    0.0
                };
                self.words() as f64 * (wordlist().len() as f64).log2() + number
            }
        }
    }

    pub fn length(&self) -> usize {
        self.length
            .clamp(*LENGTH_RANGE.start(), *LENGTH_RANGE.end())
    }

    pub fn words(&self) -> usize {
        self.words.clamp(*WORDS_RANGE.start(), *WORDS_RANGE.end())
    }

    /// The separator, limited to a few characters so it can't swamp the words.
    fn separator(&self) -> String {
        self.separator.chars().take(3).collect()
    }
}

/// A rough label for the entropy of a generated value.
pub fn strength_label(bits: f64) -> &'static str {
    match bits {
        b if b < 50.0 => "Weak",
        b if b < 70.0 => "Fair",
        b if b < 90.0 => "Good",
        _ => "Strong",
    }
}

pub fn generate(options: &GeneratorOptions) -> std::io::Result<String> {
    match options.mode {
        GeneratorMode::Password => password(options),
        GeneratorMode::Passphrase => passphrase(options),
    }
}

/// A password with at least one character of every enabled class. Rejecting
/// candidates that miss a class keeps every valid password equally likely.
fn password(options: &GeneratorOptions) -> std::io::Result<String> {
    let classes = options.classes();
    let alphabet = classes.concat();
    loop {
        let mut candidate = String::with_capacity(options.length());
        for _ in 0..options.length() {
            candidate.push(alphabet[uniform(alphabet.len())?]);
        }
        if classes
            .iter()
            .all(|class| candidate.chars().any(|c| class.contains(&c)))
        {
            return Ok(candidate);
        }
        candidate.zeroize();
    }
}

/// Words joined by the separator, optionally capitalized, with an optional digit
/// appended to one random word.
fn passphrase(options: &GeneratorOptions) -> std::io::Result<String> {
    let list = wordlist();
    let mut words = Vec::with_capacity(options.words());
    for _ in 0..options.words() {
        let word = list[uniform(list.len())?];
        let mut word = if options.capitalize {
            let mut chars = word.chars();
            chars
                .next()
                .map(|first| first.to_uppercase().chain(chars).collect())
                .unwrap_or_default()
        } else {
            word.to_string()
        };
        word.shrink_to_fit();
        words.push(word);
    }
    if options.include_number {
        let index = uniform(words.len())?;
        let digit = uniform(10)?;
        words[index].push_str(&digit.to_string());
    }
    let joined = words.join(&options.separator());
    words.zeroize();
    Ok(joined)
}

/// A uniformly random index below `size` (rejection sampling over 32-bit values).
fn uniform(size: usize) -> std::io::Result<usize> {
    assert!(size > 0 && size <= u32::MAX as usize);
    let size = size as u64;
    let limit = (1u64 << 32) / size * size;
    loop {
        let value = u64::from(u32::from_le_bytes(crate::random::random_bytes::<4>()?));
        if value < limit {
            return Ok((value % size) as usize);
        }
    }
}

/// The words between the backticks of the shared TypeScript module.
fn wordlist() -> &'static [&'static str] {
    static WORDS: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    WORDS.get_or_init(|| {
        let body = WORDLIST_SOURCE
            .split_once('`')
            .and_then(|(_, rest)| rest.split_once('`'))
            .map(|(body, _)| body)
            .unwrap_or_default();
        body.lines()
            .map(str::trim)
            .filter(|word| !word.is_empty())
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(mode: GeneratorMode) -> GeneratorOptions {
        GeneratorOptions {
            mode,
            ..GeneratorOptions::default()
        }
    }

    #[test]
    fn loads_the_full_eff_long_wordlist() {
        let words = wordlist();
        assert_eq!(words.len(), 7776);
        assert_eq!(words.first(), Some(&"abacus"));
        assert!(
            words
                .iter()
                .all(|word| word.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        );
    }

    #[test]
    fn passwords_have_the_requested_length_and_every_class() {
        for length in [8, 24, 128] {
            let options = GeneratorOptions {
                length,
                ..options(GeneratorMode::Password)
            };
            let password = generate(&options).unwrap();
            assert_eq!(password.chars().count(), length);
            assert!(password.chars().any(|c| c.is_ascii_uppercase()));
            assert!(password.chars().any(|c| c.is_ascii_lowercase()));
            assert!(password.chars().any(|c| c.is_ascii_digit()));
            assert!(password.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn passwords_respect_disabled_classes_and_ambiguity() {
        let options = GeneratorOptions {
            uppercase: false,
            symbols: false,
            avoid_ambiguous: true,
            ..options(GeneratorMode::Password)
        };
        for _ in 0..50 {
            let password = generate(&options).unwrap();
            assert!(
                password
                    .chars()
                    .all(|c| (c.is_ascii_lowercase() || c.is_ascii_digit())
                        && !AMBIGUOUS.contains(c))
            );
        }
    }

    #[test]
    fn no_classes_falls_back_to_lowercase() {
        let options = GeneratorOptions {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: false,
            ..options(GeneratorMode::Password)
        };
        assert!(
            generate(&options)
                .unwrap()
                .chars()
                .all(|c| c.is_ascii_lowercase())
        );
    }

    #[test]
    fn out_of_range_lengths_are_clamped() {
        let short = GeneratorOptions {
            length: 2,
            words: 1,
            ..GeneratorOptions::default()
        };
        assert_eq!(generate(&short).unwrap().len(), 8);
        let long = GeneratorOptions {
            mode: GeneratorMode::Passphrase,
            separator: " ".into(),
            words: 99,
            ..GeneratorOptions::default()
        };
        assert_eq!(generate(&long).unwrap().split(' ').count(), 20);
    }

    #[test]
    fn passphrases_join_capitalized_words_with_one_digit() {
        let options = GeneratorOptions {
            words: 6,
            separator: ".".into(),
            ..options(GeneratorMode::Passphrase)
        };
        let phrase = generate(&options).unwrap();
        let words = phrase.split('.').collect::<Vec<_>>();
        assert_eq!(words.len(), 6);
        assert!(
            words
                .iter()
                .all(|w| w.starts_with(|c: char| c.is_ascii_uppercase()))
        );
        assert_eq!(phrase.chars().filter(char::is_ascii_digit).count(), 1);

        let plain = GeneratorOptions {
            capitalize: false,
            include_number: false,
            ..options
        };
        let phrase = generate(&plain).unwrap();
        assert!(
            phrase
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '.' || c == '-')
        );
    }

    #[test]
    fn uniform_covers_every_index() {
        let mut seen = [0usize; 7];
        for _ in 0..7000 {
            seen[uniform(7).unwrap()] += 1;
        }
        // Each bucket expects 1000; 700 is far outside normal variation.
        assert!(seen.iter().all(|count| *count > 700), "{seen:?}");
    }

    #[test]
    fn entropy_matches_the_alphabet_and_wordlist() {
        let password = options(GeneratorMode::Password);
        // 26 + 26 + 10 + 13 = 75 characters.
        assert!((password.entropy_bits() - 24.0 * 75f64.log2()).abs() < 1e-9);
        let phrase = GeneratorOptions {
            include_number: false,
            ..options(GeneratorMode::Passphrase)
        };
        assert!((phrase.entropy_bits() - 5.0 * 7776f64.log2()).abs() < 1e-9);
        assert_eq!(strength_label(40.0), "Weak");
        assert_eq!(strength_label(64.6), "Fair");
        assert_eq!(strength_label(149.0), "Strong");
    }
}

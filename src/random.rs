//! Cryptographically secure random bytes from the kernel.

use std::fs;
use std::io::{self, Read};

pub fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Twenty-four uniformly sampled characters (144 random bits). Nothing is saved
/// or copied until the user explicitly saves or copies the edited item.
pub fn password() -> io::Result<String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bytes = random_bytes::<24>()?;
    let password = bytes
        .iter()
        .map(|byte| ALPHABET[(byte & 63) as usize] as char)
        .collect();
    use zeroize::Zeroize;
    bytes.zeroize();
    Ok(password)
}

#[cfg(test)]
mod tests {
    #[test]
    fn generated_password_has_expected_length_and_alphabet() {
        let first = super::password().unwrap();
        let second = super::password().unwrap();
        assert_eq!(first.len(), 24);
        assert!(
            first
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_ne!(first, second);
    }
}

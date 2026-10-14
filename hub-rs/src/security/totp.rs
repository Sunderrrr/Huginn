//! TOTP second factor (RFC 6238), byte-compatible with `app/services/totp.py`.
//!
//! HMAC-SHA1, 30s period, 6 digits, dynamic truncation; secrets are RFC 4648
//! base32 (what `pyotp` uses). `verify()` accepts the adjacent ±1 step for
//! clock skew (parity with `pyotp.TOTP.verify(code, valid_window=1)`).

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use subtle::ConstantTimeEq;

/// TOTP time-step in seconds.
pub const PERIOD: u64 = 30;
/// Number of digits in generated codes.
pub const DIGITS: u32 = 6;
/// Accepted clock-skew window (adjacent steps), like `_VALID_WINDOW` in Python.
pub const VALID_WINDOW: i64 = 1;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// Length of `pyotp.random_base32()` secrets.
const RANDOM_SECRET_CHARS: usize = 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("invalid base32 secret")]
    InvalidSecret,
}

/// Generate the TOTP code valid at Unix time `at_time`.
pub fn at(secret_b32: &str, at_time: u64) -> Result<String, TotpError> {
    let secret = decode_base32(secret_b32)?;
    Ok(hotp(&secret, at_time / PERIOD))
}

/// The current time-step (Python `current_step`).
pub fn current_step(now: u64) -> u64 {
    now / PERIOD
}

/// Constant-time TOTP check with a ±`valid_window` step tolerance.
///
/// `code` is normalized like the Python `verify()`: spaces stripped, all-digit.
pub fn verify(secret_b32: &str, code: &str, now: u64, valid_window: i64) -> bool {
    let code = normalize_code(code);
    if code.is_empty() || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let secret = match decode_base32(secret_b32) {
        Ok(secret) => secret,
        Err(_) => return false,
    };
    let now = now as i64;
    for offset in -valid_window..=valid_window {
        let step = ((now + offset * PERIOD as i64) / PERIOD as i64) as u64;
        let candidate = hotp(&secret, step);
        if constant_time_eq(candidate.as_bytes(), code.as_bytes()) {
            return true;
        }
    }
    false
}

/// Return the time-step a code matches (for replay tracking), else `None`.
///
/// Parity with `matched_step()` in `app/services/totp.py`: the adjacent ±1
/// steps around `now` are probed and the matched step returned.
pub fn matched_step(secret_b32: &str, code: &str, now: u64) -> Option<u64> {
    let code = normalize_code(code);
    if code.is_empty() || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secret = decode_base32(secret_b32).ok()?;
    let now = now as i64;
    for offset in -VALID_WINDOW..=VALID_WINDOW {
        let at_time = now + offset * PERIOD as i64;
        let step = (at_time / PERIOD as i64) as u64;
        let candidate = hotp(&secret, step);
        if constant_time_eq(candidate.as_bytes(), code.as_bytes()) {
            return Some(step);
        }
    }
    None
}

/// `otpauth://` provisioning URI, exactly what `pyotp` produces (default
/// algorithm/digits/period are omitted, as in `pyotp.TOTP.provisioning_uri`).
pub fn provisioning_uri(secret_b32: &str, username: &str, issuer: &str) -> String {
    format!("otpauth://totp/{issuer}:{username}?secret={secret_b32}&issuer={issuer}")
}

/// Same as [`provisioning_uri`] but with explicit `algorithm`/`digits`/`period`
/// query parameters (some authenticators want them spelled out).
pub fn provisioning_uri_with_params(
    secret_b32: &str,
    username: &str,
    issuer: &str,
    algorithm: &str,
    digits: u32,
    period: u64,
) -> String {
    format!(
        "otpauth://totp/{issuer}:{username}?secret={secret_b32}&issuer={issuer}\
         &algorithm={algorithm}&digits={digits}&period={period}"
    )
}

/// New base32 TOTP secret, like `pyotp.random_base32()`.
pub fn generate_secret() -> String {
    let mut bytes = [0u8; RANDOM_SECRET_CHARS];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|&b| BASE32_ALPHABET[(b >> 3) as usize & 31] as char)
        .collect()
}

/// HOTP (RFC 4226) with HMAC-SHA1 and dynamic truncation.
fn hotp(secret: &[u8], counter: u64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC-SHA1 accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    format!(
        "{:0width$}",
        binary % 10u32.pow(DIGITS),
        width = DIGITS as usize
    )
}

fn normalize_code(code: &str) -> String {
    code.trim().replace(' ', "")
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

/// RFC 4648 base32 decode, padding optional (what `pyotp`/`base64.b32decode`
/// accepts), case-insensitive.
pub fn decode_base32(input: &str) -> Result<Vec<u8>, TotpError> {
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    for c in input.chars() {
        if c == '=' {
            break; // padding terminator
        }
        if c.is_whitespace() {
            continue;
        }
        let value = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return Err(TotpError::InvalidSecret),
        };
        acc = (acc << 5) | value;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../security_vectors.json")).unwrap()
    }

    fn totp_vectors() -> serde_json::Value {
        vectors()["totp"].clone()
    }

    #[test]
    fn base32_decoding() {
        assert_eq!(
            decode_base32("JBSWY3DPEHPK3PXP").unwrap(),
            b"Hello!\xde\xad\xbe\xef"
        );
        assert_eq!(
            decode_base32("JBSWY3DPEHPK3PXP====").unwrap(),
            b"Hello!\xde\xad\xbe\xef"
        );
        assert_eq!(
            decode_base32("jbswy3dpehpk3pxp").unwrap(),
            b"Hello!\xde\xad\xbe\xef"
        );
        assert_eq!(decode_base32("MZXW6===").unwrap(), b"foo");
        assert_eq!(decode_base32("").unwrap(), Vec::<u8>::new());
        assert_eq!(
            decode_base32("JBSWY3DPEHPK3PX!"),
            Err(TotpError::InvalidSecret)
        );
    }

    /// Codes at the four vector timestamps match the Python implementation.
    #[test]
    fn codes_match_python() {
        let t = totp_vectors();
        let secret = t["seed_b32"].as_str().unwrap();

        assert_eq!(t["period"].as_u64().unwrap(), PERIOD);
        assert_eq!(t["digits"].as_u64().unwrap(), DIGITS as u64);
        assert_eq!(t["valid_window"].as_i64().unwrap(), VALID_WINDOW);

        for (ts, expected) in t["codes_at"].as_object().unwrap() {
            let at_time: u64 = ts.parse().unwrap();
            assert_eq!(
                at(secret, at_time).unwrap(),
                expected.as_str().unwrap(),
                "code at t={ts}"
            );
            assert_eq!(current_step(at_time), at_time / PERIOD);
        }
    }

    #[test]
    fn verify_accepts_window_and_rejects_outside() {
        let t = totp_vectors();
        let secret = t["seed_b32"].as_str().unwrap();
        let now = 1700000000u64;
        let code = at(secret, now).unwrap();

        assert!(verify(secret, &code, now, VALID_WINDOW));
        assert!(verify(secret, &code, now - PERIOD, VALID_WINDOW));
        assert!(verify(secret, &code, now + PERIOD, VALID_WINDOW));
        assert!(!verify(secret, &code, now - 2 * PERIOD, VALID_WINDOW));
        assert!(!verify(secret, &code, now + 2 * PERIOD, VALID_WINDOW));
        assert!(!verify(secret, "000000", now, VALID_WINDOW));
        assert!(!verify(secret, "abcdef", now, VALID_WINDOW));
        assert!(!verify(secret, "", now, VALID_WINDOW));
        assert!(!verify("not-base32!", &code, now, VALID_WINDOW));

        // Spaces are stripped, like Python's `verify()`.
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert!(verify(secret, &spaced, now, VALID_WINDOW));
    }

    #[test]
    fn matched_step_reports_the_matching_step() {
        let t = totp_vectors();
        let secret = t["seed_b32"].as_str().unwrap();
        let now = 1700000000u64;
        let step = now / PERIOD;
        let code = at(secret, now).unwrap();

        assert_eq!(matched_step(secret, &code, now), Some(step));
        assert_eq!(matched_step(secret, &code, now - PERIOD), Some(step));
        assert_eq!(matched_step(secret, &code, now + PERIOD), Some(step));
        assert_eq!(matched_step(secret, &code, now - 2 * PERIOD), None);
        assert_eq!(matched_step(secret, &code, now + 2 * PERIOD), None);
        assert_eq!(matched_step(secret, "000000", now), None);
        assert_eq!(matched_step(secret, "xyz", now), None);

        // A code from the previous step maps to that step.
        let prev = at(secret, now - PERIOD).unwrap();
        assert_eq!(matched_step(secret, &prev, now), Some(step - 1));
    }

    #[test]
    fn provisioning_uri_matches_pyotp() {
        let t = totp_vectors();
        assert_eq!(
            provisioning_uri(t["seed_b32"].as_str().unwrap(), "admin", "Huginn"),
            t["provisioning_uri"].as_str().unwrap()
        );
        assert_eq!(
            provisioning_uri_with_params("JBSWY3DPEHPK3PXP", "admin", "Huginn", "SHA1", 6, 30),
            "otpauth://totp/Huginn:admin?secret=JBSWY3DPEHPK3PXP&issuer=Huginn\
             &algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn generated_secrets_are_base32() {
        let s = generate_secret();
        assert_eq!(s.len(), 16);
        assert!(s.bytes().all(|b| BASE32_ALPHABET.contains(&b)));
        assert!(decode_base32(&s).is_ok());
        assert_ne!(s, generate_secret());
    }
}

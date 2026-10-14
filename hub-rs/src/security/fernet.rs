//! Fernet-compatible symmetric encryption for TOTP secrets at rest.
//!
//! Byte parity with `app/services/totp.py` (`cryptography.fernet.Fernet` over a
//! key derived from `mfa_encryption_key`):
//!
//! - `key = base64url(sha256(mfa_encryption_key utf-8))` (padded);
//! - `token = base64url([0x80][timestamp u64 BE][iv 16B][AES-128-CBC-PKCS7(plaintext)][HMAC-SHA256])`,
//!   padded base64url, where the HMAC covers `token[:-32]` and the **first**
//!   16 bytes of the decoded key are the HMAC key (the last 16 are the AES
//!   key), exactly like `cryptography`'s `Fernet` (`_signing_key = key[:16]`,
//!   `_encryption_key = key[16:]`).

use aes::Aes128;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Fernet token version byte.
const VERSION: u8 = 0x80;
const IV_LEN: usize = 16;
const MAC_LEN: usize = 32;
const KEY_LEN: usize = 32;

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

#[derive(Debug, thiserror::Error)]
pub enum FernetError {
    #[error("cannot decode Fernet token")]
    Decode,
    #[error("invalid Fernet token version")]
    Version,
    #[error("invalid Fernet token signature")]
    Signature,
    #[error("invalid Fernet token padding")]
    Padding,
    #[error("plaintext is not valid UTF-8")]
    Utf8,
    #[error("encryption failed: {0}")]
    Encrypt(String),
}

/// Derive the 32-byte Fernet key from the configured MFA secret:
/// `sha256(mfa_encryption_key utf-8)`.
pub fn derive_key(mfa_encryption_key: &str) -> [u8; KEY_LEN] {
    Sha256::digest(mfa_encryption_key.as_bytes()).into()
}

/// The derived key as a padded urlsafe-base64 string (what the Python
/// `_fernet()` helper passes to `Fernet`).
pub fn derive_key_b64(mfa_encryption_key: &str) -> String {
    URL_SAFE.encode(derive_key(mfa_encryption_key))
}

/// Fernet-compatible cipher.
#[derive(Debug, Clone)]
pub struct Fernet {
    signing_key: [u8; 16],
    encryption_key: [u8; 16],
}

impl Fernet {
    /// Build the cipher from the configured MFA encryption key.
    pub fn new(mfa_encryption_key: &str) -> Self {
        Self::from_derived_key(&derive_key(mfa_encryption_key))
    }

    /// Build the cipher from an already-derived 32-byte key.
    pub fn from_derived_key(key: &[u8; KEY_LEN]) -> Self {
        let mut signing_key = [0u8; 16];
        let mut encryption_key = [0u8; 16];
        signing_key.copy_from_slice(&key[..16]);
        encryption_key.copy_from_slice(&key[16..]);
        Self {
            signing_key,
            encryption_key,
        }
    }

    /// Encrypt a UTF-8 secret (current timestamp).
    pub fn encrypt(&self, plaintext: &str) -> Result<String, FernetError> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.encrypt_at(plaintext, ts)
    }

    /// Encrypt a UTF-8 secret with an explicit timestamp.
    pub fn encrypt_at(&self, plaintext: &str, timestamp: u64) -> Result<String, FernetError> {
        self.encrypt_bytes_at(plaintext.as_bytes(), timestamp)
    }

    /// Encrypt raw bytes with the current timestamp.
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<String, FernetError> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.encrypt_bytes_at(plaintext, ts)
    }

    /// Encrypt raw bytes with an explicit timestamp and IV (fully
    /// deterministic; used where reproducible tokens are needed).
    pub fn encrypt_with_iv(
        &self,
        plaintext: &[u8],
        timestamp: u64,
        iv: &[u8; IV_LEN],
    ) -> Result<String, FernetError> {
        let ct = Aes128CbcEnc::new_from_slices(&self.encryption_key, iv)
            .map_err(|_| FernetError::Encrypt("bad key/iv length".to_owned()))?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        Ok(self.seal(timestamp, iv, &ct))
    }

    /// Encrypt raw bytes with an explicit timestamp (random IV).
    pub fn encrypt_bytes_at(
        &self,
        plaintext: &[u8],
        timestamp: u64,
    ) -> Result<String, FernetError> {
        let mut iv = [0u8; IV_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut iv);
        self.encrypt_with_iv(plaintext, timestamp, &iv)
    }

    /// Decrypt to a UTF-8 secret (like Python `decrypt_secret`).
    pub fn decrypt(&self, token: &str) -> Result<String, FernetError> {
        let bytes = self.decrypt_bytes(token)?;
        String::from_utf8(bytes).map_err(|_| FernetError::Utf8)
    }

    /// Decrypt to raw bytes, rejecting bad version/mac/padding.
    pub fn decrypt_bytes(&self, token: &str) -> Result<Vec<u8>, FernetError> {
        let raw = b64url_decode(token).map_err(|_| FernetError::Decode)?;
        if raw.len() < 1 + 8 + IV_LEN + MAC_LEN {
            return Err(FernetError::Decode);
        }
        if raw[0] != VERSION {
            return Err(FernetError::Version);
        }
        let (body, mac) = raw.split_at(raw.len() - MAC_LEN);
        let expected = self.mac(body);
        if !bool::from(mac.ct_eq(expected.as_slice())) {
            return Err(FernetError::Signature);
        }
        let iv: &[u8] = &body[9..9 + IV_LEN];
        let ct: &[u8] = &body[9 + IV_LEN..];
        Aes128CbcDec::new_from_slices(&self.encryption_key, iv)
            .map_err(|_| FernetError::Decode)?
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .map_err(|_| FernetError::Padding)
    }

    fn seal(&self, timestamp: u64, iv: &[u8; IV_LEN], ct: &[u8]) -> String {
        let mut body = Vec::with_capacity(1 + 8 + IV_LEN + ct.len());
        body.push(VERSION);
        body.extend_from_slice(&timestamp.to_be_bytes());
        body.extend_from_slice(iv);
        body.extend_from_slice(ct);
        let mac = self.mac(&body);
        body.extend_from_slice(&mac);
        URL_SAFE.encode(body)
    }

    fn mac(&self, body: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.signing_key)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(body);
        mac.finalize().into_bytes().to_vec()
    }
}

/// One-shot encryption with the configured MFA key.
pub fn encrypt(mfa_encryption_key: &str, plaintext: &str) -> Result<String, FernetError> {
    Fernet::new(mfa_encryption_key).encrypt(plaintext)
}

/// One-shot decryption with the configured MFA key.
pub fn decrypt(mfa_encryption_key: &str, token: &str) -> Result<String, FernetError> {
    Fernet::new(mfa_encryption_key).decrypt(token)
}

/// Padded base64url decode (padding tolerated).
fn b64url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(input.trim_end_matches('='))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../security_vectors.json")).unwrap()
    }

    fn fernet_vectors() -> serde_json::Value {
        vectors()["fernet"].clone()
    }

    /// The derived key matches the Python vector byte for byte.
    #[test]
    fn derived_key_matches_python() {
        let f = fernet_vectors();
        let mfa_key = f["mfa_key"].as_str().unwrap();
        assert_eq!(
            derive_key_b64(mfa_key),
            f["derived_key_b64"].as_str().unwrap()
        );
    }

    /// The ciphertext produced by Python's Fernet decrypts to the TOTP secret.
    #[test]
    fn decrypts_python_ciphertext() {
        let f = fernet_vectors();
        let fe = Fernet::new(f["mfa_key"].as_str().unwrap());
        let ciphertext = f["ciphertext"].as_str().unwrap();
        assert_eq!(
            fe.decrypt(ciphertext).unwrap(),
            f["plaintext_secret_b32"].as_str().unwrap()
        );
        assert_eq!(
            fe.decrypt_bytes(ciphertext).unwrap(),
            f["plaintext_secret_b32"].as_str().unwrap().as_bytes()
        );
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let f = fernet_vectors();
        let fe = Fernet::new(f["mfa_key"].as_str().unwrap());
        let plaintext = f["plaintext_secret_b32"].as_str().unwrap();

        let token = fe.encrypt(plaintext).unwrap();
        assert!(
            token.starts_with("gAAAAA"),
            "Fernet version/timestamp prefix"
        );
        assert_eq!(fe.decrypt(&token).unwrap(), plaintext);

        // Deterministic encryption reproduces the Python token layout.
        let fixed = fe
            .encrypt_with_iv(plaintext.as_bytes(), 1791983162, &[7u8; 16])
            .unwrap();
        assert_eq!(fe.decrypt(&fixed).unwrap(), plaintext);
    }

    /// Tampered tokens are rejected (HMAC check covers everything but the mac).
    #[test]
    fn rejects_tampered_tokens() {
        let f = fernet_vectors();
        let fe = Fernet::new(f["mfa_key"].as_str().unwrap());
        let ciphertext = f["ciphertext"].as_str().unwrap();
        assert!(f["tampered_must_fail"].as_bool().unwrap());

        // Flip one character inside the ciphertext part of the token.
        let raw = b64url_decode(ciphertext).unwrap();
        let mut tampered = raw.clone();
        tampered[40] ^= 0x01;
        assert!(matches!(
            fe.decrypt_bytes(&URL_SAFE.encode(tampered)),
            Err(FernetError::Signature)
        ));

        // Wrong key -> signature failure.
        assert!(matches!(
            Fernet::new("another-key").decrypt(ciphertext),
            Err(FernetError::Signature)
        ));

        // Version byte != 0x80 (re-sealed so the mac still validates).
        let fe2 = Fernet::from_derived_key(&derive_key(f["mfa_key"].as_str().unwrap()));
        let mut body = raw[..raw.len() - MAC_LEN].to_vec();
        body[0] = 0x81;
        let mut resealed = body.clone();
        resealed.extend_from_slice(&fe2.mac(&body));
        assert!(matches!(
            fe2.decrypt_bytes(&URL_SAFE.encode(resealed)),
            Err(FernetError::Version)
        ));

        // Truncated / garbage.
        assert!(matches!(fe.decrypt_bytes("AAAA"), Err(FernetError::Decode)));
        assert!(matches!(fe.decrypt_bytes(""), Err(FernetError::Decode)));
    }

    /// A correctly signed token with broken PKCS7 padding is rejected.
    #[test]
    fn rejects_invalid_padding() {
        use cbc::cipher::block_padding::NoPadding;

        let f = fernet_vectors();
        let fe = Fernet::new(f["mfa_key"].as_str().unwrap());

        // Build a 2-block ciphertext by hand: P0 arbitrary, P1 = [0x00;15] ++ [0x0f]
        // (claims 15 padding bytes but the preceding byte is 0x00 -> invalid).
        let iv = [3u8; IV_LEN];
        let p0 = [0x41u8; 16];
        let mut p1 = [0u8; 16];
        p1[15] = 0x0f;

        // CBC: C0 = E(K, P0 ^ IV); C1 = E(K, P1 ^ C0)  =>  D(K, C1) ^ C0 == P1.
        let c0 = Aes128CbcEnc::new_from_slices(&fe.encryption_key, &iv)
            .unwrap()
            .encrypt_padded_vec_mut::<NoPadding>(&p0);
        let c1 = Aes128CbcEnc::new_from_slices(&fe.encryption_key, &c0)
            .unwrap()
            .encrypt_padded_vec_mut::<NoPadding>(&p1);

        let mut body = Vec::new();
        body.push(VERSION);
        body.extend_from_slice(&0u64.to_be_bytes());
        body.extend_from_slice(&iv);
        body.extend_from_slice(&c0);
        body.extend_from_slice(&c1);
        let mut token = body.clone();
        token.extend_from_slice(&fe.mac(&body));
        assert!(matches!(
            fe.decrypt_bytes(&URL_SAFE.encode(token)),
            Err(FernetError::Padding)
        ));
    }
}

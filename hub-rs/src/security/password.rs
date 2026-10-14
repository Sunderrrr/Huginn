//! User password hashing — Argon2id, PHC-string encoded.
//!
//! Parity with `app/core/security.py` (argon2-cffi `PasswordHasher`): the
//! encoded hash is `$argon2id$v=19$m=...,t=...,p=...$salt$hash` with standard
//! base64 (unpadded) salt/hash, exactly like argon2-cffi produces.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use rand::RngCore;
use subtle::ConstantTimeEq;

/// Argon2id cost parameters (unit of `memory_cost`: KiB).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordParams {
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
    pub hash_len: u32,
    pub salt_len: u32,
}

/// Default cost parameters — identical to the ones in `security_vectors.json`
/// (verified against the reference PHC vector at test time).
pub const DEFAULT_PARAMS: PasswordParams = PasswordParams {
    time_cost: 3,
    memory_cost: 65536,
    parallelism: 4,
    hash_len: 32,
    salt_len: 16,
};

/// Largest hash length accepted when verifying a PHC string (argon2 maximum
/// usable output is 64 bytes).
const MAX_HASH_LEN: usize = 64;
/// Smallest hash length accepted when verifying a PHC string.
const MIN_HASH_LEN: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("invalid argon2 parameters: {0}")]
    InvalidParams(String),
    #[error("invalid password hash: {0}")]
    InvalidHash(String),
    #[error("hashing failed: {0}")]
    Hashing(String),
}

/// Hash a password with a fresh random salt, returning an argon2-cffi
/// compatible PHC string.
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    hash_password_with(password, DEFAULT_PARAMS)
}

/// Same as [`hash_password`] with explicit cost parameters.
pub fn hash_password_with(password: &str, params: PasswordParams) -> Result<String, PasswordError> {
    let mut salt = vec![0u8; params.salt_len as usize];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut hash = vec![0u8; params.hash_len as usize];
    argon2(params)?
        .hash_password_into(password.as_bytes(), &salt, &mut hash)
        .map_err(|e| PasswordError::Hashing(e.to_string()))?;
    Ok(format!(
        "$argon2id$v=19$m={},t={},p={}${}${}",
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        STANDARD_NO_PAD.encode(salt),
        STANDARD_NO_PAD.encode(hash)
    ))
}

/// Verify a password against an optional PHC hash.
///
/// Returns `False` for missing hashes (after spending comparable work, so the
/// timing does not reveal whether the account has a password — parity with
/// `verify_password()` in `app/core/security.py`).
pub fn verify_password(password: &str, password_hash: Option<&str>) -> bool {
    match password_hash {
        None => {
            let _ = hash_password(password);
            false
        }
        Some(phc) => verify_password_phc(password, phc),
    }
}

/// Whether the hash was produced with weaker/different parameters than the
/// current defaults (parity with argon2-cffi `check_needs_rehash`).
pub fn needs_rehash(password_hash: &str) -> bool {
    let parsed = match parse_phc(password_hash) {
        Ok(parsed) => parsed,
        Err(_) => return true,
    };
    let d = DEFAULT_PARAMS;
    parsed.version != 0x13
        || parsed.time_cost != d.time_cost
        || parsed.memory_cost != d.memory_cost
        || parsed.parallelism != d.parallelism
        || (parsed.hash.len() as u32) < d.hash_len
        || (parsed.salt.len() as u32) < d.salt_len
}

/// A parsed argon2 PHC string.
struct PhcHash {
    version: u32,
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

fn argon2(params: PasswordParams) -> Result<Argon2<'static>, PasswordError> {
    let p = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(params.hash_len as usize),
    )
    .map_err(|e| PasswordError::InvalidParams(e.to_string()))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, p))
}

fn parse_phc(phc: &str) -> Result<PhcHash, PasswordError> {
    let invalid = |why: &str| PasswordError::InvalidHash(why.to_owned());
    let parts: Vec<&str> = phc.split('$').collect();
    if parts.len() != 6 || !parts[0].is_empty() {
        return Err(invalid("not an argon2 PHC string"));
    }
    if parts[1] != "argon2id" {
        return Err(invalid("not an argon2id hash"));
    }
    let version = match parts[2] {
        "v=19" => 19,
        "v=16" => 16,
        _ => return Err(invalid("unsupported version")),
    };
    let (mut m, mut t, mut p) = (None, None, None);
    for kv in parts[3].split(',') {
        let mut it = kv.splitn(2, '=');
        let (key, value) = match (it.next(), it.next()) {
            (Some(k), Some(v)) => (k, v),
            _ => return Err(invalid("malformed parameters")),
        };
        let value: u32 = value
            .parse()
            .map_err(|_| invalid("non-numeric parameter"))?;
        match key {
            "m" => m = Some(value),
            "t" => t = Some(value),
            "p" => p = Some(value),
            _ => return Err(invalid("unknown parameter")),
        }
    }
    let (m, t, p) = match (m, t, p) {
        (Some(m), Some(t), Some(p)) => (m, t, p),
        _ => return Err(invalid("missing parameters")),
    };
    let salt = b64_decode(parts[4]).map_err(|_| invalid("invalid salt encoding"))?;
    let hash = b64_decode(parts[5]).map_err(|_| invalid("invalid hash encoding"))?;
    if hash.len() < MIN_HASH_LEN || hash.len() > MAX_HASH_LEN {
        return Err(invalid("invalid hash length"));
    }
    Ok(PhcHash {
        version,
        time_cost: t,
        memory_cost: m,
        parallelism: p,
        salt,
        hash,
    })
}

fn verify_password_phc(password: &str, phc: &str) -> bool {
    let parsed = match parse_phc(phc) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    let params = PasswordParams {
        time_cost: parsed.time_cost,
        memory_cost: parsed.memory_cost,
        parallelism: parsed.parallelism,
        hash_len: parsed.hash.len() as u32,
        salt_len: parsed.salt.len() as u32,
    };
    let version = match parsed.version {
        19 => Version::V0x13,
        16 => Version::V0x10,
        _ => return false,
    };
    let argon2 = match Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(params.hash_len as usize),
    ) {
        Ok(p) => Argon2::new(Algorithm::Argon2id, version, p),
        Err(_) => return false,
    };
    let mut computed = vec![0u8; parsed.hash.len()];
    if argon2
        .hash_password_into(password.as_bytes(), &parsed.salt, &mut computed)
        .is_err()
    {
        return false;
    }
    bool::from(computed.ct_eq(&parsed.hash))
}

/// Standard base64 without padding (padding tolerated, like argon2-cffi).
fn b64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD_NO_PAD.decode(input.trim_end_matches('='))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../security_vectors.json")).unwrap()
    }

    /// The Python-generated PHC vector verifies, wrong passwords don't, and the
    /// cost parameters are exactly the ones carried by the vectors.
    #[test]
    fn verifies_python_phc_vector() {
        let v = vectors();
        let a = &v["argon2"];
        let phc = a["phc_verify_only"].as_str().unwrap();
        let password = a["password"].as_str().unwrap();

        assert!(verify_password(password, Some(phc)));
        assert!(!verify_password("wrong password", Some(phc)));
        assert!(!verify_password("", Some(phc)));
        // Missing hash -> false (but still does the work).
        assert!(!verify_password(password, None));
    }

    #[test]
    fn params_match_vectors() {
        let v = vectors();
        let p = &v["argon2"]["params"];
        assert_eq!(p["type"].as_str().unwrap(), "ID");
        assert_eq!(p["version"].as_i64().unwrap(), 19);
        assert_eq!(
            DEFAULT_PARAMS.time_cost,
            p["time_cost"].as_u64().unwrap() as u32
        );
        assert_eq!(
            DEFAULT_PARAMS.memory_cost,
            p["memory_cost"].as_u64().unwrap() as u32
        );
        assert_eq!(
            DEFAULT_PARAMS.parallelism,
            p["parallelism"].as_u64().unwrap() as u32
        );
        assert_eq!(
            DEFAULT_PARAMS.hash_len,
            p["hash_len"].as_u64().unwrap() as u32
        );
        assert_eq!(
            DEFAULT_PARAMS.salt_len,
            p["salt_len"].as_u64().unwrap() as u32
        );

        // The reference PHC really carries those parameters.
        let parsed = parse_phc(v["argon2"]["phc_verify_only"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.time_cost, DEFAULT_PARAMS.time_cost);
        assert_eq!(parsed.memory_cost, DEFAULT_PARAMS.memory_cost);
        assert_eq!(parsed.parallelism, DEFAULT_PARAMS.parallelism);
        assert_eq!(parsed.hash.len(), DEFAULT_PARAMS.hash_len as usize);
        assert_eq!(parsed.salt.len(), DEFAULT_PARAMS.salt_len as usize);
    }

    #[test]
    fn hash_password_roundtrip_and_format() {
        let h = hash_password("correct horse battery staple").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
        assert!(verify_password("correct horse battery staple", Some(&h)));
        assert!(!verify_password("Correct horse battery staple", Some(&h)));
        assert!(!needs_rehash(&h));

        let parts: Vec<&str> = h.split('$').collect();
        assert_eq!(
            b64_decode(parts[5]).unwrap().len(),
            DEFAULT_PARAMS.hash_len as usize
        );
        assert_eq!(
            b64_decode(parts[4]).unwrap().len(),
            DEFAULT_PARAMS.salt_len as usize
        );

        // Two calls yield different salts.
        let h2 = hash_password("correct horse battery staple").unwrap();
        assert_ne!(h, h2);
        assert!(verify_password("correct horse battery staple", Some(&h2)));
    }

    #[test]
    fn needs_rehash_flags_old_params() {
        let weak = hash_password_with(
            "pw",
            PasswordParams {
                time_cost: 1,
                memory_cost: 4096,
                parallelism: 1,
                hash_len: 32,
                salt_len: 16,
            },
        )
        .unwrap();
        assert!(needs_rehash(&weak));
        // Short salt also needs a rehash (argon2-cffi rule).
        let short_salt = hash_password_with(
            "pw",
            PasswordParams {
                salt_len: 8,
                ..DEFAULT_PARAMS
            },
        )
        .unwrap();
        assert!(needs_rehash(&short_salt));
    }

    #[test]
    fn rejects_malformed_hashes() {
        assert!(!verify_password("pw", Some("garbage")));
        assert!(!verify_password(
            "pw",
            Some("$argon2i$v=19$m=65536,t=3,p=4$aaaa$bbbb")
        ));
        assert!(!verify_password(
            "pw",
            Some("$argon2id$v=19$m=65536,t=3,p=4$")
        ));
        assert!(!verify_password(
            "pw",
            Some("$argon2id$v=19$m=65536,t=3,p=4$!!!notb64!!!$HZ7hck1fk6CCqx+eERzycu4kYo2+isUeQFx9icA8dQI")
        ));
    }
}

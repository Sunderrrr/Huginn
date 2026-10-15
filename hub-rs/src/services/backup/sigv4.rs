//! AWS Signature Version 4 request signing (header-based), hand-rolled.
//!
//! The hub uploads database dumps to S3-compatible storage (AWS S3, MinIO,
//! Cloudflare R2, Backblaze B2 …) without pulling in the AWS SDK: SigV4 is
//! just an HMAC-SHA256 chain over a canonical request ([`hmac`] + [`sha2`] are
//! already in the tree for the security primitives).
//!
//! Canonicalisation follows the AWS spec to the letter and is verified in the
//! tests against two independent references:
//!
//! * the worked IAM example published in the AWS docs
//!   (`create-signed-request` / signature calculation for `ListUsers`), and
//! * `sigv4_vectors.json`, canonical requests produced by **botocore** (the
//!   reference implementation every AWS SDK and every S3-compatible server is
//!   tested against) for S3-shaped requests.
//!
//! The two rules that are easy to get wrong (and are pinned by the vectors):
//!
//! * the canonical URI is the **URI-encoded path**: the path is given decoded
//!   (as a raw object key) and percent-encoded here exactly once — the same
//!   encoding goes on the wire, so the server sees the key it decodes back;
//! * the canonical query string percent-encodes every name and value with the
//!   unreserved set only (`A-Za-z0-9-._~` — so `/`, space, `+`, `=` … all get
//!   encoded) and sorts the pairs afterwards.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Everything one request needs to be signed. `path` is the **decoded** path
/// (raw object key); [`SignParams::canonical_uri`] encodes it exactly like the
/// request does on the wire. `query` holds decoded name/value pairs.
#[derive(Debug, Clone)]
pub struct SignParams<'a> {
    pub method: &'a str,
    /// Host header value (`bucket.s3.…` or `host:port` for custom endpoints).
    pub host: &'a str,
    /// Decoded path, e.g. `db/backups/x.sql.gz` or `/`.
    pub path: &'a str,
    /// Decoded query parameters (already split).
    pub query: &'a [(String, String)],
    /// The headers to sign; must contain `host`. Names are lower-cased and
    /// values trimmed/collapsed on canonicalisation.
    pub headers: Vec<(String, String)>,
    /// Lowercase hex SHA-256 of the payload (or `UNSIGNED-PAYLOAD`).
    pub payload_sha256_hex: &'a str,
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    /// Request timestamp, `YYYYMMDDTHHMMSSZ`.
    pub amz_date: &'a str,
}

impl SignParams<'_> {
    /// The date part of [`Self::amz_date`] (`YYYYMMDD`).
    pub fn date(&self) -> &str {
        &self.amz_date[..self.amz_date.len().min(8)]
    }

    /// `YYYYMMDD/region/service/aws4_request`.
    pub fn credential_scope(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            self.date(),
            self.region,
            self.service
        )
    }
}

/// Percent-encode per RFC 3986 with the unreserved set `A-Za-z0-9-._~` left
/// as-is (AWS `UriEncode`). `keep_slash` is true for path components only —
/// the `/` of an object key is *not* encoded.
pub fn uri_encode(value: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            b'/' if keep_slash => out.push('/'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Lowercase hexadecimal SHA-256.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    crate::security::hex_encode(&hasher.finalize())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// `kSigning = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service),
/// "aws4_request")` — returns the raw key bytes.
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// The `CanonicalURI` element.
pub fn canonical_uri(params: &SignParams) -> String {
    let encoded = uri_encode(params.path, true);
    if encoded.is_empty() {
        "/".to_owned()
    } else {
        encoded
    }
}

/// The `CanonicalQueryString` element: percent-encoded pairs sorted by name
/// (then value), joined with `&`.
pub fn canonical_query_string(params: &SignParams) -> String {
    let mut pairs: Vec<(String, String)> = params
        .query
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The `CanonicalHeaders` element (lower-cased names, trimmed/collapsed
/// values, sorted, each line terminated by `\n`).
pub fn canonical_headers(params: &SignParams) -> String {
    let mut headers: Vec<(String, String)> = params
        .headers
        .iter()
        .map(|(name, value)| {
            let collapsed = value.split_whitespace().collect::<Vec<_>>().join(" ");
            (name.trim().to_ascii_lowercase(), collapsed)
        })
        .collect();
    headers.sort();
    let mut out = String::new();
    for (name, value) in headers {
        out.push_str(&name);
        out.push(':');
        out.push_str(&value);
        out.push('\n');
    }
    out
}

/// The `SignedHeaders` element.
pub fn signed_headers(params: &SignParams) -> String {
    let mut names: Vec<String> = params
        .headers
        .iter()
        .map(|(name, _)| name.trim().to_ascii_lowercase())
        .collect();
    names.sort();
    names.dedup();
    names.join(";")
}

/// The six-element canonical request.
pub fn canonical_request(params: &SignParams) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        params.method,
        canonical_uri(params),
        canonical_query_string(params),
        canonical_headers(params),
        signed_headers(params),
        params.payload_sha256_hex
    )
}

/// The four-element string to sign (no trailing newline).
pub fn string_to_sign(params: &SignParams) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        params.amz_date,
        params.credential_scope(),
        sha256_hex(canonical_request(params).as_bytes())
    )
}

/// Lowercase hex signature.
pub fn signature(params: &SignParams) -> String {
    let key = signing_key(
        params.secret_key,
        params.date(),
        params.region,
        params.service,
    );
    crate::security::hex_encode(&hmac_sha256(&key, string_to_sign(params).as_bytes()))
}

/// The complete `Authorization: …` header value.
pub fn authorization(params: &SignParams) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        params.access_key,
        params.credential_scope(),
        signed_headers(params),
        signature(params)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example published in the AWS IAM docs ("Create a signed AWS
    /// request" / signature calculation for `ListUsers`) — every intermediate
    /// value is asserted, not just the final signature.
    #[test]
    fn matches_the_published_aws_iam_example() {
        let query = vec![
            ("Action".to_owned(), "ListUsers".to_owned()),
            ("Version".to_owned(), "2010-05-08".to_owned()),
        ];
        let params = SignParams {
            method: "GET",
            host: "iam.amazonaws.com",
            path: "/",
            query: &query,
            headers: vec![
                (
                    "content-type".to_owned(),
                    "application/x-www-form-urlencoded; charset=utf-8".to_owned(),
                ),
                ("host".to_owned(), "iam.amazonaws.com".to_owned()),
                ("x-amz-date".to_owned(), "20150830T123600Z".to_owned()),
            ],
            payload_sha256_hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            access_key: "AKIDEXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "iam",
            amz_date: "20150830T123600Z",
        };

        // Task 1: canonical request + its hash.
        assert_eq!(
            canonical_request(&params),
            "GET\n/\nAction=ListUsers&Version=2010-05-08\n\
             content-type:application/x-www-form-urlencoded; charset=utf-8\n\
             host:iam.amazonaws.com\n\
             x-amz-date:20150830T123600Z\n\
             \n\
             content-type;host;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(canonical_request(&params).as_bytes()),
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        );

        // Task 2: string to sign.
        assert_eq!(
            string_to_sign(&params),
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\n\
             f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        );

        // Task 3: signing key + signature + the Authorization header.
        assert_eq!(
            crate::security::hex_encode(&signing_key(
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                "20150830",
                "us-east-1",
                "iam"
            )),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
        assert_eq!(
            signature(&params),
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
        assert_eq!(
            authorization(&params),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    /// `sigv4_vectors.json` — canonical requests produced by botocore 1.40
    /// (reference implementation) for S3-shaped requests. The vectors were
    /// generated with the paths passed decoded and the queries passed fully
    /// percent-encoded, which is exactly how [`SignParams`] sees them.
    #[test]
    fn matches_the_botocore_s3_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("sigv4_vectors.json")).unwrap();
        for vector in vectors.as_array().unwrap() {
            let name = vector["name"].as_str().unwrap();
            let url = vector["url"].as_str().unwrap();
            let (raw_path, raw_query) = match url.split_once('?') {
                Some((path, query)) => (path, query),
                None => (url, ""),
            };
            let path = raw_path
                .split_once("://")
                .map(|(_, rest)| rest)
                .unwrap_or(raw_path);
            let path = match path.split_once('/') {
                Some((_, path)) => format!("/{path}"),
                None => "/".to_owned(),
            };
            let query: Vec<(String, String)> = raw_query
                .split('&')
                .filter(|pair| !pair.is_empty())
                .map(|pair| {
                    let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                    (query_decode(k), query_decode(v))
                })
                .collect();
            // Sign exactly the headers botocore signed (read from its own
            // SignedHeaders list).
            let expected_auth = vector["authorization"].as_str().unwrap();
            let signed = expected_auth
                .split("SignedHeaders=")
                .nth(1)
                .and_then(|s| s.split(',').next())
                .unwrap()
                .to_owned();
            let headers: Vec<(String, String)> = signed
                .split(';')
                .map(|h| {
                    let value = vector["headers"][h]
                        .as_str()
                        .unwrap_or_else(|| panic!("{name}: no captured value for header {h}"));
                    (h.to_owned(), value.to_owned())
                })
                .collect();

            // `Credential=AK/scope-date/region/service/aws4_request` — read
            // the scope from botocore's own header (some vectors are not s3).
            let credential = expected_auth
                .split("Credential=")
                .nth(1)
                .and_then(|s| s.split(',').next())
                .unwrap()
                .to_owned();
            let scope: Vec<&str> = credential.split('/').collect();
            let params = SignParams {
                method: vector["method"].as_str().unwrap(),
                host: vector["headers"]["host"].as_str().unwrap(),
                path: &path,
                query: &query,
                headers,
                payload_sha256_hex: vector["payload_sha256"].as_str().unwrap(),
                access_key: scope[0],
                secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                region: scope[2],
                service: scope[3],
                amz_date: vector["headers"]["x-amz-date"].as_str().unwrap(),
            };

            assert_eq!(
                canonical_request(&params),
                vector["canonical_request"],
                "{name}"
            );
            assert_eq!(string_to_sign(&params), vector["string_to_sign"], "{name}");
            assert_eq!(authorization(&params), expected_auth, "{name}");
        }
    }

    /// Go-style query decoding (`+` is a space, `%XX` is a byte).
    fn query_decode(raw: &str) -> String {
        let bytes = raw.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b'%' if i + 2 < bytes.len() => {
                    let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                    match u8::from_str_radix(hex, 16) {
                        Ok(byte) => {
                            out.push(byte);
                            i += 3;
                        }
                        Err(_) => {
                            out.push(bytes[i]);
                            i += 1;
                        }
                    }
                }
                other => {
                    out.push(other);
                    i += 1;
                }
            }
        }
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn uri_encode_follows_the_aws_rules() {
        // Unreserved set stays literal (including `~`).
        assert_eq!(uri_encode("aZ0-._~", false), "aZ0-._~");
        // Space is %20, never `+`.
        assert_eq!(uri_encode("a b", false), "a%20b");
        // Everything outside the unreserved set is encoded, `/` included when
        // it is not a path separator…
        assert_eq!(uri_encode("a/b", false), "a%2Fb");
        assert_eq!(uri_encode("100%+left", false), "100%25%2Bleft");
        // …and kept for object keys.
        assert_eq!(
            uri_encode("db backups/x.sql.gz", true),
            "db%20backups/x.sql.gz"
        );
        assert_eq!(uri_encode("été", true), "%C3%A9t%C3%A9");
    }

    #[test]
    fn canonical_query_sorts_and_encodes_pairs() {
        let query = vec![
            ("prefix".to_owned(), "db/backups/".to_owned()),
            ("max-keys".to_owned(), "100".to_owned()),
            ("list-type".to_owned(), "2".to_owned()),
        ];
        let params = SignParams {
            method: "GET",
            host: "b",
            path: "/",
            query: &query,
            headers: vec![("host".to_owned(), "b".to_owned())],
            payload_sha256_hex: "",
            access_key: "",
            secret_key: "",
            region: "",
            service: "",
            amz_date: "",
        };
        assert_eq!(
            canonical_query_string(&params),
            "list-type=2&max-keys=100&prefix=db%2Fbackups%2F"
        );
    }

    #[test]
    fn canonical_headers_trim_collapse_and_sort() {
        let params = SignParams {
            method: "GET",
            host: "b",
            path: "/",
            query: &[],
            headers: vec![
                ("X-Amz-Date".to_owned(), "  20150830T123600Z ".to_owned()),
                ("Host".to_owned(), "b".to_owned()),
                ("content-type".to_owned(), "a   b".to_owned()),
            ],
            payload_sha256_hex: "",
            access_key: "",
            secret_key: "",
            region: "",
            service: "",
            amz_date: "",
        };
        assert_eq!(
            canonical_headers(&params),
            "content-type:a b\nhost:b\nx-amz-date:20150830T123600Z\n"
        );
        assert_eq!(signed_headers(&params), "content-type;host;x-amz-date");
    }
}

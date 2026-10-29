//! The agent's rules from vandam-cloud, into memory only (never written to disk).
//!
//! `GET <cloud>/v1/rules?agent=<version>&have=<rules>` answers zstd(JSON `{v, rules, min_agent,
//! files}`) with signed claims `{v, rules, min_agent, sha256, size}` in `x-vandam-rules`, signed
//! by the cloud's issuer key under `vandam-rules-v1\0` (vandam-cloud `api/src/rules.rs`). The
//! bundle is applied only when the claims verify against the issuer key this build trusts and the
//! bytes match their sha256 and size.
//!
//! A release build trusts only what it was built with: `VANDAM_CLOUD_URL` and `VANDAM_ISSUER_KEY`
//! (base64url ed25519 public key) at build time, nothing at run time. A debug build also takes
//! them from the environment when running, and without a cloud keeps the repo's `rules/` folder.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::rules::ConfigManager;

pub const RULES_DOMAIN: &[u8] = b"vandam-rules-v1\0";
pub const CLAIMS_HEADER: &str = "x-vandam-rules";
const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_UNPACKED_BYTES: usize = 64 * 1024 * 1024;
/// How long the daemon waits for its first bundle before starting with none.
pub const FIRST_WAIT: Duration = Duration::from_secs(15);
const REFRESH: Duration = Duration::from_secs(6 * 3600);

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub v: u32,
    pub rules: u64,
    pub min_agent: String,
    pub sha256: String,
    pub size: u64,
}

/// Where the rules come from and which key signs them.
#[derive(Clone)]
pub struct CloudRules {
    pub base: String,
    pub key: VerifyingKey,
}

impl CloudRules {
    /// The build's cloud, or `None` (a debug build with no cloud given, or a release build made
    /// without one: the latter has no rules at all).
    pub fn configured() -> Option<Self> {
        let pick = |build: Option<&'static str>, run: &str| -> Option<String> {
            if cfg!(debug_assertions) {
                if let Ok(v) = std::env::var(run) {
                    return Some(v);
                }
            }
            build.map(|s| s.to_string())
        };
        let base = pick(option_env!("VANDAM_CLOUD_URL"), "VANDAM_CLOUD_URL")?;
        let key = parse_key(&pick(option_env!("VANDAM_ISSUER_KEY"), "VANDAM_ISSUER_KEY")?)?;
        Some(CloudRules { base: base.trim_end_matches('/').to_string(), key })
    }
}

pub fn parse_key(b64: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = B64.decode(b64.trim()).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// The claims of a token signed under the rules domain by `key`, or why not.
pub fn verify_claims(key: &VerifyingKey, token: &str) -> Result<Claims, String> {
    let (p, s) = token.split_once('.').ok_or("claims token malformed")?;
    let payload = B64.decode(p).map_err(|_| "claims token malformed")?;
    let sig = Signature::from_slice(&B64.decode(s).map_err(|_| "claims token malformed")?).map_err(|_| "claims token malformed")?;
    let mut m = RULES_DOMAIN.to_vec();
    m.extend_from_slice(&payload);
    key.verify(&m, &sig).map_err(|_| "claims signature does not verify")?;
    serde_json::from_slice(&payload).map_err(|e| format!("claims: {}", e))
}

/// The bundle's JSON once its bytes match the verified claims.
pub fn open_bundle(claims: &Claims, bytes: &[u8]) -> Result<Vec<u8>, String> {
    if claims.v != 1 {
        return Err(format!("claims version {} not understood", claims.v));
    }
    if bytes.len() as u64 != claims.size || hex(&Sha256::digest(bytes)) != claims.sha256 {
        return Err("bundle does not match its signed claims".into());
    }
    use std::io::Read;
    let mut out = Vec::new();
    zstd::stream::read::Decoder::new(bytes)
        .map_err(|e| e.to_string())?
        .take(MAX_UNPACKED_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() > MAX_UNPACKED_BYTES {
        return Err("bundle unpacks too large".into());
    }
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub enum Fetched {
    New { rules: u64, json: Vec<u8> },
    Current,
}

/// One round: asks for the newest bundle this agent meets.
pub async fn fetch(cloud: &CloudRules, have: Option<u64>) -> Result<Fetched, String> {
    let mut url = format!("{}/v1/rules?agent={}", cloud.base, env!("CARGO_PKG_VERSION"));
    if let Some(n) = have {
        url.push_str(&format!("&have={}", n));
    }
    let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().map_err(|e| e.to_string())?;
    let resp = client.get(&url).send().await.map_err(|e| format!("{}: {}", url, e))?;
    match resp.status().as_u16() {
        304 => return Ok(Fetched::Current),
        200 => {}
        s => return Err(format!("{}: HTTP {}", url, s)),
    }
    let token = resp
        .headers()
        .get(CLAIMS_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or("rules answer has no signed claims")?
        .to_string();
    let claims = verify_claims(&cloud.key, &token)?;
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err("rules bundle too large".into());
    }
    let json = open_bundle(&claims, &bytes)?;
    Ok(Fetched::New { rules: claims.rules, json })
}

/// At start: the first bundle, waited for up to `FIRST_WAIT`. Applied to the global rules source,
/// so the `ConfigManager` built after this reads it. Returns the rules number applied.
pub async fn first(cloud: &CloudRules) -> Option<u64> {
    match tokio::time::timeout(FIRST_WAIT, fetch(cloud, None)).await {
        Ok(Ok(Fetched::New { rules, json })) => match crate::rules::source::parse_bundle(&json) {
            Ok(src) => {
                crate::rules::source::set(src);
                tracing::info!("[Vandam Rules] rules {} from {}", rules, cloud.base);
                Some(rules)
            }
            Err(e) => {
                tracing::error!("[Vandam Rules] bundle refused: {}", e);
                None
            }
        },
        Ok(Ok(Fetched::Current)) => None,
        Ok(Err(e)) => {
            tracing::error!("[Vandam Rules] {}", e);
            None
        }
        Err(_) => {
            tracing::error!("[Vandam Rules] no answer from {} within {:?}; starting with no rules", cloud.base, FIRST_WAIT);
            None
        }
    }
}

/// Keeps the rules current: retries 5 s doubling to 5 min until a bundle arrives, then refreshes
/// every 6 h; each new bundle replaces the whole state at once.
pub async fn keep_current(cloud: CloudRules, config: Arc<ConfigManager>, mut have: Option<u64>) {
    let mut backoff = Duration::from_secs(5);
    loop {
        let wait = if have.is_some() { REFRESH } else { backoff };
        tokio::time::sleep(wait).await;
        match fetch(&cloud, have).await {
            Ok(Fetched::New { rules, json }) => match config.reload_from_bytes(&json) {
                Ok(()) => {
                    tracing::info!("[Vandam Rules] rules {} applied", rules);
                    have = Some(rules);
                    backoff = Duration::from_secs(5);
                }
                Err(e) => tracing::error!("[Vandam Rules] bundle refused: {}", e),
            },
            Ok(Fetched::Current) => backoff = Duration::from_secs(5),
            Err(e) => {
                tracing::warn!("[Vandam Rules] {}", e);
                backoff = (backoff * 2).min(Duration::from_secs(300));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn token(key: &SigningKey, claims: &serde_json::Value) -> String {
        let payload = serde_json::to_vec(claims).unwrap();
        let mut m = RULES_DOMAIN.to_vec();
        m.extend_from_slice(&payload);
        format!("{}.{}", B64.encode(&payload), B64.encode(key.sign(&m).to_bytes()))
    }

    #[test]
    fn a_bundle_opens_only_with_claims_signed_by_the_trusted_key_and_matching_bytes() {
        let issuer = SigningKey::from_bytes(&[5; 32]);
        let json = br#"{"v":1,"rules":4,"min_agent":"0.1.0","files":{"a.json":{"x":1}}}"#;
        let bytes = zstd::encode_all(&json[..], 3).unwrap();
        let claims = serde_json::json!({"v": 1, "rules": 4, "min_agent": "0.1.0", "sha256": hex(&Sha256::digest(&bytes)), "size": bytes.len()});
        let t = token(&issuer, &claims);

        let c = verify_claims(&issuer.verifying_key(), &t).unwrap();
        assert_eq!(open_bundle(&c, &bytes).unwrap(), json.to_vec());
        let src = crate::rules::source::parse_bundle(&open_bundle(&c, &bytes).unwrap()).unwrap();
        assert_eq!(src.json("a.json").unwrap()["x"], 1);

        // Another key's claims, or bytes that are not the ones signed for: refused.
        assert!(verify_claims(&SigningKey::from_bytes(&[6; 32]).verifying_key(), &t).is_err());
        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(open_bundle(&c, &tampered).is_err());
    }
}

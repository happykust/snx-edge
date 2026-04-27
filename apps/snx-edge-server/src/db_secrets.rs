//! Profile-secret encryption layer.
//!
//! VPN profile config blobs in `profiles.config` historically stored the user
//! password and certificate password as plaintext JSON strings — anyone with
//! read access to the SQLite file (a Mikrotik admin, a backup, a stolen disk)
//! could harvest them. This module wraps those two fields with
//! ChaCha20-Poly1305 AEAD when an encryption key is configured.
//!
//! Wire format inside the JSON object: a value previously stored as
//! `"password": "hunter2"` becomes
//! `"password": {"__enc": "<base64-ciphertext>", "__nonce": "<base64-nonce>"}`.
//! A top-level `"__enc_v": 1` marker on the JSON object lets the read path
//! distinguish encrypted from plaintext blobs without a separate column —
//! this is important for backwards compatibility: an existing install with no
//! key can keep reading legacy plaintext data, and an install that adopts the
//! key only encrypts new/updated profiles.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde_json::Value;

use crate::error::AppError;

/// JSON keys that get encrypted in profile configs.
const SECRET_FIELDS: &[&str] = &["password", "cert_password"];

/// Marker on the JSON object indicating its secret fields have been encrypted
/// with this module. Bumped if/when the wire format changes.
const ENC_MARKER: &str = "__enc_v";
const ENC_VERSION: u64 = 1;

/// Encrypt every recognised secret field in `value` (a JSON object) in place.
/// No-op for non-string fields or empty strings. Idempotent: a value already
/// encrypted (the JSON `{"__enc": ..., "__nonce": ...}` shape) is left alone.
///
/// Sets the top-level `__enc_v` marker so `decrypt_profile_secrets` knows to
/// run.
pub fn encrypt_profile_secrets(value: &mut Value, key: &[u8; 32]) -> Result<(), AppError> {
    let Some(obj) = value.as_object_mut() else {
        return Ok(());
    };

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut wrote_any = false;

    for field in SECRET_FIELDS {
        let Some(existing) = obj.get(*field) else {
            continue;
        };

        // Skip already-encrypted shape so re-saves are idempotent.
        if existing.is_object() && existing.get("__enc").is_some() {
            wrote_any = true;
            continue;
        }

        let Some(plain) = existing.as_str() else {
            continue;
        };
        if plain.is_empty() {
            continue;
        }

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ct = cipher
            .encrypt(&nonce, plain.as_bytes())
            .map_err(|e| AppError::Internal(format!("profile encrypt failed: {e}")))?;

        obj.insert(
            (*field).to_string(),
            serde_json::json!({
                "__enc": B64.encode(&ct),
                "__nonce": B64.encode(nonce.as_slice()),
            }),
        );
        wrote_any = true;
    }

    if wrote_any {
        obj.insert(
            ENC_MARKER.to_string(),
            Value::Number(serde_json::Number::from(ENC_VERSION)),
        );
    }

    Ok(())
}

/// Reverse of `encrypt_profile_secrets`. No-op if `__enc_v` is absent (legacy
/// plaintext blob) so existing installs without an encryption key keep
/// working. Strips `__enc_v` after a successful decrypt so downstream
/// consumers see clean JSON.
pub fn decrypt_profile_secrets(value: &mut Value, key: &[u8; 32]) -> Result<(), AppError> {
    let Some(obj) = value.as_object_mut() else {
        return Ok(());
    };

    if obj.get(ENC_MARKER).is_none() {
        return Ok(());
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    for field in SECRET_FIELDS {
        let Some(entry) = obj.get(*field) else {
            continue;
        };
        let Some(entry_obj) = entry.as_object() else {
            continue;
        };
        let (Some(enc), Some(nonce_str)) = (
            entry_obj.get("__enc").and_then(|v| v.as_str()),
            entry_obj.get("__nonce").and_then(|v| v.as_str()),
        ) else {
            continue;
        };

        let ct = B64
            .decode(enc)
            .map_err(|e| AppError::Internal(format!("profile decrypt: bad ciphertext b64: {e}")))?;
        let nonce_bytes = B64
            .decode(nonce_str)
            .map_err(|e| AppError::Internal(format!("profile decrypt: bad nonce b64: {e}")))?;
        if nonce_bytes.len() != 12 {
            return Err(AppError::Internal(
                "profile decrypt: nonce length not 12".to_string(),
            ));
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plain = cipher
            .decrypt(nonce, ct.as_ref())
            .map_err(|e| AppError::Internal(format!("profile decrypt failed: {e}")))?;
        let plain_str = String::from_utf8(plain).map_err(|e| {
            AppError::Internal(format!("profile decrypt: ciphertext not utf-8: {e}"))
        })?;
        obj.insert((*field).to_string(), Value::String(plain_str));
    }

    obj.remove(ENC_MARKER);
    Ok(())
}

/// Returns true if the JSON blob carries the encryption marker. Lets callers
/// decide whether they need a key without committing to a decrypt attempt.
pub fn is_encrypted(value: &Value) -> bool {
    value.as_object().and_then(|o| o.get(ENC_MARKER)).is_some()
}

/// Decode an encryption key from an env-var value. Tries the encoding most
/// likely to be 32 bytes first: a 64-character all-hex string is parsed as
/// hex, anything else is parsed as base64 (and then hex as a fallback).
/// Returns `Err` if the value is set but unparseable — we want a loud
/// failure at startup, not silent fallback to plaintext.
pub fn decode_key(raw: &str) -> Result<[u8; 32], AppError> {
    let trimmed = raw.trim();

    // Disambiguate: a 64-char string of [0-9a-fA-F] is also valid base64
    // but the operator clearly meant hex. Try that first.
    let bytes = if trimmed.len() == 64 && trimmed.bytes().all(|b| hex_nibble(b).is_ok()) {
        hex_decode(trimmed)
            .map_err(|_| AppError::Internal("profile encryption key: invalid hex".to_string()))?
    } else if let Ok(b) = B64.decode(trimmed) {
        b
    } else if let Ok(b) = hex_decode(trimmed) {
        b
    } else {
        return Err(AppError::Internal(
            "profile encryption key is neither base64 nor hex".to_string(),
        ));
    };

    if bytes.len() != 32 {
        return Err(AppError::Internal(format!(
            "profile encryption key must decode to 32 bytes (got {})",
            bytes.len()
        )));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixed_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, slot) in k.iter_mut().enumerate() {
            *slot = i as u8;
        }
        k
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = fixed_key();
        let mut v = json!({
            "server": "vpn.example.com",
            "username": "alice",
            "password": "hunter2",
            "cert_password": "p12-secret",
            "mtu": 1400,
        });

        let original = v.clone();
        encrypt_profile_secrets(&mut v, &key).expect("encrypt");
        // Encrypted shape replaces the string fields and inserts the marker.
        assert!(v.get("__enc_v").is_some());
        assert!(v["password"].is_object());
        assert!(v["cert_password"].is_object());
        // Non-secret fields untouched.
        assert_eq!(v["server"], original["server"]);
        assert_eq!(v["mtu"], original["mtu"]);

        decrypt_profile_secrets(&mut v, &key).expect("decrypt");
        assert!(v.get("__enc_v").is_none());
        assert_eq!(v, original);
    }

    #[test]
    fn decrypt_no_marker_is_noop() {
        let key = fixed_key();
        let mut v = json!({
            "server": "vpn.example.com",
            "password": "plaintext-still",
        });
        let original = v.clone();
        decrypt_profile_secrets(&mut v, &key).expect("decrypt");
        assert_eq!(v, original);
    }

    #[test]
    fn empty_password_is_not_encrypted() {
        let key = fixed_key();
        let mut v = json!({"password": ""});
        encrypt_profile_secrets(&mut v, &key).expect("encrypt");
        // Nothing to encrypt, so no marker either.
        assert!(v.get("__enc_v").is_none());
        assert_eq!(v["password"], "");
    }

    #[test]
    fn decode_key_accepts_base64_and_hex() {
        let raw_bytes: [u8; 32] = [42u8; 32];
        let b64 = B64.encode(raw_bytes);
        let hex: String = raw_bytes.iter().map(|b| format!("{b:02x}")).collect();

        assert_eq!(decode_key(&b64).unwrap(), raw_bytes);
        assert_eq!(decode_key(&hex).unwrap(), raw_bytes);
    }

    #[test]
    fn decode_key_rejects_short_input() {
        // 16 bytes hex → 16 raw bytes, not 32.
        let short_hex = "00".repeat(16);
        assert!(decode_key(&short_hex).is_err());
    }
}

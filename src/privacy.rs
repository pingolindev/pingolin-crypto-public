// Copyright (c) 2026 Pingolin LLC
//
// This file is part of Pingolin Crypto.
//
// Pingolin Crypto is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Pingolin Crypto is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Pingolin Crypto. If not, see <https://www.gnu.org/licenses/>.

//! Privacy-enhancing utilities for metadata protection
//!
//! This module provides functions to reduce metadata leakage:
//! - Timestamp bucketing with jitter
//! - Per-circle pseudonyms for user/device IDs
//! - Deterministic pseudonym derivation from circle keys

use crate::keys::SymmetricKey;
use rand::rngs::OsRng;
use rand::Rng;
use subtle::ConstantTimeEq;

/// Default bucket size for timestamp bucketing (5 minutes in milliseconds)
pub const DEFAULT_BUCKET_MS: i64 = 5 * 60 * 1000;

/// Minimum bucket size (1 minute)
pub const MIN_BUCKET_MS: i64 = 60 * 1000;

/// Maximum bucket size (1 hour)
pub const MAX_BUCKET_MS: i64 = 60 * 60 * 1000;

/// Configuration for timestamp bucketing
#[derive(Debug, Clone, Copy)]
pub struct TimestampBucketConfig {
    /// Bucket size in milliseconds
    pub bucket_ms: i64,
    /// Whether to add random jitter within the bucket
    pub add_jitter: bool,
}

impl Default for TimestampBucketConfig {
    fn default() -> Self {
        Self {
            bucket_ms: DEFAULT_BUCKET_MS,
            add_jitter: true,
        }
    }
}

impl TimestampBucketConfig {
    /// Create a new config with specified bucket size
    pub fn new(bucket_minutes: i64, add_jitter: bool) -> Self {
        let bucket_ms = (bucket_minutes * 60 * 1000).clamp(MIN_BUCKET_MS, MAX_BUCKET_MS);
        Self { bucket_ms, add_jitter }
    }

    /// Bucket for real-time updates (1 minute)
    pub fn realtime() -> Self {
        Self {
            bucket_ms: MIN_BUCKET_MS,
            add_jitter: true,
        }
    }

    /// Bucket for history queries (15 minutes)
    pub fn history() -> Self {
        Self {
            bucket_ms: 15 * 60 * 1000,
            add_jitter: true,
        }
    }

    /// No bucketing (preserves exact timestamp) - use sparingly
    pub fn none() -> Self {
        Self {
            bucket_ms: 1, // Effectively no bucketing
            add_jitter: false,
        }
    }
}

/// Bucket a timestamp (Unix ms) to reduce precision.
///
/// Rounds down to the bucket boundary; with `add_jitter`, adds a random
/// offset inside the bucket so equal inputs don't correlate exactly.
pub fn bucket_timestamp(timestamp_ms: i64, config: &TimestampBucketConfig) -> i64 {
    let base = (timestamp_ms / config.bucket_ms) * config.bucket_ms;

    if config.add_jitter {
        // OsRng, not a thread RNG: predictable jitter would undo the bucketing
        let jitter = OsRng.gen_range(0..config.bucket_ms);
        base + jitter
    } else {
        base
    }
}

/// Bucket a timestamp without jitter (deterministic)
///
/// Useful for query alignment - both client and server can compute the same bucket.
pub fn bucket_timestamp_deterministic(timestamp_ms: i64, bucket_ms: i64) -> i64 {
    (timestamp_ms / bucket_ms) * bucket_ms
}

/// Context strings for pseudonym derivation (domain separation)
/// V1: Legacy keyed_hash (kept for backward compatibility)
const PSEUDONYM_USER_CONTEXT_V1: &str = "pingolin.privacy.pseudonym.user.v1";
const PSEUDONYM_DEVICE_CONTEXT_V1: &str = "pingolin.privacy.pseudonym.device.v1";
/// V2: Proper derive_key with domain separation (recommended)
const PSEUDONYM_USER_CONTEXT_V2: &str = "pingolin.privacy.pseudonym.user.v2";
const PSEUDONYM_DEVICE_CONTEXT_V2: &str = "pingolin.privacy.pseudonym.device.v2";

/// Derive a per-circle pseudonym for a user ID (v2 - recommended)
///
/// Uses BLAKE3's derive_key function which is specifically designed for key derivation
/// with proper domain separation via the context string. This is more cryptographically
/// appropriate than keyed_hash (which is designed for MAC).
///
/// The pseudonym is deterministic (same inputs = same output) but:
/// - Cannot be reversed to get the original user_id
/// - Different circles produce different pseudonyms for the same user
/// - Server cannot correlate users across circles
///
/// Returns a 32-character hex pseudonym (the first 16 hash bytes).
pub fn derive_user_pseudonym(circle_key: &SymmetricKey, user_id: &str) -> String {
    // Stream the inputs into BLAKE3's derive_key hasher rather than concatenating
    // them into a heap Vec: a concatenated buffer would leave an un-wiped copy of
    // the raw circle key on the heap on every call, and this runs once per row on
    // the hot read path. Streaming is byte-identical to
    // derive_key(context, circle_key || user_id).
    let mut hasher = blake3::Hasher::new_derive_key(PSEUDONYM_USER_CONTEXT_V2);
    hasher.update(circle_key.as_bytes());
    hasher.update(user_id.as_bytes());
    let hash = hasher.finalize();
    // Use first 16 bytes (128-bit) as pseudonym - sufficient for collision resistance
    hex::encode(&hash.as_bytes()[..16])
}

/// Derive a per-circle pseudonym for a device ID (v2 - recommended)
///
/// Same construction and properties as [`derive_user_pseudonym`], under the
/// device domain-separation context.
pub fn derive_device_pseudonym(circle_key: &SymmetricKey, device_id: &str) -> String {
    // Stream inputs into the hasher (see derive_user_pseudonym) to avoid a heap Vec
    // holding an un-wiped copy of the raw circle key on the hot read path.
    let mut hasher = blake3::Hasher::new_derive_key(PSEUDONYM_DEVICE_CONTEXT_V2);
    hasher.update(circle_key.as_bytes());
    hasher.update(device_id.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash.as_bytes()[..16])
}

/// Derive a per-circle pseudonym for a user ID (v1 - legacy, for backward compatibility)
///
/// Uses keyed_hash which works but is semantically designed for MAC, not key derivation.
/// New code should use derive_user_pseudonym() instead.
#[allow(dead_code)]
pub fn derive_user_pseudonym_v1(circle_key: &SymmetricKey, user_id: &str) -> String {
    let input = format!("{}:{}", PSEUDONYM_USER_CONTEXT_V1, user_id);
    let hash = blake3::keyed_hash(circle_key.as_bytes(), input.as_bytes());
    hex::encode(&hash.as_bytes()[..16])
}

/// Derive a per-circle pseudonym for a device ID (v1 - legacy, for backward compatibility)
#[allow(dead_code)]
pub fn derive_device_pseudonym_v1(circle_key: &SymmetricKey, device_id: &str) -> String {
    let input = format!("{}:{}", PSEUDONYM_DEVICE_CONTEXT_V1, device_id);
    let hash = blake3::keyed_hash(circle_key.as_bytes(), input.as_bytes());
    hex::encode(&hash.as_bytes()[..16])
}

/// Derive both pseudonyms at once; returns (user_pseudonym, device_pseudonym).
pub fn derive_pseudonyms(
    circle_key: &SymmetricKey,
    user_id: &str,
    device_id: &str,
) -> (String, String) {
    (
        derive_user_pseudonym(circle_key, user_id),
        derive_device_pseudonym(circle_key, device_id),
    )
}

/// Verify that a pseudonym matches an expected user_id for a given circle
///
/// Useful for the circle owner to verify pseudonym mappings they know.
/// Supports both v1 (legacy) and v2 (current) pseudonym formats for backward compatibility.
///
/// SECURITY: Uses constant-time comparison AND constant-time OR to prevent timing attacks.
/// Both v1 and v2 comparisons are always performed to ensure consistent timing regardless
/// of which version matches. An attacker cannot determine the pseudonym version or how
/// many characters matched by measuring response time.
pub fn verify_user_pseudonym(
    circle_key: &SymmetricKey,
    user_id: &str,
    pseudonym: &str,
) -> bool {
    let expected_v2 = derive_user_pseudonym(circle_key, user_id);
    let expected_v1 = derive_user_pseudonym_v1(circle_key, user_id);

    let matches_v2 = expected_v2.as_bytes().ct_eq(pseudonym.as_bytes());
    let matches_v1 = expected_v1.as_bytes().ct_eq(pseudonym.as_bytes());

    // `|` not `||`: constant-time OR, no early return
    (matches_v2 | matches_v1).into()
}

/// Verify that a pseudonym matches an expected device_id for a given circle
///
/// Supports both v1 (legacy) and v2 (current) pseudonym formats for backward compatibility.
///
/// SECURITY: Uses constant-time comparison AND constant-time OR to prevent timing attacks.
/// Both v1 and v2 comparisons are always performed to ensure consistent timing regardless
/// of which version matches.
pub fn verify_device_pseudonym(
    circle_key: &SymmetricKey,
    device_id: &str,
    pseudonym: &str,
) -> bool {
    let expected_v2 = derive_device_pseudonym(circle_key, device_id);
    let expected_v1 = derive_device_pseudonym_v1(circle_key, device_id);

    let matches_v2 = expected_v2.as_bytes().ct_eq(pseudonym.as_bytes());
    let matches_v1 = expected_v1.as_bytes().ct_eq(pseudonym.as_bytes());

    // `|` not `||`: constant-time OR, no early return
    (matches_v2 | matches_v1).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_timestamp_deterministic() {
        let ts = 1704067200000_i64; // 2024-01-01 00:00:00 UTC
        let bucket = DEFAULT_BUCKET_MS;

        let bucketed = bucket_timestamp_deterministic(ts + 60_000, bucket);
        assert_eq!(bucketed, ts); // Should round down to bucket start

        let bucketed2 = bucket_timestamp_deterministic(ts + 4 * 60_000, bucket);
        assert_eq!(bucketed2, ts); // Still in same bucket

        let bucketed3 = bucket_timestamp_deterministic(ts + 5 * 60_000, bucket);
        assert_eq!(bucketed3, ts + 5 * 60_000); // New bucket
    }

    #[test]
    fn test_bucket_timestamp_with_jitter() {
        let ts = 1704067200000_i64;
        let config = TimestampBucketConfig::default();

        let bucketed = bucket_timestamp(ts, &config);

        // Should be within the bucket
        let base = (ts / config.bucket_ms) * config.bucket_ms;
        assert!(bucketed >= base);
        assert!(bucketed < base + config.bucket_ms);
    }

    #[test]
    fn test_user_pseudonym_deterministic() {
        let key = SymmetricKey::generate();
        let user_id = "550e8400-e29b-41d4-a716-446655440000";

        let pseudo1 = derive_user_pseudonym(&key, user_id);
        let pseudo2 = derive_user_pseudonym(&key, user_id);

        assert_eq!(pseudo1, pseudo2);
        assert_eq!(pseudo1.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn test_different_circles_different_pseudonyms() {
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();
        let user_id = "550e8400-e29b-41d4-a716-446655440000";

        let pseudo1 = derive_user_pseudonym(&key1, user_id);
        let pseudo2 = derive_user_pseudonym(&key2, user_id);

        assert_ne!(pseudo1, pseudo2);
    }

    #[test]
    fn test_user_device_pseudonyms_different() {
        let key = SymmetricKey::generate();
        let id = "550e8400-e29b-41d4-a716-446655440000";

        let user_pseudo = derive_user_pseudonym(&key, id);
        let device_pseudo = derive_device_pseudonym(&key, id);

        // Same ID but different context should produce different pseudonyms
        assert_ne!(user_pseudo, device_pseudo);
    }

    #[test]
    fn test_verify_pseudonym() {
        let key = SymmetricKey::generate();
        let user_id = "550e8400-e29b-41d4-a716-446655440000";

        let pseudonym = derive_user_pseudonym(&key, user_id);

        assert!(verify_user_pseudonym(&key, user_id, &pseudonym));
        assert!(!verify_user_pseudonym(&key, "wrong-id", &pseudonym));
    }

    #[test]
    fn test_streaming_matches_concat_derivation() {
        // Pseudonyms already stored on the server must keep
        // resolving, so the streaming derivation has to stay
        // byte-identical to the concat-based
        // `derive_key(context, circle_key || id)`.
        let key = SymmetricKey::generate();
        let user_id = "550e8400-e29b-41d4-a716-446655440000";
        let device_id = "111e8400-e29b-41d4-a716-446655440999";

        let user_material = [key.as_bytes(), user_id.as_bytes()].concat();
        let expected_user =
            hex::encode(&blake3::derive_key(PSEUDONYM_USER_CONTEXT_V2, &user_material)[..16]);
        assert_eq!(derive_user_pseudonym(&key, user_id), expected_user);

        let device_material = [key.as_bytes(), device_id.as_bytes()].concat();
        let expected_device =
            hex::encode(&blake3::derive_key(PSEUDONYM_DEVICE_CONTEXT_V2, &device_material)[..16]);
        assert_eq!(derive_device_pseudonym(&key, device_id), expected_device);
    }
}

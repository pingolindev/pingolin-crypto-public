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

//! Pingolin Crypto - Zero-knowledge encryption primitives
//!
//! This crate provides all cryptographic operations for the Pingolin ecosystem:
//! - Password-based key derivation (Argon2id)
//! - Symmetric encryption (XChaCha20-Poly1305)
//! - Asymmetric key exchange (X25519)
//! - Digital signatures (Ed25519)

pub mod error;
pub mod kdf;
pub mod keys;
pub mod symmetric;
pub mod asymmetric;
pub mod sharing;
pub mod vault;
pub mod privacy;

#[cfg(feature = "ffi")]
pub mod ffi;

pub use error::CryptoError;
pub use kdf::{derive_user_key, derive_subkey, KdfParams};
pub use keys::{
    SymmetricKey, UserKey, VaultKey, ItemKey,
    Salt, Nonce, EncryptedBlob,
    X25519PublicKey, X25519SecretKey,
    Ed25519PublicKey, Ed25519SecretKey, Signature,
};
pub use symmetric::{encrypt, decrypt, encrypt_with_aad, decrypt_with_aad};
pub use asymmetric::{
    generate_x25519_keypair, generate_ed25519_keypair,
    sign, verify,
};
pub use sharing::{encrypt_for_recipient, decrypt_from_sender};
pub use privacy::{
    bucket_timestamp, bucket_timestamp_deterministic,
    derive_user_pseudonym, derive_device_pseudonym, derive_pseudonyms,
    verify_user_pseudonym, verify_device_pseudonym,
    TimestampBucketConfig, DEFAULT_BUCKET_MS,
};

/// Re-exported so consumers can wipe their own buffers without taking a
/// direct `zeroize` dependency.
pub use zeroize::Zeroize;

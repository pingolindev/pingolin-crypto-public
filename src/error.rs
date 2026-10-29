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

//! Error types for cryptographic operations

use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    Kdf(String),

    /// Encryption failed
    #[error("Encryption failed")]
    Encryption,

    /// Decryption failed - invalid key or corrupted data
    #[error("Decryption failed - invalid key or corrupted data")]
    Decryption,

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Invalid nonce length
    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },

    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerification,

    /// Invalid public key
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid secret key
    #[error("Invalid secret key")]
    InvalidSecretKey,

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Base64 decoding error
    #[error("Base64 decode error: {0}")]
    Base64Decode(String),
}

impl From<base64::DecodeError> for CryptoError {
    fn from(err: base64::DecodeError) -> Self {
        CryptoError::Base64Decode(err.to_string())
    }
}

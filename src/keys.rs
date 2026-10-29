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

//! Key types with automatic zeroization

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// 32-byte symmetric key - zeroized on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    /// Generate a new random symmetric key
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        Self(key)
    }

    /// Create from existing bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw key bytes. Avoid copying these into buffers that won't be
    /// zeroized — the wrapper exists so the long-lived copy wipes on drop.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Try to create from slice
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

impl Clone for SymmetricKey {
    fn clone(&self) -> Self {
        // SECURITY: Copy bytes into a new array to ensure the clone is independent.
        // Both the original and clone will be zeroized on drop via ZeroizeOnDrop.
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.0);
        Self(bytes)
    }
}

/// User's master key derived from password
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UserKey(pub(crate) SymmetricKey);

impl UserKey {
    /// Create from symmetric key
    pub fn from_symmetric(key: SymmetricKey) -> Self {
        Self(key)
    }

    /// Get underlying key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// Per-vault encryption key
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey(pub(crate) SymmetricKey);

impl VaultKey {
    /// Generate a new vault key
    pub fn generate() -> Self {
        Self(SymmetricKey::generate())
    }

    /// Create from symmetric key
    pub fn from_symmetric(key: SymmetricKey) -> Self {
        Self(key)
    }

    /// Get underlying key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Get the inner symmetric key
    pub fn inner(&self) -> &SymmetricKey {
        &self.0
    }
}

/// Per-item encryption key
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ItemKey(pub(crate) SymmetricKey);

impl ItemKey {
    /// Generate a new item key
    pub fn generate() -> Self {
        Self(SymmetricKey::generate())
    }

    /// Create from symmetric key
    pub fn from_symmetric(key: SymmetricKey) -> Self {
        Self(key)
    }

    /// Get underlying key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// Salt for key derivation (not secret, stored alongside encrypted data)
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Salt(pub [u8; 32]);

impl Salt {
    /// Generate a new random salt
    pub fn generate() -> Self {
        let mut salt = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        Self(salt)
    }

    /// Create from existing bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Try to create from slice
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Encode to base64
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::try_from_slice(&bytes)
    }
}

/// Nonce for XChaCha20-Poly1305 (24 bytes)
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Nonce(pub [u8; 24]);

impl Nonce {
    /// Generate a new random nonce
    pub fn generate() -> Self {
        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        Self(nonce)
    }

    /// Create from existing bytes
    pub fn from_bytes(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    /// Try to create from slice
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 24 {
            return Err(CryptoError::InvalidNonceLength {
                expected: 24,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; 24];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Encode to base64
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::try_from_slice(&bytes)
    }
}

/// Encrypted blob with metadata needed for decryption
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EncryptedBlob {
    /// Nonce used for encryption
    pub nonce: Nonce,
    /// The encrypted data
    pub ciphertext: Vec<u8>,
    /// Which key version encrypted this
    pub key_id: String,
}

impl EncryptedBlob {
    /// Create a new encrypted blob
    pub fn new(nonce: Nonce, ciphertext: Vec<u8>, key_id: impl Into<String>) -> Self {
        Self {
            nonce,
            ciphertext,
            key_id: key_id.into(),
        }
    }

    /// Encode nonce to base64
    pub fn nonce_base64(&self) -> String {
        self.nonce.to_base64()
    }

    /// Encode ciphertext to base64
    pub fn ciphertext_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.ciphertext)
    }
}

/// X25519 public key for key exchange
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(pub [u8; 32]);

impl X25519PublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Try to create from slice
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Encode to base64
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::try_from_slice(&bytes)
    }
}

/// X25519 secret key (zeroized on drop)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SecretKey(pub(crate) [u8; 32]);

impl X25519SecretKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Ed25519 public key for signatures
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey(pub [u8; 32]);

impl Ed25519PublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Try to create from slice
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Encode to base64
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::try_from_slice(&bytes)
    }
}

/// Ed25519 secret key (zeroized on drop)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519SecretKey(pub(crate) [u8; 32]);

impl Ed25519SecretKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Ed25519 signature
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Try to create from slice
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 64 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 64,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Encode to base64
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::try_from_slice(&bytes)
    }
}

// serde has no built-in impls for [u8; 64], so Signature round-trips as base64
impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_base64(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_key_generation() {
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_salt_base64_roundtrip() {
        let salt = Salt::generate();
        let encoded = salt.to_base64();
        let decoded = Salt::from_base64(&encoded).unwrap();
        assert_eq!(salt, decoded);
    }

    #[test]
    fn test_nonce_base64_roundtrip() {
        let nonce = Nonce::generate();
        let encoded = nonce.to_base64();
        let decoded = Nonce::from_base64(&encoded).unwrap();
        assert_eq!(nonce, decoded);
    }
}

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

//! Vault key management utilities

use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::kdf::derive_subkey;
use crate::keys::{EncryptedBlob, SymmetricKey, UserKey, VaultKey};
use crate::symmetric;

/// Vault containing encrypted keys
pub struct Vault {
    pub key: VaultKey,
    pub key_id: String,
}

impl Vault {
    pub fn new(key_id: impl Into<String>) -> Self {
        Self {
            key: VaultKey::generate(),
            key_id: key_id.into(),
        }
    }

    pub fn from_key(key: VaultKey, key_id: impl Into<String>) -> Self {
        Self {
            key,
            key_id: key_id.into(),
        }
    }

    pub fn encrypt_for_storage(&self, user_key: &UserKey) -> Result<EncryptedBlob, CryptoError> {
        let encryption_key = derive_subkey(user_key, "vault-encryption");
        symmetric::encrypt(&encryption_key, self.key.as_bytes(), &self.key_id)
    }

    pub fn decrypt_from_storage(
        user_key: &UserKey,
        encrypted: &EncryptedBlob,
    ) -> Result<Self, CryptoError> {
        let encryption_key = derive_subkey(user_key, "vault-encryption");
        let decrypted = symmetric::decrypt(&encryption_key, encrypted)?;
        let key = SymmetricKey::try_from_slice(&decrypted)?;

        Ok(Self {
            key: VaultKey::from_symmetric(key),
            key_id: encrypted.key_id.clone(),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedBlob, CryptoError> {
        symmetric::encrypt(self.key.inner(), plaintext, &self.key_id)
    }

    /// Decrypt data from the vault.
    ///
    /// Returns the plaintext wrapped in `Zeroizing` to ensure it's securely
    /// cleared from memory when dropped.
    pub fn decrypt(&self, encrypted: &EncryptedBlob) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        symmetric::decrypt(self.key.inner(), encrypted)
    }
}

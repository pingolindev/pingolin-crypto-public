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

//! Symmetric encryption using XChaCha20-Poly1305

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::{EncryptedBlob, Nonce, SymmetricKey};

/// Maximum plaintext size (100 MB). An AEAD call buffers roughly the whole
/// input, so an unbounded plaintext is a memory-DoS vector.
const MAX_PLAINTEXT_SIZE: usize = 100 * 1024 * 1024;

/// Encrypt plaintext with XChaCha20-Poly1305
pub fn encrypt(
    key: &SymmetricKey,
    plaintext: &[u8],
    key_id: &str,
) -> Result<EncryptedBlob, CryptoError> {
    if plaintext.len() > MAX_PLAINTEXT_SIZE {
        return Err(CryptoError::Encryption);
    }

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = Nonce::generate();

    let ciphertext = cipher
        .encrypt((&nonce.0).into(), plaintext)
        .map_err(|_| CryptoError::Encryption)?;

    Ok(EncryptedBlob::new(nonce, ciphertext, key_id))
}

/// Encrypt with associated data (AAD)
///
/// Note: AAD is authenticated but NOT encrypted - do not put sensitive data in AAD.
pub fn encrypt_with_aad(
    key: &SymmetricKey,
    plaintext: &[u8],
    aad: &[u8],
    key_id: &str,
) -> Result<EncryptedBlob, CryptoError> {
    if plaintext.len() > MAX_PLAINTEXT_SIZE {
        return Err(CryptoError::Encryption);
    }

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = Nonce::generate();

    let payload = Payload { msg: plaintext, aad };
    let ciphertext = cipher
        .encrypt((&nonce.0).into(), payload)
        .map_err(|_| CryptoError::Encryption)?;

    Ok(EncryptedBlob::new(nonce, ciphertext, key_id))
}

/// Decrypt ciphertext
///
/// Returns the plaintext wrapped in `Zeroizing` to ensure it's securely
/// cleared from memory when dropped.
pub fn decrypt(key: &SymmetricKey, blob: &EncryptedBlob) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    cipher
        .decrypt((&blob.nonce.0).into(), blob.ciphertext.as_ref())
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decryption)
}

/// Decrypt with associated data
///
/// Returns the plaintext wrapped in `Zeroizing` to ensure it's securely
/// cleared from memory when dropped.
pub fn decrypt_with_aad(
    key: &SymmetricKey,
    blob: &EncryptedBlob,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let payload = Payload {
        msg: &blob.ciphertext,
        aad,
    };

    cipher
        .decrypt((&blob.nonce.0).into(), payload)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = SymmetricKey::generate();
        let plaintext = b"Hello, world!";

        let encrypted = encrypt(&key, plaintext, "v1").unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        // Zeroizing<Vec<u8>> derefs to &[u8]
        assert_eq!(plaintext.as_slice(), &*decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();
        let plaintext = b"Secret";

        let encrypted = encrypt(&key1, plaintext, "v1").unwrap();
        let result = decrypt(&key2, &encrypted);

        assert!(result.is_err());
    }
}

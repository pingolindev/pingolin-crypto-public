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

//! Key sharing utilities using X25519 with BLAKE3 key derivation.
//!
//! This module provides secure key sharing using the following scheme:
//!
//! 1. **Ephemeral key generation**: A new X25519 keypair is generated for each
//!    encryption operation (ephemeral-static ECDH).
//!
//! 2. **Diffie-Hellman**: X25519 DH is performed between the ephemeral secret
//!    and the recipient's static public key.
//!
//! 3. **Key Derivation**: The raw DH output is processed through BLAKE3's
//!    `derive_key` function with domain separation to produce a uniformly
//!    random encryption key.
//!
//! 4. **Encryption**: XChaCha20-Poly1305 AEAD encrypts the shared key.
//!
//! # Security Properties
//!
//! - **Forward secrecy**: Each encryption uses a fresh ephemeral key, so
//!   compromise of the recipient's long-term key doesn't expose past messages.
//!
//! - **Domain separation**: The KDF context `pingolin-x25519-kdf-v1` ensures
//!   keys derived here cannot be confused with keys from other protocols.
//!
//! - **Uniform key distribution**: BLAKE3 key derivation ensures the resulting
//!   key is indistinguishable from random, even if the DH output has biased bits.
//!
//! For why raw DH output must never be used as a key directly, see the
//! [`crate::asymmetric`] module docs.

use zeroize::Zeroize;

use crate::asymmetric::{generate_x25519_keypair, x25519_diffie_hellman};
use crate::error::CryptoError;
use crate::keys::{EncryptedBlob, SymmetricKey, X25519PublicKey, X25519SecretKey};
use crate::symmetric;

/// Domain separation context for ECDH key derivation.
///
/// This string uniquely identifies the Pingolin key sharing protocol and
/// prevents the derived keys from being valid in other contexts.
const ECDH_KDF_CONTEXT: &str = "pingolin-x25519-kdf-v1";

/// Convert a raw X25519 shared secret into a uniformly-distributed symmetric
/// key via BLAKE3 `derive_key`, bound to this protocol by `ECDH_KDF_CONTEXT`.
fn derive_shared_key(dh_output: [u8; 32]) -> SymmetricKey {
    let derived = blake3::derive_key(ECDH_KDF_CONTEXT, &dh_output);
    SymmetricKey::from_bytes(derived)
}

/// Encrypt a key for sharing with another user
pub fn encrypt_for_recipient(
    key_to_share: &SymmetricKey,
    recipient_public: &X25519PublicKey,
    key_id: &str,
) -> Result<(X25519PublicKey, EncryptedBlob), CryptoError> {
    let (ephemeral_secret, ephemeral_public) = generate_x25519_keypair();
    let mut dh_output = x25519_diffie_hellman(&ephemeral_secret, recipient_public);
    let shared_key = derive_shared_key(dh_output);
    dh_output.zeroize();
    // ephemeral_secret needs no explicit wipe: ZeroizeOnDrop covers it at scope end
    let encrypted = symmetric::encrypt(&shared_key, key_to_share.as_bytes(), key_id)?;

    Ok((ephemeral_public, encrypted))
}

/// Decrypt a key that was shared by another user
pub fn decrypt_from_sender(
    encrypted: &EncryptedBlob,
    sender_ephemeral_public: &X25519PublicKey,
    recipient_secret: &X25519SecretKey,
) -> Result<SymmetricKey, CryptoError> {
    let mut dh_output = x25519_diffie_hellman(recipient_secret, sender_ephemeral_public);
    let shared_key = derive_shared_key(dh_output);
    dh_output.zeroize();
    let decrypted = symmetric::decrypt(&shared_key, encrypted)?;

    SymmetricKey::try_from_slice(&decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_sharing_roundtrip() {
        let (recipient_secret, recipient_public) = generate_x25519_keypair();
        let shared_key = SymmetricKey::generate();

        let (ephemeral_public, encrypted) =
            encrypt_for_recipient(&shared_key, &recipient_public, "v1").unwrap();

        let decrypted = decrypt_from_sender(&encrypted, &ephemeral_public, &recipient_secret).unwrap();

        assert_eq!(shared_key.as_bytes(), decrypted.as_bytes());
    }
}

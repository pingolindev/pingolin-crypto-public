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

//! Asymmetric cryptography: X25519 key exchange and Ed25519 signatures
//!
//! # Security Notes
//!
//! ## X25519 Key Exchange
//!
//! This module provides raw X25519 Diffie-Hellman operations. The output of
//! `x25519_diffie_hellman` is a raw shared secret that should **NOT** be used
//! directly as an encryption key. Raw DH outputs have several properties that
//! make them unsuitable for direct use:
//!
//! 1. **Non-uniform distribution**: The output is a point on the curve, not a
//!    uniformly random byte string. Some bits may be biased.
//!
//! 2. **Insufficient key separation**: The same DH output used for multiple
//!    purposes (encryption, MAC, etc.) can lead to cryptographic weaknesses.
//!
//! 3. **Missing domain separation**: Without context binding, the same shared
//!    secret might be valid in multiple protocols, enabling cross-protocol attacks.
//!
//! **Always derive keys using a proper KDF** before use. See `crate::sharing` for
//! the recommended pattern using BLAKE3 key derivation with domain separation.
//!
//! ## Ed25519 Signatures
//!
//! Ed25519 is used for authentication and message integrity. Sign keys should
//! be kept secret and never transmitted. Public keys can be freely shared.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::error::CryptoError;
use crate::keys::{Ed25519PublicKey, Ed25519SecretKey, Signature, X25519PublicKey, X25519SecretKey};

/// Generate an X25519 key pair for Diffie-Hellman key exchange.
///
/// Returns a (secret_key, public_key) tuple. The secret key must be kept
/// confidential. The public key can be shared freely.
pub fn generate_x25519_keypair() -> (X25519SecretKey, X25519PublicKey) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = X25519Public::from(&secret);

    (
        X25519SecretKey::from_bytes(secret.to_bytes()),
        X25519PublicKey::from_bytes(public.to_bytes()),
    )
}

/// Perform raw X25519 Diffie-Hellman key exchange.
///
/// # Security Warning
///
/// **DO NOT use this output directly as an encryption key!**
///
/// The raw DH shared secret must be processed through a Key Derivation Function
/// (KDF) before use. Use `crate::sharing::encrypt_for_recipient` for the
/// high-level API that handles KDF properly.
///
/// This function is exposed for cases where custom KDF processing is needed,
/// but callers must ensure proper key derivation is performed.
///
/// Returns the 32-byte raw shared secret. Pass it through a KDF (e.g. BLAKE3
/// `derive_key`) with domain separation before using it as a symmetric key.
pub fn x25519_diffie_hellman(
    our_secret: &X25519SecretKey,
    their_public: &X25519PublicKey,
) -> [u8; 32] {
    let secret = StaticSecret::from(our_secret.0);
    let public = X25519Public::from(their_public.0);
    let shared = secret.diffie_hellman(&public);
    *shared.as_bytes()
}

/// Generate an Ed25519 key pair for signing
pub fn generate_ed25519_keypair() -> (Ed25519SecretKey, Ed25519PublicKey) {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();

    (
        Ed25519SecretKey::from_bytes(signing_key.to_bytes()),
        Ed25519PublicKey::from_bytes(verifying_key.to_bytes()),
    )
}

/// Sign a message with Ed25519
pub fn sign(secret_key: &Ed25519SecretKey, message: &[u8]) -> Signature {
    let signing_key = SigningKey::from_bytes(&secret_key.0);
    let signature = signing_key.sign(message);
    Signature::from_bytes(signature.to_bytes())
}

/// Verify an Ed25519 signature
pub fn verify(
    public_key: &Ed25519PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    let verifying_key =
        VerifyingKey::from_bytes(&public_key.0).map_err(|_| CryptoError::InvalidPublicKey)?;

    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);

    verifying_key
        .verify(message, &sig)
        .map_err(|_| CryptoError::SignatureVerification)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_key_exchange() {
        let (alice_secret, alice_public) = generate_x25519_keypair();
        let (bob_secret, bob_public) = generate_x25519_keypair();

        let alice_shared = x25519_diffie_hellman(&alice_secret, &bob_public);
        let bob_shared = x25519_diffie_hellman(&bob_secret, &alice_public);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let (secret, public) = generate_ed25519_keypair();
        let message = b"Hello, world!";

        let signature = sign(&secret, message);
        let result = verify(&public, message, &signature);

        assert!(result.is_ok());
    }
}

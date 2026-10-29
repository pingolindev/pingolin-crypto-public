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

//! Key derivation using Argon2id

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::keys::{Salt, SymmetricKey, UserKey};

/// Argon2id parameters - tuned for security/performance balance
#[derive(Clone, Debug)]
pub struct KdfParams {
    /// Memory cost in KiB
    pub memory_kib: u32,
    /// Time cost (iterations)
    pub iterations: u32,
    /// Parallelism (lanes)
    pub parallelism: u32,
}

impl KdfParams {
    /// Minimum memory cost (8 MiB) - below this is too weak
    pub const MIN_MEMORY_KIB: u32 = 8192;
    /// Maximum memory cost (1 GiB) - prevents DoS via excessive memory
    pub const MAX_MEMORY_KIB: u32 = 1_048_576;
    /// Minimum iterations - must be at least 4 per OWASP 2024 mobile baseline
    pub const MIN_ITERATIONS: u32 = 4;
    /// Maximum iterations - prevents DoS via excessive CPU
    pub const MAX_ITERATIONS: u32 = 64;
    /// Minimum parallelism
    pub const MIN_PARALLELISM: u32 = 1;
    /// Maximum parallelism - prevents excessive thread spawning
    pub const MAX_PARALLELISM: u32 = 8;

    /// Validate KDF parameters are within acceptable bounds.
    /// Returns an error if any parameter is outside the allowed range.
    ///
    /// This prevents DoS attacks where a malicious client requests
    /// excessive memory or CPU-intensive KDF operations.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.memory_kib < Self::MIN_MEMORY_KIB || self.memory_kib > Self::MAX_MEMORY_KIB {
            return Err(CryptoError::Kdf(format!(
                "Memory cost must be between {} and {} KiB, got {}",
                Self::MIN_MEMORY_KIB, Self::MAX_MEMORY_KIB, self.memory_kib
            )));
        }
        if self.iterations < Self::MIN_ITERATIONS || self.iterations > Self::MAX_ITERATIONS {
            return Err(CryptoError::Kdf(format!(
                "Iterations must be between {} and {}, got {}",
                Self::MIN_ITERATIONS, Self::MAX_ITERATIONS, self.iterations
            )));
        }
        if self.parallelism < Self::MIN_PARALLELISM || self.parallelism > Self::MAX_PARALLELISM {
            return Err(CryptoError::Kdf(format!(
                "Parallelism must be between {} and {}, got {}",
                Self::MIN_PARALLELISM, Self::MAX_PARALLELISM, self.parallelism
            )));
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 65536, // 64 MiB
            iterations: 8,     // 2x the enforced OWASP-2024 minimum (MIN_ITERATIONS)
            parallelism: 4,
        }
    }
}

impl KdfParams {
    /// Standard parameters for desktop/server
    pub fn standard() -> Self {
        Self::default()
    }

    /// Parameters for mobile devices - balanced for security on constrained hardware.
    /// Uses 64 MiB memory (OWASP minimum recommendation) with 8 iterations.
    pub fn mobile() -> Self {
        Self {
            memory_kib: 65536, // 64 MiB (OWASP minimum)
            iterations: 8,     // 2x the enforced minimum: GPU/ASIC margin on constrained hardware
            parallelism: 2,
        }
    }

    /// Higher parameters for extra security (slower)
    /// Uses 256 MiB memory with 16 iterations for maximum security
    pub fn high_security() -> Self {
        Self {
            memory_kib: 262144, // 256 MiB
            iterations: 16,
            parallelism: 4,
        }
    }
}

/// Derive user's master key from password
pub fn derive_user_key(
    password: &[u8],
    salt: &Salt,
    params: &KdfParams,
) -> Result<UserKey, CryptoError> {
    params.validate()?;

    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password, &salt.0, &mut output)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    let key = UserKey::from_symmetric(SymmetricKey::from_bytes(output));
    output.zeroize();

    Ok(key)
}

/// Derive a sub-key for a specific purpose using BLAKE3 key derivation.
///
/// Uses BLAKE3's `derive_key` function which is specifically designed for key derivation,
/// providing proper domain separation via the context string.
pub fn derive_subkey(master_key: &UserKey, context: &str) -> SymmetricKey {
    let derived = blake3::derive_key(context, master_key.as_bytes());
    SymmetricKey::from_bytes(derived)
}

// Recovery keys never pass through this crate: clients hash them with BLAKE2b
// (libsodium crypto_generichash) and the auth service verifies with the same
// construction. They are 256-bit random values, so unsalted hashing is
// sufficient for storage.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_user_key() {
        let password = b"correct horse battery staple";
        let salt = Salt::generate();
        let params = KdfParams::default();

        let key1 = derive_user_key(password, &salt, &params).unwrap();
        let key2 = derive_user_key(password, &salt, &params).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_salts_produce_different_keys() {
        let password = b"password123";
        let salt1 = Salt::generate();
        let salt2 = Salt::generate();
        let params = KdfParams::default();

        let key1 = derive_user_key(password, &salt1, &params).unwrap();
        let key2 = derive_user_key(password, &salt2, &params).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_derive_subkey() {
        let password = b"password";
        let salt = Salt::generate();
        let params = KdfParams::default();
        let master = derive_user_key(password, &salt, &params).unwrap();

        let vault_key = derive_subkey(&master, "vault");
        let auth_key = derive_subkey(&master, "auth");

        assert_ne!(vault_key.as_bytes(), auth_key.as_bytes());
    }
}

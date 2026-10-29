# pingolin-crypto

Zero-knowledge encryption primitives shared by every Pingolin surface:
XChaCha20-Poly1305 AEAD, X25519 key agreement, Ed25519 signatures, BLAKE3,
Argon2id, plus the key-wrapping, sharing, and vault constructions built on
them.

This crate is where Pingolin's end-to-end encryption is implemented. It is
consumed by the auth server and by the mobile SDK, so the same construction
runs on the server and on every client.

## What is in it

| Module | Contents |
| --- | --- |
| `kdf` | Argon2id password-based key derivation and subkey derivation (`derive_user_key`, `derive_subkey`, `KdfParams`) |
| `keys` | The key and blob types — `UserKey`, `VaultKey`, `ItemKey`, `Salt`, `Nonce`, `EncryptedBlob`, and the X25519/Ed25519 key types |
| `symmetric` | XChaCha20-Poly1305 encryption, with and without additional authenticated data (`encrypt`, `decrypt`, `encrypt_with_aad`, `decrypt_with_aad`) |
| `asymmetric` | X25519 and Ed25519 keypair generation, signing and verification |
| `sharing` | Encrypting an item for another recipient (`encrypt_for_recipient`, `decrypt_from_sender`) |
| `vault` | The vault construction layered on the key types |
| `privacy` | Timestamp bucketing and pseudonym derivation/verification for user and device identifiers |
| `error` | `CryptoError` |

Key types wipe themselves on drop; `zeroize::Zeroize` is re-exported so
consumers can wipe their own buffers without taking the dependency directly.

## Consumers and layout

The crate is consumed by **path dependency as a sibling checkout** — clone it
next to the repos that use it:

```
<parent>/
  pingolin-crypto/        <- this repo
  auth/                   auth-api:                ../../../pingolin-crypto
  mobile-sdk/             crates/mobile-sdk:       ../../../pingolin-crypto
```

Consumer builds, including their Docker images, recreate the same sibling
layout. Nothing about the parent directory's name matters.

## Build and test

The only prerequisite is a stable Rust toolchain from [rustup](https://rustup.rs).

```sh
cargo build
cargo test     # 18 tests
```

Property-based tests use `proptest`; both it and `criterion` are
dev-dependencies and are not part of a consumer's build.

## Features

The default feature set is empty, and that is what every consumer currently
uses. Two optional features are declared in `Cargo.toml`:

- **`ffi`** — intended to expose the crate over UniFFI. **It does not
  currently build**: `src/lib.rs` declares `pub mod ffi;` behind the feature,
  but there is no `src/ffi.rs`, so `cargo build --features ffi` fails with
  E0583. Mobile clients reach these primitives through the `mobile-sdk` repo's
  own UniFFI layer instead. Note that this also makes `--all-features` fail.
- **`wasm`** — declared, but no code is currently conditional on it, so
  enabling it changes nothing.

## Third-party licences

[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) lists every third-party Rust
crate compiled into this one, with full licence texts. It is generated:

```sh
cargo install cargo-about
cargo about generate --config about.toml --output-file THIRD_PARTY_LICENSES.md about.hbs
```

Regenerate it whenever dependencies change. It fails rather than silently
accepting a licence not listed in `about.toml`.

## Contributing and security

This repository is published as one snapshot per release: each commit is a
shipped version, tagged with it, and the tree at a tag is the source that
version was built from. Development happens elsewhere, so this repository
takes no pull requests or issues.

Report security problems by email to **security@mail.pingolin.com**, not in
public.

## Licence

Pingolin Crypto is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE).

The Pingolin name and logos are trademarks of Pingolin LLC and are not covered
by the licence. A modified version you distribute must not use them.

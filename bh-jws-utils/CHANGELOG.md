# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Rust's Cargo Semantic
Versioning](https://doc.rust-lang.org/cargo/reference/semver.html).

## [Unreleased]

### Added
- Added `private_key_pem` and `private_jwk` methods for `Es256Signer` to
  complete the method suite of useful `Es256Signer` serializations.
- Added `JwkPrivate` to improve JWK ecosystem.
- Derived `Clone` for `Es256Signer`

### Changed
- Changed `Es256Signer` (de)serialization representation from PEM representation
  as bytes to JWK representation.

## [0.5.1] - 2025-09-12

### Added

- Added a blanket impl of `HasJwkKid` for `SignerWithChain` that forwards to the
  inner signer.

## [0.5.0] - 2025-09-11

### Added

- Added the `Es256Signer::public_key_pem` method.

### Changed

- The `bhx5chain` dependency is bumped to version `0.3` (from `0.2`).
- `Es256Signer::from_private_key_pem` now takes PEM as more idiomatically as
  `&str` rather than `&[u8]`.

### Removed

- Removed deprecated `Es256SignerWithChain` constructors.
- Removed direct dependency on crate `iref`.

## [0.4.0] - 2025-09-03

### Added

- The `SignerWithChain` decorator for generic `Signer`s, a generalization of the
  previous `Es256SignerWithChain` which used a hardcoded `Signer` implementation.

### Changed

- The `openssl` default Cargo feature no longer exists, but the code it gated is
  retained. This was done because of two reasons:
  - an existing public function had silently depended on this default feature;
  - new code requires the `openssl` dependency for certain cryptographic checks,
    making it no longer optional and the Cargo feature not really useful.

- The `Es256SignerWithChain` `struct` is now a type alias for the newly added
  generic `SignerWithChain` specialized with `Es256Signer` as before.

### Deprecated

- The `Es256SignerWithChain` constructors `generate` and `from_private_key` are
  deprecated in favor of newly added `SignerWithChain::new`.

### Fixed

- Fixed the build of the crate when default features were disabled.

## [0.3.0] - 2025-04-22

### Added

- The `public_jwk` method on the `Signer` `trait` that exposes the public key of
  the respective implementer in the JWK format.

## [0.2.0] - 2025-04-09

### Changed

- The `bhx5chain` dependency is bumped to version `0.2` (from `0.1`).

## [0.1.0] - 2025-04-01

### Added

- This CHANGELOG file for tracking changes important to end users of the
  `bh-jws-utils` library.
- README.md describing the crate.
- Initial version of the `bh-jws-utils` crate.


[Unreleased]: <https://github.com/blockhousetech/eudi-rust-core/compare/bh-jws-utils/v0.5.1...HEAD>
[0.5.1]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-jws-utils/v0.5.1>
[0.5.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-jws-utils/v0.5.0>
[0.4.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-jws-utils/v0.4.0>
[0.3.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-jws-utils/v0.3.0>
[0.2.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-jws-utils/v0.2.0>
[0.1.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-jws-utils/v0.1.0>

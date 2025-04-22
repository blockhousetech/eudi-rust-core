# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Rust's Cargo Semantic
Versioning](https://doc.rust-lang.org/cargo/reference/semver.html).

## [Unreleased]

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


[Unreleased]: <https://github.com/blockhousetech/eudi-rust-core/compare/bh-jws-utils/v0.3.0...HEAD>
[0.3.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-jws-utils/v0.3.0>
[0.2.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-jws-utils/v0.2.0>
[0.1.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-jws-utils/v0.1.0>

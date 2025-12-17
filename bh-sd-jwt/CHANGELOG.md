# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Rust's Cargo Semantic
Versioning](https://doc.rust-lang.org/cargo/reference/semver.html).

## [Unreleased]

### Changed

- Removed the check in `X5ChainIssuerPublicKeyLookup::lookup` that the `iss`
  value is a valid HTTPS URL and that it corresponds to a URI/DNS SAN in the leaf
  certificate of the `x5c` header field. This is because this requirement was
  removed as of draft 10 of the SD-JWT VC standard.

## [0.4.0] - 2025-11-10

### Changed

- The `bh-jws-utils` dependency is bumped to version `0.6` (from `0.5`).

### Added

- Check that `iss` value uses the `HTTPS` scheme.

## [0.3.0] - 2025-09-11

### Changed

- The `bh-jws-utils` dependency is bumped to version `0.5` (from `0.3`).
- The `bh-status-list` dependency is bumped to version `0.2` (from `0.1`).
- The `bhx5chain` dependency is bumped to version `0.3` (from `0.2`).

## [0.2.1] - 2025-09-08

### Added

- `sub` and `iat` methods on the `IssuerJwt`, that return the
  corresponding claims.

## [0.2.0] - 2025-06-17

### Changed

- Updated `JsonNodePathSegment` handling to use the `$.node1.node2`
  path format instead of the previous `$['node1']['node2']` format.
  This change was made to align with third-party holders,
  who use the dot notation format.

## [0.1.0] - 2025-06-10

### Added

- This CHANGELOG file for tracking changes important to end users of the
  `bh-sd-jwt` library.
- README.md describing the crate.
- Initial version of the `bh-sd-jwt` crate.

[Unreleased]: <https://github.com/blockhousetech/eudi-rust-core/compare/bh-sd-jwt/v0.4.0...HEAD>
[0.4.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-sd-jwt/v0.4.0>
[0.3.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-sd-jwt/v0.3.0>
[0.2.1]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-sd-jwt/v0.2.1>
[0.2.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-sd-jwt/v0.2.0>
[0.1.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bh-sd-jwt/v0.1.0>

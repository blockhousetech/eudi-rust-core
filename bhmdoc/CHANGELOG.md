# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Rust's Cargo Semantic
Versioning](https://doc.rust-lang.org/cargo/reference/semver.html).

## [Unreleased]

### Changed

- Updated `bh-jws-utils` dependency from 0.5 to 0.6.

### Added

- The associated function `new` for the `ValidityInfo`.
- Implemented `From<DateTime> for chrono::DateTime<Utc>`.

### Changed

- The `DateTime` no longer allows the use of sub-second precision and
  non-UTC time zones.
- The `ValidityInfo` can no longer be created nor deserialized with
  `validFrom` set to before `signed`, and `validUntil` set to before
  `validFrom`.
- `IssuerSigned` and `DeviceResponse` no longer allow `Base64` paddings
  for deserializing from `base64url`-encoded strings.
- Untagged `tdate` values are no longer accepted, i.e., in order to
  deserialize `DateTime`, it needs to be tagged with `0`.

## [0.3.0] - 2025-09-11

### Changed

- The `bh-jws-utils` dependency is bumped to version `0.5` (from `0.3`).
- The `bhx5chain` dependency is bumped to version `0.3` (from `0.2`).

## [0.2.1] - 2025-09-08

### Added

- The `ValidityInfo` is now publicly exposed, along with all its
  properties.
- The `Device` now has a public `validity_info` method that fetches the
  `ValidityInfo` of the contained credential.

## [0.2.0] - 2025-04-24

### Added

- The `Verifier` can now optionally verify the Issuer's authenticity.
- `Claims` now implements `Debug`, `Clone`, and `PartialEq`.
- The _mdoc_ Device `Signer` must now match the `DeviceKey` signed by
the Issuer.

## [0.1.0] - 2025-04-22

### Added

- This CHANGELOG file for tracking changes important to end users of the
  `bhmdoc` library.
- README.md describing the crate.
- Initial version of the `bhmdoc` crate.

[Unreleased]: <https://github.com/blockhousetech/eudi-rust-core/compare/bhmdoc/v0.3.0...HEAD>
[0.3.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bhmdoc/v0.3.0>
[0.2.1]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bhmdoc/v0.2.1>
[0.2.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bhmdoc/v0.2.0>
[0.1.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bhmdoc/v0.1.0>

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Rust's Cargo Semantic
Versioning](https://doc.rust-lang.org/cargo/reference/semver.html).

## [Unreleased]

## [0.2.0] - 2025-04-07

### Removed

- The chain is no longer verified against trusted root certificates upon
  creation.

### Added

- The `X509Trust` structure to hold the trusted root certificates.
- The method on the `X5Chain` that verifies the certificate chain against the
  trusted root certificates within the `X509Trust`.

## [0.1.0] - 2025-03-26

### Added

- This CHANGELOG file for tracking changes important to end users of the
  `bhx5chain` library.
- README.md describing the crate.
- Initial version of the `bhx5chain` crate.


[Unreleased]: <https://github.com/blockhousetech/eudi-rust-core/compare/bhx5chain/v0.1.0...HEAD>
[0.1.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bhx5chain/v0.1.0>
[0.2.0]: <https://github.com/blockhousetech/eudi-rust-core/releases/tag/bhx5chain/v0.2.0>

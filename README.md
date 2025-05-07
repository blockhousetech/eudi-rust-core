# eudi-rust-core

Core Rust crates used in The Blockhouse Technology Ltd. (TBTL) EUDI efforts.

## Crates Overview

### [bhmdoc](./bhmdoc/README.md)

Provides functionality for working with the mDL/mdoc specification as defined
in [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) and expanded on
in [ISO/IEC TS 18013-7:2024](https://www.iso.org/standard/82772.html) to
include integration with [OpenID for Verifiable
Credentials](https://openid.net/sg/openid4vc/specifications/).

The crate focuses on the issuing, presenting, and verifying of mdoc documents
using the `Issuer`, `Device`, and `Verifier` structs.

### [bhx5chain](./bhx5chain/README.md)

Focuses on the management and validation of ordered X.509 certificate chains as
defined in [RFC
9360](https://www.rfc-editor.org/rfc/rfc9360.html#section-2-5.4.1).

### [bh-jws-utils](./bh-jws-utils/README.md)

Offers functionalities for working with JSON Web Signatures (JWS).  This crate
includes utilities for signing and verifying JWTs using well-defined traits
(`JwtSigner` and `JwtVerifier`) and implementations (e.g., an OpenSSL-backed
signer for ECDSA keys).

### [bherror](./bherror/README.md)

Provides a robust error handling mechanism tailored for TBTL’s codebase. It
includes versatile error types (`Error`, `ErrorDyn`), comprehensive error
context propagation, and integration (such as `axum` adapters) to simplify
error logging and reporting.

### [bh-uri-utils](./bh-uri-utils/README.md)

Provides a collection of utility functions for working with URIs across various
Rust libraries.  This crate harmonizes the behavior of different URI
implementations (e.g. handling prefixes, suffixes, and conversions) to prevent
unexpected bugs.

NOTE: The crate is primarily intended for use within TBTL projects.  If you are
working outside TBTL, consider using a well-adopted crate such as
[iref](https://crates.io/crates/iref) or the URI solutions provided by your web
framework of choice.

### [bh-status-list](./bh-status-list/README.md)

This library provides functionality for working with status list data structures
as defined in the [IETF Token Status List
specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03)

## License

<sup>
Licensed under <a href="../COPYING">GNU Affero General Public License, Version 3</a>.
</sup>

# eudi-rust-core

Core Rust crates used in The Blockhouse Technology Ltd. (TBTL) EUDI efforts.

## Crates Overview

### [bherror](./bherror/README.md)

Provides a robust error handling mechanism tailored for TBTL’s codebase. It
includes versatile error types (`Error`, `ErrorDyn`), comprehensive error
context propagation, and integration (such as `axum` adapters) to simplify
error logging and reporting.

### [bhx5chain](./bhx5chain/README.md)

Focuses on the management and validation of ordered X.509 certificate chains as
defined in [RFC
9360](https://www.rfc-editor.org/rfc/rfc9360.html#section-2-5.4.1).

### [bh-jws-utils](./bh-jws-utils/README.md)

Offers functionalities for working with JSON Web Signatures (JWS).  This crate
includes utilities for signing and verifying JWTs using well-defined traits
(`JwtSigner` and `JwtVerifier`) and implementations (e.g., an OpenSSL-backed
signer for ECDSA keys).

### [bhmdoc](./bhmdoc/README.md)

Provides functionality for working with the mDL/mdoc specification as defined
in [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) and expanded on
in [ISO/IEC TS 18013-7:2024](https://www.iso.org/standard/82772.html) to
include integration with [OpenID for Verifiable
Credentials](https://openid.net/sg/openid4vc/specifications/).

The crate focuses on the issuing, presenting, and verifying of mdoc documents
using the `Issuer`, `Device`, and `Verifier` structs.

## License

<sup>
Licensed under <a href="../COPYING">GNU Affero General Public License, Version 3</a>.
</sup>

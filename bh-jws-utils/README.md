# bh-jws-utils

This library provides functionality for working with [JSON Web Signatures
(JWS)](https://www.rfc-editor.org/rfc/rfc7515.html) for use in other The
Blockhouse Technology Limited (TBTL) projects.

## Details

The primary way to use this library is via the `JwtSigner` and `JwtVerifier`
traits, which provide functionality for signing JWTs and verifying signed JWTs.
A default `openssl` backed implementation of these traits is available by using
the `openssl_impl::Es256Signer` and `openssl:impl:Es256Verifier` structs which
implement `JwtSigner` and `JwtVerifier` respectively.

For additional documentation & examples, take a look at the [crate
documentation](https://docs.rs/bh-jws-utils).

## Changelog

The changelog can be found [here](CHANGELOG.md).

## License

<sup> Licensed under <a href="../COPYING">GNU Affero General Public License,
Version 3</a>. </sup>

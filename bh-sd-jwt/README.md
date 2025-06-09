# bh-sd-jwt

This library provides functionality for working with the SD-JWT format for
Verifiable Credentials as defined in the [IETF SD-JWT-based Verifiable
Credentials specification][1] and the mechanism that allows for selective
disclosure of individual elements of JSON data structure as defined in the [IETF
Selective Disclosure for JWTs specification][2].

## Details

The primary way to use this library is to use the `IssuerJwt` struct to issue
JWTs, `Holder` to store an issued JWT and `Verifier` to verify an SD-JWT
presentation.

For additional documentation & examples, take a look at the [crate
documentation][3] and the examples in the source code.

## Changelog

The changelog can be found [here](CHANGELOG.md).

## License

<sup> Licensed under <a href="../COPYING">GNU Affero General Public License,
Version 3</a>. </sup>

[1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc
[2]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt
[3]: https://docs.rs/bh-sd-jwt
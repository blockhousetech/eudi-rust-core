# bh-status-list

This library provides functionality for working with status list data structures
as defined in the [IETF Token Status List specification][1].

## Creating lists

Use `StatusListInternal` to build and update lists, and `StatusListToken` to issue
JWT Status List Tokens.

## Verifying lists

`StatusClaim::evaluate` fetches a JWT and checks the credential's status in one
call. Use it when you know the signing key before fetching and require the
token's `iss` to match the credential issuer. `StatusListToken::verify` applies
the same issuer check to a JWT you already have.

`StatusListResponse::verify` provides a shared path for JWT and signed CWT.
Fetching and verification are separate so the caller can inspect the returned
header before selecting a key. This path accepts an optional `iss` and relies
on the caller to authorize the signing key for the credential's list. Both
formats return a `VerifiedStatusList`.

1. Verify the credential, then use its `StatusClaim` as the list reference.
2. Fetch the response with `StatusClaim::fetch` or your application's own
   transport. An HTTP client uses `STATUS_LIST_JWT_MEDIA_TYPE` and
   `STATUS_LIST_CWT_MEDIA_TYPE` to advertise the formats allowed by the
   caller's policy. Check the response's `Content-Type` against those formats.
   Use `StatusListResponse::Jwt` for a compact JWT string and
   `StatusListResponse::Cwt` for binary, tagged `COSE_Sign1` bytes.
3. If you need signing-key hints, call `response.parse()`. The parsed token
   exposes `algorithm()` and `key_id()` for either format. For certificate
   information, use `jwt_header()` to access `x5c` or `cwt_token()` to access
   `x5chain()`. Treat these fields as untrusted hints and apply your own
   algorithm, certificate trust, and signer authorization rules.
4. Pass the authorized key, signature verifier, current Unix time in seconds,
   and the credential's status-list URI to the parsed token's `verify()`.
   If you already have an authorized key, `response.verify()` does both steps.
   Verification matches the token's subject to the credential's URI, checks
   applicable time claims, and authenticates the token before decompressing
   the list.
5. Call `VerifiedStatusList::status` with the credential's reference. This
   checks the URI and index and returns the raw status code. Zero is the status
   list's valid code. Apply the verifier's status policy to other codes.

### Reusing a verified list

`VerifiedStatusList::issued_at` exposes `iat` for the caller's freshness policy.
`expires_at` is the optional absolute expiration time. `ttl` is the optional
cache lifetime measured from retrieval. Record the retrieval time and enforce
both available limits before reusing a cached list. Apply the caller's signer
authorization policy to the credential whose status is being checked.

For additional documentation & examples, take a look at the [crate
documentation][2].

## Changelog

The changelog can be found [here](CHANGELOG.md).

## License

<sup> Licensed under <a href="../COPYING">GNU Affero General Public License,
Version 3</a>. </sup>

[1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21
[2]: https://docs.rs/bh-status-list

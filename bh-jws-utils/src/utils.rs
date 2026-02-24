// Copyright (C) 2020-2026  The Blockhouse Technology Limited (TBTL).
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
// License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::cell::Cell;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bherror::traits::{ErrorContext as _, ForeignError as _, PropagateError as _};
use serde_json::Value;

use crate::{
    openssl_ec_pub_key_to_jwk, CryptoError, FormatError, JwkPublic, SignatureVerifier, Signer,
    SigningAlgorithm,
};

/// Type alias for a boxed error.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Create payload for a `JWS`, given its header and claims.
///
/// The payload is constructed by concatenating the header and claims by `.`
/// character, i.e. `<header>.<claims>`, as defined [here].
///
/// [here]: https://www.rfc-editor.org/rfc/rfc7515.html#section-5.1
pub fn construct_jws_payload(header: &str, claims: &str) -> String {
    format!("{header}.{claims}")
}

/// Returns the `base64url`-encoded string of the given `input`.
pub fn base64_url_encode<T: AsRef<[u8]>>(input: T) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// Decodes the given `payload` as the `base64url`-encoded string **without
/// padding** into bytes.
pub fn base64_url_decode<T: AsRef<[u8]>>(payload: T) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(payload)
}

/// Utility function that delegates to [`jwt::SignWithKey`] while allowing
/// proper propagation of errors from both the foreign trait and the [`Signer`].
pub(crate) fn sign_jwt<UnsignedJwt, SignedJwt, S>(
    unsigned_jwt: UnsignedJwt,
    signer: &S,
) -> Result<SignedJwt, BoxError>
where
    UnsignedJwt: jwt::SignWithKey<SignedJwt>,
    S: Signer + ?Sized,
{
    let signer_wrapper = ErrorHolder::new(signer);
    unsigned_jwt
        .sign_with_key(&signer_wrapper)
        .map_err(signer_wrapper.combine_error())
}

impl<T: Signer + ?Sized> jwt::SigningAlgorithm for ErrorHolder<&'_ T> {
    fn algorithm_type(&self) -> jwt::AlgorithmType {
        self.inner.algorithm().into()
    }

    fn sign(&self, header: &str, claims: &str) -> Result<String, jwt::Error> {
        let message = construct_jws_payload(header, claims);

        match self.inner.sign(message.as_bytes()) {
            Ok(signature_bytes) => Ok(base64_url_encode(signature_bytes)),
            Err(error) => Err(self.store_error(error)),
        }
    }
}

/// Utility function that delegates to [`jwt::VerifyWithKey`] while allowing
/// proper propagation of errors from both the foreign trait and the
/// [`SignatureVerifier`].
pub(crate) fn verify_jwt_signature<UnverifiedJwt, VerifiedJwt, V>(
    unverified_jwt: UnverifiedJwt,
    verifier: &V,
    public_key: &JwkPublic,
) -> Result<VerifiedJwt, BoxError>
where
    UnverifiedJwt: jwt::VerifyWithKey<VerifiedJwt>,
    V: SignatureVerifier + ?Sized,
{
    let verifier_wrapper = ErrorHolder::new(VerifierWrapper {
        verifier,
        public_key,
    });
    unverified_jwt
        .verify_with_key(&verifier_wrapper)
        .map_err(verifier_wrapper.combine_error())
}

/// Adapter for implementing [jwt::VerifyingAlgorithm], for internal use.
struct VerifierWrapper<'a, T: SignatureVerifier + ?Sized> {
    verifier: &'a T,
    public_key: &'a JwkPublic,
}

impl<T: SignatureVerifier + ?Sized> jwt::VerifyingAlgorithm
    for ErrorHolder<VerifierWrapper<'_, T>>
{
    fn algorithm_type(&self) -> jwt::AlgorithmType {
        self.inner.verifier.algorithm().into()
    }

    fn verify_bytes(
        &self,
        header: &str,
        claims: &str,
        signature: &[u8],
    ) -> Result<bool, jwt::Error> {
        let message = construct_jws_payload(header, claims);

        self.inner
            .verifier
            .verify(message.as_bytes(), signature, self.inner.public_key)
            .map_err(|error| self.store_error(error))
    }
}

/// Helper wrapper for collecting errors from signer/verifier implementations
/// which cannot be piped through `jwt:Error`.
struct ErrorHolder<T> {
    inner: T,
    /// Interior-mutable slot for the error returned by the wrapped signer, if any.
    /// `jwt::Error` doesn't let us convey it, so we have to do it in a roundabout way...
    error: Cell<Option<BoxError>>,
}

impl<T> ErrorHolder<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            error: Cell::new(None),
        }
    }

    fn store_error(&self, error: BoxError) -> jwt::Error {
        let previous = self.error.replace(Some(error));
        debug_assert!(previous.is_none());

        // Not really "correct", but we need to return *something*
        // The caller should recover the true error from the wrapper instead...
        jwt::Error::InvalidSignature
    }

    /// Check whether an underlying error occurred, returning it if it did, or
    /// returning the [`jwt::Error`] if not.
    ///
    /// The caller SHOULD call this function as a finalizer to recover the
    /// true error if it is present, rather than the one returned by
    /// `jwt` crate trait impls.
    fn combine_error(self) -> impl FnOnce(jwt::Error) -> BoxError {
        |jwt_error| {
            if let Some(underlying_error) = self.error.into_inner() {
                debug_assert!(matches!(jwt_error, jwt::Error::InvalidSignature));
                underlying_error
            } else {
                Box::new(jwt_error)
            }
        }
    }
}

/// Retrieve public JWK from the provided x5chain certificate chain leaf.
///
/// Currently, only `Es256` is supported.
pub fn public_jwk_from_x5chain_leaf(
    x5chain: &bhx5chain::X5Chain,
    alg: &SigningAlgorithm,
    kid: Option<&str>,
) -> bherror::Result<JwkPublic, CryptoError> {
    let pkey = x5chain
        .leaf_certificate_key()
        .with_err(|| CryptoError::InvalidX5Chain)
        .ctx(|| "invalid public key from certificate")?;

    match (alg, pkey.id()) {
        (SigningAlgorithm::Es256, openssl::pkey::Id::EC) => {
            let ec_key = pkey
                .ec_key()
                .foreign_err(|| CryptoError::CryptoBackend)
                .ctx(|| "invalid EC key")?;

            openssl_ec_pub_key_to_jwk(&ec_key, kid).ctx(|| "unable to construct JWK")
        }
        _ => Err(bherror::Error::root(CryptoError::Unsupported(
            "only Es256 is currently supported".to_string(),
        ))),
    }
}

/// Compute the _JWK SHA-256 Thumbprint_ of the provided public JWK.
///
/// The thumbprint is computed as per [RFC 7638][1], and returned as raw bytes.
/// In order to obtain a proper thumbprint string, the output needs to be
/// `base64url`-encoded **without** padding.
///
/// [1]: <https://www.rfc-editor.org/info/rfc7638>
pub fn jwk_sha256_thumbprint_bytes(jwk: JwkPublic) -> bherror::Result<Vec<u8>, FormatError> {
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(Value::Object(jwk))
        .foreign_err(|| FormatError::JwkParsingFailed("invalid JWK".to_owned()))?;

    let thumbprint = jwk.thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256);

    // decode to get the raw bytes
    base64_url_decode(thumbprint)
        // should never fail
        .foreign_err(|| FormatError::JwkParsingFailed("invalid SHA-256 Thumbprint".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Example taken from the `Section B.2.6.1.` of the [OpenID4VP][1].
    ///
    /// [1]: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.1>
    #[test]
    fn test_jwk_sha256_thumbprint_bytes() {
        let Value::Object(jwk) = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
            "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
            "use": "enc",
            "alg": "ECDH-ES",
            "kid": "1",
        }) else {
            unreachable!("JWK must be JSON object")
        };

        let thumbprint = jwk_sha256_thumbprint_bytes(jwk).unwrap();
        let thumbprint_hex = hex::encode(thumbprint);

        let expected = "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047";

        assert_eq!(expected, thumbprint_hex);
    }
}

// Copyright (C) 2020-2025  The Blockhouse Technology Limited (TBTL).
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

use std::str::FromStr;

use bherror::Error;
use bhx5chain::X5Chain;
use serde::{Deserialize, Serialize};

use crate::{error::SignatureError, utils::BoxError, JwkPublic};

/// Signature algorithms approved for use in the context of EUDI.
///
/// # Algorithms
///
/// This enumeration contains only JOSE asymmetric signature algorithms approved
/// for use by SOG-IS ACM v1.2, with any parameters (e.g. RSA modulus size)
/// meeting therein imposed requirements.
///
/// For more details see the following references:
/// - IETF draft [section 5.1.1], [section 10.1];
/// - [SOG-IS Agreed Cryptographic Mechanisms v1.2];
/// - [ETSI TS 119 312] sections 6 and 7.
///
/// [section 5.1.1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-08#section-5.1.1-2
/// [section 10.1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-08#section-10.1-3
/// [SOG-IS Agreed Cryptographic Mechanisms v1.2]: https://www.sogis.eu/documents/cc/crypto/SOGIS-Agreed-Cryptographic-Mechanisms-1.2.pdf
/// [ETSI TS 119 312]: https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/01.04.03_60/ts_119312v010403p.pdf
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SigningAlgorithm {
    /// ECDSA over P-256 with SHA-256
    Es256,
    /// ECDSA over P-384 with SHA-384
    Es384,
    /// ECDSA over P-521 with SHA-512
    Es512,
    /// RSASSA-PSS with SHA-256 and MGF1 with SHA-256
    Ps256,
    /// RSASSA-PSS with SHA-384 and MGF1 with SHA-384
    Ps384,
    /// RSASSA-PSS with SHA-512 and MGF1 with SHA-512
    Ps512,
}

/// JWS `"alg"` header parameter value for digital signature algorithm
/// **ECDSA using P-256 and SHA-256**, as specified in [RFC7518].
///
/// [RFC7518]: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
pub const SIGNING_ALG_ES256: &str = "ES256";
/// JWS `"alg"` header parameter value for digital signature algorithm
/// **ECDSA using P-384 and SHA-384**, as specified in [RFC7518].
///
/// [RFC7518]: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
pub const SIGNING_ALG_ES384: &str = "ES384";
/// JWS `"alg"` header parameter value for digital signature algorithm
/// **ECDSA using P-521 and SHA-512**, as specified in [RFC7518].
///
/// [RFC7518]: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
pub const SIGNING_ALG_ES512: &str = "ES512";
/// JWS `"alg"` header parameter value for digital signature algorithm
/// **RSASSA-PSS using SHA-256 and MGF1 with SHA-256**, as specified in [RFC7518].
///
/// [RFC7518]: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
pub const SIGNING_ALG_PS256: &str = "PS256";
/// JWS `"alg"` header parameter value for digital signature algorithm
/// **RSASSA-PSS using SHA-384 and MGF1 with SHA-384**, as specified in [RFC7518].
///
/// [RFC7518]: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
pub const SIGNING_ALG_PS384: &str = "PS384";
/// JWS `"alg"` header parameter value for digital signature algorithm
/// **RSASSA-PSS using SHA-512 and MGF1 with SHA-512**, as specified in [RFC7518].
///
/// [RFC7518]: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
pub const SIGNING_ALG_PS512: &str = "PS512";

impl FromStr for SigningAlgorithm {
    type Err = Error<SignatureError>;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            SIGNING_ALG_ES256 => Ok(SigningAlgorithm::Es256),
            SIGNING_ALG_ES384 => Ok(SigningAlgorithm::Es384),
            SIGNING_ALG_ES512 => Ok(SigningAlgorithm::Es512),
            SIGNING_ALG_PS256 => Ok(SigningAlgorithm::Ps256),
            SIGNING_ALG_PS384 => Ok(SigningAlgorithm::Ps384),
            SIGNING_ALG_PS512 => Ok(SigningAlgorithm::Ps512),
            _ => Err(Error::root(SignatureError::InvalidSigningAlgorithm(
                value.to_string(),
            ))),
        }
    }
}

impl std::fmt::Display for SigningAlgorithm {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let message = match self {
            Self::Es256 => SIGNING_ALG_ES256,
            Self::Es384 => SIGNING_ALG_ES384,
            Self::Es512 => SIGNING_ALG_ES512,
            Self::Ps256 => SIGNING_ALG_PS256,
            Self::Ps384 => SIGNING_ALG_PS384,
            Self::Ps512 => SIGNING_ALG_PS512,
        };
        write!(f, "{}", message)
    }
}

impl From<SigningAlgorithm> for jwt::AlgorithmType {
    fn from(value: SigningAlgorithm) -> Self {
        match value {
            SigningAlgorithm::Es256 => Self::Es256,
            SigningAlgorithm::Es384 => Self::Es384,
            SigningAlgorithm::Es512 => Self::Es512,
            SigningAlgorithm::Ps256 => Self::Ps256,
            SigningAlgorithm::Ps384 => Self::Ps384,
            SigningAlgorithm::Ps512 => Self::Ps512,
        }
    }
}

/// An external signing backend, to be used for computing a JWS signature.
///
/// # Algorithms
///
/// Implementors of this trait must use only approved JOSE asymmetric signature algorithms,
/// with any parameters (e.g. RSA modulus size) meeting standards-imposed requirements.
/// For more details see [`SigningAlgorithm`].
///
/// The output of the signer, regardless of the algorithm, must be a valid **JWS signature**.
/// See step 5 in [section 5.1 of RFC7515](https://www.rfc-editor.org/rfc/rfc7515.html#section-5.1)
/// for more information.
pub trait Signer {
    /// The algorithm this signer uses. Must be a constant function.
    fn algorithm(&self) -> SigningAlgorithm;

    /// Produce a JWS signature as a byte array, not yet base64url-encoded.
    ///
    /// The `message` is guaranteed to be a valid JWS signing input.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, BoxError>;
}

/// Subtrait for [`Signer`]-s which have an associated JWK `kid` (Key ID) parameter.
/// This is used to set the `kid` header parameter when signing a JWT.
pub trait HasJwkKid: Signer {
    /// Return the `kid` parameter of the associated JWK.
    ///
    /// See [section 4.5 of RFC7517](https://datatracker.ietf.org/doc/html/rfc7517#section-4.5)
    /// for more detials.
    fn jwk_kid(&self) -> &str;
}

/// Subtrait for [`Signer`]-s which have an associated `x5chain`.
pub trait HasX5Chain: Signer {
    /// Return the `x5c` parameter of the associated JWK.
    fn x5chain(&self) -> X5Chain;
}

/// An external backend for signature verification, to be used for verifying
/// JWS signatures.
pub trait SignatureVerifier: Sync {
    /// The algorithm used for the signature verification.
    fn algorithm(&self) -> SigningAlgorithm;

    /// Verifies the signature of the message, against the provided public key.
    ///
    /// The algorithm used to verify the signature must be the one returned by
    /// [`SignatureVerifier::algorithm`].
    ///
    /// # Return
    /// Method returns `Ok(true)` if the signature if valid for the given
    /// message, `Ok(false)` if it isn't (but there was no issue with the
    /// verifier itself), and `Err(_)` when the verifier itself encounters an
    /// error for any other reason.
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &JwkPublic,
    ) -> Result<bool, BoxError>;
}

/// An external backend capable of signing JWTs.
///
/// This is an extension trait over [`Signer`]; prefer depending on this trait
/// when writing code which handles JWTs. It is however not object safe; depend
/// on [`Signer`] directly if you need that.
pub trait JwtSigner: Signer {
    /// Utility function that delegates to [`jwt::SignWithKey`] while allowing
    /// proper propagation of errors from both the foreign trait and the [`Signer`].
    fn sign_jwt<UnsignedJwt, SignedJwt>(
        &self,
        unsigned_jwt: UnsignedJwt,
    ) -> Result<SignedJwt, BoxError>
    where
        UnsignedJwt: jwt::SignWithKey<SignedJwt>;
}

impl<S: Signer + ?Sized> JwtSigner for S {
    fn sign_jwt<UnsignedJwt, SignedJwt>(
        &self,
        unsigned_jwt: UnsignedJwt,
    ) -> Result<SignedJwt, BoxError>
    where
        UnsignedJwt: jwt::SignWithKey<SignedJwt>,
    {
        crate::utils::sign_jwt(unsigned_jwt, self)
    }
}

/// An external backend capable of verifying the signatures of JWTs.
///
/// This is an extension trait over [`SignatureVerifier`]; prefer depending on
/// this trait when writing code which handles JWTs. It is however not object
/// safe; depend on [`SignatureVerifier`] directly if you need that.
pub trait JwtVerifier: SignatureVerifier {
    /// Utility function that delegates to [`jwt::VerifyWithKey`] while allowing
    /// proper propagation of errors from both the foreign trait and the
    /// [`SignatureVerifier`].
    fn verify_jwt_signature<UnverifiedJwt, VerifiedJwt>(
        &self,
        unverified_jwt: UnverifiedJwt,
        public_key: &JwkPublic,
    ) -> Result<VerifiedJwt, BoxError>
    where
        UnverifiedJwt: jwt::VerifyWithKey<VerifiedJwt>;
}

impl<V: SignatureVerifier + ?Sized> JwtVerifier for V {
    fn verify_jwt_signature<UnverifiedJwt, VerifiedJwt>(
        &self,
        unverified_jwt: UnverifiedJwt,
        public_key: &JwkPublic,
    ) -> Result<VerifiedJwt, BoxError>
    where
        UnverifiedJwt: jwt::VerifyWithKey<VerifiedJwt>,
    {
        crate::utils::verify_jwt_signature(unverified_jwt, self, public_key)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn signing_algorithms_serialize_correctly() {
        struct TestCase<'a> {
            alg: SigningAlgorithm,
            alg_str: &'a str,
        }

        let test_cases: &[TestCase] = &[
            TestCase {
                alg: SigningAlgorithm::Es256,
                alg_str: SIGNING_ALG_ES256,
            },
            TestCase {
                alg: SigningAlgorithm::Es384,
                alg_str: SIGNING_ALG_ES384,
            },
            TestCase {
                alg: SigningAlgorithm::Es512,
                alg_str: SIGNING_ALG_ES512,
            },
            TestCase {
                alg: SigningAlgorithm::Ps256,
                alg_str: SIGNING_ALG_PS256,
            },
            TestCase {
                alg: SigningAlgorithm::Ps384,
                alg_str: SIGNING_ALG_PS384,
            },
            TestCase {
                alg: SigningAlgorithm::Ps512,
                alg_str: SIGNING_ALG_PS512,
            },
        ];

        for TestCase { alg, alg_str } in test_cases {
            let serialized = serde_json::to_string(alg).unwrap();
            let expected = format!("\"{}\"", alg_str);
            assert_eq!(expected, serialized);

            let deserialized_serde: SigningAlgorithm = serde_json::from_str(&expected).unwrap();
            assert_eq!(alg, &deserialized_serde);

            let deserialized_str = SigningAlgorithm::from_str(alg_str).unwrap();
            assert_eq!(alg, &deserialized_str);

            assert_eq!(*alg, SigningAlgorithm::from_str(&alg.to_string()).unwrap());
        }
    }
}

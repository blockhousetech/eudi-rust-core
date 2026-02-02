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

use bh_jws_utils::{jwt, JwkPublic, JwtSigner, JwtVerifier, SigningAlgorithm};
use iref::Uri;
use serde::{Deserialize, Serialize};

use crate::{
    token,
    utils::jwt::{sign_jwt_token, verify_jwt_token},
    Error, Result, StatusList, UriBuf,
};

const STATUS_LIST_TOKEN_TYP: &str = "statuslist+jwt";

/// The cryptographically signed Status List in the JWT format.
///
/// More can be read [here][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03#name-status-list-token
pub struct StatusListToken<S>(jwt::Token<StatusListTokenHeader, StatusListTokenClaims, S>);

impl StatusListToken<token::Signed> {
    /// Creates a new **SIGNED** `StatusListToken`.
    ///
    /// The arguments are as follows:
    /// - `claims`: claims of the Status List Token,
    /// - `kid`: an ID of the private key used to sign the token,
    /// - `key`: an implementation of the algorithm used to sign the token with
    ///   the specific private key.
    ///
    /// # Errors
    ///
    /// If the signature fails to compute, the [`Error::TokenSigningFailed`]
    /// will be returned.
    pub fn new(claims: StatusListTokenClaims, kid: String, key: &impl JwtSigner) -> Result<Self> {
        let alg = key.algorithm();

        let header = StatusListTokenHeader {
            alg,
            kid,
            typ: STATUS_LIST_TOKEN_TYP.to_owned(),
        };

        let signed_token = sign_jwt_token(header, claims, key)?;

        Ok(Self(signed_token))
    }

    /// Returns the [`StatusListToken`] token as a `&str`.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Display for StatusListToken<token::Signed> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<StatusListToken<token::Verified>> for (StatusListTokenHeader, StatusListTokenClaims) {
    fn from(token: StatusListToken<token::Verified>) -> Self {
        token.0.into()
    }
}

impl StatusListToken<token::Verified> {
    /// Verifies a signed Status List Token.
    ///
    /// It verifies the signature of the JWT token and also its claims.
    ///
    /// The arguments are as follows:
    /// - `token`: the String representation of the JWT token,
    /// - `verifier`: the verifier of the token signature,
    /// - `current_time`: the current time in seconds, elapsed since the UNIX
    ///   epoch,
    /// - `iss`: the `iss` claim from the Verifiable Credential itself,
    /// - `sub`: the `uri` claim from the `status` claim of the Verifiable
    ///   Credential.
    ///
    /// # Errors
    ///
    /// The function can result in the following errors:
    /// - [`Error::TokenParsingFailed`] if it is unable to parse the JWT token,
    /// - [`Error::TokenSignatureVerificationFailed`] if the signature of the
    ///   JWT token is invalid,
    /// - [`Error::InvalidTokenHeaderTyp`] if the `typ` claim in the header is
    ///   not set to `statuslist+jwt`,
    /// - [`Error::InvalidTokenIss`] if the `iss` claim is not equal to the
    ///   provided `iss` value,
    /// - [`Error::InvalidTokenSub`] if the `sub` claim is not equal to the
    ///   provided `sub` value,
    /// - [`Error::TokenExpired`] if the token is expired based on the `exp`
    ///   claim.
    pub fn verify(
        token: &str,
        verifier: &(impl JwtVerifier + ?Sized),
        public_key: &JwkPublic,
        current_time: u64,
        iss: &Uri,
        sub: &Uri,
    ) -> Result<Self> {
        // Verify the JWT signature.
        let verified_token = verify_jwt_token(token, verifier, public_key)?;

        // Verify JWT header.
        verified_token.header().verify()?;

        // Verify JWT claims.
        verified_token.claims().verify(current_time, iss, sub)?;

        Ok(Self(verified_token))
    }

    /// Returns the token header.
    pub fn header(&self) -> &StatusListTokenHeader {
        self.0.header()
    }

    /// Returns the token claims.
    pub fn claims(&self) -> &StatusListTokenClaims {
        self.0.claims()
    }
}

/// Header of the Status List Token in the JWT format.
#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub struct StatusListTokenHeader {
    /// An algorithm used to sign the token.
    pub alg: SigningAlgorithm,

    /// An ID of the private key used to sign the token.
    pub kid: String,

    /// Type of the JWT, which is always _`statuslist+jwt`_.
    pub typ: String,
}

impl StatusListTokenHeader {
    /// Verifies the header of the Status List Token.
    ///
    /// The only step is checking if the `typ` claim is set to `statuslist+jwt`.
    /// If not, [`Error::InvalidTokenHeaderTyp`] is returned.
    fn verify(&self) -> Result<()> {
        if self.typ != STATUS_LIST_TOKEN_TYP {
            return Err(bherror::Error::root(Error::InvalidTokenHeaderTyp(
                self.typ.to_owned(),
            )));
        }

        Ok(())
    }
}

impl jwt::JoseHeader for StatusListTokenHeader {
    fn algorithm_type(&self) -> jwt::AlgorithmType {
        self.alg.into()
    }
}

/// Claims of the Status List Token in the JWT format.
#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub struct StatusListTokenClaims {
    /// A unique identifier of the Issuer of the Status List Token.
    ///
    /// It **MUST** be the same as the `iss` claim value of the Verifiable
    /// Credential itself.
    pub iss: UriBuf,

    /// The URI of the Status List Token.
    ///
    /// It **MUST** be equal to the `uri` claim in the `status` claim of the
    /// Verifiable Credential.
    pub sub: UriBuf,

    /// The time at which the Status List Token was issued.
    ///
    /// It is expressed in seconds since the *UNIX* epoch.
    pub iat: u64,

    /// The optional expiration time of the Status List Token, after which the
    /// token is not valid anymore.
    ///
    /// It is expressed in seconds since the *UNIX* epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,

    /// The optional *time-to-live* parameter, specifying the maximum amount of
    /// time, in seconds, that the Status List Token can be cached before a
    /// fresh copy should be retrieved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,

    /// The Status List contained in the token.
    pub status_list: StatusList,
}

impl StatusListTokenClaims {
    /// Sets claims for the Status List Token.
    ///
    /// The arguments are as follows:
    /// - `iss`: the unique identifier of the Issuer of the Status List Token,
    /// - `sub`: the URI of the Status List Token,
    /// - `iat`: the time at which the Status List Token was issued,
    /// - `exp`: the expiration time of the Status List Token, after which the
    ///   token is not valid anymore,
    /// - `ttl`: the *time-to-live* parameter, specifying the maximum amount of
    ///   time, in seconds, that the Status List Token can be cached before a
    ///   fresh copy should be retrieved,
    /// - `status_list`: the Status List contained in the token.
    ///
    /// # Note
    ///
    /// The `iss` value **MUST** be the same as the `iss` claim value of the
    /// Verifiable Credentials whose `status` values are stored in the list.
    ///
    /// The `sub` value **MUST** be equal to the `uri` claim in the `status`
    /// claim of the Verifiable Credentials whose `status` values are stored in
    /// the list.
    pub fn new(
        iss: UriBuf,
        sub: UriBuf,
        iat: u64,
        exp: Option<u64>,
        ttl: Option<u64>,
        status_list: StatusList,
    ) -> Self {
        Self {
            iss,
            sub,
            iat,
            exp,
            ttl,
            status_list,
        }
    }

    /// Verifies claims of the Status List Token.
    ///
    /// The following verification steps are performed:
    /// - `iss`: checks if the `iss` claim is equal to the provided `iss` value,
    ///   and returns [`Error::InvalidTokenIss`] if not,
    /// - `sub`: checks if the `sub` claim is equal to the provided `sub` value,
    ///   and returns [`Error::InvalidTokenSub`] if not,
    /// - `exp`: checks whether `exp` is in the past (token expired), and
    ///   returns [`Error::TokenExpired`] if it is.
    fn verify(&self, current_time: u64, iss: &Uri, sub: &Uri) -> Result<()> {
        if self.iss != iss {
            return Err(bherror::Error::root(Error::InvalidTokenIss(
                iss.to_owned(),
                self.iss.clone(),
            )));
        }

        if self.sub != sub {
            return Err(bherror::Error::root(Error::InvalidTokenSub(
                sub.to_owned(),
                self.sub.clone(),
            )));
        }

        if let Some(exp) = self.exp {
            if exp < current_time {
                return Err(bherror::Error::root(Error::TokenExpired(current_time, exp)));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use bh_jws_utils::{
        json_object, BoxError,
        SigningAlgorithm::{self, *},
    };

    use super::*;
    use crate::{JwtError, StatusBits, StatusListInternal};

    fn str_to_uri(s: &str) -> UriBuf {
        UriBuf::from_str(s).unwrap()
    }

    struct DummySigner(SigningAlgorithm, bool);

    impl bh_jws_utils::Signer for DummySigner {
        fn algorithm(&self) -> SigningAlgorithm {
            self.0
        }

        fn sign(&self, _message: &[u8]) -> std::result::Result<Vec<u8>, BoxError> {
            self.1
                .then(|| b"signatureb64".to_vec())
                .ok_or(Box::new(JwtError::InvalidSignature))
        }

        fn public_jwk(&self) -> std::result::Result<JwkPublic, BoxError> {
            unimplemented!("this is currently not needed")
        }
    }

    struct DummyVerifier(SigningAlgorithm, std::result::Result<bool, ()>);

    impl bh_jws_utils::SignatureVerifier for DummyVerifier {
        fn algorithm(&self) -> SigningAlgorithm {
            self.0
        }

        fn verify(&self, _: &[u8], _: &[u8], _: &JwkPublic) -> std::result::Result<bool, BoxError> {
            self.1.map_err(|_| Box::new(JwtError::Format) as _)
        }
    }

    fn dummy_jwk() -> JwkPublic {
        json_object!({})
    }

    fn get_valid_jwt(alg: SigningAlgorithm, iss: UriBuf, sub: UriBuf, exp: Option<u64>) -> String {
        let status_list = StatusListInternal::new(StatusBits::Eight, Option::None);

        let claims =
            StatusListTokenClaims::new(iss, sub, 100, exp, Option::None, status_list.into());

        let token_signed =
            StatusListToken::new(claims, "kid".to_owned(), &DummySigner(alg, true)).unwrap();

        token_signed.to_string()
    }

    #[test]
    fn test_status_list_token_signing_fails() {
        let status_list = StatusListInternal::new(StatusBits::Eight, Option::None);

        let claims = StatusListTokenClaims::new(
            str_to_uri("http://iss"),
            str_to_uri("http://sub"),
            100,
            Option::None,
            Option::None,
            status_list.into(),
        );

        let err = StatusListToken::new(claims, "kid".to_owned(), &DummySigner(Es512, false))
            .err()
            .unwrap();

        assert!(matches!(err.error, Error::TokenSigningFailed));
    }

    #[test]
    fn test_status_list_token_new_success() {
        let status_list = StatusListInternal::new(StatusBits::Two, Option::None);

        let claims = StatusListTokenClaims::new(
            str_to_uri("http://iss"),
            str_to_uri("http://sub"),
            100,
            Option::None,
            Option::None,
            status_list.into(),
        );

        let _token =
            StatusListToken::new(claims, "kid".to_owned(), &DummySigner(Es256, true)).unwrap();
    }

    #[test]
    fn test_status_list_token_verify_success() {
        let status_list = StatusListInternal::new(StatusBits::One, Option::None);

        let iss = str_to_uri("http://iss");
        let sub = str_to_uri("http://sub");
        let iat = 100;

        let claims = StatusListTokenClaims::new(
            iss.clone(),
            sub.clone(),
            iat,
            Option::None,
            Option::None,
            status_list.into(),
        );

        let token_signed =
            StatusListToken::new(claims, "kid".to_owned(), &DummySigner(Es512, true)).unwrap();

        let token_verified = StatusListToken::verify(
            token_signed.as_str(),
            &DummyVerifier(Es512, Ok(true)),
            &dummy_jwk(),
            100,
            &iss,
            &sub,
        )
        .unwrap();

        let (header, claims) = token_verified.into();

        assert_eq!(header.alg, Es512);
        assert_eq!(header.kid, "kid");
        assert_eq!(header.typ, STATUS_LIST_TOKEN_TYP);

        assert_eq!(claims.iss, iss);
        assert_eq!(claims.sub, sub);
        assert_eq!(claims.iat, iat);
    }

    #[test]
    fn test_status_list_token_verify_parse_fails() {
        let err = StatusListToken::verify(
            "invalid-token",
            &DummyVerifier(Ps384, Ok(true)),
            &dummy_jwk(),
            100,
            &str_to_uri("http://iss"),
            &str_to_uri("http://sub"),
        )
        .err()
        .unwrap();

        assert!(matches!(err.error, Error::TokenParsingFailed));
    }

    #[test]
    fn test_status_list_token_verify_invalid_alg_fails() {
        let iss = str_to_uri("http://iss");
        let sub = str_to_uri("http://sub");

        let jwt = get_valid_jwt(Ps512, iss.clone(), sub.clone(), Option::None);

        let err = StatusListToken::verify(
            &jwt,
            &DummyVerifier(Ps256, Ok(true)),
            &dummy_jwk(),
            100,
            &iss,
            &sub,
        )
        .err()
        .unwrap();

        assert!(matches!(err.error, Error::TokenSignatureVerificationFailed));
    }

    #[test]
    fn test_status_list_token_verify_signature_mismatch_fails() {
        let iss = str_to_uri("http://iss");
        let sub = str_to_uri("http://sub");

        let jwt = get_valid_jwt(Ps384, iss.clone(), sub.clone(), Option::None);

        let err = StatusListToken::verify(
            &jwt,
            &DummyVerifier(Ps384, Ok(false)),
            &dummy_jwk(),
            100,
            &iss,
            &sub,
        )
        .err()
        .unwrap();

        assert!(matches!(err.error, Error::TokenSignatureVerificationFailed));
    }

    #[test]
    fn test_status_list_token_verify_signature_verification_fails() {
        let iss = str_to_uri("http://iss");
        let sub = str_to_uri("http://sub");

        let jwt = get_valid_jwt(Ps384, iss.clone(), sub.clone(), Option::None);

        let err = StatusListToken::verify(
            &jwt,
            &DummyVerifier(Ps384, Err(())),
            &dummy_jwk(),
            100,
            &iss,
            &sub,
        )
        .err()
        .unwrap();

        assert!(matches!(err.error, Error::TokenSignatureVerificationFailed));
    }

    #[test]
    fn test_status_list_token_verify_iss_mismatch_fails() {
        let iss = str_to_uri("http://iss");
        let sub = str_to_uri("http://sub");

        let iss_invalid = str_to_uri("http://iss-invalid");

        let jwt = get_valid_jwt(Es512, iss_invalid.clone(), sub.clone(), Option::None);

        let err = StatusListToken::verify(
            &jwt,
            &DummyVerifier(Es512, Ok(true)),
            &dummy_jwk(),
            100,
            &iss,
            &sub,
        )
        .err()
        .unwrap();

        assert!(
            matches!(err.error, Error::InvalidTokenIss(iss_vc, iss_rec) if iss_vc == iss && iss_rec == iss_invalid)
        );
    }

    #[test]
    fn test_status_list_token_verify_sub_mismatch_fails() {
        let iss = str_to_uri("http://iss");
        let sub = str_to_uri("http://sub");

        let sub_invalid = str_to_uri("http://sub-invalid");

        let jwt = get_valid_jwt(Es256, iss.clone(), sub_invalid.clone(), Option::None);

        let err = StatusListToken::verify(
            &jwt,
            &DummyVerifier(Es256, Ok(true)),
            &dummy_jwk(),
            100,
            &iss,
            &sub,
        )
        .err()
        .unwrap();

        assert!(
            matches!(err.error, Error::InvalidTokenSub(sub_vc, sub_rec) if sub_vc == sub && sub_rec == sub_invalid)
        );
    }

    #[test]
    fn test_status_list_token_verify_token_expired_fails() {
        let iss = str_to_uri("http://iss");
        let sub = str_to_uri("http://sub");

        let jwt = get_valid_jwt(Es256, iss.clone(), sub.clone(), Some(200));

        let err = StatusListToken::verify(
            &jwt,
            &DummyVerifier(Es256, Ok(true)),
            &dummy_jwk(),
            300,
            &iss,
            &sub,
        )
        .err()
        .unwrap();

        assert!(matches!(err.error, Error::TokenExpired(curr, exp) if curr == 300 && exp == 200));
    }
}

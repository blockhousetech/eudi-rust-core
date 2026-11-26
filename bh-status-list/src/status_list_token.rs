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

use bh_jws_utils::{jwt, JwkPublic, JwtSigner, JwtVerifier, SignatureVerifier, SigningAlgorithm};
use bherror::traits::ForeignError as _;
use bhx5chain::JwtX5Chain;
use iref::Uri;
use serde::{de::IgnoredAny, Deserialize, Serialize};

use crate::{
    status_list::EncodedStatusList,
    token,
    utils::jwt::{parse_jwt_token_unverified, sign_jwt_token, verify_jwt_token},
    verified::{validate_numeric_dates, validate_optional_claims, validate_subject},
    CwtStatusListToken, Error, Result, StatusList, StatusListResponse, UriBuf, VerifiedStatusList,
};

const STATUS_LIST_TOKEN_TYP: &str = "statuslist+jwt";

/// The cryptographically signed Status List in the JWT format.
///
/// More can be read [here][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1
pub struct StatusListToken<S> {
    header: StatusListTokenHeader,
    claims: StatusListTokenClaims,
    signature: S,
}

impl StatusListToken<token::Signed> {
    /// Creates a new **SIGNED** `StatusListToken`.
    ///
    /// The arguments are as follows:
    /// - `claims`: claims of the Status List Token,
    /// - `kid`: an optional ID of the private key used to sign the token,
    /// - `x5c`: an optional X.509 certificate chain corresponding to the key
    ///   used to sign the token,
    /// - `key`: an implementation of the algorithm used to sign the token with
    ///   the specific private key.
    ///
    /// # Errors
    ///
    /// If the signature fails to compute, the [`Error::TokenSigningFailed`]
    /// will be returned.
    pub fn new(
        claims: StatusListTokenClaims,
        kid: Option<String>,
        x5c: Option<JwtX5Chain>,
        key: &impl JwtSigner,
    ) -> Result<Self> {
        let alg = key.algorithm();

        // TODO: verify x5c leaf key is the JWT signing key

        let header = StatusListTokenHeader {
            alg,
            kid,
            x5c,
            typ: STATUS_LIST_TOKEN_TYP.to_owned(),
            crit: None,
            b64: None,
        };

        let token_string = sign_jwt_token(&header, &claims, key)?;
        Ok(Self {
            header,
            claims,
            signature: token::Signed { token_string },
        })
    }

    /// Returns the [`StatusListToken`] token as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.signature.token_string
    }
}

impl std::fmt::Display for StatusListToken<token::Signed> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<StatusListToken<token::Verified>> for (StatusListTokenHeader, StatusListTokenClaims) {
    fn from(token: StatusListToken<token::Verified>) -> Self {
        (token.header, token.claims)
    }
}

impl StatusListToken<token::Verified> {
    /// Verifies a signed JWT Status List Token under an issuer-binding policy.
    ///
    /// Use this when the token must name the credential issuer. For JWT or
    /// CWT verification with an optional issuer, use
    /// [`crate::StatusListResponse::verify`].
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
    /// - [`Error::TokenExpired`] if the current time has reached `exp`,
    /// - [`Error::TokenNotYetValid`] if the current time precedes `nbf`.
    pub fn verify(
        token: &str,
        verifier: &(impl JwtVerifier + ?Sized),
        public_key: &JwkPublic,
        current_time: u64,
        iss: &Uri,
        sub: &Uri,
    ) -> Result<Self> {
        let token = parse_jwt_token_unverified::<JwtClaims<u64>>(token)?;
        let verified = verify_jwt_token(token, verifier, public_key)?;
        let (header, claims) = verified.into();
        header.verify()?;
        let issuer = claims
            .iss
            .as_deref()
            .ok_or_else(|| bherror::Error::root(Error::InvalidTokenClaims).ctx("missing issuer"))?
            .parse::<UriBuf>()
            .foreign_err(|| Error::InvalidTokenClaims)?;
        if issuer.as_str() != iss.as_str() {
            return Err(bherror::Error::root(Error::InvalidTokenIss(
                iss.to_owned(),
                issuer,
            )));
        }
        claims.validate(sub)?;
        if let Some(exp) = claims.exp.filter(|&exp| exp <= current_time) {
            return Err(bherror::Error::root(Error::TokenExpired(current_time, exp)));
        }
        if claims.nbf.is_some_and(|nbf| nbf > current_time) {
            return Err(bherror::Error::root(Error::TokenNotYetValid));
        }
        let claims = StatusListTokenClaims::new(
            issuer,
            claims.sub,
            claims.iat,
            claims.exp,
            claims.ttl,
            claims.status_list.decode()?,
        );
        Ok(Self {
            header,
            claims,
            signature: token::Verified,
        })
    }

    /// Returns the token header.
    pub fn header(&self) -> &StatusListTokenHeader {
        &self.header
    }

    /// Returns the token claims.
    pub fn claims(&self) -> &StatusListTokenClaims {
        &self.claims
    }
}

/// Header of the Status List Token in the JWT format.
#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub struct StatusListTokenHeader {
    /// An algorithm used to sign the token.
    pub alg: SigningAlgorithm,

    /// An optional ID of the private key used to sign the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// An optional X.509 certificate chain corresponding to the key used to
    /// sign the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<JwtX5Chain>,

    /// Type of the JWT, which is always _`statuslist+jwt`_.
    pub typ: String,

    #[serde(default, deserialize_with = "optional_claim", skip_serializing)]
    crit: Option<Vec<String>>,
    #[serde(default, deserialize_with = "optional_claim", skip_serializing)]
    b64: Option<bool>,
}

impl StatusListTokenHeader {
    /// Parses a Status List Token header without verifying the token
    /// signature.
    ///
    /// Use the `kid` and `x5c` values as key-resolution hints. Authorize the
    /// resolved key for the credential's Status List before calling
    /// [`StatusListToken::verify`] or [`crate::StatusListResponse::verify`].
    ///
    /// The header `typ` claim is still validated to ensure the token is a
    /// Status List Token.
    pub fn unverified_from_token(token: &str) -> Result<StatusListTokenHeader> {
        let token = parse_jwt_token_unverified::<IgnoredAny>(token)?;

        token.header().verify()?;

        let (header, _) = token.into();

        Ok(header)
    }

    fn verify(&self) -> Result<()> {
        if self.typ != STATUS_LIST_TOKEN_TYP {
            return Err(bherror::Error::root(Error::InvalidTokenHeaderTyp(
                self.typ.to_owned(),
            )));
        }

        if self.crit.is_some() || self.b64.is_some() {
            return Err(bherror::Error::root(Error::InvalidTokenHeader)
                .ctx("unsupported JOSE critical header or payload encoding"));
        }
        Ok(())
    }
}

impl jwt::JoseHeader for StatusListTokenHeader {
    fn algorithm_type(&self) -> jwt::AlgorithmType {
        self.alg.into()
    }
}

impl jwt::JoseHeader for &StatusListTokenHeader {
    fn algorithm_type(&self) -> jwt::AlgorithmType {
        jwt::JoseHeader::algorithm_type(*self)
    }
}

/// Claims of the Status List Token in the JWT format.
#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub struct StatusListTokenClaims {
    /// A unique identifier of the Issuer of the Status List Token.
    ///
    /// The issuer-bound verification API requires this to equal the
    /// credential's `iss` value.
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
    /// Issuer-bound verification requires the `iss` value to match the
    /// credential's issuer.
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
}

#[derive(Deserialize)]
struct JwtClaims<T> {
    #[serde(default, deserialize_with = "optional_claim")]
    iss: Option<String>,
    sub: UriBuf,
    iat: T,
    #[serde(default, deserialize_with = "optional_claim")]
    exp: Option<T>,
    #[serde(default, deserialize_with = "optional_claim")]
    nbf: Option<T>,
    #[serde(default, deserialize_with = "optional_claim")]
    ttl: Option<u64>,
    #[serde(rename = "jti", default, deserialize_with = "optional_claim")]
    _jwt_id: Option<String>,
    #[serde(rename = "aud", default, deserialize_with = "claim_present")]
    audience_present: bool,
    status_list: EncodedStatusList,
}

fn optional_claim<'de, T: Deserialize<'de>, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

fn claim_present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<bool, D::Error> {
    IgnoredAny::deserialize(deserializer)?;
    Ok(true)
}

impl<T> JwtClaims<T> {
    fn validate(&self, sub: &Uri) -> Result<()> {
        validate_subject(&self.sub, sub)?;
        validate_optional_claims(self.iss.as_deref(), self.ttl, self.audience_present)
    }
}

/// A parsed JWT or CWT Status List Token awaiting signature verification.
///
/// Use the header as a hint to resolve an authorized signing key. Then call
/// [`Self::verify`] on the same token.
pub struct UnverifiedStatusListToken<'a>(ParsedStatusListToken<'a>);

enum ParsedStatusListToken<'a> {
    Jwt(jwt::Token<StatusListTokenHeader, JwtClaims<f64>, jwt::token::Unverified<'a>>),
    Cwt(CwtStatusListToken),
}

impl<'a> UnverifiedStatusListToken<'a> {
    pub(crate) fn parse(response: &'a StatusListResponse) -> Result<Self> {
        match response {
            StatusListResponse::Jwt(token) => {
                let token = parse_jwt_token_unverified(token)?;
                token.header().verify()?;
                Ok(Self(ParsedStatusListToken::Jwt(token)))
            }
            StatusListResponse::Cwt(token) => Ok(Self(ParsedStatusListToken::Cwt(
                CwtStatusListToken::parse(token)?,
            ))),
        }
    }

    /// Returns the signature algorithm advertised by the token.
    pub fn algorithm(&self) -> SigningAlgorithm {
        match &self.0 {
            ParsedStatusListToken::Jwt(token) => token.header().alg,
            ParsedStatusListToken::Cwt(token) => token.algorithm(),
        }
    }

    /// Returns the key ID as bytes, using UTF-8 for JWT key IDs.
    pub fn key_id(&self) -> Option<&[u8]> {
        match &self.0 {
            ParsedStatusListToken::Jwt(token) => token.header().kid.as_deref().map(str::as_bytes),
            ParsedStatusListToken::Cwt(token) => token.key_id(),
        }
    }

    /// Returns the JWT header when the response carries a JWT.
    ///
    /// The header exposes the optional `x5c` certificate chain.
    pub fn jwt_header(&self) -> Option<&StatusListTokenHeader> {
        match &self.0 {
            ParsedStatusListToken::Jwt(token) => Some(token.header()),
            ParsedStatusListToken::Cwt(_) => None,
        }
    }

    /// Returns the parsed CWT when the response carries a CWT.
    ///
    /// Use [`CwtStatusListToken::x5chain`] to access any certificate bytes.
    pub fn cwt_token(&self) -> Option<&CwtStatusListToken> {
        match &self.0 {
            ParsedStatusListToken::Jwt(_) => None,
            ParsedStatusListToken::Cwt(token) => Some(token),
        }
    }

    /// Verifies this token against the list URI from the verified credential.
    ///
    /// Supply an authorized key, a verifier for an allowed algorithm, and
    /// the current Unix time in seconds. See [`StatusListResponse::verify`]
    /// for the shared verification rules.
    pub fn verify(
        self,
        verifier: &(impl SignatureVerifier + ?Sized),
        public_key: &JwkPublic,
        current_time: u64,
        uri: &Uri,
    ) -> Result<VerifiedStatusList> {
        match self.0 {
            ParsedStatusListToken::Jwt(token) => {
                let verified = verify_jwt_token(token, verifier, public_key)?;
                let (_, claims) = verified.into();
                claims.validate(uri)?;
                validate_numeric_dates(current_time, claims.iat, claims.exp, claims.nbf)?;
                Ok(VerifiedStatusList {
                    iss: claims.iss,
                    sub: claims.sub,
                    iat: claims.iat,
                    exp: claims.exp,
                    ttl: claims.ttl,
                    status_list: claims.status_list.decode()?,
                })
            }
            ParsedStatusListToken::Cwt(token) => {
                token.verify(verifier, public_key, current_time, uri)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use bh_jws_utils::{
        json_object, BoxError,
        SigningAlgorithm::{self, *},
    };
    use bhx5chain::JwtX5Chain;

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
        let status_list = StatusListInternal::new(StatusBits::Eight, None);

        let claims = StatusListTokenClaims::new(iss, sub, 100, exp, None, status_list.into());

        let token_signed = StatusListToken::new(
            claims,
            Some("kid".to_owned()),
            Some(JwtX5Chain::dummy()),
            &DummySigner(alg, true),
        )
        .unwrap();

        token_signed.to_string()
    }

    #[test]
    fn test_status_list_token_signing_fails() {
        let status_list = StatusListInternal::new(StatusBits::Eight, None);

        let claims = StatusListTokenClaims::new(
            str_to_uri("http://iss"),
            str_to_uri("http://sub"),
            100,
            None,
            None,
            status_list.into(),
        );

        let err = StatusListToken::new(
            claims,
            Some("kid".to_owned()),
            None,
            &DummySigner(Es512, false),
        )
        .err()
        .unwrap();

        assert!(matches!(err.error, Error::TokenSigningFailed));
    }

    #[test]
    fn test_status_list_token_new_success() {
        let status_list = StatusListInternal::new(StatusBits::Two, None);

        let claims = StatusListTokenClaims::new(
            str_to_uri("http://iss"),
            str_to_uri("http://sub"),
            100,
            None,
            None,
            status_list.into(),
        );

        let _token = StatusListToken::new(
            claims,
            Some("kid".to_owned()),
            None,
            &DummySigner(Es256, true),
        )
        .unwrap();
    }

    #[test]
    fn test_status_list_token_new_without_kid_success() {
        let status_list = StatusListInternal::new(StatusBits::Two, None);

        let claims = StatusListTokenClaims::new(
            str_to_uri("http://iss"),
            str_to_uri("http://sub"),
            100,
            None,
            None,
            status_list.into(),
        );

        let _token = StatusListToken::new(claims, None, None, &DummySigner(Es256, true)).unwrap();
    }

    #[test]
    fn test_status_list_token_new_with_x5c_success() {
        let status_list = StatusListInternal::new(StatusBits::Two, None);

        let claims = StatusListTokenClaims::new(
            str_to_uri("http://iss"),
            str_to_uri("http://sub"),
            100,
            None,
            None,
            status_list.into(),
        );

        let _token = StatusListToken::new(
            claims,
            Some("kid".to_owned()),
            Some(JwtX5Chain::dummy()),
            &DummySigner(Es256, true),
        )
        .unwrap();
    }

    #[test]
    fn test_status_list_token_verify_success() {
        let status_list = StatusListInternal::new(StatusBits::One, None);

        let iss = str_to_uri("http://iss");
        let sub = str_to_uri("http://sub");
        let iat = 100;

        let claims = StatusListTokenClaims::new(
            iss.clone(),
            sub.clone(),
            iat,
            None,
            None,
            status_list.into(),
        );

        let jwt_x5chain = JwtX5Chain::dummy();
        let token_signed = StatusListToken::new(
            claims,
            Some("kid".to_owned()),
            Some(jwt_x5chain.clone()),
            &DummySigner(Es512, true),
        )
        .unwrap();

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
        assert_eq!(header.kid, Some("kid".to_owned()));
        assert_eq!(header.x5c, Some(jwt_x5chain));
        assert_eq!(header.typ, STATUS_LIST_TOKEN_TYP);

        assert_eq!(claims.iss, iss);
        assert_eq!(claims.sub, sub);
        assert_eq!(claims.iat, iat);
    }

    #[test]
    fn test_status_list_token_parse_unverified_header_success() {
        let jwt = get_valid_jwt(
            Es256,
            str_to_uri("http://iss"),
            str_to_uri("http://sub"),
            None,
        );

        let header = StatusListTokenHeader::unverified_from_token(&jwt).unwrap();

        assert_eq!(header.alg, Es256);
        assert_eq!(header.kid, Some("kid".to_owned()));
        assert_eq!(header.x5c, Some(JwtX5Chain::dummy()));
        assert_eq!(header.typ, STATUS_LIST_TOKEN_TYP);
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
    fn test_status_list_token_parse_unverified_header_invalid_typ_fails() {
        let status_list = StatusListInternal::new(StatusBits::Eight, None);
        let claims = StatusListTokenClaims::new(
            str_to_uri("http://iss"),
            str_to_uri("http://sub"),
            100,
            None,
            None,
            status_list.into(),
        );
        let header = StatusListTokenHeader {
            alg: Es256,
            kid: Some("kid".to_owned()),
            x5c: None,
            typ: "not-status-list".to_owned(),
            crit: None,
            b64: None,
        };
        let jwt = sign_jwt_token(&header, &claims, &DummySigner(Es256, true)).unwrap();

        let err = StatusListTokenHeader::unverified_from_token(&jwt)
            .err()
            .unwrap();

        assert!(matches!(err.error, Error::InvalidTokenHeaderTyp(typ) if typ == "not-status-list"));
    }

    #[test]
    fn test_status_list_token_verify_invalid_alg_fails() {
        let iss = str_to_uri("http://iss");
        let sub = str_to_uri("http://sub");

        let jwt = get_valid_jwt(Ps512, iss.clone(), sub.clone(), None);

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

        let jwt = get_valid_jwt(Ps384, iss.clone(), sub.clone(), None);

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

        let jwt = get_valid_jwt(Ps384, iss.clone(), sub.clone(), None);

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

        let jwt = get_valid_jwt(Es512, iss_invalid.clone(), sub.clone(), None);

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

        let jwt = get_valid_jwt(Es256, iss.clone(), sub_invalid.clone(), None);

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

    #[test]
    fn verifies_jwt_without_iss_and_rejects_expiration_boundary() {
        use bh_jws_utils::{Es256Signer, Es256Verifier};
        use serde_json::json;

        let sub = str_to_uri("https://example.com/statuslists/1");
        let claims = json!({
            "sub": sub.as_str(),
            "iat": 100,
            "exp": 200,
            "status_list": { "bits": 1, "lst": "eNrbuRgAAhcBXQ" },
        });
        let signer = Es256Signer::generate("test".into()).unwrap();
        let key = signer.public_jwk().unwrap();
        let header = StatusListTokenHeader {
            alg: Es256,
            kid: Some("test".into()),
            x5c: None,
            typ: STATUS_LIST_TOKEN_TYP.to_owned(),
            crit: None,
            b64: None,
        };
        let jwt: jwt::Token<_, _, token::Signed> =
            signer.sign_jwt(jwt::Token::new(header, claims)).unwrap();
        let response = crate::StatusListResponse::Jwt(jwt.into());
        let token = response.parse().unwrap();
        assert_eq!(token.algorithm(), Es256);
        assert_eq!(token.key_id(), Some(b"test".as_slice()));
        assert_eq!(token.jwt_header().unwrap().typ, STATUS_LIST_TOKEN_TYP);
        assert!(token.cwt_token().is_none());
        let verified = token.verify(&Es256Verifier, &key, 199, &sub).unwrap();
        assert_eq!(verified.issuer(), None);
        assert_eq!(verified.status_list().lst(), &[0xb9, 0xa3]);
        let error = response
            .verify(&Es256Verifier, &key, 200, &sub)
            .unwrap_err();
        assert!(matches!(error.error, Error::TokenExpired(200, 200)));
    }
}

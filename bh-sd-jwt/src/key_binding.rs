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

use bh_jws_utils::{
    jwt, JwkPublic, JwtSigner, JwtVerifier as _, SignatureVerifier, SigningAlgorithm,
};
use bherror::{
    traits::{ForeignBoxed, ForeignError, PropagateError},
    Error,
};
use jwt::claims::SecondsSinceEpoch;
use serde::{Deserialize, Serialize};

use crate::{
    holder::{HolderError, Result as HolderResult},
    sd_jwt::{SdJwt, SdJwtKB, SD_JWT_DELIMITER},
    utils,
    verifier::{Result as VerifierResult, VerifierError},
    Hasher, Result,
};

/// Error type related to Key Binding `JWT` operations.
#[derive(strum_macros::Display, PartialEq, Debug, Clone)]
pub enum KBError {
    /// Error representing a missing key binding in the `SD-JWT`.
    #[strum(to_string = "Missing key binding")]
    MissingKeyBinding,

    /// Error when the Key Binding JWT syntax is invalid.
    #[strum(to_string = "Invalid KBJwt syntax: {0}")]
    InvalidKBJwtSyntax(String),

    /// Error when the Key Binding JWT signature is invalid.
    #[strum(to_string = "Invalid KBJwt signature")]
    InvalidKBJwtSignature,

    /// Error when the Key Binding JWT `typ` field is not set to the expected
    /// value.
    #[strum(to_string = "Invalid KBJwt type {0}")]
    InvalidKBJwtType(String),

    /// Error when the Key Binding JWT is expired.
    #[strum(to_string = "KBJwt expired: iat is {0}, expiration offset {1} and current time {2}")]
    KBJwtExpired(u64, u64, u64),

    /// Error when the Key Binding JWT nonce is invalid.
    #[strum(to_string = "Invalid KBJwt nonce. Provided nonce was {0}")]
    InvalidKBJwtNonce(String),

    /// Error when the Key Binding JWT `aud` field is invalid.
    #[strum(to_string = "Invalid KBJwt aud. Provided aud was `{0}`; expected `{1}`")]
    InvalidKBJwtAud(String, String),

    /// Error when the Key Binding JWT `sd_hash` field is the wrong value.
    #[strum(to_string = "Invalid KBJwt hash. Claims hash was {0}, provided was {1}")]
    InvalidKBJwtSdHash(String, String),

    /// Error when the provided signing algorithm does not have a signature
    /// verifier implementation.
    #[strum(to_string = "Missing signature verifier: {0}")]
    MissingSignatureVerifier(SigningAlgorithm),
}

impl bherror::BhError for KBError {}

/// The required value of the Key Binding `JWT` header `typ` element, as
/// specified [here].
///
/// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.3-3.1.2.1
pub(crate) const KB_JWT_HEADER_TYP: &str = "kb+jwt";

/// A maximum difference of the time when the Key Binding `JWT` was received by
/// the Verifier and the time when it was created by the Holder, expressed in
/// seconds.
///
/// The current default is set to 5 minutes.
// TODO(issues/51)
pub(crate) const KB_JWT_EXPIRATION_OFFSET: SecondsSinceEpoch = 5 * 60;

/// Header of the Key Binding `JWT`, as specified [here].
///
/// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.3-3.1.1
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub(crate) struct KBJwtHeader {
    /// The Key Binding `JWT` type. The value of this attribute **MUST** always
    /// be `kb+jwt`, as specified [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.3-3.1.2.1
    pub(crate) typ: String,

    /// A digital signature algorithm identifier, as specified [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.3-3.1.2.2
    pub(crate) alg: SigningAlgorithm,
}

impl KBJwtHeader {
    /// Constructs and returns a new Key Binding `JWT` header from the provided
    /// [`SigningAlgorithm`](crate::traits::SigningAlgorithm).
    ///
    /// The `typ` attribute is always set to [`KB_JWT_HEADER_TYP`].
    pub(crate) fn new(alg: SigningAlgorithm) -> Self {
        Self {
            typ: KB_JWT_HEADER_TYP.to_owned(),
            alg,
        }
    }
}

impl jwt::JoseHeader for KBJwtHeader {
    fn algorithm_type(&self) -> jwt::AlgorithmType {
        self.alg.into()
    }
}

/// Claims of the Key Binding `JWT`, as specified [here].
///
/// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.3-3.2.1
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub(crate) struct KBJwtClaims {
    /// The time at which the Key Binding `JWT` was issued, as specified [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.3-3.2.2.1
    pub(crate) iat: SecondsSinceEpoch,

    /// The intended receiver of the Key Binding `JWT`, as specified [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.3-3.2.2.2
    /// See also: [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3)
    pub(crate) aud: String,

    /// A value used to ensure the freshness of the signature, as specified
    /// [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.3-3.2.2.3
    pub(crate) nonce: String,

    /// The `base64url`-encoded hash digest over the Issuer-signed `JWT` and the
    /// selected disclosures, as specified [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.3-3.2.2.4
    pub(crate) sd_hash: String,
}

impl KBJwtClaims {
    /// Constructs a new Key Binding `JWT` from its parameters.
    ///
    /// The `aud` field is created to hold only a single value provided within
    /// the [`KeyBindingChallenge`].
    pub(crate) fn new(
        challenge: KeyBindingChallenge,
        current_time: SecondsSinceEpoch,
        sd_hash: String,
    ) -> Self {
        Self {
            iat: current_time,
            aud: challenge.aud,
            nonce: challenge.nonce,
            sd_hash,
        }
    }
}

/// The challenge to be sent to the holder. The purpose of the
/// challenge is to ensure the freshness of the key binding signature, as
/// well as the proper audience.
#[derive(Debug, Clone)]
pub struct KeyBindingChallenge {
    /// The intended receiver of the Key Binding `JWT`, as specified [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.3-3.2.2.2
    /// See also: [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3)
    pub aud: String,
    /// A value used to ensure the freshness of the signature, as specified
    /// [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.3-3.2.2.3
    pub nonce: String,
}

pub(crate) struct KBJwt<Status>(jwt::Token<KBJwtHeader, KBJwtClaims, Status>);

type KBJwtUnverified<'a> = jwt::Token<KBJwtHeader, KBJwtClaims, jwt::Unverified<'a>>;

impl<Status> KBJwt<Status> {
    pub(crate) fn header(&self) -> &KBJwtHeader {
        self.0.header()
    }

    pub(crate) fn claims(&self) -> &KBJwtClaims {
        self.0.claims()
    }
}

impl KBJwt<jwt::token::Signed> {
    /// Creates a new **signed** Key Binding `JWT` based on its claims, using
    /// the provided [`Signer`] implementation to sign the payload.
    pub(crate) fn new(claims: KBJwtClaims, signer: &impl JwtSigner) -> HolderResult<Self> {
        let header = KBJwtHeader::new(signer.algorithm());

        let token_unsigned = jwt::Token::new(header, claims);
        let token_signed = signer
            .sign_jwt(token_unsigned)
            .foreign_boxed_err(|| HolderError::KBJwtSigningFailed)?;

        Ok(KBJwt(token_signed))
    }

    /// Returns the `String` representation of the underlying **signed** `JWT`,
    /// consuming `self`.
    pub(crate) fn into_string(self) -> String {
        self.0.into()
    }
}

impl KBJwt<jwt::token::Verified> {
    /// Parses and verifies a Key Binding `JWT` by verifying the signature
    /// against the provided `holder_public_key` and using the given
    /// [`Verifier`], and validating its header and claims.
    pub(crate) fn validate<'a>(
        kb_jwt: &str,
        holder_public_key: &JwkPublic,
        get_signature_verifier: impl FnOnce(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
        challenge: &KeyBindingChallenge,
        current_time: SecondsSinceEpoch,
        sd_hash: &str,
    ) -> Result<Self, KBError> {
        // !!! Start of direct access to not-yet-integrity-verified fields
        let (token_unverified, verifier) =
            Self::get_signature_verifier(kb_jwt, get_signature_verifier)?;
        // !!! End of direct access to not-yet-integrity-verified fields

        let token_verified = verifier
            .verify_jwt_signature(token_unverified, holder_public_key)
            .foreign_boxed_err(|| KBError::InvalidKBJwtSignature)?;

        let jwt = Self(token_verified);

        jwt.validate_header()?;

        jwt.validate_claims(challenge, current_time, sd_hash)?;

        Ok(jwt)
    }

    /// Directly access not-yet-integrity-verified fields in order to look up the
    /// signature verifier implementation.
    ///
    /// This is sound because:
    ///
    /// - The signature verifier implementations are all for known and
    ///   known-secure asymmetric signature algorithms, i.e. there is no
    ///   possibility of e.g. `alg: none`.
    ///   At worst the attacker could:
    ///
    ///   - point us to a different secure algorithm which doesn't correspond
    ///     to the public key's and will as such result in a verification error
    ///     within `verify_with_key`.
    fn get_signature_verifier<'a>(
        kb_jwt: &str,
        get_signature_verifier: impl FnOnce(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
    ) -> Result<(KBJwtUnverified<'_>, &'a dyn SignatureVerifier), KBError> {
        // Despite the documentation of `jwt::Token::parse_unverified`
        // (rightfully) not recommending using it (to prevent reading the
        // contents without prior verification), we need to do this in order to
        // get access to the header's `alg` claim which we will need for
        // the verifier implementation lookup.

        let token_unverified: KBJwtUnverified = jwt::Token::parse_unverified(kb_jwt)
            .foreign_err(|| KBError::InvalidKBJwtSyntax(kb_jwt.to_string()))?;

        let signing_algorithm = token_unverified.header().alg;
        let verifier = get_signature_verifier(signing_algorithm)
            .ok_or_else(|| Error::root(KBError::MissingSignatureVerifier(signing_algorithm)))?;

        Ok((token_unverified, verifier))
    }

    /// Validates the Key Binding `JWT` header.
    ///
    /// The header is valid if its `typ` field is set to `kb+jwt`.
    fn validate_header(&self) -> Result<(), KBError> {
        let header = self.header();

        // check that `typ` is equal to `KB_JWT_HEADER_TYP`
        if header.typ != KB_JWT_HEADER_TYP {
            return Err(Error::root(KBError::InvalidKBJwtType(header.typ.clone())));
        }

        Ok(())
    }

    /// Validates the Key Binding `JWT` claims.
    ///
    /// The following validation steps are performed:
    ///   - `iat`: the creation time of the Key Binding `JWT` needs to be within
    ///     an acceptable time window,
    ///   - `nonce`: it needs to be the same as the one from the `challenge`,
    ///   - `aud`: it needs to contain the value from the `challenge`,
    ///   - `sd_hash`: it needs to be the same as the computed `sd_hash` value.
    fn validate_claims(
        &self,
        challenge: &KeyBindingChallenge,
        current_time: SecondsSinceEpoch,
        sd_hash: &str,
    ) -> Result<(), KBError> {
        let claims = self.claims();

        // check that `iat` >= `current_time` - `KB_JWT_EXPIRATION_OFFSET`
        if claims.iat + KB_JWT_EXPIRATION_OFFSET < current_time {
            return Err(Error::root(KBError::KBJwtExpired(
                claims.iat,
                KB_JWT_EXPIRATION_OFFSET,
                current_time,
            )));
        }

        // check that `nonce` is equal to the one from the `challenge`
        if claims.nonce != challenge.nonce {
            return Err(Error::root(KBError::InvalidKBJwtNonce(
                claims.nonce.clone(),
            )));
        }

        // check that `aud` contains the `aud` from the challenge
        if claims.aud != challenge.aud {
            return Err(Error::root(KBError::InvalidKBJwtAud(
                claims.aud.clone(),
                challenge.aud.clone(),
            )));
        }

        // check that `sd_hash` is equal to the one provided
        if claims.sd_hash != sd_hash {
            return Err(Error::root(KBError::InvalidKBJwtSdHash(
                claims.sd_hash.clone(),
                sd_hash.to_string(),
            )));
        }

        Ok(())
    }
}

impl SdJwt {
    /// Constructs and signs the Key Binding `JWT`.
    ///
    /// The `sd_hash` claim of the Key Binding `JWT` is generated by computing
    /// the `base64url`-encoded hash digest over the Issuer-signed `JWT` and the
    /// selected disclosures, as defined [here].
    ///
    /// # Note
    /// The provided `hasher` **MUST** use the same algorithm that was used to
    /// hide the claims of the `SD-JWT`.
    ///
    /// # Errors
    /// An error will be returned if the computation of the Key Binding `JWT` signature fails.
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#name-integrity-protection-of-the
    pub(crate) fn calc_key_binding_jwt(
        &self,
        hasher: impl Hasher,
        challenge: KeyBindingChallenge,
        current_time: SecondsSinceEpoch,
        signer: &impl JwtSigner,
    ) -> HolderResult<String> {
        let sd_hash = sd_hash(self, hasher);
        let claims = KBJwtClaims::new(challenge, current_time, sd_hash);

        let signed_kb_jwt = KBJwt::<jwt::token::Signed>::new(claims, signer)?;

        Ok(signed_kb_jwt.into_string())
    }

    /// Constructs, signs and adds the Key Binding JWT to this `SD-JWT`, resulting
    /// in a `SD-JWT+KB`.
    pub(crate) fn add_key_binding_jwt(
        self,
        hasher: impl Hasher,
        challenge: KeyBindingChallenge,
        current_time: SecondsSinceEpoch,
        signer: &impl JwtSigner,
    ) -> HolderResult<SdJwtKB> {
        let key_binding_jwt = self.calc_key_binding_jwt(hasher, challenge, current_time, signer)?;

        Ok(SdJwtKB {
            sd_jwt: self,
            key_binding_jwt,
        })
    }
}

impl SdJwtKB {
    /// Verifies a Key Binding `JWT` against the provided `holder_public_key`
    /// and [`KeyBindingChallenge`], according to the [official documentation],
    /// using the [`SignatureVerifier`] implementation looked up from the provided
    /// callback.
    ///
    /// # Notes
    /// The provided `hasher` **MUST** use the same algorithm that was used to
    /// hide the claims of the `SD-JWT`.
    ///
    /// The signing algorithm has not been verified to comply with the security
    /// standards of the `SD-JWT` specification, but it should not be necessary
    /// because it is already one of the
    /// [`SigningAlgorithm`](crate::SigningAlgorithm) variants, that are all
    /// deemed secure.
    ///
    /// # Errors
    /// An error will be returned if the Key Binding `JWT` is not present,
    /// if its verification fails, or there is no available verifier for that algorithm.
    ///
    /// [official documentation]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-8.3-4.3.1
    pub(crate) fn verify_key_binding_jwt<'a>(
        &self,
        hasher: impl Hasher,
        holder_public_key: &JwkPublic,
        challenge: &KeyBindingChallenge,
        current_time: SecondsSinceEpoch,
        get_signature_verifier: impl FnOnce(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
    ) -> VerifierResult<KBJwt<jwt::token::Verified>> {
        let kb_jwt = &self.key_binding_jwt;

        let sd_hash = sd_hash(&self.sd_jwt, hasher);

        let verified = KBJwt::<jwt::token::Verified>::validate(
            kb_jwt,
            holder_public_key,
            get_signature_verifier,
            challenge,
            current_time,
            &sd_hash,
        )
        .match_err(|kb_error| VerifierError::KeyBinding(kb_error.clone()))?;

        Ok(verified)
    }
}

/// Generates a payload for the Key Binding `JWT` `sd_hash` value of the provided `SD-JWT`
///
/// It is generated by concatenating the Issuer-signed `JWT` followed by a
/// `~` character and the list of disclosures, each followed by a `~`
/// character.
fn sd_hash_payload(sd_jwt: &SdJwt) -> String {
    let mut payload = String::new();

    payload += &sd_jwt.jwt;
    payload += SD_JWT_DELIMITER;

    for disclosure in &sd_jwt.disclosures {
        payload += disclosure;
        payload += SD_JWT_DELIMITER;
    }

    payload
}

/// Computes a `sd_hash` value of the provided `SD_JWT` using the provided `Hasher`,
/// as a `base64url`-encoded hash digest of the payload.
fn sd_hash(sd_jwt: &SdJwt, hasher: impl Hasher) -> String {
    utils::base64_url_digest(sd_hash_payload(sd_jwt).as_bytes(), hasher)
}

// TODO(issues/52) unit tests

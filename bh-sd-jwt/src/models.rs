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

use bh_jws_utils::{jwt, JwkPublic, JwtVerifier as _, SignatureVerifier, SigningAlgorithm};
use bherror::{
    traits::{ForeignBoxed, ForeignError, PropagateError},
    Error,
};
pub use iref::Uri;
pub use jwt::claims::SecondsSinceEpoch;
use serde::{Deserialize, Serialize};
pub use serde_json::{Map, Value};
use yoke::Yoke;

use crate::error::{FormatError, Result, SignatureError};
mod disclosure;
mod error;
mod path;
pub(crate) mod path_map;

pub use disclosure::*;
pub(crate) use error::*;
pub use path::*;

use crate::{
    utils::SD_ALG_FIELD_NAME, Hasher, HashingAlgorithm, IssuerJwt, IssuerJwtHeader,
    IssuerPublicKeyLookup,
};

/// The `cnf` claim of the SD-JWT, containing the public key to bind with the credential.
///
/// See the [draft] and [RFC7800] for details.
///
/// [draft]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-08#section-5.1.2
/// [RFC7800]: https://www.rfc-editor.org/rfc/rfc7800.html#section-3
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CnfClaim {
    /// Public key bound to the credential.
    pub jwk: JwkPublic,
}

/// A JSON object, i.e. a mapping from [`String`] to [`Value`].
pub type JsonObject = Map<String, Value>;

/// Panics if the argument is not a JSON object.
#[inline(always)]
pub(crate) fn into_object(value: Value) -> JsonObject {
    if let Value::Object(object) = value {
        object
    } else {
        panic!("Argument wasn't an object")
    }
}

/// Helper macro with the same syntax as [`serde_json::json`] specialized for
/// constructing JSON objects.
///
/// It will construct a more specific type ([`serde_json::Map<String,Value>`])
/// than just [`serde_json::Value`] when constructing an object, and panic if
/// the syntax is valid JSON but not an object.
#[macro_export]
macro_rules! json_object {
    ($stuff:tt) => {
        match ::serde_json::json!($stuff) {
            ::serde_json::Value::Object(o) => o,
            _ => unreachable!("JSON literal wasn't an object"),
        }
    };
}

pub(crate) const SD: &str = "_sd";
pub(crate) const ELLIPSIS: &str = "...";
pub(crate) static RESERVED_CLAIM_NAMES: &[&str] = &[SD, SD_ALG_FIELD_NAME, ELLIPSIS];

/// SD-JWT in parsed form for the issuance flow.
pub(crate) struct ParsedSdJwtIssuance<State> {
    pub(crate) jwt: jwt::Token<IssuerJwtHeader, IssuerJwt, State>,
    pub(crate) disclosures: Vec<Disclosure>,
}

/// SD-JWT in parsed form created by the issuer to be handed to the holder.
#[cfg_attr(test, derive(Debug))]
pub struct IssuedSdJwt(pub(crate) ParsedSdJwtIssuance<jwt::token::Signed>);

impl IssuedSdJwt {
    /// Serialize the issued SD-JWT into the Compact Serialization format.
    pub fn into_string_compact(self) -> String {
        crate::SdJwt::new(
            self.0.jwt.into(),
            self.0
                .disclosures
                .into_iter()
                .map(Disclosure::into_string)
                .collect(),
        )
        .to_string()
    }
}

/// SD-JWT (in parsed form), but not yet validated in any other way.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct SdJwtUnverified<'a>(pub(crate) ParsedSdJwtIssuance<jwt::Unverified<'a>>);

impl SdJwtUnverified<'_> {
    pub(crate) async fn verify<'a>(
        self,
        issuer_public_key_lookup: &impl IssuerPublicKeyLookup,
        get_signature_verifier: impl FnOnce(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
    ) -> Result<(SdJwtSignatureVerified, SigningAlgorithm, JwkPublic), SignatureError> {
        // !!! Start of direct access to not-yet-integrity-verified fields
        let (verifier, alg, key) = self
            .get_signature_verifier_and_public_key(issuer_public_key_lookup, get_signature_verifier)
            .await?;
        // !!! End of direct access to not-yet-integrity-verified fields

        let unverified_jwt = self.0.jwt;
        let jwt = verifier
            .verify_jwt_signature(unverified_jwt, &key)
            .foreign_boxed_err(|| SignatureError::InvalidJwtSignature)?;

        let disclosures = self.0.disclosures;

        Ok((
            SdJwtSignatureVerified(ParsedSdJwtIssuance { jwt, disclosures }),
            alg,
            key,
        ))
    }

    /// Directly access not-yet-integrity-verified fields in order to look up the
    /// public key and signature verifier implementation.
    ///
    /// This is sound because:
    ///
    /// - The issuer public key lookup implementation must be (by contract) such that it only
    ///   obtains public keys from trusted sources, so an attacker cannot point us to completely
    ///   arbitrary public keys, but only those whose corresponding private keys are deemed not
    ///   under control of attackers;
    ///
    /// - The signature verifier implementations are all for known and
    ///   known-secure asymmetric signature algorithms, i.e. there is no
    ///   possibility of e.g. `alg: none`.
    ///   At worst the attacker could:
    ///
    ///   - point us to a different secure algorithm which doesn't correspond
    ///     to the public key's and will as such result in a verification error
    ///     within `verify_with_key`, or
    ///
    ///   - point us to an algorithm which does match a _different_ (but still trusted)
    ///     public key, using which the signature will not verify correctly for reasons
    ///     mentioned above.
    async fn get_signature_verifier_and_public_key<'a>(
        &self,
        issuer_public_key_lookup: &impl IssuerPublicKeyLookup,
        get_signature_verifier: impl FnOnce(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
    ) -> Result<(&'a dyn SignatureVerifier, SigningAlgorithm, JwkPublic), SignatureError> {
        let key = issuer_public_key_lookup
            .lookup(&self.0.jwt.claims().iss, self.0.jwt.header())
            .await
            .with_err(|| SignatureError::PublicKeyLookupFailed)?;

        let alleged_signing_algorithm = self.0.jwt.header().alg;
        let verifier = get_signature_verifier(alleged_signing_algorithm).ok_or_else(|| {
            Error::root(SignatureError::MissingSignatureVerifier(
                alleged_signing_algorithm,
            ))
        })?;

        Ok((verifier, alleged_signing_algorithm, key))
    }
}

impl crate::SdJwt {
    /// Further parse the SD-JWT's JWT and disclosures into a to-be-verified form.
    pub(crate) fn parse(&self) -> Result<SdJwtUnverified<'_>, FormatError> {
        // Despite the documentation of `jwt::Token::parse_unverified`
        // (rightfully) not recommending using it (to prevent reading the
        // contents without prior verification), we need to do this in order to
        // get access to the header and the `iss` claim which we will need for
        // the public key lookup.

        // NB: this call wants to borrow the jwt, rather than own it, while
        // `SdJwt` takes ownership over the string it is parsed from, which is
        // why this whole fn exists as a `&self` method on `SdJwt` rather than a
        // `from_str` method on `IssuedSdJwtUnverified` so that the jwt string
        // remains on the stack when calling this whole fn. Prehaps this could be
        // fixed by making `SdJwt` generic over ownership/borrowing (e.g. via `Cow`)?
        let jwt =
            jwt::Token::parse_unverified(&self.jwt).foreign_err(|| FormatError::NonParseableJwt)?;

        let disclosures = self
            .disclosures
            .iter()
            .cloned()
            .map(Disclosure::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(SdJwtUnverified(ParsedSdJwtIssuance { jwt, disclosures }))
    }

    pub(crate) async fn to_signature_verified_sd_jwt<'a>(
        &self,
        issuer_public_key_lookup: &impl IssuerPublicKeyLookup,
        get_signature_verifier: impl FnOnce(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
    ) -> Result<(SdJwtSignatureVerified, SigningAlgorithm, JwkPublic), crate::Error> {
        self.parse()
            .match_err(|format_error| crate::Error::Format(format_error.clone()))?
            .verify(issuer_public_key_lookup, get_signature_verifier)
            .await
            .match_err(|signature_error| crate::Error::Signature(signature_error.clone()))
    }
}

/// The SD-JWT (in parsed form) verified against the issuer's public key, but not otherwise.
///
/// NB: keep the field private to this module to enforce correctness-by-construction!
pub(crate) struct SdJwtSignatureVerified(ParsedSdJwtIssuance<jwt::Verified>);

impl SdJwtSignatureVerified {
    /// Decode the SD-JWT, reconstructing the original payload.
    ///
    /// CAUTION: do not expose or kb checks could be circumvented
    pub(crate) fn into_decoded(
        self,
        get_hasher: impl Fn(HashingAlgorithm) -> Option<Box<dyn Hasher>>,
    ) -> Result<SdJwtDecoded, crate::Error> {
        SdJwtDecoded::new(self, get_hasher)
    }
}

/// The SD-JWT (in parsed form) fully decoded and verified except for key binding.
///
/// NB: keep the fields private to this module to enforce correctness-by-construction!
pub(crate) struct SdJwtDecoded {
    decoded_claims: IssuerJwt,
    disclosures_by_path: Yoke<DisclosureByPathTable<'static>, Vec<Disclosure>>,
    hasher: Box<dyn Hasher>,
}

impl SdJwtDecoded {
    pub(crate) fn new(
        verified_sd_jwt: SdJwtSignatureVerified,
        get_hasher: impl Fn(HashingAlgorithm) -> Option<Box<dyn Hasher>>,
    ) -> Result<Self, crate::Error> {
        let ParsedSdJwtIssuance { jwt, disclosures } = verified_sd_jwt.0;
        // Put the whole payload into the decoder to automatically handle
        // duplicate keys hidden in disclosures in the root object.
        // TODO this could be optimized to not deep copy the whole claims during `to_object`
        let full_payload = jwt.claims().to_object();

        let mut owned_output = None;

        // Let the constructed map borrow from the disclosure Vec
        let disclosures_by_path = Yoke::try_attach_to_cart(disclosures, |disclosures| {
            let (decoded_claims, hasher, disclosures_by_path) =
                crate::decoder::decode_disclosed_claims(&full_payload, disclosures, get_hasher)
                    .match_err(|err| crate::Error::Decoding(err.clone()))?;

            owned_output = Some((decoded_claims, hasher));

            Ok(disclosures_by_path)
        })?;

        let (decoded_claims, hasher) = owned_output.unwrap();

        let decoded_claims = serde_json::from_value(decoded_claims.into())
            .foreign_err(|| crate::Error::Format(FormatError::InvalidVcSchema))?;

        Ok(Self {
            decoded_claims,
            disclosures_by_path,
            hasher,
        })
    }

    /// Pre-computed map from disclosure path in the reconstructed model to disclosure
    pub(crate) fn disclosures_by_path(&self) -> &DisclosureByPathTable<'_> {
        self.disclosures_by_path.get()
    }

    pub(crate) fn claims(&self) -> &IssuerJwt {
        &self.decoded_claims
    }

    pub(crate) fn into_claims(self) -> IssuerJwt {
        self.decoded_claims
    }

    pub(crate) fn key_binding_public_key(&self) -> &JwkPublic {
        &self.decoded_claims.cnf.jwk
    }

    pub(crate) fn hasher(&self) -> &dyn Hasher {
        &*self.hasher
    }
}

// TODO(issues/55) unit tests (e.g. signature verification)

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

//! Provides the [`Issuer`] type for issuing JWTs.

use std::collections::HashSet;

use bh_jws_utils::{jwt, HasJwkKid, HasX5Chain, JwkPublic, JwtSigner};
use bh_status_list::StatusClaim;
use bherror::{
    traits::{ErrorContext as _, ForeignBoxed, PropagateError},
    Error,
};
use bhx5chain::JwtX5Chain;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    encoder, error::FormatError, iref::UriBuf, utils::check_claim_names_object,
    verifier::VerifierError, CnfClaim, Error::Format, Hasher, HashingAlgorithm, IssuedSdJwt,
    JsonNodePath, JsonNodePathSegment, JsonObject, ParsedSdJwtIssuance, SecondsSinceEpoch,
};

/// Issuer of JWT Verifiable Credentials (VC) with selectively disclosable claims, i.e. SD-JWT VCs.
pub struct Issuer<H: Hasher> {
    hasher: H,
}

/// Error type related to the Issuer operations.
#[derive(strum_macros::Display, Debug, PartialEq, Eq)]
pub enum IssuerError {
    /// Error indicating that a claim name is reserved or registered and should
    /// not be used in the selectively disclosable claims.
    #[strum(to_string = "Use of reserved or registered claim name {0}")]
    ReservedOrRegisteredClaimName(&'static str),

    /// Error indicating that the provided disclosure path is invalid.
    #[strum(to_string = "Invalid path {0}")]
    InvalidPath(String),

    /// Error indicating that the provided disclosure path does not exist.
    #[strum(to_string = "Non existent path {0}")]
    NonExistentPath(String),

    /// Error indicating that the signing of the JWT failed.
    #[strum(to_string = "Signing failed")]
    SigningFailed,

    /// Error indicating that the provided disclosure paths contain a path that
    /// is a duplicate of another path.
    #[strum(to_string = "Duplicate path {0}")]
    DuplicatePath(String),
}

impl bherror::BhError for IssuerError {}

/// Result type used by the [`issuer`][crate::issuer] module.
pub type Result<T> = bherror::Result<T, IssuerError>;

impl<H: Hasher> Issuer<H> {
    /// Construct a new [`Issuer`] with the given [`Hasher`].
    pub fn new(hasher: H) -> Self {
        Self { hasher }
    }

    /// Create a new SD-JWT with disclosures for the JSON nodes at the provided
    /// paths, if they all exist.
    ///
    /// Paths which are extensions of other paths will cause creation of recursive disclosures,
    /// i.e. disclosures which themselves contain hash pointers to other disclosures, as described
    /// in more detail in the [draft].
    ///
    /// [draft]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#name-example-sd-jwt-with-recursi
    pub fn issue<S: JwtSigner + HasJwkKid + HasX5Chain, R: CryptoRngCore + ?Sized>(
        &self,
        mut jwt_payload: IssuerJwt,
        disclosure_paths: &[&JsonNodePath],
        signer: &S,
        rng: &mut R,
    ) -> Result<IssuedSdJwt> {
        // TODO(issues/49) be careful to match hasher collision resistance to the signing algorithm

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#name-registered-jwt-claims
        check_registered_path_in_paths(disclosure_paths)?;

        // set the `sd_alg` field to the appropriate value
        jwt_payload.sd_alg = Some(self.hasher.algorithm());

        // Create the encoder over only the custom claims part to prevent trying
        // to create disclosures for the non-selectively disclosable registered
        // claims.
        let disclosures =
            encoder::encode_claims(&mut jwt_payload.claims, disclosure_paths, &self.hasher, rng)?;

        let x5c = signer
            .x5chain()
            .try_into()
            .with_err(|| IssuerError::SigningFailed)
            .ctx(|| "invalid Issuer X.509 certificate chain")?;

        let header = IssuerJwtHeader {
            typ: TYP_VC_SD_JWT.into(),
            // TODO(issues/45) - we removed kid because this is incompatible with referent verifier
            kid: None,
            alg: signer.algorithm(),
            x5c: Some(x5c),
        };
        let unsigned_token = jwt::Token::new(header, jwt_payload);
        let signed_token = signer
            .sign_jwt(unsigned_token)
            .foreign_boxed_err(|| IssuerError::SigningFailed)?;
        Ok(IssuedSdJwt(ParsedSdJwtIssuance {
            jwt: signed_token,
            disclosures,
        }))
    }
}

/// Check if some `path` in provided array of `paths` is leading to a registered
/// claim which should not be disclosable.
///
/// Note: it does not check if `paths` contains a `path` whose segment is registered
/// claim (e.g. `iss.address`), if this path exists, then the claims object is not a
/// valid one and this is checked in `IssuerJwt::new` function
fn check_registered_path_in_paths(paths: &[&[crate::JsonNodePathSegment]]) -> Result<()> {
    for path in paths {
        if let [JsonNodePathSegment::Key(key)] = path {
            if let Some(name) = REGISTERED_CLAIM_NAMES.iter().find(|&name| name.eq(key)) {
                return Err(Error::root(IssuerError::ReservedOrRegisteredClaimName(
                    name,
                )));
            }
        }
    }
    Ok(())
}

/// Value to set for the [`typ`][IssuerJwtHeader::typ] header parameter when issuing an SD-JWT
/// verifiable credential.
///
/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01#section-3.2.1-2>
pub const TYP_VC_SD_JWT: &str = "vc+sd-jwt";

/// JWT Header of a [`Issuer`].
///
/// Header field values will be used to lookup the public key of the Issuer.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuerJwtHeader {
    /// Type of the payload; its value *must* be [`TYP_VC_SD_JWT`].
    pub typ: String,

    /// Algorithm used to sign the payload.
    pub alg: bh_jws_utils::SigningAlgorithm,

    /// Optional identifier of the key used for signing.
    ///
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-08#section-3.5-2.3>
    /// <https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html#section-5-1.8>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Optional field containing a certificate or certificate chain corresponding to the
    /// key used to sign the JWT.
    ///
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-08#section-3.5-2.2.1>
    /// <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<JwtX5Chain>,
}

impl jwt::JoseHeader for IssuerJwtHeader {
    fn algorithm_type(&self) -> jwt::AlgorithmType {
        self.alg.into()
    }
}

/// Template for the JWT the issuer signs. See the [interoperability profile]
/// for the set of mandatory and option registered claims.
///
/// [interoperability profile]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01#name-jwt-claims-set
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct IssuerJwt {
    /// Issuer of the verifiable credential.
    ///
    /// [Reference](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01#section-3.2.2.2-3.1.1)
    // HACK(third-party) allow non-uri `iss`
    pub iss: String,

    /// The time before which the Verifiable Credential MUST NOT be accepted before validating.
    ///
    /// [Reference](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01#section-3.2.2.2-3.3.1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<SecondsSinceEpoch>,

    /// The expiry time of the Verifiable Credential after which the Verifiable
    /// Credential is no longer valid.
    ///
    /// [Reference](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01#section-3.2.2.2-3.4.2.1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<SecondsSinceEpoch>,

    /// Holder's public JWK for key binding purposes.
    ///
    /// [Reference](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01#section-3.2.2.2-3.5.2.1)
    pub cnf: CnfClaim,

    /// Verifiable credential type. Case-sensitive `StringOrUri` Collision-Resistant Name.
    ///
    /// [Reference](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01#section-3.2.2.1.1-1)
    pub vct: String,

    /// The information on how to read the status of the Verifiable Credential.
    ///
    /// [Reference](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01#section-3.2.2.2-3.7.2.1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusClaim>,

    /// The hash algorithm used to hide the claims, as specified [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#name-hash-function-claim
    #[serde(rename = "_sd_alg", skip_serializing_if = "Option::is_none")]
    pub(crate) sd_alg: Option<HashingAlgorithm>,

    /// Remaining custom issuer defined claims.
    #[serde(flatten)]
    pub claims: JsonObject,
}

lazy_static::lazy_static! {
    /// Claim names registered for use with SD-JWT VCs, with defined semantics.
    /// These are **NOT** selectively disclosable!
    ///
    /// See the [SD-JWT VC draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01#section-3.2.2.2).
    ///
    pub(crate) static ref REGISTERED_CLAIM_NAMES: HashSet<&'static str> = {
        ["iss", "nbf", "exp", "cnf", "vct", "status"].into_iter().collect()
    };
}

impl IssuerJwt {
    /// Create a new JWT with registered claims marked required by the
    /// [interoperability profile].
    ///
    /// Note: `claims` should not contain any registered claim name (_`iss`_,
    /// _`nbf`_, _`exp`_, _`cnf`_, _`vct`_, _`status`_), and an error is
    /// returned if it does.
    ///
    /// [interoperability profile]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01#name-registered-jwt-claims
    pub fn new(
        vct: String,
        iss: UriBuf,
        holder_binding_public_jwk: JwkPublic,
        claims: JsonObject,
    ) -> Result<Self> {
        if let Some(name) = check_claim_names_object(
            &claims,
            &|claim| REGISTERED_CLAIM_NAMES.get(claim).copied(),
            false,
        ) {
            return Err(bherror::Error::root(
                IssuerError::ReservedOrRegisteredClaimName(name),
            ));
        }
        Ok(Self {
            iss: iss.to_string(),
            nbf: None,
            exp: None,
            cnf: CnfClaim {
                jwk: holder_binding_public_jwk,
            },
            vct,
            status: None,
            sd_alg: None,
            claims,
        })
    }

    /// Adds the `sub` claim to the `JWT`.
    ///
    /// If the `sub` claim already exists, the current value will be overwritten
    /// with the new one.
    pub fn add_sub_claim(&mut self, sub: String) {
        self.claims.insert("sub".to_owned(), sub.into());
    }

    /// Returns the `sub` claim.
    ///
    /// [`None`] is returned if it is missing, or it is not a string.
    pub fn sub(&self) -> Option<&str> {
        self.claims.get("sub").and_then(serde_json::Value::as_str)
    }

    /// Adds the `iat` claim to the `JWT`.
    ///
    /// If the `iat` claim already exists, the current value will be overwritten
    /// with the new one.
    pub fn add_iat_claim(&mut self, iat: SecondsSinceEpoch) {
        self.claims.insert("iat".to_owned(), iat.into());
    }

    /// Returns the `iat` claim.
    ///
    /// [`None`] is returned if it is missing, or it is not a `u64`.
    pub fn iat(&self) -> Option<SecondsSinceEpoch> {
        self.claims.get("iat").and_then(serde_json::Value::as_u64)
    }

    /// Serializes the Issuer's JWT into a `JSON` object.
    pub fn to_object(&self) -> JsonObject {
        crate::into_object(
            serde_json::to_value(self).expect("Implementation error: cannot serialize as JSON"),
        )
    }

    /// Validates the claims of the Issued `JWT`, as needed by the Holder.
    ///
    /// The following validation steps are performed:
    /// - `exp`: check that the `JWT` did not expire, i.e. `exp` field is in the
    ///   future,
    /// - `iat`: check that this value, if present, is a number, as no other
    ///   checks on it could be performed.
    ///
    /// # Error
    /// If any of the validity criteria are not met, an error is returned.
    pub(crate) fn validate_claims_holder(
        &self,
        current_time: SecondsSinceEpoch,
    ) -> crate::Result<(), crate::Error> {
        // check that the JWT did not expire
        // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
        if let Some(exp) = self.exp {
            // RFC: "on or after"
            if current_time >= exp {
                return Err(Error::root(crate::Error::JwtExpired(current_time, exp)));
            };
        };

        // check that `IAT`, if exists, is a number
        if let Some(iat) = self.claims.get("iat") {
            if !iat.is_number() {
                return Err(Error::root(Format(FormatError::InvalidIatFormat)));
            };
        };

        Ok(())
    }

    /// Validates the claims of the Issued `JWT`, as needed by the Verifier.
    ///
    /// The following validation steps are performed:
    /// - all checks that are also needed by the Holder, using the
    ///   [`Self::validate_claims_holder`] method,
    /// - `nbf`: check that the `JWT` is already valid, i.e. this value is in
    ///   the past.
    ///
    /// # Error
    /// If any of the validity criteria are not met, an error is returned.
    pub(crate) fn validate_claims_verifier(
        &self,
        current_time: SecondsSinceEpoch,
    ) -> crate::Result<(), VerifierError> {
        self.validate_claims_holder(current_time)
            .match_err(|crate_error| crate_error.to_verifier_error())?;

        // check that `nbf`, if present, is in the past
        if let Some(nbf) = self.nbf {
            if current_time < nbf {
                return Err(Error::root(VerifierError::JwtNotYetValid(
                    current_time,
                    nbf,
                )));
            };
        };

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::str::FromStr;

    use bhx5chain::X5Chain;
    use iref::IriBuf;
    use jwt::VerifyWithKey;

    use super::*;
    use crate::{
        decoder::decode_disclosed_claims,
        json_object,
        test_utils::{dummy_hasher_factory, symbolic_crypto::*},
        traits::SHA_256_ALG_NAME,
        utils::SD_ALG_FIELD_NAME,
        DisplayWrapper, JsonNodePathSegment, SdJwt, Sha256, Value, RESERVED_CLAIM_NAMES,
    };

    impl<State> std::fmt::Debug for ParsedSdJwtIssuance<State> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            #[derive(Debug)]
            #[allow(dead_code)]
            struct DebugWrapper<'a> {
                header: &'a IssuerJwtHeader,
                claims: &'a IssuerJwt,
            }

            f.debug_struct("IssuedSdJwt")
                .field(
                    "jwt",
                    &DebugWrapper {
                        header: self.jwt.header(),
                        claims: self.jwt.claims(),
                    },
                )
                .field("disclosures", &self.disclosures)
                .finish()
        }
    }

    pub(crate) fn dummy_https_iss() -> UriBuf {
        IriBuf::new("https://example.com/.well-known/jwt-issuer".into())
            .unwrap()
            .try_into_uri()
            .unwrap()
    }

    pub(crate) fn dummy_claims() -> JsonObject {
        json_object!({
            "foo": "bar",
            "baz": 42,
            "parent": {
                "child1": [
                    "elem 0",
                    "elem 1",
                    "elem 2",
                    {
                        "nested": false,
                    }
                ],
                "child2": {
                    "leaf": Value::Null,
                    "foo": "bar",
                },
                "child3": "bar",
            },
        })
    }

    pub(crate) fn test_issuer_jwt() -> IssuerJwt {
        IssuerJwt::new(
            "TestCredential".into(),
            dummy_https_iss(),
            dummy_public_jwk(),
            dummy_claims(),
        )
        .unwrap()
    }

    use JsonNodePathSegment::*;

    pub(crate) const TEST_DISCLOSURE_PATHS: &[&JsonNodePath] = &[
        &[Key("foo")],
        &[Key("parent")],
        // Recursive disclosure, disclosure with array element leaf
        &[Key("parent"), Key("child1"), Index(1)],
        // paths that go through arrays
        &[Key("parent"), Key("child1"), Index(3), Key("nested")],
        // Recursive disclosure, disclosure with key leaf
        &[Key("parent"), Key("child2"), Key("leaf")],
        // Recursive disclosure, disclosure with non-unique key-value pair
        &[Key("parent"), Key("child2"), Key("foo")],
        // Recursive disclosure, disclosure with non-unique value
        &[Key("parent"), Key("child3")],
    ];

    pub(crate) fn test_sd_jwt(
        issuer_jwt: IssuerJwt,
        disclosure_paths: &[&JsonNodePath],
    ) -> IssuedSdJwt {
        let public_jwk = issuer_jwt.cnf.jwk.clone();
        Issuer::new(Sha256)
            .issue(
                issuer_jwt,
                disclosure_paths,
                &StubSigner::new(public_jwk, X5Chain::dummy()),
                &mut rand::thread_rng(),
            )
            .expect("Issuing failed")
    }

    #[test]
    fn happy_path() {
        let hasher = Sha256;
        let issuer = Issuer::new(&hasher);

        let issuer_jwt = test_issuer_jwt();

        // Create disclosures for paths that exist and are supported
        // Sign the JWT using a symbolic signer and assemble the SD-JWT
        let issued_sd_jwt = issuer
            .issue(
                issuer_jwt,
                TEST_DISCLOSURE_PATHS,
                &StubSigner::default(),
                &mut rand::thread_rng(),
            )
            .expect("Issuing failed");

        let claims = &issued_sd_jwt.0.jwt.claims().claims;
        let disclosures = &issued_sd_jwt.0.disclosures[..];

        // Test that the number of created disclosures is equal to the number of
        // requested selectively disclosable nodes
        assert_eq!(
            disclosures.len(),
            TEST_DISCLOSURE_PATHS.len(),
            "Wrong number of disclosures"
        );

        // TODO(issues/50) test that the disclosure with a certain digest corresponds to the
        // node at that path in the original - otherwise, an implementation may
        // output just _some_ SD-JWT with a similar schema.

        let (decoded_claims, hasher, _) =
            decode_disclosed_claims(claims, disclosures, dummy_hasher_factory).unwrap();
        assert_eq!(decoded_claims, dummy_claims());
        assert_eq!(hasher.algorithm(), HashingAlgorithm::Sha256);

        // Verify the symbolic signature
        let serialized_compact = issued_sd_jwt.into_string_compact();
        println!("{}", serialized_compact);
        let parsed = SdJwt::from_str(&serialized_compact).unwrap();
        parsed
            .parse()
            .expect("Invalid compact serialization of an issued SD-JWT")
            .0
            .jwt
            .verify_with_key(&StubVerifier::default())
            .expect("Invalid signature");
    }

    #[test]
    fn invalid_paths() {
        let issuer = Issuer::new(Sha256);

        let non_existent_paths: &[&JsonNodePath] = &[
            &[Key("parent"), Key("nonexistent_key")],
            &[Key("parent"), Key("child1"), Index(42)],
        ];
        for path in non_existent_paths {
            let disclosure_paths = &[*path];
            let non_existent_path = issuer.issue(
                test_issuer_jwt(),
                disclosure_paths,
                &StubSigner::default(),
                &mut rand::thread_rng(),
            );
            assert_eq!(
                non_existent_path.unwrap_err().error,
                IssuerError::NonExistentPath(DisplayWrapper(*path).to_string())
            );
        }

        let invalid_path: &JsonNodePath = &[Index(42)];
        let error = issuer.issue(
            test_issuer_jwt(),
            &[invalid_path],
            &StubSigner::default(),
            &mut rand::thread_rng(),
        );
        assert_eq!(
            error.unwrap_err().error,
            IssuerError::InvalidPath(DisplayWrapper(invalid_path).to_string())
        );
        let empty_path: &JsonNodePath = &[];
        let disclosure_paths = &[empty_path];
        let error = issuer.issue(
            test_issuer_jwt(),
            disclosure_paths,
            &StubSigner::default(),
            &mut rand::thread_rng(),
        );
        assert_eq!(
            error.unwrap_err().error,
            IssuerError::InvalidPath(DisplayWrapper(empty_path).to_string())
        );

        // Try to form a disclosure for reserved or non-selectively-disclosable fields
        for claim in RESERVED_CLAIM_NAMES
            .iter()
            .chain(REGISTERED_CLAIM_NAMES.iter())
        {
            let path = &[Key(claim)];
            let error = issuer.issue(
                test_issuer_jwt(),
                &[path],
                &StubSigner::default(),
                &mut rand::thread_rng(),
            );
            assert_eq!(
                error.unwrap_err().error,
                IssuerError::ReservedOrRegisteredClaimName(claim)
            );
        }

        // Try to form a disclosure for non-selectively-disclosable fields alongside selectively disclosable
        let registered_path = &[Key("iss")];
        let valid_path = &[Key("parent"), Key("child1")];

        let error = issuer.issue(
            test_issuer_jwt(),
            &[valid_path, registered_path],
            &StubSigner::default(),
            &mut rand::thread_rng(),
        );

        assert_eq!(
            error.unwrap_err().error,
            IssuerError::ReservedOrRegisteredClaimName("iss")
        );
    }

    #[test]
    fn path_through_array_test() {
        let issuer = Issuer::new(Sha256);

        let path = &[Key("parent"), Key("child1"), Index(3), Key("nested")];
        let _ = issuer
            .issue(
                test_issuer_jwt(),
                &[path],
                &StubSigner::default(),
                &mut rand::thread_rng(),
            )
            .unwrap();
    }

    #[test]
    fn model_errors() {
        let invalid_models = [
            (json_object!({ "iss": "definitely not a URI" }), "iss"),
            (json_object!({ "nbf": "definitely not a URI" }), "nbf"),
            (json_object!({ "exp": "definitely not a URI" }), "exp"),
            (json_object!({ "cnf": "definitely not a URI" }), "cnf"),
            (json_object!({ "vct": "definitely not a URI" }), "vct"),
            (json_object!({ "status": "definitely not a URI" }), "status"),
        ];

        for (model, reserved_name) in invalid_models {
            let result = IssuerJwt::new(
                "TestCredential".into(),
                dummy_https_iss(),
                dummy_public_jwk(),
                model,
            );

            assert_eq!(
                result.unwrap_err().error,
                IssuerError::ReservedOrRegisteredClaimName(reserved_name)
            );
        }

        // It _is_ valid to add a selectively disclosable `sub` claim
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01#section-3.2.2.2-5.1.1
        let sub = "subject identifier";
        let issuer_jwt = IssuerJwt::new(
            "TestCredential".into(),
            dummy_https_iss(),
            dummy_public_jwk(),
            json_object!({
                "sub": sub,
            }),
        )
        .unwrap();

        let issuer = Issuer::new(Sha256);

        let sd_jwt = issuer
            .issue(
                issuer_jwt,
                &[&[Key("sub")]],
                &StubSigner::default(),
                &mut rand::thread_rng(),
            )
            .unwrap();

        assert_eq!(sd_jwt.0.disclosures[0].claim_name().unwrap(), "sub");
        assert_eq!(sd_jwt.0.disclosures[0].value(), sub);
    }

    #[test]
    fn sd_alg_field_name_serializes_correctly() {
        let alg = HashingAlgorithm::Sha256;
        let alg_name = SHA_256_ALG_NAME;

        let mut jwt = test_issuer_jwt();
        jwt.sd_alg = Some(alg);

        // make sure there is no _sd_alg in claims
        assert!(!jwt.claims.contains_key(SD_ALG_FIELD_NAME));

        // make sure sd_alg field name serializes correctly
        let serialized = serde_json::to_value(&jwt).unwrap();
        let ser_object = serialized.as_object().unwrap();
        assert!(ser_object.contains_key(SD_ALG_FIELD_NAME));

        // make sure sd_alg value serializes correctly
        let ser_sd_alg = ser_object.get(SD_ALG_FIELD_NAME).unwrap();
        let ser_sd_alg = ser_sd_alg.as_str().unwrap();
        assert_eq!(ser_sd_alg, alg_name);

        // make sure sd_alg deserializes correctly
        let deserialized: IssuerJwt = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.sd_alg, jwt.sd_alg);
    }
}

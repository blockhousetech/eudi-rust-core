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

//! The module provides the [`Holder`] type for managing and presenting SD-JWTs.
//!
//! It verifies an issued SD-JWT, allows access to the underlying claims, and builds a presentation
//! (an SD-JWT with key binding) that discloses only selected claims.

use std::fmt::Debug;

use bh_jws_utils::{jwt, JwtSigner, SignatureVerifier, SigningAlgorithm};
use bherror::{traits::PropagateError, Error};
use jwt::claims::SecondsSinceEpoch;

use crate::{
    error::{FormatError, SignatureError},
    key_binding::KeyBindingChallenge,
    paths_exist,
    sd_jwt::{SdJwt, SdJwtKB},
    traits::IssuerPublicKeyLookup,
    utils::VecDisplayWrapper,
    DecodingError, DisplayWrapper, Hasher, HashingAlgorithm, IssuerJwt, JsonNodePath, SdJwtDecoded,
};

/// Holder of a SD-JWT VC. Capable of creating [`SdJwtKB`]s with selectively
/// disclosed claims.
///
/// A single instance of a `Holder` is to be used per SD-JWT, and it need not be
/// persisted from issuing to presentation, as it can be constructed on-demand
/// when presentation is required.
pub struct Holder {
    decoded_sd_jwt: SdJwtDecoded,
    original_issuer_jwt: String,
}

/// Error type representing various errors that can occur during Holder
/// operations.
#[derive(strum_macros::Display, Debug, PartialEq)]
pub enum HolderError {
    /// Error indicated that the SD-JWT is not in a valid format.
    #[strum(to_string = "Invalid SDJwt serialization")]
    InvalidSdJwtSerialization,

    /// Error indicating that the Key Binding JWT was found in the issued
    /// SD-JWT,
    #[strum(to_string = "KBJwt found in issued SDJwt")]
    KBJwtInIssuedSdJwt,

    /// Error indicating that the Key Binding JWT signing failed.
    #[strum(to_string = "KBJwt signing failed")]
    KBJwtSigningFailed,

    /// Error indicating that the SD-JWT contains claims that do not exist.
    #[strum(to_string = "Nonexistent claims found: {0}")]
    NonexistentClaims(VecDisplayWrapper<String>),

    /// Error while decoding the SD-JWT.
    #[strum(to_string = "{0}")]
    Decoding(DecodingError),

    /// Error indicating that the SD-JWT is not in a valid format.
    #[strum(to_string = "{0}")]
    Format(FormatError),

    /// Error related to signature verification.
    #[strum(to_string = "{0}")]
    Signature(SignatureError),

    /// JWT not yet valid error, indicating the JWT's `nbf` (not before) claim
    /// is in the future.
    #[strum(to_string = "JWT not yet valid: current time is {0}, nbf is {1}")]
    JwtNotYetValid(u64, u64),

    /// JWT expired error, indicating the JWT's `exp` (expiration) claim is in
    /// the past.
    #[strum(to_string = "JWT expired, current time is {0}, exp is {1}")]
    JwtExpired(u64, u64),
}

impl bherror::BhError for HolderError {}

/// Result type used by the [`holder`][crate::holder] module.
pub type Result<T> = bherror::Result<T, HolderError>;

/// The "successful" result of [`Holder::verify_held`], indicating that either
/// the held credential was validated successfully, or the validation failed due
/// to uncontrollable reasons (e.g. expiration, unable to look up public key).
#[allow(clippy::large_enum_variant)]
pub enum VerifyHeldResult {
    /// The validation succeeded, so we have a valid [`Holder`].
    Holder(Holder),

    /// The validation failed or could not be completed due to "impure" reasons
    /// (outside the holder's control), including:
    ///
    /// - the credential has expired (passage of time);
    /// - the issuer's public key could not be looked up (e.g. network failure, revocation).
    ///
    /// Since callers may encounter such failures due to reasons outside their
    /// control even on previously validated credentials, these situations
    /// should not be handled as hard internal errors and should not be
    /// immediately propagated as this may disrupt functionality if there were
    /// other, _valid_ held credentials.
    ///
    /// For this reason, these conditions are modeled by this enum variant and
    /// are returned inside `Ok(_)` to prevent accidentally early-returning
    /// without handling these conditions gracefully.
    Invalid {
        /// Concrete [`HolderError`] that caused the validation to fail.
        error: Error<HolderError>,
        // TODO extend this with claims (for user preview only)?
    },
}

impl VerifyHeldResult {
    /// Convert this into a [`Result`]; useful for suppressing special handling
    /// of relevant kinds of errors.
    pub fn into_result(self) -> Result<Holder> {
        match self {
            VerifyHeldResult::Holder(holder) => Ok(holder),
            VerifyHeldResult::Invalid { error } => Err(error),
        }
    }
}

impl Debug for VerifyHeldResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Holder(_) => f.write_str("Holder"),
            Self::Invalid { error } => f.debug_struct("Invalid").field("error", error).finish(),
        }
    }
}

impl Holder {
    /// Import an issued SD-JWT, verifying its validity.
    ///
    /// An issued `SD-JWT` is valid if it does not contain the Key Binding
    /// `JWT`, the signature of the `JWT` is valid against the issuer's public
    /// key, the hashing algorithm is in a valid form and on the list of allowed
    /// and supported algorithms and if the received payload can be successfully
    /// re-constructed using the received disclosures.
    ///
    /// # Cryptography
    ///
    /// The caller needs to provide an implementation of a [`Hasher`] for every
    /// algorithm they want to support, using the `get_hasher` argument. If the
    /// received payload uses an algorithm whose [`Hasher`] the caller did not
    /// provide, an error will be returned.
    ///
    /// # Arguments
    /// The associated function's arguments are as follows:
    ///
    /// - `issued_sd_jwt`: String representation of the issued `SD-JWT` in
    ///   **compact** form,
    ///
    /// - `issuer_public_key_lookup`: an implementation of the interface
    ///   capable of resolving the issuer's public key based on the `iss`
    ///   claim of the `JWT` and its header (see [`IssuerPublicKeyLookup`]),
    ///
    /// - `get_hasher`: a function that returns an instance of a [`Hasher`]
    ///   based on the provided [`HashingAlgorithm`], or `None` if it is not
    ///   supported,
    ///
    /// - `get_signature_verifier`: a function that returns an implementation
    ///   of a [`SignatureVerifier`] based on the provided [`SigningAlgorithm`],
    ///   or `None` if it is not supported.
    ///
    /// # Notes
    /// - The caller needs to support at least `SHA-256` hashing algorithm, as
    ///   specified [here].
    ///
    /// - The `get_hasher` function will be called twice due to some backend
    ///   restrictions.
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.1.1-3
    pub async fn verify_issued<'a>(
        issued_sd_jwt: &str,
        issuer_public_key_lookup: &impl IssuerPublicKeyLookup,
        get_hasher: impl Fn(HashingAlgorithm) -> Option<Box<dyn Hasher>>,
        get_signature_verifier: impl FnOnce(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
        current_time: SecondsSinceEpoch,
    ) -> Result<Self> {
        let sd_jwt: SdJwt = issued_sd_jwt
            .parse()
            .with_err(|| HolderError::InvalidSdJwtSerialization)?;

        // Verify signature of the issued SD-JWT
        let decoded_sd_jwt = sd_jwt
            .to_signature_verified_sd_jwt(issuer_public_key_lookup, get_signature_verifier)
            .await
            .match_err(|crate_error| crate_error.to_holder_error())?
            .0
            .into_decoded(get_hasher)
            .match_err(|crate_error| crate_error.to_holder_error())?;

        // Validate the additional `SD-JWT-VC` claims
        decoded_sd_jwt
            .claims()
            .validate_claims_holder(current_time)
            .match_err(|crate_error| crate_error.to_holder_error())?;

        // TODO(issues/46) check that the `cnf.jwk` claim corresponds to the holder's public key?

        Ok(Self {
            decoded_sd_jwt,
            original_issuer_jwt: sd_jwt.jwt,
        })
    }

    /// Import an already held SD-JWT, verifying its validity in a more controlled way.
    ///
    /// Refer to the documentation of [`Holder::verify_issued`] for the meaning of the arguments.
    ///
    /// If there were unrecoverable and essential errors with the held SD-JWT, `Err(_)` is returned.
    /// Otherwise, `Ok(_)` is returned, with the following semnatics:
    ///
    /// - If the credential was fully valid, [`VerifyHeldResult::Holder`] is returned;
    ///
    /// - If the credential was invalid (or could not be validated) due to
    ///   reasons outside the holder's control, [`VerifyHeldResult::Invalid`] is
    ///   returned with the associated error, allowing these errors to be handled more gracefully.
    ///
    /// Tip: `.and_then(VerifyHeldResult::into_result)` can be chained to this
    /// call to recover the same behavior as [`Holder::verify_issued`].
    pub async fn verify_held<'a>(
        held_sd_jwt: &str,
        issuer_public_key_lookup: &impl IssuerPublicKeyLookup,
        get_hasher: impl Fn(HashingAlgorithm) -> Option<Box<dyn Hasher>>,
        get_signature_verifier: impl FnOnce(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
        current_time: SecondsSinceEpoch,
    ) -> Result<VerifyHeldResult> {
        let result = Self::verify_issued(
            held_sd_jwt,
            issuer_public_key_lookup,
            get_hasher,
            get_signature_verifier,
            current_time,
        )
        .await;

        match result {
            Ok(holder) => Ok(VerifyHeldResult::Holder(holder)),
            Err(error) => match error.error {
                // TODO better distinguish public key lookup failures - some may be
                // revocations, some may be retryable (e.g. network error)
                HolderError::JwtExpired(..)
                | HolderError::Signature(crate::SignatureError::PublicKeyLookupFailed) => {
                    Ok(VerifyHeldResult::Invalid { error })
                }
                _ => Err(error),
            },
        }
    }

    /// Return the fully reconstructed claim set in the held SD-JWT, with all
    /// SD-JWT format-specific metadata removed. To be used only for the purpose
    /// of displaying the contents to the End-User.
    pub fn claims(&self) -> &IssuerJwt {
        self.decoded_sd_jwt.claims()
    }

    /// Consumes the [`Holder`] and returns the fully reconstructed claim set in
    /// the held SD-JWT, with all SD-JWT format-specific metadata removed. To be
    /// used only for the purpose of displaying the contents to the End-User.
    pub fn into_claims(self) -> IssuerJwt {
        self.decoded_sd_jwt.into_claims()
    }

    /// Create a verifiable [`SdJwtKB`] of the held SD-JWT with the provided
    /// claim set and for the provided verifier's challenge, while proving key
    /// binding using the holder's private key to sign the KB JWT.
    ///
    /// # Details
    ///
    /// ## Claim set
    ///
    /// The set of disclosures included in the presentation is the smallest set
    /// of them which when combined include all the paths in
    /// `claims_to_disclose`. Note that it is valid for the paths to include
    /// even non-selectively-disclosable claims.
    ///
    /// Also note that the total set of claims disclosed may in general **exceed**
    /// the requested set due to the structure of disclosures; for example, if an
    /// object node is selectively disclosable only as a whole, requesting any
    /// of its fields (or descendants) will require *all* the fields to be pulled in.
    /// **This could result in disclosing more information than intended.**
    /// Depending on the details of protocols used for presentation exchange, this
    /// could prevent the presentation from proceeding; see e.g.
    /// [the `limit_disclosure` constraint in DIF presentation exchange](
    /// https://identity.foundation/presentation-exchange/#limited-disclosure-submissions)
    ///
    /// ## Key Binding
    ///
    /// The [`KeyBindingChallenge`] should be set to the values received via
    /// some presentation exchange protocol from the verifier, that the verifier
    /// expects to find in the signed KB JWT. The `current_time` parameter will be
    /// used to set the `iat` claim of the KB JWT.
    ///
    /// # Errors
    ///
    /// If any requested path doesn't exist within the fully reconstructed payload,
    /// this function will error with [`HolderError::NonexistentClaims`].
    ///
    /// Otherwise, the function will only error if the Key Binding JWT signing fails.
    pub fn present(
        &self,
        claims_to_disclose: &[&JsonNodePath],
        key_binding_challenge: KeyBindingChallenge,
        current_time: SecondsSinceEpoch,
        key_binding_signer: &impl JwtSigner,
    ) -> Result<SdJwtKB> {
        // First check whether all paths correspond to existing nodes - including non-selectively
        // disclosable ones, just to be sure
        paths_exist(&self.claims().to_object(), claims_to_disclose).map_err(
            |nonexistent_claims| {
                Error::root(HolderError::NonexistentClaims(VecDisplayWrapper(
                    nonexistent_claims
                        .into_iter()
                        .map(|path| DisplayWrapper(path).to_string())
                        .collect(),
                )))
            },
        )?;

        // Compute the set of disclosures to send
        let presented_disclosures = self
            .decoded_sd_jwt
            .disclosures_by_path()
            .disclosures_covering_paths(claims_to_disclose)
            .map(|disclosure| disclosure.as_str().to_owned())
            .collect();

        let sd_jwt = SdJwt::new(self.original_issuer_jwt.clone(), presented_disclosures);

        // TODO(issues/47) also compute whether there is anything disclosed beyond
        // what was requested due to the limitations of the schema, as this
        // could maybe prevent presentation from proceeding, e.g.
        // https://identity.foundation/presentation-exchange/#limited-disclosure-submissions

        let sd_jwt_kb = sd_jwt.add_key_binding_jwt(
            self.decoded_sd_jwt.hasher(),
            key_binding_challenge,
            current_time,
            key_binding_signer,
        )?;

        Ok(sd_jwt_kb)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        issuer::tests::{test_issuer_jwt, test_sd_jwt, TEST_DISCLOSURE_PATHS},
        test_utils::{
            dummy_hasher_factory, dummy_key_binding_audience, header_public_key_lookup,
            symbolic_crypto::{StubSigner, StubVerifier},
        },
    };

    pub(crate) async fn test_holder(
        issuer_jwt: IssuerJwt,
        signature_verifier: StubVerifier,
        current_time: u64,
    ) -> Holder {
        let sd_jwt = test_sd_jwt(issuer_jwt, TEST_DISCLOSURE_PATHS).into_string_compact();
        Holder::verify_issued(
            &sd_jwt,
            &header_public_key_lookup(),
            dummy_hasher_factory,
            |_| Some(&signature_verifier),
            current_time,
        )
        .await
        .expect("SD-JWT import failed")
    }

    fn dummy_key_binding_challenge() -> KeyBindingChallenge {
        KeyBindingChallenge {
            aud: dummy_key_binding_audience(),
            nonce: "babadeda".into(),
        }
    }

    mod unit {

        use super::*;
        use crate::{
            issuer::tests::TEST_DISCLOSURE_PATHS, test_utils::failing_public_key_lookup, Disclosure,
        };

        #[tokio::test]
        async fn present_happy_path() {
            let iat = 100;
            let holder = test_holder(test_issuer_jwt(), StubVerifier::default(), iat).await;

            let test_cases: &[&[&JsonNodePath]] = &[
                &[],
                &[&["foo".into()]],
                &[&["parent".into()]],
                &[
                    // NB: not a disclosure node in itself, but a child of one
                    &["parent".into(), "child1".into()],
                ],
                &[&["parent".into(), "child1".into(), 1.into()]],
                &[
                    // TODO(issues/48)
                    // The problem is that since we did not request the disclosure at `$.parent.child1[1]`,
                    // it wasn't present (so far so good) but that causes the actually requested disclosure
                    // at `$.parent.child1[3]` to _not_ be at the index 3, but 2. This is actually correct!
                    //
                    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#section-8.1-4.3.2.4
                    //
                    // How are we supposed to test this then??
                    //
                    // And how would this actually work in the real world? I.e. a verifier requests
                    // presentation of something that is directly or transitively within an array,
                    // but doesn't request a different array element that is selectively
                    // disclosable and is before the requested one?
                    //
                    // The verifier _will_ receive it, but it won't be at the expected index...
                    // Will the presentation request ever ask for _specific_ array elements,
                    // rather than all or none (or first N)?
                    // Context:
                    // https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html#section-5-1.10.2.2
                    // https://identity.foundation/presentation-exchange/#input-descriptor-object
                    //
                    // &["parent".into(), "child1".into(), 3.into(), "nested".into()],
                ],
                &[
                    &["parent".into(), "child1".into(), 1.into()],
                    // NB: this works because all preceding disclosures are requested
                    &["parent".into(), "child1".into(), 3.into(), "nested".into()],
                ],
                &[
                    // NB: this properly removes the `_sd` array from `child2`
                    &["parent".into(), "child2".into(), "leaf".into()],
                ],
                &[&["parent".into(), "child2".into(), "foo".into()]],
                // Disclose everything
                TEST_DISCLOSURE_PATHS,
                &[
                    // NB: not even selectively disclosable
                    &["baz".into()],
                ],
            ];

            for (test_case, claims_to_disclose) in test_cases.iter().enumerate() {
                let sd_jwt_kb = holder
                    .present(
                        claims_to_disclose,
                        dummy_key_binding_challenge(),
                        iat,
                        &StubSigner::default(),
                    )
                    .expect("Failed to create sd-jwt+kb");

                let claims = sd_jwt_kb.sd_jwt.parse().unwrap().0.jwt.claims().to_object();
                let disclosures = sd_jwt_kb
                    .sd_jwt
                    .disclosures
                    .iter()
                    .cloned()
                    .map(|disclosure| Disclosure::try_from(disclosure).unwrap())
                    .collect::<Vec<_>>();
                let (reconstructed, ..) = crate::decoder::decode_disclosed_claims(
                    &claims,
                    &disclosures,
                    dummy_hasher_factory,
                )
                .unwrap();
                println!("Test case #{}:\n{:#?}\n", test_case, reconstructed);

                paths_exist(&reconstructed, claims_to_disclose)
                    .expect("Some requested paths are missing");
            }
        }

        #[tokio::test]
        async fn present_nonexistent_paths() {
            let holder = test_holder(test_issuer_jwt(), StubVerifier::default(), 100).await;

            struct TestCase<'a> {
                fake_paths: &'a [&'a JsonNodePath<'a>],
                real_paths: &'a [&'a JsonNodePath<'a>],
            }

            let test_cases: &[TestCase] = &[
                TestCase {
                    fake_paths: &[&["babadeda".into()]],
                    real_paths: &[],
                },
                TestCase {
                    fake_paths: &[&["parent".into(), "babadeda".into()]],
                    real_paths: &[],
                },
                TestCase {
                    fake_paths: &[&["parent".into(), 37.into()]],
                    real_paths: &[],
                },
                TestCase {
                    fake_paths: &[
                        &["parent".into(), 37.into()],
                        &["parent".into(), "child1".into(), 42.into()],
                    ],
                    real_paths: &[
                        &["foo".into()],
                        &["baz".into()],
                        &["parent".into(), "child1".into()],
                    ],
                },
            ];

            for TestCase {
                fake_paths,
                real_paths,
            } in test_cases
            {
                let claims_to_disclose = &[*real_paths, *fake_paths].concat();
                let error = holder
                    .present(
                        claims_to_disclose,
                        dummy_key_binding_challenge(),
                        100,
                        &StubSigner::default(),
                    )
                    .expect_err("Presentation succeeded but shouldn't have");

                let paths_rendered = VecDisplayWrapper(
                    fake_paths
                        .iter()
                        .map(|path| DisplayWrapper(*path).to_string())
                        .collect(),
                );
                assert_eq!(error.error, HolderError::NonexistentClaims(paths_rendered))
            }
        }

        #[test]
        fn verify_held() {
            const EXP: SecondsSinceEpoch = 200;
            let sd_jwt = test_sd_jwt(
                IssuerJwt {
                    exp: Some(EXP),
                    ..test_issuer_jwt()
                },
                TEST_DISCLOSURE_PATHS,
            )
            .into_string_compact();

            let call_verify_held = |sd_jwt, current_time| {
                let signature_verifier = StubVerifier::default();

                futures::executor::block_on(Holder::verify_held(
                    sd_jwt,
                    &header_public_key_lookup(),
                    dummy_hasher_factory,
                    |_| Some(&signature_verifier),
                    current_time,
                ))
            };

            let still_valid = call_verify_held(&sd_jwt, EXP - 1).unwrap();
            assert!(matches!(still_valid, VerifyHeldResult::Holder(_)));

            let expired = call_verify_held(&sd_jwt, EXP).unwrap();
            assert!(matches!(expired, VerifyHeldResult::Invalid { error }
                if error.error == HolderError::JwtExpired(EXP, EXP)
            ));

            let lookup_failed = {
                let signature_verifier = StubVerifier::default();

                futures::executor::block_on(Holder::verify_held(
                    &sd_jwt,
                    // `IssuerPublicKeyLookup` is not object safe, so we can't
                    // make it an argument of `call_verify_held` ...
                    &failing_public_key_lookup(),
                    dummy_hasher_factory,
                    |_| Some(&signature_verifier),
                    EXP - 1,
                ))
            }
            .unwrap();
            assert!(matches!(lookup_failed, VerifyHeldResult::Invalid { error }
                if error.error == HolderError::Signature(crate::SignatureError::PublicKeyLookupFailed)
            ));

            let _garbage_sd_jwt = call_verify_held("garbage sd-jwt", EXP - 1).unwrap_err();
        }
    }

    mod integration {
        use super::*;

        #[tokio::test]
        async fn issuer_holder_happy_path() {
            let holder = test_holder(test_issuer_jwt(), StubVerifier::default(), 100).await;
            let expected_claims = test_issuer_jwt();
            assert_eq!(holder.claims(), &expected_claims);
        }
    }
}

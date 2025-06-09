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

//! This module provides the [`Verifier`] type for verifying SD-JWT+KB presentations.

use bh_jws_utils::{base64_url_encode, JwkPublic, SignatureVerifier, SigningAlgorithm};
use bherror::traits::PropagateError;
use rand_core::CryptoRngCore;

use crate::{
    error::{FormatError, SignatureError},
    key_binding::{KBError, KeyBindingChallenge},
    sd_jwt::SdJwtKB,
    traits::IssuerPublicKeyLookup,
    DecodingError, Hasher, HashingAlgorithm, IssuerJwt, SecondsSinceEpoch,
};

/// Verifier of SD-JWT+KB verifiable presentation.
///
/// This verifier requires Key Binding. Note that the decision whether to
/// require Key Binding for a particular use case **MUST NOT** be based on
/// whether a Key Binding JWT is provided by the Holder or not, according
/// to [official documentation].
///
/// # Lifecycle
///
/// A fresh instance must be constructed for every presentation exchange
/// session.  The instance should live for the entire session, as it contains
/// the nonce value used for ensuring freshness of the presentation that needs
/// to be both communicated to the [Holder](crate::holder::Holder) and used in
/// verification of the [SdJwtKB].
///
/// NB: Does **NOT** implement [Clone] to prevent nonce reuse!
///
/// [official documentation]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.3-4.1
pub struct Verifier {
    challenge: KeyBindingChallenge,
}

/// Error type for errors related to the SD-JWT verifier.
#[derive(strum_macros::Display, Debug, PartialEq)]
pub enum VerifierError {
    /// Error indicating that the nonce generation failed.
    #[strum(to_string = "Nonce generation failed")]
    NonceGenerationFailed,

    /// Error with Key Binding JWT.
    #[strum(to_string = "{0}")]
    KeyBinding(KBError),

    /// Error indicating that the provided SD-JWT format is invalid.
    #[strum(to_string = "Format error: {0}")]
    Format(FormatError),

    /// Error indicating that the signature verification failed.
    #[strum(to_string = "Signature error: {0}")]
    Signature(SignatureError),

    /// Error indicating that the decoding of the SD-JWT failed.
    #[strum(to_string = "Decoding error: {0}")]
    Decoding(DecodingError),

    /// Error indicating that the JWT is not yet valid, i.e. the `nbf` (not
    /// before) claim is set to a future time.
    #[strum(to_string = "Jwt not yet valid: current time is {0}, nbf is {1}")]
    JwtNotYetValid(u64, u64),

    /// Error indicating that the JWT has expired, i.e. the `exp` (expiration)
    /// claim is set to a time in the past.
    #[strum(to_string = "Jwt expired, current time is {0}, expiration is {1}")]
    JwtExpired(u64, u64),
}

impl bherror::BhError for VerifierError {}

/// Result type used by the [`verifier`][crate::verifier] module.
pub type Result<T> = bherror::Result<T, VerifierError>;

impl Verifier {
    /// Construct a verifier for a new presentation exchange session.
    ///
    /// # Key Binding
    ///
    /// This verifier will require Key Binding. The challenge parameters include
    /// the `aud` parameter which represents the identifier of the verifier
    /// entity for the purpose of proving key binding, and the nonce to be used
    /// for replay prevention that will be sampled from the provided
    /// `nonce_rng`.
    ///
    /// # Lifecycle
    ///
    /// The verifier instance needs to be persisted for the duration of the
    /// presentation exchange session, as it holds the aforementioned
    /// challenge-related parameters as its state, since they will be needed for
    /// verification once the presentation arrives.
    ///
    /// Note that no implementation is provided for (de)serialization, cloning,
    /// nor construction from an explicit value of the nonce, in order to
    /// prevent accidental reuse of the nonce. Callers should carefully consider
    /// how to store the verifier instance until presentation verification.
    ///
    /// # Errors
    ///
    /// This constructor will only fail if sampling of the nonce fails.
    pub fn new<R: CryptoRngCore + ?Sized>(aud: String, nonce_rng: &mut R) -> Result<Self> {
        let nonce = generate_nonce(nonce_rng)?;

        Ok(Self::from_challenge(KeyBindingChallenge { aud, nonce }))
    }

    /// Constructs a [`Verifier`] for an existing presentation exchange session.
    ///
    /// The provided [`KeyBindingChallenge`] is under complete control of the
    /// caller, which might be a security risk. If this is not desired, take a
    /// look at [`Verifier::new`] associated function.
    ///
    /// # Note
    /// The caller of this function needs to ensure that the `nonce` value
    /// provided within the [`KeyBindingChallenge`] **WILL NOT** be reused.
    pub fn from_challenge(challenge: KeyBindingChallenge) -> Self {
        Self { challenge }
    }

    /// Return the challenge to be sent to the holder. The purpose of the
    /// challenge is to ensure the freshness of the key binding signature, as
    /// well as the proper audience, in order to prevent credential replay attacks.
    pub fn key_binding_challenge(&self) -> &KeyBindingChallenge {
        &self.challenge
    }

    /// Verify the provided SD-JWT+KB presentation, returning the reconstructed
    /// payload, an algorithm used to sign the JWT, and the resolved public key
    /// of the SD-JWT Issuer in the JWK format.
    ///
    /// # Key Binding
    ///
    /// This function will verify key binding, using the public JWK contained in
    /// the issuer-signed JWT's `cnf` claim, and comparing the `aud` and `nonce`
    /// claims in the KB JWT against the challenge values created on
    /// construction.
    ///
    /// The validation of the `iat` claim in the KB JWT will be done against
    /// `current_time`, accepting only values of `iat` within the previous 5 min
    /// (this is currently chosen arbitrarily).
    ///
    /// # Lifecycle
    ///
    /// This method must take ownership of the [`Verifier`] to destroy the
    /// nonce value used in this presentation exchange session, in order to prevent
    /// accidental reuse.
    ///
    /// # Cryptography
    ///
    /// The caller needs to provide an implementation of a [`Hasher`] for every
    /// algorithm they want to support, using the `get_hasher` argument. If the
    /// received payload uses an algorithm whose [`Hasher`] the caller did not
    /// provide, an error will be returned.
    ///
    /// # Arguments
    /// - `sd_jwt_kb`: SD-JWT+KB presentation to verify,
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
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.1.1-3
    pub async fn verify<'a>(
        self,
        sd_jwt_kb: SdJwtKB,
        issuer_public_key_lookup: &impl IssuerPublicKeyLookup,
        current_time: SecondsSinceEpoch,
        get_hasher: impl Fn(HashingAlgorithm) -> Option<Box<dyn Hasher>>,
        get_signature_verifier: impl Fn(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
    ) -> Result<(IssuerJwt, SigningAlgorithm, JwkPublic)> {
        let (verified_sd_jwt, signing_algorithm, issuer_public_key) = sd_jwt_kb
            .sd_jwt
            .to_signature_verified_sd_jwt(issuer_public_key_lookup, &get_signature_verifier)
            .await
            .match_err(|crate_error| crate_error.to_verifier_error())?;

        let decoded_sd_jwt = verified_sd_jwt
            .into_decoded(get_hasher)
            .match_err(|crate_error| crate_error.to_verifier_error())?;

        sd_jwt_kb.verify_key_binding_jwt(
            decoded_sd_jwt.hasher(),
            decoded_sd_jwt.key_binding_public_key(),
            &self.challenge,
            current_time,
            get_signature_verifier,
        )?;

        let claims = decoded_sd_jwt.into_claims();

        // Validate the additional `SD-JWT-VC` claims
        claims.validate_claims_verifier(current_time)?;

        Ok((claims, signing_algorithm, issuer_public_key))
    }
}

/// Generates a `nonce` value.
///
/// The `nonce` is generated as a random, `base64-url` encoded `String` with 256
/// bits of entropy.
///
/// # Error
/// If the `nonce` generation fails, [`VerifierError::NonceGenerationFailed`] is
/// returned.
pub fn generate_nonce<R: CryptoRngCore + ?Sized>(nonce_rng: &mut R) -> Result<String> {
    let mut nonce_bytes = [0u8; 32];
    nonce_rng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|err| bherror::Error::root(VerifierError::NonceGenerationFailed).ctx(err))?;
    Ok(base64_url_encode(nonce_bytes))
}

#[cfg(test)]
mod tests {

    use rand::thread_rng;

    use super::*;
    use crate::{
        holder::tests::test_holder, key_binding::KB_JWT_EXPIRATION_OFFSET,
        test_utils::dummy_key_binding_audience, SHA_256_ALG_NAME,
    };

    fn test_verifier() -> Verifier {
        Verifier::new(dummy_key_binding_audience(), &mut thread_rng()).unwrap()
    }

    use serde_json::json;

    use crate::{
        into_object,
        issuer::tests::{dummy_claims, dummy_https_iss, test_issuer_jwt},
        test_utils::{
            dummy_hasher_factory, dummy_public_key_lookup, header_public_key_lookup,
            symbolic_crypto::{dummy_public_jwk, StubSigner, StubVerifier},
        },
    };

    #[tokio::test]
    async fn invalid_presentation_missing_signature_verifier() {
        let verifier = test_verifier();
        let challenge = verifier.key_binding_challenge();
        let iat = 100;

        let holder = test_holder(test_issuer_jwt(), StubVerifier::default(), iat).await;
        let presentation = holder
            .present(&[], challenge.clone(), iat, &StubSigner::default())
            .unwrap();

        let invalid_verify = verifier
            .verify(
                presentation,
                &dummy_public_key_lookup(),
                iat,
                dummy_hasher_factory,
                |_| None, // this is the line causing InvalidPresentation
            )
            .await;
        assert_eq!(
            invalid_verify.unwrap_err().error,
            VerifierError::Signature(SignatureError::MissingSignatureVerifier(
                SigningAlgorithm::Es256
            ))
        );
    }

    #[tokio::test]
    async fn invalid_presentation_mismatched_algorithm() {
        let verifier = test_verifier();
        let challenge = verifier.key_binding_challenge();
        let iat = 100;

        let holder = test_holder(test_issuer_jwt(), StubVerifier::default(), iat).await;
        let presentation = holder
            .present(&[], challenge.clone(), iat, &StubSigner::default())
            .unwrap();

        let public_jwk_wrong = into_object(json!({
            "kid": "test key id",
            "alg": "ES512" // this is set to ES512, the signature algorithm should be ES256
        }));
        let signature_verifier = StubVerifier::new(public_jwk_wrong); // uses different algorithm than signer
        let invalid_verify = verifier
            .verify(
                presentation,
                &dummy_public_key_lookup(),
                iat,
                dummy_hasher_factory,
                |_| Some(&signature_verifier),
            )
            .await;
        assert_eq!(
            invalid_verify.unwrap_err().error,
            VerifierError::Signature(SignatureError::InvalidJwtSignature)
        );
    }

    #[tokio::test]
    async fn invalid_presentation_invalid_signature() {
        let verifier = test_verifier();
        let challenge = verifier.key_binding_challenge();
        let iat = 100;

        let holder = test_holder(test_issuer_jwt(), StubVerifier::default(), iat).await;
        let mut sd_jwk_kb = holder
            .present(&[], challenge.clone(), iat, &StubSigner::default())
            .unwrap();

        // signature is last part of jwt, change it to be invalid
        let last_ch_signature = sd_jwk_kb.sd_jwt.jwt.pop().unwrap();
        let wrong_ch = if last_ch_signature == '0' { '1' } else { '0' };

        sd_jwk_kb.sd_jwt.jwt.push(wrong_ch);

        let signature_verifier = StubVerifier::default();
        let invalid_verify = verifier
            .verify(
                sd_jwk_kb,
                &dummy_public_key_lookup(),
                iat,
                dummy_hasher_factory,
                |_| Some(&signature_verifier),
            )
            .await;
        assert_eq!(
            invalid_verify.unwrap_err().error,
            VerifierError::Signature(SignatureError::InvalidJwtSignature)
        );
    }

    #[tokio::test]
    async fn invalid_presentation_missing_hasher() {
        let verifier = test_verifier();
        let challenge = verifier.key_binding_challenge();
        let iat = 100;

        let holder = test_holder(test_issuer_jwt(), StubVerifier::default(), iat).await;
        let presentation = holder
            .present(&[], challenge.clone(), iat, &StubSigner::default())
            .unwrap();

        let signature_verifier = StubVerifier::default();
        let invalid_verify = verifier
            .verify(
                presentation,
                &dummy_public_key_lookup(),
                iat,
                |_| None, // missing hasher
                |_| Some(&signature_verifier),
            )
            .await;
        assert_eq!(
            invalid_verify.unwrap_err().error,
            VerifierError::Decoding(DecodingError::MissingHasher(SHA_256_ALG_NAME.to_string()))
        );
    }

    #[tokio::test]
    async fn key_binding_invalid_kbjwt_signature() {
        let iat = 100;
        let holder = test_holder(test_issuer_jwt(), StubVerifier::default(), iat).await;

        let verifier = test_verifier();
        let challenge = verifier.key_binding_challenge();

        let mut sd_jwt_kb = holder
            .present(&[], challenge.clone(), iat, &StubSigner::default())
            .unwrap();

        sd_jwt_kb.key_binding_jwt.pop();
        sd_jwt_kb.key_binding_jwt.push('1');

        let signature_verifier = StubVerifier::default();
        let invalid_verify = verifier
            .verify(
                sd_jwt_kb,
                &header_public_key_lookup(),
                iat,
                dummy_hasher_factory,
                |_| Some(&signature_verifier),
            )
            .await;
        assert_eq!(
            invalid_verify.unwrap_err().error,
            VerifierError::KeyBinding(KBError::InvalidKBJwtSignature)
        );
    }

    #[tokio::test]
    async fn key_binding_expired() {
        let iat = 100;
        let holder = test_holder(test_issuer_jwt(), StubVerifier::default(), iat).await;

        let verifier = test_verifier();
        let challenge = verifier.key_binding_challenge();

        let presentation = holder
            .present(&[], challenge.clone(), iat, &StubSigner::default())
            .unwrap();

        let signature_verifier = StubVerifier::default();
        let current_time = iat + 5 * 60 + 10; // should cause expiration of key binding because KB_JWT_EXPIRATION_OFFSET is 5 * 60
        let invalid_verify = verifier
            .verify(
                presentation,
                &dummy_public_key_lookup(),
                current_time,
                dummy_hasher_factory,
                |_| Some(&signature_verifier),
            )
            .await;
        assert_eq!(
            invalid_verify.unwrap_err().error,
            VerifierError::KeyBinding(KBError::KBJwtExpired(
                iat,
                KB_JWT_EXPIRATION_OFFSET,
                current_time
            ))
        );
    }

    #[tokio::test]
    async fn key_binding_invalid_kbjwt_nonce() {
        let iat = 100;
        let holder = test_holder(test_issuer_jwt(), StubVerifier::default(), iat).await;

        let verifier = test_verifier();
        let mut challenge = verifier.key_binding_challenge().clone();

        challenge.nonce.pop();
        challenge.nonce.push('1'); // presentation uses different challenge than the verifier provided

        let presentation_challenge_nonce = challenge.nonce.clone();

        let presentation = holder
            .present(&[], challenge.clone(), iat, &StubSigner::default())
            .unwrap();

        let signature_verifier = StubVerifier::default();
        let invalid_verify = verifier
            .verify(
                presentation,
                &header_public_key_lookup(),
                iat,
                dummy_hasher_factory,
                |_| Some(&signature_verifier),
            )
            .await;
        assert_eq!(
            invalid_verify.unwrap_err().error,
            VerifierError::KeyBinding(KBError::InvalidKBJwtNonce(presentation_challenge_nonce))
        );
    }

    #[tokio::test]
    async fn key_binding_invalid_kbjwt_aud() {
        let iat = 100;
        let holder = test_holder(test_issuer_jwt(), StubVerifier::default(), iat).await;

        let verifier = test_verifier();
        let mut challenge = verifier.key_binding_challenge().clone();

        let original_aud = challenge.aud.clone();

        challenge.aud.pop();
        challenge.aud.push('1'); // presentation uses different challenge than the verifier provided

        let presentation_challenge_aud = challenge.aud.clone();

        let presentation = holder
            .present(&[], challenge, iat, &StubSigner::default())
            .unwrap();

        let signature_verifier = StubVerifier::default();
        let invalid_verify = verifier
            .verify(
                presentation,
                &header_public_key_lookup(),
                iat,
                dummy_hasher_factory,
                |_| Some(&signature_verifier),
            )
            .await;
        assert_eq!(
            invalid_verify.unwrap_err().error,
            VerifierError::KeyBinding(KBError::InvalidKBJwtAud(
                presentation_challenge_aud,
                original_aud,
            ))
        );
    }

    #[tokio::test]
    async fn nbf_in_future() {
        let mut issuer_jwt = IssuerJwt::new(
            "TestCredential".into(),
            dummy_https_iss(),
            dummy_public_jwk(),
            dummy_claims(),
        )
        .unwrap();

        let iat = 100;
        let nbf = iat + 50;
        issuer_jwt.nbf = Some(nbf); // set nbf (not before) to future

        let holder = test_holder(issuer_jwt, StubVerifier::default(), iat).await;

        let verifier = test_verifier();
        let challenge = verifier.key_binding_challenge();

        let presentation = holder
            .present(&[], challenge.clone(), iat, &StubSigner::default())
            .unwrap();

        let signature_verifier = StubVerifier::default();
        let invalid_verify = verifier
            .verify(
                presentation,
                &header_public_key_lookup(),
                iat,
                dummy_hasher_factory,
                |_| Some(&signature_verifier),
            )
            .await;
        assert_eq!(
            invalid_verify.unwrap_err().error,
            VerifierError::JwtNotYetValid(iat, nbf)
        );
    }

    #[tokio::test]
    async fn presentation_expired() {
        let mut issuer_jwt = IssuerJwt::new(
            "TestCredential".into(),
            dummy_https_iss(),
            dummy_public_jwk(),
            dummy_claims(),
        )
        .unwrap();

        let iat = 100;
        let expiration_time = iat + 15;
        let verify_time = iat + 20;

        issuer_jwt.exp = Some(expiration_time);

        let holder = test_holder(issuer_jwt, StubVerifier::default(), iat).await;

        let verifier = test_verifier();
        let challenge = verifier.key_binding_challenge();

        let presentation = holder
            .present(&[], challenge.clone(), iat, &StubSigner::default())
            .unwrap();

        let signature_verifier = StubVerifier::default();
        let invalid_verify = verifier
            .verify(
                presentation,
                &header_public_key_lookup(),
                verify_time,
                dummy_hasher_factory,
                |_| Some(&signature_verifier),
            )
            .await;
        assert_eq!(
            invalid_verify.unwrap_err().error,
            VerifierError::JwtExpired(verify_time, expiration_time)
        );
    }

    mod integration {

        use JsonNodePathSegment::*;

        use super::*;
        use crate::{
            issuer::tests::{test_issuer_jwt, TEST_DISCLOSURE_PATHS as TEST_PATHS},
            paths_exist,
            test_utils::{
                dummy_hasher_factory, dummy_public_key_lookup,
                symbolic_crypto::{StubSigner, StubVerifier},
            },
            JsonNodePath, JsonNodePathSegment,
        };

        #[tokio::test]
        async fn holder_verifier_happy_path() {
            let iat = 100;
            let holder = test_holder(test_issuer_jwt(), StubVerifier::default(), iat).await;

            struct TestCase<'a> {
                requested_claims: &'a [&'a JsonNodePath<'a>],
                not_to_be_disclosed_claims: &'a [&'a JsonNodePath<'a>],
                implied_paths: &'a [&'a JsonNodePath<'a>],
            }

            let test_cases = &[
                TestCase {
                    requested_claims: &[],
                    not_to_be_disclosed_claims: TEST_PATHS,
                    implied_paths: &[
                        // non-selectively disclosable claim in the root object
                        &["baz".into()],
                    ],
                },
                TestCase {
                    requested_claims: TEST_PATHS,
                    not_to_be_disclosed_claims: &[],
                    implied_paths: &[
                        // non-selectively disclosable claim in the root object
                        &["baz".into()],
                    ],
                },
                TestCase {
                    requested_claims: &[&[Key("foo")]],
                    not_to_be_disclosed_claims: &[
                        // the only other disclosure at this level + ancestor of
                        // all other disclosures
                        &[Key("parent")],
                    ],
                    implied_paths: &[
                        // non-selectively disclosable claim in the root object
                        &["baz".into()],
                    ],
                },
                TestCase {
                    requested_claims: &[&[Key("parent")]],
                    not_to_be_disclosed_claims: &[
                        &[Key("foo")],
                        // NB: difficult to test for absence of `$.parent.child1[1]`
                        // form the original as the subsequent array entry from the
                        // original will exist at that path in the reconstruction
                        // &[Key("parent"), Key("child1"), Index(1)],
                        &[Key("parent"), Key("child2"), Key("leaf")],
                        &[Key("parent"), Key("child2"), Key("foo")],
                        &[Key("parent"), Key("child3")],
                    ],
                    implied_paths: &[
                        // non-selectively disclosable claim in the root object
                        &["baz".into()],
                    ],
                },
                TestCase {
                    requested_claims: &[&[Key("parent"), Key("child1"), Index(1)]],
                    not_to_be_disclosed_claims: &[
                        &[Key("foo")],
                        &[Key("parent"), Key("child2"), Key("leaf")],
                        &[Key("parent"), Key("child2"), Key("foo")],
                        &[Key("parent"), Key("child3")],
                    ],
                    implied_paths: &[
                        // non-selectively disclosable claim in the root object
                        &["baz".into()],
                        // ancestor of &[Key("parent"), Key("child1"), Index(1)]
                        &[Key("parent")],
                        // non-selectively-disclosable siblings within the same
                        // array as &[Key("parent"), Key("child1"), Index(1)]
                        &["parent".into(), "child1".into(), 0.into()],
                        &["parent".into(), "child1".into(), 2.into()],
                        &["parent".into(), "child1".into(), 3.into()],
                    ],
                },
                TestCase {
                    requested_claims: &[&[Key("parent"), Key("child2"), Key("leaf")]],
                    not_to_be_disclosed_claims: &[
                        &[Key("foo")],
                        // NB: difficult to test for absence of `$.parent.child1[1]`
                        // form the original as the subsequent array entry from the
                        // original will exist at that path in the reconstruction
                        // &[Key("parent"), Key("child1"), Index(1)],
                        &[Key("parent"), Key("child2"), Key("foo")],
                        &[Key("parent"), Key("child3")],
                    ],
                    implied_paths: &[
                        // non-selectively disclosable claim in the root object
                        &["baz".into()],
                        // ancestor of &[Key("parent"), Key("child2"), Key("leaf")]
                        &[Key("parent")],
                    ],
                },
                TestCase {
                    requested_claims: &[
                        &[Key("foo")],
                        &[Key("parent"), Key("child1"), Index(1)],
                        &[Key("parent"), Key("child2"), Key("foo")],
                    ],
                    not_to_be_disclosed_claims: &[
                        &[Key("parent"), Key("child2"), Key("leaf")],
                        &[Key("parent"), Key("child3")],
                    ],
                    implied_paths: &[
                        // non-selectively disclosable claim in the root object
                        &["baz".into()],
                        // ancestor of &[Key("parent"), Key("child1"), Index(1)] and &[Key("parent"), Key("child2"), Key("foo")],
                        &[Key("parent")],
                        // non-selectively-disclosable siblings within the same
                        // array as &[Key("parent"), Key("child1"), Index(1)]
                        &["parent".into(), "child1".into(), 0.into()],
                        &["parent".into(), "child1".into(), 2.into()],
                        &["parent".into(), "child1".into(), 3.into()],
                    ],
                },
                TestCase {
                    requested_claims: &[
                        // non-selectively disclosable claim in the root object
                        &["baz".into()],
                    ],
                    not_to_be_disclosed_claims: TEST_PATHS,
                    implied_paths: &[],
                },
                TestCase {
                    requested_claims: &[
                        &[Key("parent"), Key("child1"), Index(1)],
                        &[Key("parent"), Key("child1"), Index(3), Key("nested")],
                    ],
                    not_to_be_disclosed_claims: &[
                        &[Key("foo")],
                        &[Key("parent"), Key("child2"), Key("leaf")],
                        &[Key("parent"), Key("child3")],
                    ],
                    implied_paths: &[
                        // non-selectively disclosable claim in the root object
                        &["baz".into()],
                        // ancestor of &[Key("parent"), Key("child1"), Index(1)] and &[Key("parent"), Key("child2"), Key("foo")],
                        &[Key("parent")],
                        // non-selectively-disclosable siblings within the same
                        // array as &[Key("parent"), Key("child1"), Index(3)]
                        &[Key("parent"), Key("child1"), Index(2)],
                        &[Key("parent"), Key("child1"), Index(3)],
                    ],
                },
            ];

            for TestCase {
                requested_claims,
                not_to_be_disclosed_claims,
                implied_paths,
            } in test_cases
            {
                let verifier = test_verifier();
                let challenge = verifier.key_binding_challenge();

                let presentation = holder
                    .present(
                        requested_claims,
                        challenge.clone(),
                        iat,
                        &StubSigner::default(),
                    )
                    .unwrap();

                let signature_verifier = StubVerifier::default();
                let reconstructed = verifier
                    .verify(
                        presentation,
                        &dummy_public_key_lookup(),
                        iat,
                        dummy_hasher_factory,
                        |_| Some(&signature_verifier),
                    )
                    .await
                    .unwrap()
                    .0;

                let reconstructed = reconstructed.to_object();

                paths_exist(&reconstructed, requested_claims).expect("Requested path(s) missing");
                paths_exist(&reconstructed, implied_paths)
                    .expect("Indirectly requested path(s) missing");

                for not_to_be_disclosed_path in *not_to_be_disclosed_claims {
                    paths_exist(&reconstructed, &[not_to_be_disclosed_path]).expect_err(
                        "Some non-requested selectively disclosable paths \
                        (and not indirectly implied by the request) are present",
                    );
                }
            }
        }
    }
}

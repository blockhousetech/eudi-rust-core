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

//! This module provides the [`Verifier`] type which is used to verify issued `mDoc` Credentials.

use bh_jws_utils::{JwkPublic, SignatureVerifier, SigningAlgorithm};
use bh_status_list::StatusClaim;
use bhx5chain::X509Trust;
use rand::Rng;

use crate::{
    models::{
        data_retrieval::{device_retrieval::response::Document, Claims},
        DeviceResponse,
    },
    utils::rand::generate_nonce,
    MdocError, Result,
};

/// Verifier of issued `mDoc` Credentials.
pub struct Verifier {
    client_id: String,
    response_uri: String,
    nonce: String,
}

/// Claims as verified by the [`Verifier`].
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub struct VerifiedClaims {
    /// The actual claims of the credential.
    pub claims: Claims,

    /// The pointer to the status of the credential within the corresponding
    /// status list.
    pub status: Option<StatusClaim>,
}

impl Verifier {
    /// Creates a new [`Verifier`].
    ///
    /// It will also create a new `nonce` value used by this verifier to later
    /// successfully verify a device signature. The provided `nonce_rng` will be
    /// used to generate that `nonce`.
    ///
    /// If you wish to provide your own `nonce` value, use [`Verifier::from_parts`].
    pub fn new<R: Rng + ?Sized>(
        client_id: String,
        response_uri: String,
        nonce_rng: &mut R,
    ) -> Self {
        let nonce = generate_nonce(nonce_rng);
        Self::from_parts(client_id, response_uri, nonce)
    }

    /// Create a new [`Verifier`] but with the provided `nonce` value.
    ///
    /// If you don't want to explicitly provide the `nonce` value, you may use [`Verifier::new`]
    /// which will generate it.
    pub fn from_parts(client_id: String, response_uri: String, nonce: String) -> Self {
        Self {
            client_id,
            response_uri,
            nonce,
        }
    }

    /// Verifies, extracts and returns the claims from the `mDoc` credential.
    ///
    /// One can optionally provide a [`X509Trust`], in which case, the
    /// authenticity of the Issuer will be verified against that `trust`. If
    /// `trust` is set to [`None`], the authenticity of the Issuer **WILL NOT**
    /// be verified.
    ///
    /// If the [`DeviceResponse`] was sent **encrypted** to the [`Verifier`],
    /// the `jwk_public` argument **MUST BE** the [`Verifier`]'s public JWK used
    /// to encrypt the response. Otherwise, it **MUST BE** [`None`].
    ///
    /// # Error
    ///
    /// An error is returned if the provided [`DeviceResponse`] does not contain
    /// any [`Document`]s or if there was an error during the verification
    /// process.
    pub fn verify<'a>(
        self,
        device_response: DeviceResponse,
        current_time: u64,
        jwk_public: Option<&JwkPublic>,
        trust: Option<&X509Trust>,
        get_signature_verifier: impl Fn(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
    ) -> Result<Vec<VerifiedClaims>> {
        device_response
            .into_documents()
            .ok_or_else(|| bherror::Error::root(MdocError::EmptyDeviceResponse))?
            .into_iter()
            .map(|document| {
                self.document_verify_into_claims(
                    document,
                    jwk_public,
                    trust,
                    &get_signature_verifier,
                    current_time,
                )
            })
            .collect::<Result<_>>()
    }

    /// Gets the `nonce` value as `&str`.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Returns the data elements from the provided [`Document`], while
    /// performing the necessary verifications.
    fn document_verify_into_claims<'a>(
        &self,
        document: Document,
        jwk_public: Option<&JwkPublic>,
        trust: Option<&X509Trust>,
        get_signature_verifier: impl Fn(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
        current_time: u64,
    ) -> Result<VerifiedClaims> {
        document.verify(
            &self.client_id,
            &self.response_uri,
            self.nonce(),
            jwk_public,
            trust,
            get_signature_verifier,
        )?;

        document.validate(current_time)?;

        Ok(VerifiedClaims {
            status: document.status()?,
            claims: document.into_claims(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bh_jws_utils::Es256Verifier;

    use super::*;
    use crate::{
        models::mdl::MDL_NAMESPACE,
        utils::test::{issuer_x509_trust, present_dummy_mdoc},
    };

    #[test]
    fn test_verify_successful_with_trust() {
        let verifier = Verifier::from_parts(
            "client_id".to_owned(),
            "response_uri".to_owned(),
            "nonce".to_owned(),
        );

        let device_response = present_dummy_mdoc(100, None, None);

        let expected_claims = vec![VerifiedClaims {
            claims: Claims(HashMap::from([(
                MDL_NAMESPACE.into(),
                HashMap::from([("lastName".into(), "Doe".into())]),
            )])),
            status: None,
        }];

        let trust = issuer_x509_trust();

        let claims = verifier
            .verify(device_response, 105, None, Some(&trust), |_| {
                Some(&Es256Verifier)
            })
            .unwrap();

        assert_eq!(expected_claims, claims);
    }

    #[test]
    fn test_verify_fails_issuer_not_trusted() {
        let verifier = Verifier::from_parts(
            "client_id".to_owned(),
            "response_uri".to_owned(),
            "nonce".to_owned(),
        );

        let device_response = present_dummy_mdoc(100, None, None);

        // no Issuer is trusted (empty `trust`)
        let trust = X509Trust::new(vec![]);

        let err = verifier
            .verify(device_response, 105, None, Some(&trust), |_| {
                Some(&Es256Verifier)
            })
            .unwrap_err();

        assert_eq!(err.error, MdocError::X5Chain);
    }

    #[test]
    fn test_verify_successful_no_trust() {
        let verifier = Verifier::from_parts(
            "client_id".to_owned(),
            "response_uri".to_owned(),
            "nonce".to_owned(),
        );

        let device_response = present_dummy_mdoc(100, None, None);

        let expected_claims = vec![VerifiedClaims {
            claims: Claims(HashMap::from([(
                MDL_NAMESPACE.into(),
                HashMap::from([("lastName".into(), "Doe".into())]),
            )])),
            status: None,
        }];

        // every Issuer is trusted (`trust` not provided)
        let claims = verifier
            .verify(device_response, 105, None, None, |_| Some(&Es256Verifier))
            .unwrap();

        assert_eq!(expected_claims, claims);
    }

    #[test]
    fn test_verify_successful_with_status() {
        let verifier = Verifier::from_parts(
            "client_id".to_owned(),
            "response_uri".to_owned(),
            "nonce".to_owned(),
        );

        let device_response = present_dummy_mdoc(
            100,
            Some(StatusClaim::new(
                "https://example.com/status-list".parse().unwrap(),
                74,
            )),
            None,
        );

        let expected_claims = vec![VerifiedClaims {
            claims: Claims(HashMap::from([(
                MDL_NAMESPACE.into(),
                HashMap::from([("lastName".into(), "Doe".into())]),
            )])),
            status: Some(StatusClaim::new(
                "https://example.com/status-list".parse().unwrap(),
                74,
            )),
        }];

        // every Issuer is trusted (`trust` not provided)
        let claims = verifier
            .verify(device_response, 105, None, None, |_| Some(&Es256Verifier))
            .unwrap();

        assert_eq!(expected_claims, claims);
    }

    #[test]
    fn test_verify_with_jwk_public_success() {
        let jwk_public = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "Nd4Fg0Yp6UaNe2Kv8RcXt9kLm3Qw7Zx2Vc8Bn5Hs1Jd",
            "y": "Wp2Ls9Xd4Rf6Hy1Nm3Tq7Vb0Zj5UgPe4Ka9Mn2QorT8k",
        });
        let jwk_public = jwk_public.as_object().unwrap();

        let verifier = Verifier::from_parts(
            "client_id".to_owned(),
            "response_uri".to_owned(),
            "nonce".to_owned(),
        );

        let device_response = present_dummy_mdoc(100, None, Some(jwk_public));

        let expected_claims = vec![VerifiedClaims {
            claims: Claims(HashMap::from([(
                MDL_NAMESPACE.into(),
                HashMap::from([("lastName".into(), "Doe".into())]),
            )])),
            status: None,
        }];

        // every Issuer is trusted (`trust` not provided)
        let claims = verifier
            .verify(device_response, 105, Some(jwk_public), None, |_| {
                Some(&Es256Verifier)
            })
            .unwrap();

        assert_eq!(expected_claims, claims);
    }
}

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

//! This module defines a [`Device`] type that works with an issued Credential.

use bh_jws_utils::{SignatureVerifier, SigningAlgorithm};
use bherror::traits::ForeignBoxed as _;

use crate::{
    models::{
        data_retrieval::{
            common::DocType,
            device_retrieval::{
                issuer_auth::ValidityInfo,
                request::DeviceRequest,
                response::{DeviceSigned, Document, IssuerNameSpaces, IssuerSigned},
            },
            BorrowedClaims, Claims,
        },
        DeviceResponse,
    },
    DeviceKey, MdocError, Result,
};

/// This represents an `mDoc` device.
///
/// The device is currently able to accept the issued credential and return the
/// claims from that credential.
#[derive(Debug)]
pub struct Device {
    doc_type: DocType,
    issuer_signed: IssuerSigned,
}

impl Device {
    /// Return the document type.
    ///
    /// In the context of OpenID for [Verifiable Presentations][1] and [Verifiable Credential
    /// Issuance][2] this identifies the type of the Credential.
    ///
    /// [1]: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>
    /// [2]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>
    pub fn doc_type(&self) -> &DocType {
        &self.doc_type
    }

    /// Accepts the issued `mDoc` (param. `issuer_signed`) after performing all the necessary
    /// validations.
    ///
    /// The provided credential **MUST BE** _CBOR_-serialized and _base64url_-encoded (**without
    /// padding**) string.
    ///
    /// The following validations are performed.
    ///
    /// - The Issuer's signature must verify successfully.
    /// - The Credential must not be expired.
    /// - The provided `doc_type` must match the signed one.
    /// - The hashes of the provided claims must be signed.
    pub fn verify_issued<'a>(
        issuer_signed: &str,
        doc_type: DocType,
        current_time: u64,
        get_signature_verifier: impl Fn(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
    ) -> Result<Self> {
        let issuer_signed = IssuerSigned::from_base64_url(issuer_signed)?;

        // `trust: None` => Device does not verify the Issuer's authenticity
        issuer_signed.verify_signature(None, get_signature_verifier)?;

        issuer_signed.validate_device(current_time, &doc_type)?;

        Ok(Self {
            doc_type,
            issuer_signed,
        })
    }

    /// Creates a Verifiable Presentation of the owned Credential.
    ///
    /// The claims are selectively disclosed as requested within the provided
    /// [`DeviceRequest`]. The [`IntentToRetain`][crate::models::IntentToRetain]
    /// **IS NOT** taken into account when disclosing claims.
    ///
    /// If the owned [`DocType`] is not requested within the [`DeviceRequest`],
    /// an _empty_ [`DeviceResponse`] will be returned. If no existing claims
    /// are selected, a [`Document`] with no claims will be returned, but it
    /// will include both the Issuer's and the Device's signature.
    ///
    /// Non-existent [`DocType`]s, [`NameSpace`][crate::models::NameSpace]s and
    /// claims requested within the [`DeviceRequest`] will be ignored as
    /// specified in the `Section 8.3.2.2.2.1` of the [ISO/IEC 18013-5:2021][1].
    ///
    /// All the disclosed claims will also be signed by the [`Device`].
    ///
    /// The underlying `status` will always be set to `0` (_OK_) as per `Table
    /// 8` of the [ISO/IEC 18013-5:2021][1], since the errors are returned
    /// within the `Result`.
    ///
    /// # Errors
    ///
    /// The method can result with the following errors:
    /// - [`DeviceAuthentication`][MdocError::DeviceAuthentication] if the
    ///   payload for the Device's signature fails to compute,
    /// - [`Signing`][MdocError::Signing] if the Device's signature fails to
    ///   compute,
    /// - [`DocumentExpired`][MdocError::DocumentExpired] if the underlying
    ///   [`Document`] expired,
    /// - [`DocumentNotYetValid`][MdocError::DocumentNotYetValid] if the
    ///   underlying [`Document`] is not valid yet,
    /// - [`InvalidDeviceSigner`][MdocError::InvalidDeviceSigner] if the
    ///   provided `mdoc` Device [`Signer`][bh_jws_utils::Signer] does not match
    ///   the signed public key of the `mdoc` Device.
    ///
    /// # Notes
    ///
    /// This will present **AT MOST ONE** [`Document`], because currently the
    /// nature of the [`Device`] is to hold only a single [`Document`].
    ///
    /// The [`ReaderAuth`][crate::models::ReaderAuth] from the [`DeviceRequest`]
    /// **IS NOT** verified.
    ///
    /// [1]: <https://www.iso.org/standard/69084.html>
    #[allow(clippy::too_many_arguments)]
    pub fn present(
        &self,
        current_time: u64,
        request: &DeviceRequest,
        client_id: &str,
        response_uri: &str,
        nonce: &str,
        mdoc_generated_nonce: &str,
        signer: &impl bh_jws_utils::Signer,
    ) -> Result<DeviceResponse> {
        // the provided `signer` must match the signed device public key
        self.check_device_key(signer)?;

        // find the appropriate `DocRequest` based on the `doc_type`
        let Some(doc_request) = request.find_by_doc_type(&self.doc_type) else {
            // if the `doc_type` is absent, return the empty `DeviceResponse`
            return Ok(DeviceResponse::new(Vec::new()));
        };

        // create a new `IssuerSigned` with the selected claims
        let issuer_signed = self
            .issuer_signed
            .filtered_claims(doc_request.name_spaces());

        // sign all the claims with the device as well
        let device_name_spaces = issuer_signed
            .name_spaces
            .as_ref()
            .map(IssuerNameSpaces::to_device_name_spaces)
            .unwrap_or_default();

        // create a `DeviceSigned`, i.e. key-binding
        let device_signed = DeviceSigned::new(
            device_name_spaces,
            client_id,
            response_uri,
            nonce,
            mdoc_generated_nonce,
            &self.doc_type,
            signer,
        )?;

        let document = Document::new(self.doc_type.clone(), issuer_signed, device_signed);

        // perform non-signature validations, e.g. don't present expired or
        // not-yet-valid credential
        document.validate(current_time)?;

        Ok(DeviceResponse::new(vec![document]))
    }

    /// Consumes `self` to extract and return the [`Claims`].
    pub fn into_claims(self) -> (DocType, Claims) {
        (self.doc_type, self.issuer_signed.into_claims())
    }

    /// Extracts and returns the [`BorrowedClaims`].
    pub fn claims(&self) -> (&DocType, BorrowedClaims<'_>) {
        (&self.doc_type, self.issuer_signed.claims())
    }

    /// Returns the [`ValidityInfo`] of the underlying credential.
    pub fn validity_info(&self) -> Result<ValidityInfo> {
        self.issuer_signed.issuer_auth.validity_info()
    }

    /// Verify that the [`DeviceKey`] signed by the `mdoc` Issuer matches the
    /// one from the provided `signer`.
    fn check_device_key(&self, signer: &impl bh_jws_utils::Signer) -> Result<()> {
        let mut signed_device_key = self.issuer_signed.device_key()?;
        signed_device_key.canonicalize();

        let mut signer_device_key =
            DeviceKey::from_jwk(&signer.public_jwk().foreign_boxed_err(|| {
                MdocError::InvalidDeviceSigner("unable to fetch public JWK".to_owned())
            })?)?;
        signer_device_key.canonicalize();

        if signed_device_key != signer_device_key {
            return Err(bherror::Error::root(MdocError::InvalidDeviceSigner(
                "public key does not match the signed one".to_owned(),
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use assert_matches::assert_matches;
    use bh_jws_utils::Es256Verifier;

    use super::*;
    use crate::{
        models::{
            data_retrieval::device_retrieval::request::DocRequest,
            mdl::{MDL_DOCUMENT_TYPE, MDL_NAMESPACE},
        },
        utils::test::{issue_dummy_mdoc, issue_dummy_mdoc_to_device, SimpleSigner},
        MdocError, Verifier,
    };

    #[test]
    fn test_verify_issued_success() {
        let issued = issue_dummy_mdoc(100);

        let device = Device::verify_issued(
            &issued.serialize_issuer_signed().unwrap(),
            MDL_DOCUMENT_TYPE.into(),
            105,
            |_| Some(&Es256Verifier),
        )
        .unwrap();

        let (doc_type, claims) = device.into_claims();

        let expected_claims = Claims(HashMap::from([(
            MDL_NAMESPACE.into(),
            HashMap::from([
                ("firstName".into(), "John".into()),
                ("lastName".into(), "Doe".into()),
            ]),
        )]));

        assert_eq!(DocType::from(MDL_DOCUMENT_TYPE), doc_type);
        assert_eq!(expected_claims.0, claims.0);
    }

    #[test]
    fn test_verify_issued_parse_fail() {
        let err = Device::verify_issued("<INVALID-MDOC>", MDL_DOCUMENT_TYPE.into(), 100, |_| None)
            .unwrap_err();

        assert_matches!(err.error, MdocError::IssuerSignedParse);
    }

    #[test]
    fn test_verify_issued_expired_fails() {
        let issued = issue_dummy_mdoc(100);

        let err = Device::verify_issued(
            &issued.serialize_issuer_signed().unwrap(),
            MDL_DOCUMENT_TYPE.into(),
            100 + 400 * 24 * 60 * 60, // 400 days after issuance
            |_| Some(&Es256Verifier),
        )
        .unwrap_err();

        assert_matches!(err.error, MdocError::DocumentExpired(_));
    }

    #[test]
    fn test_verify_issued_not_yet_valid_success() {
        let issued = issue_dummy_mdoc(100);

        let _device = Device::verify_issued(
            &issued.serialize_issuer_signed().unwrap(),
            MDL_DOCUMENT_TYPE.into(),
            40, // 1 minute before issuance
            |_| Some(&Es256Verifier),
        )
        .unwrap();
    }

    #[test]
    fn test_verify_issued_invalid_doc_type_fails() {
        let issued = issue_dummy_mdoc(100);

        let err = Device::verify_issued(
            &issued.serialize_issuer_signed().unwrap(),
            "<INVALID-DOC-TYPE>".into(),
            100,
            |_| Some(&Es256Verifier),
        )
        .unwrap_err();

        assert_matches!(
            err.error,
            MdocError::InvalidDocType(expected, actual)
                if expected == "<INVALID-DOC-TYPE>".into() && actual == MDL_DOCUMENT_TYPE.into()
        );
    }

    #[test]
    fn test_present_successful() {
        let device = issue_dummy_mdoc_to_device(100);

        let doc_request = DocRequest::builder(MDL_DOCUMENT_TYPE.into())
            .add_name_space(
                MDL_NAMESPACE.into(),
                HashMap::from([("lastName".into(), false.into())]),
            )
            .build();
        let request = DeviceRequest::new(vec![doc_request]);

        let device_response = device
            .present(
                101,
                &request,
                "client_id",
                "response_uri",
                "nonce",
                "mdoc_generated_nonce",
                &SimpleSigner::device(),
            )
            .unwrap();

        let documents = device_response.into_documents().unwrap();
        assert_eq!(1, documents.len());
        let document = documents.into_iter().next().unwrap();

        let issuer_signed_claims = document.issuer_signed.into_claims().0;
        let device_signed_claims = document.device_signed.into_claims().0;

        let expected_claims = HashMap::from([(
            MDL_NAMESPACE.into(),
            HashMap::from([("lastName".into(), "Doe".into())]),
        )]);

        assert_eq!(expected_claims, issuer_signed_claims);
        assert_eq!(issuer_signed_claims, device_signed_claims);
    }

    #[test]
    fn test_present_no_target_documents_successful() {
        let device = issue_dummy_mdoc_to_device(100);

        // no document is requested
        let request = DeviceRequest::new(Vec::new());

        let device_response = device
            .present(
                101,
                &request,
                "client_id",
                "response_uri",
                "nonce",
                "mdoc_generated_nonce",
                &SimpleSigner::device(),
            )
            .unwrap();

        let documents = device_response.into_documents();
        assert!(documents.is_none());
    }

    #[test]
    fn test_present_no_matching_documents_successful() {
        let device = issue_dummy_mdoc_to_device(100);

        // the requested document does not exist
        let doc_request = DocRequest::builder("NON-EXISTENT DOCUMENT".into())
            .add_name_space(
                MDL_NAMESPACE.into(),
                HashMap::from([("lastName".into(), false.into())]),
            )
            .build();
        let request = DeviceRequest::new(vec![doc_request]);

        let device_response = device
            .present(
                101,
                &request,
                "client_id",
                "response_uri",
                "nonce",
                "mdoc_generated_nonce",
                &SimpleSigner::device(),
            )
            .unwrap();

        let documents = device_response.into_documents();
        assert!(documents.is_none());
    }

    #[test]
    fn test_present_non_existent_claims_successful() {
        let device = issue_dummy_mdoc_to_device(100);

        // non-existent name spaces and claims are ignored
        let doc_request = DocRequest::builder(MDL_DOCUMENT_TYPE.into())
            .add_name_space(
                MDL_NAMESPACE.into(),
                HashMap::from([
                    ("lastName".into(), true.into()),
                    ("nonExistentClaim".into(), false.into()),
                ]),
            )
            .add_name_space(
                "NON-EXISTENT-NAMESPACE".into(),
                HashMap::from([("anotherNonExistentClaim".into(), false.into())]),
            )
            .build();
        let request = DeviceRequest::new(vec![doc_request]);

        let device_response = device
            .present(
                101,
                &request,
                "client_id",
                "response_uri",
                "nonce",
                "mdoc_generated_nonce",
                &SimpleSigner::device(),
            )
            .unwrap();

        let documents = device_response.into_documents().unwrap();
        assert_eq!(1, documents.len());
        let document = documents.into_iter().next().unwrap();

        let issuer_signed_claims = document.issuer_signed.into_claims().0;
        let device_signed_claims = document.device_signed.into_claims().0;

        let expected_claims = HashMap::from([(
            MDL_NAMESPACE.into(),
            HashMap::from([("lastName".into(), "Doe".into())]),
        )]);

        assert_eq!(expected_claims, issuer_signed_claims);
        assert_eq!(issuer_signed_claims, device_signed_claims);
    }

    #[test]
    fn test_present_no_matching_claims_successful() {
        let device = issue_dummy_mdoc_to_device(100);

        // no claims are requested, and consequently matched
        let doc_request = DocRequest::builder(MDL_DOCUMENT_TYPE.into()).build();
        let request = DeviceRequest::new(vec![doc_request]);

        let device_response = device
            .present(
                101,
                &request,
                "client_id",
                "response_uri",
                "nonce",
                "mdoc_generated_nonce",
                &SimpleSigner::device(),
            )
            .unwrap();

        let documents = device_response.into_documents().unwrap();
        assert_eq!(1, documents.len());
        let document = documents.into_iter().next().unwrap();

        let issuer_signed_claims = document.issuer_signed.into_claims();
        assert!(issuer_signed_claims.0.is_empty());

        let device_signed_claims = document.device_signed.into_claims().0;
        assert!(device_signed_claims.is_empty());
    }

    #[test]
    fn test_present_expired_credential_fails() {
        let device = issue_dummy_mdoc_to_device(100);

        let doc_request = DocRequest::builder(MDL_DOCUMENT_TYPE.into()).build();
        let request = DeviceRequest::new(vec![doc_request]);

        let err = device
            .present(
                100 + 400 * 24 * 60 * 60, // set time to 400 days later
                &request,
                "client_id",
                "response_uri",
                "nonce",
                "mdoc_generated_nonce",
                &SimpleSigner::device(),
            )
            .unwrap_err();

        assert_matches!(err.error, MdocError::DocumentExpired(_));
    }

    #[test]
    fn test_present_not_yet_valid_credential_fails() {
        let device = issue_dummy_mdoc_to_device(100);

        let doc_request = DocRequest::builder(MDL_DOCUMENT_TYPE.into()).build();
        let request = DeviceRequest::new(vec![doc_request]);

        let err = device
            .present(
                90, // set time to past
                &request,
                "client_id",
                "response_uri",
                "nonce",
                "mdoc_generated_nonce",
                &SimpleSigner::device(),
            )
            .unwrap_err();

        assert_matches!(err.error, MdocError::DocumentNotYetValid(100));
    }

    #[test]
    fn test_presentation_verifies_successfully() {
        let device = issue_dummy_mdoc_to_device(100);
        let verifier = Verifier::from_parts(
            "client_id".to_owned(),
            "response_uri".to_owned(),
            "nonce".to_owned(),
        );

        let doc_request = DocRequest::builder(MDL_DOCUMENT_TYPE.into())
            .add_name_space(
                MDL_NAMESPACE.into(),
                HashMap::from([("lastName".into(), false.into())]),
            )
            .build();
        let request = DeviceRequest::new(vec![doc_request]);

        let device_response = device
            .present(
                101,
                &request,
                "client_id",
                "response_uri",
                "nonce",
                "mdoc_generated_nonce",
                &SimpleSigner::device(),
            )
            .unwrap();

        let claims = verifier
            .verify(device_response, 101, "mdoc_generated_nonce", None, |_| {
                Some(&Es256Verifier)
            })
            .unwrap();
        assert_eq!(1, claims.len());
        let claims = claims.into_iter().next().unwrap().0;

        let expected_claims = HashMap::from([(
            MDL_NAMESPACE.into(),
            HashMap::from([("lastName".into(), "Doe".into())]),
        )]);

        assert_eq!(expected_claims, claims);
    }

    #[test]
    fn test_present_check_device_key() {
        let device = issue_dummy_mdoc_to_device(100);

        // the signer is correct
        let _device_response = device
            .present(
                105,
                &DeviceRequest::new(vec![]),
                "client_id",
                "response_uri",
                "nonce",
                "mdoc_generated_nonce",
                &SimpleSigner::device(), // use the correct signer
            )
            .unwrap();

        // the signer is wrong
        let err = device
            .present(
                110,
                &DeviceRequest::new(vec![]),
                "client_id",
                "response_uri",
                "nonce",
                "mdoc_generated_nonce",
                &SimpleSigner::issuer(), // use the wrong signer
            )
            .unwrap_err();
        assert_matches!(
            err.error,
            MdocError::InvalidDeviceSigner(s) if s == "public key does not match the signed one"
        );
    }
}

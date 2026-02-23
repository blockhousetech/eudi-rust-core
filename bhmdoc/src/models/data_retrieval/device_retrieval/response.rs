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

//! This module defines the data model described in the section "8.3.2.1.2.2 Device retrieval mdoc
//! response" of the [ISO/IEC 18013-5:2021][1] standard.
//!
//! [1]: <https://www.iso.org/standard/69084.html>
use std::collections::HashMap;

use bh_jws_utils::{JwkPublic, SignatureVerifier, SigningAlgorithm};
use bh_status_list::StatusClaim;
use bherror::traits::{ErrorContext as _, ForeignError as _};
use bhx5chain::X509Trust;
use rand::Rng;
use serde::{Deserialize, Serialize};

use super::{
    device_auth::{DeviceAuth, DeviceAuthentication},
    issuer_auth::{DigestAlgorithm, IssuerAuth},
    request::NameSpaces,
};
use crate::{
    models::{
        data_retrieval::{
            common::{DataElementIdentifier, DataElementValue, DocType, NameSpace},
            device_retrieval::issuer_auth::ValidityInfo,
            BorrowedClaims, Claims,
        },
        Bytes, BytesCbor,
    },
    utils::{
        base64::{base64_url_decode, base64_url_encode},
        digest::{sha256, sha384, sha512},
    },
    DeviceKey, MdocError, Result,
};

/// The version of the [`DeviceResponse`] structure.
///
/// The value is currently specified in the section `8.3.2.1.2.2` of the [ISO/IEC 18013-5:2021][1].
///
/// [1]: <https://www.iso.org/standard/69084.html>
const DEVICE_RESPONSE_VERSION: &str = "1.0";

/// [`DeviceResponse`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    documents: Option<Vec<Document>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    document_errors: Option<Vec<DocumentError>>,
    status: u64,
}

impl DeviceResponse {
    pub(crate) fn new(documents: Vec<Document>) -> Self {
        Self {
            version: DEVICE_RESPONSE_VERSION.to_owned(),
            // set to `None` if no `Document`s are present
            documents: (!documents.is_empty()).then_some(documents),
            document_errors: None,
            status: 0,
        }
    }

    /// Parses the provided `base64url`-encoded (**without padding**) `string` of _CBOR_ data into
    /// [`DeviceResponse`], as per `Table B.6` of [ISO/IEC TS 18013-7:2024][1].
    ///
    /// [1]: <https://www.iso.org/standard/82772.html>
    pub fn from_base64_cbor(value: &str) -> Result<Self> {
        let decoded = base64_url_decode(value)
            .foreign_err(|| MdocError::DeviceResponseParse("invalid base64".to_owned()))?;

        ciborium::from_reader(decoded.as_slice())
            .foreign_err(|| MdocError::DeviceResponseParse("invalid CBOR".to_owned()))
    }

    /// Serializes the [`DeviceResponse`] to `base64url`-encoded (**without padding**) `string` of
    /// _CBOR_ data, as per `Table B.6` of [ISO/IEC TS 18013-7:2024][1].
    ///
    /// [1]: <https://www.iso.org/standard/82772.html>
    pub fn to_base64_cbor(&self) -> Result<String> {
        let mut cbor = Vec::new();
        ciborium::into_writer(self, &mut cbor).foreign_err(|| {
            MdocError::DeviceResponseParse("serialization to CBOR failed".to_owned())
        })?;

        Ok(base64_url_encode(cbor))
    }

    /// Consumes the [`DeviceResponse`] and returns the underlying
    /// [`Document`]s.
    pub fn into_documents(self) -> Option<Vec<Document>> {
        self.documents
    }
}

/// [`Document`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC 18013-5:2021][1] standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    doc_type: DocType,
    pub(crate) issuer_signed: IssuerSigned,
    pub(crate) device_signed: DeviceSigned,
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<Errors>,
}

impl Document {
    pub(crate) fn new(
        doc_type: DocType,
        issuer_signed: IssuerSigned,
        device_signed: DeviceSigned,
    ) -> Self {
        Self {
            doc_type,
            issuer_signed,
            device_signed,
            errors: None,
        }
    }

    /// Validates the claims of the underlying [`IssuerSigned`].
    ///
    /// Note: this is intended to be used **ONLY** by the `mDoc` verifier, and
    /// not the holder (device), because some information, such as `validUntil`,
    /// is evaluated differently, i.e. *not-yet-valid* credential might be
    /// accepted by the holder, and not the verifier.
    pub(crate) fn validate(&self, current_time: u64) -> Result<()> {
        self.issuer_signed
            .validate_verifier(current_time, &self.doc_type)
    }

    /// Extracts and returns only the data elements.
    pub(crate) fn into_claims(self) -> Claims {
        self.issuer_signed.into_claims()
    }

    /// Verifies both issuer signature and device signature or MAC of this [`Document`].
    ///
    /// If [`X509Trust`] is provided, the Issuer's authenticity is verified as well.
    ///
    /// **Note**: currently, only the signature is supported for the `DeviceAuth`. Verifying the
    /// MAC results in the [`DeviceMac`][MdocError::DeviceMac] error.
    pub(crate) fn verify<'a>(
        &self,
        client_id: &str,
        response_uri: &str,
        nonce: &str,
        jwk_public: Option<&JwkPublic>,
        trust: Option<&X509Trust>,
        get_signature_verifier: impl Fn(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
    ) -> Result<()> {
        self.issuer_signed
            .verify_signature(trust, &get_signature_verifier)
            .ctx(|| "issuer signature")?;

        let device_key = self.issuer_signed.device_key()?;

        self.device_signed
            .verify_signature(
                client_id,
                response_uri,
                nonce,
                jwk_public,
                &self.doc_type,
                get_signature_verifier,
                &device_key,
            )
            .ctx(|| "device signature")
    }

    /// Get the pointer to the credential's status.
    ///
    /// For more information, take a look at the [Token Status List (TSL)][1].
    ///
    /// [1]: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-15.html>
    pub fn status(&self) -> Result<Option<StatusClaim>> {
        self.issuer_signed.status()
    }
}

/// [`DocumentError`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentError(DocType, ErrorCode);

/// [`IssuerSigned`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSigned {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name_spaces: Option<IssuerNameSpaces>,
    pub(crate) issuer_auth: IssuerAuth,
}

impl IssuerSigned {
    /// Creates a new `IssuerSigned` object with a single namespace.
    pub(crate) fn new<Signer: bh_jws_utils::Signer + bh_jws_utils::HasX5Chain, R: Rng + ?Sized>(
        doc_type: DocType,
        name_spaces: Claims,
        device_key: DeviceKey,
        signer: &Signer,
        rng: &mut R,
        validity_info: ValidityInfo,
        status: Option<StatusClaim>,
    ) -> Result<Self> {
        let name_spaces = IssuerNameSpaces(
            name_spaces
                .0
                .into_iter()
                .map(|(name_space, items)| {
                    let items = items
                        .into_iter()
                        .enumerate()
                        .map(|(digest_id, (element_identifier, element_value))| {
                            IssuerSignedItem {
                                digest_id: digest_id.into(),
                                random: Bytes::random_salt(rng),
                                element_identifier,
                                element_value,
                            }
                            .into()
                        })
                        .collect();

                    (name_space, items)
                })
                .collect(),
        );

        let issuer_auth = IssuerAuth::new(
            doc_type,
            &name_spaces,
            device_key,
            signer,
            validity_info,
            status,
        )?;

        Ok(Self {
            name_spaces: Some(name_spaces),
            issuer_auth,
        })
    }

    /// Deserializes the provided _CBOR_-serialized and _base64url_-encoded (**without padding**)
    /// string into the [`IssuerSigned`].
    pub(crate) fn from_base64_url(base64_url: &str) -> Result<Self> {
        let decoded = base64_url_decode(base64_url)
            .foreign_err(|| MdocError::IssuerSignedParse)
            .ctx(|| "invalid base64-url payload")?;

        ciborium::from_reader(decoded.as_slice())
            .foreign_err(|| MdocError::IssuerSignedParse)
            .ctx(|| "invalid CBOR payload")
    }

    /// Created a new [`IssuerSigned`] with the claims filtered with respect to
    /// the provided [`NameSpaces`].
    ///
    /// In other words, the claims are here selectively disclosed.
    pub(crate) fn filtered_claims(&self, name_spaces: &NameSpaces) -> Self {
        let filtered = self
            .name_spaces
            .as_ref()
            .and_then(|all_name_spaces| all_name_spaces.filtered_claims(name_spaces));

        Self {
            name_spaces: filtered,
            issuer_auth: self.issuer_auth.clone(),
        }
    }

    /// Extracts and returns only the data elements.
    pub fn into_claims(self) -> Claims {
        self.name_spaces
            .map(IssuerNameSpaces::into_claims)
            .unwrap_or_else(|| Claims(HashMap::new()))
    }

    /// Extracts and returns the [`BorrowedClaims`].
    pub fn claims(&self) -> BorrowedClaims<'_> {
        self.name_spaces
            .as_ref()
            .map(IssuerNameSpaces::claims)
            .unwrap_or_else(|| BorrowedClaims(HashMap::new()))
    }

    /// Returns the signed [`DeviceKey`] of the respective `mdoc` Device the
    /// credential is issued to.
    pub fn device_key(&self) -> Result<DeviceKey> {
        self.issuer_auth.device_key()
    }

    /// Verifies the issuer's signature of the underlying [`IssuerAuth`].
    ///
    /// If [`X509Trust`] is provided, the Issuer's authenticity is verified as well.
    pub(crate) fn verify_signature<'a>(
        &self,
        trust: Option<&X509Trust>,
        get_signature_verifier: impl Fn(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
    ) -> Result<()> {
        self.issuer_auth
            .verify_signature(trust, get_signature_verifier)
    }

    /// Validates the claims of the underlying [`IssuerAuth`].
    ///
    /// **Note**: this is intended to be used only by the `mDoc` Verifier.
    fn validate_verifier(&self, current_time: u64, doc_type: &DocType) -> Result<()> {
        self.issuer_auth
            .validate_verifier(current_time, doc_type, self.name_spaces.as_ref())
    }

    /// Validates the claims of the underlying [`IssuerAuth`].
    ///
    /// Unlike [`validate_verifier`][Self::validate_verifier], this does not
    /// validate the _validFrom_ claim, as the Device should be able to accept
    /// _not-yet-valid_ credentials.
    ///
    /// **Note**: this is intended to be used only by the `mDoc` Device.
    pub(crate) fn validate_device(&self, current_time: u64, doc_type: &DocType) -> Result<()> {
        self.issuer_auth
            .validate_device(current_time, doc_type, self.name_spaces.as_ref())
    }

    /// Get the pointer to the credential's status.
    ///
    /// For more information, take a look at the [Token Status List (TSL)][1].
    ///
    /// [1]: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-15.html>
    pub fn status(&self) -> Result<Option<StatusClaim>> {
        self.issuer_auth.status()
    }
}

/// [`IssuerNameSpaces`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IssuerNameSpaces(pub(crate) HashMap<NameSpace, Vec<IssuerSignedItemBytes>>);

impl IssuerNameSpaces {
    /// Extracts and returns only the data elements.
    pub fn into_claims(self) -> Claims {
        Claims(
            self.0
                .into_iter()
                .map(|(k, vs)| {
                    let vs_map = vs
                        .into_iter()
                        .map(|item| {
                            let item = IssuerSignedItem::from(item);
                            (item.element_identifier, item.element_value)
                        })
                        .collect();

                    (k, vs_map)
                })
                .collect(),
        )
    }

    /// Extracts and returns the [`BorrowedClaims`].
    fn claims(&self) -> BorrowedClaims<'_> {
        BorrowedClaims(
            self.0
                .iter()
                .map(|(k, vs)| {
                    let vs_map = vs
                        .iter()
                        .map(|item| {
                            (
                                &item.0.inner.element_identifier,
                                &item.0.inner.element_value,
                            )
                        })
                        .collect();

                    (k, vs_map)
                })
                .collect(),
        )
    }

    /// Selectively discloses claims based on the provided [`NameSpaces`].
    ///
    /// If no claims are disclosed, [`None`] is returned.
    fn filtered_claims(&self, name_spaces: &NameSpaces) -> Option<Self> {
        let mut filtered = HashMap::new();

        for (name_space, issuer_signed_items) in &self.0 {
            let Some(data_elements) = name_spaces.0.get(name_space) else {
                // no claims from this namespace are selected
                continue;
            };

            let filtered_name_space: Vec<IssuerSignedItemBytes> = issuer_signed_items
                .iter()
                .filter(|item| {
                    data_elements
                        .0
                        .contains_key(&item.0.inner.element_identifier)
                })
                .cloned()
                .collect();

            if !filtered_name_space.is_empty() {
                filtered.insert(name_space.clone(), filtered_name_space);
            }
        }

        if filtered.is_empty() {
            return None;
        };

        Some(Self(filtered))
    }

    /// Converts the Issuer-signed claims to the format to be signed by the
    /// Device.
    pub(crate) fn to_device_name_spaces(&self) -> DeviceNameSpaces {
        DeviceNameSpaces(
            self.0
                .iter()
                .map(|(name_space, issuer_signed_items)| {
                    let device_signed_items = DeviceSignedItems(
                        issuer_signed_items
                            .iter()
                            .map(|item| {
                                (
                                    item.0.inner.element_identifier.clone(),
                                    item.0.inner.element_value.clone(),
                                )
                            })
                            .collect(),
                    );

                    (name_space.clone(), device_signed_items)
                })
                .collect(),
        )
    }
}

/// [`IssuerSignedItemBytes`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC
/// 18013-5:2021][1] standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IssuerSignedItemBytes(pub(crate) BytesCbor<IssuerSignedItem>);

impl IssuerSignedItemBytes {
    /// Computes the digest of the serialized `self`.
    pub fn digest(&self, alg: &DigestAlgorithm) -> Result<Vec<u8>> {
        let serialize = || -> Result<Vec<u8>> {
            let mut payload = Vec::new();
            ciborium::into_writer(self, &mut payload)
                .foreign_err(|| MdocError::IssuerAuth)
                .ctx(|| "unable to serialize `IssuerSignedItemBytes`")?;

            Ok(payload)
        };

        let payload = match self.0.original_data {
            Some(ref original_data) => original_data,
            None => &serialize()?,
        };

        Ok(match alg {
            DigestAlgorithm::Sha256 => sha256(payload).to_vec(),
            DigestAlgorithm::Sha384 => sha384(payload).to_vec(),
            DigestAlgorithm::Sha512 => sha512(payload).to_vec(),
        })
    }
}

impl From<IssuerSignedItem> for IssuerSignedItemBytes {
    fn from(value: IssuerSignedItem) -> Self {
        Self(value.into())
    }
}

impl From<IssuerSignedItemBytes> for IssuerSignedItem {
    fn from(value: IssuerSignedItemBytes) -> Self {
        value.0.inner
    }
}

/// [`IssuerSignedItem`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedItem {
    pub(super) random: Bytes,
    #[serde(rename = "digestID")]
    pub(super) digest_id: DigestID,
    pub(super) element_value: DataElementValue,
    pub(super) element_identifier: DataElementIdentifier,
}

/// Digest ID for issuer data authentication.
#[derive(
    Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct DigestID(u64);

impl std::fmt::Display for DigestID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for DigestID {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<usize> for DigestID {
    fn from(value: usize) -> Self {
        Self(value as u64)
    }
}

/// [`DeviceSigned`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSigned {
    pub(crate) name_spaces: DeviceNameSpacesBytes,
    device_auth: DeviceAuth,
}

impl DeviceSigned {
    /// Creates a new [`DeviceSigned`] object by computing the signature with
    /// the provided [`Signer`][bh_jws_utils::Signer] over the provided data.
    pub(crate) fn new(
        name_spaces: DeviceNameSpaces,
        client_id: &str,
        response_uri: &str,
        nonce: &str,
        jwk_public: Option<&JwkPublic>,
        doc_type: &DocType,
        signer: &impl bh_jws_utils::Signer,
    ) -> Result<Self> {
        let name_spaces = name_spaces.into();

        let device_authentication = DeviceAuthentication::new(
            client_id,
            response_uri,
            nonce,
            jwk_public,
            doc_type,
            &name_spaces,
        )?;

        let device_auth = DeviceAuth::new_signature(device_authentication, signer)?;

        Ok(Self {
            name_spaces,
            device_auth,
        })
    }

    /// Extracts and returns only the data elements.
    pub fn into_claims(self) -> Claims {
        self.name_spaces.0.inner.into_claims()
    }

    /// Extracts and returns the [`BorrowedClaims`].
    pub fn claims(&self) -> BorrowedClaims<'_> {
        self.name_spaces.0.inner.claims()
    }

    /// Verifies the underlying signature or MAC.
    ///
    /// The payload for the signature is detached, i.e. it is not directly
    /// contained underneath. It is constructed from the provided arguments, and
    /// used as such to verify the signature against.
    ///
    /// **Note**: currently, only the signature is supported. Verifying the MAC
    /// results in the [DeviceMac][MdocError::DeviceMac] error.
    #[allow(clippy::too_many_arguments)]
    fn verify_signature<'a>(
        &self,
        client_id: &str,
        response_uri: &str,
        nonce: &str,
        jwk_public: Option<&JwkPublic>,
        doc_type: &DocType,
        get_signature_verifier: impl Fn(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
        device_key: &DeviceKey,
    ) -> Result<()> {
        let device_authentication = DeviceAuthentication::new(
            client_id,
            response_uri,
            nonce,
            jwk_public,
            doc_type,
            &self.name_spaces,
        )?;

        self.device_auth
            .verify_signature(device_authentication, get_signature_verifier, device_key)
    }
}

/// [`DeviceNameSpacesBytes`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC
/// 18013-5:2021][1] standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceNameSpacesBytes(pub(crate) BytesCbor<DeviceNameSpaces>);

impl From<DeviceNameSpaces> for DeviceNameSpacesBytes {
    fn from(value: DeviceNameSpaces) -> Self {
        Self(value.into())
    }
}

/// [`DeviceNameSpaces`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviceNameSpaces(HashMap<NameSpace, DeviceSignedItems>);

impl DeviceNameSpaces {
    /// Extracts and returns only the data elements.
    pub fn into_claims(self) -> Claims {
        Claims(self.0.into_iter().map(|(k, vs)| (k, vs.0)).collect())
    }

    /// Extracts and returns the [`BorrowedClaims`].
    pub fn claims(&self) -> BorrowedClaims<'_> {
        BorrowedClaims(
            self.0
                .iter()
                .map(|(k, vs)| (k, vs.0.iter().collect()))
                .collect(),
        )
    }
}

impl From<HashMap<NameSpace, DeviceSignedItems>> for DeviceNameSpaces {
    fn from(value: HashMap<NameSpace, DeviceSignedItems>) -> Self {
        Self(value)
    }
}

/// [`DeviceSignedItems`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceSignedItems(HashMap<DataElementIdentifier, DataElementValue>);

/// [`Errors`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC 18013-5:2021][1] standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Errors(HashMap<NameSpace, ErrorItems>);

/// [`ErrorItems`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorItems(HashMap<DataElementIdentifier, ErrorCode>);

/// [`ErrorCode`] as defined in the section `8.3.2.1.2.2` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorCode(i64);

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use assert_matches::assert_matches;
    use bh_jws_utils::Es256Verifier;
    use ciborium::{from_reader, into_writer};

    use super::*;
    use crate::{
        models::mdl::MDL_DOCUMENT_TYPE,
        utils::test::{present_dummy_mdoc, remove_original_data_from_documents},
    };

    /// This was generated by the [`Reference Wallet 2026.02.35-Demo`][1]
    /// implementation, where the credential is issued by some version of the
    /// [`Reference Issuer`][2], and presented to some version of the
    /// [`Reference Verifier`][3].
    ///
    /// The corresponding [`NONCE`], [`CLIENT_ID`], [`RESPONSE_URI`], and
    /// [`JWK_PUBLIC`] parameters must be used as set below.
    ///
    /// [1]: <https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/releases/tag/Wallet%2FDemo_Version%3D2026.02.35-Demo_Build%3D35>
    /// [2]: <https://issuer.eudiw.dev/>
    /// [3]: <https://verifier.eudiw.dev/>
    const VP_TOKEN: &str = "\
o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1\
ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xgdgYWGOkZnJhbmRvbVgggPzYjvo5\
sj1LZaukGuZXcGm6VW1Vfqia3qtK3kr_M6VoZGlnZXN0SUQCbGVsZW1lbnRWYWx1ZWNEb2VxZWxlbWVu\
dElkZW50aWZpZXJrZmFtaWx5X25hbWVqaXNzdWVyQXV0aIRDoQEmoRghWQLjMIIC3zCCAoWgAwIBAgIU\
f3lohTmDMAmS_YX_q4hqoRyJB54wCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAt\
IFVUIDAyMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNV\
BAYTAlVUMB4XDTI1MDQxMDE0Mzc1MloXDTI2MDcwNDE0Mzc1MVowUjEUMBIGA1UEAwwLUElEIERTIC0g\
MDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMC\
VVQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS7WAAWqPze0Us3z8pajyVPWBRmrRbCi5X2s9GvlybQ\
ytwTumcZnej9BkLfAglloX5tv-NgWfDfgt_06s-5tV4lo4IBLTCCASkwHwYDVR0jBBgwFoAUYseURyi9\
D6IWIKeawkmURPEB08cwGwYDVR0RBBQwEoIQaXNzdWVyLmV1ZGl3LmRldjAWBgNVHSUBAf8EDDAKBggr\
gQICAAABAjBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwv\
cGlkX0NBX1VUXzAyLmNybDAdBgNVHQ4EFgQUql_opxkQlYy0llaToPbDE_myEcEwDgYDVR0PAQH_BAQD\
AgeAMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxl\
dC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwIDSAAwRQIhANJV\
SDsqT3IkGcKWWgSeubkDOdi5_UE9b1GF_X5fQRFaAiBp5t6tHh8XwFhPstzOHMopvBD_Gwms0RAUgmSn\
6ku8GlkDydgYWQPEp2ZzdGF0dXOia3N0YXR1c19saXN0omNpZHgZDWJjdXJpeGhodHRwczovL2lzc3Vl\
ci5ldWRpdy5kZXYvdG9rZW5fc3RhdHVzX2xpc3QvRkMvb3JnLmlzby4xODAxMy41LjEubURMLzJiNGIw\
ZjdmLTk3NDctNDY4OC05MjdiLTRiMzhjNGJmMTRkYm9pZGVudGlmaWVyX2xpc3SiYmlkZDM0MjZjdXJp\
eGZodHRwczovL2lzc3Vlci5ldWRpdy5kZXYvaWRlbnRpZmllcl9saXN0L0ZDL29yZy5pc28uMTgwMTMu\
NS4xLm1ETC8yYjRiMGY3Zi05NzQ3LTQ2ODgtOTI3Yi00YjM4YzRiZjE0ZGJnZG9jVHlwZXVvcmcuaXNv\
LjE4MDEzLjUuMS5tRExndmVyc2lvbmMxLjBsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjYtMDItMjNU\
MTM6MjU6MjRaaXZhbGlkRnJvbcB0MjAyNi0wMi0yM1QxMzoyNToyNFpqdmFsaWRVbnRpbMB0MjAyNi0w\
NS0yNFQxMzoyNToyNFpsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMasAWCAVQqrF2ovH1d2A\
8dBRqbcn2DQTnMqpqQ0wmvVVoN7V4gFYIMrlAhjxmIFlh78z-73jrWUawS5E2iOPCC-rFtOIM50YAlgg\
s_kTaTqDHZH-DhtBU3MtgPUZppU3ep0HrJ6XnjyvypQDWCCMu9PksTXHrFJGnUcjN7dZJKY_7mQFt4h4\
BLUdtiRLbwRYIOUa9lmbAD4Zp1Fa_KsAzZd5IW0riMtawy0bFTMw6_-vBVggywCflSAGWLK6Krz9E7WX\
2TikEQ8-MLDxHMzJpCFTNTYGWCBlyyEVAKST-R00Sj4s9RJHV5ntXh5Lr3cOoasPa_CTawdYIPctvgf1\
Cx8HQLOLOgaw3xOF3bmR6RX92tk8xXveCtHUCFggSKJGe2mws6DwozAc9rcagbTSDITLG-1AVr7jOyfL\
CM4JWCAuyitIdxiXZ5YFYjuKGYlINv7sx5YfYjIN1gTgzJ2_kwpYIIoXryVtvN0daAQMLtLZR_Vf9zbo\
4d0OouTiDnpA0bVqbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggJbG7AOnvFQW6oG-mClpy\
IsXtK5yth6WspwXGaNM1an0iWCDoQf8lXNG8KtRz8pdWXDdX9o_OTRN4Qaz1XZqD72eqPW9kaWdlc3RB\
bGdvcml0aG1nU0hBLTI1NlhAXy9DpmPSvNza6y7U8SkuMhTMDTu3whEWpfao6yW56i393NShBYYNXfV3\
ZWIGsrm3whdowBb_pICmUZRfDsz0BGxkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGEGgamRldmljZUF1\
dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQMFrGbV-wHiWX3CNLlMl0wvhal-cRGHZNBauNajZ92Vl\
dRJdySqkRghbuK47fyFF8zxMLDRxbMh5Zkrw4JWA5jdmc3RhdHVzAA";
    const NONCE: &str = "cb0d0a3d-ebfb-4121-a5c2-fece61d2af3b";
    const CLIENT_ID: &str = "x509_hash:LTHlBmrN6Wc9oE3TxFZp47fET6iFBQIiwMJiu3BLcqw";
    const RESPONSE_URI : &str= "https://verifier-backend.eudiw.dev/wallet/direct_post/1n0Mq96zae3-jsu44I8JVQhQw42Bv0Ja47mOiDnB1JpEzne-OxEmUpzVZLv1rn64SxmBpaqLZ2Sd-kOClSImwA";
    static JWK_PUBLIC: LazyLock<serde_json::Value> = LazyLock::new(|| {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "r45mB4JcqaKaAlXA_D_fbAE_vKKBP1puuq8CM7hUvSc",
            "y": "iXlhRqEDKtbR0qcya8Bty3d6RzHcCqmx2cfw-N5vS0E",
        })
    });

    #[test]
    fn test_response() {
        let response = present_dummy_mdoc(100, None, None);

        let mut encoded = Vec::new();

        into_writer(&response, &mut encoded).unwrap();

        let mut decoded: DeviceResponse = from_reader(encoded.as_slice()).unwrap();

        // default `[CoseSign1/CoseMac0].protected.original_data` is `None`, but
        // after ser/de it becomes `Some(vec![...])` so we reset here manually
        if let Some(documents) = &mut decoded.documents {
            for document in documents {
                document.device_signed.name_spaces.0.original_data = None;

                match &mut document.device_signed.device_auth {
                    DeviceAuth::DeviceSignature(s) => s.0.protected.original_data = None,
                    DeviceAuth::DeviceMac(m) => m.0.protected.original_data = None,
                }
            }
        };

        assert_eq!(response, decoded);
    }

    #[test]
    fn device_response_from_base64() {
        let mut response = DeviceResponse::from_base64_cbor(VP_TOKEN).unwrap();

        remove_original_data_from_documents(response.documents.as_mut().unwrap());

        let document = response.documents.as_ref().unwrap()[0].clone();

        let expected = DeviceResponse {
            version: DEVICE_RESPONSE_VERSION.to_owned(),
            documents: Some(vec![Document {
                doc_type: MDL_DOCUMENT_TYPE.into(),
                issuer_signed: IssuerSigned {
                    name_spaces: Some(IssuerNameSpaces(
                        [(
                            "org.iso.18013.5.1".into(),
                            vec![IssuerSignedItem {
                                digest_id: 2u64.into(),
                                random: Bytes::from_hex("80fcd88efa39b23d4b65aba41ae6577069ba556d557ea89adeab4ade4aff33a5")
                                    .unwrap(),
                                element_identifier: "family_name".into(),
                                element_value: "Doe".into(),
                            }
                            .into()],
                        )]
                        .into(),
                    )),
                    // reuse issuer_auth
                    issuer_auth: document.issuer_signed.issuer_auth,
                },
                // reuse device_signed
                device_signed: document.device_signed,
                errors: None,
            }]),
            document_errors: None,
            status: 0,
        };

        assert_eq!(expected, response);
    }

    #[test]
    fn device_response_from_base64_with_padding_fails() {
        let payload = VP_TOKEN.to_owned() + "=";

        let err = DeviceResponse::from_base64_cbor(&payload).unwrap_err();

        assert_matches!(
            err.error,
            MdocError::DeviceResponseParse(m) if m == "invalid base64"
        );
    }

    #[test]
    fn issuer_signed_from_base64() {
        /// This was generated by `third-party` issuer implementation at some point.
        /// Additionally, the padding was removed.
        const PAYLOAD: &str = "omppc3N1ZXJBdXRohEOhASahGCFZAecwggHjMIIBiKADAgEC\
AhRCXIm4V0_ijmgwvAU7VQagMjJlszAKBggqhkjOPQQDAjBHMQswCQYDVQQGEwJIUjEPMA0GA1UECAw\
GWmFncmViMQ0wCwYDVQQKDARUQlRMMRgwFgYDVQQDDA9jb2NvbnV0LXNlcnZpY2UwHhcNMjUwMzIwMT\
AyMTI2WhcNMjYwMzIwMTAyMTI2WjBHMQswCQYDVQQGEwJIUjEPMA0GA1UECAwGWmFncmViMQ0wCwYDV\
QQKDARUQlRMMRgwFgYDVQQDDA9jb2NvbnV0LXNlcnZpY2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\
AAQoMb_S450l7uSzpg3Ac3d_2DQtPwMWEXdbl1WK4na_jtfSwWlG4IJp3kLqtHWsWrl1sQHHLk-S2UV\
hsFoEJOG1o1IwUDAvBgNVHREEKDAmggdjb2NvbnV0ggpyZWYtaXNzdWVyhwR_AAABgglsb2NhbGhvc3\
QwHQYDVR0OBBYEFMtIKw_T_nfvmfSDEHTqHynZJJeEMAoGCCqGSM49BAMCA0kAMEYCIQC-WlW88jeeM\
aAnTYBaS2C0QhOOCjKQX80NTFlhcwRHwQIhAJcNa8JY-G88-XLT9zutVmsM6vC9--zXEsqIWZUII-Si\
WQJY2BhZAlOmZ2RvY1R5cGV3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjFndmVyc2lvbmMxLjBsdmFsaWR\
pdHlJbmZvo2ZzaWduZWTAdDIwMjUtMDQtMDhUMDk6Mjk6NDNaaXZhbGlkRnJvbcB0MjAyNS0wNC0wOF\
QwOToyOTo0M1pqdmFsaWRVbnRpbMB0MjAyNS0wNy0wN1QwMDowMDowMFpsdmFsdWVEaWdlc3RzoXdld\
S5ldXJvcGEuZWMuZXVkaS5waWQuMagAWCBQbkmM5ddu_l-tfle2sA0Ez_qgMtNjnleUg_GdZkMvtgFY\
IEx5H9ZtPz1P-iuHb1xaOb7tfP7lDI99WbrUAb7ROwaHAlggPWe5EIyTXarOU_7LAXLRzE99zcBFcLG\
BGOlRwqUIzokDWCDs3HhoQnFQpxlyGT8-nWjKGQTVqWV2Rgh7HKm0EXpdlgRYIMc8oeP68SHapA_KAD\
4yqeDfs3puZklnreSiuihI_tJZBVggV9_PseKCmcX5yc685UHe_CI-W6-llBnYz6m9aEsKuOsGWCD-C\
QyNZKW1fhWlcVbKJhH5iFhwZC8TkP1JFlPIf_GVywdYIH300knio0cNBEWjrOk-Ocxd1JecyXeOYHMf\
b3dW-I3MbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVgfsre15Dvj4mur1XZR8GTBkfEWF8x\
4LCWkNlQGF0OwXSJYIJ01R0R4H-UssTKi6VdDpewuyQPmjYecsVUQWS-ISbyHb2RpZ2VzdEFsZ29yaX\
RobWdTSEEtMjU2WEDoN6Ue634M-9LlWAB2yjFdQAOBWKJjh7XpfvIo8HMEqhakWeOU1XMSZGhMMfoJK\
JP_f4qG6OOI4YNGS8zXPxHtam5hbWVTcGFjZXOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xiNgYWGyk\
ZnJhbmRvbVgga-n30BK9HyPzLbIH33wqrnL7MN6Is-hUyJRW2fB4RxpoZGlnZXN0SUQAbGVsZW1lbnR\
WYWx1ZdkD7GoyMDI1LTAxLTAxcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGXYGFhgpGZyYW5kb2\
1YIMkm7U_78-CWhniH5sHiQYKEzXW-8yAehcSGU1dc-RgJaGRpZ2VzdElEAWxlbGVtZW50VmFsdWX0c\
WVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzE42BhYY6RmcmFuZG9tWCBf_umbK3Upi4eu3ykcitDH\
3cNapjIY2vb3pLS6YjUUHmhkaWdlc3RJRAJsZWxlbWVudFZhbHVlZExlYWRxZWxlbWVudElkZW50aWZ\
pZXJqZ2l2ZW5fbmFtZdgYWG2kZnJhbmRvbVggswa0-_wx3W92HhKOwruVqKWvZ4RyxNaagTgCboVD0S\
NoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZdkD7GoyMDI1LTA3LTA3cWVsZW1lbnRJZGVudGlmaWVya2V4c\
GlyeV9kYXRl2BhYZKRmcmFuZG9tWCCluLZPpNMcbbhydfr-f5TwwKZYyLOwUsp_huttA4-uf2hkaWdl\
c3RJRARsZWxlbWVudFZhbHVlZE1lYWFxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhvpGZ\
yYW5kb21YIJHV8kSIxcv4m0jcv713ymAac9T8uqFcV-z2dEYjXBAMaGRpZ2VzdElEBWxlbGVtZW50Vm\
FsdWXZA-xqMjAyNS0wNC0wOHFlbGVtZW50SWRlbnRpZmllcm1pc3N1YW5jZV9kYXRl2BhYdaRmcmFuZ\
G9tWCDQPMt2xE6tGSBMHFud6DOM31oMUjS00bcUnkjAU51SSGhkaWdlc3RJRAZsZWxlbWVudFZhbHVl\
b1Rlc3QgUElEIGlzc3VlcnFlbGVtZW50SWRlbnRpZmllcnFpc3N1aW5nX2F1dGhvcml0edgYWGakZnJ\
hbmRvbVgglEWoNQu1bHeEKsFdtWeV4lcgfPin7fnscdkmRVdT5tRoZGlnZXN0SUQHbGVsZW1lbnRWYW\
x1ZWJGQ3FlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnk";

        assert_matches!(
            IssuerSigned::from_base64_url(PAYLOAD),
            Ok(IssuerSigned { .. })
        );
    }

    #[test]
    fn issuer_signed_from_base64_with_padding_fails() {
        /// This was generated by `third-party` issuer implementation at some point.
        const PAYLOAD: &str = "omppc3N1ZXJBdXRohEOhASahGCFZAecwggHjMIIBiKADAgEC\
AhRCXIm4V0_ijmgwvAU7VQagMjJlszAKBggqhkjOPQQDAjBHMQswCQYDVQQGEwJIUjEPMA0GA1UECAw\
GWmFncmViMQ0wCwYDVQQKDARUQlRMMRgwFgYDVQQDDA9jb2NvbnV0LXNlcnZpY2UwHhcNMjUwMzIwMT\
AyMTI2WhcNMjYwMzIwMTAyMTI2WjBHMQswCQYDVQQGEwJIUjEPMA0GA1UECAwGWmFncmViMQ0wCwYDV\
QQKDARUQlRMMRgwFgYDVQQDDA9jb2NvbnV0LXNlcnZpY2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\
AAQoMb_S450l7uSzpg3Ac3d_2DQtPwMWEXdbl1WK4na_jtfSwWlG4IJp3kLqtHWsWrl1sQHHLk-S2UV\
hsFoEJOG1o1IwUDAvBgNVHREEKDAmggdjb2NvbnV0ggpyZWYtaXNzdWVyhwR_AAABgglsb2NhbGhvc3\
QwHQYDVR0OBBYEFMtIKw_T_nfvmfSDEHTqHynZJJeEMAoGCCqGSM49BAMCA0kAMEYCIQC-WlW88jeeM\
aAnTYBaS2C0QhOOCjKQX80NTFlhcwRHwQIhAJcNa8JY-G88-XLT9zutVmsM6vC9--zXEsqIWZUII-Si\
WQJY2BhZAlOmZ2RvY1R5cGV3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjFndmVyc2lvbmMxLjBsdmFsaWR\
pdHlJbmZvo2ZzaWduZWTAdDIwMjUtMDQtMDhUMDk6Mjk6NDNaaXZhbGlkRnJvbcB0MjAyNS0wNC0wOF\
QwOToyOTo0M1pqdmFsaWRVbnRpbMB0MjAyNS0wNy0wN1QwMDowMDowMFpsdmFsdWVEaWdlc3RzoXdld\
S5ldXJvcGEuZWMuZXVkaS5waWQuMagAWCBQbkmM5ddu_l-tfle2sA0Ez_qgMtNjnleUg_GdZkMvtgFY\
IEx5H9ZtPz1P-iuHb1xaOb7tfP7lDI99WbrUAb7ROwaHAlggPWe5EIyTXarOU_7LAXLRzE99zcBFcLG\
BGOlRwqUIzokDWCDs3HhoQnFQpxlyGT8-nWjKGQTVqWV2Rgh7HKm0EXpdlgRYIMc8oeP68SHapA_KAD\
4yqeDfs3puZklnreSiuihI_tJZBVggV9_PseKCmcX5yc685UHe_CI-W6-llBnYz6m9aEsKuOsGWCD-C\
QyNZKW1fhWlcVbKJhH5iFhwZC8TkP1JFlPIf_GVywdYIH300knio0cNBEWjrOk-Ocxd1JecyXeOYHMf\
b3dW-I3MbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVgfsre15Dvj4mur1XZR8GTBkfEWF8x\
4LCWkNlQGF0OwXSJYIJ01R0R4H-UssTKi6VdDpewuyQPmjYecsVUQWS-ISbyHb2RpZ2VzdEFsZ29yaX\
RobWdTSEEtMjU2WEDoN6Ue634M-9LlWAB2yjFdQAOBWKJjh7XpfvIo8HMEqhakWeOU1XMSZGhMMfoJK\
JP_f4qG6OOI4YNGS8zXPxHtam5hbWVTcGFjZXOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xiNgYWGyk\
ZnJhbmRvbVgga-n30BK9HyPzLbIH33wqrnL7MN6Is-hUyJRW2fB4RxpoZGlnZXN0SUQAbGVsZW1lbnR\
WYWx1ZdkD7GoyMDI1LTAxLTAxcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGXYGFhgpGZyYW5kb2\
1YIMkm7U_78-CWhniH5sHiQYKEzXW-8yAehcSGU1dc-RgJaGRpZ2VzdElEAWxlbGVtZW50VmFsdWX0c\
WVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzE42BhYY6RmcmFuZG9tWCBf_umbK3Upi4eu3ykcitDH\
3cNapjIY2vb3pLS6YjUUHmhkaWdlc3RJRAJsZWxlbWVudFZhbHVlZExlYWRxZWxlbWVudElkZW50aWZ\
pZXJqZ2l2ZW5fbmFtZdgYWG2kZnJhbmRvbVggswa0-_wx3W92HhKOwruVqKWvZ4RyxNaagTgCboVD0S\
NoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZdkD7GoyMDI1LTA3LTA3cWVsZW1lbnRJZGVudGlmaWVya2V4c\
GlyeV9kYXRl2BhYZKRmcmFuZG9tWCCluLZPpNMcbbhydfr-f5TwwKZYyLOwUsp_huttA4-uf2hkaWdl\
c3RJRARsZWxlbWVudFZhbHVlZE1lYWFxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhvpGZ\
yYW5kb21YIJHV8kSIxcv4m0jcv713ymAac9T8uqFcV-z2dEYjXBAMaGRpZ2VzdElEBWxlbGVtZW50Vm\
FsdWXZA-xqMjAyNS0wNC0wOHFlbGVtZW50SWRlbnRpZmllcm1pc3N1YW5jZV9kYXRl2BhYdaRmcmFuZ\
G9tWCDQPMt2xE6tGSBMHFud6DOM31oMUjS00bcUnkjAU51SSGhkaWdlc3RJRAZsZWxlbWVudFZhbHVl\
b1Rlc3QgUElEIGlzc3VlcnFlbGVtZW50SWRlbnRpZmllcnFpc3N1aW5nX2F1dGhvcml0edgYWGakZnJ\
hbmRvbVgglEWoNQu1bHeEKsFdtWeV4lcgfPin7fnscdkmRVdT5tRoZGlnZXN0SUQHbGVsZW1lbnRWYW\
x1ZWJGQ3FlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnk=";

        let err = IssuerSigned::from_base64_url(PAYLOAD).unwrap_err();

        assert_matches!(err.error, MdocError::IssuerSignedParse);
    }

    #[test]
    fn test_document_verify_device_signature() {
        let device_response = DeviceResponse::from_base64_cbor(VP_TOKEN).unwrap();
        let document = device_response.documents.as_ref().unwrap()[0].clone();

        document
            .verify(
                CLIENT_ID,
                RESPONSE_URI,
                NONCE,
                Some(JWK_PUBLIC.as_object().unwrap()),
                None,
                |_| Some(&Es256Verifier),
            )
            .unwrap();
    }

    #[test]
    fn test_document_verify_device_signature_invalid_nonce() {
        let device_response = DeviceResponse::from_base64_cbor(VP_TOKEN).unwrap();
        let document = device_response.documents.as_ref().unwrap()[0].clone();

        let nonce = "invalid_nonce";

        let err = document
            .verify(
                CLIENT_ID,
                RESPONSE_URI,
                nonce,
                Some(JWK_PUBLIC.as_object().unwrap()),
                None,
                |_| Some(&Es256Verifier),
            )
            .unwrap_err();

        assert_matches!(err.error, MdocError::InvalidSignature);
    }

    #[test]
    fn test_document_verify_device_signature_missing_jwk_public() {
        let device_response = DeviceResponse::from_base64_cbor(VP_TOKEN).unwrap();
        let document = device_response.documents.as_ref().unwrap()[0].clone();

        let err = document
            .verify(CLIENT_ID, RESPONSE_URI, NONCE, None, None, |_| {
                Some(&Es256Verifier)
            })
            .unwrap_err();

        assert_matches!(err.error, MdocError::InvalidSignature);
    }

    #[test]
    fn test_document_verify_device_signature_wrong_jwk_public() {
        let device_response = DeviceResponse::from_base64_cbor(VP_TOKEN).unwrap();
        let document = device_response.documents.as_ref().unwrap()[0].clone();

        let jwk_public = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "Zp7aQ2vLm9Xc4Rt6Hy8Kj3Nd5Fg1Ws0TbUeYq2Mn4Lo",
            "y": "mQ4nV7cX2sZd8Lf1Hp6Wr3Tk9Jy0Bg5UaNe2Pv8RcKs",
        });

        let err = document
            .verify(
                CLIENT_ID,
                RESPONSE_URI,
                NONCE,
                Some(jwk_public.as_object().unwrap()),
                None,
                |_| Some(&Es256Verifier),
            )
            .unwrap_err();

        assert_matches!(err.error, MdocError::InvalidSignature);
    }

    #[test]
    fn test_document_verify_device_signature_invalid_client_id() {
        let device_response = DeviceResponse::from_base64_cbor(VP_TOKEN).unwrap();
        let document = device_response.documents.as_ref().unwrap()[0].clone();

        let client_id = "invalid_client_id";

        let err = document
            .verify(
                client_id,
                RESPONSE_URI,
                NONCE,
                Some(JWK_PUBLIC.as_object().unwrap()),
                None,
                |_| Some(&Es256Verifier),
            )
            .unwrap_err();

        assert_matches!(err.error, MdocError::InvalidSignature);
    }

    #[test]
    fn test_document_verify_device_signature_invalid_response_uri() {
        let device_response = DeviceResponse::from_base64_cbor(VP_TOKEN).unwrap();
        let document = device_response.documents.as_ref().unwrap()[0].clone();

        let response_uri = "invalid_response_uri";

        let err = document
            .verify(
                CLIENT_ID,
                response_uri,
                NONCE,
                Some(JWK_PUBLIC.as_object().unwrap()),
                None,
                |_| Some(&Es256Verifier),
            )
            .unwrap_err();

        assert_matches!(err.error, MdocError::InvalidSignature);
    }

    #[test]
    fn test_document_verify_device_signature_missing_verifier() {
        let device_response = DeviceResponse::from_base64_cbor(VP_TOKEN).unwrap();
        let document = device_response.documents.as_ref().unwrap()[0].clone();

        let err = document
            .verify(
                CLIENT_ID,
                RESPONSE_URI,
                NONCE,
                Some(JWK_PUBLIC.as_object().unwrap()),
                None,
                |_| None,
            )
            .unwrap_err();

        assert_matches!(err.error, MdocError::MissingSignatureVerifier(alg) if alg == SigningAlgorithm::Es256);
    }

    #[test]
    fn test_document_verify_device_signature_with_invalid_keys() {
        let device_response = DeviceResponse::from_base64_cbor(VP_TOKEN).unwrap();
        let mut document = device_response.documents.as_ref().unwrap()[0].clone();

        // signature from malicious party
        document
            .device_signed
            .device_auth
            .device_signature_inner_mut()
            .signature = hex::decode("0a72d6c63a2eb9f0ef6ccc70a7b06c193d9d279d637d427c9ee2b41ce430041408bd6ea822e9457591d52e78ed6efacfc5e05d485fb21574d9c75af456013377").unwrap();

        let err = document
            .verify(
                CLIENT_ID,
                RESPONSE_URI,
                NONCE,
                Some(JWK_PUBLIC.as_object().unwrap()),
                None,
                |_| Some(&Es256Verifier),
            )
            .unwrap_err();

        assert_matches!(err.error, MdocError::InvalidSignature)
    }

    #[test]
    fn test_device_response_to_from_base64_cbor() {
        let mut device_response = present_dummy_mdoc(100, None, None);

        // we set this because after deserialization it gets set to that vec
        // automatically
        // ISO doesn't mention anything about placing stuff in the protected
        // header here
        device_response
            .documents
            .as_mut()
            .unwrap()
            .first_mut()
            .unwrap()
            .device_signed
            .device_auth
            .device_signature_inner_mut()
            .protected
            .original_data = Some(vec![161, 1, 38]);

        let serialized = device_response.to_base64_cbor().unwrap();

        let mut deserialized = DeviceResponse::from_base64_cbor(&serialized).unwrap();

        remove_original_data_from_documents(deserialized.documents.as_mut().unwrap());
        remove_original_data_from_documents(device_response.documents.as_mut().unwrap());

        assert_eq!(device_response, deserialized);
    }

    #[test]
    fn reordered_fields_in_issuer_signed_item_bytes_produce_different_digest() {
        // Generated with cbor.zone
        const ISSUER_SIGNED_ITEM_BYTES: &str = "d8185852a46672616e646f6d50f4b65b3379407aa9a0390309\
b792344c71656c656d656e744964656e7469666965726b66616d696c795f6e616d65686469676573744944006c656c656d\
656e7456616c756563446f65";

        let mut issuer_signed_item_bytes: IssuerSignedItemBytes =
            ciborium::from_reader(hex::decode(ISSUER_SIGNED_ITEM_BYTES).unwrap().as_slice())
                .unwrap();

        let deserialized_data_digest = issuer_signed_item_bytes
            .digest(&DigestAlgorithm::Sha256)
            .unwrap();

        // this is same as creating new instance without deserialized data
        issuer_signed_item_bytes.0.original_data = None;

        let newly_created_data_digest = issuer_signed_item_bytes
            .digest(&DigestAlgorithm::Sha256)
            .unwrap();

        assert_ne!(deserialized_data_digest, newly_created_data_digest);
    }
}

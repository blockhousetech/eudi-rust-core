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

//! This module defines the data model described in the section "8.3.2.1.2.2 Device retrieval mdoc
//! response" of the [ISO/IEC 18013-5:2021][1] standard.
//!
//! [1]: <https://www.iso.org/standard/69084.html>
use std::collections::HashMap;

use base64::Engine as _;
use bh_jws_utils::{SignatureVerifier, SigningAlgorithm};
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

    /// Parses the provided `base64url`-encoded `string` of _CBOR_ data into
    /// [`DeviceResponse`].
    pub fn from_base64_cbor(value: &str) -> Result<Self> {
        // HACK(third-party): We should only use `base64_url_decode`, but the `vp_token` from a
        // certain `third-party` implementation is encoded with invalid padding so we workaround
        // that here.

        let decoded = match base64_url_decode(value) {
            Ok(decoded) => decoded,
            Err(base64::DecodeError::InvalidPadding) => base64::engine::general_purpose::URL_SAFE
                .decode(value)
                .foreign_err(|| MdocError::DeviceResponseParse("invalid base64".to_owned()))?,
            Err(err) => Err(err)
                .foreign_err(|| MdocError::DeviceResponseParse("invalid base64".to_owned()))?,
        };

        ciborium::from_reader(decoded.as_slice())
            .foreign_err(|| MdocError::DeviceResponseParse("invalid CBOR".to_owned()))
    }

    /// Serializes the [`DeviceResponse`] to `base64url`-encoded (**without
    /// padding**) `string` of _CBOR_ data.
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
    /// MAC results in the [DeviceMac][MdocError::DeviceMac] error.
    pub(crate) fn verify<'a>(
        &self,
        client_id: &str,
        response_uri: &str,
        nonce: &str,
        mdoc_generated_nonce: &str,
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
                mdoc_generated_nonce,
                &self.doc_type,
                get_signature_verifier,
                &device_key,
            )
            .ctx(|| "device signature")
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
    issuer_auth: IssuerAuth,
}

impl IssuerSigned {
    /// Creates a new `IssuerSigned` object with a single namespace.
    pub(crate) fn new<Signer: bh_jws_utils::Signer + bh_jws_utils::HasX5Chain, R: Rng + ?Sized>(
        doc_type: DocType,
        name_spaces: Claims,
        device_key: DeviceKey,
        signer: &Signer,
        rng: &mut R,
        current_time: u64,
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

        let issuer_auth =
            IssuerAuth::new(doc_type, &name_spaces, device_key, signer, current_time)?;

        Ok(Self {
            name_spaces: Some(name_spaces),
            issuer_auth,
        })
    }

    /// Deserializes the provided _CBOR_-serialized and _base64url_-encoded string into the
    /// [`IssuerSigned`].
    pub(crate) fn from_base64_url(base64_url: &str) -> Result<Self> {
        // TODO(issues/24): Remove fallback to URL_SAFE once certain `third-party` implementation
        // fixes its bug.
        let decoded = match base64_url_decode(base64_url) {
            Ok(decoded) => decoded,
            Err(base64::DecodeError::InvalidPadding) => base64::engine::general_purpose::URL_SAFE
                .decode(base64_url)
                .foreign_err(|| MdocError::IssuerSignedParse)
                .ctx(|| "invalid base64-url payload")?,
            Err(err) => {
                return Err(err)
                    .foreign_err(|| MdocError::IssuerSignedParse)
                    .ctx(|| "invalid base64-url payload")
            }
        };

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
        mdoc_generated_nonce: &str,
        doc_type: &DocType,
        signer: &impl bh_jws_utils::Signer,
    ) -> Result<Self> {
        let name_spaces = name_spaces.into();

        let device_authentication = DeviceAuthentication::new(
            client_id,
            response_uri,
            nonce,
            mdoc_generated_nonce,
            doc_type,
            &name_spaces,
        );

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
        mdoc_generated_nonce: &str,
        doc_type: &DocType,
        get_signature_verifier: impl Fn(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
        device_key: &DeviceKey,
    ) -> Result<()> {
        let device_authentication = DeviceAuthentication::new(
            client_id,
            response_uri,
            nonce,
            mdoc_generated_nonce,
            doc_type,
            &self.name_spaces,
        );

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
    use assert_matches::assert_matches;
    use bh_jws_utils::{Es256Verifier, Signer as _};
    use ciborium::{from_reader, into_writer};
    use coset::{
        iana::{EnumI64 as _, HeaderParameter},
        CoseSign1Builder, Header, Label,
    };

    use super::*;
    use crate::{
        models::{
            data_retrieval::device_retrieval::device_auth::{
                DeviceAuthentication, DeviceAuthenticationBytes,
            },
            mdl::{MDL_DOCUMENT_TYPE, MDL_NAMESPACE},
        },
        utils::test::{present_dummy_mdoc, remove_original_data_from_documents},
    };

    /// This was generated by `third-party` wallet implementation at some point.
    const VP_TOKEN: &str =
        "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBld2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xbGlz\
        c3VlclNpZ25lZKJqbmFtZVNwYWNlc6F3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjGB2BhYZKRmcmFuZG9tW\
        CB8MjtuYHWCMGH1iz5EmmpJXhbTQLzz_TTp6Dy1-479FWhkaWdlc3RJRABsZWxlbWVudFZhbHVlZEpvaG\
        5xZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWVqaXNzdWVyQXV0aIRDoQEmoRghWQMEMIIDADCCAoa\
        gAwIBAgIUGazK3gunp2AkVzo824kBG4hV-1gwCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3Vl\
        ciBDQSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xC\
        zAJBgNVBAYTAlVUMB4XDTI1MDExNDEyNTcyM1oXDTI2MDQwOTEyNTcyMlowUzEVMBMGA1UEAwwMUElEIE\
        RTIC0gMDAzMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgN\
        VBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAy52Z4doQ6MCdAuG1U9fFFfKvlhmGbmtSVXd\
        F7BNyvktmQbch58hZOfItH8j29wcU3OGf3nNEo1FG8o1vOora6OCAS0wggEpMB8GA1UdIwQYMBaAFLNsu\
        JEXHNekGmYxh0Lhi8BAzJUbMBsGA1UdEQQUMBKCEGlzc3Vlci5ldWRpdy5kZXYwFgYDVR0lAQH_BAwwCg\
        YIK4ECAgAAAQIwQwYDVR0fBDwwOjA4oDagNIYyaHR0cHM6Ly9wcmVwcm9kLnBraS5ldWRpdy5kZXYvY3J\
        sL3BpZF9DQV9VVF8wMS5jcmwwHQYDVR0OBBYEFH7QIGQSbLgqDS8Pdq5Uu_IyX3-IMA4GA1UdDwEB_wQE\
        AwIHgDBdBgNVHRIEVjBUhlJodHRwczovL2dpdGh1Yi5jb20vZXUtZGlnaXRhbC1pZGVudGl0eS13YWxsZ\
        XQvYXJjaGl0ZWN0dXJlLWFuZC1yZWZlcmVuY2UtZnJhbWV3b3JrMAoGCCqGSM49BAMCA2gAMGUCMFh4E-\
        SbogxFDzalQt3tVWWkcqx6hcImUQ6UVwLeBWPRoKgpyCnyGp-yLHDWrGvoOQIxAO155AH-T3Mg14Oc6Qn\
        c6Ht6o-YuIN86voO6GkwconHsrcBSj5TwJcqNB5qtf7I191kDd9gYWQNyp2ZzdGF0dXOhblN0YXR1c0xp\
        c3RJbmZvomtzdGF0dXNfbGlzdKJjaWR4AGN1cml4amh0dHBzOi8vaXNzdWVyLmV1ZGl3LmRldi90b2tlb\
        l9zdGF0dXNfbGlzdC9GQy9ldS5ldXJvcGEuZWMuZXVkaS5waWQuMS9lMThmZWZhMi1mMWU4LTQzMGEtOW\
        E5Ni0xNDE5NzZjZjM2ZGFvaWRlbnRpZmllcl9saXN0omJpZGEwY3VyaXhoaHR0cHM6Ly9pc3N1ZXIuZXV\
        kaXcuZGV2L2lkZW50aWZpZXJfbGlzdC9GQy9ldS5ldXJvcGEuZWMuZXVkaS5waWQuMS9lMThmZWZhMi1m\
        MWU4LTQzMGEtOWE5Ni0xNDE5NzZjZjM2ZGFnZG9jVHlwZXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMWd2Z\
        XJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB0MjAyNS0wMi0xMlQxMDoyNzowM1ppdmFsaWRGcm\
        9twHQyMDI1LTAyLTEyVDEwOjI3OjAzWmp2YWxpZFVudGlswHQyMDI1LTA1LTEzVDAwOjAwOjAwWmx2YWx\
        1ZURpZ2VzdHOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xqABYIILzC0H8YlT-HDQEoGsKwNQNIaHU6NQH\
        3MQab3ss38XJAVggg_sFPzlWXjwUd13K8yf805nzq6aO_JRGdDhS-uNQh5ICWCCGFlYfQZl3bdgxQZrdm\
        _s1ic30DKo7gu8lfENpG1KcfANYIC5shdtREMDfd3cLIj5_3Xu2V8ezGyEqk71j2TQdh0Y1BFggAj5wDS\
        09j2m_t08cWpYaIfwKEC9uyl6W0A6km1eOsy0FWCAg6V6lEdPPcxTd2PUIcuV099dLSgGmdmQwLeLzS6s\
        BvQZYIHt5BaSLWphy3u7yxzwbM6fyrYjbBldnl_2DDjILna0SB1ggZVnBUlU1JuF2z4f7Dv2PP98xBxUb\
        e1I6USNeQ_tT9NdtZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCBpaI3FCk1DmWUfjkHwuppqR\
        0rHAvGM-0PuRid6viT-IyJYIEiIVRM3JmtTe7q8t7jjY9QYTtLu3EVWjvKvLV1n2hQjb2RpZ2VzdEFsZ2\
        9yaXRobWdTSEEtMjU2WECrwHqWhLDY3Pa-HuSUdmZtTIMb9xSl48Cqgj712l0jsdTFdFAje861N_Pwx0v\
        oJLnis7A7aB9JWmpmLOt8VtWhbGRldmljZVNpZ25lZKJqbmFtZVNwYWNlc9gYQaBqZGV2aWNlQXV0aKFv\
        ZGV2aWNlU2lnbmF0dXJlhEOhASag9lhArMbbgrbAa-oHqKaR4XyY8r2LWSTMIOCpsUSxcr1CBJqsiV50c\
        5mID9l7UiqSCu-idnROQitmza2XSLK8_CK2_2ZzdGF0dXMA";

    const VERIFIER_NONCE: &str = "u-mIdOrsG-G6ynC27BJ2QQ";
    const MDOC_GENERATED_NONCE: &str = "hg5-4lUtlgpx5gwdhsQEBQ";

    // Generate device response with valid signatures and certificates.
    fn dummy_response() -> DeviceResponse {
        let name_spaces = IssuerNameSpaces(
            [(
                MDL_NAMESPACE.to_owned().into(),
                vec![
                    IssuerSignedItem {
                        digest_id: 0u64.into(),
                        random: "f4b65b3379407aa9a0390309b792344c".parse().unwrap(),
                        element_identifier: "family_name".to_owned().into(),
                        element_value: "Doe".into(),
                    }
                    .into(),
                    IssuerSignedItem {
                        digest_id: 1u64.into(),
                        random: "b82484fc40a0f1c999e9aa168eb6f57c".parse().unwrap(),
                        element_identifier: "given_name".to_owned().into(),
                        element_value: "John".into(),
                    }
                    .into(),
                    IssuerSignedItem {
                        digest_id: 2u64.into(),
                        random: "e247c0fe30b80eadce962b3de07084b3".parse().unwrap(),
                        element_identifier: "birth_date".to_owned().into(),
                        element_value: "1980-01-02".into(),
                    }
                    .into(),
                ],
            )]
            .into(),
        );

        let issuer_signer = crate::utils::test::SimpleSigner::issuer();
        let (device_signer, device_key) = crate::utils::test::dummy_device_key();

        let issuer_auth = IssuerAuth::new(
            "org.iso.18013.5.1.mDL".into(),
            &name_spaces,
            device_key,
            &issuer_signer,
            100,
        )
        .unwrap();

        let issuer_signed = IssuerSigned {
            name_spaces: Some(name_spaces),
            issuer_auth,
        };

        let device_name_spaces = DeviceNameSpaces(HashMap::new()).into();
        let doctype = MDL_DOCUMENT_TYPE.into();
        let device_authentication: DeviceAuthenticationBytes = DeviceAuthentication::new(
            "dummy verifier client id",
            "http://dummy-uri",
            "dummy nonce",
            "other dummy nonce",
            &doctype,
            &device_name_spaces,
        )
        .into();

        let mut payload = Vec::new();
        into_writer(&device_authentication, &mut payload)
            .foreign_err(|| MdocError::DeviceAuthentication)
            .unwrap();

        let alg = coset::iana::Algorithm::ES256;
        let protected = coset::Header {
            alg: Some(coset::Algorithm::Assigned(alg)),
            ..Default::default()
        };

        let unprotected = Header {
            rest: vec![(
                Label::Int(HeaderParameter::X5Chain.to_i64()),
                ciborium::Value::Array(vec![]),
            )],
            ..Default::default()
        };

        let mut device_cose_sign1 = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .create_detached_signature(&payload, &[], |data| device_signer.sign(data).unwrap())
            .build();

        // default `CoseSign1.protected.original_data` is `None`, but after
        // ser/de it becomes `Some(vec![161, 1, 38])` so it is set like that here manually
        device_cose_sign1.protected.original_data = Some(vec![161, 1, 38]);

        let device_signed = DeviceSigned {
            name_spaces: device_name_spaces,
            device_auth: DeviceAuth::DeviceSignature(device_cose_sign1.into()),
        };

        DeviceResponse {
            version: DEVICE_RESPONSE_VERSION.to_owned(),
            documents: Some(vec![Document {
                doc_type: MDL_DOCUMENT_TYPE.into(),
                issuer_signed,
                device_signed,
                errors: None,
            }]),
            document_errors: None,
            status: 0,
        }
    }

    #[test]
    fn test_response() {
        let response = dummy_response();

        let mut encoded = Vec::new();

        into_writer(&response.clone(), &mut encoded).unwrap();

        let mut decoded: DeviceResponse = from_reader(encoded.as_slice()).unwrap();

        remove_original_data_from_documents(decoded.documents.as_mut().unwrap());

        assert_eq!(response, decoded);
    }

    #[test]
    fn device_response_from_base64() {
        /// This was generated by a `third-party` implementation at some point.
        const PAYLOAD: &str = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9y\
Zy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZ19pc29fMTgwMTN\
fNV8xgtgYWFKkaGRpZ2VzdElEAGZyYW5kb21QIBsw4QdcCU7p3TAlXLUhR3FlbGVtZW50SWRlbnRpZm\
llcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVjRG9l2BhYWKRoZGlnZXN0SUQCZnJhbmRvbVACqLYXh\
eJFRzC40lsh6yq8cWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5ODAt\
MDEtMDJqaXNzdWVyQXV0aIRDoQEmoRghWQFLMIIBRzCB7qADAgECAgg57ch6mnj5KjAKBggqhkjOPQQ\
DAjAXMRUwEwYDVQQDDAxNRE9DIFJPT1QgQ0EwHhcNMjQwNTAyMTMxMzMwWhcNMjUwNTAyMTMxMzMwWj\
AbMRkwFwYDVQQDDBBNRE9DIFRlc3QgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEG0RIN\
BiF-oQUD3d5DGnegQuXenI29JDaMGoMvioKRBN53d4UazakS2unu8BnsEtxutS2kqRhYBPYk9RAriU3\
gaMgMB4wDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSAAwRQIhAI5wBBA\
A3ewqIwslhuzFn4rNFW9dkz2TY7xeImO7CraYAiAYhai1NzJ6abAiYg8HxcRdYpO4bu2Sej8E6CzFHK\
34Y1kBw9gYWQG-pmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2Vzd\
HOhcW9yZ19pc29fMTgwMTNfNV8xowBYIIXUtCznu-4CnWivDESZoRvtlxjQdmt79EdKfzubMty1AVgg\
vBXpuXDOlefwcyCY2yOOK4ONuyNq__cpD64kBycgVUACWCBhHekPObnLF5tmMy6BX4aZ2rbI8Getkzb\
zo8OhrW-T621kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIHcbsgk0wLT6AIkzndNF4CLjAj\
7bNEf4dMw0c98EINZ3Ilgg80Q6qOipMrsZB7WDWI6dyGqa8jNARA58GtHx0oyLUt9nZG9jVHlwZXVvc\
mcuaXNvLjE4MDEzLjUuMS5tRExsdmFsaWRpdHlJbmZvo2ZzaWduZWTAeB4yMDI0LTEyLTA0VDA4OjQz\
OjQ2Ljk1NzI5ODY3N1ppdmFsaWRGcm9twHgeMjAyNC0xMi0wNFQwODo0Mzo0Ni45NTczMDA1NTFaanZ\
hbGlkVW50aWzAeB4yMDI1LTEyLTA0VDA4OjQzOjQ2Ljk1NzMwMDk5NlpYQE4rD9KsoPn9QFfdBNStvM\
NEaaCfkGsUf462YdFWxpyvQK2z8socwOWKxtsRsu05UQjSDKClfrYnIjdrK9qgHV9sZGV2aWNlU2lnb\
mVkompuYW1lU3BhY2Vz2BhBoGpkZXZpY2VBdXRooW9kZXZpY2VTaWduYXR1cmWEQ6EBJqEYIYD2WEDs\
5eTKpqi4GeqQSGuBlU4NVSidbnVpWrSC0OHGUThorpCiRuWvBa4zsQwK5of3yGQiuqlCQrkgLFVYpjJ\
tseR5ZnN0YXR1cwA=";

        let mut response = DeviceResponse::from_base64_cbor(PAYLOAD).unwrap();

        remove_original_data_from_documents(response.documents.as_mut().unwrap());

        let document = response.documents.as_ref().unwrap()[0].clone();

        let expected = DeviceResponse {
            version: DEVICE_RESPONSE_VERSION.to_owned(),
            documents: Some(vec![Document {
                doc_type: MDL_DOCUMENT_TYPE.into(),
                issuer_signed: IssuerSigned {
                    name_spaces: Some(IssuerNameSpaces(
                        [(
                            "org_iso_18013_5_1".into(),
                            vec![
                                IssuerSignedItem {
                                    digest_id: 0u64.into(),
                                    random: Bytes::from_hex("201b30e1075c094ee9dd30255cb52147")
                                        .unwrap(),
                                    element_identifier: "family_name".into(),
                                    element_value: "Doe".into(),
                                }
                                .into(),
                                IssuerSignedItem {
                                    digest_id: 2u64.into(),
                                    random: Bytes::from_hex("02a8b61785e2454730b8d25b21eb2abc")
                                        .unwrap(),
                                    element_identifier: "birth_date".into(),
                                    element_value: "1980-01-02".into(),
                                }
                                .into(),
                            ],
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
    fn issuer_signed_from_base64_with_padding() {
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

        assert_matches!(
            IssuerSigned::from_base64_url(PAYLOAD),
            Ok(IssuerSigned { .. })
        );
    }

    #[test]
    fn test_document_verify_device_signature() {
        let device_response = DeviceResponse::from_base64_cbor(VP_TOKEN).unwrap();
        let document = device_response.documents.as_ref().unwrap()[0].clone();

        let client_id = "https://192.168.0.22:5000/protocol/oid4vp/authorization-response";
        let response_uri = "https://192.168.0.22:5000/protocol/oid4vp/authorization-response";
        let nonce = VERIFIER_NONCE;
        let mdoc_generated_nonce = MDOC_GENERATED_NONCE;

        document
            .verify(
                client_id,
                response_uri,
                nonce,
                mdoc_generated_nonce,
                None,
                |_| Some(&Es256Verifier),
            )
            .unwrap();
    }

    #[test]
    fn test_document_verify_device_signature_invalid_nonce() {
        let device_response = DeviceResponse::from_base64_cbor(VP_TOKEN).unwrap();
        let document = device_response.documents.as_ref().unwrap()[0].clone();

        let client_id = "https://192.168.0.22:5000/protocol/oid4vp/authorization-response";
        let response_uri = "https://192.168.0.22:5000/protocol/oid4vp/authorization-response";
        let nonce = "invalid_nonce";
        let mdoc_generated_nonce = MDOC_GENERATED_NONCE;

        let err = document
            .verify(
                client_id,
                response_uri,
                nonce,
                mdoc_generated_nonce,
                None,
                |_| Some(&Es256Verifier),
            )
            .unwrap_err();

        assert_matches!(err.error, MdocError::InvalidSignature);
    }

    #[test]
    fn test_document_verify_device_signature_invalid_mdoc_generated_nonce() {
        let device_response = DeviceResponse::from_base64_cbor(VP_TOKEN).unwrap();
        let document = device_response.documents.as_ref().unwrap()[0].clone();

        let client_id = "https://192.168.0.22:5000/protocol/oid4vp/authorization-response";
        let response_uri = "https://192.168.0.22:5000/protocol/oid4vp/authorization-response";
        let nonce = VERIFIER_NONCE;
        let mdoc_generated_nonce = "invalid nonce";

        let err = document
            .verify(
                client_id,
                response_uri,
                nonce,
                mdoc_generated_nonce,
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
        let response_uri = "https://192.168.0.22:5000/protocol/oid4vp/authorization-response";
        let nonce = VERIFIER_NONCE;
        let mdoc_generated_nonce = MDOC_GENERATED_NONCE;

        let err = document
            .verify(
                client_id,
                response_uri,
                nonce,
                mdoc_generated_nonce,
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

        let client_id = "https://192.168.0.22:5000/protocol/oid4vp/authorization-response";
        let response_uri = "invalid_response_uri";
        let nonce = VERIFIER_NONCE;
        let mdoc_generated_nonce = MDOC_GENERATED_NONCE;

        let err = document
            .verify(
                client_id,
                response_uri,
                nonce,
                mdoc_generated_nonce,
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

        let client_id = "https://192.168.0.22:5000/protocol/oid4vp/authorization-response";
        let response_uri = "https://192.168.0.22:5000/protocol/oid4vp/authorization-response";
        let nonce = VERIFIER_NONCE;
        let mdoc_generated_nonce = MDOC_GENERATED_NONCE;

        let err = document
            .verify(
                client_id,
                response_uri,
                nonce,
                mdoc_generated_nonce,
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

        let client_id = "https://192.168.0.22:5000/protocol/oid4vp/authorization-response";
        let response_uri = "https://192.168.0.22:5000/protocol/oid4vp/authorization-response";
        let nonce = VERIFIER_NONCE;
        let mdoc_generated_nonce = MDOC_GENERATED_NONCE;

        // signature from malicious party
        document
            .device_signed
            .device_auth
            .device_signature_inner_mut()
            .signature = hex::decode("0a72d6c63a2eb9f0ef6ccc70a7b06c193d9d279d637d427c9ee2b41ce430041408bd6ea822e9457591d52e78ed6efacfc5e05d485fb21574d9c75af456013377").unwrap();

        let err = document
            .verify(
                client_id,
                response_uri,
                nonce,
                mdoc_generated_nonce,
                None,
                |_| Some(&Es256Verifier),
            )
            .unwrap_err();

        assert_matches!(err.error, MdocError::InvalidSignature)
    }

    #[test]
    fn test_device_response_to_from_base64_cbor() {
        let mut device_response = present_dummy_mdoc(100);

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

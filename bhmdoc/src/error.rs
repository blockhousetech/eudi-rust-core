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

//! This module defines the error values returned by the crate API.

use bh_jws_utils::SigningAlgorithm;

use crate::models::data_retrieval::{
    common::{DocType, NameSpace},
    device_retrieval::response::DigestID,
};

/// Error type used across the crate API.
#[derive(strum_macros::Display, Debug, PartialEq, Clone)]
pub enum MdocError {
    /// Error used by
    /// [`MobileSecurityObject`][crate::models::data_retrieval::device_retrieval::issuer_auth::MobileSecurityObject]
    /// API.
    #[strum(to_string = "Error in Mobile Security Object")]
    MobileSecurityObject,
    /// Error used by [`issuer_auth`][crate::models::data_retrieval::device_retrieval::issuer_auth]
    /// API.
    #[strum(to_string = "Error in Issuer Auth")]
    IssuerAuth,
    /// Error when we fail to create a
    /// [`DeviceSignature`][crate::models::data_retrieval::device_retrieval::device_auth::DeviceSignature].
    #[strum(to_string = "Error when signing data")]
    Signing,
    /// Error when we fail to decode a JWK.
    #[strum(to_string = "Error while converting JWK to DeviceKey: {0}")]
    JwkToCoseKey(String),
    /// Error when we fail to encode a JWK.
    #[strum(to_string = "Error while converting DeviceKey to JWK: {0}")]
    CoseKeyToJwk(String),
    /// Error when we fail to parse a
    /// [`DeviceResponse`][crate::models::data_retrieval::device_retrieval::response::DeviceResponse].
    #[strum(to_string = "Failed to parse Device Response: {0}")]
    DeviceResponseParse(String),
    /// Error when verifying `mDoc` Credential if we get an an empty
    /// [`DeviceResponse`][crate::models::data_retrieval::device_retrieval::response::DeviceResponse].
    #[strum(to_string = "Device Response contains no documents")]
    EmptyDeviceResponse,
    /// Error when we detect a signature isn't valid.
    #[strum(to_string = "Signature validation failed")]
    InvalidSignature,
    /// Error when the underlying data model is missing a signing algorithm or if we don't support
    /// it.
    #[strum(to_string = "Signing algorithm is missing or unsupported")]
    MissingSigningAlgorithm,
    /// Error when we are missing an appropriate signature verification implementation.
    #[strum(to_string = "Signature verifier for the {0} is missing")]
    MissingSignatureVerifier(SigningAlgorithm),
    /// Error if we don't have a valid public key in
    /// [`IssuerAuth`][crate::models::data_retrieval::device_retrieval::issuer_auth::IssuerAuth].
    #[strum(to_string = "Issuer's public key from `IssuerAuth` is missing or not valid")]
    InvalidPublicKey,
    /// Error when we encounter an unexpected `doc_type`.
    #[strum(to_string = "Invalid `doc_type`, expected {0}, actual {1}")]
    InvalidDocType(DocType, DocType),
    /// Error when the document isn't valid yet, but will be at a later time.
    #[strum(to_string = "Document becomes valid at timestamp {0}")]
    DocumentNotYetValid(i64),
    /// Error when the document has expired.
    #[strum(to_string = "Document expired at timestamp {0}")]
    DocumentExpired(i64),
    /// Error when we are missing a digest for a namespace of a
    /// [`MobileSecurityObject`][crate::models::data_retrieval::device_retrieval::issuer_auth::MobileSecurityObject].
    #[strum(to_string = "Missing digests for namespace {0}")]
    MissingDigestNamespace(NameSpace),
    /// Error when we encounter an invalid digest for a namespace of a
    /// [`MobileSecurityObject`][crate::models::data_retrieval::device_retrieval::issuer_auth::MobileSecurityObject].
    #[strum(to_string = "Missing or invalid digest, namespace=\"{0}\", id=\"{1}\"")]
    MissingOrInvalidDigest(NameSpace, DigestID),
    /// Error when we fail to serialize
    /// [`DeviceAuthentication`][crate::models::data_retrieval::device_retrieval::device_auth::DeviceAuthentication].
    #[strum(to_string = "Failed to serialize `DeviceAuthenticationBytes`")]
    DeviceAuthentication,
    /// Error indicating we currently do not support
    /// [`DeviceMac`][crate::models::data_retrieval::device_retrieval::device_auth::DeviceAuth::DeviceMac].
    #[strum(to_string = "Device MAC is not supported")]
    DeviceMac,
    /// Error when we expect an `x5chain` but it is missing or invalid.
    #[strum(to_string = "Missing or invalid X5Chain")]
    X5Chain,
    /// Error when we fail to parse an issued `mDoc` Credential.
    #[strum(to_string = "Unable to parse issued credential")]
    IssuerSignedParse,
    /// Error when we try to construct [`DateTime`][crate::models::DateTime] from an invalid value.
    #[strum(to_string = "Invalid value for Date Time")]
    InvalidDateTime,
    /// The provided Device [`Signer`][bh_jws_utils::Signer] is invalid.
    #[strum(to_string = "Invalid Device Signer: {0}")]
    InvalidDeviceSigner(String),
    /// Invalid
    /// [`ValidityInfo`][crate::models::data_retrieval::device_retrieval::issuer_auth::ValidityInfo]
    /// data.
    #[strum(to_string = "Validity Info is invalid")]
    InvalidValidityInfo,
}

impl bherror::BhError for MdocError {}

/// Type alias for [`bherror::Result`] types returned by the crate's API.
pub type Result<T> = bherror::Result<T, MdocError>;

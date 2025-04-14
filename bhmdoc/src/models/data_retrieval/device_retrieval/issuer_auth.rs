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

//! This module implements the data model based on the findings from [ISO/IEC 18013-5:2021][1],
//! [RFC 8152][2], [RFC 9052][3], [RFC 9360][4].
//!
//! For now we only support a small subset of features, just to keep things simple.  We should
//! gradually expand the features as needed.
//!
//! [1]: <https://www.iso.org/standard/69084.html>
//! [2]: <https://datatracker.ietf.org/doc/rfc8152/>
//! [3]: <https://datatracker.ietf.org/doc/rfc9052/>
//! [4]: <https://datatracker.ietf.org/doc/rfc9360/>

use std::collections::HashMap;

use bh_jws_utils::{public_jwk_from_x5chain_leaf, JwkPublic, SignatureVerifier, SigningAlgorithm};
use bherror::traits::{
    ErrorContext as _, ForeignBoxed as _, ForeignError as _, PropagateError as _,
};
use bhx5chain::X5Chain;
use coset::{
    iana::{EnumI64 as _, HeaderParameter},
    Algorithm, CoseKey, Header, Label, RegisteredLabelWithPrivate,
};

use super::response::{DigestID, IssuerNameSpaces, IssuerSignedItemBytes};
use crate::{
    error::MdocError,
    models::{
        data_retrieval::common::{DataElementIdentifier, DocType, NameSpace},
        Bytes, BytesCbor, DateTime,
    },
    utils::coset::{cose_key_to_jwk, coset_alg_to_jws_alg, deserialize_coset, serialize_coset},
    Result,
};

/// The version of the [`MobileSecurityObject`] structure.
///
/// The value is currently specified in the section `9.1.2.4` of the [ISO/IEC 18013-5:2021][1].
///
/// [1]: <https://www.iso.org/standard/69084.html>
const MOBILE_SECURITY_OBJECT_VERSION: &str = "1.0";

/// The default `kid` value of the Issuer's public key.
const DEFAULT_ISSUER_KID: &str = "issuer_kid";

/// The default digest algorithm used to add claims' digests to the
/// [`MobileSecurityObject`].
const MSO_DEFAULT_DIGEST_ALG: DigestAlgorithm = DigestAlgorithm::Sha256;

/// [`IssuerAuth`] as defined in the section `9.1.2.4` of the [ISO/IEC 18013-5:2021][1] standard.
///
/// This is just a wrapper around [`coset::CoseSign1`].  More information about `COSE_Sign1`
/// structure can be found in [RFC 8152][2].
///
/// [1]: <https://www.iso.org/standard/69084.html>
/// [2]: <https://datatracker.ietf.org/doc/html/rfc8152>
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IssuerAuth(
    #[serde(
        serialize_with = "serialize_coset",
        deserialize_with = "deserialize_coset"
    )]
    coset::CoseSign1,
);

impl IssuerAuth {
    /// Create a new [`IssuerAuth`].
    ///
    /// The certificate used in `COSE_Sign1` unprotected field is used for verifying
    /// [`IssuerAuth`]'s signature.
    ///
    /// We also hardcode used protocols.
    ///
    /// We use SHA-256 hashing algorithm for digests creation, and for signing purposes we use
    /// ES256.
    ///
    /// Taking values from `name_spaces` we create digests that are used for selective disclosure.
    /// Digests are made using [`IssuerSignedItemBytes`] as specified in section `9.1.2.5` of the
    /// [ISO/IEC 18013-5:2021][1].
    ///
    /// Cryptographic material used for issuing the credential are the following.
    ///
    ///  - `issuer_key`: key used for signing [`IssuerAuth`] and exporting it's public key for
    ///    verification purpose.
    ///  - `device_key`: public key that is bound to the issued credential.
    ///
    /// [1]: <https://www.iso.org/standard/69084.html>
    pub fn new<Signer: bh_jws_utils::Signer + bh_jws_utils::HasX5Chain>(
        doc_type: DocType,
        name_spaces: &IssuerNameSpaces,
        device_key: DeviceKey,
        signer: &Signer,
        current_time: u64,
    ) -> crate::Result<Self> {
        // For now we are only signing with ES256
        let alg = match signer.algorithm() {
            SigningAlgorithm::Es256 => coset::iana::Algorithm::ES256,
            _ => {
                return Err(bherror::Error::root(MdocError::IssuerAuth)
                    .ctx("Only ES256 signatures are currently supported"))
            }
        };
        let protected = Header {
            alg: Some(Algorithm::Assigned(alg)),
            ..Default::default()
        };

        let unprotected = Header {
            rest: vec![(
                Label::Int(HeaderParameter::X5Chain.to_i64()),
                x5chain_to_cbor_value(signer.x5chain())?,
            )],
            ..Default::default()
        };

        let mso: MobileSecurityObjectBytes =
            MobileSecurityObject::new(doc_type, name_spaces, device_key, current_time)?.into();
        let mut mso_bytes = vec![];
        ciborium::into_writer(&mso, &mut mso_bytes).foreign_err(|| MdocError::IssuerAuth)?;

        let mut cose_sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(mso_bytes)
            .try_create_signature(&[], |data| signer.sign(data))
            .foreign_boxed_err(|| MdocError::IssuerAuth)?
            .build();

        // This is hack so our test passes. The `original_data` field will only be filled if
        // CoseSign1 is deserialized from CBOR. However, in test we have following case:
        //
        //  - manually create CoseSign1 (`original_data` is empty)
        //  - serialize CoseSign1
        //  - deserialize CoseSign1 (now `original_data` isn't empty)
        //  - compare created and deserialized structs
        //
        // This fix will help as we always use same signing algorithm, but we must be aware of this
        // once we start supporting other.
        cose_sign1.protected.original_data = Some(vec![161, 1, 38]);

        Ok(Self(cose_sign1))
    }

    /// Verifies the issuer's signature of the [`IssuerAuth`].
    ///
    /// The required information is extracted from the unprotected and protected
    /// header of the underlying `COSE_Sign1` structure.
    pub(crate) fn verify_signature<'a>(
        &self,
        get_signature_verifier: impl Fn(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
    ) -> Result<()> {
        let alg = self
            .signing_algorithm()
            .ok_or_else(|| bherror::Error::root(MdocError::MissingSigningAlgorithm))
            .ctx(|| "issuer authentication")?;

        let jwk = self.public_jwk(&alg)?;

        let signature_verifier = get_signature_verifier(alg)
            .ok_or_else(|| bherror::Error::root(MdocError::MissingSignatureVerifier(alg)))?;

        self.0.verify_signature(&[], |sig, data| {
            let verified = signature_verifier
                .verify(data, sig, &jwk)
                .foreign_boxed_err(|| MdocError::InvalidSignature)
                .ctx(|| "error while verifying signature")?;

            if !verified {
                return Err(bherror::Error::root(MdocError::InvalidSignature)
                    .ctx("the signature is not valid"));
            };

            Ok(())
        })
    }

    /// Validates the claims of the underlying [`MobileSecurityObject`].
    ///
    /// Validation includes the time-validity information, as well as the
    /// presence of digests of the provided [`IssuerNameSpaces`].
    ///
    /// **Note**: this is intended to be used only by the `mDoc` Verifier.
    pub(crate) fn validate_verifier(
        &self,
        current_time: u64,
        doc_type: &DocType,
        name_spaces: Option<&IssuerNameSpaces>,
    ) -> Result<()> {
        self.mso()?
            .validate_verifier(current_time, doc_type, name_spaces)
    }

    /// Validates the claims of the underlying [`MobileSecurityObject`].
    ///
    /// Validation includes the time-validity information, as well as the
    /// presence of digests of the provided [`IssuerNameSpaces`].
    ///
    /// **Note**: this is intended to be used only by the `mDoc` Device.
    pub(crate) fn validate_device(
        &self,
        current_time: u64,
        doc_type: &DocType,
        name_spaces: Option<&IssuerNameSpaces>,
    ) -> Result<()> {
        self.mso()?
            .validate_device(current_time, doc_type, name_spaces)
    }

    /// Extract the Issuer's public key in the JWK format.
    ///
    /// Currently, only `ECDSA` keys are supported.
    fn public_jwk(&self, alg: &SigningAlgorithm) -> Result<JwkPublic> {
        let x5chain = self.x5chain()?;

        public_jwk_from_x5chain_leaf(&x5chain, alg, Some(DEFAULT_ISSUER_KID))
            .with_err(|| MdocError::InvalidPublicKey)
    }

    /// Return the [`MobileSecurityObject`] from the payload of the underlying
    /// `COSE_Sign1` structure.
    fn mso(&self) -> Result<MobileSecurityObject> {
        let Some(payload) = &self.0.payload else {
            return Err(bherror::Error::root(MdocError::IssuerAuth).ctx("MSO is missing"));
        };

        let mso: MobileSecurityObjectBytes = ciborium::from_reader(payload.as_slice())
            .foreign_err(|| MdocError::IssuerAuth)
            .ctx(|| "Invalid Mobile Security Object")?;

        Ok(mso.into())
    }

    /// Returns the [`DeviceKey`] from the underlying [`MobileSecurityObject`].
    pub fn device_key(&self) -> Result<DeviceKey> {
        Ok(self.mso()?.device_key_info.device_key)
    }

    /// Return the `alg` element from the protected header of the underlying
    /// `COSE_Sign1` structure.
    pub fn signing_algorithm(&self) -> Option<SigningAlgorithm> {
        let alg = self.0.protected.header.alg.as_ref()?;

        let RegisteredLabelWithPrivate::Assigned(alg) = alg else {
            return None;
        };

        coset_alg_to_jws_alg(alg)
    }

    /// Return the `x5chain` from the unprotected header of the underlying
    /// `COSE_Sign1` structure.
    pub fn x5chain(&self) -> Result<X5Chain> {
        let x5chain = self
            .0
            .unprotected
            .rest
            .iter()
            .find_map(|(l, v)| (l == &Label::Int(HeaderParameter::X5Chain.to_i64())).then_some(v))
            .ok_or_else(|| bherror::Error::root(MdocError::X5Chain).ctx("missing `x5chain`"))?;

        cbor_value_to_x5chain(x5chain.clone())
    }
}

/// Based on [RFC 9360][1], x5chain should be serialized based on number of certificates in chain,
/// as it states:
///
/// > This header parameter allows for a single X.509 certificate or a chain of X.509 certificates
/// > to be carried in the message.
/// >
/// >   *  If a single certificate is conveyed, it is placed in a CBOR byte string.
/// >
/// >   *  If multiple certificates are conveyed, a CBOR array of byte strings is used, with each
/// >      certificate being in its own byte string.
///
/// [1]: <https://www.rfc-editor.org/rfc/rfc9360.html#section-2-5.4.4>
fn x5chain_to_cbor_value(x5chain: X5Chain) -> Result<ciborium::Value> {
    let mut certs = x5chain
        .as_bytes()
        .with_err(|| MdocError::X5Chain)
        .ctx(|| "X.509 certificate to DER error")?
        .into_iter()
        .map(|cert| cert.into())
        .collect::<Vec<ciborium::Value>>();

    Ok(if certs.len() == 1 {
        certs.remove(0)
    } else {
        certs.into()
    })
}

/// Converts the [`ciborium::Value`] to the [`X5Chain`].
///
/// If the [`ciborium::Value`] contains [`Bytes`][ciborium::Value::Bytes], they
/// are representing a single certificate. If it contains
/// [`Array`][ciborium::Value::Array] of [`Bytes`][ciborium::Value::Bytes], it
/// represents the chain of certificates. Otherwise, [`MdocError::X5Chain`] is
/// returned.
fn cbor_value_to_x5chain(value: ciborium::Value) -> Result<X5Chain> {
    let chain = match value {
        ciborium::Value::Bytes(bytes) => vec![bytes],
        ciborium::Value::Array(arr) => arr
            .into_iter()
            .map(ciborium::Value::into_bytes)
            .collect::<std::result::Result<_, _>>()
            // `map_err` must be used because underlying error is not `StdErr`
            .map_err(|_| {
                bherror::Error::root(MdocError::X5Chain).ctx("`x5chain` must only contain bytes")
            })?,
        _ => {
            return Err(
                bherror::Error::root(MdocError::X5Chain).ctx("`x5chain` must only contain bytes")
            )
        }
    };

    X5Chain::from_raw_bytes(&chain)
        .with_err(|| MdocError::X5Chain)
        .ctx(|| "invalid `x5chain`")
}

/// [`MobileSecurityObjectBytes`] as defined in the section `9.1.2.4` of the [ISO/IEC
/// 18013-5:2021][1] standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct MobileSecurityObjectBytes(BytesCbor<MobileSecurityObject>);

impl From<MobileSecurityObject> for MobileSecurityObjectBytes {
    fn from(value: MobileSecurityObject) -> Self {
        Self(value.into())
    }
}

impl From<MobileSecurityObjectBytes> for MobileSecurityObject {
    fn from(value: MobileSecurityObjectBytes) -> Self {
        value.0.inner
    }
}

/// [`MobileSecurityObject`] as defined in the section `9.1.2.4` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileSecurityObject {
    version: String,
    digest_algorithm: DigestAlgorithm,
    value_digests: ValueDigests,
    device_key_info: DeviceKeyInfo,
    doc_type: DocType,
    validity_info: ValidityInfo,
}

impl MobileSecurityObject {
    fn new(
        doc_type: DocType,
        IssuerNameSpaces(ref name_spaces): &IssuerNameSpaces,
        device_key: DeviceKey,
        current_time: u64,
    ) -> Result<Self> {
        let digest = |item: &IssuerSignedItemBytes| -> Result<(DigestID, Bytes)> {
            Ok((
                item.0.inner.digest_id,
                item.digest(&MSO_DEFAULT_DIGEST_ALG)?.into(),
            ))
        };

        let value_digests = name_spaces
            .iter()
            .map(|(name_space, items)| {
                let digests = items
                    .iter()
                    .map(digest)
                    .collect::<Result<_>>()
                    .with_err(|| MdocError::MobileSecurityObject)?;

                Ok((name_space.clone(), DigestIDs(digests)))
            })
            .collect::<Result<_>>()?;

        let signed = current_time.try_into()?;
        let valid_from = current_time.try_into()?;
        // We set validity for one year, but this shall be parameter in near future
        let valid_until = (current_time + 365 * 24 * 60 * 60).try_into()?;

        Ok(MobileSecurityObject {
            version: MOBILE_SECURITY_OBJECT_VERSION.to_owned(),
            digest_algorithm: MSO_DEFAULT_DIGEST_ALG,
            value_digests: ValueDigests(value_digests),
            device_key_info: DeviceKeyInfo {
                device_key,
                key_authorizations: None,
                key_info: None,
            },
            doc_type,
            validity_info: ValidityInfo {
                signed,
                valid_from,
                valid_until,
                expected_update: None,
            },
        })
    }

    /// Performs all validation steps for the [`MobileSecurityObject`].
    ///
    /// It includes the validation of the underlying [`DocType`], time-validity
    /// information and the digests of the provided [`IssuerNameSpaces`].
    ///
    /// **Note**: this is intended to be used only by the `mDoc` Verifier.
    fn validate_verifier(
        &self,
        current_time: u64,
        doc_type: &DocType,
        name_spaces: Option<&IssuerNameSpaces>,
    ) -> Result<()> {
        if &self.doc_type != doc_type {
            return Err(bherror::Error::root(MdocError::InvalidDocType(
                doc_type.clone(),
                self.doc_type.clone(),
            )));
        }

        self.validity_info.validate_verifier(current_time)?;

        if let Some(name_spaces) = name_spaces {
            self.validate_name_spaces(name_spaces)?;
        };

        Ok(())
    }

    /// Performs all validation steps for the [`MobileSecurityObject`].
    ///
    /// It includes the validation of the underlying [`DocType`], time-validity
    /// information and the digests of the provided [`IssuerNameSpaces`].
    ///
    /// **Note**: this is intended to be used only by the `mDoc` Device.
    fn validate_device(
        &self,
        current_time: u64,
        doc_type: &DocType,
        name_spaces: Option<&IssuerNameSpaces>,
    ) -> Result<()> {
        if &self.doc_type != doc_type {
            return Err(bherror::Error::root(MdocError::InvalidDocType(
                doc_type.clone(),
                self.doc_type.clone(),
            )));
        }

        self.validity_info.validate_device(current_time)?;

        if let Some(name_spaces) = name_spaces {
            self.validate_name_spaces(name_spaces)?;
        };

        Ok(())
    }

    /// Validates only the digests of the provided [`IssuerNameSpaces`].
    ///
    /// The digests of data elements from the [`IssuerNameSpaces`] are
    /// calculated and their presence is checked with respect to this
    /// [`MobileSecurityObject`].
    fn validate_name_spaces(&self, name_spaces: &IssuerNameSpaces) -> Result<()> {
        for (name_space, items) in &name_spaces.0 {
            if items.is_empty() {
                continue;
            }

            let mso_digests = self.value_digests.0.get(name_space).ok_or_else(|| {
                bherror::Error::root(MdocError::MissingDigestNamespace(name_space.clone()))
            })?;

            for item in items {
                let digest_id = &item.0.inner.digest_id;

                let mso_digest = mso_digests.0.get(digest_id).ok_or_else(|| {
                    bherror::Error::root(MdocError::MissingOrInvalidDigest(
                        name_space.clone(),
                        *digest_id,
                    ))
                    .ctx("the digest is missing")
                })?;
                let target_digest = item.digest(&self.digest_algorithm)?;

                if mso_digest.0 != target_digest {
                    return Err(bherror::Error::root(MdocError::MissingOrInvalidDigest(
                        name_space.clone(),
                        *digest_id,
                    ))
                    .ctx("the digest is not valid"));
                }
            }
        }

        Ok(())
    }
}

/// Supported digest algorithms as defined by the table 21 of the section `9.1.2.5` in the [ISO/IEC
/// 18013-5:2021][1] standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum DigestAlgorithm {
    /// Designates the SHA-256 digest algorithm as specified in [ISO/IEC 10118-3][1].
    ///
    /// [1]: <https://www.iso.org/standard/67116.html>
    #[serde(rename = "SHA-256")]
    Sha256,
    /// Designates the SHA-384 digest algorithm as specified in [ISO/IEC 10118-3][1].
    ///
    /// [1]: <https://www.iso.org/standard/67116.html>
    #[serde(rename = "SHA-384")]
    Sha384,
    /// Designates the SHA-512 digest algorithm as specified in [ISO/IEC 10118-3][1].
    ///
    /// [1]: <https://www.iso.org/standard/67116.html>
    #[serde(rename = "SHA-512")]
    Sha512,
}

/// [`ValueDigests`] as defined in the section `9.1.2.4` of the [ISO/IEC 18013-5:2021][1] standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ValueDigests(HashMap<NameSpace, DigestIDs>);

/// [`DigestIDs`] as defined in the section `9.1.2.4` of the [ISO/IEC 18013-5:2021][1] standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DigestIDs(HashMap<DigestID, Bytes>);

/// [`DeviceKeyInfo`] as defined in the section `9.1.2.4` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyInfo {
    device_key: DeviceKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_authorizations: Option<KeyAuthorizations>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_info: Option<KeyInfo>,
}

/// User's device public key.
///
/// For more details on COSE_Key specifications look
/// [here](https://datatracker.ietf.org/doc/html/rfc8152)
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DeviceKey(
    #[serde(
        serialize_with = "serialize_coset",
        deserialize_with = "deserialize_coset"
    )]
    pub(crate) CoseKey,
);

impl DeviceKey {
    /// Method for creating `DeviceKey` out of `JWK`.
    pub fn from_jwk(jwk: &serde_json::Map<String, serde_json::Value>) -> Result<Self> {
        Ok(Self(
            crate::utils::coset::cose_key_from_jwk(jwk).ctx(|| "Failed to create DeviceKey")?,
        ))
    }

    /// Returns a JWK representation of the underlying `COSE_Key`.
    pub fn as_jwk(&self) -> Result<serde_json::Map<String, serde_json::Value>> {
        cose_key_to_jwk(&self.0)
    }
}

/// [`KeyAuthorizations`] as defined in the section `9.1.2.4` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyAuthorizations {
    #[serde(skip_serializing_if = "Option::is_none")]
    name_spaces: Option<AuthorizedNameSpaces>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_elements: Option<AuthorizedDataElements>,
}

/// [`AuthorizedNameSpaces`] as defined in the section `9.1.2.4` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuthorizedNameSpaces(Vec<NameSpace>);

/// [`AuthorizedDataElements`] as defined in the section `9.1.2.4` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuthorizedDataElements(HashMap<NameSpace, DataElementsArray>);

/// [`DataElementsArray`] as defined in the section `9.1.2.4` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DataElementsArray(Vec<DataElementIdentifier>);

/// [`KeyInfo`] as defined in the section `9.1.2.4` of the [ISO/IEC 18013-5:2021][1] standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KeyInfo(HashMap<i64, ciborium::Value>);

/// [`ValidityInfo`] as defined in the section `9.1.2.4` of the [ISO/IEC 18013-5:2021][1] standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityInfo {
    signed: DateTime,
    valid_from: DateTime,
    valid_until: DateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_update: Option<DateTime>,
}

impl ValidityInfo {
    /// Validates the expiration and the not-valid-before claim.
    ///
    /// **Note**: this is intended to be used only by the `mDoc` Verifier.
    fn validate_verifier(&self, current_time: u64) -> Result<()> {
        let valid_from = self.valid_from.0.timestamp();
        if (current_time as i128) < (valid_from as i128) {
            return Err(bherror::Error::root(MdocError::DocumentNotYetValid(
                valid_from,
            )));
        }

        let valid_until = self.valid_until.0.timestamp();
        if (current_time as i128) > (valid_until as i128) {
            return Err(bherror::Error::root(MdocError::DocumentExpired(
                valid_until,
            )));
        }

        Ok(())
    }

    /// Validates the expiration claim.
    ///
    /// **Note**: this is intended to be used only by the `mDoc` Device.
    fn validate_device(&self, current_time: u64) -> Result<()> {
        let valid_until = self.valid_until.0.timestamp();
        if (current_time as i128) > (valid_until as i128) {
            return Err(bherror::Error::root(MdocError::DocumentExpired(
                valid_until,
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use bh_jws_utils::Es256Verifier;

    use crate::{
        models::{
            data_retrieval::device_retrieval::{
                issuer_auth::IssuerAuth,
                response::{IssuerNameSpaces, IssuerSignedItem},
            },
            mdl::MDL_NAMESPACE,
        },
        MdocError,
    };

    fn dummy_issuer_auth(current_time: u64) -> IssuerAuth {
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
        let (_, device_key) = crate::utils::test::dummy_device_key();

        IssuerAuth::new(
            "org.iso.18013.5.1.mDL".into(),
            &name_spaces,
            device_key,
            &issuer_signer,
            current_time,
        )
        .unwrap()
    }

    #[test]
    fn load_third_party_issuer_auth() {
        const THIRD_PARTY_ISSUER_AUTH: &str = "\
8443a10126a1182159014b308201473081eea00302010202083\
9edc87a9a78f92a300a06082a8648ce3d040302301731153013\
06035504030c0c4d444f4320524f4f54204341301e170d32343\
03530323133313333305a170d3235303530323133313333305a\
301b3119301706035504030c104d444f4320546573742049737\
37565723059301306072a8648ce3d020106082a8648ce3d0301\
07034200041b4448341885fa84140f77790c69de810b977a723\
6f490da306a0cbe2a0a441379ddde146b36a44b6ba7bbc067b0\
4b71bad4b692a4616013d893d440ae253781a320301e300c060\
3551d130101ff04023000300e0603551d0f0101ff0404030207\
80300a06082a8648ce3d04030203480030450221008e7004100\
0ddec2a230b2586ecc59f8acd156f5d933d9363bc5e2263bb0a\
b69802201885a8b537327a69b022620f07c5c45d6293b86eed9\
27a3f04e82cc51cadf8635901c3d8185901bea6677665727369\
6f6e63312e306f646967657374416c676f726974686d6753484\
12d3235366c76616c756544696765737473a1716f72672e6973\
6f2e31383031332e352e31a300582025a0d893e78de394f50c1\
e4e4b741010a2fc683642ecb144f289ca9d74a168440158203f\
74f1795d847e6b72c548ca6f1e57c9a6def0f5c80fa643a8aae\
079939662bd0258202f028fcb6e1690f8c0e7d8569662564c78\
b88ea51f554a414cd04b69834f4e506d6465766963654b65794\
96e666fa1696465766963654b6579a401022001215820257958\
58a9cf54bd8575597e963dffc521696718c0b95ed3bc14acffe\
f6320e82258202dd4fae416f2bab6726593b97914c7b7e1342c\
d446bb8ef025a1cac6567cd40f67646f6354797065756f72672\
e69736f2e31383031332e352e312e6d444c6c76616c69646974\
79496e666fa3667369676e6564c0781e323032342d31302d323\
95431313a30323a30392e3933363334323036395a6976616c69\
6446726f6dc0781e323032342d31302d32395431313a30323a3\
0392e3933363334333733305a6a76616c6964556e74696cc078\
1e323032352d31302d32395431313a30323a30392e393336333\
4333934315a5840d274be6b6491b022cee4be5fcb6561414191\
53a10ccec1cefce93ea4df318d9d8b73c277a0eba2854a4b782\
e300ed9abd07e775942b1e93b33ad21c9b1a50509";

        let issuer_auth_bytes = hex::decode(THIRD_PARTY_ISSUER_AUTH).unwrap();
        let issuer_auth =
            ciborium::from_reader::<IssuerAuth, _>(issuer_auth_bytes.as_slice()).unwrap();

        let mut issuer_auth_deser_bytes = vec![];
        ciborium::into_writer(&issuer_auth, &mut issuer_auth_deser_bytes).unwrap();
        assert_eq!(issuer_auth_bytes, issuer_auth_deser_bytes);
    }

    #[test]
    fn create_issuer_auth() {
        let issuer_auth = dummy_issuer_auth(100);
        let digests_map = issuer_auth.mso().unwrap().value_digests;
        let digests = digests_map
            .0
            .get(&MDL_NAMESPACE.to_string().into())
            .unwrap();

        assert_eq!(
            hex::encode(&digests.0.get(&0u64.into()).unwrap().0),
            "a5d3d4ceb0814fa7b292836e0a6eb4e0a53200bd5b1485510e714a3a1653198e"
        );

        assert_eq!(
            hex::encode(&digests.0.get(&1u64.into()).unwrap().0),
            "cb246762793d791fa32bc84536c63ab714363f93d59a1aaf3e2b3c47322be01e"
        );

        assert_eq!(
            hex::encode(&digests.0.get(&2u64.into()).unwrap().0),
            "407cba6e4b70b8121455d2c12cb9f906125e7e6bfe839cf0f7d9f70d1297df7d"
        );
    }

    // Based on example from [github][1]. This example is part of [RFC][2] and should be
    // representable for our verification check. This proves that mdoc credential, based on
    // `issuerAuth`'s signature, is verifiable using `bh-jws-utils` crate.
    //
    // The example was modified in a way to use x5chain for unprotected field. The x5chain was
    // generated manually from JWK found in [1]. This way we are compatible with our interface, but
    // we still use same payload and keys.
    //
    // [1] <https://github.com/cose-wg/Examples/blob/master/ecdsa-examples/ecdsa-sig-01.json>
    // [2] <https://datatracker.ietf.org/doc/html/rfc8152#page-102>
    #[test]
    fn verify_issuer_auth() {
        const CBOR_EXAMPLE: &str =
"8445a201260300a118215901ea308201e63082018ca00302010202142925438a3b4ab7567d1843aed31de1259ea37ff33\
00a06082a8648ce3d040302306a310b30090603550406130255533113301106035504080c0a43616c69666f726e6961311\
6301406035504070c0d53616e204672616e636973636f31183016060355040a0c0f4d79204f7267616e697a6174696f6e3\
114301206035504030c0b6578616d706c652e636f6d301e170d3234313231393039343834365a170d32353132313930393\
43834365a306a310b30090603550406130255533113301106035504080c0a43616c69666f726e696131163014060355040\
70c0d53616e204672616e636973636f31183016060355040a0c0f4d79204f7267616e697a6174696f6e311430120603550\
4030c0b6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004bac5b11cad8f99f\
9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6\
fb6ed28bbfc117ea310300e300c0603551d130101ff04023000300a06082a8648ce3d040302034800304502200d1150f20\
02bcb15d30326c0b4282635844e64173a16e85429da6439cef303bc0221009b95183e4ab8b47513cbab8635e26d55a57e5\
e0ce85f2099f9502f4a2d7048f454546869732069732074686520636f6e74656e742e58406520bbaf2081d7e0ed0f95f76\
eb0733d667005f7467cec4b87b9381a6ba1ede8e00df29f32a37230f39a842a54821fdd223092819d7728efb9d3a0080b7\
5380b";

        let issuer_auth_bytes = hex::decode(CBOR_EXAMPLE).unwrap();
        let issuer_auth =
            ciborium::from_reader::<IssuerAuth, _>(issuer_auth_bytes.as_slice()).unwrap();

        assert_matches!(
            issuer_auth.verify_signature(|_| Some(&Es256Verifier)),
            Ok(_)
        );
    }

    #[test]
    fn validate_issuer_auth() {
        let now = 100;

        let issuer_auth = dummy_issuer_auth(now);

        // IssuerAuth is valid when no namespaces aren't provided
        assert_matches!(
            issuer_auth.validate_verifier(now, &"org.iso.18013.5.1.mDL".into(), None),
            Ok(_)
        );

        // IssuerAuth is valid when namespaces are empty
        let namespaces = IssuerNameSpaces(std::collections::HashMap::from([(
            MDL_NAMESPACE.to_owned().into(),
            vec![],
        )]));

        assert_matches!(
            issuer_auth.validate_verifier(now, &"org.iso.18013.5.1.mDL".into(), Some(&namespaces)),
            Ok(_)
        );

        // IssuerAuth is valid when some valid namespace exist
        let namespaces = IssuerNameSpaces(std::collections::HashMap::from([(
            MDL_NAMESPACE.to_owned().into(),
            vec![IssuerSignedItem {
                digest_id: 0u64.into(),
                random: "f4b65b3379407aa9a0390309b792344c".parse().unwrap(),
                element_identifier: "family_name".to_owned().into(),
                element_value: "Doe".into(),
            }
            .into()],
        )]));

        assert_matches!(
            issuer_auth.validate_verifier(now, &"org.iso.18013.5.1.mDL".into(), Some(&namespaces)),
            Ok(_)
        );

        // IssuerAuth isn't valid when namespace identifier doesn't match any data
        let namespaces = IssuerNameSpaces(std::collections::HashMap::from([(
            MDL_NAMESPACE.to_owned().into(),
            vec![IssuerSignedItem {
                digest_id: 0u64.into(),
                random: "f4b65b3379407aa9a0390309b792344c".parse().unwrap(),
                element_identifier: "unknown_field".to_owned().into(),
                element_value: "Doe".into(),
            }
            .into()],
        )]));

        assert_matches!(
            issuer_auth
                .validate_verifier(now, &"org.iso.18013.5.1.mDL".into(), Some(&namespaces))
                .unwrap_err()
                .error,
            MdocError::MissingOrInvalidDigest(_, _)
        );

        // IssuerAuth isn't valid if it's not valid yet
        let past = now - 1;

        assert_matches!(
            issuer_auth
                .validate_verifier(past, &"org.iso.18013.5.1.mDL".into(), None)
                .unwrap_err()
                .error,
            MdocError::DocumentNotYetValid(_)
        );

        // IssuerAuth isn't valid if it's expired
        let future = now + 400 * 24 * 60 * 60;
        assert_matches!(
            issuer_auth
                .validate_verifier(future, &"org.iso.18013.5.1.mDL".into(), None)
                .unwrap_err()
                .error,
            MdocError::DocumentExpired(_)
        );
    }
}

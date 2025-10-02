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

//! This module defines the [`Issuer`] type, which is responsible for issuing `mDL` & other
//! `mso_mdoc` Credentials in the context of [OpenID for Verifiable Credential Issuance][1].
//!
//! [1]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>

use std::collections::HashMap;

use rand::Rng;

use crate::models::data_retrieval::device_retrieval::response::IssuerUnsigned;
use crate::models::issue::UnsignedDocument;
use crate::{
    models::{
        data_retrieval::{
            common::DocType,
            device_retrieval::{issuer_auth::ValidityInfo},
            Claims,
        },
        issue::IssuedDocument,
        mdl::{MDL, MDL_DOCUMENT_TYPE, MDL_NAMESPACE},
    },
    DeviceKey, Result,
};
use bh_jws_utils::SigningAlgorithm;
use bhx5chain::X5Chain;

/// The [`Issuer`] is responsible for issuing `mDL` & other `mso_mdoc` Credentials in the
/// context of [OpenID for Verifiable Credential Issuance][1].
///
/// The type provides two methods.
///
///   * [`Issuer::issue`] for issuing any type of `mso_mdoc` Credentials.
///   * [`Issuer::issue_mdl`] for issuing `mDL` (mobile driving license) documents as defined
///     in the [ISO/IEC 18013-5:2021][2] standard.
///
/// [1]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>
/// [2]: <https://www.iso.org/standard/69084.html>
pub struct Issuer;

impl Issuer {
    /// Docs
    #[allow(clippy::too_many_arguments)]
    pub fn issue_unsigned<R: Rng + ?Sized>(
        &self,
        doc_type: DocType,
        name_spaces: Claims,
        device_key: DeviceKey,
        alg: SigningAlgorithm,
        x5chain: X5Chain,
        rng: &mut R,
        validity_info: ValidityInfo,
    ) -> Result<UnsignedDocument> {
        let issuer_unsigned = IssuerUnsigned::new(
            doc_type.clone(),
            name_spaces,
            device_key,
            alg,
            x5chain,
            rng,
            validity_info,
        )?;

        Ok(UnsignedDocument::new(doc_type, issuer_unsigned))
    }

    /// Issue a new `mDL` Credential.
    pub fn issue_mdl_unsigned<R: Rng + ?Sized>(
        &self,
        mdl: MDL,
        device_key: DeviceKey,
        alg: SigningAlgorithm,
        x5chain: X5Chain,
        rng: &mut R,
        validity_info: ValidityInfo,
    ) -> Result<UnsignedDocument> {
        let mut name_spaces = HashMap::new();
        name_spaces.insert(MDL_NAMESPACE.into(), mdl.into());

        self.issue_unsigned(
            MDL_DOCUMENT_TYPE.into(),
            Claims(name_spaces),
            device_key,
            alg,
            x5chain,
            rng,
            validity_info,
        )
    }

    /// Docs
    pub fn tbs_data(&self, unsigned_document: &UnsignedDocument) -> Vec<u8> {
        unsigned_document.tbs_data()
    }

    // TODO: maybe just use unsigned_document.issue
    /// Docs
    pub fn issue(
        &self,
        unsigned_document: UnsignedDocument,
        signature: Vec<u8>,
    ) -> Result<IssuedDocument> {
        unsigned_document.issue(signature)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use ciborium::into_writer;
    use rand::thread_rng;

    use super::*;
    use crate::{
        models::{
            data_retrieval::common::{DataElementIdentifier, DataElementValue},
            mdl::MDLMandatory,
            FullDate,
        },
        utils::test::validity_info,
    };
    use bh_jws_utils::HasX5Chain;
    use bh_jws_utils::Signer;

    fn issue(unsigned: UnsignedDocument) -> Result<IssuedDocument> {
        let issuer_signer = crate::utils::test::SimpleSigner::issuer();

        let tbs_data = Issuer.tbs_data(&unsigned);
        let signature = issuer_signer.sign(&tbs_data).unwrap();

        Issuer.issue(unsigned, signature)
    }

    #[test]
    fn test_issue() {
        let mut rng = thread_rng();
        let issuer_signer = crate::utils::test::SimpleSigner::issuer();
        let (_, device_key) = crate::utils::test::dummy_device_key();

        let claims = Claims(HashMap::from([(
            MDL_NAMESPACE.into(),
            HashMap::<DataElementIdentifier, DataElementValue>::from([(
                "name".into(),
                "John".into(),
            )]),
        )]));

        let unsigned = Issuer
            .issue_unsigned(
                MDL_DOCUMENT_TYPE.into(),
                claims,
                device_key,
                issuer_signer.algorithm(),
                issuer_signer.x5chain(),
                &mut rng,
                validity_info(100),
            )
            .unwrap();

        let issued = issue(unsigned).unwrap();

        let mut encoded = Vec::new();

        into_writer(&issued, &mut encoded).unwrap();

        let encoded_hex = hex::encode(&encoded);

        println!("{}", encoded_hex);
    }

    #[test]
    fn test_issue_mdl() {
        let mut rng = thread_rng();
        let issuer_signer = crate::utils::test::SimpleSigner::issuer();
        let (_, device_key) = crate::utils::test::dummy_device_key();

        let mdl_mandatory = MDLMandatory {
            family_name: "Doe".to_owned(),
            given_name: "John".to_owned(),
            birth_date: "1980-01-02".parse().unwrap(),
            issue_date: FullDate::from_str("2024-01-01").unwrap().into(),
            expiry_date: FullDate::from_str("2029-01-01").unwrap().into(),
            issuing_authority: "MUP".to_owned(),
            issuing_country: "RH".to_owned(),
            document_number: "1234".to_owned(),
            portrait: vec![1u8, 2, 3].into(),
            driving_privileges: 7,
            un_distinguishing_sign: "sign".to_owned(),
        };

        let mdl = MDL::new(mdl_mandatory);

        let unsigned = Issuer
            .issue_mdl_unsigned(
                mdl,
                device_key,
                issuer_signer.algorithm(),
                issuer_signer.x5chain(),
                &mut rng,
                validity_info(100),
            )
            .unwrap();

        let issued = issue(unsigned).unwrap();

        let mut encoded = Vec::new();

        into_writer(&issued, &mut encoded).unwrap();

        let encoded_hex = hex::encode(&encoded);

        println!("{}", encoded_hex);
    }
}

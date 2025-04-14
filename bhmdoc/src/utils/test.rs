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

use std::collections::HashMap;

use bh_jws_utils::{Es256Verifier, HasX5Chain, Signer, SigningAlgorithm};
use bhx5chain::X5Chain;
use coset::CoseKeyBuilder;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::Private,
    x509::X509,
};
use rand::thread_rng;

use crate::{
    models::{
        data_retrieval::{device_retrieval::response::Document, Claims},
        issue::IssuedDocument,
        mdl::{MDL_DOCUMENT_TYPE, MDL_NAMESPACE},
        DeviceRequest, DeviceResponse, DocRequest,
    },
    Device, DeviceKey, Issuer,
};

pub(crate) struct SimpleSigner {
    key: EcKey<Private>,
    cert: Option<X509>,
}

// Good enough implementation of signer that should provide valid issuer's and device's signatures.
impl SimpleSigner {
    pub fn issuer() -> Self {
        let key = "-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEILgeXnSEs6kMtkw60nBVEXIc3m/nF5LjPEIwUC4cEhpZoAoGCCqGSM49\
AwEHoUQDQgAEWpR+rzdovqY4i6fxZE8/lPrWQTPBGt0kfpbHqsTII0PUJQ85NIJ5\
mMBCA0MB6BcdQNThclRs93GJ7oVDiBnOxw==\n\
-----END EC PRIVATE KEY-----";

        let cert = "-----BEGIN CERTIFICATE-----\n\
MIICtTCCAlugAwIBAgIUIAe5tLOxpf5iboVrcw/QIyBU6jYwCgYIKoZIzj0EAwIw\
ZTELMAkGA1UEBhMCSFIxFDASBgNVBAgMC0dyYWQgWmFncmViMQ8wDQYDVQQHDAZa\
YWdyZWIxDTALBgNVBAoMBFRCVEwxETAPBgNVBAsMCFRlYW0gQmVlMQ0wCwYDVQQD\
DARyb290MB4XDTI0MTIzMTA4MjMzOVoXDTI1MTIzMTA4MjMzOVowZTELMAkGA1UE\
BhMCSFIxFDASBgNVBAgMC0dyYWQgWmFncmViMQ8wDQYDVQQHDAZaYWdyZWIxDTAL\
BgNVBAoMBFRCVEwxETAPBgNVBAsMCFRlYW0gQmVlMQ0wCwYDVQQDDARyb290MFkw\
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWpR+rzdovqY4i6fxZE8/lPrWQTPBGt0k\
fpbHqsTII0PUJQ85NIJ5mMBCA0MB6BcdQNThclRs93GJ7oVDiBnOx6OB6DCB5TAP\
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTRdwhNw27J4czlNtsNN43+tp2eNTCB\
ogYDVR0jBIGaMIGXgBTRdwhNw27J4czlNtsNN43+tp2eNaFppGcwZTELMAkGA1UE\
BhMCSFIxFDASBgNVBAgMC0dyYWQgWmFncmViMQ8wDQYDVQQHDAZaYWdyZWIxDTAL\
BgNVBAoMBFRCVEwxETAPBgNVBAsMCFRlYW0gQmVlMQ0wCwYDVQQDDARyb290ghQg\
B7m0s7Gl/mJuhWtzD9AjIFTqNjAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID\
SAAwRQIhAK87AC9NmIAhLdXjs8d3q46oJZyNDlhb6siMILKj0XfoAiApoMI8iZBj\
o/pWdBX48fIKg7CDcsHq3cRO2XZlkwE8rQ==\n\
-----END CERTIFICATE-----";

        let cert = openssl::x509::X509::from_pem(cert.as_bytes()).unwrap();

        Self {
            key: EcKey::private_key_from_pem(key.as_bytes()).unwrap(),
            cert: Some(cert),
        }
    }

    pub fn device() -> Self {
        let key = "-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEILjSIcrmsTJCekmHPvgO+DAFUwQKejDs8ajG0x2ze/WToAoGCCqGSM49\
AwEHoUQDQgAEY+7+D1tppcAeeumcKCydGrJizZJTHIK1bpZWVO6q0ywjuuJozvRS\
CVBBTs23XV01ROn8DbkFeLlejoWr/G584w==\n\
-----END EC PRIVATE KEY-----
        )";

        Self {
            key: EcKey::private_key_from_pem(key.as_bytes()).unwrap(),
            cert: None,
        }
    }
}

impl Signer for SimpleSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Es256
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let digest = crate::utils::digest::sha256(message);
        let signature = EcdsaSig::sign(&digest, self.key.as_ref()).unwrap();

        let mut ser_sig = signature.r().to_vec_padded(32).unwrap();
        ser_sig.extend(signature.s().to_vec_padded(32).unwrap());

        Ok(ser_sig)
    }
}

impl HasX5Chain for SimpleSigner {
    fn x5chain(&self) -> X5Chain {
        X5Chain::new(vec![self.cert.clone().unwrap()]).unwrap()
    }
}

pub(crate) fn dummy_device_key() -> (SimpleSigner, DeviceKey) {
    let signer = SimpleSigner::device();

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();
    signer
        .key
        .public_key()
        .affine_coordinates(group.as_ref(), &mut x, &mut y, &mut ctx)
        .unwrap();

    let pub_key = DeviceKey(
        CoseKeyBuilder::new_ec2_pub_key(coset::iana::EllipticCurve::P_256, x.to_vec(), y.to_vec())
            .build(),
    );

    (SimpleSigner::device(), pub_key)
}

pub(crate) fn issue_dummy_mdoc(current_time: u64) -> IssuedDocument {
    let mut rng = thread_rng();
    let issuer_signer = SimpleSigner::issuer();
    let (_, device_key) = dummy_device_key();

    let claims = Claims(HashMap::from([(
        MDL_NAMESPACE.into(),
        HashMap::from([
            ("firstName".into(), "John".into()),
            ("lastName".into(), "Doe".into()),
        ]),
    )]));

    Issuer
        .issue(
            MDL_DOCUMENT_TYPE.into(),
            claims,
            device_key,
            &issuer_signer,
            &mut rng,
            current_time,
        )
        .unwrap()
}

pub(crate) fn issue_dummy_mdoc_to_device(current_time: u64) -> Device {
    let issued = issue_dummy_mdoc(current_time);

    Device::verify_issued(
        &issued.serialize_issuer_signed().unwrap(),
        MDL_DOCUMENT_TYPE.into(),
        current_time,
        |_| Some(&Es256Verifier),
    )
    .unwrap()
}

pub(crate) fn present_dummy_mdoc(current_time: u64) -> DeviceResponse {
    let device = issue_dummy_mdoc_to_device(100);

    let doc_request = DocRequest::builder(MDL_DOCUMENT_TYPE.into())
        .add_name_space(
            MDL_NAMESPACE.into(),
            HashMap::from([("lastName".into(), false.into())]),
        )
        .build();
    let request = DeviceRequest::new(vec![doc_request]);

    device
        .present(
            current_time,
            &request,
            "client_id",
            "response_uri",
            "nonce",
            "mdoc_generated_nonce",
            &SimpleSigner::device(),
        )
        .unwrap()
}

/// Remove original data from issuer signed an device signed parts of Documents.
///
/// Helper method used only for tests when we don't depend on original data but need to remove it
/// so we can properly compare generated and expected documents.
pub(crate) fn remove_original_data_from_documents(documents: &mut [Document]) {
    documents.iter_mut().for_each(|document| {
        document
            .issuer_signed
            .name_spaces
            .as_mut()
            .unwrap()
            .0
            .values_mut()
            .for_each(|items| {
                items
                    .iter_mut()
                    .for_each(|item| item.0.original_data = None)
            })
    });

    documents
        .iter_mut()
        .for_each(|document| document.device_signed.name_spaces.0.original_data = None);
}

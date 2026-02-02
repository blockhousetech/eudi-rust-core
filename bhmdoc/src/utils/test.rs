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

use std::collections::HashMap;

use bh_jws_utils::Es256Verifier;
use bh_jws_utils::{Es256Signer, Es256SignerWithChain};
use bh_status_list::StatusClaim;
use bhx5chain::X509Trust;
use bhx5chain::X5Chain;
use rand::thread_rng;

use crate::{
    models::{
        data_retrieval::{
            device_retrieval::{issuer_auth::ValidityInfo, response::Document},
            Claims,
        },
        issue::IssuedDocument,
        mdl::{MDL_DOCUMENT_TYPE, MDL_NAMESPACE},
        DeviceRequest, DeviceResponse, DocRequest,
    },
    Device, DeviceKey, Issuer,
};

const ISSUER_KEY: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILgeXnSEs6kMtkw60nBVEXIc3m/nF5LjPEIwUC4cEhpZoAoGCCqGSM49
AwEHoUQDQgAEWpR+rzdovqY4i6fxZE8/lPrWQTPBGt0kfpbHqsTII0PUJQ85NIJ5
mMBCA0MB6BcdQNThclRs93GJ7oVDiBnOxw==
-----END EC PRIVATE KEY-----";

const ISSUER_SELF_SIGNED_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBuDCCAV6gAwIBAgIULXEdVlwLjqTzYdqJ/ttQvP1ZY7wwCgYIKoZIzj0EAwIw
ETEPMA0GA1UEAwwGaXNzdWVyMCAXDTI2MDExMzA5NDMzM1oYDzIxMjUxMjIwMDk0
MzMzWjARMQ8wDQYDVQQDDAZpc3N1ZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARalH6vN2i+pjiLp/FkTz+U+tZBM8Ea3SR+lseqxMgjQ9QlDzk0gnmYwEIDQwHo
Fx1A1OFyVGz3cYnuhUOIGc7Ho4GRMIGOMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
BBYEFNF3CE3DbsnhzOU22w03jf62nZ41MEwGA1UdIwRFMEOAFNF3CE3DbsnhzOU2
2w03jf62nZ41oRWkEzARMQ8wDQYDVQQDDAZpc3N1ZXKCFC1xHVZcC46k82Haif7b
ULz9WWO8MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNIADBFAiEAsiqBfmRt
qlTziovu+5yvNScpH4iyXbV/NzDSrbSZKa0CIE3vMvlhWbNIcWYKqy3yhEtzoLEu
7bAw0TM3HO5G5/S7
-----END CERTIFICATE-----";

/// Tests assume each call returns the same certificate.
pub fn issuer_signer() -> Es256SignerWithChain {
    let signer = Es256Signer::from_private_key_pem("".into(), ISSUER_KEY).unwrap();

    // NB: abuses the (documented) fact that this does not validate certificates
    // to import a root certificate as a leaf, even though the struct is not
    // meant to contain self-signed certs
    let x5chain = X5Chain::from_pem(&[ISSUER_SELF_SIGNED_CERT]).unwrap();

    Es256SignerWithChain::new(signer, x5chain).unwrap()
}

/// Tests assume each call returns the same certificate.
pub fn issuer_x509_trust() -> X509Trust {
    let cert = openssl::x509::X509::from_pem(ISSUER_SELF_SIGNED_CERT.as_bytes()).unwrap();
    X509Trust::new(vec![cert])
}

/// Tests assume each call returns the same key.
pub fn device_signer() -> Es256Signer {
    const DEVICE_KEY: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILjSIcrmsTJCekmHPvgO+DAFUwQKejDs8ajG0x2ze/WToAoGCCqGSM49
AwEHoUQDQgAEY+7+D1tppcAeeumcKCydGrJizZJTHIK1bpZWVO6q0ywjuuJozvRS
CVBBTs23XV01ROn8DbkFeLlejoWr/G584w==
-----END EC PRIVATE KEY-----";

    Es256Signer::from_private_key_pem("".into(), DEVICE_KEY).unwrap()
}

pub(crate) fn dummy_device_key() -> (Es256Signer, DeviceKey) {
    let signer = device_signer();
    let device_key = DeviceKey::from_jwk(&signer.public_jwk().unwrap()).unwrap();

    (signer, device_key)
}

pub(crate) fn issue_dummy_mdoc(current_time: u64, status: Option<StatusClaim>) -> IssuedDocument {
    let mut rng = thread_rng();
    let issuer_signer = issuer_signer();
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
            validity_info(current_time),
            status,
        )
        .unwrap()
}

pub(crate) fn issue_dummy_mdoc_to_device(current_time: u64, status: Option<StatusClaim>) -> Device {
    let issued = issue_dummy_mdoc(current_time, status);

    Device::verify_issued(
        &issued.serialize_issuer_signed().unwrap(),
        MDL_DOCUMENT_TYPE.into(),
        current_time,
        |_| Some(&Es256Verifier),
    )
    .unwrap()
}

pub(crate) fn present_dummy_mdoc(current_time: u64, status: Option<StatusClaim>) -> DeviceResponse {
    let device = issue_dummy_mdoc_to_device(100, status);

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
            &device_signer(),
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

pub(crate) fn validity_info(current_time: u64) -> ValidityInfo {
    ValidityInfo::new(
        current_time.try_into().unwrap(),
        current_time.try_into().unwrap(),
        (current_time + 365 * 24 * 60 * 60).try_into().unwrap(), // in 1 year
        None,
    )
    .unwrap()
}

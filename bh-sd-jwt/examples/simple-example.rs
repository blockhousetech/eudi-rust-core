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

use bh_jws_utils::{Es256Signer, Es256Verifier, SignerWithChain, SigningAlgorithm};
use bh_sd_jwt::{
    holder::Holder,
    issuer::Issuer,
    json_object,
    lookup::X5ChainIssuerPublicKeyLookup,
    verifier::Verifier,
    DisplayWrapper, HashingAlgorithm, IssuerJwt, JsonNodePath,
    JsonNodePathSegment::{Index as I, Key as K},
    Sha256,
};
use iref::UriBuf;

/// Current time in seconds from the UNIX epoch.
const CURRENT_TIME: u64 = 100;

/// The claims that are set to be selectively discloseable by the issuer.
const DISCLOSEABLE_CLAIMS: &[&JsonNodePath] = &[
    &[K("given_name")],
    &[K("address")],
    &[K("address"), K("street_address")],
    &[K("address"), K("locality")],
    &[K("address"), K("postal_code")],
    &[K("address"), K("country")],
    &[K("nationalities")],
    &[K("nationalities"), I(0)],
    &[K("nationalities"), I(1)],
    &[K("nationalities"), I(2)],
];

/// The claims requested by the verifier.
const REQUESTED_CLAIMS: &[&JsonNodePath] = &[
    &[K("address"), K("postal_code")],
    &[K("nationalities"), I(1)],
];

#[tokio::main]
async fn main() {
    // the actual issued claims
    let claims = json_object!({
        "given_name": "John",
        "address": {
            "street_address": "Street 17",
            "locality": "New York",
            "postal_code": "07008",
            "country": "US"
        },
        "nationalities": [
            "US", "DE", "RH"
        ],
    });

    // the issuer's identifier
    let iss = UriBuf::new("https://example.com/issuer".into()).unwrap();

    // used to sign the issued credential
    let issuer_signer = Es256Signer::generate("issuer_kid".to_owned()).unwrap();
    let cert_chain = bhx5chain::Builder::dummy()
        .generate_x5chain(&issuer_signer.public_key_pem().unwrap(), Some(&iss))
        .unwrap();
    let issuer_signer = SignerWithChain::new(issuer_signer, cert_chain).unwrap();

    // used by holder to create a cryptographic key binding
    let holder_signer = Es256Signer::generate("holder_kid".to_owned()).unwrap();

    let jwt_payload = IssuerJwt::new(
        "personal_identity_card".to_owned(), // the type of the credential
        iss,
        holder_signer.public_jwk().unwrap(),
        claims,
    )
    .unwrap();

    // the SD-JWT Issuer
    let issuer = Issuer::new(Sha256);

    let mut rng = rand::thread_rng();

    // issue the given credential
    let issued_sd_jwt = issuer
        .issue(jwt_payload, DISCLOSEABLE_CLAIMS, &issuer_signer, &mut rng)
        .unwrap()
        .into_string_compact();

    // the SD-JWT Holder
    // accept the issued credential on the holder (wallet) side
    let holder = Holder::verify_issued(
        &issued_sd_jwt,
        &X5ChainIssuerPublicKeyLookup::trust_all(),
        |alg| (alg == HashingAlgorithm::Sha256).then_some(Box::new(Sha256)),
        |alg| (alg == SigningAlgorithm::Es256).then_some(&Es256Verifier),
        CURRENT_TIME + 10,
    )
    .await
    .unwrap();

    println!(
        "Issued Credential:\n{}",
        serde_json::to_string_pretty(holder.claims()).unwrap(),
    );

    // the SD-JWT Verifier
    let verifier = Verifier::new("target_audience".to_owned(), &mut rng).unwrap();

    println!("\nRequested Claims: [");
    for claim in REQUESTED_CLAIMS {
        println!("  {}", DisplayWrapper(*claim))
    }
    println!("]");

    // create a verifiable presentation of the credential
    // only the [`REQUESTED_CLAIMS`] are disclosed
    let sd_jwt_kb = holder
        .present(
            REQUESTED_CLAIMS,
            verifier.key_binding_challenge().to_owned(),
            CURRENT_TIME + 20,
            &holder_signer,
        )
        .unwrap();

    // verify the presented credential
    let received_claims = verifier
        .verify(
            sd_jwt_kb,
            &X5ChainIssuerPublicKeyLookup::trust_all(),
            CURRENT_TIME + 30,
            |alg| (alg == HashingAlgorithm::Sha256).then_some(Box::new(Sha256)),
            |alg| (alg == SigningAlgorithm::Es256).then_some(&Es256Verifier),
        )
        .await
        .unwrap()
        .0;

    println!(
        "\nVerified Claims:\n{}",
        serde_json::to_string_pretty(&received_claims).unwrap()
    );
}

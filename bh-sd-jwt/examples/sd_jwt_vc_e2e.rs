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

use std::str::FromStr;

use bh_jws_utils::{Es256Signer, Es256SignerWithChain, Es256Verifier, JwkPublic, SigningAlgorithm};
use bh_sd_jwt::{
    holder::Holder, issuer::Issuer, json_object, lookup::X5ChainIssuerPublicKeyLookup,
    verifier::Verifier, DisplayWrapper, HashingAlgorithm, IssuerJwt, IssuerPublicKeyLookup,
    JsonNodePath, KeyBindingChallenge, SdJwtKB, SecondsSinceEpoch, Sha256, SignatureError,
};
use bherror::Error;
use iref::UriBuf;

#[tokio::main]
async fn main() {
    let (issuer_signer, issuer_public_key) = issuer_init_signing_key();
    let (holder_key_binding_signer, holder_key_binding_public_key) = holder_init_key_binding();

    let issuer_public_key_oracle = IssuerPublicKeyOracle(issuer_public_key);
    let issuer_public_key_x5c = X5ChainIssuerPublicKeyLookup::trust_all();

    let sd_jwt_vc_pid = issuer(&issuer_signer, holder_key_binding_public_key);

    println!("=====================================================================");

    let oracle_holder = holder_accept(&sd_jwt_vc_pid, &issuer_public_key_oracle).await;
    let x5c_holder = holder_accept(&sd_jwt_vc_pid, &issuer_public_key_x5c).await;

    let presentation_definitions = [
        NOTHING_SELECTIVELY_DISCLOSABLE,
        EVERYTHING,
        AGE_OVER_18_AND_NATIONALITIES,
    ];

    println!("Issuer public key lookup with oracle cases:");
    for (case, claims_to_disclose) in presentation_definitions.iter().enumerate() {
        println!("=====================================================================");
        let (verifier, key_binding_challenge) =
            verifier_init(format!("https://example.com/verifier{}", case));

        println!("Verifier {} requesting claims: [", case);
        for claim in *claims_to_disclose {
            println!("  {}", DisplayWrapper(*claim))
        }
        println!("]\n");

        let sd_jwk_kb = oracle_holder
            .present(
                claims_to_disclose,
                key_binding_challenge,
                HOLDER_PRESENT_TIME,
                &holder_key_binding_signer,
            )
            .unwrap();

        println!("SD-JWT+KB :\n{}\n", sd_jwk_kb);

        let received_claims =
            verifier_accept(verifier, &sd_jwk_kb.to_string(), &issuer_public_key_oracle).await;
        let pretty_json = serde_json::to_string_pretty(&received_claims).unwrap();
        println!("Verifier {} received claims:\n{}\n", case, pretty_json);
    }

    println!("Issuer public key lookup with x5c cases:");
    for (case, claims_to_disclose) in presentation_definitions.iter().enumerate() {
        println!("=====================================================================");
        let (verifier, key_binding_challenge) =
            verifier_init(format!("https://example.com/verifier{}", case));

        println!("Verifier {} requesting claims: [", case);
        for claim in *claims_to_disclose {
            println!("  {}", DisplayWrapper(*claim))
        }
        println!("]\n");

        let sd_jwk_kb = x5c_holder
            .present(
                claims_to_disclose,
                key_binding_challenge,
                HOLDER_PRESENT_TIME,
                &holder_key_binding_signer,
            )
            .unwrap();

        println!("SD-JWT+KB :\n{}\n", sd_jwk_kb);

        let received_claims =
            verifier_accept(verifier, &sd_jwk_kb.to_string(), &issuer_public_key_x5c).await;
        let pretty_json = serde_json::to_string_pretty(&received_claims).unwrap();
        println!("Verifier {} received claims:\n{}\n", case, pretty_json);
    }
}

const ISSUER_KID: &str = "issuer kid";
const HOLDER_KID: &str = "holder kid";

fn iss() -> UriBuf {
    iref::IriBuf::new("https://example.com/issuer".into())
        .unwrap()
        .try_into_uri()
        .unwrap()
}

fn issuer_init_signing_key() -> (Es256SignerWithChain, JwkPublic) {
    generate_key_pair_with_chain(ISSUER_KID, "Issuer", Some(&iss()))
}

fn holder_init_key_binding() -> (Es256Signer, JwkPublic) {
    generate_key_pair(HOLDER_KID, "Holder binding")
}

fn generate_key_pair(kid: &str, name: &str) -> (Es256Signer, JwkPublic) {
    let signer = Es256Signer::generate(kid.to_owned()).unwrap();
    let public_jwk = signer.public_jwk().unwrap();
    println!(
        "{} public key:\n{}\n",
        name,
        serde_json::to_string_pretty(&public_jwk).unwrap()
    );
    (signer, public_jwk)
}

fn generate_key_pair_with_chain(
    kid: &str,
    name: &str,
    iss: Option<&UriBuf>,
) -> (Es256SignerWithChain, JwkPublic) {
    let signer = Es256Signer::generate(kid.to_owned()).unwrap();
    let cert_chain = bhx5chain::Builder::dummy()
        .generate_x5chain(&signer.public_key_pem().unwrap(), iss)
        .unwrap();
    let signer = Es256SignerWithChain::new(signer, cert_chain).unwrap();
    let public_jwk = signer.public_jwk().unwrap();
    println!(
        "{} public key:\n{}\n",
        name,
        serde_json::to_string_pretty(&public_jwk).unwrap()
    );
    (signer, public_jwk)
}

use bh_sd_jwt::JsonNodePathSegment::Key;
const DISCLOSURE_PATHS: &[&JsonNodePath] = &[
    &[Key("given_name")],
    &[Key("family_name")],
    &[Key("birthdate")],
    &[Key("source_document_type")],
    &[Key("address")],
    &[Key("address"), Key("street_address")],
    &[Key("address"), Key("locality")],
    &[Key("address"), Key("postal_code")],
    &[Key("address"), Key("country")],
    &[Key("nationalities")],
    &[Key("gender")],
    &[Key("birth_family_name")],
    &[Key("place_of_birth")],
    &[Key("place_of_birth"), Key("locality")],
    &[Key("also_known_as")],
    &[Key("age_equal_or_over"), Key("12")],
    &[Key("age_equal_or_over"), Key("14")],
    &[Key("age_equal_or_over"), Key("16")],
    &[Key("age_equal_or_over"), Key("18")],
    &[Key("age_equal_or_over"), Key("21")],
    &[Key("age_equal_or_over"), Key("65")],
];

const NOTHING_SELECTIVELY_DISCLOSABLE: &[&JsonNodePath] = &[];
const EVERYTHING: &[&JsonNodePath] = DISCLOSURE_PATHS;
const AGE_OVER_18_AND_NATIONALITIES: &[&JsonNodePath] = &[
    &[Key("age_equal_or_over"), Key("18")],
    &[Key("nationalities")],
];

const IAT: SecondsSinceEpoch = 1683000000;
const HOLDER_ACCEPT_TIME: SecondsSinceEpoch = 1783000000;
const HOLDER_PRESENT_TIME: SecondsSinceEpoch = 1783000100;
const VERIFIER_ACCEPT_TIME: SecondsSinceEpoch = 1783000110;
const EXP: SecondsSinceEpoch = 1883000000;

fn issuer(signer: &Es256SignerWithChain, key_binding_public_key: JwkPublic) -> String {
    let issuer = Issuer::new(Sha256);

    let vct = "https://bmi.bund.example/credential/pid/1.0".into();

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#appendix-B.1-4
    let claims = json_object!({
        // passed explicitly in our constructor
        // "vct": "https://bmi.bund.example/credential/pid/1.0",
        "given_name": "Erika",
        "family_name": "Mustermann",
        "birthdate": "1963-08-12",
        "source_document_type": "id_card",
        "address": {
            "street_address": "Heidestraße 17",
            "locality": "Köln",
            "postal_code": "51147",
            "country": "DE"
        },
        "nationalities": [
            "DE"
        ],
        "gender": "female",
        "birth_family_name": "Gabler",
        "place_of_birth": {
            "locality": "Berlin",
            "country": "DE"
        },
        "also_known_as": "Schwester Agnes",
        "age_equal_or_over": {
            "12": true,
            "14": true,
            "16": true,
            "18": true,
            "21": true,
            "65": false
        }
    });
    println!(
        "Issuer claim set (the interesting ones):\n{}\n",
        serde_json::to_string_pretty(&claims).unwrap(),
    );

    let mut jwt_payload = IssuerJwt::new(vct, iss(), key_binding_public_key, claims).unwrap();

    jwt_payload.add_iat_claim(IAT);
    jwt_payload.exp = Some(EXP);

    let issued_sd_jwt = issuer
        .issue_with_x5c(
            jwt_payload,
            DISCLOSURE_PATHS,
            signer,
            &mut rand::thread_rng(),
        )
        .unwrap();

    let serialized_sd_jwt_vc = issued_sd_jwt.into_string_compact();
    println!(
        "Issued following SD-JWT VC (serialized):\n{}\n",
        serialized_sd_jwt_vc,
    );

    serialized_sd_jwt_vc
}

async fn holder_accept<IPKL: IssuerPublicKeyLookup>(
    issued_sd_jwt: &str,
    issuer_public_key_lookup: &IPKL,
) -> Holder {
    let holder = Holder::verify_issued(
        issued_sd_jwt,
        issuer_public_key_lookup,
        |alg| (alg == HashingAlgorithm::Sha256).then_some(Box::new(Sha256)),
        |alg| (alg == SigningAlgorithm::Es256).then_some(&Es256Verifier),
        HOLDER_ACCEPT_TIME,
    )
    .await
    .unwrap();

    println!(
        "Holder accepted SD-JWT VC, claims:\n{}\n",
        serde_json::to_string_pretty(holder.claims()).unwrap()
    );

    holder
}

fn verifier_init(verifier_aud: String) -> (Verifier, KeyBindingChallenge) {
    let verifier = Verifier::new(verifier_aud, &mut rand::thread_rng()).unwrap();
    let key_binding_challenge = verifier.key_binding_challenge().clone();
    (verifier, key_binding_challenge)
}

async fn verifier_accept<IPKL: IssuerPublicKeyLookup>(
    verifier: Verifier,
    sd_jwt_kb: &str,
    issuer_public_key_lookup: &IPKL,
) -> IssuerJwt {
    verifier
        .verify(
            SdJwtKB::from_str(sd_jwt_kb).unwrap(),
            issuer_public_key_lookup,
            VERIFIER_ACCEPT_TIME,
            |alg| (alg == HashingAlgorithm::Sha256).then_some(Box::new(Sha256)),
            |alg| (alg == SigningAlgorithm::Es256).then_some(&Es256Verifier),
        )
        .await
        .unwrap()
        .0
}

/// Mock source of the issuer public key; the lookup is in general protocol-aware
struct IssuerPublicKeyOracle(JwkPublic);
impl IssuerPublicKeyLookup for IssuerPublicKeyOracle {
    type Err = SignatureError;

    async fn lookup(
        &self,
        alleged_iss: &str,
        header: &bh_sd_jwt::IssuerJwtHeader,
    ) -> Result<JwkPublic, Error<Self::Err>> {
        // Mocked ...
        assert_eq!(alleged_iss, "https://example.com/issuer");
        // TODO(issues/45) - return this check once `kid` is used again
        // assert_eq!(header.kid.as_ref().unwrap(), ISSUER_KID);
        assert!(header.x5c.is_some());

        Ok(self.0.clone())
    }
}

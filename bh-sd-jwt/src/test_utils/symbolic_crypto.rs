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

use std::{borrow::Cow, str::FromStr};

use bh_jws_utils::{
    jwt, HasJwkKid, HasX5Chain, JwkPublic, SignatureVerifier, Signer, SigningAlgorithm,
};
use bhx5chain::X5Chain;
use serde::{Deserialize, Serialize};

use crate::{json_object, JsonObject};

// TODO(issues/57)
pub(crate) struct StubSigner {
    pub(crate) public_jwk: JwkPublic,
    pub(crate) x5chain: X5Chain,
}

/// Symbolic signature over the given message with the would-be private key
/// corresponding to the given public key, in lieu of a real signature algorithm.
///
/// Bulky, but tests the important thing: over which message and using which
/// key pair was the signature produced, regardless of the (correctness of
/// the) implementation of the signature algorithm.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct StubSignature<'m, 'k>(Cow<'m, [u8]>, Cow<'k, JwkPublic>);

impl StubSignature<'_, '_> {
    pub(crate) fn verify(&self, message: &[u8], public_key: &JwkPublic) -> bool {
        self == &StubSignature(message.into(), Cow::Borrowed(public_key))
    }
}

impl Signer for StubSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::from_str(self.public_jwk.get("alg").unwrap().as_str().unwrap()).unwrap()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(serde_json::to_string(&StubSignature(
            message.into(),
            Cow::Borrowed(&self.public_jwk),
        ))?
        .into_bytes())
    }

    fn public_jwk(&self) -> Result<JwkPublic, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.public_jwk.clone())
    }
}

impl HasJwkKid for StubSigner {
    fn jwk_kid(&self) -> &str {
        self.public_jwk.get("kid").unwrap().as_str().unwrap()
    }
}

impl HasX5Chain for StubSigner {
    fn x5chain(&self) -> X5Chain {
        self.x5chain.clone()
    }
}

impl Default for StubSigner {
    fn default() -> Self {
        Self {
            public_jwk: dummy_public_jwk(),
            x5chain: X5Chain::dummy(),
        }
    }
}

impl StubSigner {
    pub fn new(public_jwk: JwkPublic, x5chain: X5Chain) -> Self {
        Self {
            public_jwk,
            x5chain,
        }
    }
}

#[derive(Clone)]
pub(crate) struct StubVerifier {
    pub(crate) public_jwk: JwkPublic,
}

impl Default for StubVerifier {
    fn default() -> Self {
        Self {
            public_jwk: dummy_public_jwk(),
        }
    }
}

impl StubVerifier {
    pub fn new(public_jwk: JwkPublic) -> Self {
        Self { public_jwk }
    }
}

impl jwt::VerifyingAlgorithm for StubVerifier {
    fn algorithm_type(&self) -> jwt::AlgorithmType {
        self.algorithm().into()
    }

    fn verify_bytes(
        &self,
        header: &str,
        claims: &str,
        signature: &[u8],
    ) -> std::result::Result<bool, jwt::Error> {
        let message = bh_jws_utils::construct_jws_payload(header, claims);
        let success = <Self as SignatureVerifier>::verify(
            self,
            message.as_bytes(),
            signature,
            &self.public_jwk,
        )
        .expect("StubVerifier::verify should never error");
        Ok(success)
    }
}

impl SignatureVerifier for StubVerifier {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::from_str(self.public_jwk.get("alg").unwrap().as_str().unwrap()).unwrap()
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &JwkPublic,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let Ok(symbolic_signature) = serde_json::from_slice::<StubSignature>(signature) else {
            return Ok(false);
        };
        Ok(symbolic_signature.verify(message, public_key))
    }
}

pub(crate) fn dummy_public_jwk() -> JsonObject {
    json_object!({
        // TODO(issues/45) - set "test kid id" once we return `kid` in SD-JWT header
        "kid": Option::<String>::None,
        "alg": "ES256",
    })
}

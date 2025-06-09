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

use bh_jws_utils::JwkPublic;
use bherror::Error;
use serde_json::json;

use crate::{
    into_object, Hasher, HashingAlgorithm, IssuerJwtHeader, IssuerPublicKeyLookup, Sha256,
    SignatureError,
};
pub(crate) mod symbolic_crypto;

pub(crate) fn dummy_public_key_lookup() -> impl IssuerPublicKeyLookup {
    struct Lookup;

    impl IssuerPublicKeyLookup for Lookup {
        type Err = SignatureError;

        async fn lookup(
            &self,
            _alleged_iss: &str,
            _header: &IssuerJwtHeader,
        ) -> Result<JwkPublic, Error<Self::Err>> {
            // Ignore the `iss` claim and the header entirely - for more sophisticated tests,
            // a more detailed implementation is needed
            Ok(symbolic_crypto::dummy_public_jwk())
        }
    }

    Lookup
}

pub(crate) fn header_public_key_lookup() -> impl IssuerPublicKeyLookup {
    struct Lookup;

    impl IssuerPublicKeyLookup for Lookup {
        type Err = SignatureError;

        async fn lookup(
            &self,
            _alleged_iss: &str,
            header: &IssuerJwtHeader,
        ) -> Result<JwkPublic, Error<Self::Err>> {
            // Ignore the `iss` claim entirely - for more sophisticated tests,
            // a more detailed implementation is needed
            Ok(into_object(json!({
                "kid": header.kid,
                "alg": header.alg,
            })))
        }
    }

    Lookup
}

pub(crate) fn failing_public_key_lookup() -> impl IssuerPublicKeyLookup {
    struct FailingLookup;

    impl IssuerPublicKeyLookup for FailingLookup {
        type Err = SignatureError;

        async fn lookup(
            &self,
            _alleged_iss: &str,
            _header: &crate::IssuerJwtHeader,
        ) -> std::result::Result<bh_jws_utils::JwkPublic, Error<Self::Err>> {
            Err(Error::root(SignatureError::PublicKeyLookupFailed))
        }
    }

    FailingLookup
}

pub(crate) fn dummy_hasher_factory(algorithm: HashingAlgorithm) -> Option<Box<dyn Hasher>> {
    match algorithm {
        HashingAlgorithm::Sha256 => Some(Box::new(Sha256)),
    }
}

pub(crate) fn dummy_key_binding_audience() -> String {
    "http://example.com/dummy_sd_jwt_verifier".into()
}
